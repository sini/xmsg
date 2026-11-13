use crate::enroll::protocol_tests::{enrollment_fingerprint, network_server, Harness};
use crate::enroll_consumer_tests::{certificate_serial, enrolled_node, recording_acceptor};
use crate::{enroll, enroll_cli};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use std::time::Duration;

type BrowserFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<Option<String>, Box<dyn std::error::Error + Send + Sync>>,
            > + Send
            + 'a,
    >,
>;
struct Browser<'a> {
    env: &'a Harness,
    http: reqwest::Client,
    calls: AtomicUsize,
}
impl enroll_cli::Browser for Browser<'_> {
    fn interact<'a>(&'a self, _: &'a str, _: enroll_cli::Flow) -> BrowserFuture<'a> {
        Box::pin(async { panic!("device consumer attempted browser callback/PKCE flow") })
    }
    fn device<'a>(
        &'a self,
        uri: &'a str,
        code: &'a str,
        request: &'a str,
        spki: &'a str,
    ) -> BrowserFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert!(!uri.is_empty());
            assert!(
                spki.starts_with("sha256:"),
                "terminal key fingerprint omitted sha256: prefix"
            );
            assert!(self.env.idp.authorize_device(code));
            let pending = tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    let response = self
                        .http
                        .get("http://localhost/v1/enrollment/pending")
                        .send()
                        .await
                        .unwrap();
                    assert_eq!(response.status(), reqwest::StatusCode::OK);
                    let pending: Vec<Value> = response.json().await.unwrap();
                    if let Some(value) = pending.into_iter().find(|v| v["request_id"] == request) {
                        break value;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("verified device request never reached local approval");
            for table in ["enroll_bindings", "enroll_rates", "enroll_certs"] {
                let count: i64 = self
                    .env
                    .db
                    .lock()
                    .unwrap()
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                    .unwrap();
                assert_eq!(
                    count, 0,
                    "pending device request gained authority before local approval"
                );
            }
            assert_eq!(pending["user"], "alice");
            assert_eq!(pending["host"], "laptop");
            assert_eq!(
                pending["spki_sha256"], spki,
                "terminal and local operator fingerprints differ"
            );
            let response = self
                .http
                .post(format!("http://localhost/v1/enrollment/{request}/approve"))
                .json(&json!({"user":"alice", "host":"laptop", "spki_sha256":spki}))
                .send()
                .await?;
            assert_eq!(
                response.status(),
                reqwest::StatusCode::OK,
                "exact terminal fingerprint approval failed"
            );
            Ok(None)
        })
    }
}
fn state(env: &Harness) -> std::sync::Arc<crate::http::AppState> {
    std::sync::Arc::new(crate::http::AppState {
        sessions_dirs: env.service.fed.sessions_dirs.clone(),
        agy_config: env.service.fed.agy_config.clone(),
        agy_store: env.service.fed.agy_store.clone(),
        pi_store: env.service.fed.pi_store.clone(),
        pi_notify_tx: env.service.fed.pi_notify_tx.clone(),
        svc_store: env.service.fed.svc_store.clone(),
        svc_notify_tx: env.service.fed.svc_notify_tx.clone(),
        node_name: env.service.fed.node_name.clone(),
        max_body: 65536,
        max_attachment_bytes: env.service.fed.max_attachment_bytes,
        request_counter: std::sync::atomic::AtomicU64::new(0),
        db: env.db.clone(),
        notify_tx: env.service.fed.notify_tx.clone(),
        reply_ttl: std::time::Duration::from_secs(600),
        idempotency_ttl: std::time::Duration::from_secs(86400),
        long_poll_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(16)),
        fed_state: Some(env.service.fed.clone()),
    })
}
async fn enable(env: &Harness) -> (reqwest::Client, tokio::task::JoinHandle<()>) {
    let mut policy = (*env.service.ca.policy()).clone();
    policy
        .providers
        .insert("idp".into(), env.idp.device_config(true));
    std::fs::write(
        env._directory.path().join("policy.json"),
        serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    env.service.ca.reload_policy().unwrap();
    env.service.register_local_approval().unwrap();
    env.idp.require_device_authorization();
    let socket_dir = env._directory.path().join("operator");
    crate::enroll_client::private_directory(&socket_dir).unwrap();
    let socket = socket_dir.join("operator.sock");
    let listener =
        crate::http::bind_ucred_unix_listener(&socket, crate::agent::current_uid(), None).unwrap();
    let router = crate::http::build_unix_router(state(env));
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<crate::http::HttpPeer>(),
        )
        .await
        .unwrap();
    });
    let http = reqwest::Client::builder()
        .unix_socket(socket)
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    (http, task)
}
fn args(
    url: &str,
    fingerprint: String,
    directory: &std::path::Path,
    flow: enroll_cli::Flow,
) -> enroll_cli::Args {
    enroll_cli::Args {
        url: Some(url.into()),
        fingerprint: Some(fingerprint),
        root_file: None,
        provider: Some("idp".into()),
        flow,
        host: Some("laptop".into()),
        state_dir: Some(directory.into()),
        renew: false,
    }
}

#[tokio::test]
async fn device_consumer_enrolls_then_receives_a_pattern_mailbox_and_replies_over_federation() {
    use crate::{fed, storage};
    let fed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let env = Harness::new_with_address(&fed_listener.local_addr().unwrap().to_string()).await;
    let hub = env.service.fed.clone();
    let seen = std::sync::Arc::new(Mutex::new(vec![]));
    let acceptor = recording_acceptor(&hub, seen.clone());
    let federation = tokio::spawn(async move {
        fed::run_fed_listener_with_acceptor(fed_listener, hub, acceptor)
            .await
            .unwrap()
    });
    let (url, enrollment) = network_server(&env, false).await;
    let (http, operator) = enable(&env).await;
    let browser = Browser {
        env: &env,
        http,
        calls: AtomicUsize::new(0),
    };
    let directory = env._directory.path().join("federating-client");
    enroll_cli::run_with_browser(
        args(
            &url,
            enrollment_fingerprint(&env),
            &directory,
            enroll_cli::Flow::Device,
        ),
        &browser,
    )
    .await
    .unwrap();
    assert_eq!(browser.calls.load(Ordering::SeqCst), 1);
    assert_eq!(env.idp.device_requests(), 1);
    assert!(env.idp.device_polls() >= 1);
    assert!(
        !env.idp.request_paths().iter().any(|p| p == "/authorize"),
        "device flow used authorization-code endpoint"
    );
    assert_ne!(
        std::fs::read(directory.join("hub-ca.pem")).unwrap(),
        std::fs::read(directory.join("root.pem")).unwrap()
    );
    for name in [
        "fed.key",
        "fed.crt",
        "root.pem",
        "enroll.json",
        "peers.json",
        "hub-ca.pem",
    ] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(directory.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let leaf = enrolled_node(&directory, &env);
    assert!(fed::get_federated_inbox(&leaf, "team.hub", 0)
        .await
        .unwrap()
        .is_none());
    assert!(env
        .service
        .fed
        .current_peers()
        .get("alice.laptop")
        .is_none());
    assert!(
        env.service
            .fed
            .current_peers()
            .get_peer_config("alice.laptop")
            .unwrap()
            .leaf
    );
    let state = std::sync::Arc::new(crate::http::AppState {
        sessions_dirs: env.service.fed.sessions_dirs.clone(),
        agy_config: env.service.fed.agy_config.clone(),
        agy_store: env.service.fed.agy_store.clone(),
        pi_store: env.service.fed.pi_store.clone(),
        pi_notify_tx: env.service.fed.pi_notify_tx.clone(),
        svc_store: env.service.fed.svc_store.clone(),
        svc_notify_tx: env.service.fed.svc_notify_tx.clone(),
        node_name: env.service.fed.node_name.clone(),
        max_body: 65536,
        max_attachment_bytes: env.service.fed.max_attachment_bytes,
        request_counter: std::sync::atomic::AtomicU64::new(0),
        db: env.db.clone(),
        notify_tx: env.service.fed.notify_tx.clone(),
        reply_ttl: std::time::Duration::from_secs(600),
        idempotency_ttl: std::time::Duration::from_secs(86400),
        long_poll_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(16)),
        fed_state: Some(env.service.fed.clone()),
    });
    let queued = crate::surface::send(
        &state,
        &crate::surface::Sender::service("sender"),
        "worker@alice.laptop",
        "consumer mailbox body",
        None,
    )
    .await
    .unwrap();
    let id = queued.message_id;
    assert_eq!(
        queued.outcome, "queued",
        "consumer node had no admitted mailbox"
    );
    let pending = crate::surface::replies(&state, &id, 0, 0).await;
    assert!(pending.as_ref().is_ok_and(|rows|rows.is_empty()),"pending reply poll for admitted leaf must return empty replies, not UnknownPeer: {pending:?}");
    let item = fed::get_federated_inbox(&leaf, "team.hub", 0)
        .await
        .unwrap()
        .unwrap();
    let fed::FedInboxItem::Message(message) = item else {
        panic!("queued item was not message")
    };
    assert_eq!(message.id, id);
    assert_eq!(message.body, "consumer mailbox body");
    fed::ack_federated_inbox(&leaf, "team.hub", &id)
        .await
        .unwrap();
    assert_eq!(
        storage::count_peer_mailbox_messages(&env.db.lock().unwrap(), "alice.laptop").unwrap(),
        0
    );
    let reply = fed::FedReplyEnvelope {
        v: fed::WIRE_VERSION,
        id: ulid::Ulid::new().to_string(),
        in_reply_to: id.clone(),
        replier: storage::Origin::service("worker", "alice.laptop"),
        text: "consumer reply".into(),
        created_at: storage::now_epoch_secs(),
        attachments: vec![],
    };
    fed::send_federated_reply(&leaf, "team.hub", &reply)
        .await
        .unwrap();
    let replies = storage::get_all_replies(&env.db.lock().unwrap(), &id).unwrap();
    assert!(
        replies.iter().any(|v| v.text == "consumer reply"),
        "consumer reply never reached sender storage"
    );
    assert!(
        !seen.lock().unwrap().is_empty(),
        "no real client-certificate handshake observed"
    );
    federation.abort();
    let _ = federation.await;
    operator.abort();
    let _ = operator.await;
    enrollment.abort();
    let _ = enrollment.await;
}

#[tokio::test]
async fn device_actual_auto_renewal_reloads_the_certificate_presented_on_the_next_outbound_dial() {
    use crate::enroll::Clock;
    use crate::fed;
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    let now = enroll::WallClock.now();
    let fed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let env = Harness::new_with_now(
        &fed_listener.local_addr().unwrap().to_string(),
        now - 16 * 3600,
    )
    .await;
    let hub = env.service.fed.clone();
    let seen = std::sync::Arc::new(Mutex::new(vec![]));
    let acceptor = recording_acceptor(&hub, seen.clone());
    let federation = tokio::spawn(async move {
        fed::run_fed_listener_with_acceptor(fed_listener, hub, acceptor)
            .await
            .unwrap()
    });
    let (url, enrollment) = network_server(&env, false).await;
    let (http, operator) = enable(&env).await;
    let browser = Browser {
        env: &env,
        http,
        calls: AtomicUsize::new(0),
    };
    let directory = env._directory.path().join("renewing-client");
    enroll_cli::run_with_browser(
        args(
            &url,
            enrollment_fingerprint(&env),
            &directory,
            enroll_cli::Flow::Device,
        ),
        &browser,
    )
    .await
    .unwrap();
    assert_eq!(browser.calls.load(Ordering::SeqCst), 1);
    assert_eq!(env.idp.device_requests(), 1);
    assert!(env.idp.device_polls() >= 1);
    assert!(
        !env.idp.request_paths().iter().any(|p| p == "/authorize"),
        "device flow used authorization-code endpoint"
    );
    assert_ne!(
        std::fs::read(directory.join("hub-ca.pem")).unwrap(),
        std::fs::read(directory.join("root.pem")).unwrap()
    );
    for name in [
        "fed.key",
        "fed.crt",
        "root.pem",
        "enroll.json",
        "peers.json",
        "hub-ca.pem",
    ] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(directory.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let leaf = enrolled_node(&directory, &env);
    let reloader = std::sync::Arc::new(
        fed::CredentialReloader::new_full(
            directory.join("fed.crt"),
            directory.join("fed.key"),
            Some(directory.join("peers.json")),
            Some(fed::OwnNode {
                name: "alice.laptop".into(),
                pin: None,
            }),
            leaf.current_peers(),
            Some(leaf.clone()),
            std::sync::Arc::new(Mutex::new(Default::default())),
        )
        .unwrap(),
    );
    // No periodic watcher is started, as in the interval-zero serve branch.
    let old = std::fs::read(directory.join("fed.crt")).unwrap();
    let old_serial = certificate_serial(&old);
    let key = std::fs::read(directory.join("fed.key")).unwrap();
    assert!(fed::get_federated_inbox(&leaf, "team.hub", 0)
        .await
        .unwrap()
        .is_none());
    let observed = seen.lock().unwrap().last().unwrap().clone();
    assert_eq!(
        x509_parser::parse_x509_certificate(&observed)
            .unwrap()
            .1
            .raw_serial_as_string(),
        old_serial
    );
    let before_idp = env.idp.request_paths().len();
    env.clock.0.store(enroll::WallClock.now(), Ordering::SeqCst);
    let renewal = tokio::spawn(enroll_cli::auto_renew(directory.clone(), reloader));
    let renewed = tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            let bytes = std::fs::read(directory.join("fed.crt")).unwrap();
            if certificate_serial(&bytes) != old_serial {
                break bytes;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("automatic renewal did not write a new certificate at its due time");
    renewal.abort();
    let _ = renewal.await;
    assert!(
        std::fs::read(directory.join("fed.key")).unwrap() == key,
        "renewal changed the local private key"
    );
    let old_der = CertificateDer::from_pem_slice(&old).unwrap();
    let new_der = CertificateDer::from_pem_slice(&renewed).unwrap();
    assert_eq!(
        fed::extract_uri_sans(&old_der).unwrap(),
        fed::extract_uri_sans(&new_der).unwrap()
    );
    assert_eq!(
        fed::spki_sha256_from_der(&old_der).unwrap(),
        fed::spki_sha256_from_der(&new_der).unwrap()
    );
    assert_eq!(
        env.idp.request_paths().len(),
        before_idp,
        "renewal contacted the identity provider"
    );
    assert!(fed::get_federated_inbox(&leaf, "team.hub", 0)
        .await
        .unwrap()
        .is_none());
    let observed = seen.lock().unwrap().last().unwrap().clone();
    let presented = x509_parser::parse_x509_certificate(&observed)
        .unwrap()
        .1
        .raw_serial_as_string();
    assert_eq!(
        presented,
        certificate_serial(&renewed),
        "next outbound TLS connection presented the stale certificate serial"
    );
    federation.abort();
    let _ = federation.await;
    operator.abort();
    let _ = operator.await;
    enrollment.abort();
    let _ = enrollment.await;
}

#[tokio::test]
async fn device_approval_routes_require_local_uid_and_are_absent_from_public_routers() {
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let env = Harness::new().await;
    let (http, operator) = enable(&env).await;
    assert_eq!(
        http.get("http://localhost/v1/enrollment/pending")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let pair = tokio::net::UnixStream::pair().unwrap();
    let mut wrong = crate::process::peer_cred(&pair.0).unwrap();
    wrong.uid = crate::agent::current_uid().wrapping_add(1);
    for (method, route) in [
        ("GET", "/v1/enrollment/pending"),
        ("POST", "/v1/enrollment/request/approve"),
        ("POST", "/v1/enrollment/request/deny"),
    ] {
        for router in [
            crate::http::build_router(state(&env)),
            crate::enroll::router(env.service.clone()),
        ] {
            let result = router
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(route)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                result.status(),
                StatusCode::NOT_FOUND,
                "public router exposed local enrollment approval route"
            );
        }
        for peer in [
            None,
            Some(crate::http::HttpPeer {
                peer: Some(wrong.clone()),
            }),
        ] {
            let mut request = Request::builder()
                .method(method)
                .uri(route)
                .body(Body::empty())
                .unwrap();
            if let Some(peer) = peer {
                request.extensions_mut().insert(ConnectInfo(peer));
            }
            let result = crate::http::build_unix_router(state(&env))
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(
                result.status(),
                StatusCode::FORBIDDEN,
                "approval route accepted absent or wrong UID credentials"
            );
        }
    }
    operator.abort();
    let _ = operator.await;
}
