use crate::enroll::protocol_tests::{enrollment_fingerprint, network_server, Harness};
use crate::{enroll, enroll_cli};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

struct Browser<'a> {
    idp: &'a crate::enroll_oidc::signed_fixture::Fixture,
    calls: AtomicUsize,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}
impl enroll_cli::Browser for Browser<'_> {
    fn interact<'a>(
        &'a self,
        url: &'a str,
        flow: enroll_cli::Flow,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Option<String>, Box<dyn std::error::Error + Send + Sync>>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (code, state) = self.idp.authorize(url);
            let url = reqwest::Url::parse(url)?;
            let redirect = url
                .query_pairs()
                .find(|(name, _)| name == "redirect_uri")
                .unwrap()
                .1
                .into_owned();
            let mut redirect = reqwest::Url::parse(&redirect)?;
            redirect
                .query_pairs_mut()
                .append_pair("code", &code)
                .append_pair("state", &state);
            if matches!(flow, enroll_cli::Flow::Paste) {
                return Ok(Some(redirect.into()));
            }
            let task = tokio::spawn(async move {
                let http = reqwest::Client::builder()
                    .no_proxy()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
                    .unwrap();
                assert!(http
                    .get(redirect)
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .is_success());
            });
            self.tasks.lock().unwrap().push(task);
            Ok(None)
        })
    }
}
impl Browser<'_> {
    async fn finish(&self) {
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
        for task in tasks {
            task.await.unwrap();
        }
    }
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
async fn production_client_loopback_and_paste_write_verified_identity() {
    for flow in [enroll_cli::Flow::Loopback, enroll_cli::Flow::Paste] {
        let env = Harness::new().await;
        let (url, listener) = network_server(&env, false).await;
        let browser = Browser {
            idp: &env.idp,
            calls: AtomicUsize::new(0),
            tasks: Mutex::new(vec![]),
        };
        let directory = env._directory.path().join("client");
        enroll_cli::run_with_browser(
            args(&url, enrollment_fingerprint(&env), &directory, flow),
            &browser,
        )
        .await
        .unwrap();
        browser.finish().await;
        assert_eq!(browser.calls.load(Ordering::SeqCst), 1);
        for name in [
            "fed.key",
            "fed.crt",
            "root.pem",
            "enroll.json",
            "peers.json",
            "hub-ca.pem",
        ] {
            assert!(directory.join(name).is_file(), "client output missing");
        }
        assert_ne!(
            std::fs::read(directory.join("hub-ca.pem")).unwrap(),
            std::fs::read(directory.join("root.pem")).unwrap(),
            "hub bundle used enrollment root rather than fleet root"
        );
        listener.abort();
        let _ = listener.await;
    }
}

#[tokio::test]
async fn production_client_refuses_wrong_root_before_creating_a_key_or_contacting_idp() {
    let env = Harness::new().await;
    let (url, listener) = network_server(&env, false).await;
    let browser = Browser {
        idp: &env.idp,
        calls: AtomicUsize::new(0),
        tasks: Mutex::new(vec![]),
    };
    let directory = env._directory.path().join("wrong-root");
    let wrong = format!("sha256:{}", "0".repeat(64));
    assert_ne!(wrong, enrollment_fingerprint(&env));
    let outcome = enroll_cli::run_with_browser(
        args(&url, wrong, &directory, enroll_cli::Flow::Loopback),
        &browser,
    )
    .await;
    assert!(outcome.is_err(), "wrong fingerprint enrollment succeeded");
    assert!(
        !directory.exists(),
        "wrong fingerprint created private state before trust"
    );
    assert_eq!(browser.calls.load(Ordering::SeqCst), 0);
    assert!(
        env.idp.request_paths().is_empty(),
        "wrong root reached the identity provider"
    );
    assert_eq!(
        env.db
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM enroll_certs", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    listener.abort();
    let _ = listener.await;
}

#[tokio::test]
async fn production_client_keeps_existing_peers_and_refuses_key_clobber() {
    let env = Harness::new().await;
    let (url, listener) = network_server(&env, false).await;
    let browser = Browser {
        idp: &env.idp,
        calls: AtomicUsize::new(0),
        tasks: Mutex::new(vec![]),
    };
    let directory = env._directory.path().join("existing-peers");
    crate::enroll_client::private_directory(&directory).unwrap();
    let existing = b"{\"peers\":{}}\n";
    std::fs::write(directory.join("peers.json"), existing).unwrap();
    enroll_cli::run_with_browser(
        args(
            &url,
            enrollment_fingerprint(&env),
            &directory,
            enroll_cli::Flow::Loopback,
        ),
        &browser,
    )
    .await
    .unwrap();
    browser.finish().await;
    assert_eq!(
        std::fs::read(directory.join("peers.json")).unwrap(),
        existing,
        "existing peers file was overwritten"
    );
    let key = std::fs::read(directory.join("fed.key")).unwrap();
    let outcome = enroll_cli::run_with_browser(
        args(
            &url,
            enrollment_fingerprint(&env),
            &directory,
            enroll_cli::Flow::Loopback,
        ),
        &browser,
    )
    .await;
    assert!(
        outcome.is_err(),
        "existing private key was silently replaced"
    );
    assert!(
        std::fs::read(directory.join("fed.key")).unwrap() == key,
        "existing private key bytes changed"
    );
    assert_eq!(browser.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        env.db
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM enroll_certs", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    listener.abort();
    let _ = listener.await;
}

#[derive(Debug)]
struct RecordingVerifier {
    inner: std::sync::Arc<dyn rustls::server::danger::ClientCertVerifier>,
    seen: std::sync::Arc<Mutex<Vec<Vec<u8>>>>,
}
impl rustls::server::danger::ClientCertVerifier for RecordingVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.root_hint_subjects()
    }
    fn verify_client_cert(
        &self,
        leaf: &rustls::pki_types::CertificateDer<'_>,
        chain: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let result = self.inner.verify_client_cert(leaf, chain, now)?;
        self.seen.lock().unwrap().push(leaf.to_vec());
        Ok(result)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
fn recording_acceptor(
    hub: &crate::fed::FedState,
    seen: std::sync::Arc<Mutex<Vec<Vec<u8>>>>,
) -> tokio_rustls::TlsAcceptor {
    let verifier = RecordingVerifier {
        inner: std::sync::Arc::new(crate::fed::CombinedClientCertVerifier::new(
            hub.current_peers(),
        )),
        seen,
    };
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(std::sync::Arc::new(verifier))
        .with_single_cert(
            hub.cert_chain(),
            rustls::pki_types::PrivatePkcs8KeyDer::from(hub.key_der()).into(),
        )
        .unwrap();
    tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config))
}
fn certificate_serial(pem: &[u8]) -> String {
    use rustls::pki_types::pem::PemObject;
    let der = rustls::pki_types::CertificateDer::from_pem_slice(pem).unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
    cert.raw_serial_as_string()
}

fn enrolled_node(
    directory: &std::path::Path,
    env: &Harness,
) -> std::sync::Arc<crate::fed::FedState> {
    use rustls::pki_types::pem::PemObject;
    let cert = std::fs::read(directory.join("fed.crt")).unwrap();
    let key =
        rcgen::KeyPair::from_pem(&std::fs::read_to_string(directory.join("fed.key")).unwrap())
            .unwrap();
    let chain = rustls::pki_types::CertificateDer::pem_slice_iter(&cert)
        .map(|v| v.unwrap().to_vec())
        .collect::<Vec<_>>();
    let peers = std::sync::Arc::new(
        crate::fed::PeersMap::load_from_file(&directory.join("peers.json")).unwrap(),
    );
    let db = rusqlite::Connection::open_in_memory().unwrap();
    crate::storage::init_db(&db).unwrap();
    let mut node = crate::enroll::protocol_tests::node_state(
        std::sync::Arc::new(Mutex::new(db)),
        env._directory.path(),
        chain,
        key.serialize_der(),
        peers,
    );
    std::sync::Arc::get_mut(&mut node).unwrap().node_name = "alice.laptop".into();
    node
}

#[tokio::test]
async fn consumer_enrolls_then_receives_a_pattern_mailbox_and_replies_over_federation() {
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
    let browser = Browser {
        idp: &env.idp,
        calls: AtomicUsize::new(0),
        tasks: Mutex::new(vec![]),
    };
    let directory = env._directory.path().join("federating-client");
    enroll_cli::run_with_browser(
        args(
            &url,
            enrollment_fingerprint(&env),
            &directory,
            enroll_cli::Flow::Loopback,
        ),
        &browser,
    )
    .await
    .unwrap();
    browser.finish().await;
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
    enrollment.abort();
    let _ = enrollment.await;
}

#[tokio::test]
async fn actual_auto_renewal_reloads_the_certificate_presented_on_the_next_outbound_dial() {
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
    let browser = Browser {
        idp: &env.idp,
        calls: AtomicUsize::new(0),
        tasks: Mutex::new(vec![]),
    };
    let directory = env._directory.path().join("renewing-client");
    enroll_cli::run_with_browser(
        args(
            &url,
            enrollment_fingerprint(&env),
            &directory,
            enroll_cli::Flow::Loopback,
        ),
        &browser,
    )
    .await
    .unwrap();
    browser.finish().await;
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
    enrollment.abort();
    let _ = enrollment.await;
}
