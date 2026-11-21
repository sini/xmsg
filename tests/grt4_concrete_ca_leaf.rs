#![cfg(feature = "daemon")]

use rcgen::{CertificateParams, Issuer, KeyPair};
use rustls::pki_types::CertificateDer;
use serde_json::json;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use xmsg::client::{ClientOptions, RegisteredService};
use xmsg::fed::{FedInboxItem, FedReplyEnvelope, FedState, PeersMap, RateLimiter};
use xmsg::{agy, pi, storage, svc};

const HUB: &str = "fleet.hub";
const LEAF: &str = "guard.pods";
const HUB_URI: &str = "spiffe://example.invalid/host/hub/user/fleet";
const POD_URI: &str = "spiffe://example.invalid/ns/pods/sa/guard";
const HOST_URI: &str = "spiffe://example.invalid/host/pods/user/guard";

struct Ca {
    params: CertificateParams,
    key: KeyPair,
    file: PathBuf,
}

impl Ca {
    fn new(directory: &Path) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut params = CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate().unwrap();
        let file = directory.join("ca.pem");
        std::fs::write(&file, params.self_signed(&key).unwrap().pem()).unwrap();
        Self { params, key, file }
    }

    fn identity(&self, uri: &str) -> (CertificateDer<'static>, Vec<u8>) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::URI(uri.try_into().unwrap())];
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let cert = params
            .signed_by(&key, &Issuer::from_params(&self.params, &self.key))
            .unwrap();
        (cert.der().clone(), key.serialize_der())
    }

    fn hub_peers(&self) -> Arc<PeersMap> {
        let patterns = [
            "spiffe://example.invalid/host/*/user/*",
            "spiffe://example.invalid/ns/*/sa/*",
        ];
        Arc::new(
            PeersMap::load_from_json(
                &json!({
                    "peers": {LEAF: {
                        "ca": self.file, "identities": [POD_URI], "leaf": true,
                        "allow": ["send", "reply"]
                    }},
                    "hub": {
                        "patterns": patterns.map(|pattern| json!({"pattern":pattern,"ca":self.file})),
                        "rules": patterns.map(|pattern| json!({"pattern":pattern,"allow":["send","reply"],"leaf":true}))
                    }
                })
                .to_string(),
            )
            .unwrap(),
        )
    }

    fn leaf_peers(&self, address: std::net::SocketAddr) -> Arc<PeersMap> {
        Arc::new(
            PeersMap::load_from_json(
                &json!({HUB: {
                    "address": address.to_string(), "ca": self.file,
                    "identities": [HUB_URI], "allow": ["send", "reply"]
                }})
                .to_string(),
            )
            .unwrap(),
        )
    }
}

fn node(
    name: &str,
    peers: Arc<PeersMap>,
    identity: &(CertificateDer<'static>, Vec<u8>),
    database: &Path,
    directory: &Path,
    leaf: bool,
) -> Arc<FedState> {
    std::fs::create_dir_all(directory.join("sessions")).unwrap();
    std::fs::create_dir_all(directory.join("presence")).unwrap();
    std::fs::write(directory.join("locks"), "").unwrap();
    let db = rusqlite::Connection::open(database).unwrap();
    storage::init_db(&db).unwrap();
    let (notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(32);
    Arc::new(FedState {
        discovery: Default::default(),
        node_name: name.into(),
        peers: peers.into(),
        cert_der: identity.0.to_vec(),
        cert_chain_der: vec![identity.0.to_vec()],
        key_der: identity.1.clone(),
        rate_limiter: Arc::new(RateLimiter::new(600, 200)),
        db: Arc::new(Mutex::new(db)),
        sessions_dirs: vec![directory.join("sessions")],
        agy_config: agy::AgyConfig {
            presence_dir: directory.join("presence"),
            proc_locks_path: directory.join("locks"),
            proc_root: PathBuf::from(xmsg::process::LIVE_PROC_ROOT),
            agy_bin: "agy".into(),
            trusted_agy_exes: vec![],
            brain_dir: PathBuf::new(),
            ..Default::default()
        },
        agy_store: agy::new_agy_store(),
        pi_store: pi::new_pi_store(),
        pi_notify_tx,
        svc_store: svc::new_svc_store(),
        svc_notify_tx,
        notify_tx,
        max_body: 65536,
        max_attachment_bytes: xmsg::attachments::DEFAULT_MAX_ATTACHMENT_BYTES,
        is_leaf: leaf,
        leaf_principal: leaf.then(|| "worker".into()),
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: Duration::from_secs(600),
        list_queries: Default::default(),
    })
}

struct Tasks(Vec<tokio::task::JoinHandle<()>>);

impl Tasks {
    async fn stop(mut self) {
        for task in self.0.drain(..) {
            task.abort();
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }
    }
}

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

async fn sender(hub: &Arc<FedState>, directory: &Path, tasks: &mut Tasks) -> RegisteredService {
    let state = Arc::new(xmsg::http::AppState {
        sessions_dirs: hub.sessions_dirs.clone(),
        agy_config: hub.agy_config.clone(),
        agy_store: hub.agy_store.clone(),
        pi_store: hub.pi_store.clone(),
        pi_notify_tx: hub.pi_notify_tx.clone(),
        svc_store: hub.svc_store.clone(),
        svc_notify_tx: hub.svc_notify_tx.clone(),
        node_name: hub.node_name.clone(),
        max_body: hub.max_body,
        max_attachment_bytes: hub.max_attachment_bytes,
        request_counter: AtomicU64::new(1),
        db: hub.db.clone(),
        notify_tx: hub.notify_tx.clone(),
        reply_ttl: Duration::from_secs(600),
        idempotency_ttl: Duration::from_secs(600),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(8)),
        fed_state: Some(hub.clone()),
    });
    let register_socket = directory.join("reg.sock");
    let agent_socket = directory.join("agent.sock");
    let uid = xmsg::agent::current_uid();
    let register = agy::bind_register_listener(&register_socket, uid)
        .await
        .unwrap();
    let agent = xmsg::agent::bind_agent_listener(&agent_socket, uid)
        .await
        .unwrap();
    let register_state = state.clone();
    let trusted = HashMap::from([("sender".into(), std::env::current_exe().unwrap())]);
    tasks.0.push(tokio::spawn(async move {
        agy::run_register_server_with_listener(register, register_state, uid, trusted)
            .await
            .unwrap();
    }));
    tasks.0.push(tokio::spawn(async move {
        xmsg::agent::run_agent_server_with_listener(agent, state, uid)
            .await
            .unwrap();
    }));
    RegisteredService::register(ClientOptions {
        register_socket,
        agent_socket,
        max_frame_bytes: 65536,
        operation_timeout: Duration::from_secs(5),
        service: "sender".into(),
        expected_node: Some(HUB.into()),
        daemon_uid: uid,
    })
    .await
    .expect("grt4 concrete cycle hub sender registration failed")
}

const SIGNAL_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_STAGE_TIMEOUT: Duration = Duration::from_secs(10);

async fn probe_hostile_inbox(
    fed_state: &FedState,
    peer_name: &str,
) -> Result<hyper::StatusCode, xmsg::error::AppError> {
    let peers = fed_state.current_peers();
    let peer = peers
        .get(peer_name)
        .ok_or_else(|| xmsg::error::AppError::UnknownPeer(peer_name.to_string()))?;
    let chain = fed_state
        .cert_chain_der
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect();
    let connector = xmsg::fed::make_tls_connector_with_credentials(
        chain,
        fed_state.key_der.clone(),
        peer,
        peers.clone(),
    )?;
    let name = rustls::pki_types::ServerName::try_from(peer.name.clone())
        .map_err(|e| xmsg::error::AppError::Internal(e.to_string()))?;
    let tcp = tokio::time::timeout(
        PROBE_STAGE_TIMEOUT,
        tokio::net::TcpStream::connect(&peer.address),
    )
    .await
    .map_err(|_| {
        xmsg::error::AppError::Internal(format!(
            "probe_hostile_inbox timed out after {PROBE_STAGE_TIMEOUT:?} during tcp_connect"
        ))
    })?
    .map_err(|e| xmsg::error::AppError::PeerUnreachable(format!("connecting: {e}")))?;
    let tls = tokio::time::timeout(PROBE_STAGE_TIMEOUT, connector.connect(name, tcp))
        .await
        .map_err(|_| {
            xmsg::error::AppError::Internal(format!(
                "probe_hostile_inbox timed out after {PROBE_STAGE_TIMEOUT:?} during tls_connect"
            ))
        })?
        .map_err(|e| {
            xmsg::error::AppError::PeerUnreachable(format!("TLS handshake failed: {e}"))
        })?;
    let io = hyper_util::rt::TokioIo::new(tls);
    let (mut sender, conn) = tokio::time::timeout(
        PROBE_STAGE_TIMEOUT,
        hyper::client::conn::http1::handshake(io),
    )
    .await
    .map_err(|_| {
        xmsg::error::AppError::Internal(format!(
            "probe_hostile_inbox timed out after {PROBE_STAGE_TIMEOUT:?} during http1_handshake"
        ))
    })?
    .map_err(|e| xmsg::error::AppError::PeerUnreachable(format!("HTTP handshake failed: {e}")))?;
    let conn_task = tokio::spawn(conn);
    let req = hyper::Request::builder()
        .method("GET")
        .uri("/fed/v2/inbox?wait=0")
        .header("host", peer.name.as_str())
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .map_err(|e| xmsg::error::AppError::Internal(e.to_string()))?;
    let result = match tokio::time::timeout(PROBE_STAGE_TIMEOUT, sender.send_request(req)).await {
        Ok(Ok(resp)) => Ok(resp.status()),
        Ok(Err(e)) => Err(xmsg::error::AppError::PeerUnreachable(format!(
            "Request failed: {e}"
        ))),
        Err(_) => Err(xmsg::error::AppError::Internal(format!(
            "probe_hostile_inbox timed out after {PROBE_STAGE_TIMEOUT:?} during send_request"
        ))),
    };
    conn_task.abort();
    let _ = tokio::time::timeout(Duration::from_secs(5), conn_task).await;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concrete_addressless_ca_leaf_survives_mixed_patterns_and_hub_restart() {
    let directory = tempfile::tempdir().unwrap();
    let ca = Ca::new(directory.path());
    let hub_identity = ca.identity(HUB_URI);
    let leaf_identity = ca.identity(POD_URI);
    let hostile_identity = ca.identity(HOST_URI);
    let hub_database = directory.path().join("hub.db");

    for generation in 0..2 {
        // Keep Unix socket paths well below macOS's 104-byte sun_path limit regardless of TMPDIR.
        let runtime = tempfile::Builder::new()
            .prefix("grt4-")
            .tempdir_in("/tmp")
            .unwrap();
        std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let peers = ca.hub_peers();
        let concrete = peers.get(LEAF).unwrap();
        assert!(concrete.leaf && concrete.address.is_empty());
        let hub = node(
            HUB,
            peers.clone(),
            &hub_identity,
            &hub_database,
            runtime.path(),
            false,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let hub_controls = xmsg::observe_fed::test_hooks::controls(&hub);
        let state = hub.clone();
        let (startup_err_tx, startup_err_rx) = tokio::sync::oneshot::channel::<String>();
        let mut tasks = Tasks(vec![tokio::spawn(async move {
            if let Err(err) = xmsg::fed::run_fed_listener(listener, state).await {
                let _ = startup_err_tx.send(err.to_string());
                panic!("grt4 hub federation listener failed: {err}");
            }
        })]);
        tokio::select! {
            ready = hub_controls.listener_ready.wait_for_timeout(1, SIGNAL_WAIT_TIMEOUT, "listener_ready") => {
                ready.unwrap_or_else(|err| {
                    panic!("grt4 concrete cycle generation {generation}: {err}")
                });
            }
            startup_err = startup_err_rx => {
                match startup_err {
                    Ok(err) => panic!(
                        "grt4 concrete cycle generation {generation}: federation listener failed before listener_ready: {err}"
                    ),
                    Err(_) => panic!(
                        "grt4 concrete cycle generation {generation}: federation listener task exited before listener_ready"
                    ),
                }
            }
        }
        let leaf = node(
            LEAF,
            ca.leaf_peers(address),
            &leaf_identity,
            &runtime.path().join("leaf.db"),
            runtime.path(),
            true,
        );
        let hostile = node(
            LEAF,
            ca.leaf_peers(address),
            &hostile_identity,
            &runtime.path().join("hostile.db"),
            runtime.path(),
            true,
        );
        let hostile_err = match probe_hostile_inbox(&hostile, HUB).await {
            Err(err @ xmsg::error::AppError::PeerUnreachable(_))
            | Err(err @ xmsg::error::AppError::PeerRejected(_)) => err,
            Err(err) => {
                panic!("grt4 concrete cycle hostile host failed with unexpected error: {err:?}")
            }
            Ok(status) => {
                panic!(
                    "grt4 concrete cycle hostile host was admitted (captured the pod alias): HTTP {status}"
                )
            }
        };
        hub_controls
            .tls_handshake_done
            .wait_for_timeout(1, SIGNAL_WAIT_TIMEOUT, "tls_handshake_done")
            .await
            .unwrap_or_else(|err| {
                panic!(
                    "grt4 concrete cycle generation {generation}: {err} (client_err={hostile_err:?}, refusals={})",
                    hub_controls.tls_handshake_refusals.count()
                )
            });
        assert_eq!(
            hub_controls.tls_handshake_refusals.count(),
            1,
            "grt4 concrete cycle hub did not record TLS refusal for hostile host"
        );
        assert!(xmsg::fed::get_federated_inbox(&leaf, HUB, 0)
            .await
            .expect("grt4 concrete CA leaf failed to authenticate and poll")
            .is_none());
        assert!(
            peers.admitted_clients.read().unwrap().is_empty(),
            "grt4 concrete cycle installed a dynamic identity"
        );

        let mut sender = sender(&hub, runtime.path(), &mut tasks).await;
        let question = format!("concrete CA question {generation}");
        let sent = sender
            .send(&format!("worker@{LEAF}"), &question, None)
            .await
            .expect("grt4 hub failed to send to its addressless concrete CA leaf");
        assert_eq!(
            storage::count_peer_mailbox_messages(&hub.db.lock().unwrap(), LEAF).unwrap(),
            1
        );
        let Some(FedInboxItem::Message(message)) = xmsg::fed::get_federated_inbox(&leaf, HUB, 0)
            .await
            .expect("grt4 concrete CA leaf failed its queued pull")
        else {
            panic!("grt4 concrete CA leaf pulled no queued message")
        };
        assert_eq!(message.id, sent.message_id);
        assert_eq!(message.body, question);
        assert_eq!(message.to.as_deref(), Some("worker"));
        xmsg::fed::ack_federated_inbox(&leaf, HUB, &message.id)
            .await
            .expect("grt4 concrete CA leaf failed to ACK its hub mailbox");
        assert!(xmsg::fed::get_federated_inbox(&leaf, HUB, 0)
            .await
            .unwrap()
            .is_none());
        let answer = format!("concrete CA answer {generation}");
        let reply_id = ulid::Ulid::new().to_string();
        xmsg::fed::send_federated_reply(
            &leaf,
            HUB,
            &FedReplyEnvelope {
                v: xmsg::fed::WIRE_VERSION,
                id: reply_id.clone(),
                in_reply_to: message.id.clone(),
                replier: storage::Origin::service("worker", LEAF),
                text: answer.clone(),
                created_at: storage::now_epoch_secs(),
                attachments: vec![],
            },
        )
        .await
        .expect("grt4 concrete CA leaf failed to reply");
        let reply = sender
            .poll(5)
            .await
            .unwrap()
            .expect("grt4 hub sender failed to pull the concrete CA leaf reply");
        assert_eq!(reply.message_id(), reply_id);
        assert_eq!(reply.text(), answer);
        assert_eq!(reply.in_reply_to(), Some(message.id.as_str()));
        assert_eq!(reply.from_name(), "worker@guard.pods");
        sender
            .ack(reply.message_id())
            .await
            .expect("grt4 hub sender failed to ACK the concrete CA leaf reply");
        assert!(storage::is_svc_message_acked(&hub.db.lock().unwrap(), &reply_id).unwrap());
        assert_eq!(
            storage::count_peer_mailbox_messages(&hub.db.lock().unwrap(), LEAF).unwrap(),
            0
        );
        drop(sender);
        tasks.stop().await;
    }
}
