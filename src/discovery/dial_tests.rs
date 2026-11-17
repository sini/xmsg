use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use http_body_util::BodyExt;
use rustls::pki_types::CertificateDer;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpSocket};
use tokio::task::{JoinHandle, JoinSet};

use super::*;
use crate::discovery::Source;

const N: &str = "owner.n";
const M: &str = "owner.m";
const UNRULED: &str = "owner.unruled";

fn uri(node: &str) -> String {
    let (user, host) = node.split_once('.').unwrap();
    format!("spiffe://discovery.test/host/{host}/user/{user}")
}

struct Ca {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    pem: String,
}

#[derive(Clone)]
struct Identity {
    cert: Vec<u8>,
    key: Vec<u8>,
}

impl Ca {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "discovery fixture CA");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let pem = params.self_signed(&key).unwrap().pem();
        Self { params, key, pem }
    }

    fn issue(&self, node: &str) -> Identity {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, node);
        params.subject_alt_names = vec![rcgen::SanType::URI(uri(node).try_into().unwrap())];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let cert = params
            .signed_by(&key, &rcgen::Issuer::from_params(&self.params, &self.key))
            .unwrap();
        Identity {
            cert: cert.der().to_vec(),
            key: key.serialize_der(),
        }
    }
}

struct Fixture {
    _root: TempDir,
    fs: Arc<FedState>,
    client_pin: String,
}

impl Fixture {
    fn new(ca: &Ca, entries: &[(&str, Option<String>)]) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = tempfile::tempdir().unwrap();
        let ca_file = root.path().join("ca.pem");
        std::fs::write(&ca_file, &ca.pem).unwrap();
        let (cert, key, client_pin) =
            crate::fed::generate_self_signed_ed25519("fixture-client").unwrap();
        let (_, _, hub_pin) = crate::fed::generate_self_signed_ed25519("fixture-hub").unwrap();
        let mut peers = serde_json::Map::new();
        peers.insert(
            "hub".into(),
            json!({"address":"127.0.0.1:9", "pin":hub_pin, "allow":["send"], "default_route":true}),
        );
        for (node, address) in entries {
            let mut entry = json!({"ca":ca_file,"identities":[uri(node)],"allow":["send"]});
            if let Some(address) = address {
                entry["address"] = Value::String(address.clone());
            }
            peers.insert((*node).into(), entry);
        }
        let peers = PeersMap::load_from_json(&json!({"peers":peers}).to_string()).unwrap();
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        crate::storage::init_db(&connection).unwrap();
        let fs = Arc::new(FedState {
            discovery: Default::default(),
            node_name: crate::node::node_name_from_cert(&cert).unwrap(),
            peers: Arc::new(peers).into(),
            cert_der: cert,
            cert_chain_der: Vec::new(),
            key_der: key,
            rate_limiter: Arc::new(crate::fed::RateLimiter::new(60, 20)),
            db: Arc::new(Mutex::new(connection)),
            sessions_dirs: vec![root.path().join("sessions")],
            agy_config: crate::agy::AgyConfig::default(),
            agy_store: crate::agy::new_agy_store(),
            pi_store: crate::pi::new_pi_store(),
            pi_notify_tx: tokio::sync::broadcast::channel(16).0,
            svc_store: crate::svc::new_svc_store(),
            svc_notify_tx: tokio::sync::broadcast::channel(16).0,
            notify_tx: tokio::sync::broadcast::channel(16).0,
            max_body: 65536,
            max_attachment_bytes: 8 * 1024 * 1024,
            is_leaf: false,
            leaf_principal: None,
            outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
            dynamic_tls: Default::default(),
            reply_ttl: Duration::from_secs(3600),
            list_queries: Default::default(),
        });
        Self {
            _root: root,
            fs,
            client_pin,
        }
    }

    fn peer(&self, name: &str) -> PeerConfig {
        self.fs.current_peers().get_peer_config(name).unwrap()
    }

    fn inject(&self, server: &Server, hint: &str) -> Candidate {
        let now = Instant::now();
        let candidate = Candidate {
            addr: server.address,
            source: Source::Mdns,
            hint: Some(hint.into()),
            root_fp: None,
            seen_at: now,
            expires_at: now + Duration::from_secs(60),
        };
        self.fs
            .discovery
            .candidates
            .write()
            .unwrap()
            .inject_for_test(candidate.clone());
        candidate
    }
}

struct Server {
    address: std::net::SocketAddr,
    accepted: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Server {
    async fn start(identity: Identity, client_pin: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peers = PeersMap::load_from_json(
            &json!({"peers":{"client":{"pin":client_pin,"leaf":true,"allow":["send"]}}})
                .to_string(),
        )
        .unwrap();
        let acceptor = crate::fed::make_tls_acceptor(
            &[CertificateDer::from(identity.cert)],
            &identity.key,
            Arc::new(peers),
        )
        .unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let accepted_task = accepted.clone();
        let requests_task = requests.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    connection = listener.accept() => {
                        let (tcp, _) = connection.unwrap();
                        accepted_task.fetch_add(1, Ordering::SeqCst);
                        let acceptor = acceptor.clone();
                        let requests = requests_task.clone();
                        connections.spawn(async move {
                            let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(3), acceptor.accept(tcp)).await else { return; };
                            assert!(tls.get_ref().1.peer_certificates().is_some_and(|chain| !chain.is_empty()), "fixture TLS omitted client authentication");
                            let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                                let requests = requests.clone();
                                async move {
                                    requests.fetch_add(1, Ordering::SeqCst);
                                    let bytes = request.into_body().collect().await.unwrap().to_bytes();
                                    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                                    let response = serde_json::to_string(&crate::inbox::DeliveryResponse {
                                        session_id: "fixture-target".into(), from_name: "fixture".into(), bytes: 1,
                                        message_id: body["id"].as_str().unwrap_or("fixture").into(),
                                        outcome: Some("queued".into()),
                                    }).unwrap();
                                    Ok::<_, Infallible>(hyper::Response::new(http_body_util::Full::new(bytes::Bytes::from(response))))
                                }
                            });
                            let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tls), service).await;
                        });
                    }
                    Some(result) = connections.join_next(), if !connections.is_empty() => result.unwrap(),
                }
            }
        });
        Self {
            address,
            accepted,
            requests,
            task,
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn candidate_hint_never_names_the_verified_presence() {
    let ca = Ca::new();
    let fixture = Fixture::new(&ca, &[(N, None), (M, None)]);
    let server = Server::start(ca.issue(M), &fixture.client_pin).await;
    fixture.inject(&server, &uri(N));
    let n = resolve_dial(&fixture.fs, &fixture.peer(N)).await.unwrap();
    assert_eq!(
        n.via_hub(),
        Some("hub"),
        "a hint admitted the wrong exact identity"
    );
    let policy = fixture.fs.current_peers();
    assert!(fixture
        .fs
        .discovery
        .lookup(
            &uri(N),
            N,
            &policy,
            Instant::now(),
            crate::storage::now_epoch_secs()
        )
        .is_none());
    let m = resolve_dial(&fixture.fs, &fixture.peer(M))
        .await
        .unwrap()
        .into_direct()
        .unwrap();
    let actual =
        crate::fed::extract_uri_sans(m.get_ref().1.peer_certificates().unwrap()[0].as_ref())
            .unwrap();
    assert_eq!(actual, [uri(M)]);
    assert!(
        fixture
            .fs
            .discovery
            .lookup(
                &uri(M),
                M,
                &policy,
                Instant::now(),
                crate::storage::now_epoch_secs()
            )
            .is_some(),
        "verified M was not keyed by its certificate URI"
    );
    assert!(
        fixture
            .fs
            .discovery
            .lookup(
                &uri(N),
                M,
                &policy,
                Instant::now(),
                crate::storage::now_epoch_secs()
            )
            .is_none(),
        "untrusted hint became a presence key"
    );
    assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn unruled_candidate_is_rejected_and_negative_cache_prevents_immediate_reprobe() {
    let ca = Ca::new();
    let fixture = Fixture::new(&ca, &[(N, None)]);
    let server = Server::start(ca.issue(UNRULED), &fixture.client_pin).await;
    let candidate = fixture.inject(&server, &uri(N));
    let first = resolve_dial(&fixture.fs, &fixture.peer(N)).await.unwrap();
    assert_eq!(
        first.via_hub(),
        Some("hub"),
        "an unruled certificate became a direct peer"
    );
    let policy = fixture.fs.current_peers();
    assert!(fixture
        .fs
        .discovery
        .lookup(
            &uri(UNRULED),
            N,
            &policy,
            Instant::now(),
            crate::storage::now_epoch_secs()
        )
        .is_none());
    assert!(
        fixture
            .fs
            .discovery
            .is_negative(candidate.addr, N, &policy, Instant::now()),
        "unruled address was not negatively cached"
    );
    let accepted = server.accepted.load(Ordering::SeqCst);
    assert_eq!(
        accepted, 1,
        "fixture never received the first candidate probe"
    );
    let second = resolve_dial(&fixture.fs, &fixture.peer(N)).await.unwrap();
    assert_eq!(second.via_hub(), Some("hub"));
    assert_eq!(
        server.accepted.load(Ordering::SeqCst),
        accepted,
        "negative cache repeated an immediate probe"
    );
}

#[tokio::test]
async fn static_address_wins_over_an_actually_verified_discovered_presence_for_send() {
    let ca = Ca::new();
    let seed = Fixture::new(&ca, &[]);
    let identity = ca.issue(N);
    let static_server = Server::start(identity.clone(), &seed.client_pin).await;
    let discovered_server = Server::start(identity, &seed.client_pin).await;
    let fixture = fixture_with_identity(&seed, &ca, N, static_server.address.to_string());
    let candidate = fixture.inject(&discovered_server, &uri(N));
    let policy = fixture.fs.current_peers();
    drop(
        discovered(&fixture.fs, &fixture.peer(N), &policy, candidate)
            .await
            .unwrap(),
    );
    let envelope = crate::fed::FedEnvelope {
        v: 2,
        id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
        origin: crate::storage::Origin::anonymous("fixture", &fixture.fs.node_name),
        to: crate::fed::FedTarget {
            r#ref: "fixture-target".into(),
        },
        body: "fixture".into(),
        thread_id: String::new(),
        created_at: crate::storage::now_epoch_secs(),
        forwarded: None,
        attachments: Vec::new(),
    };
    crate::fed::send_federated_message(&fixture.fs, N, &envelope)
        .await
        .unwrap();
    assert_eq!(
        static_server.requests.load(Ordering::SeqCst),
        1,
        "static endpoint did not receive the operation"
    );
    assert_eq!(
        discovered_server.requests.load(Ordering::SeqCst),
        0,
        "discovered endpoint overrode static routing"
    );
    assert_eq!(
        discovered_server.accepted.load(Ordering::SeqCst),
        1,
        "static send opened another discovered connection"
    );
}

fn fixture_with_identity(seed: &Fixture, ca: &Ca, node: &str, address: String) -> Fixture {
    let mut fixture = Fixture::new(ca, &[(node, Some(address))]);
    let fs = Arc::get_mut(&mut fixture.fs).unwrap();
    fs.cert_der = seed.fs.cert_der.clone();
    fs.key_der = seed.fs.key_der.clone();
    fs.node_name = seed.fs.node_name.clone();
    fixture.client_pin = seed.client_pin.clone();
    fixture
}

#[tokio::test]
async fn static_connection_failure_does_not_fall_through_to_discovered_presence() {
    let ca = Ca::new();
    let seed = Fixture::new(&ca, &[]);
    let discovered_server = Server::start(ca.issue(N), &seed.client_pin).await;
    let reserved = TcpSocket::new_v4().unwrap();
    reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let fixture = fixture_with_identity(&seed, &ca, N, reserved.local_addr().unwrap().to_string());
    let candidate = fixture.inject(&discovered_server, &uri(N));
    let policy = fixture.fs.current_peers();
    drop(
        discovered(&fixture.fs, &fixture.peer(N), &policy, candidate)
            .await
            .unwrap(),
    );
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        resolve_dial(&fixture.fs, &fixture.peer(N)),
    )
    .await
    .unwrap();
    assert!(
        result.is_err(),
        "failed static endpoint silently fell through to discovery or its hub"
    );
    assert_eq!(
        discovered_server.accepted.load(Ordering::SeqCst),
        1,
        "static failure tried the discovered endpoint"
    );
    assert_eq!(discovered_server.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn unavailable_discovery_cannot_permit_addressless_entries_or_malformed_addresses() {
    let ca = Ca::new();
    let root = tempfile::tempdir().unwrap();
    let ca_file = root.path().join("ca.pem");
    std::fs::write(&ca_file, ca.pem).unwrap();
    let ca_entry = json!({"ca":ca_file,"identities":[uri(N)],"allow":["send"]});
    let config = |entry: Value| {
        let peers = serde_json::Map::from_iter([(N.to_string(), entry)]);
        json!({"peers":peers,"discovery":{"mdns":{}}}).to_string()
    };
    let error = PeersMap::load_from_json(&config(ca_entry.clone())).unwrap_err();
    assert!(
        error.contains("missing required field 'address'"),
        "{error}"
    );
    let mut malformed = ca_entry;
    malformed["address"] = json!(42);
    let error = PeersMap::load_from_json(&config(malformed)).unwrap_err();
    assert!(error.contains("'address' must be a string"), "{error}");
    let (_, _, pin) = crate::fed::generate_self_signed_ed25519("pinned").unwrap();
    let pinned = json!({"pin":pin,"allow":["send"]});
    let error = PeersMap::load_from_json(
        &json!({"peers":{"pinned":pinned},"discovery":{"mdns":{}}}).to_string(),
    )
    .unwrap_err();
    assert!(
        error.contains("missing required field 'address'"),
        "{error}"
    );
}

#[tokio::test]
async fn static_address_wins_for_reverse_observe_error_answer() {
    let ca = Ca::new();
    let seed = Fixture::new(&ca, &[]);
    let identity = ca.issue(N);
    let static_server = Server::start(identity.clone(), &seed.client_pin).await;
    let discovered_server = Server::start(identity, &seed.client_pin).await;
    let fixture = fixture_with_identity(&seed, &ca, N, static_server.address.to_string());
    let candidate = fixture.inject(&discovered_server, &uri(N));
    let policy = fixture.fs.current_peers();
    drop(
        discovered(&fixture.fs, &fixture.peer(N), &policy, candidate)
            .await
            .unwrap(),
    );
    let control = crate::observe_relay::Control {
        id: "a".repeat(32),
        hub: uri(N),
        leaf: uri(M),
        collector: uri(UNRULED),
        read: crate::observe_relay::Kind::Events,
        query: String::new(),
        remaining_ms: 5000,
    };
    assert!(
        crate::observe_relay::post_discovery_error_answer_for_test(&fixture.fs, N, &control).await
    );
    assert_eq!(
        static_server.requests.load(Ordering::SeqCst),
        1,
        "static endpoint did not receive the reverse-observe answer"
    );
    assert_eq!(
        discovered_server.requests.load(Ordering::SeqCst),
        0,
        "discovered endpoint overrode reverse-observe static routing"
    );
}

#[test]
fn configured_leaf_keeps_its_existing_mailbox_route() {
    let ca = Ca::new();
    let mut fixture = Fixture::new(&ca, &[]);
    let policy = PeersMap::load_from_json(
        &json!({"peers":{"leaf":{
            "pin":fixture.client_pin,"leaf":true,"allow":["send"]
        }}})
        .to_string(),
    )
    .unwrap();
    Arc::get_mut(&mut fixture.fs).unwrap().peers = Arc::new(policy).into();
    assert!(
        is_direct(&fixture.fs, &fixture.peer("leaf")),
        "leaf mailbox route was lost"
    );
}

#[test]
fn policy_metadata_commit_is_leased_and_rejects_an_old_generation() {
    let ca = Ca::new();
    let fixture = Fixture::new(&ca, &[(N, None)]);
    let old = fixture.fs.current_peers();
    let called = std::sync::atomic::AtomicBool::new(false);
    assert_eq!(
        fixture.fs.with_discovery_policy(&old, || {
            assert!(
                fixture.fs.dynamic_tls.try_write().is_err(),
                "metadata publication lost its policy lease"
            );
            true
        }),
        Some(true)
    );
    assert!(
        fixture.fs.dynamic_tls.try_write().is_ok(),
        "metadata publication leaked its lease"
    );
    let current = Arc::new((*old).clone());
    let acceptor = crate::fed::make_tls_acceptor(
        &[CertificateDer::from(fixture.fs.cert_der.clone())],
        &fixture.fs.key_der,
        current.clone(),
    )
    .unwrap();
    *fixture.fs.dynamic_tls.write().unwrap() = Some(crate::fed::DynamicTls {
        cert_der: fixture.fs.cert_der.clone(),
        cert_chain_der: Vec::new(),
        key_der: fixture.fs.key_der.clone(),
        ca_anchors: Default::default(),
        acceptor,
        peers: current,
    });
    let result = fixture
        .fs
        .with_discovery_policy(&old, || called.store(true, Ordering::SeqCst));
    assert!(
        result.is_none(),
        "old generation metadata effect was committed"
    );
    assert!(
        !called.load(Ordering::SeqCst),
        "old generation metadata closure ran"
    );
}

#[tokio::test]
async fn discovery_probe_slots_are_shared_and_bounded() {
    let state = super::super::state::State::default();
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(state.probes.clone().acquire_owned().await.unwrap());
    }
    assert!(
        state.probes.clone().try_acquire_owned().is_err(),
        "discovery exceeded four shared probes"
    );
    drop(held);
    assert_eq!(state.probes.available_permits(), 4);
}

struct X6Http {
    method: hyper::Method,
    path: String,
    body: Value,
    outbound_peer: Option<String>,
}

struct X6Server {
    address: std::net::SocketAddr,
    accepted: Arc<AtomicUsize>,
    received: tokio::sync::mpsc::UnboundedReceiver<X6Http>,
    task: JoinHandle<()>,
}

impl X6Server {
    async fn start(identity: Identity, fixture: &Fixture) -> Self {
        Self::with_status(identity, fixture, hyper::StatusCode::OK).await
    }

    async fn with_status(
        identity: Identity,
        fixture: &Fixture,
        post_status: hyper::StatusCode,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peers = PeersMap::load_from_json(
            &json!({"peers":{"client":{
                "pin":fixture.client_pin,"leaf":true,"allow":["send"]
            }}})
            .to_string(),
        )
        .unwrap();
        let acceptor = crate::fed::make_tls_acceptor(
            &[CertificateDer::from(identity.cert)],
            &identity.key,
            Arc::new(peers),
        )
        .unwrap();
        let db = fixture.fs.db.clone();
        let (tx, received) = tokio::sync::mpsc::unbounded_channel();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    connection = listener.accept() => {
                        let (tcp, _) = connection.unwrap();
                        count.fetch_add(1, Ordering::SeqCst);
                        let acceptor = acceptor.clone();
                        let tx = tx.clone();
                        let db = db.clone();
                        connections.spawn(async move {
                            let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(3), acceptor.accept(tcp)).await else { return; };
                            let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                                let tx = tx.clone();
                                let db = db.clone();
                                async move {
                                    let method = request.method().clone();
                                    let path = request.uri().to_string();
                                    let bytes = request.into_body().collect().await.unwrap().to_bytes();
                                    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                                    let outbound_peer = body["id"].as_str().and_then(|id| {
                                        crate::storage::get_outbound(&db.lock().unwrap(), id).unwrap().map(|row| row.peer)
                                    });
                                    let response = if method == hyper::Method::POST {
                                        serde_json::to_string(&crate::inbox::DeliveryResponse {
                                            session_id: "fixture-target".into(), from_name: "fixture".into(), bytes: 1,
                                            message_id: body["id"].as_str().unwrap().into(), outcome: Some("queued".into()),
                                        }).unwrap()
                                    } else { "[]".into() };
                                    let status = if method == hyper::Method::POST { post_status } else { hyper::StatusCode::OK };
                                    let _ = tx.send(X6Http { method, path, body, outbound_peer });
                                    Ok::<_, Infallible>(hyper::Response::builder().status(status).body(http_body_util::Full::new(bytes::Bytes::from(response))).unwrap())
                                }
                            });
                            let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tls), service).await;
                        });
                    }
                    Some(result) = connections.join_next(), if !connections.is_empty() => result.unwrap(),
                }
            }
        });
        Self {
            address,
            accepted,
            received,
            task,
        }
    }
}

impl Drop for X6Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn x6_app(fixture: &Fixture) -> Arc<crate::http::AppState> {
    let fs = &fixture.fs;
    Arc::new(crate::http::AppState {
        sessions_dirs: fs.sessions_dirs.clone(),
        agy_config: fs.agy_config.clone(),
        agy_store: fs.agy_store.clone(),
        pi_store: fs.pi_store.clone(),
        pi_notify_tx: fs.pi_notify_tx.clone(),
        svc_store: fs.svc_store.clone(),
        svc_notify_tx: fs.svc_notify_tx.clone(),
        node_name: fs.node_name.clone(),
        max_body: fs.max_body,
        max_attachment_bytes: fs.max_attachment_bytes,
        request_counter: AtomicU64::new(0),
        db: fs.db.clone(),
        notify_tx: fs.notify_tx.clone(),
        reply_ttl: fs.reply_ttl,
        idempotency_ttl: Duration::from_secs(3600),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(16)),
        fed_state: Some(fs.clone()),
    })
}

async fn x6_surface_send(discovery_succeeds: bool, post_fails: bool) {
    let ca = Ca::new();
    let mut fixture = Fixture::new(&ca, &[(N, None)]);
    let (cert, key, pin) = crate::fed::generate_self_signed_ed25519("fixture-hub").unwrap();
    let mut hub = X6Server::start(Identity { cert, key }, &fixture).await;
    let mut target = X6Server::with_status(
        ca.issue(if discovery_succeeds { N } else { M }),
        &fixture,
        if post_fails {
            hyper::StatusCode::SERVICE_UNAVAILABLE
        } else {
            hyper::StatusCode::OK
        },
    )
    .await;
    let policy = PeersMap::load_from_json(&json!({"peers":{
        "hub":{"address":hub.address.to_string(),"pin":pin,"allow":["send","reply"],"dial":"outbound","default_route":true},
        (N):{"ca":fixture._root.path().join("ca.pem"),"identities":[uri(N)],"allow":["send","reply"]}
    }}).to_string()).unwrap();
    Arc::get_mut(&mut fixture.fs).unwrap().peers = Arc::new(policy).into();
    let now = Instant::now();
    fixture
        .fs
        .discovery
        .candidates
        .write()
        .unwrap()
        .inject_for_test(Candidate {
            addr: target.address,
            source: Source::Mdns,
            hint: Some(uri(N)),
            root_fp: None,
            seen_at: now,
            expires_at: now + Duration::from_secs(60),
        });
    let state = x6_app(&fixture);
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        crate::surface::send(
            &state,
            &crate::surface::Sender::service("sender"),
            &format!("receiver@{N}"),
            "x6",
            None,
        ),
    )
    .await
    .unwrap();
    if post_fails {
        assert!(
            matches!(result, Err(AppError::ServiceUnavailable(_))),
            "{result:?}"
        );
        let post = tokio::time::timeout(Duration::from_secs(2), target.received.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(post.method, hyper::Method::POST);
        assert_eq!(post.outbound_peer.as_deref(), Some(N));
        assert_eq!(target.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(
            hub.accepted.load(Ordering::SeqCst),
            0,
            "request failure retried via the hub"
        );
        assert!(
            target.received.try_recv().is_err(),
            "application request repeated"
        );
        return;
    }
    assert!(
        result.is_ok(),
        "same SEND lost its prepared operation route: {result:?}"
    );
    let result = result.unwrap();
    assert_eq!(result.outcome, "queued");
    let receiver = if discovery_succeeds {
        &mut target.received
    } else {
        &mut hub.received
    };
    let post = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(post.method, hyper::Method::POST);
    assert_eq!(post.path, "/fed/v2/messages");
    assert_eq!(
        post.body["to"]["ref"],
        if discovery_succeeds {
            "receiver".to_string()
        } else {
            format!("receiver@{N}")
        }
    );
    assert!(
        post.body["forwarded"].is_null(),
        "sender fabricated forwarding provenance"
    );
    let actual_peer = if discovery_succeeds { N } else { "hub" };
    assert_eq!(
        post.outbound_peer.as_deref(),
        Some(actual_peer),
        "bookkeeping preceded the operation route"
    );
    let outbound = crate::storage::get_outbound(&state.db.lock().unwrap(), &result.message_id)
        .unwrap()
        .unwrap();
    assert_eq!(outbound.peer, actual_peer);
    assert_eq!(outbound.target_ref, format!("fixture-target@{N}"));
    assert_eq!(
        target.accepted.load(Ordering::SeqCst),
        1,
        "discovered TLS was discarded and probed twice"
    );
    if discovery_succeeds {
        assert_eq!(
            hub.accepted.load(Ordering::SeqCst),
            0,
            "direct success contacted the hub"
        );
    } else {
        assert!(
            target.received.try_recv().is_err(),
            "rejected discovery received an application request"
        );
        let poll = tokio::time::timeout(Duration::from_secs(2), hub.received.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(poll.method, hyper::Method::GET);
        assert!(
            poll.path
                .starts_with(&format!("/fed/v2/messages/{}/replies?", result.message_id)),
            "poller did not use the actual hub: {}",
            poll.path
        );
    }
}

#[tokio::test]
async fn x6_failed_discovery_uses_hub_within_same_surface_send() {
    x6_surface_send(false, false).await;
}

#[tokio::test]
async fn x6_successful_discovery_uses_prepared_tls_without_hub() {
    x6_surface_send(true, false).await;
}

#[tokio::test]
async fn x6_prepared_send_rejects_a_reloaded_policy_before_request() {
    let ca = Ca::new();
    let fixture = Fixture::new(&ca, &[(N, None)]);
    let server = Server::start(ca.issue(N), &fixture.client_pin).await;
    fixture.inject(&server, &uri(N));
    let prepared = prepare_send(&fixture.fs, N).await.unwrap().unwrap();
    let current = Arc::new((*fixture.fs.current_peers()).clone());
    let acceptor = crate::fed::make_tls_acceptor(
        &[CertificateDer::from(fixture.fs.cert_der.clone())],
        &fixture.fs.key_der,
        current.clone(),
    )
    .unwrap();
    *fixture.fs.dynamic_tls.write().unwrap() = Some(crate::fed::DynamicTls {
        cert_der: fixture.fs.cert_der.clone(),
        cert_chain_der: Vec::new(),
        key_der: fixture.fs.key_der.clone(),
        ca_anchors: Default::default(),
        acceptor,
        peers: current,
    });
    let envelope = crate::fed::FedEnvelope {
        v: crate::fed::WIRE_VERSION,
        id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
        origin: crate::storage::Origin::anonymous("fixture", &fixture.fs.node_name),
        to: crate::fed::FedTarget {
            r#ref: "receiver".into(),
        },
        body: "x6".into(),
        thread_id: String::new(),
        created_at: crate::storage::now_epoch_secs(),
        forwarded: None,
        attachments: Vec::new(),
    };
    let result = crate::fed::send_federated_message_prepared_with(
        &fixture.fs,
        N,
        &envelope,
        false,
        prepared,
    )
    .await;
    assert!(
        matches!(result, Err(AppError::PeerRejected(ref detail)) if detail.contains("policy changed")),
        "old prepared proof survived reload: {result:?}"
    );
    assert_eq!(server.requests.load(Ordering::SeqCst), 0);
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn x6_admitted_addressless_nonleaf_is_not_prepared() {
    let ca = Ca::new();
    let fixture = Fixture::new(&ca, &[]);
    let policy = fixture.fs.current_peers();
    policy.admitted_clients.write().unwrap().insert(
        N.into(),
        crate::fed::AdmittedClient {
            canonical_name: N.into(),
            uri: uri(N),
            pin: fixture.client_pin.clone(),
            not_after: i64::MAX,
            config: PeerConfig {
                name: N.into(),
                pin: Some(fixture.client_pin.clone()),
                allow: vec!["send".into()],
                ..Default::default()
            },
        },
    );
    assert!(!policy.get_peer_config(N).unwrap().leaf);
    assert!(policy.get(N).is_none());
    assert!(
        prepare_send(&fixture.fs, N).await.unwrap().is_none(),
        "admitted policy entered configured discovery preparation"
    );
}

#[tokio::test]
async fn x6_request_error_does_not_retry_through_hub() {
    x6_surface_send(true, true).await;
}
