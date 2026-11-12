use std::collections::HashMap;
use std::sync::{atomic::AtomicU64, Arc, Mutex};
use std::time::Duration;

use http_body_util::Full;
use hyper::{body::Incoming, service::service_fn, Request, Response};
use rustls::pki_types::CertificateDer;
use xmsg::fed::{FedState, PeerConfig, PeersMap, RateLimiter};

#[tokio::test]
async fn malicious_upstream_cannot_return_more_than_the_requested_chunk() {
    let (client_cert, client_key, client_pin) =
        xmsg::fed::generate_self_signed_ed25519("reader").unwrap();
    let (origin_cert, origin_key, origin_pin) =
        xmsg::fed::generate_self_signed_ed25519("origin").unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let acceptor = xmsg::fed::make_tls_acceptor(
        &[CertificateDer::from(origin_cert)],
        &origin_key,
        Arc::new(PeersMap::new(HashMap::from([(
            "reader".into(),
            PeerConfig {
                name: "reader".into(),
                pin: Some(client_pin),
                allow: vec!["reply".into()],
                ..Default::default()
            },
        )]))),
    )
    .unwrap();
    let server = tokio::spawn(async move {
        // The first request is an exact positive control, the second exceeds its bound.
        for payload in ["ok", "oversized"] {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    hyper_util::rt::TokioIo::new(tls),
                    service_fn(move |request: Request<Incoming>| async move {
                        assert!(request.uri().query().unwrap().contains("length=2"));
                        assert_eq!(
                            request.uri().path(),
                            "/fed/v2/attachments/item%252Fother%3Foffset%3D9%26length%3D100/0",
                            "item ID must remain one exact path segment"
                        );
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                            bytes::Bytes::from_static(payload.as_bytes()),
                        )))
                    }),
                )
                .await
                .unwrap();
        }
    });
    let db = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&db).unwrap();
    let (notify, _) = tokio::sync::broadcast::channel(16);
    let state = FedState {
        node_name: "reader".into(),
        peers: Arc::new(PeersMap::new(HashMap::from([(
            "origin".into(),
            PeerConfig {
                name: "origin".into(),
                address,
                pin: Some(origin_pin),
                allow: vec!["send".into(), "reply".into()],
                ..Default::default()
            },
        )])))
        .into(),
        cert_der: client_cert,
        cert_chain_der: vec![],
        key_der: client_key,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: Arc::new(Mutex::new(db)),
        sessions_dirs: vec![],
        agy_config: xmsg::agy::AgyConfig {
            presence_dir: Default::default(),
            proc_locks_path: Default::default(),
            proc_root: Default::default(),
            agy_bin: "agy".into(),
            trusted_agy_exes: vec![],
            brain_dir: Default::default(),
        },
        agy_store: xmsg::agy::new_agy_store(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx: notify.clone(),
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: notify.clone(),
        notify_tx: notify,
        max_body: 65536,
        max_attachment_bytes: xmsg::attachments::DEFAULT_MAX_ATTACHMENT_BYTES,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: Duration::from_secs(3600),
        list_queries: Default::default(),
    };
    let exact = xmsg::fed::fetch_attachment_chunk(
        &state,
        "origin",
        "item%2Fother?offset=9&length=100",
        0,
        0,
        2,
    )
    .await
    .unwrap();
    assert_eq!(exact, b"ok", "bounded TLS positive control");
    let excess = xmsg::fed::fetch_attachment_chunk(
        &state,
        "origin",
        "item%2Fother?offset=9&length=100",
        0,
        0,
        2,
    )
    .await;
    assert!(
        matches!(excess, Err(xmsg::error::AppError::Integrity(_))),
        "M7: fetched bytes exceeded the requested bound: {excess:?}"
    );
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}
