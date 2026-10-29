mod short_sock;

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::broadcast;

use xmsg::agent::run_agent_server;
use xmsg::agy::{new_agy_store, AgyConfig};
use xmsg::fed::{
    generate_self_signed_ed25519, run_fed_listener, FedState, PeerConfig, PeersMap, RateLimiter,
};
use xmsg::http::{build_router, AppState};
use xmsg::mcp::{run_mcp_loop, McpConfig};
use xmsg::pi::new_pi_store;
use xmsg::storage;
use xmsg::svc::new_svc_store;

struct TestNode {
    #[allow(dead_code)]
    name: String,
    fed_addr: SocketAddr,
    http_addr: SocketAddr,
    agent_sock_path: PathBuf,
    #[allow(dead_code)]
    cert_der: Vec<u8>,
    #[allow(dead_code)]
    key_der: Vec<u8>,
    #[allow(dead_code)]
    pin: String,
    db: Arc<Mutex<rusqlite::Connection>>,
    sessions_dir: PathBuf,
    #[allow(dead_code)]
    state: Arc<AppState>,
    inbox_rx: Arc<Mutex<Vec<String>>>,
    _tmp_dir: TempDir,
}

async fn create_test_node(
    name: &str,
    session_uuid: &str,
    session_label: &str,
    peers: Vec<PeerConfig>,
    creds_opt: Option<(Vec<u8>, Vec<u8>, String)>,
) -> TestNode {
    let tmp = TempDir::new().unwrap();
    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let my_uid = xmsg::agent::current_uid();
    let sock_dir = tmp.path().join("run");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let agent_sock_path = short_sock::sock_path(&sock_dir, "agent");

    let target_inbox_sock = short_sock::sock_path(&sock_dir, "inbox");
    let inbox_listener = UnixListener::bind(&target_inbox_sock).unwrap();
    let inbox_rx = Arc::new(Mutex::new(Vec::new()));
    let rx_clone = inbox_rx.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = inbox_listener.accept().await {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
                if let Ok(s) = String::from_utf8(buf) {
                    rx_clone.lock().unwrap().push(s);
                }
            }
        }
    });

    let my_pid = std::process::id();
    let proc_root = PathBuf::from(xmsg::process::LIVE_PROC_ROOT);
    let my_proc_start =
        xmsg::process::starttime(&proc_root, my_pid).unwrap_or_else(|_| "0".to_string());

    let session_json = json!({
        "pid": my_pid,
        "sessionId": session_uuid,
        "name": session_label,
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": my_proc_start,
        "messagingSocketPath": target_inbox_sock.display().to_string()
    });
    fs::write(
        sessions_dir.join(format!("{my_pid}.json")),
        session_json.to_string(),
    )
    .unwrap();

    let (cert_der, key_der, pin) = match creds_opt {
        Some(creds) => creds,
        None => generate_self_signed_ed25519(name).unwrap(),
    };

    let mut peers_map = HashMap::new();
    for p in peers {
        peers_map.insert(p.name.clone(), p);
    }
    let peers_arc = Arc::new(PeersMap::new(peers_map));

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));

    let (notify_tx, _) = broadcast::channel(16);
    let (pi_notify_tx, _) = broadcast::channel(16);
    let (svc_notify_tx, _) = broadcast::channel(16);

    let fed_state = Arc::new(FedState {
        node_name: name.to_string(),
        peers: peers_arc,
        cert_der: cert_der.clone(),
        cert_chain_der: Vec::new(),
        key_der: key_der.clone(),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: db.clone(),
        sessions_dirs: vec![sessions_dir.clone()],
        agy_config: AgyConfig {
            presence_dir: tmp.path().join("presence"),
            proc_locks_path: tmp.path().join("proc_locks"),
            proc_root: proc_root.clone(),
            agy_bin: "agy".to_string(),
            trusted_agy_exes: Vec::new(),
                brain_dir: std::path::PathBuf::new(),
    },
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx: pi_notify_tx.clone(),
        svc_store: new_svc_store(),
        svc_notify_tx: svc_notify_tx.clone(),
        notify_tx: notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: Duration::from_secs(7 * 24 * 3600),
        list_queries: Default::default(),
    });

    let fed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fed_addr = fed_listener.local_addr().unwrap();
    let fs_clone = fed_state.clone();
    tokio::spawn(async move {
        let _ = run_fed_listener(fed_listener, fs_clone).await;
    });

    let app_state = Arc::new(AppState {
        sessions_dirs: vec![sessions_dir.clone()],
        agy_config: fed_state.agy_config.clone(),
        agy_store: fed_state.agy_store.clone(),
        pi_store: fed_state.pi_store.clone(),
        pi_notify_tx,
        svc_store: fed_state.svc_store.clone(),
        svc_notify_tx,
        node_name: name.to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: Some(fed_state.clone()),
    });

    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let app = build_router(app_state.clone());
    tokio::spawn(async move {
        axum::serve(http_listener, app).await.unwrap();
    });

    let s_path = agent_sock_path.clone();
    let s_state = app_state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server(s_path, s_state, my_uid).await;
    });

    for _ in 0..1500 {
        if agent_sock_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    TestNode {
        name: name.to_string(),
        fed_addr,
        http_addr,
        agent_sock_path,
        cert_der,
        key_der,
        pin,
        db,
        sessions_dir,
        state: app_state,
        inbox_rx,
        _tmp_dir: tmp,
    }
}

#[derive(Clone)]
struct SharedLogBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedLogBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Cell 1:
// When the first federated connect attempt stalls in TCP/TLS handshake (5s),
// send_federated_message_with retries the connect phase once on a fresh
// connection and delivers; and MCP `send` (with its widened 20s timeout)
// succeeds instead of cutting off at 5s.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn c1_connect_timeout_retries_once_and_mcp_send_succeeds() {
    let creds_a = generate_self_signed_ed25519("node-a").unwrap();
    let creds_b = generate_self_signed_ed25519("peer-b").unwrap();

    let node_b = create_test_node(
        "peer-b",
        "22222222-2222-4222-8222-222222222222",
        "worker-b",
        vec![PeerConfig {
            name: "node-a".to_string(),
            address: "127.0.0.1:1".to_string(),
            pin: Some(creds_a.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string(), "list".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        Some(creds_b.clone()),
    )
    .await;

    // Proxy in front of node_b.fed_addr:
    // - 1st TCP connection: stall without responding for 6s (triggers 5s connect timeout)
    // - 2nd+ TCP connection: proxy bytes bidirectionally to node_b.fed_addr
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let real_b_addr = node_b.fed_addr;
    let proxy_accepts = Arc::new(AtomicUsize::new(0));
    let proxy_accepts_clone = proxy_accepts.clone();

    tokio::spawn(async move {
        while let Ok((mut client_stream, _)) = proxy_listener.accept().await {
            let idx = proxy_accepts_clone.fetch_add(1, Ordering::SeqCst);
            if idx == 0 {
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(6)).await;
                    drop(client_stream);
                });
            } else {
                tokio::spawn(async move {
                    if let Ok(mut upstream) = TcpStream::connect(real_b_addr).await {
                        let _ =
                            tokio::io::copy_bidirectional(&mut client_stream, &mut upstream).await;
                    }
                });
            }
        }
    });

    let node_a = create_test_node(
        "node-a",
        "11111111-1111-4111-8111-111111111111",
        "orch-a",
        vec![PeerConfig {
            name: "peer-b".to_string(),
            address: proxy_addr.to_string(),
            pin: Some(creds_b.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string(), "list".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        Some(creds_a),
    )
    .await;

    // Invoke MCP `send` tool through run_mcp_loop (which uses the MCP send timeout)
    let mcp_config = McpConfig::new(
        vec![node_a.sessions_dir.clone()],
        format!("http://{}", node_a.http_addr),
    )
    .with_agent_sock(node_a.agent_sock_path.clone());

    let mcp_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "send",
            "arguments": {
                "to": "22222222-2222-4222-8222-222222222222@peer-b",
                "text": "Deliver after connect-phase timeout retry"
            }
        }
    });
    let input_str = format!("{mcp_req}\n");
    let mcp_out = tokio::task::spawn_blocking(move || {
        let mut out = Vec::new();
        run_mcp_loop(
            &mcp_config,
            io::Cursor::new(input_str.into_bytes()),
            &mut out,
        )
        .unwrap();
        String::from_utf8(out).unwrap()
    })
    .await
    .unwrap();

    let resp_json: Value = serde_json::from_str(mcp_out.trim()).unwrap();
    assert_eq!(
        resp_json["result"]["isError"], false,
        "MCP send must succeed across a 5s connect-phase timeout retry, got: {resp_json}"
    );
    let inner_text = resp_json["result"]["content"][0]["text"].as_str().unwrap();
    let inner_val: Value = serde_json::from_str(inner_text).unwrap();
    assert_eq!(inner_val["outcome"], "delivered");
    assert_eq!(
        proxy_accepts.load(Ordering::SeqCst),
        2,
        "proxy must observe exactly 2 connection attempts (1 stalled + 1 retry)"
    );
    assert_eq!(
        node_b.inbox_rx.lock().unwrap().len(),
        1,
        "recipient on peer-b must receive the message exactly once"
    );
}

// ---------------------------------------------------------------------------
// Cell 2:
// Once the connect phase completes and `send_request` starts, a request-phase
// timeout NEVER auto-retries; and a failed federated send retains the
// `outbound` row with `outcome = "peer_unreachable"` and emits a structured
// `tracing::warn!` on target `xmsg` naming message_id, peer, address, outcome,
// and error (while `replies` on the failed message_id still returns NotFound).
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn c2_request_phase_timeout_never_retries_and_records_failed_outbound_and_trace() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let creds_a = generate_self_signed_ed25519("node-a").unwrap();
    let creds_b = generate_self_signed_ed25519("peer-b").unwrap();

    // Build a TLS server for peer-b that completes the TLS handshake, reads the HTTP request
    // headers, and then stalls without sending an HTTP response (request-phase timeout).
    let server_cert = CertificateDer::from(creds_b.0.clone());
    let server_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(creds_b.1.clone()));
    let mut tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![server_cert], server_key)
        .unwrap();
    tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg));

    let stall_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stall_addr = stall_listener.local_addr().unwrap();
    let tls_accept_count = Arc::new(AtomicUsize::new(0));
    let http_req_count = Arc::new(AtomicUsize::new(0));
    let tls_accept_clone = tls_accept_count.clone();
    let http_req_clone = http_req_count.clone();

    tokio::spawn(async move {
        while let Ok((tcp, _)) = stall_listener.accept().await {
            tls_accept_clone.fetch_add(1, Ordering::SeqCst);
            let acceptor = tls_acceptor.clone();
            let req_counter = http_req_clone.clone();
            tokio::spawn(async move {
                if let Ok(mut tls_stream) = acceptor.accept(tcp).await {
                    let mut buf = [0u8; 2048];
                    if let Ok(n) = tls_stream.read(&mut buf).await {
                        if n > 0 {
                            req_counter.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    // Stall past the 5s request timeout without writing a response
                    tokio::time::sleep(Duration::from_secs(7)).await;
                }
            });
        }
    });

    // Also create a listener for peer-c that immediately drops accepted TCP connections
    // (a non-timeout connect error) to verify connect retry ONLY happens on timeout.
    let creds_c = generate_self_signed_ed25519("peer-c").unwrap();
    let eof_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let eof_addr = eof_listener.local_addr().unwrap();
    let eof_accept_count = Arc::new(AtomicUsize::new(0));
    let eof_accept_clone = eof_accept_count.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = eof_listener.accept().await {
            eof_accept_clone.fetch_add(1, Ordering::SeqCst);
            drop(tcp);
        }
    });

    let node_a = create_test_node(
        "node-a",
        "11111111-1111-4111-8111-111111111111",
        "orch-a",
        vec![
            PeerConfig {
                name: "peer-b".to_string(),
                address: stall_addr.to_string(),
                pin: Some(creds_b.2.clone()),
                ca: None,
                identities: None,
                allow: vec!["send".to_string(), "reply".to_string(), "list".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
                dial: None,
            },
            PeerConfig {
                name: "peer-c".to_string(),
                address: eof_addr.to_string(),
                pin: Some(creds_c.2.clone()),
                ca: None,
                identities: None,
                allow: vec!["send".to_string(), "reply".to_string(), "list".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
                dial: None,
            },
        ],
        Some(creds_a),
    )
    .await;

    let log_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let log_buf_clone = log_buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .with_writer(move || SharedLogBuf(log_buf_clone.clone()))
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    // Send a federated message with an idempotency_key so we can also read its reserved message_id
    let sender_session = xmsg::registry::Session {
        session_id: "11111111-1111-4111-8111-111111111111".to_string(),
        name: Some("orch-a".to_string()),
        pid: std::process::id(),
        cwd: "/workspace".to_string(),
        status: "idle".to_string(),
        kind: "interactive".to_string(),
        entrypoint: None,
        version: None,
        started_at: 1000,
        updated_at: 2000,
        harness: "claude".to_string(),
        registered: None,
    };

    let send_res = xmsg::surface::send(
        &node_a.state,
        &xmsg::surface::Sender::Session(sender_session.clone()),
        "22222222-2222-4222-8222-222222222222@peer-b",
        "Request phase timeout test",
        Some("idem-xf5-cell2"),
    )
    .await;

    assert!(
        matches!(send_res, Err(xmsg::error::AppError::PeerUnreachable(_))),
        "request-phase timeout must return PeerUnreachable, got: {send_res:?}"
    );

    // 1. Must NEVER auto-retry once connect succeeded and send_request started
    assert_eq!(
        tls_accept_count.load(Ordering::SeqCst),
        1,
        "request-phase timeout must not retry connection (expected 1 TLS accept)"
    );
    assert_eq!(
        http_req_count.load(Ordering::SeqCst),
        1,
        "request-phase timeout must not resend HTTP request (expected 1 HTTP request)"
    );

    // 1b. Non-timeout connect failure (immediate EOF during TLS handshake) must NEVER retry
    let eof_res = xmsg::surface::send(
        &node_a.state,
        &xmsg::surface::Sender::Session(sender_session),
        "22222222-2222-4222-8222-222222222222@peer-c",
        "Non-timeout connect failure test",
        Some("idem-xf5-cell2-eof"),
    )
    .await;
    assert!(
        matches!(eof_res, Err(xmsg::error::AppError::PeerUnreachable(_))),
        "non-timeout connect failure must return PeerUnreachable, got: {eof_res:?}"
    );
    assert_eq!(
        eof_accept_count.load(Ordering::SeqCst),
        1,
        "non-timeout connect error must NOT retry (expected 1 TCP accept)"
    );

    // 2. Failed outbound row must be retained in SQLite `outbound` with outcome = "peer_unreachable"
    let outbound_row = {
        let db = node_a.db.lock().unwrap();
        let mut stmt = db
            .prepare("SELECT id, peer, target_ref, outcome FROM outbound WHERE peer = 'peer-b'")
            .unwrap();
        let mut rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .unwrap();
        rows.next().and_then(Result::ok)
    };
    let (recorded_msg_id, recorded_peer, recorded_target, recorded_outcome) =
        outbound_row.expect("failed federated send must retain an outbound row");
    assert_eq!(recorded_peer, "peer-b");
    assert_eq!(
        recorded_target,
        "22222222-2222-4222-8222-222222222222@peer-b"
    );
    assert_eq!(recorded_outcome, "peer_unreachable");

    // 3. Calling `replies` on the failed message_id must still return NotFound
    let replies_res = xmsg::surface::replies(&node_a.state, &recorded_msg_id, 0, 0).await;
    assert!(
        matches!(replies_res, Err(xmsg::error::AppError::NotFound(_))),
        "replies on a failed outbound message_id must return NotFound, got: {replies_res:?}"
    );

    // 4. Structured tracing::warn! log line must record message_id, peer, address, outcome, and error
    let logs = String::from_utf8(log_buf.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("federated send failed")
            && logs.contains(&recorded_msg_id)
            && logs.contains("peer=peer-b")
            && logs.contains("outcome=peer_unreachable"),
        "expected structured federated send failure log line, got: {logs}"
    );
}
