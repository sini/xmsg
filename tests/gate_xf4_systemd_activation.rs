use std::collections::HashMap;
use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixDatagram as StdUnixDatagram, UnixListener as StdUnixListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener, UnixStream};

use xmsg::agy::{new_agy_store, AgyConfig};
use xmsg::fed::{
    send_federated_message, CredentialReloader, FedEnvelope, FedState, FedTarget, PeerConfig,
    PeersMap, RateLimiter,
};
use xmsg::pi::new_pi_store;
use xmsg::storage;
use xmsg::svc::new_svc_store;

struct ChildGuard(Option<tokio::process::Child>);

impl ChildGuard {
    fn new(child: tokio::process::Child) -> Self {
        Self(Some(child))
    }
    fn child_mut(&mut self) -> &mut tokio::process::Child {
        self.0.as_mut().unwrap()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.start_kill();
        }
    }
}

fn generate_ca(name: &str) -> (rcgen::CertificateParams, rcgen::KeyPair, Vec<u8>, String) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let cert = params.self_signed(&key).unwrap();
    let der = cert.der().to_vec();
    let pem = cert.pem();
    (params, key, der, pem)
}

fn issue_cert(
    ca_params: &rcgen::CertificateParams,
    ca_key: &rcgen::KeyPair,
    name: &str,
    uri_sans: &[&str],
) -> (Vec<u8>, Vec<u8>, String, String) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.subject_alt_names = uri_sans
        .iter()
        .map(|u| rcgen::SanType::URI(u.to_string().try_into().unwrap()))
        .collect();
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    ];
    let issuer = rcgen::Issuer::from_params(ca_params, ca_key);
    let cert = params.signed_by(&key, &issuer).unwrap();
    let cert_der = cert.der().to_vec();
    let cert_pem = cert.pem();
    let key_der = key.serialize_der();
    let key_pem = key.serialize_pem();
    (cert_der, key_der, cert_pem, key_pem)
}

fn make_envelope(target: &str, body: &str) -> FedEnvelope {
    FedEnvelope {
        v: xmsg::fed::WIRE_VERSION,
        id: format!("msg-{}", ulid::Ulid::new()),
        origin: xmsg::storage::Origin {
            id: Some("test-sess".to_string()),
            service: None,
            node: "origin-claim".into(),
            label: Some("test-sender".to_string()),
        },
        to: FedTarget {
            r#ref: target.to_string(),
        },
        body: body.to_string(),
        thread_id: format!("thr-{}", ulid::Ulid::new()),
        created_at: 1000,
        forwarded: None,
    }
}

fn create_claude_session_fixture(
    sessions_dir: &Path,
    session_id: &str,
    name: &str,
) -> (PathBuf, Arc<Mutex<Vec<String>>>) {
    let sock_path = sessions_dir.join(format!("inbox-{session_id}.sock"));
    let listener = UnixListener::bind(&sock_path).unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let rx_clone = received.clone();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
                if let Ok(s) = String::from_utf8(buf) {
                    rx_clone.lock().unwrap().push(s);
                }
            }
        }
    });

    let my_pid = std::process::id();
    let live_proc = PathBuf::from(xmsg::process::LIVE_PROC_ROOT);
    let my_proc_start =
        xmsg::process::starttime(&live_proc, my_pid).unwrap_or_else(|_| "1000".to_string());
    let session_uuid = if xmsg::claim::is_uuid_shaped(session_id) {
        session_id.to_string()
    } else {
        use sha2::{Digest, Sha256};
        let h = hex::encode(Sha256::digest(session_id.as_bytes()));
        format!(
            "{}-{}-4{}-a{}-{}",
            &h[0..8],
            &h[8..12],
            &h[13..16],
            &h[17..20],
            &h[20..32]
        )
    };
    let session_json = serde_json::json!({
        "pid": my_pid,
        "sessionId": session_uuid,
        "name": name,
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": my_proc_start,
        "messagingSocketPath": sock_path.display().to_string()
    });
    fs::write(
        sessions_dir.join(format!("{my_pid}-{session_id}.json")),
        session_json.to_string(),
    )
    .unwrap();

    (sock_path, received)
}

async fn build_sender_fed_state(
    name: &str,
    peer_name: &str,
    peer_addr: SocketAddr,
    peer_uri: &str,
    ca_pem: &str,
    cert_pem: &str,
    key_pem: &str,
) -> (TempDir, Arc<FedState>) {
    let temp = tempdir().unwrap();
    let sessions_dir = temp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    let presence_dir = temp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    let proc_locks = temp.path().join("locks");
    fs::create_dir_all(&proc_locks).unwrap();

    let cert_path = temp.path().join("cert.pem");
    let key_path = temp.path().join("key.pem");
    let ca_path = temp.path().join("ca.pem");
    fs::write(&cert_path, cert_pem).unwrap();
    fs::write(&key_path, key_pem).unwrap();
    fs::write(&ca_path, ca_pem).unwrap();

    let mut peers = HashMap::new();
    peers.insert(
        peer_name.to_string(),
        PeerConfig {
            name: peer_name.to_string(),
            address: peer_addr.to_string(),
            pin: None,
            ca: Some(ca_path),
            identities: Some(vec![peer_uri.to_string()]),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        },
    );
    let peers_arc = Arc::new(PeersMap::new(peers));
    let db_conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&db_conn).unwrap();
    let db = Arc::new(Mutex::new(db_conn));
    let (notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(32);

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root: PathBuf::from(xmsg::process::LIVE_PROC_ROOT),
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
        brain_dir: PathBuf::new(),
    };
    let fed_state = Arc::new(FedState {
        node_name: name.to_string(),
        peers: (peers_arc.clone()).into(),
        cert_der: Vec::new(),
        cert_chain_der: Vec::new(),
        key_der: Vec::new(),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db,
        sessions_dirs: vec![sessions_dir],
        agy_config,
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx,
        svc_store: new_svc_store(),
        svc_notify_tx,
        notify_tx,
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: Duration::from_secs(3600),
        list_queries: Default::default(),
    });
    let _reloader = CredentialReloader::new(
        cert_path,
        key_path,
        peers_arc,
        fed_state.dynamic_tls.clone(),
    )
    .unwrap();
    (temp, fed_state)
}

fn new_xmsg_cmd(set_child_listen_pid: bool) -> tokio::process::Command {
    let bin = env!("CARGO_BIN_EXE_xmsg");
    if set_child_listen_pid {
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c")
            .arg("export LISTEN_PID=$$; exec \"$0\" \"$@\"")
            .arg(bin);
        cmd
    } else {
        tokio::process::Command::new(bin)
    }
}

/// Configure `pre_exec` to place `raw_fds` at `3..3+N` and clear `FD_CLOEXEC`.
fn configure_systemd_fds(
    cmd: &mut tokio::process::Command,
    raw_fds: Vec<i32>,
    _set_child_listen_pid: bool,
) {
    unsafe {
        cmd.pre_exec(move || {
            let mut staged = Vec::with_capacity(raw_fds.len());
            let base_stage = 100;
            for (idx, &src_fd) in raw_fds.iter().enumerate() {
                let target_stage = base_stage + idx as i32;
                if libc::dup2(src_fd, target_stage) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                staged.push(target_stage);
            }
            for (idx, &stage_fd) in staged.iter().enumerate() {
                let target_fd = 3 + idx as i32;
                if libc::dup2(stage_fd, target_fd) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(stage_fd);
                if libc::fcntl(target_fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

fn recv_notify_datagram(sock: &StdUnixDatagram, timeout: Duration) -> String {
    sock.set_read_timeout(Some(timeout)).unwrap();
    let mut buf = [0u8; 1024];
    let n = sock
        .recv(&mut buf)
        .expect("expected sd_notify datagram within timeout");
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

// -----------------------------------------------------------------------------
// Oracle 1: Parent pre-binds 127.0.0.1:0, passes it via LISTEN_FDS, and mTLS
// federation works on that exact port; STOPPING=1 emitted on SIGTERM.
// -----------------------------------------------------------------------------
#[tokio::test]
async fn oracle_1_socket_activated_fed_exact_port_mtls_and_stopping() {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let run_dir = tmp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("XF4 Root CA");
    let uri_server = "spiffe://example.org/ns/test/sa/server";
    let (_s_der, _s_key, s_cert_pem, s_key_pem) =
        issue_cert(&ca_params, &ca_key, "server", &[uri_server]);
    let uri_client = "spiffe://example.org/ns/test/sa/client";
    let (_c_der, _c_key, c_cert_pem, c_key_pem) =
        issue_cert(&ca_params, &ca_key, "client", &[uri_client]);

    let cert_path = tmp.path().join("server-cert.pem");
    let key_path = tmp.path().join("server-key.pem");
    let ca_path = tmp.path().join("ca.pem");
    let peers_path = tmp.path().join("peers.json");
    fs::write(&cert_path, &s_cert_pem).unwrap();
    fs::write(&key_path, &s_key_pem).unwrap();
    fs::write(&ca_path, &ca_pem).unwrap();

    let peers_json = serde_json::json!({
        "client.test": {
            "address": "127.0.0.1:9",
            "ca": ca_path.display().to_string(),
            "identities": [uri_client],
            "allow": ["send", "reply"]
        }
    });
    fs::write(&peers_path, peers_json.to_string()).unwrap();

    let (_inbox_sock, received) =
        create_claude_session_fixture(&sessions_dir, "sess-xf4-1", "recipient-xf4");

    // Pre-bind federation TCP listener on 127.0.0.1:0 in parent
    let prebound_fed = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let prebound_addr = prebound_fed.local_addr().unwrap();

    let notify_path = run_dir.join("notify.sock");
    let notify_sock = StdUnixDatagram::bind(&notify_path).unwrap();

    let agent_sock = run_dir.join("agent.sock");
    let register_sock = run_dir.join("register.sock");
    let http_sock = run_dir.join("http.sock");
    let db_path = tmp.path().join("xmsg.db");

    let mut cmd = new_xmsg_cmd(true);
    cmd.env("XDG_RUNTIME_DIR", &run_dir)
        .env("HOME", &run_dir)
        .env("RUST_LOG", "info")
        .env("LISTEN_FDS", "1")
        .env_remove("LISTEN_FDNAMES") // exercises S-1 single-TCP-listener default
        .env("NOTIFY_SOCKET", &notify_path)
        .args([
            "serve",
            "--db-path",
            db_path.to_str().unwrap(),
            "--sessions-dir",
            sessions_dir.to_str().unwrap(),
            "--register-sock",
            register_sock.to_str().unwrap(),
            "--agent-sock",
            agent_sock.to_str().unwrap(),
            "--http-sock",
            http_sock.to_str().unwrap(),
            "--fed-listen",
            "127.0.0.1:0",
            "--fed-cert",
            cert_path.to_str().unwrap(),
            "--fed-key",
            key_path.to_str().unwrap(),
            "--peers-file",
            peers_path.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    configure_systemd_fds(&mut cmd, vec![prebound_fed.as_raw_fd()], true);
    let child = cmd.spawn().expect("spawn xmsg serve");
    drop(prebound_fed); // parent drops its copy; only child holds the pre-bound socket if adopted
    let mut guard = ChildGuard::new(child);

    let msg = tokio::task::spawn_blocking({
        let notify_path = notify_path.clone();
        move || {
            let _ = notify_path;
            recv_notify_datagram(&notify_sock, Duration::from_secs(10))
        }
    })
    .await
    .unwrap();
    assert_eq!(msg.trim(), "READY=1", "expected READY=1 on NOTIFY_SOCKET");

    // Send mTLS federated message to the exact pre-bound port
    let (_sender_tmp, sender_fs) = build_sender_fed_state(
        "client.test",
        "server.test",
        prebound_addr,
        uri_server,
        &ca_pem,
        &c_cert_pem,
        &c_key_pem,
    )
    .await;

    let env = make_envelope("recipient-xf4", "hello over socket-activated fed port");
    let res = send_federated_message(&sender_fs, "server.test", &env).await;
    assert!(
        res.is_ok(),
        "mTLS federation on exact pre-bound port {} must succeed: {:?}",
        prebound_addr,
        res
    );

    for _ in 0..200 {
        if !received.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 1);
    assert!(msgs[0].contains("hello over socket-activated fed port"));
    drop(msgs);

    // Send SIGTERM and assert STOPPING=1 is emitted
    let notify_sock_stop = StdUnixDatagram::bind(run_dir.join("unused.sock")).unwrap();
    drop(notify_sock_stop);
    let pid = guard.child_mut().id().unwrap() as i32;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let status = tokio::time::timeout(Duration::from_secs(5), guard.child_mut().wait())
        .await
        .expect("child exit on SIGTERM")
        .unwrap();
    assert!(status.success(), "clean exit on SIGTERM: {:?}", status);
}

// -----------------------------------------------------------------------------
// Oracle 2: Pre-occupied-port contention control — bind(0)-drop-rebind loses
// the port under contention with EADDRINUSE, whereas LISTEN_FDS never loses it.
// -----------------------------------------------------------------------------
#[tokio::test]
async fn oracle_2_pre_occupied_port_contention_control() {
    // Part A (control): bind(0) -> drop -> contender steals the port -> rebind fails with EADDRINUSE.
    let probe = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let target_addr = probe.local_addr().unwrap();
    drop(probe);
    let thief = StdTcpListener::bind(target_addr).unwrap();
    let rebind_err = StdTcpListener::bind(target_addr).unwrap_err();
    assert_eq!(
        rebind_err.kind(),
        std::io::ErrorKind::AddrInUse,
        "bind(0)-drop-rebind loses port when contended"
    );
    drop(thief);

    // Part B (socket activation under active contention): parent binds 127.0.0.1:0,
    // spawns a background contender hammering bind(prebound_addr), and starts xmsg serve
    // with LISTEN_FDS=1 on that exact port. xmsg serve never calls bind() and succeeds.
    let prebound = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let prebound_addr = prebound.local_addr().unwrap();

    let stop_contender = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_clone = stop_contender.clone();
    let contender_handle = std::thread::spawn(move || {
        while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
            let _ = StdTcpListener::bind(prebound_addr);
            std::thread::yield_now();
        }
    });

    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let run_dir = tmp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();

    let notify_path = run_dir.join("notify.sock");
    let notify_sock = StdUnixDatagram::bind(&notify_path).unwrap();

    let mut cmd = new_xmsg_cmd(true);
    cmd.env("XDG_RUNTIME_DIR", &run_dir)
        .env("HOME", &run_dir)
        .env("LISTEN_FDS", "1")
        .env("LISTEN_FDNAMES", "listen")
        .env("NOTIFY_SOCKET", &notify_path)
        .args([
            "serve",
            "--db-path",
            tmp.path().join("xmsg.db").to_str().unwrap(),
            "--sessions-dir",
            sessions_dir.to_str().unwrap(),
            "--register-sock",
            run_dir.join("register.sock").to_str().unwrap(),
            "--agent-sock",
            run_dir.join("agent.sock").to_str().unwrap(),
            "--http-sock",
            run_dir.join("http.sock").to_str().unwrap(),
            "--listen",
            &prebound_addr.to_string(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    configure_systemd_fds(&mut cmd, vec![prebound.as_raw_fd()], true);
    let child = cmd.spawn().expect("spawn xmsg serve under contention");
    drop(prebound);
    let _guard = ChildGuard::new(child);

    let msg = tokio::task::spawn_blocking(move || {
        recv_notify_datagram(&notify_sock, Duration::from_secs(10))
    })
    .await
    .unwrap();
    stop_contender.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = contender_handle.join();
    assert_eq!(msg.trim(), "READY=1");

    let mut stream = TcpStream::connect(prebound_addr).await.unwrap();
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "resp: {resp}");
}

// -----------------------------------------------------------------------------
// Oracle 3: READY=1 arrives only after ALL configured listeners accept
// (immediate zero-retry connect on READY=1 succeeds across all sockets).
// -----------------------------------------------------------------------------
#[tokio::test]
async fn oracle_3_notify_ready_strictly_after_all_listeners_accept() {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let run_dir = tmp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();

    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("XF4 Ready CA");
    let uri_server = "spiffe://example.org/ns/test/sa/ready-server";
    let (_s_der, _s_key, s_cert_pem, s_key_pem) =
        issue_cert(&ca_params, &ca_key, "ready-server", &[uri_server]);
    let uri_client = "spiffe://example.org/ns/test/sa/ready-client";
    let (_c_der, _c_key, _c_cert_pem, _c_key_pem) =
        issue_cert(&ca_params, &ca_key, "ready-client", &[uri_client]);

    let cert_path = tmp.path().join("cert.pem");
    let key_path = tmp.path().join("key.pem");
    let ca_path = tmp.path().join("ca.pem");
    let peers_path = tmp.path().join("peers.json");
    fs::write(&cert_path, &s_cert_pem).unwrap();
    fs::write(&key_path, &s_key_pem).unwrap();
    fs::write(&ca_path, &ca_pem).unwrap();
    fs::write(
        &peers_path,
        serde_json::json!({
            "ready-client.test": {
                "address": "127.0.0.1:9",
                "ca": ca_path.display().to_string(),
                "identities": [uri_client],
                "allow": ["send", "reply"]
            }
        })
        .to_string(),
    )
    .unwrap();

    // Reserve two ephemeral TCP ports for fresh bind (so READY=1 must wait for xmsg to bind them
    // AND bind agent.sock, register.sock, http.sock)
    let p1 = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let fed_addr = p1.local_addr().unwrap();
    let p2 = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let http_tcp_addr = p2.local_addr().unwrap();
    drop(p1);
    drop(p2);

    let agent_sock = run_dir.join("agent.sock");
    let register_sock = run_dir.join("register.sock");
    let http_sock = run_dir.join("http.sock");
    let notify_path = run_dir.join("notify.sock");
    let notify_sock = StdUnixDatagram::bind(&notify_path).unwrap();

    let bin = env!("CARGO_BIN_EXE_xmsg");
    let child = tokio::process::Command::new(bin)
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env("HOME", &run_dir)
        .env_remove("LISTEN_FDS")
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDNAMES")
        .env("NOTIFY_SOCKET", &notify_path)
        .args([
            "serve",
            "--db-path",
            tmp.path().join("xmsg.db").to_str().unwrap(),
            "--sessions-dir",
            sessions_dir.to_str().unwrap(),
            "--register-sock",
            register_sock.to_str().unwrap(),
            "--agent-sock",
            agent_sock.to_str().unwrap(),
            "--http-sock",
            http_sock.to_str().unwrap(),
            "--listen",
            &http_tcp_addr.to_string(),
            "--fed-listen",
            &fed_addr.to_string(),
            "--fed-cert",
            cert_path.to_str().unwrap(),
            "--fed-key",
            key_path.to_str().unwrap(),
            "--peers-file",
            peers_path.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn xmsg serve");
    let mut guard = ChildGuard::new(child);

    let notify_sock_arc = Arc::new(notify_sock);
    let dgram = tokio::task::spawn_blocking({
        let s = notify_sock_arc.clone();
        move || recv_notify_datagram(&s, Duration::from_secs(10))
    })
    .await
    .unwrap();
    assert_eq!(dgram.trim(), "READY=1");

    // ZERO-RETRY immediate connect on all 5 listeners right on READY=1
    let _fed_conn = std::net::TcpStream::connect(fed_addr)
        .expect("fed_listen must accept immediately on READY=1 without retry");
    let _tcp_conn = std::net::TcpStream::connect(http_tcp_addr)
        .expect("listen must accept immediately on READY=1 without retry");
    let _agent_conn = std::os::unix::net::UnixStream::connect(&agent_sock)
        .expect("agent.sock must accept immediately on READY=1 without retry");
    let _reg_conn = std::os::unix::net::UnixStream::connect(&register_sock)
        .expect("register.sock must accept immediately on READY=1 without retry");
    let mut http_conn = UnixStream::connect(&http_sock)
        .await
        .expect("http.sock must accept immediately on READY=1 without retry");

    http_conn
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    http_conn.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "resp: {resp}");

    // Verify STOPPING=1 on SIGTERM
    let pid = guard.child_mut().id().unwrap() as i32;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let stop_dgram = tokio::task::spawn_blocking({
        let s = notify_sock_arc.clone();
        move || recv_notify_datagram(&s, Duration::from_secs(5))
    })
    .await
    .unwrap();
    assert_eq!(stop_dgram.trim(), "STOPPING=1");
}

// -----------------------------------------------------------------------------
// Oracle 4: RELOADING=1 / READY=1 bracket a real peer reload on SIGHUP (S-3),
// the new peer is honoured after READY=1, and an invalid reload emits
// READY=1\nSTATUS=reload failed: <reason> while keeping previous config (S-4).
// -----------------------------------------------------------------------------
#[tokio::test]
async fn oracle_4_sighup_reload_bracket_and_failed_status() {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let run_dir = tmp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let (ca1_params, ca1_key, _ca1_der, ca1_pem) = generate_ca("XF4 Reload CA 1");
    let (ca2_params, ca2_key, _ca2_der, ca2_pem) = generate_ca("XF4 Reload CA 2");

    let uri_server = "spiffe://example.org/ns/test/sa/reload-server";
    let (_s_der, _s_key, s_cert_pem, s_key_pem) =
        issue_cert(&ca1_params, &ca1_key, "reload-server", &[uri_server]);

    let uri_peer1 = "spiffe://example.org/ns/test/sa/peer1";
    let (_p1_der, _p1_key, p1_cert_pem, p1_key_pem) =
        issue_cert(&ca1_params, &ca1_key, "peer1", &[uri_peer1]);

    let uri_peer2 = "spiffe://example.org/ns/test/sa/peer2";
    let (_p2_der, _p2_key, p2_cert_pem, p2_key_pem) =
        issue_cert(&ca2_params, &ca2_key, "peer2", &[uri_peer2]);

    let cert_path = tmp.path().join("server-cert.pem");
    let key_path = tmp.path().join("server-key.pem");
    let ca1_path = tmp.path().join("ca1.pem");
    let ca2_path = tmp.path().join("ca2.pem");
    let peers_path = tmp.path().join("peers.json");
    fs::write(&cert_path, &s_cert_pem).unwrap();
    fs::write(&key_path, &s_key_pem).unwrap();
    fs::write(&ca1_path, &ca1_pem).unwrap();
    fs::write(&ca2_path, &ca2_pem).unwrap();

    // Initially only peer1.test is configured (with send, reply, and leaf=true so send, replies, and inbox are all permitted)
    fs::write(
        &peers_path,
        serde_json::json!({
            "peer1.test": {
                "ca": ca1_path.display().to_string(),
                "identities": [uri_peer1],
                "allow": ["send", "reply"],
                "leaf": true
            }
        })
        .to_string(),
    )
    .unwrap();

    let (_inbox_sock, received) =
        create_claude_session_fixture(&sessions_dir, "sess-xf4-4", "recipient-reload");

    let prebound_fed = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let fed_addr = prebound_fed.local_addr().unwrap();
    let notify_path = run_dir.join("notify.sock");
    let notify_sock = Arc::new(StdUnixDatagram::bind(&notify_path).unwrap());

    let mut cmd = new_xmsg_cmd(true);
    cmd.env("XDG_RUNTIME_DIR", &run_dir)
        .env("HOME", &run_dir)
        .env("LISTEN_FDS", "1")
        .env("LISTEN_FDNAMES", "fed")
        .env("NOTIFY_SOCKET", &notify_path)
        .args([
            "serve",
            "--db-path",
            tmp.path().join("xmsg.db").to_str().unwrap(),
            "--sessions-dir",
            sessions_dir.to_str().unwrap(),
            "--register-sock",
            run_dir.join("register.sock").to_str().unwrap(),
            "--agent-sock",
            run_dir.join("agent.sock").to_str().unwrap(),
            "--http-sock",
            run_dir.join("http.sock").to_str().unwrap(),
            "--fed-listen",
            &fed_addr.to_string(),
            "--fed-cert",
            cert_path.to_str().unwrap(),
            "--fed-key",
            key_path.to_str().unwrap(),
            "--peers-file",
            peers_path.to_str().unwrap(),
            "--fed-reload-interval-secs",
            "0", // disable timer so SIGHUP is the sole trigger
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    configure_systemd_fds(&mut cmd, vec![prebound_fed.as_raw_fd()], true);
    let child = cmd.spawn().expect("spawn xmsg serve");
    drop(prebound_fed);
    let mut guard = ChildGuard::new(child);

    let initial_ready = tokio::task::spawn_blocking({
        let s = notify_sock.clone();
        move || recv_notify_datagram(&s, Duration::from_secs(10))
    })
    .await
    .unwrap();
    assert_eq!(initial_ready.trim(), "READY=1");

    // Before reload: peer2.test is not in peers.json => rejected
    let (_p2_tmp, p2_fs) = build_sender_fed_state(
        "peer2.test",
        "reload-server.test",
        fed_addr,
        uri_server,
        &ca1_pem,
        &p2_cert_pem,
        &p2_key_pem,
    )
    .await;
    let env_before = make_envelope("recipient-reload", "before reload");
    assert!(
        send_federated_message(&p2_fs, "reload-server.test", &env_before)
            .await
            .is_err(),
        "peer2 must be rejected before reload"
    );

    // Update peers.json to add peer2.test and send SIGHUP
    fs::write(
        &peers_path,
        serde_json::json!({
            "peer1.test": {
                "ca": ca1_path.display().to_string(),
                "identities": [uri_peer1],
                "allow": ["send", "reply"],
                "leaf": true
            },
            "peer2.test": {
                "address": "127.0.0.1:9",
                "ca": ca2_path.display().to_string(),
                "identities": [uri_peer2],
                "allow": ["send", "reply"]
            }
        })
        .to_string(),
    )
    .unwrap();

    let pid = guard.child_mut().id().unwrap() as i32;
    unsafe {
        libc::kill(pid, libc::SIGHUP);
    }

    let reloading_msg = tokio::task::spawn_blocking({
        let s = notify_sock.clone();
        move || recv_notify_datagram(&s, Duration::from_secs(5))
    })
    .await
    .unwrap();
    assert!(
        reloading_msg.starts_with("RELOADING=1\nMONOTONIC_USEC="),
        "expected RELOADING=1 with MONOTONIC_USEC, got: {reloading_msg:?}"
    );
    let usec_str = reloading_msg
        .trim()
        .strip_prefix("RELOADING=1\nMONOTONIC_USEC=")
        .expect("MONOTONIC_USEC line");
    let usec: u64 = usec_str.parse().expect("valid u64 MONOTONIC_USEC");
    assert!(usec > 0);

    let ready_after_reload = tokio::task::spawn_blocking({
        let s = notify_sock.clone();
        move || recv_notify_datagram(&s, Duration::from_secs(5))
    })
    .await
    .unwrap();
    assert_eq!(ready_after_reload.trim(), "READY=1");

    // Immediately after READY=1, peer2.test is honoured!
    let env_after = make_envelope("recipient-reload", "after sighup reload");
    send_federated_message(&p2_fs, "reload-server.test", &env_after)
        .await
        .expect("peer2 must succeed after SIGHUP reload READY=1");

    for _ in 0..200 {
        if !received.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(received.lock().unwrap().len(), 1);

    // S-4: Write invalid peers.json (containing secret-looking token) and send SIGHUP.
    // Must emit RELOADING=1 then READY=1\nSTATUS=reload failed: invalid peers file
    // (content-free reason) and keep previous configuration!
    fs::write(&peers_path, "{corrupt_json_secret_token_xyz").unwrap();
    unsafe {
        libc::kill(pid, libc::SIGHUP);
    }

    let reloading_fail = tokio::task::spawn_blocking({
        let s = notify_sock.clone();
        move || recv_notify_datagram(&s, Duration::from_secs(5))
    })
    .await
    .unwrap();
    assert!(
        reloading_fail.starts_with("RELOADING=1\nMONOTONIC_USEC="),
        "expected RELOADING=1 before failed reload, got: {reloading_fail:?}"
    );

    let ready_fail = tokio::task::spawn_blocking({
        let s = notify_sock.clone();
        move || recv_notify_datagram(&s, Duration::from_secs(5))
    })
    .await
    .unwrap();
    assert_eq!(
        ready_fail.trim(),
        "READY=1\nSTATUS=reload failed: invalid peers file",
        "S-4 requires content-free reload failure status"
    );
    assert!(
        !ready_fail.contains("secret_token_xyz"),
        "STATUS must never leak file contents"
    );

    // Previous config still active after failed reload
    let env_still_ok = make_envelope("recipient-reload", "still active after failed reload");
    send_federated_message(&p2_fs, "reload-server.test", &env_still_ok)
        .await
        .expect("previous configuration must remain active after failed reload");

    // Peer revocation cell:
    // 1. While peer1.test is still present in the active configuration, open a persistent
    //    HTTP/1.1 keep-alive mTLS connection as peer1.test and verify send, replies, and inbox
    //    succeed before removal.
    let (_p1_tmp, p1_fs) = build_sender_fed_state(
        "peer1.test",
        "reload-server.test",
        fed_addr,
        uri_server,
        &ca1_pem,
        &p1_cert_pem,
        &p1_key_pem,
    )
    .await;
    let p1_peer_cfg = p1_fs
        .current_peers()
        .get("reload-server.test")
        .unwrap()
        .clone();
    let p1_connector = xmsg::fed::make_tls_connector_for_peer(&p1_fs, &p1_peer_cfg).unwrap();
    let p1_tcp = tokio::net::TcpStream::connect(fed_addr).await.unwrap();
    let p1_sni = rustls::pki_types::ServerName::try_from("reload-server.test".to_string()).unwrap();
    let p1_tls = p1_connector.connect(p1_sni, p1_tcp).await.unwrap();
    let (mut p1_keepalive, p1_conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(p1_tls))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = p1_conn.await;
    });

    let p1_env_before = make_envelope("recipient-reload", "peer1 before removal");
    let p1_deliv = send_federated_message(&p1_fs, "reload-server.test", &p1_env_before)
        .await
        .expect("peer1 send must succeed before removal");
    let p1_msg_id = p1_deliv.message_id;
    xmsg::fed::poll_federated_replies(&p1_fs, "reload-server.test", &p1_msg_id, 0, 0)
        .await
        .expect("peer1 replies poll must succeed before removal");
    xmsg::fed::get_federated_inbox(&p1_fs, "reload-server.test", 0)
        .await
        .expect("peer1 inbox poll must succeed before removal");

    // 2. Rewrite peers.json to REMOVE peer1.test (keeping only peer2.test, plus a sibling peer on
    //    ca1_path so ca1 remains an active CA anchor), send SIGHUP, and await RELOADING=1 -> READY=1.
    let uri_peer_keep = "spiffe://example.org/ns/test/sa/peer-keep";
    fs::write(
        &peers_path,
        serde_json::json!({
            "peer-keep.test": {
                "address": "127.0.0.1:9",
                "ca": ca1_path.display().to_string(),
                "identities": [uri_peer_keep],
                "allow": ["send", "reply"]
            },
            "peer2.test": {
                "address": "127.0.0.1:9",
                "ca": ca2_path.display().to_string(),
                "identities": [uri_peer2],
                "allow": ["send", "reply"]
            }
        })
        .to_string(),
    )
    .unwrap();
    unsafe {
        libc::kill(pid, libc::SIGHUP);
    }
    let reloading_revoke = tokio::task::spawn_blocking({
        let s = notify_sock.clone();
        move || recv_notify_datagram(&s, Duration::from_secs(5))
    })
    .await
    .unwrap();
    assert!(
        reloading_revoke.starts_with("RELOADING=1\nMONOTONIC_USEC="),
        "expected RELOADING=1 on peer removal reload, got: {reloading_revoke:?}"
    );
    let ready_revoke = tokio::task::spawn_blocking({
        let s = notify_sock.clone();
        move || recv_notify_datagram(&s, Duration::from_secs(5))
    })
    .await
    .unwrap();
    assert_eq!(ready_revoke.trim(), "READY=1");

    // 3. Immediately after READY=1, the removed peer1.test must be refused on send, replies, and
    //    inbox — both on its pre-existing HTTP/1.1 keep-alive connection (which reaches
    //    handle_fed_send, fed_get_replies_handler, and fed_get_inbox_handler directly) and on new
    //    connections.
    let send_body =
        serde_json::to_vec(&make_envelope("recipient-reload", "peer1 after removal")).unwrap();
    let req_send = hyper::Request::builder()
        .method("POST")
        .uri("/fed/v2/messages")
        .header("content-type", "application/json")
        .header("host", "reload-server.test")
        .body(http_body_util::Full::new(bytes::Bytes::from(send_body)))
        .unwrap();
    let resp_send = p1_keepalive.send_request(req_send).await.unwrap();
    assert_eq!(
        resp_send.status(),
        hyper::StatusCode::NOT_FOUND,
        "removed peer1 must be refused on POST /fed/v2/messages right after READY=1"
    );

    let req_replies = hyper::Request::builder()
        .method("GET")
        .uri(format!(
            "/fed/v2/messages/{p1_msg_id}/replies?after=0&wait=0"
        ))
        .header("host", "reload-server.test")
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .unwrap();
    let resp_replies = p1_keepalive.send_request(req_replies).await.unwrap();
    assert_eq!(
        resp_replies.status(),
        hyper::StatusCode::NOT_FOUND,
        "removed peer1 must be refused on GET /fed/v2/messages/{{id}}/replies right after READY=1"
    );

    let req_inbox = hyper::Request::builder()
        .method("GET")
        .uri("/fed/v2/inbox?wait=0")
        .header("host", "reload-server.test")
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .unwrap();
    let resp_inbox = p1_keepalive.send_request(req_inbox).await.unwrap();
    assert_eq!(
        resp_inbox.status(),
        hyper::StatusCode::NOT_FOUND,
        "removed peer1 must be refused on GET /fed/v2/inbox right after READY=1"
    );

    assert!(
        send_federated_message(&p1_fs, "reload-server.test", &p1_env_before)
            .await
            .is_err(),
        "removed peer1 must be refused on new send connection after READY=1"
    );
    assert!(
        xmsg::fed::poll_federated_replies(&p1_fs, "reload-server.test", &p1_msg_id, 0, 0)
            .await
            .is_err(),
        "removed peer1 must be refused on new replies connection after READY=1"
    );
    assert!(
        xmsg::fed::get_federated_inbox(&p1_fs, "reload-server.test", 0)
            .await
            .is_err(),
        "removed peer1 must be refused on new inbox connection after READY=1"
    );
}

// -----------------------------------------------------------------------------
// Oracle 5: Wrong LISTEN_PID => inherited fds are ignored and daemon binds fresh;
// plus S-5 no-variable start binds fresh identically.
// -----------------------------------------------------------------------------
#[tokio::test]
async fn oracle_5_wrong_listen_pid_ignored_and_s5_no_env_vars_binds_fresh() {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let run_dir = tmp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();

    // Keep decoy_listener open in parent on decoy_addr, and reserve fresh_addr for --listen.
    let decoy_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let probe_fresh = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let fresh_addr = probe_fresh.local_addr().unwrap();
    drop(probe_fresh);

    let notify_path = run_dir.join("notify.sock");
    let notify_sock = StdUnixDatagram::bind(&notify_path).unwrap();

    let mut cmd = new_xmsg_cmd(false);
    cmd.env("XDG_RUNTIME_DIR", &run_dir)
        .env("HOME", &run_dir)
        .env("RUST_LOG", "info")
        .env("LISTEN_FDS", "1")
        .env("LISTEN_FDNAMES", "listen")
        .env("LISTEN_PID", "99999999") // wrong PID!
        .env("NOTIFY_SOCKET", &notify_path)
        .args([
            "serve",
            "--db-path",
            tmp.path().join("xmsg.db").to_str().unwrap(),
            "--sessions-dir",
            sessions_dir.to_str().unwrap(),
            "--register-sock",
            run_dir.join("register.sock").to_str().unwrap(),
            "--agent-sock",
            run_dir.join("agent.sock").to_str().unwrap(),
            "--http-sock",
            run_dir.join("http.sock").to_str().unwrap(),
            "--listen",
            &fresh_addr.to_string(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // Pass decoy_listener as fd 3, but do NOT overwrite LISTEN_PID with child PID
    configure_systemd_fds(&mut cmd, vec![decoy_listener.as_raw_fd()], false);
    let child = cmd.spawn().expect("spawn xmsg serve with wrong LISTEN_PID");
    drop(decoy_listener);
    let _guard = ChildGuard::new(child);

    let msg = tokio::task::spawn_blocking(move || {
        recv_notify_datagram(&notify_sock, Duration::from_secs(10))
    })
    .await
    .unwrap();
    assert_eq!(msg.trim(), "READY=1");

    // Daemon must have ignored fd 3 (decoy_listener) and bound fresh_addr!
    let mut stream = TcpStream::connect(fresh_addr)
        .await
        .expect("wrong LISTEN_PID must ignore fd 3 and bind fresh_addr");
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "resp: {resp}");
    drop(_guard);

    // S-5: Start with NO LISTEN_* or NOTIFY_SOCKET variables set
    let run_dir2 = tmp.path().join("run2");
    fs::create_dir_all(&run_dir2).unwrap();
    fs::set_permissions(&run_dir2, fs::Permissions::from_mode(0o700)).unwrap();
    let http_sock2 = run_dir2.join("http.sock");
    let child2 = new_xmsg_cmd(false)
        .env("XDG_RUNTIME_DIR", &run_dir2)
        .env("HOME", &run_dir2)
        .env_remove("LISTEN_FDS")
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDNAMES")
        .env_remove("NOTIFY_SOCKET")
        .args([
            "serve",
            "--db-path",
            tmp.path().join("xmsg2.db").to_str().unwrap(),
            "--sessions-dir",
            sessions_dir.to_str().unwrap(),
            "--register-sock",
            run_dir2.join("register.sock").to_str().unwrap(),
            "--agent-sock",
            run_dir2.join("agent.sock").to_str().unwrap(),
            "--http-sock",
            http_sock2.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn S-5 no-env xmsg serve");
    let _guard2 = ChildGuard::new(child2);

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(mut s) = UnixStream::connect(&http_sock2).await {
            s.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut resp = String::new();
            s.read_to_string(&mut resp).await.unwrap();
            assert!(resp.starts_with("HTTP/1.1 200 OK"));
            break;
        }
        assert!(Instant::now() < deadline, "S-5 fresh start timed out");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// -----------------------------------------------------------------------------
// Oracle 6: Wrong fd type (regular file, SOCK_DGRAM), S-1 bad/duplicate/unconfigured
// slot names, and S-2 address/path mismatches are refused with non-zero exit.
// -----------------------------------------------------------------------------
#[tokio::test]
async fn oracle_6_refuses_bad_fd_type_s1_bad_names_and_s2_addr_mismatch() {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let bin = env!("CARGO_BIN_EXE_xmsg");

    async fn run_expect_refusal(
        tmp: &Path,
        case_name: &str,
        raw_fd: i32,
        listen_fds: &str,
        fdnames: Option<&str>,
        extra_args: &[&str],
        expected_substr: &str,
    ) {
        let run_dir = tmp.join(case_name);
        fs::create_dir_all(&run_dir).unwrap();
        fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let sessions_dir = run_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).unwrap();

        let mut cmd = new_xmsg_cmd(true);
        cmd.env("XDG_RUNTIME_DIR", &run_dir)
            .env("HOME", &run_dir)
            .env("LISTEN_FDS", listen_fds);
        if let Some(names) = fdnames {
            cmd.env("LISTEN_FDNAMES", names);
        } else {
            cmd.env_remove("LISTEN_FDNAMES");
        }
        cmd.args([
            "serve",
            "--db-path",
            run_dir.join("xmsg.db").to_str().unwrap(),
            "--sessions-dir",
            sessions_dir.to_str().unwrap(),
            "--register-sock",
            run_dir.join("register.sock").to_str().unwrap(),
            "--agent-sock",
            run_dir.join("agent.sock").to_str().unwrap(),
            "--http-sock",
            run_dir.join("http.sock").to_str().unwrap(),
        ])
        .args(extra_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

        configure_systemd_fds(&mut cmd, vec![raw_fd], true);
        let out = tokio::time::timeout(Duration::from_secs(5), cmd.output())
            .await
            .expect("process must exit quickly on refusal")
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "case '{case_name}' must exit non-zero, got {:?}, stderr: {stderr}",
            out.status
        );
        assert!(
            stderr.contains(expected_substr),
            "case '{case_name}' expected stderr containing {expected_substr:?}, got: {stderr}"
        );
    }

    // 6a: Regular file passed as fd 3
    let reg_file = tempfile::NamedTempFile::new().unwrap();
    run_expect_refusal(
        tmp.path(),
        "case_regular_file",
        reg_file.as_raw_fd(),
        "1",
        Some("listen"),
        &["--listen", "127.0.0.1:0"],
        "not a socket",
    )
    .await;

    // 6b: SOCK_DGRAM UDP socket passed as fd 3
    let udp_sock = StdUdpSocket::bind("127.0.0.1:0").unwrap();
    run_expect_refusal(
        tmp.path(),
        "case_udp_dgram",
        udp_sock.as_raw_fd(),
        "1",
        Some("listen"),
        &["--listen", "127.0.0.1:0"],
        "SOCK_STREAM",
    )
    .await;

    // 6c: S-1 unknown alias name ("federation")
    let tcp_sock = StdTcpListener::bind("127.0.0.1:0").unwrap();
    run_expect_refusal(
        tmp.path(),
        "case_s1_unknown_alias",
        tcp_sock.as_raw_fd(),
        "1",
        Some("federation"),
        &["--listen", "127.0.0.1:0"],
        "unknown LISTEN_FDNAMES slot 'federation'",
    )
    .await;

    // 6d: S-1 unconfigured slot ("listen" passed when --listen is not set)
    run_expect_refusal(
        tmp.path(),
        "case_s1_unconfigured_slot",
        tcp_sock.as_raw_fd(),
        "1",
        Some("listen"),
        &[],
        "LISTEN_FDS provided slot 'listen', but --listen is not configured",
    )
    .await;

    // 6e: S-2 IP mismatch — 0.0.0.0 adopted vs 127.0.0.1 configured
    let wildcard_sock = StdTcpListener::bind("0.0.0.0:0").unwrap();
    let wildcard_port = wildcard_sock.local_addr().unwrap().port();
    run_expect_refusal(
        tmp.path(),
        "case_s2_ip_mismatch",
        wildcard_sock.as_raw_fd(),
        "1",
        Some("listen"),
        &["--listen", &format!("127.0.0.1:{wildcard_port}")],
        "does not match configured address",
    )
    .await;

    // 6f: S-2 Unix path mismatch
    let wrong_unix_path = tmp.path().join("wrong-http.sock");
    let wrong_unix = StdUnixListener::bind(&wrong_unix_path).unwrap();
    run_expect_refusal(
        tmp.path(),
        "case_s2_unix_path_mismatch",
        wrong_unix.as_raw_fd(),
        "1",
        Some("http"),
        &[],
        "does not match configured path",
    )
    .await;
    let _ = bin;
}
