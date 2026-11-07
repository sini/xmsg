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
    let notify_sock = Arc::new(StdUnixDatagram::bind(&notify_path).unwrap());

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
        let s = notify_sock.clone();
        move || recv_notify_datagram(&s, Duration::from_secs(10))
    })
    .await
    .unwrap();
    assert_eq!(msg.trim(), "READY=1", "expected READY=1 on NOTIFY_SOCKET");

    // C3: Verify FD_CLOEXEC (O_CLOEXEC = 0o2000000) was re-applied on adopted fd 3
    #[cfg(target_os = "linux")]
    {
        let child_pid = guard.child_mut().id().unwrap();
        let fdinfo_path = format!("/proc/{child_pid}/fdinfo/3");
        let fdinfo = fs::read_to_string(&fdinfo_path)
            .unwrap_or_else(|e| panic!("failed to read {fdinfo_path}: {e}"));
        let flags_octal = fdinfo
            .lines()
            .find_map(|line| line.strip_prefix("flags:").map(str::trim))
            .unwrap_or_else(|| panic!("missing flags: line in {fdinfo_path}: {fdinfo}"));
        let flags = u64::from_str_radix(flags_octal, 8).unwrap_or_else(|e| {
            panic!("invalid octal flags '{flags_octal}' in {fdinfo_path}: {e}")
        });
        assert_ne!(
            flags & 0o2000000,
            0,
            "adopted fd 3 in {fdinfo_path} must have O_CLOEXEC (0o2000000) set, got octal {flags_octal}"
        );
    }

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

    // Send SIGTERM and assert STOPPING=1 is emitted on NOTIFY_SOCKET
    let pid = guard.child_mut().id().unwrap() as i32;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let stop_msg = tokio::task::spawn_blocking({
        let s = notify_sock.clone();
        move || recv_notify_datagram(&s, Duration::from_secs(5))
    })
    .await
    .unwrap();
    assert_eq!(
        stop_msg.trim(),
        "STOPPING=1",
        "expected STOPPING=1 on NOTIFY_SOCKET after SIGTERM"
    );
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

    // Pre-bind two ephemeral TCP listeners and pass them via LISTEN_FDS=2 (LISTEN_FDNAMES=fed:listen)
    // while agent.sock, register.sock, and http.sock are freshly bound by xmsg serve.
    let p1 = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let fed_addr = p1.local_addr().unwrap();
    let p2 = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let http_tcp_addr = p2.local_addr().unwrap();

    let agent_sock = run_dir.join("agent.sock");
    let register_sock = run_dir.join("register.sock");
    let http_sock = run_dir.join("http.sock");
    let notify_path = run_dir.join("notify.sock");
    let notify_sock = StdUnixDatagram::bind(&notify_path).unwrap();

    let mut cmd = new_xmsg_cmd(true);
    cmd.env("XDG_RUNTIME_DIR", &run_dir)
        .env("HOME", &run_dir)
        .env("LISTEN_FDS", "2")
        .env("LISTEN_FDNAMES", "fed:listen")
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
        .stderr(std::process::Stdio::piped());
    configure_systemd_fds(&mut cmd, vec![p1.as_raw_fd(), p2.as_raw_fd()], true);
    let child = cmd.spawn().expect("spawn xmsg serve");
    drop(p1);
    drop(p2);
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

    // Use host-form SPIFFE URIs sharing user `alice` so same-user routes (/fed/v2/handoff and
    // /fed/v2/handoff/ack) reach their handler logic when peer1 is present and are gated on
    // peer membership when peer1 is removed.
    let uri_server = "spiffe://example.org/host/srv/user/alice";
    let (_s_der, _s_key, s_cert_pem, s_key_pem) =
        issue_cert(&ca1_params, &ca1_key, "alice.srv", &[uri_server]);

    let uri_peer1 = "spiffe://example.org/host/p1/user/alice";
    let (_p1_der, _p1_key, p1_cert_pem, p1_key_pem) =
        issue_cert(&ca1_params, &ca1_key, "alice.p1", &[uri_peer1]);

    let uri_peer2 = "spiffe://example.org/host/p2/user/alice";
    let (_p2_der, _p2_key, p2_cert_pem, p2_key_pem) =
        issue_cert(&ca2_params, &ca2_key, "alice.p2", &[uri_peer2]);

    let cert_path = tmp.path().join("server-cert.pem");
    let key_path = tmp.path().join("server-key.pem");
    let ca1_path = tmp.path().join("ca1.pem");
    let ca2_path = tmp.path().join("ca2.pem");
    let peers_path = tmp.path().join("peers.json");
    fs::write(&cert_path, &s_cert_pem).unwrap();
    fs::write(&key_path, &s_key_pem).unwrap();
    fs::write(&ca1_path, &ca1_pem).unwrap();
    fs::write(&ca2_path, &ca2_pem).unwrap();

    // Initially only alice.p1 is configured (with send, reply, list, and leaf=true)
    fs::write(
        &peers_path,
        serde_json::json!({
            "alice.p1": {
                "ca": ca1_path.display().to_string(),
                "identities": [uri_peer1],
                "allow": ["send", "reply", "list"],
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

    // Before reload: alice.p2 is not in peers.json => rejected
    let (_p2_tmp, p2_fs) = build_sender_fed_state(
        "alice.p2",
        "alice.srv",
        fed_addr,
        uri_server,
        &ca1_pem,
        &p2_cert_pem,
        &p2_key_pem,
    )
    .await;
    let env_before = make_envelope("recipient-reload", "before reload");
    assert!(
        send_federated_message(&p2_fs, "alice.srv", &env_before)
            .await
            .is_err(),
        "alice.p2 must be rejected before reload"
    );

    // Update peers.json to add alice.p2 and send SIGHUP
    fs::write(
        &peers_path,
        serde_json::json!({
            "alice.p1": {
                "ca": ca1_path.display().to_string(),
                "identities": [uri_peer1],
                "allow": ["send", "reply", "list"],
                "leaf": true
            },
            "alice.p2": {
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

    // Immediately after READY=1, alice.p2 is honoured!
    let env_after = make_envelope("recipient-reload", "after sighup reload");
    send_federated_message(&p2_fs, "alice.srv", &env_after)
        .await
        .expect("alice.p2 must succeed after SIGHUP reload READY=1");

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
    send_federated_message(&p2_fs, "alice.srv", &env_still_ok)
        .await
        .expect("previous configuration must remain active after failed reload");

    // Keep-alive `from` narrowing + peer revocation cell (C1 + `from` ruling):
    // 1. Open a persistent HTTP/1.1 keep-alive mTLS connection as alice.p1 and verify requests
    //    succeed before narrowing `from` or removing alice.p1.
    let (_p1_tmp, p1_fs) = build_sender_fed_state(
        "alice.p1",
        "alice.srv",
        fed_addr,
        uri_server,
        &ca1_pem,
        &p1_cert_pem,
        &p1_key_pem,
    )
    .await;
    let p1_peer_cfg = p1_fs.current_peers().get("alice.srv").unwrap().clone();
    let p1_connector = xmsg::fed::make_tls_connector_for_peer(&p1_fs, &p1_peer_cfg).unwrap();
    let p1_tcp = tokio::net::TcpStream::connect(fed_addr).await.unwrap();
    let p1_sni = rustls::pki_types::ServerName::try_from("alice.srv".to_string()).unwrap();
    let p1_tls = p1_connector.connect(p1_sni, p1_tcp).await.unwrap();
    let (mut p1_keepalive, p1_conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(p1_tls))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = p1_conn.await;
    });

    async fn send_ka(
        ka: &mut hyper::client::conn::http1::SendRequest<http_body_util::Full<bytes::Bytes>>,
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (u16, String) {
        let payload = body
            .map(|v| serde_json::to_vec(&v).unwrap())
            .unwrap_or_default();
        let req = hyper::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("host", "alice.srv")
            .body(http_body_util::Full::new(bytes::Bytes::from(payload)))
            .unwrap();
        let resp = ka.send_request(req).await.unwrap();
        let st = resp.status().as_u16();
        use http_body_util::BodyExt;
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        (st, String::from_utf8_lossy(&b).to_string())
    }

    let p1_env_before = make_envelope("recipient-reload", "peer1 before removal");
    let p1_deliv = send_federated_message(&p1_fs, "alice.srv", &p1_env_before)
        .await
        .expect("alice.p1 send must succeed before removal");
    let p1_msg_id = p1_deliv.message_id;
    xmsg::fed::poll_federated_replies(&p1_fs, "alice.srv", &p1_msg_id, 0, 0)
        .await
        .expect("alice.p1 replies poll must succeed before removal");
    xmsg::fed::get_federated_inbox(&p1_fs, "alice.srv", 0)
        .await
        .expect("alice.p1 inbox poll must succeed before removal");

    let ack_body = serde_json::json!({ "id": "gate-probe-none", "messages": [] });
    let ack_before = send_ka(
        &mut p1_keepalive,
        "POST",
        "/fed/v2/handoff/ack",
        Some(ack_body.clone()),
    )
    .await;
    assert_eq!(
        ack_before.0, 200,
        "positive control: present same-user peer alice.p1 reaches handoff/ack on keep-alive: {ack_before:?}"
    );

    // 2. Narrow `from` on alice.p1 to ["192.0.2.1/32"] by reload, send SIGHUP, and await
    //    RELOADING=1 -> READY=1. Existing keep-alive connection from 127.0.0.1 must be refused
    //    with 403 Forbidden (`not allowed for peer`).
    fs::write(
        &peers_path,
        serde_json::json!({
            "alice.p1": {
                "ca": ca1_path.display().to_string(),
                "identities": [uri_peer1],
                "allow": ["send", "reply", "list"],
                "from": ["192.0.2.1/32"],
                "leaf": true
            },
            "alice.p2": {
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
    let reloading_from = tokio::task::spawn_blocking({
        let s = notify_sock.clone();
        move || recv_notify_datagram(&s, Duration::from_secs(5))
    })
    .await
    .unwrap();
    assert!(
        reloading_from.starts_with("RELOADING=1\nMONOTONIC_USEC="),
        "expected RELOADING=1 on `from` narrowing reload, got: {reloading_from:?}"
    );
    let ready_from = tokio::task::spawn_blocking({
        let s = notify_sock.clone();
        move || recv_notify_datagram(&s, Duration::from_secs(5))
    })
    .await
    .unwrap();
    assert_eq!(ready_from.trim(), "READY=1");

    let from_narrowed_ack = send_ka(
        &mut p1_keepalive,
        "POST",
        "/fed/v2/handoff/ack",
        Some(ack_body.clone()),
    )
    .await;
    assert_eq!(
        from_narrowed_ack.0, 403,
        "keep-alive request must be refused with 403 when `from` is narrowed by reload: {from_narrowed_ack:?}"
    );
    assert!(
        from_narrowed_ack
            .1
            .contains("not allowed by peer 'from' CIDR rules"),
        "expected `not allowed by peer 'from' CIDR rules` in 403 body, got: {from_narrowed_ack:?}"
    );

    // 3. Rewrite peers.json to REMOVE alice.p1 (keeping alice.p2, plus a sibling peer alice.pk on
    //    ca1_path so ca1 remains an active CA anchor), send SIGHUP, and await RELOADING=1 -> READY=1.
    let uri_peer_keep = "spiffe://example.org/host/pk/user/alice";
    fs::write(
        &peers_path,
        serde_json::json!({
            "alice.pk": {
                "address": "127.0.0.1:9",
                "ca": ca1_path.display().to_string(),
                "identities": [uri_peer_keep],
                "allow": ["send", "reply"]
            },
            "alice.p2": {
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

    // 4. Immediately after READY=1, the removed alice.p1 must be refused with 404 (`unknown node`)
    //    across every /fed/v2/* route on its pre-existing HTTP/1.1 keep-alive connection, as well
    //    as on new connections.
    let env_val =
        serde_json::to_value(make_envelope("recipient-reload", "peer1 after removal")).unwrap();
    let ka_send = send_ka(&mut p1_keepalive, "POST", "/fed/v2/messages", Some(env_val)).await;
    assert_eq!(
        ka_send.0, 404,
        "removed peer on keep-alive POST /fed/v2/messages: {ka_send:?}"
    );
    assert!(ka_send.1.contains("unknown node"), "body: {ka_send:?}");

    let ka_handoff_ack = send_ka(
        &mut p1_keepalive,
        "POST",
        "/fed/v2/handoff/ack",
        Some(ack_body),
    )
    .await;
    assert_eq!(
        ka_handoff_ack.0, 404,
        "removed peer on keep-alive POST /fed/v2/handoff/ack: {ka_handoff_ack:?}"
    );
    assert!(
        ka_handoff_ack.1.contains("unknown node"),
        "body: {ka_handoff_ack:?}"
    );

    let ka_handoff = send_ka(
        &mut p1_keepalive,
        "POST",
        "/fed/v2/handoff",
        Some(serde_json::json!({ "id": "gate-probe-none" })),
    )
    .await;
    assert_eq!(
        ka_handoff.0, 404,
        "removed peer on keep-alive POST /fed/v2/handoff: {ka_handoff:?}"
    );
    assert!(
        ka_handoff.1.contains("unknown node"),
        "body: {ka_handoff:?}"
    );

    let ka_list_answer = send_ka(
        &mut p1_keepalive,
        "POST",
        "/fed/v2/list/q1",
        Some(serde_json::json!({ "sessions": [] })),
    )
    .await;
    assert_eq!(
        ka_list_answer.0, 404,
        "removed peer on keep-alive POST /fed/v2/list/q1: {ka_list_answer:?}"
    );
    assert!(
        ka_list_answer.1.contains("unknown node"),
        "body: {ka_list_answer:?}"
    );

    let ka_sessions = send_ka(&mut p1_keepalive, "GET", "/fed/v2/sessions", None).await;
    assert_eq!(
        ka_sessions.0, 404,
        "removed peer on keep-alive GET /fed/v2/sessions: {ka_sessions:?}"
    );
    assert!(
        ka_sessions.1.contains("unknown node"),
        "body: {ka_sessions:?}"
    );

    let ka_replies = send_ka(
        &mut p1_keepalive,
        "GET",
        &format!("/fed/v2/messages/{p1_msg_id}/replies?after=0&wait=0"),
        None,
    )
    .await;
    assert_eq!(
        ka_replies.0, 404,
        "removed peer on keep-alive GET /fed/v2/messages/{{id}}/replies: {ka_replies:?}"
    );
    assert!(
        ka_replies.1.contains("unknown node"),
        "body: {ka_replies:?}"
    );

    let ka_inbox = send_ka(&mut p1_keepalive, "GET", "/fed/v2/inbox?wait=0", None).await;
    assert_eq!(
        ka_inbox.0, 404,
        "removed peer on keep-alive GET /fed/v2/inbox: {ka_inbox:?}"
    );
    assert!(ka_inbox.1.contains("unknown node"), "body: {ka_inbox:?}");

    assert!(
        send_federated_message(&p1_fs, "alice.srv", &p1_env_before)
            .await
            .is_err(),
        "removed alice.p1 must be refused on new send connection after READY=1"
    );
    assert!(
        xmsg::fed::poll_federated_replies(&p1_fs, "alice.srv", &p1_msg_id, 0, 0)
            .await
            .is_err(),
        "removed alice.p1 must be refused on new replies connection after READY=1"
    );
    assert!(
        xmsg::fed::get_federated_inbox(&p1_fs, "alice.srv", 0)
            .await
            .is_err(),
        "removed alice.p1 must be refused on new inbox connection after READY=1"
    );

    // 5. Poisoned dynamic_tls lock cell:
    //    After a reload that removed alice.p1, even if a subsequent reloader panics while
    //    holding the dynamic_tls write lock (poisoning the RwLock), current_peers(), cert_chain(),
    //    key_der(), and get_tls_acceptor() must recover the last committed DynamicTls rather than
    //    falling back to the startup PeersMap (which still contained alice.p1).
    {
        use rustls::pki_types::pem::PemObject;
        let init_peers_json = serde_json::json!({
            "alice.p1": {
                "ca": ca1_path.display().to_string(),
                "identities": [uri_peer1],
                "allow": ["send", "reply"],
                "leaf": true
            },
            "alice.p2": {
                "address": "127.0.0.1:9",
                "ca": ca2_path.display().to_string(),
                "identities": [uri_peer2],
                "allow": ["send", "reply"]
            }
        });
        let init_peers_file = tmp.path().join("poison-peers.json");
        fs::write(&init_peers_file, init_peers_json.to_string()).unwrap();

        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(s_cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(s_key_pem.as_bytes()).unwrap();
        let cert_der = certs[0].to_vec();
        let cert_chain_der: Vec<Vec<u8>> = certs.into_iter().map(|c| c.to_vec()).collect();
        let key_der = key.secret_der().to_vec();
        let startup_pm = Arc::new(PeersMap::load_from_file_for(&init_peers_file, None).unwrap());

        let db_conn = rusqlite::Connection::open_in_memory().unwrap();
        xmsg::storage::init_db(&db_conn).unwrap();
        let (notify_tx, _) = tokio::sync::broadcast::channel(16);
        let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);
        let (svc_notify_tx, _) = tokio::sync::broadcast::channel(16);
        let poison_fs = Arc::new(FedState {
            node_name: "alice.srv".to_string(),
            peers: startup_pm.clone().into(),
            cert_der,
            cert_chain_der,
            key_der,
            rate_limiter: Arc::new(RateLimiter::new(60, 20)),
            db: Arc::new(Mutex::new(db_conn)),
            sessions_dirs: vec![],
            agy_config: xmsg::agy::AgyConfig::default(),
            agy_store: xmsg::agy::new_agy_store(),
            pi_store: xmsg::pi::new_pi_store(),
            pi_notify_tx,
            svc_store: xmsg::svc::new_svc_store(),
            svc_notify_tx,
            notify_tx,
            max_body: 65536,
            is_leaf: false,
            leaf_principal: None,
            outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
            dynamic_tls: Default::default(),
            reply_ttl: Duration::from_secs(600),
            list_queries: Default::default(),
        });
        let reloader = xmsg::fed::CredentialReloader::new_full(
            cert_path.clone(),
            key_path.clone(),
            Some(init_peers_file.clone()),
            None,
            startup_pm,
            poison_fs.dynamic_tls.clone(),
            Some(poison_fs.clone()),
            Arc::new(Mutex::new(std::collections::HashSet::new())),
        )
        .unwrap();
        assert!(poison_fs.current_peers().get("alice.p1").is_some());

        // Reload removing alice.p1
        fs::write(
            &init_peers_file,
            serde_json::json!({
                "alice.p2": {
                    "address": "127.0.0.1:9",
                    "ca": ca2_path.display().to_string(),
                    "identities": [uri_peer2],
                    "allow": ["send", "reply"]
                }
            })
            .to_string(),
        )
        .unwrap();
        reloader.force_reload().unwrap();
        assert!(poison_fs.current_peers().get("alice.p1").is_none());
        assert!(poison_fs.current_peers().get("alice.p2").is_some());

        // Poison dynamic_tls write lock
        let dtls = poison_fs.dynamic_tls.clone();
        let _ = std::thread::spawn(move || {
            let _guard = dtls.write().unwrap();
            panic!("simulated reloader panic while holding dynamic_tls write guard");
        })
        .join();
        assert!(
            poison_fs.dynamic_tls.read().is_err(),
            "dynamic_tls RwLock must be poisoned"
        );

        // Even while poisoned, current_peers() must still exclude removed alice.p1 and retain alice.p2
        assert!(
            poison_fs.current_peers().get("alice.p1").is_none(),
            "poisoned dynamic_tls must not fall back to startup peers containing removed alice.p1"
        );
        assert!(
            poison_fs.current_peers().get("alice.p2").is_some(),
            "poisoned dynamic_tls must still return last committed peers containing alice.p2"
        );
        assert!(
            poison_fs.get_tls_acceptor().is_some(),
            "poisoned dynamic_tls must still return last committed TlsAcceptor"
        );
    }
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
    drop(_guard2);

    // C4: `--listen localhost:<port>` without LISTEN_FDS resolves hostname and binds fresh
    let run_dir3 = tmp.path().join("run3");
    fs::create_dir_all(&run_dir3).unwrap();
    fs::set_permissions(&run_dir3, fs::Permissions::from_mode(0o700)).unwrap();
    let probe_localhost = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let localhost_port = probe_localhost.local_addr().unwrap().port();
    drop(probe_localhost);
    let notify_path3 = run_dir3.join("notify.sock");
    let notify_sock3 = StdUnixDatagram::bind(&notify_path3).unwrap();

    let child3 = new_xmsg_cmd(false)
        .env("XDG_RUNTIME_DIR", &run_dir3)
        .env("HOME", &run_dir3)
        .env_remove("LISTEN_FDS")
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDNAMES")
        .env("NOTIFY_SOCKET", &notify_path3)
        .args([
            "serve",
            "--db-path",
            tmp.path().join("xmsg3.db").to_str().unwrap(),
            "--sessions-dir",
            sessions_dir.to_str().unwrap(),
            "--register-sock",
            run_dir3.join("register.sock").to_str().unwrap(),
            "--agent-sock",
            run_dir3.join("agent.sock").to_str().unwrap(),
            "--http-sock",
            run_dir3.join("http.sock").to_str().unwrap(),
            "--listen",
            &format!("localhost:{localhost_port}"),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn --listen localhost:<port> xmsg serve");
    let _guard3 = ChildGuard::new(child3);

    let msg3 = tokio::task::spawn_blocking(move || {
        recv_notify_datagram(&notify_sock3, Duration::from_secs(10))
    })
    .await
    .unwrap();
    assert_eq!(msg3.trim(), "READY=1");

    let mut s3 = TcpStream::connect(format!("localhost:{localhost_port}"))
        .await
        .expect("connect to --listen localhost:<port>");
    s3.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp3 = String::new();
    s3.read_to_string(&mut resp3).await.unwrap();
    assert!(resp3.starts_with("HTTP/1.1 200 OK"), "resp3: {resp3}");
    drop(_guard3);

    // P2 (Ma): take_activated_sockets unsets LISTEN_FDS, LISTEN_PID, and LISTEN_FDNAMES from the
    // process environment so a child process spawned afterwards sees none of them.
    std::env::set_var("LISTEN_FDS", "1");
    std::env::set_var("LISTEN_PID", "99999999");
    std::env::set_var("LISTEN_FDNAMES", "listen");
    let reg_dummy = tmp.path().join("dummy-reg.sock");
    xmsg::systemd::take_activated_sockets(&xmsg::systemd::ActivatedConfig {
        fed_listen: None,
        listen: None,
        agent_sock: None,
        register_sock: &reg_dummy,
        http_sock: None,
    })
    .expect("take_activated_sockets with non-matching LISTEN_PID");

    let child_env_out = std::process::Command::new("sh")
        .arg("-c")
        .arg("printf '%s|%s|%s' \"${LISTEN_FDS-unset}\" \"${LISTEN_PID-unset}\" \"${LISTEN_FDNAMES-unset}\"")
        .output()
        .expect("spawn child to inspect inherited LISTEN_* env");
    assert_eq!(
        String::from_utf8_lossy(&child_env_out.stdout),
        "unset|unset|unset",
        "child process spawned after take_activated_sockets must not inherit LISTEN_FDS, LISTEN_PID, or LISTEN_FDNAMES"
    );
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

    // 6g: S-2 nonzero TCP port mismatch — 127.0.0.1:P1 adopted vs 127.0.0.1:P2 (P2 != P1, P2 != 0) configured
    let port_sock_1 = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let p1 = port_sock_1.local_addr().unwrap().port();
    let port_sock_2 = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let p2 = port_sock_2.local_addr().unwrap().port();
    assert_ne!(p1, p2);
    run_expect_refusal(
        tmp.path(),
        "case_s2_port_mismatch",
        port_sock_1.as_raw_fd(),
        "1",
        Some("listen"),
        &["--listen", &format!("127.0.0.1:{p2}")],
        "does not match configured address",
    )
    .await;
    let _ = bin;
}
