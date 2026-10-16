mod short_sock;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use serde_json::{json, Value};
use xmsg::agent::{resolve_caller_session_peer, run_agent_server_with_listener};
use xmsg::agy::{new_agy_store, AgyConfig};
use xmsg::fed::{generate_self_signed_ed25519_pem, normalize_pin};
use xmsg::http::{bind_ucred_unix_listener, build_router, AppState, HttpPeer};
use xmsg::pi::new_pi_store;
use xmsg::process::{self, Ancestry, WalkEnd};
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

fn get_free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind free port");
    listener.local_addr().expect("local addr").port()
}

fn write_fake_stat(proc_root: &Path, pid: u32, ppid: u32, starttime: &str) {
    let dir = proc_root.join(pid.to_string());
    fs::create_dir_all(&dir).unwrap();
    let stat = format!(
        "{pid} (fake) S {ppid} {pid} {pid} 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 {starttime} 1000000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
    );
    fs::write(dir.join("stat"), stat).unwrap();
}

#[test]
#[ignore]
fn xf1_socket_client_helper() {
    use std::io::{BufRead, Read, Write};
    use std::os::unix::net::UnixStream as StdUnixStream;

    let sock = std::env::var("XF1_SOCK").expect("XF1_SOCK");
    let payload = std::env::var("XF1_PAYLOAD").unwrap_or_default();
    let wait_before_connect =
        std::env::var("XF1_WAIT_BEFORE_CONNECT").unwrap_or_default() == "1";
    let read_resp = std::env::var("XF1_READ_RESP").unwrap_or_default() == "1";

    if wait_before_connect {
        println!("ready_to_connect");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).unwrap();
    }

    let mut stream = StdUnixStream::connect(&sock).expect("helper connect");
    if !payload.is_empty() {
        stream.write_all(payload.as_bytes()).unwrap();
        stream.flush().unwrap();
    }
    if read_resp {
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap_or(0);
        std::io::stdout().write_all(&buf[..n]).unwrap();
        std::io::stdout().flush().unwrap();
    }
}

fn spawn_std_socket_helper(
    sock: &Path,
    payload: &str,
    wait_before_connect: bool,
    read_resp: bool,
) -> tokio::process::Child {
    tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "xf1_socket_client_helper",
            "--ignored",
            "--nocapture",
            "--quiet",
        ])
        .env("XF1_SOCK", sock)
        .env("XF1_PAYLOAD", payload)
        .env(
            "XF1_WAIT_BEFORE_CONNECT",
            if wait_before_connect { "1" } else { "0" },
        )
        .env("XF1_READ_RESP", if read_resp { "1" } else { "0" })
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn_std_socket_helper")
}

async fn wait_for_ready_to_connect(stdout: &mut BufReader<tokio::process::ChildStdout>) {
    let mut line = String::new();
    loop {
        line.clear();
        let n = stdout.read_line(&mut line).await.unwrap();
        assert!(n > 0, "EOF before helper printed ready_to_connect");
        if line.trim() == "ready_to_connect" {
            break;
        }
    }
}

// =============================================================================
// Defect 1 Oracles: SO_PEERPIDFD pinning of Unix socket peer credentials
// =============================================================================

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_xf1_peerpidfd_rejects_reaped_recycled_root_pid_and_fallback() {
    // Ensure test seam starts clean.
    process::set_force_peerpidfd_errno_for_test(0);

    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let proc_root = tmp.path().join("proc");
    fs::create_dir_all(&proc_root).unwrap();

    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();

    // Victim Claude session at PID 500, starttime 1000, with a real inbox socket
    let victim_pid = 500u32;
    write_fake_stat(&proc_root, victim_pid, 1, "1000");
    let victim_inbox_sock = short_sock::sock_path(&sessions_dir, "victim");
    let _victim_listener = UnixListener::bind(&victim_inbox_sock).unwrap();
    let victim_json = json!({
        "pid": victim_pid,
        "sessionId": "sess-victim",
        "name": "Victim",
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": "1000",
        "messagingSocketPath": victim_inbox_sock.display().to_string()
    });
    fs::write(
        sessions_dir.join(format!("{victim_pid}-sess-victim.json")),
        victim_json.to_string(),
    )
    .unwrap();

    // Target Claude session at PID 600, starttime 2000, to receive messages
    let target_pid = 600u32;
    write_fake_stat(&proc_root, target_pid, 1, "2000");
    let target_inbox_sock = short_sock::sock_path(&sessions_dir, "target");
    let target_listener = UnixListener::bind(&target_inbox_sock).unwrap();
    let target_received = Arc::new(Mutex::new(Vec::<String>::new()));
    let target_rx = target_received.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = target_listener.accept().await {
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf).await;
            if let Ok(line) = String::from_utf8(buf) {
                target_rx.lock().unwrap().push(line);
            }
        }
    });
    let target_json = json!({
        "pid": target_pid,
        "sessionId": "sess-target",
        "name": "Target",
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": "2000",
        "messagingSocketPath": target_inbox_sock.display().to_string()
    });
    fs::write(
        sessions_dir.join(format!("{target_pid}-sess-target.json")),
        target_json.to_string(),
    )
    .unwrap();

    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: tmp.path().join("locks"),
        proc_root: proc_root.clone(),
        agy_bin: "false".to_string(),
        trusted_agy_exes: Vec::new(),
    };

    let db_conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&db_conn).unwrap();
    let db = Arc::new(Mutex::new(db_conn));

    let (notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(32);

    let state = Arc::new(AppState {
        sessions_dirs: vec![sessions_dir.clone()],
        max_body: 65536,
        request_counter: std::sync::atomic::AtomicU64::new(0),
        fed_state: None,
        db: db.clone(),
        notify_tx,
        pi_notify_tx,
        svc_notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        node_name: "node-test".to_string(),
        agy_config: agy_config.clone(),
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        svc_store: new_svc_store(),
    });

    // Pre-sync claims so sess-victim and sess-target are in the claim table.
    xmsg::claim::sync_claims(&db, &proc_root, &state.sessions_dirs[..], "node-test")
        .await
        .unwrap();

    // -------------------------------------------------------------------------
    // Part A: Direct Ancestry::from_peer + resolve_caller_session_peer oracle
    // when child C connects, exits, is reaped, and its PID P is planted in
    // proc_root with ppid = victim_pid.
    // -------------------------------------------------------------------------
    let raw_sock = short_sock::sock_path(tmp.path(), "raw");
    let raw_listener = UnixListener::bind(&raw_sock).unwrap();

    let mut child_a = spawn_std_socket_helper(&raw_sock, "", false, false);
    let pid_a = child_a.id().expect("child_a pid");
    let (accepted_a, _) = raw_listener.accept().await.unwrap();
    let peer_a = process::peer_cred(&accepted_a).expect("peer_cred on accepted socket");
    assert_eq!(peer_a.pid, Some(pid_a));

    // Reap child_a so its PID is dead and eligible for recycling.
    let status_a = child_a.wait().await.unwrap();
    assert!(status_a.success());

    // Plant a recycled proc_root/<pid_a>/stat entry whose ppid points to sess-victim (500)!
    write_fake_stat(&proc_root, pid_a, victim_pid, "9999");

    // Walk Ancestry::from_peer: because peer_a's pidfd refers to the reaped child_a,
    // peer_a.is_alive() MUST be false and the walk MUST stop with WalkEnd::Reused(pid_a)
    // before reading the planted proc_root/<pid_a>/stat!
    let mut walk = Ancestry::from_peer(&proc_root, &peer_a);
    assert!(
        walk.next().is_none(),
        "Ancestry::from_peer must yield no items for a reaped peer even with planted proc_root/<pid>/stat"
    );
    assert_eq!(
        walk.end(),
        Some(WalkEnd::Reused(pid_a)),
        "Ancestry::from_peer must record WalkEnd::Reused(pid) when pidfd signals ESRCH"
    );

    let db_guard = db.lock().unwrap();
    let res_peer = resolve_caller_session_peer(
        &proc_root,
        &state.sessions_dirs[..],
        &agy_config,
        &state.agy_store,
        &state.pi_store,
        &state.svc_store,
        Some(&*db_guard),
        &peer_a,
    );
    drop(db_guard);
    assert!(
        res_peer.is_err(),
        "resolve_caller_session_peer must reject reaped peer with planted recycled proc entry, got: {res_peer:?}"
    );

    // -------------------------------------------------------------------------
    // Part B: End-to-end socket oracle on agent.sock AND http.sock
    // Pre-bind `agent.sock` and `http.sock` listeners so a short-lived child can
    // connect, write its request into the kernel socket buffer, and exit + be reaped
    // deterministically before the server accepts and walks `proc_root`, while a
    // recycled `<proc_root>/<P>/stat` entry with `ppid = victim_pid` is present.
    // -------------------------------------------------------------------------
    let agent_sock = short_sock::sock_path(tmp.path(), "agent");
    let uid = xmsg::agy::current_uid();
    let agent_listener = UnixListener::bind(&agent_sock).unwrap();
    fs::set_permissions(&agent_sock, fs::Permissions::from_mode(0o600)).unwrap();

    let http_sock = short_sock::sock_path(tmp.path(), "http");
    let http_listener = bind_ucred_unix_listener(&http_sock, uid, None).unwrap();

    {
        let mut child_agent = spawn_std_socket_helper(
            &agent_sock,
            "{\"action\":\"send\",\"to\":\"Target\",\"text\":\"forged-via-agent-sock\"}\n",
            false,
            false,
        );
        let pid_agent = child_agent.id().expect("pid_agent");
        let status_agent = child_agent.wait().await.unwrap();
        assert!(status_agent.success());
        write_fake_stat(&proc_root, pid_agent, victim_pid, "8888");
    }

    // Also test `http.sock` under the same race window: short-lived child sends HTTP POST /v1/messages
    // without a `from` field (so only an attested caller would be attributed to `sess-victim`; an
    // unattested caller is anonymous and rejected with 400 `'from' is required`).
    {
        let body = "{\"to\":\"Target\",\"text\":\"forged-via-http-sock\"}";
        let req = format!(
            "POST /v1/messages HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let mut child_http = spawn_std_socket_helper(&http_sock, &req, false, false);
        let pid_http = child_http.id().expect("pid_http");
        let status_http = child_http.wait().await.unwrap();
        assert!(status_http.success());
        write_fake_stat(&proc_root, pid_http, victim_pid, "7777");
    }

    // Now start both server accept loops to process the buffered connections from the reaped peers.
    let state_for_agent = state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server_with_listener(agent_listener, state_for_agent, uid).await;
    });

    let app = build_router(state.clone());
    tokio::spawn(async move {
        let make_svc = app.into_make_service_with_connect_info::<HttpPeer>();
        let _ = axum::serve(http_listener, make_svc).await;
    });

    // Wait briefly for both server handlers to process the buffered connections.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Neither forged message may have been delivered to Target!
    {
        let msgs = target_received.lock().unwrap();
        assert!(
            msgs.is_empty(),
            "neither agent.sock nor http.sock may attribute a reaped caller with recycled proc entry to sess-victim; got deliveries: {msgs:?}"
        );
    }

    // -------------------------------------------------------------------------
    // Part C: Positive control — a live child C2 whose proc_root entry descends
    // from sess-victim stays alive until the server responds, and succeeds!
    // -------------------------------------------------------------------------
    let mut live_child = spawn_std_socket_helper(
        &agent_sock,
        "{\"action\":\"send\",\"to\":\"Target\",\"text\":\"legit-from-live-child\"}\n",
        true,
        true,
    );
    let live_pid = live_child.id().expect("live_child pid");
    let mut live_stdout = BufReader::new(live_child.stdout.take().unwrap());
    let mut live_stdin = live_child.stdin.take().unwrap();
    wait_for_ready_to_connect(&mut live_stdout).await;

    // Plant live_pid in proc_root as a child of victim_pid BEFORE live_child connects!
    write_fake_stat(&proc_root, live_pid, victim_pid, "5555");
    live_stdin.write_all(b"go\n").await.unwrap();

    let mut resp_line = String::new();
    loop {
        resp_line.clear();
        let n = live_stdout.read_line(&mut resp_line).await.unwrap();
        assert!(n > 0, "EOF before helper printed response JSON");
        if resp_line.trim().starts_with('{') {
            break;
        }
    }
    let resp_json: Value =
        serde_json::from_str(resp_line.trim()).expect("live child response json");
    assert_eq!(
        resp_json["status"], "ok",
        "live child under sess-victim must be attested and succeed: {resp_json}"
    );
    let _ = live_child.wait().await;

    // Target must have received the legitimate message attributed to Victim (sess-victim)!
    tokio::time::sleep(Duration::from_millis(50)).await;
    {
        let msgs = target_received.lock().unwrap();
        assert_eq!(
            msgs.len(),
            1,
            "Target should have exactly 1 legitimate message"
        );
        assert!(
            msgs[0].contains("legit-from-live-child") && msgs[0].contains("sess-victim@node-test"),
            "Legitimate message must be attributed to sess-victim, got: {}",
            msgs[0]
        );
    }

    // -------------------------------------------------------------------------
    // Part D: Fallback cell — when SO_PEERPIDFD is unavailable (ENOPROTOOPT),
    // peer_cred falls back to SO_PEERCRED, logs once, and still attests a live caller.
    // -------------------------------------------------------------------------
    process::set_force_peerpidfd_errno_for_test(libc::ENOPROTOOPT);
    let (s1, _s2) = UnixStream::pair().unwrap();
    let my_pid = std::process::id();
    write_fake_stat(&proc_root, my_pid, victim_pid, "4444");
    let fallback_peer = process::peer_cred(&s1).expect("peer_cred under ENOPROTOOPT fallback");
    process::set_force_peerpidfd_errno_for_test(0);

    assert_eq!(fallback_peer.pid, Some(my_pid));
    assert!(
        process::peerpidfd_fallback_warned_for_test(),
        "ENOPROTOOPT fallback must trip the warn-once flag"
    );
    let db_guard = db.lock().unwrap();
    let fallback_session = resolve_caller_session_peer(
        &proc_root,
        &state.sessions_dirs[..],
        &agy_config,
        &state.agy_store,
        &state.pi_store,
        &state.svc_store,
        Some(&*db_guard),
        &fallback_peer,
    )
    .expect("fallback PeerCred must still resolve live caller via proc_root");
    drop(db_guard);
    assert_eq!(fallback_session.session_id, "sess-victim");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_xf1_live_peer_cred_attests_caller() {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let proc_root = tmp.path().join("proc");
    fs::create_dir_all(&proc_root).unwrap();

    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();

    let victim_pid = 500u32;
    write_fake_stat(&proc_root, victim_pid, 1, "1000");
    let victim_inbox_sock = short_sock::sock_path(&sessions_dir, "victim");
    let _victim_listener = UnixListener::bind(&victim_inbox_sock).unwrap();
    let victim_json = json!({
        "pid": victim_pid,
        "sessionId": "sess-victim",
        "name": "Victim",
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": "1000",
        "messagingSocketPath": victim_inbox_sock.display().to_string()
    });
    fs::write(
        sessions_dir.join(format!("{victim_pid}-sess-victim.json")),
        victim_json.to_string(),
    )
    .unwrap();

    let target_pid = 600u32;
    write_fake_stat(&proc_root, target_pid, 1, "2000");
    let target_inbox_sock = short_sock::sock_path(&sessions_dir, "target");
    let target_listener = UnixListener::bind(&target_inbox_sock).unwrap();
    let target_received = Arc::new(Mutex::new(Vec::<String>::new()));
    let target_rx = target_received.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = target_listener.accept().await {
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf).await;
            if let Ok(line) = String::from_utf8(buf) {
                target_rx.lock().unwrap().push(line);
            }
        }
    });
    let target_json = json!({
        "pid": target_pid,
        "sessionId": "sess-target",
        "name": "Target",
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": "2000",
        "messagingSocketPath": target_inbox_sock.display().to_string()
    });
    fs::write(
        sessions_dir.join(format!("{target_pid}-sess-target.json")),
        target_json.to_string(),
    )
    .unwrap();

    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: tmp.path().join("locks"),
        proc_root: proc_root.clone(),
        agy_bin: "false".to_string(),
        trusted_agy_exes: Vec::new(),
    };

    let db_conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&db_conn).unwrap();
    let db = Arc::new(Mutex::new(db_conn));

    let (notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(32);

    let state = Arc::new(AppState {
        sessions_dirs: vec![sessions_dir.clone()],
        max_body: 65536,
        request_counter: std::sync::atomic::AtomicU64::new(0),
        fed_state: None,
        db: db.clone(),
        notify_tx,
        pi_notify_tx,
        svc_notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        node_name: "node-test".to_string(),
        agy_config: agy_config.clone(),
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        svc_store: new_svc_store(),
    });

    xmsg::claim::sync_claims(&db, &proc_root, &state.sessions_dirs[..], "node-test")
        .await
        .unwrap();

    // 1. Direct `process::peer_cred` + `Ancestry::from_peer` + `resolve_caller_session_peer`
    // while the peer process is alive with its socket open (`read_resp = true`).
    let raw_sock = short_sock::sock_path(tmp.path(), "raw_live");
    let raw_listener = UnixListener::bind(&raw_sock).unwrap();
    let mut child_raw = spawn_std_socket_helper(&raw_sock, "ping\n", true, true);
    let pid_raw = child_raw.id().expect("child_raw pid");
    let mut raw_stdout = BufReader::new(child_raw.stdout.take().unwrap());
    let mut raw_stdin = child_raw.stdin.take().unwrap();
    wait_for_ready_to_connect(&mut raw_stdout).await;
    write_fake_stat(&proc_root, pid_raw, victim_pid, "3333");
    raw_stdin.write_all(b"go\n").await.unwrap();

    let (mut accepted_raw, _) = raw_listener.accept().await.unwrap();
    let peer_raw = process::peer_cred(&accepted_raw).expect("peer_cred on live accepted socket");
    assert_eq!(peer_raw.uid, xmsg::agy::current_uid());
    assert_eq!(peer_raw.pid, Some(pid_raw));

    let mut walk = Ancestry::from_peer(&proc_root, &peer_raw);
    let steps: Vec<(u32, String)> = walk.by_ref().collect();
    assert_eq!(
        steps,
        vec![(pid_raw, "3333".to_string()), (victim_pid, "1000".to_string())]
    );
    assert_eq!(walk.end(), Some(WalkEnd::Root));

    let db_guard = db.lock().unwrap();
    let resolved = resolve_caller_session_peer(
        &proc_root,
        &state.sessions_dirs[..],
        &agy_config,
        &state.agy_store,
        &state.pi_store,
        &state.svc_store,
        Some(&*db_guard),
        &peer_raw,
    )
    .expect("live peer must resolve to sess-victim");
    drop(db_guard);
    assert_eq!(resolved.session_id, "sess-victim");

    accepted_raw.write_all(b"pong\n").await.unwrap();
    drop(accepted_raw);
    let _ = child_raw.wait().await;

    // 2. End-to-end live peer attestation over `agent.sock` and `http.sock`.
    let agent_sock = short_sock::sock_path(tmp.path(), "agent_live");
    let uid = xmsg::agy::current_uid();
    let agent_listener = UnixListener::bind(&agent_sock).unwrap();
    fs::set_permissions(&agent_sock, fs::Permissions::from_mode(0o600)).unwrap();

    let http_sock = short_sock::sock_path(tmp.path(), "http_live");
    let http_listener = bind_ucred_unix_listener(&http_sock, uid, None).unwrap();

    let state_for_agent = state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server_with_listener(agent_listener, state_for_agent, uid).await;
    });

    let app = build_router(state.clone());
    tokio::spawn(async move {
        let make_svc = app.into_make_service_with_connect_info::<HttpPeer>();
        let _ = axum::serve(http_listener, make_svc).await;
    });

    // Live child on agent.sock
    let mut live_agent = spawn_std_socket_helper(
        &agent_sock,
        "{\"action\":\"send\",\"to\":\"Target\",\"text\":\"legit-via-agent-sock\"}\n",
        true,
        true,
    );
    let live_agent_pid = live_agent.id().expect("live_agent pid");
    let mut agent_stdout = BufReader::new(live_agent.stdout.take().unwrap());
    let mut agent_stdin = live_agent.stdin.take().unwrap();
    wait_for_ready_to_connect(&mut agent_stdout).await;
    write_fake_stat(&proc_root, live_agent_pid, victim_pid, "5555");
    agent_stdin.write_all(b"go\n").await.unwrap();

    let mut resp_line = String::new();
    loop {
        resp_line.clear();
        let n = agent_stdout.read_line(&mut resp_line).await.unwrap();
        assert!(n > 0, "EOF before helper printed response JSON");
        if resp_line.trim().starts_with('{') {
            break;
        }
    }
    let resp_json: Value = serde_json::from_str(resp_line.trim()).unwrap();
    assert_eq!(resp_json["status"], "ok", "{resp_json}");
    let _ = live_agent.wait().await;

    // Live child on http.sock (no `from` field, so attestation via `HttpPeer` is required)
    let body = "{\"to\":\"Target\",\"text\":\"legit-via-http-sock\"}";
    let req = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let mut live_http = spawn_std_socket_helper(&http_sock, &req, true, true);
    let live_http_pid = live_http.id().expect("live_http pid");
    let mut http_stdout = BufReader::new(live_http.stdout.take().unwrap());
    let mut http_stdin = live_http.stdin.take().unwrap();
    wait_for_ready_to_connect(&mut http_stdout).await;
    write_fake_stat(&proc_root, live_http_pid, victim_pid, "6666");
    http_stdin.write_all(b"go\n").await.unwrap();

    let mut http_resp = String::new();
    http_stdout.read_to_string(&mut http_resp).await.unwrap();
    assert!(
        http_resp.contains("202 Accepted") && http_resp.contains("\"outcome\":\"delivered\""),
        "live child on http.sock must be attested and get 202 Accepted, got: {http_resp}"
    );
    let _ = live_http.wait().await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    let msgs = target_received.lock().unwrap();
    assert_eq!(msgs.len(), 2, "Target should receive both messages: {msgs:?}");
    assert!(msgs[0].contains("legit-via-agent-sock") && msgs[0].contains("sess-victim@node-test"));
    assert!(msgs[1].contains("legit-via-http-sock") && msgs[1].contains("sess-victim@node-test"));
}

// =============================================================================
// Defect 2 Oracles: Bidirectional multi-turn replies across dial-out links
// =============================================================================

#[allow(dead_code)]
struct TestNode {
    _tmp: TempDir,
    name: String,
    fed_port: u16,
    http_port: u16,
    agent_sock: PathBuf,
    http_sock: PathBuf,
    sessions_dir: PathBuf,
    db_path: PathBuf,
    stderr_path: PathBuf,
    child: ChildGuard,
}

async fn spawn_test_node(
    name: &str,
    fed_port: u16,
    http_port: u16,
    cert_pem: &str,
    key_pem: &str,
    peers_json: Value,
) -> TestNode {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let cert_file = tmp.path().join("cert.pem");
    let key_file = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");
    let db_path = tmp.path().join("node.db");
    let stderr_path = tmp.path().join("stderr.log");

    fs::write(&cert_file, cert_pem.as_bytes()).unwrap();
    fs::write(&key_file, key_pem.as_bytes()).unwrap();
    fs::write(&peers_file, peers_json.to_string()).unwrap();

    let run_dir = tmp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let agent_sock = run_dir.join("agent.sock");
    let register_sock = run_dir.join("register.sock");
    let http_sock = run_dir.join("http.sock");
    let stderr_file = fs::File::create(&stderr_path).unwrap();
    let stdout_file = stderr_file.try_clone().unwrap();

    let bin = env!("CARGO_BIN_EXE_xmsg");
    let child = tokio::process::Command::new(bin)
        .env("RUST_LOG", "info")
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env("HOME", &run_dir)
        .args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{http_port}"),
            "--fed-listen",
            &format!("127.0.0.1:{fed_port}"),
            "--peers-file",
            peers_file.to_str().unwrap(),
            "--fed-cert",
            cert_file.to_str().unwrap(),
            "--fed-key",
            key_file.to_str().unwrap(),
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
        ])
        .stdout(std::process::Stdio::from(stdout_file))
        .stderr(std::process::Stdio::from(stderr_file))
        .spawn()
        .expect("spawn test node");

    let mut guard = ChildGuard::new(child);

    let mut ready = false;
    for _ in 0..600 {
        if guard.child_mut().try_wait().unwrap().is_some() {
            break;
        }
        if agent_sock.exists()
            && tokio::net::TcpStream::connect(("127.0.0.1", fed_port))
                .await
                .is_ok()
            && tokio::net::TcpStream::connect(("127.0.0.1", http_port))
                .await
                .is_ok()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        ready,
        "node {name} failed to start; stderr: {}",
        fs::read_to_string(&stderr_path).unwrap_or_default()
    );

    TestNode {
        _tmp: tmp,
        name: name.to_string(),
        fed_port,
        http_port,
        agent_sock,
        http_sock,
        sessions_dir,
        db_path,
        stderr_path,
        child: guard,
    }
}

fn create_claude_session_fixture(
    sessions_dir: &Path,
    session_id: &str,
    name: &str,
) -> (PathBuf, Arc<Mutex<Vec<String>>>) {
    let sock_path = short_sock::sock_path(sessions_dir, "inbox");
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
    let session_json = json!({
        "pid": my_pid,
        "sessionId": session_id,
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

async fn pop_inbox_message(
    received: &Arc<Mutex<Vec<String>>>,
    timeout_dur: Duration,
) -> Option<String> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout_dur {
        {
            let mut guard = received.lock().unwrap();
            if !guard.is_empty() {
                return Some(guard.remove(0));
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

async fn send_via_agent_sock(agent_sock: &Path, target_ref: &str, text: &str) -> Value {
    let stream = UnixStream::connect(agent_sock).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let req = json!({
        "action": "send",
        "to": target_ref,
        "text": text,
    });
    writer
        .write_all(format!("{req}\n").as_bytes())
        .await
        .unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    serde_json::from_str(&line).unwrap()
}

async fn reply_via_agent_sock(agent_sock: &Path, message_id: &str, text: &str) -> Value {
    let stream = UnixStream::connect(agent_sock).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let req = json!({
        "action": "reply",
        "message_id": message_id,
        "text": text,
    });
    writer
        .write_all(format!("{req}\n").as_bytes())
        .await
        .unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    serde_json::from_str(&line).unwrap()
}

fn extract_message_id(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(pos) = line.find("message_id=") {
            let rest = &line[pos + 11..];
            let id = rest.split_whitespace().next().unwrap_or("");
            if !id.is_empty() {
                return Some(id.to_string());
            }
        }
    }
    None
}

fn extract_reply_id(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(pos) = line.rfind("message_id=") {
            let rest = &line[pos + 11..];
            let id = rest.split([';', ' ', '\n']).next().unwrap_or("");
            if !id.is_empty() {
                return Some(id.to_string());
            }
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_xf1_dial_out_pulled_reply_answerable_end_to_end() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519_pem("node-a").unwrap();
    let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

    let port_a = get_free_port();
    let http_a = get_free_port();
    let port_b = get_free_port();
    let http_b = get_free_port();

    let peers_a = json!({
        "peers": {
            "node-b": {
                "address": format!("127.0.0.1:{port_b}"),
                "pin": normalize_pin(&pin_b),
                "dial": "outbound",
                "allow": ["send", "reply", "inbox"]
            }
        }
    });

    let peers_b = json!({
        "peers": {
            "node-a": {
                "pin": normalize_pin(&pin_a),
                "leaf": true,
                "allow": ["send", "reply", "inbox"]
            }
        }
    });

    let node_b = spawn_test_node("node-b", port_b, http_b, &cert_b, &key_b, peers_b).await;
    let node_a = spawn_test_node("node-a", port_a, http_a, &cert_a, &key_a, peers_a).await;

    let (_sock_a, rx_a) = create_claude_session_fixture(&node_a.sessions_dir, "alice", "Alice");
    let (_sock_b, rx_b) = create_claude_session_fixture(&node_b.sessions_dir, "bob", "Bob");

    // -------------------------------------------------------------------------
    // Direction 1 (4 turns):
    // Turn 1: Alice@node-a (dial-out) sends M to Bob@node-b
    // -------------------------------------------------------------------------
    let send_m =
        send_via_agent_sock(&node_a.agent_sock, "Bob@node-b", "Turn 1: Alice -> Bob").await;
    assert_eq!(send_m["status"], "ok", "Turn 1 send failed: {send_m}");

    let b_m = pop_inbox_message(&rx_b, Duration::from_secs(5))
        .await
        .expect("Bob must receive Turn 1 message M");
    assert!(b_m.contains("Turn 1: Alice -> Bob"));
    let m_id = extract_message_id(&b_m).expect("extract M id");

    // -------------------------------------------------------------------------
    // Turn 2: Bob@node-b replies R1 to M (stored on B, pulled by A's poller)
    // -------------------------------------------------------------------------
    let reply_r1 =
        reply_via_agent_sock(&node_b.agent_sock, &m_id, "Turn 2: Bob -> Alice R1").await;
    assert_eq!(reply_r1["status"], "ok", "Turn 2 reply failed: {reply_r1}");
    assert_eq!(reply_r1["reply"]["pushOutcome"], "stored");
    let r1_id_on_b = reply_r1["reply"]["pushedMessageId"]
        .as_str()
        .expect("Node B must populate pushedMessageId on stored reply R1")
        .to_string();

    let a_r1 = pop_inbox_message(&rx_a, Duration::from_secs(5))
        .await
        .expect("Alice must receive pulled reply R1");
    assert!(a_r1.contains("Turn 2: Bob -> Alice R1"));
    let r1_id_on_a = extract_reply_id(&a_r1).expect("extract R1 id on Node A");
    assert_eq!(
        r1_id_on_a, r1_id_on_b,
        "Node A and Node B must agree on authoritative R1_id (no {m_id}-1 fabrication)"
    );

    // -------------------------------------------------------------------------
    // Turn 3: Alice@node-a replies R2 to R1_id (pushed over outbound TLS to B)
    // -------------------------------------------------------------------------
    let reply_r2 =
        reply_via_agent_sock(&node_a.agent_sock, &r1_id_on_a, "Turn 3: Alice -> Bob R2").await;
    assert_eq!(reply_r2["status"], "ok", "Turn 3 reply failed: {reply_r2}");
    assert_eq!(
        reply_r2["reply"]["pushOutcome"], "pushed",
        "Alice's reply R2 to pulled reply R1 must be pushed to Bob on Node B: {reply_r2}"
    );
    let r2_id = reply_r2["reply"]["pushedMessageId"]
        .as_str()
        .expect("R2 pushedMessageId")
        .to_string();

    let b_r2 = pop_inbox_message(&rx_b, Duration::from_secs(5))
        .await
        .expect("Bob must receive Alice's reply R2 in his inbox");
    assert!(b_r2.contains("Turn 3: Alice -> Bob R2"));
    let b_r2_id = extract_reply_id(&b_r2).expect("extract R2 id on Node B");
    assert_eq!(b_r2_id, r2_id);

    // -------------------------------------------------------------------------
    // Turn 4: Bob@node-b replies R3 to R2_id (stored on B, pulled by A's poller
    // that was armed when Alice pushed R2!)
    // -------------------------------------------------------------------------
    let reply_r3 =
        reply_via_agent_sock(&node_b.agent_sock, &b_r2_id, "Turn 4: Bob -> Alice R3").await;
    assert_eq!(reply_r3["status"], "ok", "Turn 4 reply failed: {reply_r3}");
    assert_eq!(reply_r3["reply"]["pushOutcome"], "stored");
    let r3_id_on_b = reply_r3["reply"]["pushedMessageId"]
        .as_str()
        .expect("R3 pushedMessageId on B")
        .to_string();

    let a_r3 = pop_inbox_message(&rx_a, Duration::from_secs(5))
        .await
        .expect(
            "Alice must receive Bob's Turn 4 reply R3 via outbound reply poller armed on R2_id",
        );
    assert!(a_r3.contains("Turn 4: Bob -> Alice R3"));
    let r3_id_on_a = extract_reply_id(&a_r3).expect("extract R3 id on Node A");
    assert_eq!(r3_id_on_a, r3_id_on_b);

    // -------------------------------------------------------------------------
    // Direction 2 (Reverse: Listener B -> Dial-out A):
    // Bob@node-b sends M2 to Alice@node-a (enqueued on B, pulled by A's inbox loop);
    // Alice@node-a replies R4 to M2 (pushed to Bob@node-b AND arms reply poller on R4_id);
    // Bob@node-b replies R5 to R4_id (stored on B, pulled by A's poller into Alice's inbox).
    // -------------------------------------------------------------------------
    let send_m2 =
        send_via_agent_sock(&node_b.agent_sock, "Alice@node-a", "Rev 1: Bob -> Alice M2").await;
    assert_eq!(send_m2["status"], "ok", "Rev 1 send failed: {send_m2}");

    let a_m2 = pop_inbox_message(&rx_a, Duration::from_secs(5))
        .await
        .expect("Alice must pull M2 from Node B");
    assert!(a_m2.contains("Rev 1: Bob -> Alice M2"));
    let m2_id = extract_message_id(&a_m2).expect("extract M2 id");

    let reply_r4 =
        reply_via_agent_sock(&node_a.agent_sock, &m2_id, "Rev 2: Alice -> Bob R4").await;
    assert_eq!(reply_r4["status"], "ok", "Rev 2 reply failed: {reply_r4}");
    assert_eq!(reply_r4["reply"]["pushOutcome"], "pushed");
    let r4_id = reply_r4["reply"]["pushedMessageId"]
        .as_str()
        .expect("R4 pushedMessageId")
        .to_string();

    let b_r4 = pop_inbox_message(&rx_b, Duration::from_secs(5))
        .await
        .expect("Bob must receive R4 in his inbox");
    assert!(b_r4.contains("Rev 2: Alice -> Bob R4"));
    let b_r4_id = extract_reply_id(&b_r4).expect("extract R4 id on B");
    assert_eq!(b_r4_id, r4_id);

    let reply_r5 =
        reply_via_agent_sock(&node_b.agent_sock, &b_r4_id, "Rev 3: Bob -> Alice R5").await;
    assert_eq!(reply_r5["status"], "ok", "Rev 3 reply failed: {reply_r5}");
    assert_eq!(reply_r5["reply"]["pushOutcome"], "stored");
    let r5_id_on_b = reply_r5["reply"]["pushedMessageId"]
        .as_str()
        .expect("R5 pushedMessageId on B")
        .to_string();

    let a_r5 = pop_inbox_message(&rx_a, Duration::from_secs(5))
        .await
        .expect("Alice must receive R5 via outbound reply poller armed on R4_id");
    assert!(a_r5.contains("Rev 3: Bob -> Alice R5"));
    let r5_id_on_a = extract_reply_id(&a_r5).expect("extract R5 id on A");
    assert_eq!(r5_id_on_a, r5_id_on_b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_xf1_dial_out_anonymous_stored_reply_and_poller_refuses_unid_reply() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519_pem("node-a").unwrap();
    let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

    let port_a = get_free_port();
    let http_a = get_free_port();
    let port_b = get_free_port();
    let http_b = get_free_port();

    let peers_a = json!({
        "peers": {
            "node-b": {
                "address": format!("127.0.0.1:{port_b}"),
                "pin": normalize_pin(&pin_b),
                "dial": "outbound",
                "allow": ["send", "reply", "inbox"]
            }
        }
    });

    let peers_b = json!({
        "peers": {
            "node-a": {
                "pin": normalize_pin(&pin_a),
                "leaf": true,
                "allow": ["send", "reply", "inbox"]
            }
        }
    });

    let node_b = spawn_test_node("node-b", port_b, http_b, &cert_b, &key_b, peers_b).await;
    let node_a = spawn_test_node("node-a", port_a, http_a, &cert_a, &key_a, peers_a).await;

    // Create Bob on Node B, and Alice on Node A (created AFTER the anonymous HTTP send so the
    // test process's PID is not traced to Alice during the anonymous HTTP send).
    let (_sock_b, rx_b) = create_claude_session_fixture(&node_b.sessions_dir, "bob", "Bob");

    // -------------------------------------------------------------------------
    // Cell 2a: Anonymous sender on dial-out Node A (`dest_session_id == None`).
    // Sends via TCP HTTP `POST /v1/messages` with `"from": "anon-probe"`.
    // Bob replies on Node B: `push_outcome` is `"stored"`, `pushed_message_id` is `None`,
    // no `messages` or `outbound` row is created for the reply on Node B, and the
    // anonymous sender reads the reply via `GET /v1/messages/{id}/replies`.
    // -------------------------------------------------------------------------
    let client = reqwest::Client::new();
    let send_resp: Value = client
        .post(format!("http://127.0.0.1:{http_a}/v1/messages"))
        .json(&json!({
            "to": "Bob@node-b",
            "from": "anon-probe",
            "text": "hello from anonymous on dial-out node-a"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let anon_msg_id = send_resp["message_id"]
        .as_str()
        .expect("anon message_id")
        .to_string();

    let b_anon = pop_inbox_message(&rx_b, Duration::from_secs(5))
        .await
        .expect("Bob must receive anonymous message from node-a");
    assert!(b_anon.contains("hello from anonymous on dial-out node-a"));

    let bob_reply = reply_via_agent_sock(
        &node_b.agent_sock,
        &anon_msg_id,
        "reply to anonymous sender",
    )
    .await;
    assert_eq!(
        bob_reply["status"], "ok",
        "Bob reply to anon failed: {bob_reply}"
    );
    assert_eq!(bob_reply["reply"]["pushOutcome"], "stored");
    assert!(
        bob_reply["reply"]["pushedMessageId"].is_null(),
        "stored reply to anonymous sender (dest_session_id == None) must have pushedMessageId == null, got: {bob_reply}"
    );

    // Anonymous caller on Node A reads the reply via GET /v1/messages/{id}/replies
    let replies_resp: Value = client
        .get(format!(
            "http://127.0.0.1:{http_a}/v1/messages/{anon_msg_id}/replies?wait=5"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let replies_arr = replies_resp
        .as_array()
        .unwrap_or_else(|| panic!("expected JSON array of replies, got: {replies_resp}"));
    assert_eq!(replies_arr.len(), 1);
    assert_eq!(replies_arr[0]["text"], "reply to anonymous sender");
    assert!(replies_arr[0]["pushedMessageId"].is_null());

    // -------------------------------------------------------------------------
    // Cell 2b: `spawn_outbound_reply_poller` refuses a pulled reply that lacks
    // an authoritative `pushed_message_id` (logs warning, does NOT fabricate
    // `{message_id}-{seq}`, and does NOT deliver to Alice's inbox).
    // -------------------------------------------------------------------------
    let (_sock_a, rx_a) = create_claude_session_fixture(&node_a.sessions_dir, "alice", "Alice");

    let send_m =
        send_via_agent_sock(&node_a.agent_sock, "Bob@node-b", "message for unid reply").await;
    assert_eq!(send_m["status"], "ok");
    let m_id = send_m["message_id"].as_str().unwrap().to_string();

    let _b_m = pop_inbox_message(&rx_b, Duration::from_secs(5))
        .await
        .expect("Bob receives message");

    // Directly insert a reply row on Node B with `pushed_message_id = NULL` (seq = 1),
    // and then send a normal reply via Node B's agent.sock (seq = 2) to wake Node B's
    // `notify_tx` immediately and prove the poller skips seq = 1 with a warning while
    // delivering seq = 2!
    {
        let conn_b = rusqlite::Connection::open(&node_b.db_path).unwrap();
        conn_b.busy_timeout(Duration::from_secs(5)).unwrap();
        storage::insert_reply(
            &conn_b,
            &m_id,
            "bob",
            "reply-without-pushed-id",
            Some("stored"),
            None,
        )
        .unwrap();
    }
    let valid_after =
        reply_via_agent_sock(&node_b.agent_sock, &m_id, "valid-reply-after-unid").await;
    assert_eq!(valid_after["status"], "ok");

    let a_valid = pop_inbox_message(&rx_a, Duration::from_secs(5))
        .await
        .expect("Alice must receive the valid reply (seq 2)");
    assert!(
        a_valid.contains("valid-reply-after-unid")
            && !a_valid.contains("reply-without-pushed-id"),
        "Alice must receive only the valid reply, not the un-ID'd reply: {a_valid}"
    );

    let mut stderr_a = String::new();
    for _ in 0..40 {
        stderr_a = fs::read_to_string(&node_a.stderr_path).unwrap_or_default();
        if stderr_a.contains("refusing pulled reply without authoritative pushed_message_id") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        stderr_a.contains("refusing pulled reply without authoritative pushed_message_id"),
        "Node A must log warning refusing pulled reply without authoritative pushed_message_id; log: {stderr_a}"
    );

    // Node A's DB must NOT contain a fabricated `{m_id}-1` row.
    let conn_a = rusqlite::Connection::open(&node_a.db_path).unwrap();
    conn_a.busy_timeout(Duration::from_secs(5)).unwrap();
    let fabricated_id = format!("{m_id}-1");
    assert!(
        storage::get_message(&conn_a, &fabricated_id)
            .unwrap()
            .is_none(),
        "Node A must never fabricate '{fabricated_id}' in messages table"
    );
}
