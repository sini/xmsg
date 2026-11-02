use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

const SIGTERM: i32 = 15;

struct ChildGuard(Option<tokio::process::Child>);

impl ChildGuard {
    fn new(child: tokio::process::Child) -> Self {
        Self(Some(child))
    }
    fn child_mut(&mut self) -> &mut tokio::process::Child {
        self.0.as_mut().unwrap()
    }
    fn take(&mut self) -> Option<tokio::process::Child> {
        self.0.take()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.start_kill();
        }
    }
}

async fn connect_svc(sock_path: &Path) -> (BufReader<OwnedReadHalf>, OwnedWriteHalf) {
    let stream = UnixStream::connect(sock_path).await.unwrap();
    let (reader, writer) = stream.into_split();
    (BufReader::new(reader), writer)
}

async fn read_json_line(reader: &mut BufReader<OwnedReadHalf>) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    serde_json::from_str(line.trim()).unwrap()
}

#[allow(dead_code)]
struct FullNodeFixture {
    _tmp: TempDir,
    run_dir: PathBuf,
    agent_sock: PathBuf,
    register_sock: PathBuf,
    http_sock: PathBuf,
    sessions_dir: PathBuf,
    db_path: PathBuf,
    child: ChildGuard,
}

async fn spawn_full_node(tmp: Option<TempDir>) -> FullNodeFixture {
    let tmp = tmp.unwrap_or_else(|| tempdir().unwrap());
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let run_dir = tmp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let agent_sock = run_dir.join("agent.sock");
    let register_sock = run_dir.join("register.sock");
    let http_sock = run_dir.join("http.sock");
    let db_path = tmp.path().join("test.db");

    let bin = env!("CARGO_BIN_EXE_xmsg");
    let child = tokio::process::Command::new(bin)
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env("HOME", &run_dir)
        .env("RUST_LOG", "info")
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
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn full node");

    let mut guard = ChildGuard::new(child);

    let mut ready = false;
    for _ in 0..600 {
        if let Ok(Some(status)) = guard.child_mut().try_wait() {
            let mut stderr = String::new();
            if let Some(mut err) = guard.child_mut().stderr.take() {
                let _ = tokio::io::AsyncReadExt::read_to_string(&mut err, &mut stderr).await;
            }
            panic!(
                "full node exited prematurely: {:?}, stderr:\n{}",
                status, stderr
            );
        }
        if std::os::unix::net::UnixStream::connect(&agent_sock).is_ok() && std::os::unix::net::UnixStream::connect(&register_sock).is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "full node failed to become ready");

    FullNodeFixture {
        _tmp: tmp,
        run_dir,
        agent_sock,
        register_sock,
        http_sock,
        sessions_dir,
        db_path,
        child: guard,
    }
}

#[allow(dead_code)]
struct LeafNodeFixture {
    _tmp: TempDir,
    run_dir: PathBuf,
    reg_sock: PathBuf,
    sessions_dir: PathBuf,
    db_path: PathBuf,
    child: ChildGuard,
}

async fn spawn_leaf_node() -> LeafNodeFixture {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let cert_file = tmp.path().join("cert.pem");
    let key_file = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");
    let db_path = tmp.path().join("leaf.db");

    let (cert_pem, key_pem, _) = xmsg::fed::generate_self_signed_ed25519_pem("leaf-node").unwrap();
    fs::write(&cert_file, cert_pem).unwrap();
    fs::write(&key_file, key_pem).unwrap();
    fs::write(&peers_file, "{}").unwrap();

    let run_dir = tmp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let reg_sock = run_dir.join("register.sock");

    let bin = env!("CARGO_BIN_EXE_xmsg");
    let child = tokio::process::Command::new(bin)
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env("HOME", &run_dir)
        .env("RUST_LOG", "info")
        .args([
            "serve",
            "--leaf",
            "--leaf-principal",
            "svc:guard",
            "--listen",
            "127.0.0.1:0",
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
            reg_sock.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn leaf node");

    let mut guard = ChildGuard::new(child);

    let mut ready = false;
    for _ in 0..600 {
        if let Ok(Some(status)) = guard.child_mut().try_wait() {
            let mut stderr = String::new();
            if let Some(mut err) = guard.child_mut().stderr.take() {
                let _ = tokio::io::AsyncReadExt::read_to_string(&mut err, &mut stderr).await;
            }
            panic!(
                "leaf node exited prematurely: {:?}, stderr:\n{}",
                status, stderr
            );
        }
        if std::os::unix::net::UnixStream::connect(&reg_sock).is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "leaf node failed to become ready");

    LeafNodeFixture {
        _tmp: tmp,
        run_dir,
        reg_sock,
        sessions_dir,
        db_path,
        child: guard,
    }
}

// =============================================================================
// Oracle 1: SIGTERM to running full node
// The process exits 0 within a bounded timeout (5s) and logs clean shutdown.
// Mutant: disable signal handler in serve => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1_full_node_sigterm_clean_shutdown() {
    let mut node = spawn_full_node(None).await;
    let pid = node.child.child_mut().id().expect("child pid") as i32;

    let start = Instant::now();
    unsafe {
        kill(pid, SIGTERM);
    }

    let mut status = None;
    for _ in 0..100 {
        if let Ok(Some(s)) = node.child.child_mut().try_wait() {
            status = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "Shutdown exceeded 5s bound: {elapsed:?}"
    );

    let status = status.expect("Full node must exit within 5s of SIGTERM");
    assert!(
        status.success(),
        "Full node exit status must be 0, got: {status:?}"
    );

    let child = node.child.take().unwrap();
    let output = child.wait_with_output().await.unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let logs = format!("{stderr}\n{stdout}");

    assert!(
        logs.contains("shutdown complete, exiting cleanly"),
        "Shutdown log line missing from logs:\n{logs}"
    );
}

// =============================================================================
// Oracle 2: SIGTERM to leaf node (--leaf)
// The process exits 0 within a bounded timeout (5s) and logs clean shutdown.
// Mutant: disable signal handler in leaf mode => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_2_leaf_sigterm_clean_shutdown() {
    let mut node = spawn_leaf_node().await;
    let pid = node.child.child_mut().id().expect("child pid") as i32;

    let start = Instant::now();
    unsafe {
        kill(pid, SIGTERM);
    }

    let mut status = None;
    for _ in 0..100 {
        if let Ok(Some(s)) = node.child.child_mut().try_wait() {
            status = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "Shutdown exceeded 5s bound: {elapsed:?}"
    );

    let status = status.expect("Leaf node must exit within 5s of SIGTERM");
    assert!(
        status.success(),
        "Leaf node exit status must be 0, got: {status:?}"
    );

    let child = node.child.take().unwrap();
    let output = child.wait_with_output().await.unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let logs = format!("{stderr}\n{stdout}");

    assert!(
        logs.contains("shutdown complete, exiting cleanly"),
        "Shutdown log line missing from logs:\n{logs}"
    );
}

// =============================================================================
// Oracle 3: Unacknowledged message survives SIGTERM and is delivered after restart.
// Mutant: drop the message queue on shutdown => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3_unacked_message_persists_across_sigterm_restart() {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let run_dir = tmp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let agent_sock = run_dir.join("agent.sock");
    let register_sock = run_dir.join("register.sock");
    let http_sock = run_dir.join("http.sock");
    let db_path = tmp.path().join("test.db");

    let bin = env!("CARGO_BIN_EXE_xmsg");
    let current_exe = std::env::current_exe().unwrap();

    // 1. Spawn node first time
    let child1 = tokio::process::Command::new(bin)
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env("HOME", &run_dir)
        .env("RUST_LOG", "info")
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
            "--svc-exe",
            &format!("worker={}", current_exe.display()),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn first node");

    let mut guard1 = ChildGuard::new(child1);

    for _ in 0..600 {
        if std::os::unix::net::UnixStream::connect(&agent_sock).is_ok() && std::os::unix::net::UnixStream::connect(&register_sock).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 2. Connect svc daemon and register svc:worker
    let (mut reader1, mut writer1) = connect_svc(&register_sock).await;
    let reg_frame = serde_json::json!({ "harness": "svc", "name": "worker" });
    writer1
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let reg_resp = read_json_line(&mut reader1).await;
    assert_eq!(reg_resp["status"], "ok");

    // 3. Send message to svc:worker via agent.sock
    let send_stream = UnixStream::connect(&agent_sock).await.unwrap();
    let (send_reader, mut send_writer) = send_stream.into_split();
    let mut send_reader = BufReader::new(send_reader);
    let send_req = serde_json::json!({
        "action": "send",
        "to": "worker",
        "text": "critical-payload-survives-sigterm"
    });
    send_writer
        .write_all(format!("{send_req}\n").as_bytes())
        .await
        .unwrap();
    let send_resp = read_json_line(&mut send_reader).await;
    assert_eq!(send_resp["outcome"], "queued");
    let sent_msg_id = send_resp["message_id"]
        .as_str()
        .expect("messageId")
        .to_string();

    // 4. Poll and receive message on reader1, but drop connection WITHOUT acking
    let poll_cmd = serde_json::json!({ "action": "poll", "waitSecs": 5 });
    writer1
        .write_all(format!("{poll_cmd}\n").as_bytes())
        .await
        .unwrap();
    let poll_resp1 = read_json_line(&mut reader1).await;
    assert_eq!(poll_resp1["action"], "deliver");
    assert_eq!(poll_resp1["messageId"], sent_msg_id);
    assert_eq!(poll_resp1["text"], "critical-payload-survives-sigterm");

    drop(reader1);
    drop(writer1);

    // 5. Send SIGTERM to running full node
    let pid = guard1.child_mut().id().expect("child pid") as i32;
    unsafe {
        kill(pid, SIGTERM);
    }

    let mut status1 = None;
    for _ in 0..100 {
        if let Ok(Some(s)) = guard1.child_mut().try_wait() {
            status1 = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let status1 = status1.expect("First node must exit within 5s of SIGTERM");
    assert!(status1.success(), "Exit status must be 0, got: {status1:?}");

    // Remove socket files before restart
    let _ = fs::remove_file(&agent_sock);
    let _ = fs::remove_file(&register_sock);
    let _ = fs::remove_file(&http_sock);

    // 6. Spawn node second time with SAME db_path
    let child2 = tokio::process::Command::new(bin)
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env("HOME", &run_dir)
        .env("RUST_LOG", "info")
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
            "--svc-exe",
            &format!("worker={}", current_exe.display()),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn second node");

    let mut guard2 = ChildGuard::new(child2);

    for _ in 0..600 {
        if std::os::unix::net::UnixStream::connect(&agent_sock).is_ok() && std::os::unix::net::UnixStream::connect(&register_sock).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 7. Reconnect svc daemon and register svc:worker
    let (mut reader2, mut writer2) = connect_svc(&register_sock).await;
    writer2
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let reg_resp2 = read_json_line(&mut reader2).await;
    assert_eq!(reg_resp2["status"], "ok");

    // 8. Poll for messages: must deliver the unacked message from before SIGTERM!
    let poll_req = serde_json::json!({
        "action": "poll",
        "waitSecs": 5
    });
    writer2
        .write_all(format!("{poll_req}\n").as_bytes())
        .await
        .unwrap();
    let poll_resp = read_json_line(&mut reader2).await;
    assert_eq!(poll_resp["action"], "deliver");
    assert_eq!(poll_resp["messageId"], sent_msg_id);
    assert_eq!(poll_resp["text"], "critical-payload-survives-sigterm");

    // 9. Clean shutdown of second node
    let pid2 = guard2.child_mut().id().expect("child pid") as i32;
    unsafe {
        kill(pid2, SIGTERM);
    }
    let mut status2 = None;
    for _ in 0..100 {
        if let Ok(Some(s)) = guard2.child_mut().try_wait() {
            status2 = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(status2.expect("second node exit").success());
}

// =============================================================================
// Oracle 4: PID 1 in container (via unshare --user --pid --fork --forward-signals)
// The process runs as PID 1, handles SIGTERM cleanly, and exits 0 within 5s.
// Mutant: no signal handler installed => PID 1 drops unhandled signal and never exits => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_4_pid_1_unshare_container_sigterm_clean_shutdown() {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let run_dir = tmp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let agent_sock = run_dir.join("agent.sock");
    let register_sock = run_dir.join("register.sock");
    let http_sock = run_dir.join("http.sock");
    let db_path = tmp.path().join("pid1.db");

    let bin = env!("CARGO_BIN_EXE_xmsg");

    // Spawn xmsg serve as PID 1 inside a new PID + User namespace
    let child_res = tokio::process::Command::new("unshare")
        .args([
            "--user",
            "--pid",
            "--fork",
            "--forward-signals",
            "env",
            &format!("HOME={}", run_dir.display()),
            bin,
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
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let child = match child_res {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "unshare is not available ({e}), skipping PID 1 direct container test (oracles 1 and 2 cover signal handler)"
            );
            return;
        }
    };

    let mut guard = ChildGuard::new(child);

    let mut ready = false;
    for _ in 0..600 {
        if let Ok(Some(status)) = guard.child_mut().try_wait() {
            let mut stderr = String::new();
            if let Some(mut err) = guard.child_mut().stderr.take() {
                let _ = tokio::io::AsyncReadExt::read_to_string(&mut err, &mut stderr).await;
            }
            if !status.success() {
                eprintln!(
                    "unshare execution failed ({status:?}, stderr: {stderr}), skipping PID 1 direct container test (oracles 1 and 2 cover signal handler)"
                );
                return;
            }
            panic!(
                "PID 1 node exited prematurely: {:?}, stderr:\n{}",
                status, stderr
            );
        }
        if std::os::unix::net::UnixStream::connect(&agent_sock).is_ok() && std::os::unix::net::UnixStream::connect(&register_sock).is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "PID 1 node failed to become ready");

    let unshare_pid = guard.child_mut().id().expect("unshare pid") as i32;

    let start = Instant::now();
    // Sending SIGTERM to unshare forwards it to PID 1 inside the PID namespace
    unsafe {
        kill(unshare_pid, SIGTERM);
    }

    let mut status = None;
    for _ in 0..100 {
        if let Ok(Some(s)) = guard.child_mut().try_wait() {
            status = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "PID 1 shutdown exceeded 5s bound: {elapsed:?}"
    );

    let status = status.expect("PID 1 node must exit within 5s of SIGTERM");
    assert!(
        status.success(),
        "PID 1 node exit status must be 0, got: {status:?}"
    );

    let child = guard.take().unwrap();
    let output = child.wait_with_output().await.unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let logs = format!("{stderr}\n{stdout}");

    assert!(
        logs.contains("shutdown complete, exiting cleanly"),
        "Shutdown log line missing from PID 1 logs:\n{logs}"
    );
}
