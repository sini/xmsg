mod short_sock;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use serde_json::{json, Value};
use xmsg::agent::{resolve_caller_session_peer, run_agent_server_with_listener};
use xmsg::agy::{new_agy_store, AgyConfig};
use xmsg::http::AppState;
use xmsg::pi::new_pi_store;
use xmsg::process::{self, Ancestry, WalkEnd};
use xmsg::storage;
use xmsg::svc::{new_svc_store, SvcRegisterRequest};

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

fn write_fake_stat(proc_root: &Path, pid: u32, ppid: u32, starttime: &str) {
    let dir = proc_root.join(pid.to_string());
    fs::create_dir_all(&dir).unwrap();
    let stat = format!(
        "{pid} (fake) S {ppid} {pid} {pid} 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 {starttime} 1000000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
    );
    fs::write(dir.join("stat"), stat).unwrap();
}

/// Connects to `sock_path` from a forked child that writes `payload` and immediately exits,
/// then reaps the child via `waitpid` while returning the still-open connected `UnixStream`
/// in the parent. Because the kernel pins `sk_peer_pid` to the task that called `connect()`,
/// the server accepting this connection sees the reaped child's `pidfd` (`Pid: -1`).
#[cfg(target_os = "linux")]
fn connect_from_reaped_child(sock_path: &Path, payload: &[u8]) -> UnixStream {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0, "socket(AF_UNIX) failed");

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = sock_path.as_os_str().as_bytes();
    assert!(bytes.len() < addr.sun_path.len(), "socket path too long");
    for (dst, &src) in addr.sun_path.iter_mut().zip(bytes.iter()) {
        *dst = src as libc::c_char;
    }
    let addr_len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        let rc = unsafe {
            libc::connect(
                fd,
                (&addr as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
                addr_len,
            )
        };
        if rc != 0 {
            unsafe { libc::_exit(2) };
        }
        if !payload.is_empty() {
            let n = unsafe { libc::write(fd, payload.as_ptr().cast(), payload.len()) };
            if n != payload.len() as isize {
                unsafe { libc::_exit(3) };
            }
        }
        unsafe { libc::_exit(0) };
    }

    let mut status: libc::c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid);
    assert!(
         libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child connect/write failed with status {status}"
    );

    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    std_stream.set_nonblocking(true).unwrap();
    UnixStream::from_std(std_stream).unwrap()
}

#[cfg(target_os = "linux")]
#[test]
#[ignore]
fn xf1_1_pidns_server_helper() {
    use std::io::{BufRead, Write};

    let base_dir = PathBuf::from(std::env::var("XF1_1_BASE_DIR").expect("XF1_1_BASE_DIR"));
    let reg_sock = PathBuf::from(std::env::var("XF1_1_REG_SOCK").expect("XF1_1_REG_SOCK"));
    let reaped_reg_sock =
        PathBuf::from(std::env::var("XF1_1_REAPED_REG_SOCK").expect("XF1_1_REAPED_REG_SOCK"));
    let agent_sock = PathBuf::from(std::env::var("XF1_1_AGENT_SOCK").expect("XF1_1_AGENT_SOCK"));
    let probe_sock = PathBuf::from(std::env::var("XF1_1_PROBE_SOCK").expect("XF1_1_PROBE_SOCK"));

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // `cargo test` executes each test on a worker thread (so the test process has >1 thread,
    // which makes `unshare(CLONE_NEWUSER)` return `EINVAL`). Fork first so the child is
    // single-threaded (`current_is_single_threaded() == true`).
    let single_thread_pid = unsafe { libc::fork() };
    if single_thread_pid < 0 {
        println!("UNSHARE_UNAVAILABLE: initial fork failed");
        std::io::stdout().flush().unwrap();
        return;
    }
    if single_thread_pid > 0 {
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(single_thread_pid, &mut status, 0);
        }
        return;
    }

    let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::CLONE_NEWNS) };
    if rc != 0 {
        println!(
            "UNSHARE_UNAVAILABLE: unshare failed: {}",
            std::io::Error::last_os_error()
        );
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }

    let _ = fs::write("/proc/self/setgroups", "deny\n");
    if fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n")).is_err()
        || fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n")).is_err()
    {
        println!("UNSHARE_UNAVAILABLE: uid_map/gid_map write failed");
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("UNSHARE_UNAVAILABLE: fork failed");
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    if pid > 0 {
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
            libc::_exit(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                1
            });
        }
    }

    // Child is PID 1 in the new PID namespace; mount a fresh procfs for this namespace so
    // `/proc/self/fdinfo/<pidfd>` resolves PIDs in this child PID namespace (`Pid: 0` for
    // live peers in the parent namespace, `Pid: -1` for reaped peers).
    let mount_rc = unsafe {
        libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
            std::ptr::null(),
        )
    };
    if mount_rc != 0 {
        println!(
            "UNSHARE_UNAVAILABLE: mount /proc failed: {}",
            std::io::Error::last_os_error()
        );
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async move {
        let proc_root = base_dir.join("proc");
        let sessions_dir = base_dir.join("sessions");
        let presence_dir = base_dir.join("presence");
        let agy_config = AgyConfig {
            presence_dir,
            proc_locks_path: base_dir.join("locks"),
            proc_root: proc_root.clone(),
            agy_bin: "false".to_string(),
            trusted_agy_exes: Vec::new(),
                brain_dir: std::path::PathBuf::new(),
    };
        let db_conn = rusqlite::Connection::open(base_dir.join("xmsg.db")).unwrap();
        storage::init_db(&db_conn).unwrap();
        let db = Arc::new(Mutex::new(db_conn));

        let (notify_tx, _) = tokio::sync::broadcast::channel(32);
        let (pi_notify_tx, _) = tokio::sync::broadcast::channel(32);
        let (svc_notify_tx, _) = tokio::sync::broadcast::channel(32);

        let state = Arc::new(AppState {
            sessions_dirs: vec![sessions_dir],
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
            node_name: "leaf-test".to_string(),
            agy_config,
            agy_store: new_agy_store(),
            pi_store: new_pi_store(),
            svc_store: new_svc_store(),
        });

        xmsg::claim::sync_claims(&db, &proc_root, &state.sessions_dirs[..], "leaf-test")
            .await
            .unwrap();

        let probe_listener = UnixListener::bind(&probe_sock).unwrap();
        let proc_root_probe = proc_root.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = probe_listener.accept().await {
                let peer = process::peer_cred(&s).unwrap();
                let info = json!({
                    "uid": peer.uid,
                    "pid": peer.pid,
                    "is_pinned": peer.is_pinned(),
                    "is_unmapped": peer.is_unmapped(),
                    "is_pin_alive": peer.is_pin_alive(),
                    "is_alive_zero": peer.is_alive(&proc_root_probe, "0"),
                });
                let _ = s.write_all(format!("{info}\n").as_bytes()).await;
            }
        });

        // Pre-bind `reaped_reg_listener` without accepting until the outer test has connected
        // from a forked child and reaped that child.
        let reaped_reg_listener = UnixListener::bind(&reaped_reg_sock).unwrap();

        let agent_listener = UnixListener::bind(&agent_sock).unwrap();
        fs::set_permissions(&agent_sock, fs::Permissions::from_mode(0o600)).unwrap();
        let state_agent = state.clone();
        tokio::spawn(async move {
            let _ = run_agent_server_with_listener(agent_listener, state_agent, uid).await;
        });

        let state_leaf = state.clone();
        let reg_sock_clone = reg_sock.clone();
        tokio::spawn(async move {
            let _ = xmsg::svc::run_leaf_register_server(
                reg_sock_clone,
                state_leaf,
                uid,
                "svc:guard".to_string(),
            )
            .await;
        });

        for _ in 0..200 {
            if reg_sock.exists() && agent_sock.exists() && probe_sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        println!("PIDNS_SERVER_READY");
        std::io::stdout().flush().unwrap();

        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(cmd) = line else { break };
            if cmd.trim() == "ACCEPT_REAPED" {
                let (stream, _) = reaped_reg_listener.accept().await.unwrap();
                let peer = process::peer_cred(&stream).unwrap();
                let (reader, writer) = stream.into_split();
                let mut buf_reader = BufReader::new(reader);
                let mut req_line = String::new();
                buf_reader.read_line(&mut req_line).await.unwrap();
                let req: SvcRegisterRequest = serde_json::from_str(req_line.trim()).unwrap();
                let empty = std::collections::HashMap::new();
                let _ = xmsg::svc::handle_svc_connection_peer(
                    buf_reader,
                    writer,
                    state.clone(),
                    &empty,
                    uid,
                    peer,
                    req,
                    true,
                    Some("svc:guard".to_string()),
                )
                .await;
            } else if cmd.trim() == "QUIT" {
                break;
            }
        }
    });

    unsafe { libc::_exit(0) };
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_xf1_1_unmapped_peer_pid_namespace_and_ancestry_oracles() {
    process::set_force_peerpidfd_errno_for_test(0);
    process::set_force_pidfd_pid_for_test(None);

    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let proc_root = tmp.path().join("proc");
    fs::create_dir_all(&proc_root).unwrap();

    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();

    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();

    // Victim Claude session at PID 500
    let victim_pid = 500u32;
    write_fake_stat(&proc_root, victim_pid, 1, "1000");
    // Also plant `<proc_root>/0/stat` and `<proc_root>/<self_pid>/stat` with ppid = victim_pid
    // so if an unmapped peer were ever walked (either as PID 0 or via fallback ucred.pid),
    // the walk would reach `sess-victim` and fail Oracle 2!
    write_fake_stat(&proc_root, 0, victim_pid, "2000");
    write_fake_stat(&proc_root, std::process::id(), victim_pid, "2000");

    let victim_inbox_sock = short_sock::sock_path(&sessions_dir, "victim11");
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
    let target_inbox_sock = short_sock::sock_path(&sessions_dir, "target11");
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

    // -------------------------------------------------------------------------
    // Pass 1: Real PID namespace boundary via `unshare(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS)`
    // + `fork()` + `mount("proc", "/proc", ...)`. Falls back to the fdinfo seam if the
    // sandbox forbids user namespaces or mounting `/proc`.
    // -------------------------------------------------------------------------
    let reg_sock_ns = short_sock::sock_path(tmp.path(), "reg_ns");
    let reaped_reg_sock_ns = short_sock::sock_path(tmp.path(), "reaped_ns");
    let agent_sock_ns = short_sock::sock_path(tmp.path(), "agent_ns");
    let probe_sock_ns = short_sock::sock_path(tmp.path(), "probe_ns");

    let mut helper = ChildGuard::new(
        tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "xf1_1_pidns_server_helper",
                "--ignored",
                "--nocapture",
                "--quiet",
            ])
            .env("XF1_1_BASE_DIR", tmp.path())
            .env("XF1_1_REG_SOCK", &reg_sock_ns)
            .env("XF1_1_REAPED_REG_SOCK", &reaped_reg_sock_ns)
            .env("XF1_1_AGENT_SOCK", &agent_sock_ns)
            .env("XF1_1_PROBE_SOCK", &probe_sock_ns)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .expect("spawn xf1_1_pidns_server_helper"),
    );

    let mut helper_stdout = BufReader::new(helper.child_mut().stdout.take().unwrap());
    let mut helper_stdin = helper.child_mut().stdin.take().unwrap();
    let mut ready_line = String::new();
    loop {
        ready_line.clear();
        let n = helper_stdout.read_line(&mut ready_line).await.unwrap();
        assert!(n > 0, "EOF from xf1_1_pidns_server_helper before ready line");
        let trimmed = ready_line.trim();
        if trimmed == "PIDNS_SERVER_READY" || trimmed.starts_with("UNSHARE_UNAVAILABLE") {
            break;
        }
    }

    if ready_line.trim() == "PIDNS_SERVER_READY" {
        // Oracle 1 (real PID namespace): Leaf-mode svc registration succeeds.
        // Mutant: unmapped treated as dead => fails with "peer process 0 is no longer alive" => RED.
        {
            let stream = UnixStream::connect(&reg_sock_ns).await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);

            writer
                .write_all(b"{\"harness\":\"svc\",\"name\":\"guard\",\"cwd\":\"/workspace\"}\n")
                .await
                .unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let resp: Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(
                resp["status"], "ok",
                "Oracle 1: leaf-mode svc registration across PID namespace must succeed, got: {resp}"
            );
            assert_eq!(resp["address"], "guard@leaf-test");

            writer
                .write_all(b"{\"action\":\"poll\",\"waitSecs\":0}\n")
                .await
                .unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            let poll_resp: Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(poll_resp["action"], "timeout", "{poll_resp}");
        }

        // Oracle 2 (real PID namespace): The same unmapped peer on an ancestry path
        // (agent.sock as a Claude caller) is refused as unattested, while per-frame
        // `is_alive` keeps the connection open for `list`.
        // Mutant: unmapped accepted on ancestry path => resolves to `sess-victim` => RED.
        {
            let stream = UnixStream::connect(&agent_sock_ns).await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);

            writer
                .write_all(b"{\"action\":\"mcp_start\"}\n")
                .await
                .unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let mcp_resp: Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(mcp_resp["status"], "error", "{mcp_resp}");
            assert_eq!(
                mcp_resp["error"], "unattested",
                "Oracle 2: unmapped peer on agent.sock mcp_start must be refused as unattested: {mcp_resp}"
            );

            writer
                .write_all(
                    b"{\"action\":\"send\",\"to\":\"Target\",\"text\":\"forged-from-unmapped\"}\n",
                )
                .await
                .unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            let send_resp: Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(send_resp["status"], "error", "{send_resp}");
            assert_eq!(
                send_resp["error"], "denied",
                "Oracle 2: unmapped peer on agent.sock send must be refused as denied: {send_resp}"
            );
            assert!(
                send_resp["detail"]
                    .as_str()
                    .unwrap_or("")
                    .contains("ancestry is unproven"),
                "Oracle 2: unmapped peer detail must report unproven ancestry: {send_resp}"
            );

            writer.write_all(b"{\"action\":\"list\"}\n").await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            let list_resp: Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(
                list_resp["status"], "ok",
                "per-frame is_alive on agent.sock must keep alive-unmapped connection open: {list_resp}"
            );

            assert!(
                target_received.lock().unwrap().is_empty(),
                "Target must receive 0 messages from unmapped peer"
            );
        }

        // Oracle 3 (real PID namespace): A reaped peer (`Pid: -1`) is refused on
        // leaf-mode svc registration with "peer process 0 is no longer alive".
        {
            let mut reaped_stream = connect_from_reaped_child(
                &reaped_reg_sock_ns,
                b"{\"harness\":\"svc\",\"name\":\"guard\",\"cwd\":\"/reaped\"}\n",
            );
            helper_stdin.write_all(b"ACCEPT_REAPED\n").await.unwrap();
            helper_stdin.flush().await.unwrap();

            let mut line = String::new();
            BufReader::new(&mut reaped_stream)
                .read_line(&mut line)
                .await
                .unwrap();
            let resp: Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(resp["status"], "error", "{resp}");
            assert!(
                resp["detail"]
                    .as_str()
                    .unwrap_or("")
                    .contains("is no longer alive"),
                "Oracle 3: reaped peer across PID namespace (Pid: -1) must be refused: {resp}"
            );
        }

        // Probe socket confirms real kernel `/proc/self/fdinfo/<pidfd>` reports `Pid: 0`
        // (`is_unmapped == true`, `pid == None`, `is_pin_alive == true`).
        {
            let mut s = UnixStream::connect(&probe_sock_ns).await.unwrap();
            let mut line = String::new();
            BufReader::new(&mut s).read_line(&mut line).await.unwrap();
            let v: Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(v["pid"], Value::Null, "unmapped peer must have pid: None: {v}");
            assert_eq!(v["is_pinned"], true, "unmapped peer must be pinned: {v}");
            assert_eq!(v["is_unmapped"], true, "unmapped peer must be marked unmapped: {v}");
            assert_eq!(
                v["is_pin_alive"], true,
                "Oracle 1 / Mutant 1: alive-unmapped peer must have is_pin_alive() == true: {v}"
            );
            assert_eq!(
                v["is_alive_zero"], true,
                "alive-unmapped peer must have is_alive(_, \"0\") == true while pidfd is non-dead: {v}"
            );
        }

        let _ = helper_stdin.write_all(b"QUIT\n").await;
    } else {
        eprintln!(
            "note: sandbox forbade PID namespace helper ({}); relying on fdinfo Pid: 0 test seam",
            ready_line.trim()
        );
    }
    drop(helper);

    // -------------------------------------------------------------------------
    // Pass 2: In-process verification across all ancestry & registration surfaces
    // using the `set_force_pidfd_pid_for_test` seam (`Some(0)` for alive-unmapped
    // and `Some(-1)` for reaped).
    // -------------------------------------------------------------------------
    let agy_config = AgyConfig {
        presence_dir: tmp.path().join("presence"),
        proc_locks_path: tmp.path().join("locks"),
        proc_root: proc_root.clone(),
        agy_bin: "false".to_string(),
        trusted_agy_exes: Vec::new(),
            brain_dir: std::path::PathBuf::new(),
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
        node_name: "leaf-test".to_string(),
        agy_config: agy_config.clone(),
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        svc_store: new_svc_store(),
    });
    xmsg::claim::sync_claims(&db, &proc_root, &state.sessions_dirs[..], "leaf-test")
        .await
        .unwrap();

    let uid = xmsg::agy::current_uid();
    let reg_sock_seam = short_sock::sock_path(tmp.path(), "reg_seam");
    let agent_sock_seam = short_sock::sock_path(tmp.path(), "agent_seam");

    let agent_listener = UnixListener::bind(&agent_sock_seam).unwrap();
    fs::set_permissions(&agent_sock_seam, fs::Permissions::from_mode(0o600)).unwrap();
    let state_agent = state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server_with_listener(agent_listener, state_agent, uid).await;
    });

    let state_leaf = state.clone();
    let reg_sock_clone = reg_sock_seam.clone();
    tokio::spawn(async move {
        let _ = xmsg::svc::run_leaf_register_server(
            reg_sock_clone,
            state_leaf,
            uid,
            "svc:guard".to_string(),
        )
        .await;
    });

    for _ in 0..100 {
        if reg_sock_seam.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    process::set_force_pidfd_pid_for_test(Some(0));

    // Oracle 1 on seam: leaf-mode svc registration succeeds.
    {
        let stream = UnixStream::connect(&reg_sock_seam).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        writer
            .write_all(b"{\"harness\":\"svc\",\"name\":\"guard\",\"cwd\":\"/workspace\"}\n")
            .await
            .unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let resp: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(resp["status"], "ok", "{resp}");
        assert_eq!(resp["address"], "guard@leaf-test");
    }

    // Oracle 2 on seam: agent.sock refuses `mcp_start` as `unattested` and `send` as
    // `denied` (unproven ancestry), while keeping the connection alive for `list`.
    {
        let stream = UnixStream::connect(&agent_sock_seam).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        writer
            .write_all(b"{\"action\":\"mcp_start\"}\n")
            .await
            .unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let mcp_resp: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(mcp_resp["error"], "unattested", "{mcp_resp}");

        writer
            .write_all(b"{\"action\":\"send\",\"to\":\"Target\",\"text\":\"forged\"}\n")
            .await
            .unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let send_resp: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(send_resp["error"], "denied", "{send_resp}");
        assert!(
            send_resp["detail"]
                .as_str()
                .unwrap_or("")
                .contains("ancestry is unproven"),
            "{send_resp}"
        );

        writer.write_all(b"{\"action\":\"list\"}\n").await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let list_resp: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(list_resp["status"], "ok", "{list_resp}");
    }

    // Direct checks on every ancestry / non-leaf registration path:
    let (s1, _s2) = UnixStream::pair().unwrap();
    let unmapped_peer = process::peer_cred(&s1).unwrap();
    assert!(unmapped_peer.is_unmapped());
    assert!(unmapped_peer.is_pin_alive());
    assert_eq!(unmapped_peer.pid, None);

    let mut walk = Ancestry::from_peer(&proc_root, &unmapped_peer);
    assert!(walk.next().is_none());
    assert_eq!(walk.end(), Some(WalkEnd::Unreadable(0)));

    let db_guard = db.lock().unwrap();
    assert!(
        resolve_caller_session_peer(
            &proc_root,
            &state.sessions_dirs[..],
            &agy_config,
            &state.agy_store,
            &state.pi_store,
            &state.svc_store,
            Some(&*db_guard),
            &unmapped_peer,
        )
        .is_err(),
        "resolve_caller_session_peer must reject alive-unmapped peer"
    );
    drop(db_guard);

    assert!(
        xmsg::pi::verify_pi_process_peer(&proc_root, uid, &unmapped_peer).is_err(),
        "verify_pi_process_peer (pi & plugin) must reject alive-unmapped peer"
    );

    let mut trusted_svc = std::collections::HashMap::new();
    trusted_svc.insert("guard".to_string(), std::env::current_exe().unwrap());
    assert!(
        xmsg::svc::verify_svc_process_peer(&proc_root, &trusted_svc, uid, &unmapped_peer, "guard")
            .is_err(),
        "non-leaf verify_svc_process_peer must reject alive-unmapped peer"
    );

    assert!(
        xmsg::agy::attest_mcp_caller_peer(
            &proc_root,
            &agy_config.proc_locks_path,
            &agy_config.presence_dir,
            &agy_config.trusted_agy_exes,
            uid,
            &unmapped_peer,
        )
        .is_err(),
        "agy attest_mcp_caller_peer must reject alive-unmapped peer"
    );

    // Oracle 3 on seam: once fdinfo reports `Pid: -1` (reaped), `is_pin_alive()` and
    // `is_alive(_, "0")` flip to `false`, and leaf-mode svc registration is refused!
    process::set_force_pidfd_pid_for_test(Some(-1));
    assert!(
        !unmapped_peer.is_pin_alive(),
        "Oracle 3: once pidfd reports Pid: -1, is_pin_alive() must be false"
    );
    assert!(
        !unmapped_peer.is_alive(&proc_root, "0"),
        "Oracle 3: once pidfd reports Pid: -1, is_alive(_, \"0\") must be false"
    );

    {
        let stream = UnixStream::connect(&reg_sock_seam).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        writer
            .write_all(b"{\"harness\":\"svc\",\"name\":\"guard\",\"cwd\":\"/workspace\"}\n")
            .await
            .unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let resp: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(resp["status"], "error", "{resp}");
        assert!(
            resp["detail"]
                .as_str()
                .unwrap_or("")
                .contains("is no longer alive"),
            "Oracle 3: reaped peer (Pid: -1) must be refused on leaf-mode svc registration: {resp}"
        );
    }

    process::set_force_pidfd_pid_for_test(None);
}
