use super::*;
use std::{
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::net::UnixStream,
    },
    process::{Child, Command, Stdio},
    sync::Mutex,
};

fn state(root: &std::path::Path) -> Arc<AppState> {
    let sessions = root.join("sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    let connection = rusqlite::Connection::open(root.join("state.db")).unwrap();
    crate::storage::init_db(&connection).unwrap();
    Arc::new(AppState {
        sessions_dirs: vec![sessions.clone()],
        agy_config: crate::agy::AgyConfig {
            proc_root: crate::process::LIVE_PROC_ROOT.into(),
            presence_dir: sessions.join("presence"),
            proc_locks_path: sessions.join("locks"),
            ..Default::default()
        },
        agy_store: crate::agy::new_agy_store(),
        pi_store: crate::pi::new_pi_store(),
        pi_notify_tx: tokio::sync::broadcast::channel(16).0,
        svc_store: crate::svc::new_svc_store(),
        svc_notify_tx: tokio::sync::broadcast::channel(16).0,
        node_name: "attribution-test".into(),
        max_body: 65536,
        max_attachment_bytes: 65536,
        request_counter: std::sync::atomic::AtomicU64::new(1),
        db: Arc::new(Mutex::new(connection)),
        notify_tx: tokio::sync::broadcast::channel(16).0,
        reply_ttl: Duration::from_secs(60),
        idempotency_ttl: Duration::from_secs(60),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
        fed_state: None,
    })
}
struct OwnedFixtureChild(Child);
impl Drop for OwnedFixtureChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn helper(role: &str, root: &std::path::Path) -> (OwnedFixtureChild, UnixStream) {
    use std::os::unix::process::CommandExt;
    let (parent, child) = UnixStream::pair().unwrap();
    parent
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    parent
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let descriptor = child.as_raw_fd();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            "caller_attribution::tests::fixture_process",
            "--nocapture",
        ])
        .env("XMSG_ATTRIBUTION_FIXTURE_ROLE", role)
        .env("XMSG_ATTRIBUTION_FIXTURE_ROOT", root)
        .env("XMSG_ATTRIBUTION_FIXTURE_FD", descriptor.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .process_group(0);
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(descriptor, libc::F_GETFD);
            if flags < 0 || libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let process = OwnedFixtureChild(command.spawn().unwrap());
    drop(child);
    (process, parent)
}

#[test]
#[ignore = "test-only owned process entrypoint, exercised and reaped by parent attribution cases"]
fn fixture_process() {
    let role = std::env::var("XMSG_ATTRIBUTION_FIXTURE_ROLE").unwrap();
    let root = PathBuf::from(std::env::var_os("XMSG_ATTRIBUTION_FIXTURE_ROOT").unwrap());
    let fd = std::env::var("XMSG_ATTRIBUTION_FIXTURE_FD")
        .unwrap()
        .parse()
        .unwrap();
    let mut control = unsafe { UnixStream::from_raw_fd(fd) };
    control
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    if role == "caller" {
        let mut stream = UnixStream::connect(root.join("life.sock")).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(b"R").unwrap();
        control.write_all(b"R").unwrap();
        let mut done = [0];
        stream.read_exact(&mut done).unwrap();
        return;
    }
    assert!(matches!(
        role.as_str(),
        "daemon"
            | "unqualified"
            | "changed-facts"
            | "expired-facts"
            | "incomplete-reaper"
            | "incomplete-match"
            | "wrong-endpoint"
    ));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    let wrong_listener = if role == "wrong-endpoint" {
        let listener = UnixListener::bind(root.join("other-life.sock")).unwrap();
        std::fs::set_permissions(
            root.join("other-life.sock"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        Some(listener)
    } else {
        None
    };
    let config = ServerConfig {
        query_socket: root.join("query.sock"),
        lifecycle_socket: root.join(if wrong_listener.is_some() {
            "other-life.sock"
        } else {
            "life.sock"
        }),
        expected_uid: crate::client::current_uid(),
    };
    let app = state(&root);
    let _ = crate::codex::for_state(&app);
    let handle = if role != "unqualified" {
        bind(
            config,
            app.clone(),
            Arc::new(FixtureFacts {
                expires: if role == "expired-facts" {
                    Instant::now()
                } else {
                    Instant::now() + Duration::from_secs(30)
                },
                revision: std::sync::atomic::AtomicU64::new(1),
                drift: role == "changed-facts",
                reaper_complete: role != "incomplete-reaper",
                match_complete: role != "incomplete-match",
            }),
        )
        .unwrap()
    } else {
        bind_unqualified(config, app).unwrap()
    };
    control.write_all(b"R").unwrap();
    let mut done = [0];
    let _ = control.read_exact(&mut done);
    handle.stop();
}
fn directory() -> tempfile::TempDir {
    let root = std::path::Path::new("/tmp").canonicalize().unwrap();
    let directory = tempfile::Builder::new()
        .prefix("xa-")
        .tempdir_in(root)
        .unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}
fn roundtrip(role: &str) -> Reply {
    roundtrip_with_peer(role).0
}
fn authority_snapshot(file: &std::path::Path) -> Vec<(String, Vec<String>)> {
    let connection = rusqlite::Connection::open(file).unwrap();
    let mut statement = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap();
    let tables = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let escaped = table.replace('"', "\"\"");
            let mut query = connection
                .prepare(&format!("SELECT * FROM \"{escaped}\""))
                .unwrap();
            let columns = query.column_count();
            let mut rows = query
                .query_map([], |row| {
                    Ok((0..columns)
                        .map(|column| format!("{:?}", row.get_ref(column).unwrap()))
                        .collect::<Vec<_>>()
                        .join("|"))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            rows.sort();
            (table, rows)
        })
        .collect()
}
fn roundtrip_with_peer(role: &str) -> (Reply, u32) {
    use std::os::fd::AsFd;
    let directory = directory();
    std::fs::create_dir(directory.path().join("sessions")).unwrap();
    let listener = UnixListener::bind(directory.path().join("life.sock")).unwrap();
    std::fs::set_permissions(
        directory.path().join("life.sock"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let (caller, mut caller_control) = helper("caller", directory.path());
    let mut ready = [0];
    caller_control.read_exact(&mut ready).unwrap();
    listener.set_nonblocking(true).unwrap();
    let (mut original, _) = listener.accept().unwrap();
    original.set_nonblocking(false).unwrap();
    original.read_exact(&mut ready).unwrap();
    let id = "11111111-1111-4111-8111-111111111111";
    let start = crate::process::starttime(
        std::path::Path::new(crate::process::LIVE_PROC_ROOT),
        caller.0.id(),
    )
    .unwrap();
    std::fs::write(directory.path().join("sessions").join(format!("{id}.json")),serde_json::json!({
        "sessionId":id,"pid":caller.0.id(),"procStart":start,"cwd":"/","status":"idle","kind":"interactive","startedAt":1,"updatedAt":1,"messagingSocketPath":directory.path().join("caller-inbox.sock")
    }).to_string()).unwrap();
    let (daemon, mut daemon_control) = helper(role, directory.path());
    daemon_control.read_exact(&mut ready).unwrap();
    let before = authority_snapshot(&directory.path().join("state.db"));
    let deadline = Instant::now() + AUTHORITY_BUDGET;
    let stream = wire::connect(&directory.path().join("query.sock"), deadline).unwrap();
    let mut hash = Sha256::new();
    hash.update(wire::CONTEXT_DOMAIN);
    hash.update(wire::context_bytes(&None).unwrap());
    let query = wire::Query {
        v: wire::VERSION,
        runtime_epoch: "a".repeat(32),
        call_nonce: 1,
        input_digest: "b".repeat(64),
        context: None,
        context_digest: hex::encode(hash.finalize()),
    };
    wire::send_query(&stream, original.as_fd(), &query, deadline).unwrap();
    let reply = wire::receive_reply(&stream, deadline).unwrap();
    assert_eq!(
        authority_snapshot(&directory.path().join("state.db")),
        before,
        "real daemon query mutated authority or queue rows"
    );
    original.write_all(b"D").unwrap();
    daemon_control.write_all(b"D").unwrap();
    let original_pid = caller.0.id();
    drop(caller);
    drop(daemon);
    (reply, original_pid)
}
#[test]
fn default_unqualified_receiver_never_returns_principal() {
    assert!(matches!(
        roundtrip("unqualified"),
        Reply::Unavailable {
            reason: FailureReason::Unqualified,
            ..
        }
    ));
}
#[test]
fn real_daemon_fixture_resolves_original_registered_process() {
    let (reply, original_pid) = roundtrip_with_peer("daemon");
    match reply {
        Reply::Ok {
            principal,
            peer_uid,
            peer_pid,
            ..
        } => {
            assert_eq!(
                peer_uid,
                crate::client::current_uid(),
                "daemon reply used query UID instead of original"
            );
            assert_eq!(
                peer_pid, original_pid,
                "daemon reply used query PID instead of original"
            );
            assert_eq!(
                principal,
                "11111111-1111-4111-8111-111111111111@attribution-test"
            );
        }
        other => panic!("real daemon failed original attribution: {other:?}"),
    }
}
#[test]
fn changed_ongoing_eligibility_never_publishes_principal() {
    assert!(
        matches!(
            roundtrip("changed-facts"),
            Reply::Unavailable {
                reason: FailureReason::Changed,
                ..
            }
        ),
        "changed eligibility published principal"
    );
}
#[test]
fn expired_eligibility_never_publishes_principal() {
    assert!(
        matches!(
            roundtrip("expired-facts"),
            Reply::Unavailable {
                reason: FailureReason::Unqualified,
                ..
            }
        ),
        "expired eligibility published principal"
    );
}
#[test]
fn incomplete_reaper_domain_never_publishes_principal() {
    assert!(
        matches!(
            roundtrip("incomplete-reaper"),
            Reply::Unavailable {
                reason: FailureReason::Unqualified,
                ..
            }
        ),
        "incomplete reaper domain published principal"
    );
}
#[test]
fn incomplete_match_domain_never_publishes_principal() {
    assert!(
        matches!(
            roundtrip("incomplete-match"),
            Reply::Unavailable {
                reason: FailureReason::Unqualified,
                ..
            }
        ),
        "incomplete matched domain published principal"
    );
}
#[test]
fn original_from_another_owner_endpoint_never_publishes_principal() {
    assert!(
        matches!(
            roundtrip("wrong-endpoint"),
            Reply::Unavailable {
                reason: FailureReason::Endpoint,
                ..
            }
        ),
        "wrong lifecycle endpoint published a principal"
    );
}

#[test]
fn stalled_clients_have_fixed_workers_and_bounded_shutdown() {
    let directory = directory();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    let socket = directory.path().join("query.sock");
    let handle = bind_unqualified(
        ServerConfig {
            query_socket: socket.clone(),
            lifecycle_socket: directory.path().join("life.sock"),
            expected_uid: crate::client::current_uid(),
        },
        state(directory.path()),
    )
    .unwrap();
    assert_eq!(
        handle.workers.len(),
        4,
        "accepted work must use exactly four reserved workers"
    );
    let mut clients = Vec::new();
    for _ in 0..4 {
        clients.push(UnixStream::connect(&socket).unwrap());
    }
    let stats = handle.stats();
    let ready = Instant::now() + AUTHORITY_BUDGET;
    while stats.active() != 4 && Instant::now() < ready {
        std::thread::yield_now();
    }
    assert_eq!(
        stats.active(),
        4,
        "all four stalled clients must enter actual frame reads"
    );
    assert_eq!(
        stats.peak(),
        4,
        "inflight work exceeded the reserved worker bound"
    );
    let stop = Instant::now();
    handle.stop();
    assert!(
        stop.elapsed() < Duration::from_secs(3),
        "stalled frame reads escaped the absolute worker deadline"
    );
    assert_eq!(
        stats.active(),
        0,
        "shutdown must join and release all accepted work"
    );
    assert_eq!(
        stats.resolved(),
        0,
        "partial requests must never resolve authority"
    );
    assert!(
        !socket.exists(),
        "shutdown must unlink only its own query endpoint"
    );
    for mut client in clients {
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0];
        assert_eq!(
            client.read(&mut byte).unwrap(),
            0,
            "stalled accepted sockets must close during shutdown"
        );
    }
}
