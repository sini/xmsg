use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncWrite, BufReader};
use xmsg::http::AppState;
use xmsg::process::{self, PeerCred};
use xmsg::svc::{self, SvcRegisterRequest, SvcSessionInfo};

fn state(proc_root: PathBuf) -> Arc<AppState> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let (notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(16);
    Arc::new(AppState {
        max_attachment_bytes: 8 * 1024 * 1024,
        db: Arc::new(Mutex::new(conn)),
        sessions_dirs: vec![],
        max_body: 65536,
        node_name: "fixture".into(),
        request_counter: AtomicU64::new(0),
        notify_tx,
        agy_config: xmsg::agy::AgyConfig {
            trusted_agy_exes: vec![],
            presence_dir: PathBuf::new(),
            brain_dir: PathBuf::new(),
            proc_locks_path: proc_root.join("locks"),
            proc_root,
            agy_bin: "agy".into(),
        },
        agy_store: xmsg::agy::new_agy_store(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx,
        svc_store: svc::new_svc_store(),
        svc_notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(3600),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(8)),
        fed_state: None,
    })
}

#[derive(Clone)]
struct RecordingWriter(Arc<Mutex<Vec<u8>>>, bool);
impl AsyncWrite for RecordingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.1 {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        self.0.lock().unwrap().extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn svc_child_connect_helper() {
    let Some(socket) = std::env::var_os("XMSG_SVC_TEST_SOCKET") else {
        return;
    };
    let _stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
    println!("READY");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "exit");
}

async fn exited_peer() -> PeerCred {
    let temp = tempfile::Builder::new()
        .prefix("svc-life-")
        .tempdir_in("/tmp")
        .unwrap();
    let socket = temp.path().join("peer.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["svc_child_connect_helper", "--exact", "--nocapture"])
        .env("XMSG_SVC_TEST_SOCKET", &socket)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let native = process::peer_cred(&stream).unwrap();
    assert_eq!(
        native.pid_or_zero(),
        child.id(),
        "native credential positive control"
    );
    assert!(process::starttime(Path::new(process::LIVE_PROC_ROOT), child.id()).is_ok());
    writeln!(child.stdin.as_mut().unwrap(), "exit").unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(exit) = child.try_wait().unwrap() {
            assert!(exit.success());
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("child exit deadline");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(process::starttime(Path::new(process::LIVE_PROC_ROOT), native.pid_or_zero()).is_err());
    PeerCred::unpinned(native.uid, native.pid_or_zero())
}

#[tokio::test]
async fn exited_fallback_peer_is_refused_before_registration() {
    let peer = exited_peer().await;
    let state = state(PathBuf::from(process::LIVE_PROC_ROOT));
    let output = Arc::new(Mutex::new(Vec::new()));
    let result = svc::handle_svc_connection_peer(
        BufReader::new(&b""[..]),
        RecordingWriter(output.clone(), false),
        state.clone(),
        &HashMap::new(),
        unsafe { libc::geteuid() },
        peer,
        SvcRegisterRequest {
            harness: None,
            name: "worker".into(),
            cwd: None,
        },
        true,
        Some("svc:worker".into()),
    )
    .await;
    let frames = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert!(
        result.is_err() && frames.contains("not_found") && !frames.contains("\"status\":\"ok\""),
        "exited native fallback must be refused, not registered: {frames}"
    );
    assert!(state.svc_store.read().unwrap().is_empty());
}

#[tokio::test]
async fn stored_zero_does_not_keep_a_gone_readable_peer_live() {
    let peer = exited_peer().await;
    let info = SvcSessionInfo {
        session_id: "worker".into(),
        name: "worker".into(),
        pid: peer.pid_or_zero(),
        starttime: "0".into(),
        cwd: "/".into(),
        registered_at: 0,
        token: 1,
        liveness: None,
    };
    assert!(
        !svc::is_svc_session_alive(Path::new(process::LIVE_PROC_ROOT), &info),
        "stored zero must not resurrect a known-gone process"
    );
}

#[tokio::test]
async fn failed_registration_ack_does_not_leave_a_portable_ghost() {
    let temp = tempfile::tempdir().unwrap();
    let state = state(temp.path().join("unavailable-proc"));
    let result = svc::handle_svc_connection_peer(
        BufReader::new(&b""[..]),
        RecordingWriter(Arc::new(Mutex::new(vec![])), true),
        state.clone(),
        &HashMap::new(),
        unsafe { libc::geteuid() },
        PeerCred::unpinned(unsafe { libc::geteuid() }, std::process::id()),
        SvcRegisterRequest {
            harness: None,
            name: "worker".into(),
            cwd: None,
        },
        true,
        Some("svc:worker".into()),
    )
    .await;
    assert!(result.is_err(), "writer fault positive control");
    assert!(
        state.svc_store.read().unwrap().is_empty(),
        "failed ACK left a ghost registration"
    );
}

#[tokio::test]
async fn live_portable_peer_is_registered() {
    let temp = tempfile::tempdir().unwrap();
    let state = state(temp.path().join("unavailable-proc"));
    let output = Arc::new(Mutex::new(Vec::new()));
    let result = svc::handle_svc_connection_peer(
        BufReader::new(&b""[..]),
        RecordingWriter(output.clone(), false),
        state,
        &HashMap::new(),
        unsafe { libc::geteuid() },
        PeerCred::unpinned(unsafe { libc::geteuid() }, std::process::id()),
        SvcRegisterRequest {
            harness: None,
            name: "worker".into(),
            cwd: None,
        },
        true,
        Some("svc:worker".into()),
    )
    .await;
    let frames = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert!(
        result.is_ok() && frames.contains("\"status\":\"ok\""),
        "live portable positive control: {frames}"
    );
}

async fn running_registration(
    state: Arc<AppState>,
) -> (tokio::task::JoinHandle<()>, tokio::io::DuplexStream) {
    let (read, connection) = tokio::io::duplex(64);
    let output = Arc::new(Mutex::new(Vec::new()));
    let captured = output.clone();
    let task_state = state.clone();
    let task = tokio::spawn(async move {
        let _ = svc::handle_svc_connection_peer(
            BufReader::new(read),
            RecordingWriter(captured, false),
            task_state,
            &HashMap::new(),
            unsafe { libc::geteuid() },
            PeerCred::unpinned(unsafe { libc::geteuid() }, std::process::id()),
            SvcRegisterRequest {
                harness: None,
                name: "worker".into(),
                cwd: None,
            },
            true,
            Some("svc:worker".into()),
        )
        .await;
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while output.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("registration ACK barrier");
    assert!(String::from_utf8(output.lock().unwrap().clone())
        .unwrap()
        .contains("\"status\":\"ok\""));
    (task, connection)
}

#[tokio::test]
async fn cancelled_registration_does_not_leave_a_portable_ghost() {
    let temp = tempfile::tempdir().unwrap();
    let state = state(temp.path().join("unavailable-proc"));
    let (task, _connection) = running_registration(state.clone()).await;
    let snapshot = state
        .svc_store
        .read()
        .unwrap()
        .get("worker")
        .unwrap()
        .clone();
    assert!(svc::is_svc_session_alive(
        &state.agy_config.proc_root,
        &snapshot
    ));
    task.abort();
    let _ = task.await;
    assert!(
        state.svc_store.read().unwrap().is_empty(),
        "cancelled registration left a ghost"
    );
    assert!(
        !svc::is_svc_session_alive(&state.agy_config.proc_root, &snapshot),
        "cloned connection witness stayed live"
    );
}

#[tokio::test]
async fn old_cleanup_never_removes_a_new_registration() {
    let temp = tempfile::tempdir().unwrap();
    let state = state(temp.path().join("unavailable-proc"));
    let (old, _old_connection) = running_registration(state.clone()).await;
    let old_token = state.svc_store.read().unwrap()["worker"].token;
    let (new, _new_connection) = running_registration(state.clone()).await;
    let new_token = state.svc_store.read().unwrap()["worker"].token;
    assert_ne!(old_token, new_token);
    old.abort();
    let _ = old.await;
    let current = state.svc_store.read().unwrap().get("worker").cloned();
    new.abort();
    let _ = new.await;
    assert_eq!(
        current.as_ref().map(|info| info.token),
        Some(new_token),
        "old cleanup removed the newer registration"
    );
    assert!(state.svc_store.read().unwrap().is_empty());
}

struct FailingReader;
impl tokio::io::AsyncRead for FailingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
    }
}
impl tokio::io::AsyncBufRead for FailingReader {
    fn poll_fill_buf(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<&[u8]>> {
        Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
    }
    fn consume(self: Pin<&mut Self>, _: usize) {}
}

#[tokio::test]
async fn read_error_does_not_leave_a_portable_ghost() {
    let temp = tempfile::tempdir().unwrap();
    let state = state(temp.path().join("unavailable-proc"));
    let output = Arc::new(Mutex::new(Vec::new()));
    let result = svc::handle_svc_connection_peer(
        FailingReader,
        RecordingWriter(output.clone(), false),
        state.clone(),
        &HashMap::new(),
        unsafe { libc::geteuid() },
        PeerCred::unpinned(unsafe { libc::geteuid() }, std::process::id()),
        SvcRegisterRequest {
            harness: None,
            name: "worker".into(),
            cwd: None,
        },
        true,
        Some("svc:worker".into()),
    )
    .await;
    assert!(
        String::from_utf8(output.lock().unwrap().clone())
            .unwrap()
            .contains("\"status\":\"ok\""),
        "read fault follows successful registration"
    );
    assert!(result.is_err());
    assert!(
        state.svc_store.read().unwrap().is_empty(),
        "read failure left a ghost"
    );
}
