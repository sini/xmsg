use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use xmsg::http::{build_router, AppState};

fn get_self_proc_start() -> String {
    xmsg::process::starttime(
        std::path::Path::new(xmsg::process::LIVE_PROC_ROOT),
        std::process::id(),
    )
    .expect("live starttime")
}

struct TestHarness {
    _sess_dir: TempDir,
    _sock_dir: TempDir,
    base_url: String,
    _received_lines: Arc<Mutex<Vec<String>>>,
    stop_signal: Arc<AtomicBool>,
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
    }
}

async fn start_harness(max_body: usize) -> TestHarness {
    let sess_dir = tempdir().expect("tempdir for sessions");
    let sock_dir = tempdir().expect("tempdir for socket");
    let sock_path = sock_dir.path().join("inbox.sock");

    let my_pid = std::process::id();
    let my_proc_start = get_self_proc_start();

    let listener = UnixListener::bind(&sock_path).expect("bind unix socket");
    let received_lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let received_clone = received_lines.clone();
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_signal.clone();

    tokio::spawn(async move {
        while !stop_clone.load(Ordering::Relaxed) {
            tokio::select! {
                res = listener.accept() => {
                    if let Ok((mut stream, _)) = res {
                        let mut buf = Vec::new();
                        let mut temp = [0u8; 1024];
                        while let Ok(n) = stream.read(&mut temp).await {
                            if n == 0 { break; }
                            buf.extend_from_slice(&temp[..n]);
                            if buf.ends_with(b"\n") {
                                break;
                            }
                        }
                        if let Ok(s) = String::from_utf8(buf) {
                            received_clone.lock().await.push(s);
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
    });

    let live_json = format!(
        r#"{{
            "pid": {my_pid},
            "sessionId": "live-session-1234",
            "name": "my-worker",
            "cwd": "/workspace/project-a",
            "status": "idle",
            "kind": "interactive",
            "startedAt": 1000,
            "updatedAt": 2000,
            "procStart": "{my_proc_start}",
            "messagingSocketPath": "{}"
        }}"#,
        sock_path.display()
    );
    fs::write(sess_dir.path().join(format!("{my_pid}.json")), live_json).unwrap();

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let (notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);

    let app_state = Arc::new(AppState {
        sessions_dir: sess_dir.path().to_path_buf(),
        agy_config: xmsg::agy::AgyConfig {
            presence_dir: sess_dir.path().join("presence"),
            proc_locks_path: sess_dir.path().join("proc_locks"),
            proc_root: PathBuf::from("/proc"),
            agy_bin: "agy".to_string(),
            trusted_agy_exes: Vec::new(),
        },
        agy_store: xmsg::agy::new_agy_store(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx,
        host_label: "test-host".to_string(),
        max_body,
        request_counter: AtomicU64::new(1),
        db: Arc::new(std::sync::Mutex::new(conn)),
        notify_tx,
        reply_ttl: Duration::from_secs(604800),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
    });

    let app = build_router(app_state);
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp_listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        axum::serve(tcp_listener, app).await.unwrap();
    });

    TestHarness {
        _sess_dir: sess_dir,
        _sock_dir: sock_dir,
        base_url,
        _received_lines: received_lines,
        stop_signal,
    }
}

async fn post_from(base: &str, from: &str) -> (reqwest::StatusCode, serde_json::Value) {
    let res = reqwest::Client::new()
        .post(format!("{base}/v1/sessions/my-worker/messages"))
        .json(&serde_json::json!({"from": from, "text": "probe"}))
        .send()
        .await
        .unwrap();
    let st = res.status();
    (st, res.json().await.unwrap_or(serde_json::Value::Null))
}

#[tokio::test]
async fn gate2_http_prefix() {
    let h = start_harness(65536).await;

    // 1. Control arm: legitimate ASCII sender
    let (st, v) = post_from(&h.base_url, "claude").await;
    assert_eq!(st, reqwest::StatusCode::ACCEPTED);
    assert_eq!(v["fromName"], "xmsg@test-host · claude");

    // 2. B1 arms: reserved prefix variations and bypasses
    for from in [
        "session:evil",
        "\u{200B}session:evil",
        "\"session:evil",
        "<session:evil",
        "\u{0007}session:evil",
        "SESSION:evil",
        "session/evil",
    ] {
        let (st, v) = post_from(&h.base_url, from).await;
        assert_eq!(
            st,
            reqwest::StatusCode::BAD_REQUEST,
            "from={from:?} must return 400 Bad Request"
        );
        assert_eq!(v["error"], "bad_sender");
    }

    // 3. C1 lookalike arms: non-ASCII confusable characters
    for from in [
        "session\u{A789}evil",
        "\u{FF53}\u{FF45}\u{FF53}\u{FF53}\u{FF49}\u{FF4F}\u{FF4E}\u{FF1A}evil",
        "\u{0455}session:evil",
        "session\u{00A0}:evil",
    ] {
        let (st, v) = post_from(&h.base_url, from).await;
        assert_eq!(
            st,
            reqwest::StatusCode::BAD_REQUEST,
            "lookalike {from:?} must return 400 Bad Request"
        );
        assert_eq!(v["error"], "bad_sender");
    }

    // 4. Any character outside printable ASCII (0x20..=0x7E) is rejected
    for from in ["alice🦀", "worker\t1", "user\nname"] {
        let (st, v) = post_from(&h.base_url, from).await;
        assert_eq!(
            st,
            reqwest::StatusCode::BAD_REQUEST,
            "non-ASCII {from:?} must return 400 Bad Request"
        );
        assert_eq!(v["error"], "bad_sender");
    }

    // 5. Valid printable ASCII names succeed
    for from in ["alice-worker_1", "bob.agent", "lead 123"] {
        let (st, _) = post_from(&h.base_url, from).await;
        assert_eq!(
            st,
            reqwest::StatusCode::ACCEPTED,
            "valid ASCII {from:?} must return 202 Accepted"
        );
    }
}
