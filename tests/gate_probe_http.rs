use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::net::UnixListener;
use xmsg::http::{build_router, AppState};

fn get_self_proc_start() -> String {
    let stat = fs::read_to_string("/proc/self/stat").expect("read /proc/self/stat");
    let rparen = stat.rfind(')').expect("closing paren in stat");
    let fields: Vec<&str> = stat[rparen + 1..].split_whitespace().collect();
    fields[19].to_string()
}

struct TestHarness {
    _sess_dir: TempDir,
    _sock_dir: TempDir,
    base_url: String,
    stop_signal: Arc<AtomicBool>,
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
    }
}

async fn start_harness() -> TestHarness {
    let sess_dir = tempdir().expect("tempdir for sessions");
    let sock_dir = tempdir().expect("tempdir for socket");
    let sock_path = sock_dir.path().join("inbox.sock");

    let my_pid = std::process::id();
    let my_proc_start = get_self_proc_start();

    let listener = UnixListener::bind(&sock_path).expect("bind unix socket");
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_signal.clone();

    tokio::spawn(async move {
        while !stop_clone.load(Ordering::Relaxed) {
            tokio::select! {
                res = listener.accept() => {
                    if let Ok((mut stream, _)) = res {
                        use tokio::io::AsyncReadExt;
                        let mut temp = [0u8; 1024];
                        while let Ok(n) = stream.read(&mut temp).await {
                            if n == 0 { break; }
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
        },
        agy_store: xmsg::agy::new_agy_store(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx,
        host_label: "test-host".to_string(),
        max_body: 65536,
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
        stop_signal,
    }
}

#[tokio::test]
async fn test_gate_probe_b1_reserved_prefix_bypasses() {
    let harness = start_harness().await;
    let client = reqwest::Client::new();

    // B1: Leading invisible/format characters, quotes, brackets, and whitespace variations
    // attempting to bypass prefix enforcement and obtain a reserved badge
    let hostile_froms = vec![
        "\u{200b}session:evil",
        "\u{200b}\u{feff}session:evil",
        "\x07session:evil",
        "\"session:evil\"",
        "<session:evil>",
        "   session:evil",
        "\t\nsession:evil",
        "\u{200b}session/evil",
        "session/evil",
        "Session:evil",
        "SESSION:evil",
        "sEsSiOn/evil",
    ];

    for hostile in hostile_froms {
        let res = client
            .post(format!(
                "{}/v1/sessions/my-worker/messages",
                harness.base_url
            ))
            .json(&serde_json::json!({
                "from": hostile,
                "text": "attempting prefix spoof"
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(
            res.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "Hostile from '{:?}' must be rejected with 400 Bad Request",
            hostile
        );
    }

    // Verify legitimate senders are accepted
    let res = client
        .post(format!(
            "{}/v1/sessions/my-worker/messages",
            harness.base_url
        ))
        .json(&serde_json::json!({
            "from": "legit-sender",
            "text": "hello"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::ACCEPTED);
}
