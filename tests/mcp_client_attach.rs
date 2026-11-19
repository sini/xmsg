use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use xmsg::http::AppState;
use xmsg::mcp::{call_agent_sock_within, execute_tool, McpConfig};
use xmsg::registry::Session;
use xmsg::surface;

const TARGET: &str = "0199cecf-1234-7000-8000-000000005678";

struct ProxyHarness {
    state: Arc<AppState>,
    _dir: TempDir,
    proxy_sock: PathBuf,
    frames: Arc<Mutex<Vec<Value>>>,
    attach_connections: Arc<AtomicUsize>,
    total_connections: Arc<AtomicUsize>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for ProxyHarness {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl ProxyHarness {
    async fn new(max_attachment_bytes: usize) -> Self {
        let dir = tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir(&sessions).unwrap();

        let inbox_sock = dir.path().join("inbox.sock");
        let inbox_listener = UnixListener::bind(&inbox_sock).unwrap();
        let delivery = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = inbox_listener.accept().await else {
                    break;
                };
                let mut sink = Vec::new();
                let _ = stream.read_to_end(&mut sink).await;
            }
        });

        let pid = std::process::id();
        let start =
            xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), pid).unwrap();
        fs::write(
            sessions.join(format!("{pid}.json")),
            json!({
                "pid": pid,
                "sessionId": TARGET,
                "name": "recipient",
                "cwd": "/",
                "status": "idle",
                "kind": "interactive",
                "startedAt": 1,
                "updatedAt": 1,
                "procStart": start,
                "messagingSocketPath": inbox_sock,
            })
            .to_string(),
        )
        .unwrap();

        let conn = rusqlite::Connection::open(dir.path().join("state.db")).unwrap();
        xmsg::storage::init_db(&conn).unwrap();
        let state = Arc::new(AppState {
            sessions_dirs: vec![sessions.clone()],
            agy_config: xmsg::agy::AgyConfig {
                presence_dir: sessions.join("presence"),
                proc_locks_path: sessions.join("locks"),
                proc_root: PathBuf::from(xmsg::process::LIVE_PROC_ROOT),
                agy_bin: "agy".into(),
                trusted_agy_exes: Vec::new(),
                brain_dir: PathBuf::new(),
            },
            agy_store: xmsg::agy::new_agy_store(),
            pi_store: xmsg::pi::new_pi_store(),
            pi_notify_tx: tokio::sync::broadcast::channel(16).0,
            svc_store: xmsg::svc::new_svc_store(),
            svc_notify_tx: tokio::sync::broadcast::channel(16).0,
            node_name: "mcp-attach-test".into(),
            max_body: 65536,
            max_attachment_bytes,
            request_counter: AtomicU64::new(1),
            db: Arc::new(Mutex::new(conn)),
            notify_tx: tokio::sync::broadcast::channel(16).0,
            reply_ttl: Duration::from_secs(604800),
            idempotency_ttl: Duration::from_secs(86400),
            long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(16)),
            fed_state: None,
        });

        let real_agent_sock = dir.path().join("real-agent.sock");
        let server_sock = real_agent_sock.clone();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            xmsg::agent::run_agent_server(server_sock, server_state, xmsg::agy::current_uid())
                .await
                .unwrap();
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if UnixStream::connect(&real_agent_sock).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();

        let proxy_sock = dir.path().join("proxy-agent.sock");
        let proxy_listener = UnixListener::bind(&proxy_sock).unwrap();
        let frames = Arc::new(Mutex::new(Vec::new()));
        let attach_connections = Arc::new(AtomicUsize::new(0));
        let total_connections = Arc::new(AtomicUsize::new(0));

        let frames_clone = frames.clone();
        let attach_conns_clone = attach_connections.clone();
        let total_conns_clone = total_connections.clone();
        let upstream_sock = real_agent_sock.clone();
        let proxy = tokio::spawn(async move {
            loop {
                let Ok((client_stream, _)) = proxy_listener.accept().await else {
                    break;
                };
                total_conns_clone.fetch_add(1, Ordering::SeqCst);
                let frames_conn = frames_clone.clone();
                let attach_conns = attach_conns_clone.clone();
                let upstream_path = upstream_sock.clone();
                tokio::spawn(async move {
                    let upstream = UnixStream::connect(&upstream_path).await.unwrap();
                    let (client_r, mut client_w) = client_stream.into_split();
                    let (up_r, mut up_w) = upstream.into_split();
                    let mut client_lines = BufReader::new(client_r);
                    let mut up_lines = BufReader::new(up_r);
                    let mut first_frame = true;
                    loop {
                        let mut req_line = String::new();
                        let n = client_lines.read_line(&mut req_line).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        let parsed: Value = serde_json::from_str(&req_line).unwrap();
                        if first_frame {
                            first_frame = false;
                            if parsed.get("action").and_then(Value::as_str) == Some("attach") {
                                attach_conns.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        frames_conn.lock().unwrap().push(parsed);
                        up_w.write_all(req_line.as_bytes()).await.unwrap();
                        up_w.flush().await.unwrap();

                        let mut resp_line = String::new();
                        let rn = up_lines.read_line(&mut resp_line).await.unwrap();
                        if rn == 0 {
                            break;
                        }
                        client_w.write_all(resp_line.as_bytes()).await.unwrap();
                        client_w.flush().await.unwrap();
                    }
                });
            }
        });

        Self {
            state,
            _dir: dir,
            proxy_sock,
            frames,
            attach_connections,
            total_connections,
            tasks: vec![delivery, server, proxy],
        }
    }

    fn mcp_config(&self) -> McpConfig {
        McpConfig::new(self.state.sessions_dirs.clone(), "http://unused".into())
            .with_agent_sock(self.proxy_sock.clone())
    }

    fn reset_counters(&self) {
        self.frames.lock().unwrap().clear();
        self.attach_connections.store(0, Ordering::SeqCst);
        self.total_connections.store(0, Ordering::SeqCst);
    }
}

fn caller_session() -> Session {
    let mut s = surface::service_session(TARGET);
    s.harness = "claude".into();
    s
}

#[tokio::test]
async fn oracle_1_mcp_send_and_reply_stream_path_bytes_without_path_frame() {
    let h = ProxyHarness::new(1024 * 1024).await;
    let file_dir = tempdir().unwrap();
    let send_file = file_dir.path().join("send-doc.md");
    let send_bytes = b"# Send attachment\nRead by xmsg mcp, never by xmsg serve.\n";
    fs::write(&send_file, send_bytes).unwrap();
    let expected_send_sha = hex::encode(Sha256::digest(send_bytes));

    let cfg = h.mcp_config();
    let send_res = tokio::task::spawn_blocking(move || {
        let client = reqwest::blocking::Client::new();
        execute_tool(
            &cfg,
            &client,
            "send",
            &json!({
                "to": TARGET,
                "text": "hello with path attachment",
                "attachments": [{
                    "path": send_file,
                    "media_type": "text/markdown"
                }]
            }),
        )
    })
    .await
    .unwrap();
    assert_ne!(
        send_res.get("isError"),
        Some(&Value::Bool(true)),
        "{send_res}"
    );
    let send_text = send_res["content"][0]["text"].as_str().unwrap();
    let send_json: Value = serde_json::from_str(send_text).unwrap();
    let msg_id = send_json["message_id"].as_str().unwrap().to_string();

    {
        let frames = h.frames.lock().unwrap();
        assert!(
            frames.iter().all(|f| f.get("path").is_none()),
            "no agent.sock frame may carry 'path': {frames:?}"
        );
        let attach_frame = frames
            .iter()
            .find(|f| f["action"] == "attach")
            .expect("expected attach frame");
        assert_eq!(attach_frame["data"], STANDARD.encode(send_bytes));
        assert_eq!(attach_frame["name"], "send-doc.md");
        assert_eq!(attach_frame["media_type"], "text/markdown");
    }

    let read_sent =
        surface::read_attachment(&h.state, Some(&caller_session()), &msg_id, 0, 0, None)
            .await
            .unwrap();
    assert_eq!(read_sent["attachment"]["sha256"], expected_send_sha);
    assert_eq!(
        read_sent["data"].as_str().unwrap().as_bytes(),
        send_bytes.as_slice()
    );

    h.reset_counters();
    let reply_file = file_dir.path().join("reply-doc.md");
    let reply_bytes = b"# Reply attachment\nAlso staged from client process.\n";
    fs::write(&reply_file, reply_bytes).unwrap();
    let expected_reply_sha = hex::encode(Sha256::digest(reply_bytes));

    let cfg = h.mcp_config();
    let msg_id_for_reply = msg_id.clone();
    let reply_res = tokio::task::spawn_blocking(move || {
        let client = reqwest::blocking::Client::new();
        execute_tool(
            &cfg,
            &client,
            "reply",
            &json!({
                "message_id": msg_id_for_reply,
                "text": "replying with path attachment",
                "attachments": [{
                    "path": reply_file,
                    "media_type": "text/markdown"
                }]
            }),
        )
    })
    .await
    .unwrap();
    assert_ne!(
        reply_res.get("isError"),
        Some(&Value::Bool(true)),
        "{reply_res}"
    );
    let reply_text = reply_res["content"][0]["text"].as_str().unwrap();
    let reply_json: Value = serde_json::from_str(reply_text).unwrap();
    let reply_id = reply_json["messageId"].as_str().unwrap().to_string();

    {
        let frames = h.frames.lock().unwrap();
        assert!(
            frames.iter().all(|f| f.get("path").is_none()),
            "no agent.sock frame on reply may carry 'path': {frames:?}"
        );
        let attach_frame = frames
            .iter()
            .find(|f| f["action"] == "attach")
            .expect("expected reply attach frame");
        assert_eq!(attach_frame["data"], STANDARD.encode(reply_bytes));
    }

    let read_reply = surface::read_attachment(&h.state, None, &reply_id, 0, 0, None)
        .await
        .unwrap();
    assert_eq!(read_reply["attachment"]["sha256"], expected_reply_sha);
    assert_eq!(
        read_reply["data"].as_str().unwrap().as_bytes(),
        reply_bytes.as_slice()
    );
}

#[tokio::test]
async fn oracle_2_client_refuses_symlink_directory_and_fifo_before_socket() {
    let h = ProxyHarness::new(1024 * 1024).await;
    let dir = tempdir().unwrap();

    let real_file = dir.path().join("real.txt");
    fs::write(&real_file, b"secret").unwrap();
    let link_path = dir.path().join("link.txt");
    symlink(&real_file, &link_path).unwrap();

    let subdir = dir.path().join("subdir");
    fs::create_dir(&subdir).unwrap();

    let fifo_path = dir.path().join("named.fifo");
    let status = Command::new("mkfifo").arg(&fifo_path).status().unwrap();
    assert!(status.success(), "mkfifo must succeed");

    for (bad_path, expected_substr) in [
        (&link_path, "symlink"),
        (&subdir, "regular file"),
        (&fifo_path, "regular file"),
    ] {
        for tool in ["send", "reply"] {
            h.reset_counters();
            let cfg = h.mcp_config();
            let args = if tool == "send" {
                json!({
                    "to": TARGET,
                    "text": "should fail in client",
                    "attachments": [{"path": bad_path, "name": "bad.bin"}]
                })
            } else {
                json!({
                    "message_id": "01J00000000000000000000000",
                    "text": "should fail in client",
                    "attachments": [{"path": bad_path, "name": "bad.bin"}]
                })
            };
            let res = tokio::time::timeout(
                Duration::from_secs(2),
                tokio::task::spawn_blocking(move || {
                    let client = reqwest::blocking::Client::new();
                    execute_tool(&cfg, &client, tool, &args)
                }),
            )
            .await
            .expect("client path check must not block on FIFO or socket")
            .unwrap();
            assert_eq!(res.get("isError"), Some(&Value::Bool(true)), "{res}");
            let msg = res["content"][0]["text"].as_str().unwrap();
            assert!(
                msg.contains(expected_substr),
                "expected '{expected_substr}' in '{msg}' for {}",
                bad_path.display()
            );
            assert_eq!(
                h.total_connections.load(Ordering::SeqCst),
                0,
                "invalid path {} must be refused before connecting to agent.sock",
                bad_path.display()
            );
        }
    }
}

#[test]
fn oracle_3_agent_sock_read_timeout_reports_honest_seconds() {
    let home = tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let sock = home.path().join("agent.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let server = std::thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        let _ = done_rx.recv_timeout(Duration::from_secs(5));
    });

    let err = call_agent_sock_within(&sock, &json!({"action": "list"}), Duration::from_secs(1))
        .unwrap_err();
    let _ = done_tx.send(());
    server.join().unwrap();

    assert!(
        err.starts_with("timed out after 1 s"),
        "expected 'timed out after 1 s …', got: {err}"
    );
    assert!(
        !err.contains("os error") && !err.contains("Resource temporarily unavailable"),
        "timeout error must not leak raw EAGAIN/EWOULDBLOCK text: {err}"
    );
}

#[tokio::test]
async fn oracle_4_large_path_streams_chunks_on_single_connection_and_round_trips() {
    let h = ProxyHarness::new(1024 * 1024).await;
    let file_dir = tempdir().unwrap();
    let bin_file = file_dir.path().join("multi-chunk.bin");
    let original: Vec<u8> = (0..40_000usize)
        .map(|i| ((i.wrapping_mul(37).wrapping_add(13)) & 0xff) as u8)
        .collect();
    fs::write(&bin_file, &original).unwrap();
    let expected_sha = hex::encode(Sha256::digest(&original));

    h.reset_counters();
    let cfg = h.mcp_config();
    let send_res = tokio::task::spawn_blocking(move || {
        let client = reqwest::blocking::Client::new();
        execute_tool(
            &cfg,
            &client,
            "send",
            &json!({
                "to": TARGET,
                "text": "binary multi-chunk payload",
                "attachments": [{"path": bin_file}]
            }),
        )
    })
    .await
    .unwrap();
    assert_ne!(
        send_res.get("isError"),
        Some(&Value::Bool(true)),
        "{send_res}"
    );
    let send_json: Value =
        serde_json::from_str(send_res["content"][0]["text"].as_str().unwrap()).unwrap();
    let msg_id = send_json["message_id"].as_str().unwrap().to_string();

    assert_eq!(
        h.attach_connections.load(Ordering::SeqCst),
        1,
        "all chunks + finalization of >16 KiB attachment must reuse ONE agent.sock connection"
    );

    {
        let frames = h.frames.lock().unwrap();
        assert!(frames.iter().all(|f| f.get("path").is_none()));
        let attach_frames: Vec<&Value> =
            frames.iter().filter(|f| f["action"] == "attach").collect();
        // 40_000 bytes = 16384 + 16384 + 7232 (3 chunk frames) + 1 finalize frame = 4 frames
        assert_eq!(attach_frames.len(), 4, "{attach_frames:?}");
        assert_eq!(attach_frames[0]["offset"], 0);
        assert_eq!(attach_frames[1]["offset"], 16 * 1024);
        assert_eq!(attach_frames[2]["offset"], 32 * 1024);
        assert!(attach_frames[3].get("offset").is_none());
        assert_eq!(attach_frames[3]["sha256"], expected_sha);
        assert_eq!(attach_frames[3]["name"], "multi-chunk.bin");
    }

    let mut reassembled = Vec::new();
    let mut offset = 0usize;
    loop {
        let cfg = h.mcp_config();
        let mid = msg_id.clone();
        let read_res = tokio::task::spawn_blocking(move || {
            let client = reqwest::blocking::Client::new();
            execute_tool(
                &cfg,
                &client,
                "read_attachment",
                &json!({
                    "message_id": mid,
                    "index": 0,
                    "offset": offset,
                    "length": 15000
                }),
            )
        })
        .await
        .unwrap();
        assert_ne!(
            read_res.get("isError"),
            Some(&Value::Bool(true)),
            "{read_res}"
        );
        let page: Value =
            serde_json::from_str(read_res["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(page["attachment"]["sha256"], expected_sha);
        assert_eq!(page["attachment"]["media_type"], "application/octet-stream");
        let chunk_bytes = match page["encoding"].as_str().unwrap() {
            "base64" => STANDARD.decode(page["data"].as_str().unwrap()).unwrap(),
            "utf-8" => page["data"].as_str().unwrap().as_bytes().to_vec(),
            other => panic!("unexpected encoding {other}"),
        };
        reassembled.extend_from_slice(&chunk_bytes);
        match page.get("next").and_then(Value::as_u64) {
            Some(next) => offset = next as usize,
            None => break,
        }
    }
    assert_eq!(reassembled.len(), original.len());
    assert_eq!(reassembled, original);
}
