use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicU64, Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use xmsg::client::{AttachRequest, AttachmentRef};
use xmsg::http::AppState;
use xmsg::registry::Session;
use xmsg::surface::{self, Sender};

const TARGET: &str = "0199cecf-1234-7000-8000-000000001234";

struct Harness {
    state: Arc<AppState>,
    _dir: TempDir,
    agent: PathBuf,
    url: String,
    received: Arc<Mutex<Vec<String>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Harness {
    async fn new(cap: usize) -> Self {
        let dir = tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir(&sessions).unwrap();
        let socket = dir.path().join("inbox.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let messages = received.clone();
        let delivery = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                stream.read_to_end(&mut bytes).await.unwrap();
                if !bytes.is_empty() {
                    messages
                        .lock()
                        .unwrap()
                        .push(String::from_utf8(bytes).unwrap());
                }
            }
        });
        let pid = std::process::id();
        let start =
            xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), pid).unwrap();
        fs::write(
            sessions.join(format!("{pid}.json")),
            json!({
                "pid":pid,"sessionId":TARGET,"name":"recipient","cwd":"/", "status":"idle",
                "kind":"interactive","startedAt":1,"updatedAt":1,"procStart":start,
                "messagingSocketPath":socket
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
            node_name: "attachment-test".into(),
            max_body: 65536,
            max_attachment_bytes: cap,
            request_counter: AtomicU64::new(1),
            db: Arc::new(Mutex::new(conn)),
            notify_tx: tokio::sync::broadcast::channel(16).0,
            reply_ttl: Duration::from_secs(604800),
            idempotency_ttl: Duration::from_secs(86400),
            long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(16)),
            fed_state: None,
        });
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", tcp.local_addr().unwrap());
        let router = xmsg::http::build_router(state.clone());
        let http = tokio::spawn(async move {
            axum::serve(tcp, router).await.unwrap();
        });
        let agent = dir.path().join("agent.sock");
        let socket_path = agent.clone();
        let socket_state = state.clone();
        let server = tokio::spawn(async move {
            xmsg::agent::run_agent_server(socket_path, socket_state, xmsg::agy::current_uid())
                .await
                .unwrap();
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if UnixStream::connect(&agent).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        Self {
            state,
            _dir: dir,
            agent,
            url,
            received,
            tasks: vec![delivery, http, server],
        }
    }

    async fn socket(&self, request: Value) -> Value {
        let mut stream = UnixStream::connect(&self.agent).await.unwrap();
        stream
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            BufReader::new(stream).read_line(&mut line),
        )
        .await
        .unwrap()
        .unwrap();
        serde_json::from_str(&line).unwrap()
    }

    async fn stage(&self, sender: &Sender, bytes: &[u8]) -> AttachmentRef {
        let answer = surface::attach(
            &self.state,
            sender,
            AttachRequest {
                name: Some("report.txt".into()),
                media_type: Some("text/plain".into()),
                data: Some(STANDARD.encode(bytes)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        serde_json::from_value(answer["attachment"].clone()).unwrap()
    }

    async fn send(
        &self,
        sender: &Sender,
        refs: &[AttachmentRef],
        key: Option<&str>,
    ) -> xmsg::surface::SendResult {
        surface::send_with_attachments(&self.state, sender, "recipient", "file", key, refs)
            .await
            .unwrap()
    }
}

fn session(id: &str) -> Session {
    surface::service_session(id)
}
fn sender(id: &str) -> Sender {
    Sender::Session(session(id))
}
fn recipient() -> Session {
    let mut s = session(TARGET);
    s.harness = "claude".into();
    s
}

#[tokio::test]
async fn oracle_1_sender_recipient_read_and_third_session_is_denied() {
    let h = Harness::new(1024).await;
    let a = sender("sender-a");
    let b = recipient();
    let c = session("outsider");
    let reference = h.stage(&a, b"private payload").await;
    let sent = h.send(&a, &[reference], None).await;
    for caller in [&session("sender-a"), &b] {
        let range = surface::read_attachment(&h.state, Some(caller), &sent.message_id, 0, 0, None)
            .await
            .unwrap();
        assert_eq!(range["data"], "private payload");
    }
    assert_eq!(
        surface::read_attachment(&h.state, Some(&c), &sent.message_id, 0, 0, None)
            .await
            .unwrap_err()
            .code()
            .1,
        "denied"
    );
    assert_eq!(
        surface::read_attachment(&h.state, None, &sent.message_id, 0, 0, None)
            .await
            .unwrap_err()
            .code()
            .1,
        "denied"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !h.received.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let line: Value = serde_json::from_str(&h.received.lock().unwrap()[0]).unwrap();
    assert!(line["message"]["content"]
        .as_str()
        .unwrap()
        .contains("attachment 0: name=\"report.txt\""));
}

#[tokio::test]
async fn oracle_4_hash_needs_staging_or_a_readable_received_item() {
    let h = Harness::new(1024).await;
    let a = sender("sender-a");
    let c = sender("outsider");
    let reference = h.stage(&a, b"scoped").await;
    let refused = surface::send_with_attachments(
        &h.state,
        &c,
        "recipient",
        "stolen",
        None,
        std::slice::from_ref(&reference),
    )
    .await
    .unwrap_err();
    assert_eq!(refused.code().1, "not_found");
    let sent = h.send(&a, std::slice::from_ref(&reference), None).await;
    let forwarded = h
        .send(
            &Sender::Session(recipient()),
            std::slice::from_ref(&reference),
            None,
        )
        .await;
    assert_ne!(sent.message_id, forwarded.message_id);
    assert_eq!(
        surface::read_attachment(
            &h.state,
            Some(&recipient()),
            &forwarded.message_id,
            0,
            0,
            None
        )
        .await
        .unwrap()["data"],
        "scoped"
    );
}

#[tokio::test]
async fn oracle_7_upload_and_chunk_caps_apply_on_socket_and_http() {
    let h = Harness::new(4).await;
    let over = h
        .socket(json!({"action":"attach","name":"big","data":STANDARD.encode(b"12345")}))
        .await;
    assert_eq!(over["error"], "payload_too_large");
    let first = h
        .socket(json!({"action":"attach","upload":"u","offset":0,"data":STANDARD.encode(b"123")}))
        .await;
    assert_eq!(first["size"], 3);
    let over = h
        .socket(json!({"action":"attach","upload":"u","offset":3,"data":STANDARD.encode(b"45")}))
        .await;
    assert_eq!(over["error"], "payload_too_large");
    let response = reqwest::Client::new()
        .post(format!("{}/v1/attachments?name=big", h.url))
        .body("12345")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        "payload_too_large"
    );
}

#[tokio::test]
async fn oracle_8_ranges_bound_bytes_and_preserve_utf8() {
    let h = Harness::new(100000).await;
    let a = sender("sender-a");
    let reference = h.stage(&a, "a€z".as_bytes()).await;
    let sent = h.send(&a, &[reference], None).await;
    let range = surface::read_attachment(
        &h.state,
        Some(&recipient()),
        &sent.message_id,
        0,
        0,
        Some(3),
    )
    .await
    .unwrap();
    assert_eq!(range["data"], "a");
    assert_eq!(range["next"], 1);
    assert_eq!(range["length"], 1);
    for (offset, length) in [(6, 1), (0, 0), (2, 1)] {
        assert_eq!(
            surface::read_attachment(
                &h.state,
                Some(&recipient()),
                &sent.message_id,
                0,
                offset,
                Some(length)
            )
            .await
            .unwrap_err()
            .code()
            .1,
            "bad_request"
        );
    }
    let reference = h.stage(&a, &vec![b'a'; 70000]).await;
    let sent = h.send(&a, &[reference], None).await;
    let range = surface::read_attachment(
        &h.state,
        Some(&recipient()),
        &sent.message_id,
        0,
        0,
        Some(65537),
    )
    .await
    .unwrap();
    assert_eq!(range["length"], 65536);
    assert_eq!(range["next"], 65536);
}

#[tokio::test]
async fn oracle_9_expired_row_is_gone_then_purged_item_is_not_found() {
    let h = Harness::new(1024).await;
    let a = sender("sender-a");
    let reference = h.stage(&a, b"expires").await;
    let sent = h.send(&a, &[reference], None).await;
    {
        let db = h.state.db.lock().unwrap();
        db.execute(
            "UPDATE attachments SET expires_at=0 WHERE item_id=?1",
            [&sent.message_id],
        )
        .unwrap();
    }
    assert_eq!(
        surface::read_attachment(&h.state, Some(&recipient()), &sent.message_id, 0, 0, None)
            .await
            .unwrap_err()
            .code()
            .1,
        "gone"
    );
    {
        let db = h.state.db.lock().unwrap();
        db.execute("DELETE FROM messages WHERE id=?1", [&sent.message_id])
            .unwrap();
        xmsg::attachments::purge(&db, xmsg::storage::now_epoch_secs(), 86400).unwrap();
    }
    assert_eq!(
        surface::read_attachment(&h.state, Some(&recipient()), &sent.message_id, 0, 0, None)
            .await
            .unwrap_err()
            .code()
            .1,
        "not_found"
    );
}

#[tokio::test]
async fn oracle_10_keyed_refs_deduplicate_and_changed_refs_conflict() {
    let h = Harness::new(1024).await;
    let a = sender("sender-a");
    let reference = h.stage(&a, b"first").await;
    let first = h
        .send(&a, std::slice::from_ref(&reference), Some("key"))
        .await;
    let retry = h
        .send(&a, std::slice::from_ref(&reference), Some("key"))
        .await;
    assert_eq!(first.message_id, retry.message_id);
    let changed = h.stage(&a, b"second").await;
    assert_eq!(
        surface::send_with_attachments(&h.state, &a, "recipient", "file", Some("key"), &[changed])
            .await
            .unwrap_err()
            .code()
            .1,
        "conflict"
    );
    {
        let db = h.state.db.lock().unwrap();
        let count: i64 = db
            .query_row(
                "SELECT count(*) FROM attachments WHERE item_id=?1",
                [&first.message_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
    let first = h
        .socket(
            json!({"action":"attach","upload":"chunks","offset":0,"data":STANDARD.encode(b"abc")}),
        )
        .await;
    let retry = h
        .socket(
            json!({"action":"attach","upload":"chunks","offset":0,"data":STANDARD.encode(b"abc")}),
        )
        .await;
    assert_eq!(first["size"], 3);
    assert_eq!(retry["size"], 3);
    assert_eq!(
        h.socket(
            json!({"action":"attach","upload":"chunks","offset":0,"data":STANDARD.encode(b"xyz")})
        )
        .await["error"],
        "conflict"
    );
}

#[tokio::test]
async fn reply_is_readable_by_id_but_unrelated_sender_cannot_forward_its_hash() {
    let h = Harness::new(1024).await;
    let original = h
        .send(&Sender::Anonymous("visitor".into()), &[], None)
        .await;
    let b = Sender::Session(recipient());
    let reference = h.stage(&b, b"reply bytes").await;
    let reply = surface::reply_with_attachments(
        &h.state,
        &recipient(),
        &original.message_id,
        "answer",
        Some("reply-receipt"),
        std::slice::from_ref(&reference),
    )
    .await
    .unwrap();
    let repeated = surface::reply_with_attachments(
        &h.state,
        &recipient(),
        &original.message_id,
        "answer",
        Some("reply-receipt"),
        std::slice::from_ref(&reference),
    )
    .await
    .unwrap();
    assert_eq!(reply, repeated);
    let reply_id = reply.pushed_message_id.unwrap();
    assert_eq!(
        surface::read_attachment(&h.state, None, &reply_id, 0, 0, None)
            .await
            .unwrap()["data"],
        "reply bytes"
    );
    let response = reqwest::Client::new()
        .get(format!(
            "{}/v1/messages/{reply_id}/attachments/0?offset=6&length=5",
            h.url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["x-xmsg-sha256"], reference.sha256);
    assert_eq!(response.headers()["content-range"], "bytes 6-10/11");
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"bytes");
    assert_eq!(
        surface::send_with_attachments(
            &h.state,
            &sender("outsider"),
            "recipient",
            "stolen",
            None,
            std::slice::from_ref(&reference)
        )
        .await
        .unwrap_err()
        .code()
        .1,
        "not_found"
    );
    let reader = session("reply-reader");
    surface::read_attachment(&h.state, Some(&reader), &reply_id, 0, 0, None)
        .await
        .unwrap();
    let forwarded = h.send(&Sender::Session(reader), &[reference], None).await;
    assert_eq!(
        surface::read_attachment(
            &h.state,
            Some(&recipient()),
            &forwarded.message_id,
            0,
            0,
            None
        )
        .await
        .unwrap()["data"],
        "reply bytes"
    );
}

#[tokio::test]
async fn successful_anonymous_keyed_retry_survives_staging_expiry() {
    let h = Harness::new(1024).await;
    let a = Sender::Anonymous("visitor".into());
    let reference = h.stage(&a, b"still referenced").await;
    let first = h
        .send(&a, std::slice::from_ref(&reference), Some("retry-key"))
        .await;
    {
        let db = h.state.db.lock().unwrap();
        db.execute("UPDATE staged_blobs SET expires_at=0", [])
            .unwrap();
        xmsg::attachments::purge(&db, xmsg::storage::now_epoch_secs(), 86400).unwrap();
    }
    let retry = h
        .send(&a, std::slice::from_ref(&reference), Some("retry-key"))
        .await;
    assert_eq!(retry.message_id, first.message_id);
    assert_eq!(
        surface::read_attachment(&h.state, Some(&recipient()), &first.message_id, 0, 0, None)
            .await
            .unwrap()["data"],
        "still referenced"
    );
}

#[tokio::test]
async fn keyed_send_distinguishes_text_from_attachment_fingerprint() {
    for refs_first in [true, false] {
        let h = Harness::new(1024).await;
        let a = sender("sender-a");
        let reference = h.stage(&a, b"collision control").await;
        let refs = [reference];
        let plain = format!("a\0{}", serde_json::to_string(&refs).unwrap());
        let (first_text, first_refs, retry_text, retry_refs): (
            &str,
            &[AttachmentRef],
            &str,
            &[AttachmentRef],
        ) = if refs_first {
            ("a", &refs, &plain, &[])
        } else {
            (&plain, &[], "a", &refs)
        };
        surface::send_with_attachments(
            &h.state,
            &a,
            "recipient",
            first_text,
            Some("collision-key"),
            first_refs,
        )
        .await
        .unwrap();
        let error = surface::send_with_attachments(
            &h.state,
            &a,
            "recipient",
            retry_text,
            Some("collision-key"),
            retry_refs,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code().1, "conflict", "refs_first={refs_first}");
    }
}

#[tokio::test]
async fn keyed_send_compares_attachment_digest_when_text_is_unchanged() {
    for refs_first in [true, false] {
        let h = Harness::new(1024).await;
        let a = sender("sender-a");
        let refs = [h.stage(&a, b"digest control").await];
        let (first_refs, retry_refs): (&[AttachmentRef], &[AttachmentRef]) = if refs_first {
            (&refs, &[])
        } else {
            (&[], &refs)
        };
        surface::send_with_attachments(
            &h.state,
            &a,
            "recipient",
            "a",
            Some("digest-key"),
            first_refs,
        )
        .await
        .unwrap();
        let error = surface::send_with_attachments(
            &h.state,
            &a,
            "recipient",
            "a",
            Some("digest-key"),
            retry_refs,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code().1, "conflict", "refs_first={refs_first}");
    }
}

#[tokio::test]
async fn keyed_reply_distinguishes_text_from_attachment_fingerprint() {
    for refs_first in [true, false] {
        let h = Harness::new(1024).await;
        let original = h
            .send(&Sender::Anonymous("visitor".into()), &[], None)
            .await;
        let b = recipient();
        let refs = [h
            .stage(&Sender::Session(b.clone()), b"reply collision control")
            .await];
        let plain = format!("a\0{}", serde_json::to_string(&refs).unwrap());
        let (first_text, first_refs, retry_text, retry_refs): (
            &str,
            &[AttachmentRef],
            &str,
            &[AttachmentRef],
        ) = if refs_first {
            ("a", &refs, &plain, &[])
        } else {
            (&plain, &[], "a", &refs)
        };
        surface::reply_with_attachments(
            &h.state,
            &b,
            &original.message_id,
            first_text,
            Some("reply-collision-key"),
            first_refs,
        )
        .await
        .unwrap();
        let error = surface::reply_with_attachments(
            &h.state,
            &b,
            &original.message_id,
            retry_text,
            Some("reply-collision-key"),
            retry_refs,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code().1, "conflict", "refs_first={refs_first}");
    }
}

#[tokio::test]
async fn keyed_reply_compares_attachment_digest_when_text_is_unchanged() {
    for refs_first in [true, false] {
        let h = Harness::new(1024).await;
        let original = h
            .send(&Sender::Anonymous("visitor".into()), &[], None)
            .await;
        let b = recipient();
        let refs = [h
            .stage(&Sender::Session(b.clone()), b"reply digest control")
            .await];
        let (first_refs, retry_refs): (&[AttachmentRef], &[AttachmentRef]) = if refs_first {
            (&refs, &[])
        } else {
            (&[], &refs)
        };
        surface::reply_with_attachments(
            &h.state,
            &b,
            &original.message_id,
            "a",
            Some("reply-digest-key"),
            first_refs,
        )
        .await
        .unwrap();
        let error = surface::reply_with_attachments(
            &h.state,
            &b,
            &original.message_id,
            "a",
            Some("reply-digest-key"),
            retry_refs,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code().1, "conflict", "refs_first={refs_first}");
    }
}
