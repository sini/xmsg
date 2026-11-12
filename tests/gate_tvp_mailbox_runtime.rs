#![cfg(unix)]
mod hop_client;
mod short_sock;

use base64::Engine;

use rusqlite::{types::Value as SqlValue, Connection};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use xmsg::fed::generate_self_signed_ed25519_pem;
use xmsg::storage;

struct Identity {
    cert: String,
    key: String,
    pin: String,
}
impl Identity {
    fn new(name: &str) -> Self {
        let (cert, key, pin) = generate_self_signed_ed25519_pem(name).unwrap();
        Self { cert, key, pin }
    }
    fn der(&self) -> (Vec<u8>, Vec<u8>) {
        let decode = |pem: &str| {
            base64::engine::general_purpose::STANDARD
                .decode(
                    pem.lines()
                        .filter(|line| !line.starts_with('-'))
                        .collect::<String>(),
                )
                .unwrap()
        };
        (decode(&self.cert), decode(&self.key))
    }
}

struct Node {
    child: Child,
    directory: TempDir,
    http: PathBuf,
    database: PathBuf,
    fed_port: u16,
    _stdout: short_sock::StdoutCapture,
}
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Node {
    fn spawn(identity: &Identity, peers: Value, ttl: u64, rows: u64, bytes: u64) -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["run", "sessions", "codex"] {
            fs::create_dir(directory.path().join(name)).unwrap();
            fs::set_permissions(
                directory.path().join(name),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
        let cert = directory.path().join("node.crt");
        let key = directory.path().join("node.key");
        let peer_file = directory.path().join("peers.json");
        fs::write(&cert, &identity.cert).unwrap();
        fs::write(&key, &identity.key).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&peer_file, peers.to_string()).unwrap();
        let http = directory.path().join("run/http.sock");
        let database = directory.path().join("state.db");
        let codex = directory.path().join("codex");
        let mut child = Command::new(env!("CARGO_BIN_EXE_xmsg"))
            .env("CODEX_HOME", &codex)
            .env_remove("XMSG_CODEX_HOME")
            .env_remove("XMSG_CODEX_EXE")
            .env_remove("XMSG_AGY_EXE")
            .env_remove("XMSG_HOST_LABEL")
            .env("RUST_LOG", "xmsg=info")
            .arg("serve")
            .arg("--http-sock")
            .arg(&http)
            .arg("--register-sock")
            .arg(directory.path().join("run/register.sock"))
            .arg("--agent-sock")
            .arg(directory.path().join("run/agent.sock"))
            .arg("--sessions-dir")
            .arg(directory.path().join("sessions"))
            .arg("--codex-home")
            .arg(&codex)
            .arg("--db-path")
            .arg(&database)
            .args(["--fed-listen", "127.0.0.1:0"])
            .arg("--fed-cert")
            .arg(cert)
            .arg("--fed-key")
            .arg(key)
            .arg("--peers-file")
            .arg(peer_file)
            .arg("--svc-exe")
            .arg(format!(
                "worker={}",
                std::env::current_exe().unwrap().display()
            ))
            .arg("--reply-ttl")
            .arg(ttl.to_string())
            .arg("--peer-mailbox-max-rows")
            .arg(rows.to_string())
            .arg("--peer-mailbox-max-bytes")
            .arg(bytes.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = short_sock::StdoutCapture::from_std(child.stdout.take().unwrap());
        let mut node = Self {
            child,
            directory,
            http,
            database,
            fed_port: 0,
            _stdout: stdout,
        };
        node.fed_port = node
            ._stdout
            .try_wait_for_port("bound federation mTLS listener", Duration::from_secs(10))
            .unwrap_or_else(|| panic!("hub did not bind: {}", node._stdout.snapshot()));
        let deadline = Instant::now() + Duration::from_secs(10);
        while std::os::unix::net::UnixStream::connect(&node.http).is_err() {
            assert!(
                Instant::now() < deadline,
                "hub did not expose its HTTP socket: {}",
                node._stdout.snapshot()
            );
            assert!(
                node.child.try_wait().unwrap().is_none(),
                "hub exited before HTTP readiness"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        node
    }

    fn db(&self) -> Connection {
        let db = Connection::open(&self.database).unwrap();
        db.busy_timeout(Duration::from_secs(2)).unwrap();
        db
    }
    fn send(&self, to: &str, text: &str) -> (u16, Value) {
        let payload = json!({"to":to,"text":text,"from":"mailbox-runtime"}).to_string();
        let (status, response) = xmsg::http::http_request_unix_within(
            &self.http,
            "POST",
            "/v1/messages",
            Some(&payload),
            Duration::from_secs(8),
        )
        .unwrap();
        (status.as_u16(), serde_json::from_str(&response).unwrap())
    }
    fn rows(&self) -> Vec<Vec<SqlValue>> {
        let db = self.db();
        let mut statement = db
            .prepare("SELECT * FROM peer_mailbox ORDER BY id")
            .unwrap();
        let count = statement.column_count();
        statement
            .query_map([], |row| (0..count).map(|column| row.get(column)).collect())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }
}

fn offline_leaf(pin: &str) -> Value {
    json!({"pin":pin,"leaf":true,"allow":["send","reply","list"]})
}
fn hub(ttl: u64, rows: u64, bytes: u64) -> Node {
    let identity = Identity::new("hub");
    let leaf = Identity::new("leaf");
    Node::spawn(
        &identity,
        json!({"peers":{"offline":offline_leaf(&leaf.pin)}}),
        ttl,
        rows,
        bytes,
    )
}

#[test]
fn idle_hub_timer_purges_expired_mail_without_local_delivery() {
    let node = hub(1, 10, 1_000_000);
    let expired = storage::PeerMailboxMessage {
        id: "expired-idle-row".into(),
        peer: "offline".into(),
        target_ref: "status".into(),
        created_at: storage::now_epoch_secs() - 10,
        from_name: "fixture".into(),
        bytes: 4,
        body: "idle".into(),
        envelope: "{}".into(),
        origin: storage::Origin::service("fixture", "origin"),
    };
    storage::insert_peer_mailbox(&node.db(), &expired).unwrap();
    assert_eq!(node.rows().len(), 1);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !node.rows().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        node.rows().is_empty(),
        "idle hub retained expired peer mail without any local delivery"
    );
    let delivered: i64 = node
        .db()
        .query_row("SELECT count(*) FROM messages", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        delivered, 0,
        "oracle accidentally performed a local delivery"
    );
}

#[test]
fn local_sender_observes_row_cap_refusal_without_losing_earlier_mail() {
    let node = hub(604800, 2, 16 * 1024 * 1024);
    for text in ["first", "second"] {
        let (status, reply) = node.send("status@offline", text);
        assert_eq!(status, 202, "{reply}");
    }
    let before = node.rows();
    assert_eq!(before.len(), 2);
    let (status, reply) = node.send("status@offline", "third");
    assert_eq!(
        status, 429,
        "mailbox row cap was not visible to the sender: {reply}"
    );
    assert_eq!(reply["error"], "peer_mailbox_full");
    assert_eq!(
        node.rows(),
        before,
        "capacity refusal changed earlier mailbox rows"
    );
}

#[test]
fn local_sender_observes_byte_cap_refusal_without_losing_earlier_mail() {
    let node = hub(604800, 10, 1024);
    let (status, reply) = node.send("status@offline", "small");
    assert_eq!(status, 202, "first message must fit: {reply}");
    let before = node.rows();
    let (status, reply) = node.send("status@offline", &"界".repeat(1024));
    assert_eq!(
        status, 429,
        "mailbox byte cap was not visible to the sender: {reply}"
    );
    assert_eq!(reply["error"], "peer_mailbox_full");
    assert_eq!(
        node.rows(),
        before,
        "byte refusal changed earlier mailbox rows"
    );
}

#[test]
fn default_route_sender_preserves_remote_mailbox_full_code() {
    let sender = Identity::new("sender");
    let hub_identity = Identity::new("hub");
    let leaf = Identity::new("leaf");
    let hub = Node::spawn(
        &hub_identity,
        json!({"peers":{
            "sender":{"address":"127.0.0.1:9","pin":sender.pin,"allow":["send","reply","list","forward"]},
            "offline":offline_leaf(&leaf.pin)
        }}),
        604800,
        1,
        16 * 1024 * 1024,
    );
    let origin = Node::spawn(
        &sender,
        json!({"peers":{"hub":{
            "address":format!("127.0.0.1:{}",hub.fed_port),"pin":hub_identity.pin,
            "allow":["send","reply","list"],"default_route":true
        }}}),
        604800,
        10,
        16 * 1024 * 1024,
    );
    let (status, response) = origin.send("status@offline", "first");
    assert_eq!(
        status, 202,
        "forwarding positive control failed: {response}"
    );
    let before = hub.rows();
    assert_eq!(before.len(), 1);
    let (status, response) = origin.send("status@offline", "second");
    assert_eq!(
        status, 429,
        "hub cap did not reach the original sender: {response}"
    );
    assert_eq!(response["error"], "peer_mailbox_full");
    assert_eq!(
        hub.rows(),
        before,
        "forwarded refusal changed earlier mailbox rows"
    );
}

fn sql_text(value: &SqlValue) -> &str {
    match value {
        SqlValue::Text(text) => text,
        other => panic!("expected SQL text, got {other:?}"),
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn forwarded_reply_refusal_does_not_poison_retry_deduplication() {
    assert_forwarded_reply_refusal(false);
}

#[test]
fn forwarded_file_reply_refusal_leaves_no_metadata_and_retries_after_capacity_recovers() {
    assert_forwarded_reply_refusal(true);
}

fn assert_forwarded_reply_refusal(with_attachment: bool) {
    let hub_identity = Identity::new("hub");
    let responder = Identity::new("responder");
    let leaf = Identity::new("leaf");
    let hub = Node::spawn(
        &hub_identity,
        json!({"peers":{
            "responder":{"address":"127.0.0.1:9","pin":responder.pin,"allow":["reply"]},
            "offline":offline_leaf(&leaf.pin)
        }}),
        604800,
        1,
        16 * 1024 * 1024,
    );
    assert_eq!(hub.send("status@offline", "occupy capacity").0, 202);
    let before = hub.rows();
    let stamp = storage::now_epoch_secs();
    let original = ulid::Ulid::new().to_string();
    let reply_id = ulid::Ulid::new().to_string();
    let db = hub.db();
    storage::insert_message(
        &db,
        &storage::MessageRecord {
            id: original.clone(),
            created_at: stamp,
            session_id: "worker".into(),
            from_name: "caller".into(),
            bytes: 8,
            outcome: "relayed".into(),
            recipient_harness: "fed".into(),
            return_harness: Some("svc".into()),
            return_session_id: Some("caller".into()),
            thread_id: original.clone(),
            return_host: Some("offline".into()),
        },
    )
    .unwrap();
    storage::insert_outbound(&db, &original, "responder", "worker", "delivered", stamp).unwrap();
    storage::insert_forwarded_message(&db, &original, "offline", stamp).unwrap();
    let mut reply = json!({"v":2,"id":reply_id,"in_reply_to":original,"replier":{"service":"worker","node":"unattested"},"text":"reply with a full return mailbox","created_at":stamp});
    if with_attachment {
        reply["attachments"] =
            json!([{"name":"file.txt","size":4,"media_type":"text/plain","sha256":"a".repeat(64)}]);
    }
    let (cert, key) = responder.der();
    let origin = hop_client::Origin {
        cert_der: &cert,
        key_der: &key,
    };
    let runtime = runtime();
    for attempt in 0..2 {
        let (status, response) = runtime.block_on(hop_client::request(
            &origin,
            &hub_identity.pin,
            hub.fed_port,
            "POST",
            "/fed/v2/replies",
            Some(reply.clone()),
        ));
        assert_eq!(status,429,"forwarded reply capacity refusal was hidden or retry dedup was poisoned (attempt {attempt}): {response}");
        assert_eq!(response["error"], "peer_mailbox_full");
        assert_eq!(
            hub.rows(),
            before,
            "rejected forwarded reply changed earlier mailbox rows"
        );
        assert!(
            storage::get_reply_by_pushed_id(&db, &reply_id)
                .unwrap()
                .is_none(),
            "capacity refusal persisted a successful reply receipt"
        );
        assert!(
            xmsg::attachments::list_rows(&db, &reply_id)
                .unwrap()
                .is_empty(),
            "capacity refusal persisted forwarded attachment metadata"
        );
    }
    let filler = sql_text(&before[0][0]);
    storage::delete_peer_mailbox_message(&db, "offline", filler).unwrap();
    let (status, response) = runtime.block_on(hop_client::request(
        &origin,
        &hub_identity.pin,
        hub.fed_port,
        "POST",
        "/fed/v2/replies",
        Some(reply),
    ));
    assert_eq!(
        status, 200,
        "same reply did not recover after capacity became available: {response}"
    );
    assert_eq!(hub.rows().len(), 1);
    assert_eq!(sql_text(&hub.rows()[0][0]), reply_id);
}

fn service_frame(
    reader: &mut std::io::BufReader<std::os::unix::net::UnixStream>,
    value: Value,
) -> Value {
    use std::io::{BufRead, Write};
    writeln!(reader.get_mut(), "{value}").unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

#[test]
fn mailbox_reply_service_child() {
    let Ok(directory) = std::env::var("TVP_REPLY_SERVICE_DIRECTORY") else {
        return;
    };
    let directory = PathBuf::from(directory);
    let socket =
        std::os::unix::net::UnixStream::connect(directory.join("run/register.sock")).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut reader = std::io::BufReader::new(socket);
    let registered = service_frame(&mut reader, json!({"harness":"svc","name":"worker"}));
    assert_eq!(registered["status"], "ok", "{registered}");
    fs::write(directory.join("service-ready"), "ready").unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let message = loop {
        let message = service_frame(&mut reader, json!({"action":"poll","waitSecs":1}));
        if message["action"] == "deliver" {
            break message;
        }
        assert!(Instant::now() < deadline, "service did not receive request");
    };
    let id = message["messageId"].as_str().unwrap();
    let mut frame = json!({"action":"reply","messageId":id,"text":"local worker reply","idempotencyKey":"full-mailbox-retry"});
    if directory.join("with-attachment").exists() {
        let socket =
            std::os::unix::net::UnixStream::connect(directory.join("run/agent.sock")).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        let staged = service_frame(
            &mut std::io::BufReader::new(socket),
            json!({"action":"attach","schema_version":2,"name":"reply.txt","media_type":"text/plain","data":base64::engine::general_purpose::STANDARD.encode(b"reply file")}),
        );
        assert_eq!(
            staged["status"], "ok",
            "attachment staging positivecontrol: {staged}"
        );
        frame["attachments"] = json!([staged["attachment"].clone()]);
    }
    let attempts: Vec<_> = (0..2)
        .map(|_| service_frame(&mut reader, frame.clone()))
        .collect();
    fs::write(
        directory.join("reply-attempts.json"),
        serde_json::to_vec(&attempts).unwrap(),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !directory.join("retry-ready").exists() {
        assert!(
            Instant::now() < deadline,
            "parent did not release mailbox capacity"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let result = service_frame(&mut reader, frame);
    fs::write(
        directory.join("reply-recovered.json"),
        serde_json::to_vec(&result).unwrap(),
    )
    .unwrap();
}

struct ServiceProcess(Child);
impl Drop for ServiceProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn wait_for_file(node: &Node, name: &str) -> PathBuf {
    let file = node.directory.path().join(name);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !file.exists() {
        assert!(Instant::now() < deadline, "service did not produce {name}");
        std::thread::sleep(Duration::from_millis(10));
    }
    file
}

#[test]
fn local_service_reply_refusal_preserves_retry_after_capacity_recovers() {
    assert_local_service_reply_refusal(false);
}

#[test]
fn local_service_file_reply_refusal_leaves_no_metadata_and_retries_after_capacity_recovers() {
    assert_local_service_reply_refusal(true);
}

fn assert_local_service_reply_refusal(with_attachment: bool) {
    let hub_identity = Identity::new("hub");
    let leaf = Identity::new("leaf");
    let hub = Node::spawn(
        &hub_identity,
        json!({"peers":{"offline":offline_leaf(&leaf.pin)}}),
        604800,
        1,
        16 * 1024 * 1024,
    );
    assert_eq!(hub.send("status@offline", "occupy capacity").0, 202);
    let before = hub.rows();
    if with_attachment {
        fs::write(hub.directory.path().join("with-attachment"), "fixture").unwrap();
    }
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "mailbox_reply_service_child", "--nocapture"])
        .env("TVP_REPLY_SERVICE_DIRECTORY", hub.directory.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _service = ServiceProcess(command.spawn().unwrap());
    wait_for_file(&hub, "service-ready");
    let original = ulid::Ulid::new().to_string();
    let envelope = json!({"v":2,"id":original,"origin":{"service":"caller","node":"unattested"},"to":{"ref":"worker"},"body":"reply to my offline leaf","thread_id":original,"created_at":storage::now_epoch_secs()});
    let (cert, key) = leaf.der();
    let origin = hop_client::Origin {
        cert_der: &cert,
        key_der: &key,
    };
    let (status, response) = runtime().block_on(hop_client::send_envelope(
        &origin,
        &hub_identity.pin,
        hub.fed_port,
        envelope,
    ));
    assert_eq!(
        status, 202,
        "incoming request positive control failed: {response}"
    );
    let attempts: Vec<Value> =
        serde_json::from_slice(&fs::read(wait_for_file(&hub, "reply-attempts.json")).unwrap())
            .unwrap();
    for response in attempts {
        assert_eq!(
            response["status"], "error",
            "local reply queue failure was hidden: {response}"
        );
        assert_eq!(response["error"], "peer_mailbox_full", "{response}");
    }
    assert_eq!(
        hub.rows(),
        before,
        "rejected local reply changed earlier mailbox rows"
    );
    let replies = storage::get_all_replies(&hub.db(), &original).unwrap();
    assert!(
        replies.is_empty(),
        "capacity refusal persisted a successful local reply receipt"
    );
    assert_eq!(
        hub.db()
            .query_row("SELECT COUNT(*) FROM attachments", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0,
        "capacity refusal persisted local attachment metadata"
    );
    storage::delete_peer_mailbox_message(&hub.db(), "offline", sql_text(&before[0][0])).unwrap();
    fs::write(hub.directory.path().join("retry-ready"), "retry").unwrap();
    let result: Value =
        serde_json::from_slice(&fs::read(wait_for_file(&hub, "reply-recovered.json")).unwrap())
            .unwrap();
    assert_eq!(
        result["status"], "ok",
        "same idempotency key did not recover after capacity was freed: {result}"
    );
    assert_eq!(hub.rows().len(), 1);
}
