mod short_sock;

use base64::{engine::general_purpose::STANDARD, Engine};
use rustls::pki_types::ServerName;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

const ALICE: &str = "0199cecf-a11c-7000-8000-0000000a11ce";
const BOB: &str = "0199cecf-b0b0-7000-8000-00000000b0b0";
const QUINN: &str = "0199cecf-000c-7000-8000-00000000000c";
const WAIT: Duration = Duration::from_secs(20);

struct Identity {
    cert: String,
    key: String,
    pin: String,
}

impl Identity {
    fn new(name: &str) -> Self {
        let (cert, key, pin) = xmsg::fed::generate_self_signed_ed25519_pem(name).unwrap();
        Self { cert, key, pin }
    }

    fn entry(&self, port: u16, allow: &[&str]) -> Value {
        json!({"address":format!("127.0.0.1:{port}"),"pin":self.pin,"allow":allow})
    }
}

struct Node {
    temp: TempDir,
    identity: Identity,
    config: Value,
    child: Child,
    output: short_sock::StdoutCapture,
    fed_port: u16,
    agent: PathBuf,
    db: PathBuf,
    received: Arc<Mutex<Vec<String>>>,
    inbox: tokio::task::JoinHandle<()>,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.inbox.abort();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Node {
    async fn new(identity: Identity, id: &str, label: &str, config: Value, extra: &[&str]) -> Self {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for dir in ["run", "sessions", "codex"] {
            fs::create_dir(temp.path().join(dir)).unwrap();
        }
        let run = temp.path().join("run");
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        let agent = short_sock::sock_path(&run, "a");
        let register = short_sock::sock_path(&run, "r");
        let http = short_sock::sock_path(&run, "h");
        let inbox_path = short_sock::sock_path(&run, "i");
        let listener = UnixListener::bind(&inbox_path).unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_copy = received.clone();
        let inbox = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut body = Vec::new();
                stream.read_to_end(&mut body).await.unwrap();
                received_copy
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(body).unwrap());
            }
        });
        let pid = std::process::id();
        let start =
            xmsg::process::starttime(std::path::Path::new(xmsg::process::LIVE_PROC_ROOT), pid)
                .unwrap();
        fs::write(
            temp.path().join("sessions").join(format!("{pid}.json")),
            json!({
                "pid":pid,"sessionId":id,"name":label,"cwd":"/","status":"idle",
                "kind":"interactive","startedAt":1,"updatedAt":1,"procStart":start,
                "messagingSocketPath":inbox_path
            })
            .to_string(),
        )
        .unwrap();
        let cert = temp.path().join("cert.pem");
        let key = temp.path().join("key.pem");
        let peers = temp.path().join("peers.json");
        let db = temp.path().join("state.db");
        fs::write(&cert, &identity.cert).unwrap();
        fs::write(&key, &identity.key).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&peers, config.to_string()).unwrap();
        let leaf = extra.contains(&"--leaf");
        let mut command = Command::new(env!("CARGO_BIN_EXE_xmsg"));
        command.arg("serve");
        if !leaf {
            command.args(["--fed-listen", "127.0.0.1:0"]);
        }
        let mut child = command
            .env("HOME", temp.path())
            .env("XDG_RUNTIME_DIR", &run)
            .env("CODEX_HOME", temp.path().join("codex"))
            .env_remove("XMSG_CODEX_HOME")
            .env("RUST_LOG", "xmsg=info")
            .args(["--listen", "127.0.0.1:0"])
            .arg("--codex-home")
            .arg(temp.path().join("codex"))
            .arg("--sessions-dir")
            .arg(temp.path().join("sessions"))
            .arg("--db-path")
            .arg(&db)
            .arg("--fed-cert")
            .arg(&cert)
            .arg("--fed-key")
            .arg(&key)
            .arg("--peers-file")
            .arg(&peers)
            .arg("--agent-sock")
            .arg(&agent)
            .arg("--register-sock")
            .arg(&register)
            .arg("--http-sock")
            .arg(&http)
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let output = short_sock::StdoutCapture::from_std(child.stdout.take().unwrap());
        let fed_port = if leaf {
            0
        } else {
            output
                .try_wait_for_port("bound federation mTLS listener", WAIT)
                .unwrap_or_else(|| panic!("federation listener not ready: {}", output.snapshot()))
        };
        tokio::time::timeout(WAIT, async {
            loop {
                if UnixStream::connect(&agent).await.is_ok() {
                    break;
                }
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "node exited: {}",
                    output.snapshot()
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("agent socket readiness");
        Self {
            temp,
            identity,
            config,
            child,
            output,
            fed_port,
            agent,
            db,
            received,
            inbox,
        }
    }

    fn reload(&mut self, config: Value) {
        let marker = "successfully reloaded federation TLS credentials and peers";
        let old = self.output.line_count_containing(marker);
        fs::write(self.temp.path().join("peers.json"), config.to_string()).unwrap();
        assert_eq!(
            unsafe { libc::kill(self.child.id() as i32, libc::SIGHUP) },
            0
        );
        assert!(
            self.output.wait_for_line_count(marker, old + 1, WAIT),
            "peer reload: {}",
            self.output.snapshot()
        );
        self.config = config;
    }

    async fn agent(&self, frame: Value) -> Value {
        tokio::time::timeout(WAIT, async {
            let mut stream = UnixStream::connect(&self.agent).await.unwrap();
            stream
                .write_all(format!("{frame}\n").as_bytes())
                .await
                .unwrap();
            let mut line = String::new();
            BufReader::new(stream).read_line(&mut line).await.unwrap();
            serde_json::from_str(&line).unwrap()
        })
        .await
        .expect("agent action timeout")
    }

    async fn stage(&self, data: &[u8]) -> Value {
        let answer = self.agent(json!({"action":"attach","name":"file.txt","media_type":"text/plain","data":STANDARD.encode(data)})).await;
        assert_eq!(answer["status"], "ok", "stage: {answer}");
        answer["attachment"].clone()
    }

    async fn send(&self, target: &str, attachment: Value) -> String {
        let answer = self.agent(json!({"action":"send","to":target,"text":"file exchange","attachments":[attachment]})).await;
        assert_eq!(
            answer["status"], "ok",
            "federated attachment send must succeed: {answer}"
        );
        answer["message_id"].as_str().unwrap().to_string()
    }

    async fn read(&self, id: &str) -> Value {
        self.agent(
            json!({"action":"read_attachment","message_id":id,"index":0,"offset":0,"length":65536}),
        )
        .await
    }

    async fn wait_delivery(&self, id: &str) {
        tokio::time::timeout(WAIT, async {
            loop {
                if self.received.lock().unwrap().iter().any(|s| s.contains(id)) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("delivery {id} absent: {}", self.output.snapshot()));
    }

    async fn fed(
        &self,
        destination: &Node,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (u16, Vec<u8>) {
        let der = |pem: &str| {
            STANDARD
                .decode(
                    pem.lines()
                        .filter(|line| !line.starts_with("---"))
                        .collect::<String>(),
                )
                .unwrap()
        };
        let connector = xmsg::fed::make_tls_connector(
            &der(&self.identity.cert),
            &der(&self.identity.key),
            &destination.identity.pin,
        )
        .unwrap();
        tokio::time::timeout(WAIT, async {
            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", destination.fed_port))
                .await
                .unwrap();
            let tls = connector
                .connect(
                    ServerName::try_from("attachment-test".to_string()).unwrap(),
                    tcp,
                )
                .await
                .unwrap();
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                    .await
                    .unwrap();
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let request = hyper::Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(http_body_util::Full::new(bytes::Bytes::from(
                    body.map(|v| v.to_string()).unwrap_or_default(),
                )))
                .unwrap();
            let response = sender.send_request(request).await.unwrap();
            let status = response.status().as_u16();
            use http_body_util::BodyExt;
            let bytes = http_body_util::Limited::new(response.into_body(), 128 * 1024)
                .collect()
                .await
                .unwrap()
                .to_bytes();
            (status, bytes.to_vec())
        })
        .await
        .expect("federation request timeout")
    }
}

async fn pair(extra_a: &[&str]) -> (Node, Node) {
    let ia = Identity::new("node-a");
    let ib = Identity::new("node-b");
    let mut b = Node::new(
        ib,
        BOB,
        "Bob",
        json!({"peers":{"node-a":ia.entry(9,&["send","reply"])}}),
        &[],
    )
    .await;
    let a = Node::new(
        ia,
        ALICE,
        "Alice",
        json!({"peers":{"node-b":b.identity.entry(b.fed_port,&["send","reply"])}}),
        extra_a,
    )
    .await;
    b.reload(json!({"peers":{"node-a":a.identity.entry(a.fed_port,&["send","reply"])}}));
    (a, b)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_attachment_send_read_and_reply_round_trip() {
    let (a, b) = pair(&[]).await;
    let id = a.send("Bob@node-b", a.stage(b"outbound file").await).await;
    b.wait_delivery(&id).await;
    let read = b.read(&id).await;
    assert_eq!(
        read["data"], "outbound file",
        "recipient must fetch complete verified file: {read}"
    );
    let attachment = b.stage(b"reply file").await;
    let reply = b
        .agent(json!({"action":"reply","message_id":id,"text":"answer","attachments":[attachment]}))
        .await;
    assert_eq!(reply["status"], "ok", "reply with file: {reply}");
    let pushed = reply["reply"]["pushedMessageId"]
        .as_str()
        .expect("reply attachment item ID");
    a.wait_delivery(pushed).await;
    let read = a.read(pushed).await;
    assert_eq!(
        read["data"], "reply file",
        "reply reader must fetch complete verified file: {read}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn downstream_and_live_reply_right_are_both_required() {
    let (mut a, b) = pair(&[]).await;
    let iq = Identity::new("node-q");
    let q = Node::new(
        iq,
        QUINN,
        "Quinn",
        json!({"peers":{"node-a":a.identity.entry(a.fed_port,&["send","reply"])}}),
        &[],
    )
    .await;
    a.reload(json!({"peers":{"node-b":b.identity.entry(b.fed_port,&["send","reply"]),"node-q":q.identity.entry(q.fed_port,&["send","reply"])}}));
    let id = a
        .send("Bob@node-b", a.stage(b"only intended peer").await)
        .await;
    let uri = format!("/fed/v2/attachments/{id}/0?offset=0&length=65536");
    let (status, body) = b.fed(&a, "GET", &uri, None).await;
    assert_eq!(
        status,
        200,
        "intended downstream positive control: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(body, b"only intended peer");
    let (status, body) = q.fed(&a, "GET", &uri, None).await;
    assert_eq!(
        status,
        403,
        "M2: another admitted reply-capable peer read the item: {}",
        String::from_utf8_lossy(&body)
    );
    a.reload(json!({"peers":{"node-b":b.identity.entry(b.fed_port,&["send"]),"node-q":q.identity.entry(q.fed_port,&["send","reply"])}}));
    let (status, body) = b.fed(&a, "GET", &uri, None).await;
    assert_eq!(
        status,
        403,
        "M3: a reloaded peer without reply right read the item: {}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn corrupt_upstream_is_not_cached_and_next_read_retries() {
    let (a, b) = pair(&[]).await;
    let mut original = vec![b'x'; 65536 + 17];
    original[..19].copy_from_slice(b"whole original file");
    let mut corrupted = original.clone();
    *corrupted.last_mut().unwrap() = b'y';
    let reference = a.stage(&original).await;
    let hash = reference["sha256"].as_str().unwrap().to_string();
    let id = a.send("Bob@node-b", reference).await;
    b.wait_delivery(&id).await;
    let db = rusqlite::Connection::open(&a.db).unwrap();
    db.execute(
        "UPDATE blobs SET data=?1 WHERE sha256=?2",
        rusqlite::params![corrupted, hash],
    )
    .unwrap();
    let request =
        json!({"action":"read_attachment","message_id":id,"index":0,"offset":0,"length":9});
    let failure = b.agent(request.clone()).await;
    assert_eq!(
        failure["error"], "integrity",
        "M6: corrupt bytes were accepted: {failure}"
    );
    let target = rusqlite::Connection::open(&b.db).unwrap();
    let count: i64 = target
        .query_row("SELECT count(*) FROM blobs WHERE sha256=?1", [&hash], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 0, "M6: corrupt fetched blob persisted");
    db.execute(
        "UPDATE blobs SET data=?1 WHERE sha256=?2",
        rusqlite::params![original, hash],
    )
    .unwrap();
    let retried = b.agent(request).await;
    assert_eq!(
        retried["data"], "whole ori",
        "M6: next read did not retry cleanly: {retried}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn original_expiry_is_checked_before_destination_ttl() {
    let (a, b) = pair(&["--reply-ttl", "2"]).await;
    let id = a
        .send("Bob@node-b", a.stage(b"short origin lifetime").await)
        .await;
    b.wait_delivery(&id).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let expired = b.read(&id).await;
    assert_eq!(
        expired["error"], "gone",
        "M9: origin expiry was replaced by destination TTL: {expired}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cached_hash_never_substitutes_for_forwarded_item_possession() {
    let (mut a, mut b) = pair(&[]).await;
    let q = Node::new(
        Identity::new("node-q"),
        QUINN,
        "Quinn",
        json!({"peers":{"node-a":a.identity.entry(a.fed_port,&["send","reply"])}}),
        &[],
    )
    .await;
    a.reload(json!({"peers":{"node-b":b.identity.entry(b.fed_port,&["send","reply"]),"node-q":q.identity.entry(q.fed_port,&["send","reply","forward"])}}));
    b.reload(json!({"peers":{"node-a":a.identity.entry(a.fed_port,&["send","reply","relayed"])}}));
    let reference = a.stage(b"cached elsewhere is not possession").await;
    let first = a.send("Bob@node-b", reference.clone()).await;
    b.wait_delivery(&first).await;
    assert_eq!(
        b.read(&first).await["data"],
        "cached elsewhere is not possession",
        "M5 positive control must prime both caches"
    );
    let id = ulid::Ulid::new().to_string();
    let (status, body) = q
        .fed(
            &a,
            "POST",
            "/fed/v2/messages",
            Some(json!({
                "v":2,"id":id,"origin":{"id":QUINN,"node":"unattested.claim","label":"Quinn"},
                "to":{"ref":"Bob@node-b"},"body":"forged possession","thread_id":id,
                "created_at":xmsg::storage::now_epoch_secs(),"attachments":[reference]
            })),
        )
        .await;
    assert_eq!(
        status,
        202,
        "forwarded reference accepted as metadata: {}",
        String::from_utf8_lossy(&body)
    );
    b.wait_delivery(&id).await;
    let failed = b.read(&id).await;
    let local_refused = matches!(
        failed["error"].as_str(),
        Some("gone" | "not_found" | "unavailable" | "peer_unreachable")
    );
    let (status, body) = b
        .fed(
            &a,
            "GET",
            &format!("/fed/v2/attachments/{id}/0?offset=0&length=65536"),
            None,
        )
        .await;
    let relay_refused = matches!(status, 404 | 410 | 502 | 503);
    assert!(local_refused && relay_refused, "M5: per-item possession: local_refused={local_refused} local={failed}; relay_refused={relay_refused} status={status} body={}",String::from_utf8_lossy(&body));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_hop_hub_fetches_upstream_and_enforces_its_downstream_row() {
    let ia = Identity::new("node-a");
    let ih = Identity::new("hub");
    let ib = Identity::new("node-b");
    let mut b = Node::new(
        ib,
        BOB,
        "Bob",
        json!({"peers":{"hub":ih.entry(9,&["send","reply","relayed"])}}),
        &[],
    )
    .await;
    let mut hub = Node::new(ih,QUINN,"Hub",json!({"peers":{"node-a":ia.entry(9,&["send","reply","forward"]),"node-b":b.identity.entry(b.fed_port,&["send","reply"])}}),&[]).await;
    let mut route = hub.identity.entry(hub.fed_port, &["send", "reply"]);
    route["default_route"] = true.into();
    let a = Node::new(ia, ALICE, "Alice", json!({"peers":{"hub":route}}), &[]).await;
    b.reload(json!({"peers":{"hub":hub.identity.entry(hub.fed_port,&["send","reply","relayed"])}}));
    hub.reload(json!({"peers":{"node-a":a.identity.entry(a.fed_port,&["send","reply","forward"]),"node-b":b.identity.entry(b.fed_port,&["send","reply"])}}));
    let id = a
        .send("Bob@node-b", a.stage(b"through authenticated hub").await)
        .await;
    b.wait_delivery(&id).await;
    let read = b.read(&id).await;
    assert_eq!(
        read["data"], "through authenticated hub",
        "hub must verify upstream before serving: {read}"
    );
    {
        let db = rusqlite::Connection::open(&hub.db).unwrap();
        assert_eq!(
            db.execute(
                "UPDATE attachments SET downstream='' WHERE item_id=?1",
                [&id]
            )
            .unwrap(),
            1
        );
    }
    let (status, body) = b
        .fed(
            &hub,
            "GET",
            &format!("/fed/v2/attachments/{id}/0?offset=0&length=65536"),
            None,
        )
        .await;
    assert_eq!(
        status,
        403,
        "M2 hub: cleared downstream association still permits cached fetch: {}",
        String::from_utf8_lossy(&body)
    );
    let db = rusqlite::Connection::open(&hub.db).unwrap();
    let removed = db
        .execute("DELETE FROM attachments WHERE item_id=?1", [&id])
        .unwrap();
    assert_eq!(
        removed, 1,
        "hub positive control must have one per-item row"
    );
    let (status, body) = b
        .fed(
            &hub,
            "GET",
            &format!("/fed/v2/attachments/{id}/0?offset=0&length=65536"),
            None,
        )
        .await;
    assert!(
        matches!(status, 403 | 404),
        "M2 hub: cached blob remained fetchable after downstream row deletion: {}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn undialable_leaf_origin_supplies_attachment_by_reverse_mailbox_query() {
    let ia = Identity::new("leaf");
    let ih = Identity::new("hub");
    let ib = Identity::new("node-b");
    let mut b = Node::new(
        ib,
        BOB,
        "Bob",
        json!({"peers":{"hub":ih.entry(9,&["send","reply","relayed"])}}),
        &[],
    )
    .await;
    let mut leaf_entry = ia.entry(9, &["send", "reply", "forward"]);
    leaf_entry["leaf"] = true.into();
    let mut hub = Node::new(ih,QUINN,"Hub",json!({"peers":{"leaf":leaf_entry,"node-b":b.identity.entry(b.fed_port,&["send","reply"])}}),&[]).await;
    let mut route = hub.identity.entry(hub.fed_port, &["send", "reply"]);
    route["dial"] = "outbound".into();
    route["default_route"] = true.into();
    let leaf = Node::new(
        ia,
        ALICE,
        "Leaf",
        json!({"peers":{"hub":route}}),
        &["--leaf", "--leaf-principal", "demo"],
    )
    .await;
    assert_eq!(
        leaf.fed_port, 0,
        "leaf fixture must have no inbound federation listener"
    );
    b.reload(json!({"peers":{"hub":hub.identity.entry(hub.fed_port,&["send","reply","relayed"])}}));
    let mut leaf_entry = leaf.identity.entry(9, &["send", "reply", "forward"]);
    leaf_entry["leaf"] = true.into();
    hub.reload(json!({"peers":{"leaf":leaf_entry,"node-b":b.identity.entry(b.fed_port,&["send","reply"])}}));
    let id = leaf
        .send(
            "Bob@node-b",
            leaf.stage(b"reverse query file from leaf").await,
        )
        .await;
    b.wait_delivery(&id).await;
    let read = b.read(&id).await;
    assert_eq!(
        read["data"], "reverse query file from leaf",
        "undialable origin must answer via pull mailbox, not inbound dial: {read}"
    );
    let reference = b.stage(b"reply file back to leaf").await;
    let answer = b.agent(json!({"action":"reply","message_id":id,"text":"file answer","attachments":[reference]})).await;
    assert_eq!(answer["status"], "ok", "reply via hub to leaf: {answer}");
    let pushed = answer["reply"]["pushedMessageId"].as_str().unwrap();
    let db = rusqlite::Connection::open(&leaf.db).unwrap();
    tokio::time::timeout(WAIT, async {
        loop {
            if xmsg::storage::has_svc_message(&db, pushed).unwrap() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("leaf must receive reply from hub mailbox");
    let replies = leaf
        .agent(json!({"action":"replies","message_id":id,"wait":0}))
        .await;
    assert_eq!(
        replies["replies"][0]["attachments"],
        json!([reference]),
        "leaf reply metadata must retain attachment refs from queued reply envelope: {replies}"
    );
    let read = leaf.read(pushed).await;
    assert_eq!(
        read["data"], "reply file back to leaf",
        "leaf must read reply file through hub: {read}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_federation_reference_is_refused_before_storage() {
    let (a, b) = pair(&[]).await;
    let mut reference = a.stage(b"small file").await;
    reference["size"] = (xmsg::attachments::DEFAULT_MAX_ATTACHMENT_BYTES + 1).into();
    let id = ulid::Ulid::new().to_string();
    let (status, body) = a
        .fed(
            &b,
            "POST",
            "/fed/v2/messages",
            Some(json!({
                "v":2,"id":id,"origin":{"id":ALICE,"node":"unattested.claim","label":"Alice"},
                "to":{"ref":"Bob"},"body":"oversize ref","thread_id":id,
                "created_at":xmsg::storage::now_epoch_secs(),"attachments":[reference]
            })),
        )
        .await;
    assert_eq!(
        status,
        413,
        "M7: oversized federation reference was accepted: {}",
        String::from_utf8_lossy(&body)
    );
    let db = rusqlite::Connection::open(&b.db).unwrap();
    let count: i64 = db
        .query_row(
            "SELECT count(*) FROM attachments WHERE item_id=?1",
            [&id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0, "M7: oversized reference persisted");
}

fn same_user_identities() -> (TempDir, Identity, Identity) {
    let root = TempDir::new().unwrap();
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    fs::write(
        root.path().join("ca.pem"),
        ca_params.self_signed(&ca_key).unwrap().pem(),
    )
    .unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let issue = |host: &str| {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            format!("spiffe://owh.test/host/{host}/user/sini")
                .try_into()
                .unwrap(),
        )];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let cert = params.signed_by(&key, &issuer).unwrap();
        Identity {
            pin: xmsg::fed::spki_sha256_from_der(cert.der()).unwrap(),
            cert: cert.pem(),
            key: key.serialize_pem(),
        }
    };
    (root, issue("p"), issue("q"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handoff_transfers_attachment_upstream_and_original_expiry() {
    let (ca, ip, iq) = same_user_identities();
    let peer = |host: &str, port: u16| json!({"address":format!("127.0.0.1:{port}"),"ca":ca.path().join("ca.pem"),"identities":[format!("spiffe://owh.test/host/{host}/user/sini")],"allow":["send","reply","list"]});
    let mut p = Node::new(
        ip,
        ALICE,
        "Alice",
        json!({"peers":{"sini.q":peer("q",9)}}),
        &[],
    )
    .await;
    let reference: xmsg::client::AttachmentRef =
        serde_json::from_value(p.stage(b"attachment follows handoff").await).unwrap();
    let id = ulid::Ulid::new().to_string();
    let now = xmsg::storage::now_epoch_secs();
    let expiry = now + 60;
    let from_name = format!("Alice · {ALICE}@sini.p");
    let db = rusqlite::Connection::open(&p.db).unwrap();
    let tx = db.unchecked_transaction().unwrap();
    xmsg::storage::insert_queued(
        &tx,
        &xmsg::storage::QueuedMessage {
            id: id.clone(),
            instance_id: BOB.into(),
            created_at: now,
            expires_at: expiry,
            from_name: from_name.clone(),
            body: format!("attachment handoff\n[xmsg] message_id={id}"),
        },
    )
    .unwrap();
    xmsg::storage::insert_message(
        &tx,
        &xmsg::storage::MessageRecord {
            id: id.clone(),
            created_at: now,
            session_id: BOB.into(),
            from_name,
            bytes: 18,
            outcome: "queued".into(),
            recipient_harness: "claude".into(),
            return_harness: Some("claude".into()),
            return_session_id: Some(ALICE.into()),
            thread_id: id.clone(),
            return_host: None,
        },
    )
    .unwrap();
    tx.execute(
        "INSERT INTO instance_seen(id,harness,last_live) VALUES (?1,'claude',?2)",
        rusqlite::params![BOB, now],
    )
    .unwrap();
    xmsg::attachments::insert_rows(&tx, &id, &[reference], expiry, "", "").unwrap();
    tx.commit().unwrap();
    let q = Node::new(
        iq,
        BOB,
        "Bob",
        json!({"peers":{"sini.p":peer("p",p.fed_port)}}),
        &[],
    )
    .await;
    p.reload(json!({"peers":{"sini.q":peer("q",q.fed_port)}}));
    q.wait_delivery(&id).await;
    tokio::time::timeout(WAIT, async {
        loop {
            let held = xmsg::attachments::get_row(&db, &id, 0).unwrap().unwrap();
            if held.downstream == "sini.q" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("handoff ACK must authorize attachment downstream");
    let target = rusqlite::Connection::open(&q.db).unwrap();
    let row = xmsg::attachments::get_row(&target, &id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(
        row.upstream, "sini.p",
        "handoff authenticated holder is upstream"
    );
    assert_eq!(
        row.expires_at, expiry,
        "handoff must preserve original attachment expiry"
    );
    let read = q.read(&id).await;
    assert_eq!(
        read["data"], "attachment follows handoff",
        "handed-over attachment must fetch from holder: {read}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keyed_federated_send_and_reply_preserve_refs_without_duplicate_delivery() {
    let (a, b) = pair(&[]).await;
    let reference = a.stage(b"keyed original").await;
    let request = json!({"action":"send","to":"Bob@node-b","text":"keyed file","attachments":[reference],"idempotency_key":"owh-send"});
    let first = a.agent(request.clone()).await;
    assert_eq!(first["status"], "ok", "keyed first send: {first}");
    let id = first["message_id"].as_str().unwrap();
    b.wait_delivery(id).await;
    assert_eq!(b.read(id).await["data"], "keyed original");
    rusqlite::Connection::open(&a.db)
        .unwrap()
        .execute("DELETE FROM blobs", [])
        .unwrap();
    let retried = a.agent(request.clone()).await;
    assert_eq!(
        retried["status"], "ok",
        "settled send retry must not need gone source bytes: {retried}"
    );
    assert_eq!(
        retried["message_id"], first["message_id"],
        "M10: retry allocated another message"
    );
    assert_eq!(
        b.received
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.contains(id))
            .count(),
        1,
        "M10: keyed attachment send delivered twice"
    );
    let different = a.stage(b"different ref").await;
    let mut changed = request;
    changed["attachments"] = json!([different]);
    let conflict = a.agent(changed).await;
    assert_eq!(
        conflict["error"], "conflict",
        "M10: changed send refs accepted on same key: {conflict}"
    );

    let reference = b.stage(b"keyed reply file").await;
    let request = json!({"action":"reply","message_id":id,"text":"keyed answer","attachments":[reference],"idempotency_key":"owh-reply"});
    let first = b.agent(request.clone()).await;
    assert_eq!(first["status"], "ok", "keyed first reply: {first}");
    let pushed = first["reply"]["pushedMessageId"].as_str().unwrap();
    a.wait_delivery(pushed).await;
    assert_eq!(a.read(pushed).await["data"], "keyed reply file");
    rusqlite::Connection::open(&b.db)
        .unwrap()
        .execute("DELETE FROM blobs", [])
        .unwrap();
    let retried = b.agent(request.clone()).await;
    assert_eq!(
        retried["status"], "ok",
        "settled reply retry must not need gone source bytes: {retried}"
    );
    assert_eq!(
        retried["reply"]["seq"], first["reply"]["seq"],
        "M10: retry inserted another reply"
    );
    assert_eq!(
        retried["reply"]["pushedMessageId"],
        first["reply"]["pushedMessageId"]
    );
    assert_eq!(
        a.received
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.contains(pushed))
            .count(),
        1,
        "M10: keyed attachment reply delivered twice"
    );
    let mut changed = request;
    changed["attachments"] = json!([b.stage(b"different reply ref").await]);
    let conflict = b.agent(changed).await;
    assert_eq!(
        conflict["error"], "conflict",
        "M10: changed reply refs accepted on same key: {conflict}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reply_attachment_fetch_requires_live_send_right() {
    let (a, mut b) = pair(&[]).await;
    let id = a.send("Bob@node-b", a.stage(b"request").await).await;
    b.wait_delivery(&id).await;
    let reference = b.stage(b"answer file").await;
    let answer = b
        .agent(json!({"action":"reply","message_id":id,"text":"answer","attachments":[reference]}))
        .await;
    assert_eq!(answer["status"], "ok", "reply setup: {answer}");
    let pushed = answer["reply"]["pushedMessageId"].as_str().unwrap();
    let uri = format!("/fed/v2/attachments/{pushed}/0?offset=0&length=65536");
    let (status, body) = a.fed(&b, "GET", &uri, None).await;
    assert_eq!(
        status,
        200,
        "reply downstream positive control: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(body, b"answer file");
    b.reload(json!({"peers":{"node-a":a.identity.entry(a.fed_port,&["reply"])}}));
    let (status, body) = a.fed(&b, "GET", &uri, None).await;
    assert_eq!(
        status,
        403,
        "M3: reply attachment remained readable without live send right: {}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recipient_forwards_without_reupload_and_verified_item_survives_upstream_loss() {
    let (a, mut b) = pair(&[]).await;
    let q = Node::new(
        Identity::new("node-q"),
        QUINN,
        "Quinn",
        json!({"peers":{"node-b":b.identity.entry(b.fed_port,&["send","reply"])}}),
        &[],
    )
    .await;
    b.reload(json!({"peers":{"node-a":a.identity.entry(a.fed_port,&["send","reply"]),"node-q":q.identity.entry(q.fed_port,&["send","reply"])}}));
    let reference = a.stage(b"forward without reupload").await;
    let original = a.send("Bob@node-b", reference.clone()).await;
    b.wait_delivery(&original).await;
    let before: i64 = rusqlite::Connection::open(&b.db)
        .unwrap()
        .query_row("SELECT count(*) FROM blobs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, 0, "recipient starts with refs, not bytes");
    let request = json!({"action":"send","to":"Quinn@node-q","text":"forwarded file","attachments":[reference],"idempotency_key":"owh-forward"});
    let first = b.agent(request.clone()).await;
    assert_eq!(
        first["status"], "ok",
        "recipient must lazily fetch and forward without staging: {first}"
    );
    let id = first["message_id"].as_str().unwrap();
    q.wait_delivery(id).await;
    assert_eq!(q.read(id).await["data"], "forward without reupload");
    rusqlite::Connection::open(&a.db)
        .unwrap()
        .execute("DELETE FROM blobs", [])
        .unwrap();
    let (status, _) = b
        .fed(
            &a,
            "GET",
            &format!("/fed/v2/attachments/{original}/0?offset=0&length=65536"),
            None,
        )
        .await;
    assert_eq!(
        status, 410,
        "upstream loss control must refuse a fresh fetch"
    );
    let again = b.agent(request.clone()).await;
    assert_eq!(
        again["status"], "ok",
        "settled forward retry must not refetch: {again}"
    );
    assert_eq!(again["message_id"], first["message_id"]);
    let mut next = request;
    next["idempotency_key"] = "owh-forward-new-key".into();
    let next = b.agent(next).await;
    assert_eq!(
        next["status"], "ok",
        "verified remote item must not refetch for a new forward: {next}"
    );
    let next_id = next["message_id"].as_str().unwrap();
    q.wait_delivery(next_id).await;
    assert_eq!(q.read(next_id).await["data"], "forward without reupload");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn federated_raw_ranges_are_bounded_bytes_without_utf8_trimming() {
    let (a, b) = pair(&["--max-body", "64"]).await;
    let payload = "é".repeat(64);
    let id = a
        .send("Bob@node-b", a.stage(payload.as_bytes()).await)
        .await;
    let uri = |offset: usize, length: usize| {
        format!("/fed/v2/attachments/{id}/0?offset={offset}&length={length}")
    };
    let (status, body) = b.fed(&a, "GET", &uri(0, 65536), None).await;
    assert_eq!(status, 200);
    assert_eq!(body.len(), 64, "M8: raw range exceeded message-body cap");
    assert_eq!(body, &payload.as_bytes()[..64]);
    let (status, body) = b.fed(&a, "GET", &uri(1, 1), None).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        vec![0xa9],
        "raw transport must not trim UTF-8 byte chunks"
    );
    for (offset, length) in [(0, 0), (129, 1)] {
        let (status, _) = b.fed(&a, "GET", &uri(offset, length), None).await;
        assert_eq!(status, 400, "invalid raw range must be refused");
    }
    let (status, body) = b.fed(&a, "GET", &uri(128, 1), None).await;
    assert_eq!(status, 200);
    assert!(body.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fetch_larger_than_attachment_rate_burst_keeps_verified_progress() {
    let (a, b) = pair(&[]).await;
    let data = vec![b'x'; 64 * 65536 + 1];
    let file = a.temp.path().join("large-file");
    fs::write(&file, &data).unwrap();
    let staged = a
        .agent(json!({"action":"attach","path":file,"name":"large.txt"}))
        .await;
    assert_eq!(
        staged["status"], "ok",
        "large-file staging fixture: {staged}"
    );
    let id = a.send("Bob@node-b", staged["attachment"].clone()).await;
    b.wait_delivery(&id).await;
    let read = tokio::time::timeout(WAIT, async {
        loop {
            let read = b.agent(json!({"action":"read_attachment","message_id":id,"index":0,"offset":0,"length":9})).await;
            if read["state"] != "pending" { break read; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await.expect("large-file fetch must settle after bounded rate waits");
    assert_eq!(
        read["data"], "xxxxxxxxx",
        "rate-limited chunks must resume the same whole-blob verification: {read}"
    );
    let db = rusqlite::Connection::open(&b.db).unwrap();
    let stored: i64 = db
        .query_row("SELECT size FROM blobs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        stored,
        data.len() as i64,
        "a prefix must not be published as a complete file"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leaf_acks_configured_oversize_ref_and_delivers_next_plain_message() {
    let il = Identity::new("leaf");
    let ih = Identity::new("hub");
    let mut leaf_entry = il.entry(9, &["send", "reply"]);
    leaf_entry["leaf"] = true.into();
    let hub = Node::new(ih, QUINN, "Hub", json!({"peers":{"leaf":leaf_entry}}), &[]).await;
    let mut route = hub.identity.entry(hub.fed_port, &["send", "reply"]);
    route["dial"] = "outbound".into();
    route["default_route"] = true.into();
    let leaf = Node::new(
        il,
        ALICE,
        "Leaf",
        json!({"peers":{"hub":route}}),
        &[
            "--leaf",
            "--leaf-principal",
            "demo",
            "--max-attachment-bytes",
            "8",
        ],
    )
    .await;
    let bad = hub.send("demo@leaf", hub.stage(b"123456789").await).await;
    let next = hub
        .agent(json!({"action":"send","to":"demo@leaf","text":"next plain message"}))
        .await;
    assert_eq!(next["status"], "ok", "next plain send: {next}");
    let next = next["message_id"].as_str().unwrap();
    let db = rusqlite::Connection::open(&leaf.db).unwrap();
    let hub_db = rusqlite::Connection::open(&hub.db).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if xmsg::storage::has_svc_message(&db, next).unwrap() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("configured oversize ref must be ACKed so next plain mail can advance");
    assert!(
        !xmsg::storage::has_svc_message(&db, &bad).unwrap(),
        "oversize message entered service queue"
    );
    let bad_rows: i64 = hub_db
        .query_row(
            "SELECT count(*) FROM peer_mailbox WHERE id=?1",
            [&bad],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        bad_rows, 0,
        "permanently refused mailbox item must be ACKed"
    );
    assert_eq!(
        leaf.output
            .line_count_containing("rejecting malformed message pulled from hub on leaf"),
        1,
        "permanent bad metadata must be rejected once, without redelivery or a hot loop"
    );
    assert_eq!(
        leaf.output
            .line_count_containing("backing off without acking hub"),
        0,
        "permanent bad metadata must not enter retryable storage failure path"
    );
}
