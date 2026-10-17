//! HA8 — Instance Reclaim for `pi`, `opencode`, and `hermes` (with XF2.1).
//!
//! Covers:
//! - Oracle 1: Reclaim after restart & queued delivery (`pi`, `opencode`, `hermes`)
//! - Oracle 2: Wrong secret refused with identical `denied` (`"reclaim refused"`)
//! - Oracle 3: Expired window (`reply_ttl`) refused with `denied`, fallback to fresh mint
//! - Oracle 4: `/new` (fresh session) mints a fresh address while old stays reclaimable
//! - Oracle 5: Secret rotation on reclaim (presenting pre-rotation secret after reclaim is `denied`)
//! - Oracle 6: Live-elsewhere conflict returns `live_elsewhere` (when secret is valid), while wrong secret on live returns `denied`
//! - Oracle 7: `continues` + reclaim across restart (`hermes` compression chain)
//! - Change 1 (§3.1): `detach` vs permanent `release` (`release` clears `reclaim_hash`, answers `gone`, `closed` in inactive `list`)
//! - Change 3 (§3.3): `list` live-only default vs `status: "inactive"` (`parked` for reclaimable, `closed` for released/expired), no secret in `list`
//! - Change 4: Cross-harness reclaim refused (`pi` secret on `opencode`, `opencode` secret on `hermes`) with identical `denied`
//! - Change 5: Reclaimable row older than 1 hour (`> 3600s`) survives `sync_claims` / purge

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

fn node_name() -> String {
    xmsg::node::local_node_name()
}

struct Node {
    _tmp: TempDir,
    child: Child,
    db_path: PathBuf,
    http_sock: PathBuf,
    register_sock: PathBuf,
}

impl Node {
    fn start(reply_ttl: Option<u64>) -> Node {
        let tmp = tempdir().unwrap();
        let run = tmp.path().join("xmsg");
        let sessions = tmp.path().join("sessions");
        fs::create_dir_all(&run).unwrap();
        fs::create_dir_all(&sessions).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let db_path = tmp.path().join("xmsg.db");
        let http_sock = run.join("http.sock");
        let register_sock = run.join("register.sock");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_xmsg"));
        cmd.env("XDG_RUNTIME_DIR", &run)
            .env("HOME", &run)
            .env_remove("XMSG_HOST_LABEL")
            .arg("serve")
            .arg("--db-path")
            .arg(&db_path)
            .arg("--sessions-dir")
            .arg(&sessions)
            .arg("--http-sock")
            .arg(&http_sock)
            .arg("--agent-sock")
            .arg(run.join("agent.sock"))
            .arg("--register-sock")
            .arg(&register_sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(ttl) = reply_ttl {
            cmd.arg("--reply-ttl").arg(ttl.to_string());
        }
        let mut child = cmd.spawn().expect("spawn xmsg serve");
        for _ in 0..600 {
            if let Ok(Some(_)) = child.try_wait() {
                panic!("xmsg serve exited early");
            }
            if http_sock.exists() && register_sock.exists() {
                return Node {
                    _tmp: tmp,
                    child,
                    db_path,
                    http_sock,
                    register_sock,
                };
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("xmsg serve did not bind sockets in time");
    }

    async fn http(&self, method: &str, path: &str, body: Option<&Value>) -> (u16, Value) {
        let mut stream = UnixStream::connect(&self.http_sock).await.unwrap();
        let payload = body.map(|b| b.to_string()).unwrap_or_default();
        let req = if body.is_some() {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            )
        } else {
            format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        };
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).await.unwrap();
        let (head, body_str) = raw.split_once("\r\n\r\n").unwrap();
        let status: u16 = head
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let val =
            serde_json::from_str(body_str).unwrap_or_else(|_| Value::String(body_str.to_string()));
        (status, val)
    }

    async fn send(&self, to: &str, text: &str) -> (u16, Value) {
        self.http(
            "POST",
            "/v1/messages",
            Some(&json!({ "to": to, "from": "ci-sender", "text": text })),
        )
        .await
    }

    async fn list(&self, query: &str) -> Vec<Value> {
        let path = if query.is_empty() {
            "/v1/recipients".to_string()
        } else {
            format!("/v1/recipients?{query}")
        };
        let (status, body) = self.http("GET", &path, None).await;
        assert_eq!(status, 200, "{body}");
        serde_json::from_value(body["recipients"].clone()).unwrap()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct PiConn {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl PiConn {
    async fn open_raw(sock: &Path, frame: Value) -> (PiConn, Value) {
        let stream = UnixStream::connect(sock).await.unwrap();
        let (r, w) = stream.into_split();
        let mut conn = PiConn {
            reader: BufReader::new(r),
            writer: w,
        };
        let resp = conn.call(frame).await;
        (conn, resp)
    }

    async fn open(sock: &Path, frame: Value) -> (PiConn, Value) {
        let (conn, resp) = Self::open_raw(sock, frame).await;
        assert_eq!(resp["status"], "ok", "pi registration: {resp}");
        (conn, resp)
    }

    async fn call(&mut self, frame: Value) -> Value {
        self.writer
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(10), self.reader.read_line(&mut line))
            .await
            .expect("register.sock pi answer")
            .unwrap();
        serde_json::from_str(&line).unwrap()
    }
}

struct PluginConn {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    next: u64,
}

impl PluginConn {
    async fn open(sock: &Path, harness: &str) -> PluginConn {
        let stream = UnixStream::connect(sock).await.unwrap();
        let (r, w) = stream.into_split();
        let mut conn = PluginConn {
            reader: BufReader::new(r),
            writer: w,
            next: 0,
        };
        conn.writer
            .write_all(format!("{}\n", json!({ "harness": harness })).as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        conn.reader.read_line(&mut line).await.unwrap();
        let hello: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(hello["status"], "ok", "{hello}");
        conn
    }

    async fn call(&mut self, mut frame: Value) -> Value {
        self.next += 1;
        let rid = format!("r{}", self.next);
        frame
            .as_object_mut()
            .unwrap()
            .insert("request_id".into(), Value::String(rid.clone()));
        self.writer
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(10), self.reader.read_line(&mut line))
            .await
            .expect("register.sock plugin answer")
            .unwrap();
        let resp: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(resp["request_id"], rid, "{resp}");
        resp
    }
}

// =============================================================================
// Oracle 1, 4, 5 & Change 1: Reclaim after restart + queued delivery + secret
// rotation + /new fresh mint + permanent release for `pi`, `opencode`, `hermes`.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ha8_oracle_1_4_5_reclaim_queued_delivery_and_rotation() {
    let node = Node::start(None);
    let n = node_name();

    // --- 1a. PI ---
    let (pi1, r1) = PiConn::open(
        &node.register_sock,
        json!({ "harness": "pi", "sessionId": "native-pi-1", "sessionName": "pi-one" }),
    )
    .await;
    let pi_id = r1["sessionId"].as_str().unwrap().to_string();
    let pi_addr = r1["address"].as_str().unwrap().to_string();
    let pi_sec1 = r1["reclaim"].as_str().unwrap().to_string();
    assert_eq!(pi_addr, format!("{pi_id}@{n}"));
    assert!(!pi_sec1.is_empty());

    // Disconnect pi1 (detach)
    drop(pi1);
    for _ in 0..100 {
        if node.list("").await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Send a message while pi1 is detached -> queued
    let (status, sent) = node.send(&pi_addr, "queued-for-pi").await;
    assert_eq!(status, 202, "{sent}");
    assert_eq!(sent["outcome"], "queued", "{sent}");

    // Oracle 4: `/new` (registering without reclaim) mints a fresh address while pi_id stays reclaimable
    let (pi_new, r_new) = PiConn::open(
        &node.register_sock,
        json!({ "harness": "pi", "sessionId": "native-pi-2", "sessionName": "pi-two" }),
    )
    .await;
    let pi_new_id = r_new["sessionId"].as_str().unwrap().to_string();
    assert_ne!(pi_new_id, pi_id);
    drop(pi_new);

    // Reclaim pi_id with pi_sec1 -> gets same sessionId/address and a rotated secret pi_sec2
    let (mut pi2, r2) = PiConn::open(
        &node.register_sock,
        json!({
            "harness": "pi",
            "sessionId": "native-pi-1",
            "sessionName": "pi-one",
            "reclaim": { "id": pi_id, "secret": pi_sec1 }
        }),
    )
    .await;
    assert_eq!(r2["sessionId"], pi_id);
    assert_eq!(r2["address"], pi_addr);
    let pi_sec2 = r2["reclaim"].as_str().unwrap().to_string();
    assert_ne!(pi_sec2, pi_sec1, "Oracle 5: reclaim MUST rotate the secret");

    // Poll receives the queued message
    let delivered = pi2.call(json!({ "action": "poll", "waitSecs": 1 })).await;
    assert_eq!(delivered["action"], "deliver", "{delivered}");
    assert_eq!(delivered["text"], "queued-for-pi");
    let ack = pi2
        .call(json!({ "action": "ack", "messageId": delivered["messageId"] }))
        .await;
    assert_eq!(ack["status"], "ok");
    drop(pi2);
    for _ in 0..100 {
        if node.list("").await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Oracle 5: Presenting pre-rotation secret pi_sec1 after rotation is refused `denied`
    let (_, bad_rot) = PiConn::open_raw(
        &node.register_sock,
        json!({
            "harness": "pi",
            "reclaim": { "id": pi_id, "secret": pi_sec1 }
        }),
    )
    .await;
    assert_eq!(bad_rot["status"], "error", "{bad_rot}");
    assert_eq!(bad_rot["error"], "denied", "{bad_rot}");
    assert_eq!(bad_rot["detail"], "reclaim refused", "{bad_rot}");

    // Presenting rotated secret pi_sec2 succeeds
    let (pi3, r3) = PiConn::open(
        &node.register_sock,
        json!({
            "harness": "pi",
            "reclaim": { "id": pi_id, "secret": pi_sec2 }
        }),
    )
    .await;
    assert_eq!(r3["sessionId"], pi_id);
    drop(pi3);

    // --- 1b. OPENCODE & HERMES (plugin protocol) ---
    for harness in ["opencode", "hermes"] {
        let mut p1 = PluginConn::open(&node.register_sock, harness).await;
        let reg1 = p1
            .call(json!({ "action": "register", "session": "sess-1" }))
            .await;
        assert_eq!(reg1["status"], "ok", "{reg1}");
        let addr = reg1["address"].as_str().unwrap().to_string();
        let id = addr.split('@').next().unwrap().to_string();
        let sec1 = reg1["reclaim"].as_str().unwrap().to_string();

        // Explicit detach parks the session (keeps reclaim_hash)
        let det = p1
            .call(json!({ "action": "detach", "session": "sess-1" }))
            .await;
        assert_eq!(det["status"], "ok", "{det}");
        drop(p1);

        // Send while detached -> queued
        let (status, sent) = node.send(&addr, &format!("queued-for-{harness}")).await;
        assert_eq!(status, 202, "{sent}");
        assert_eq!(sent["outcome"], "queued", "{sent}");

        // Reconnect and reclaim with sec1 -> rotates to sec2 and delivers queued message
        let mut p2 = PluginConn::open(&node.register_sock, harness).await;
        let reg2 = p2
            .call(json!({
                "action": "register",
                "session": "sess-1",
                "reclaim": { "id": id, "secret": sec1 }
            }))
            .await;
        assert_eq!(reg2["status"], "ok", "{reg2}");
        assert_eq!(reg2["address"], addr);
        let sec2 = reg2["reclaim"].as_str().unwrap().to_string();
        assert_ne!(sec2, sec1, "Oracle 5 ({harness}): secret must rotate");

        let deliv = p2.call(json!({ "action": "poll", "wait": 1 })).await;
        assert_eq!(deliv["action"], "deliver", "{deliv}");
        assert_eq!(deliv["text"], format!("queued-for-{harness}"));
        let ack = p2
            .call(json!({
                "action": "ack",
                "session": "sess-1",
                "message_id": deliv["message_id"]
            }))
            .await;
        assert_eq!(ack["status"], "ok", "{ack}");

        // Detach and verify pre-rotation sec1 is refused
        p2.call(json!({ "action": "detach", "session": "sess-1" }))
            .await;
        let stale = p2
            .call(json!({
                "action": "register",
                "session": "sess-1",
                "reclaim": { "id": id, "secret": sec1 }
            }))
            .await;
        assert_eq!(stale["status"], "error", "{stale}");
        assert_eq!(stale["error"], "denied", "{stale}");

        // Reclaim with sec2 and permanently `release` (§3.1)
        let reg3 = p2
            .call(json!({
                "action": "register",
                "session": "sess-1",
                "reclaim": { "id": id, "secret": sec2 }
            }))
            .await;
        assert_eq!(reg3["status"], "ok", "{reg3}");
        let sec3 = reg3["reclaim"].as_str().unwrap().to_string();
        let rel = p2
            .call(json!({ "action": "release", "session": "sess-1" }))
            .await;
        assert_eq!(rel["status"], "ok", "{rel}");

        // Permanently released address answers 410 gone and refuses reclaim even with latest secret
        let (status, gone_body) = node.send(&addr, "after-release").await;
        assert_eq!(status, 410, "{gone_body}");
        assert_eq!(gone_body["error"], "gone", "{gone_body}");
        let after_rel = p2
            .call(json!({
                "action": "register",
                "session": "sess-1",
                "reclaim": { "id": id, "secret": sec3 }
            }))
            .await;
        assert_eq!(after_rel["status"], "error", "{after_rel}");
        assert_eq!(after_rel["error"], "denied", "{after_rel}");
    }
}

// =============================================================================
// Oracle 2, Oracle 6 & Change 4: Wrong secret, unknown ID, cross-harness
// reclaim, and live-elsewhere conflict.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ha8_oracle_2_6_and_change_4_security_and_liveness() {
    let node = Node::start(None);

    // Mint a pi session and an opencode session
    let (pi1, r_pi) = PiConn::open(
        &node.register_sock,
        json!({ "harness": "pi", "sessionName": "pi-live" }),
    )
    .await;
    let pi_id = r_pi["sessionId"].as_str().unwrap().to_string();
    let pi_sec = r_pi["reclaim"].as_str().unwrap().to_string();

    let mut oc1 = PluginConn::open(&node.register_sock, "opencode").await;
    let r_oc = oc1
        .call(json!({ "action": "register", "session": "oc-s1" }))
        .await;
    let oc_addr = r_oc["address"].as_str().unwrap().to_string();
    let oc_id = oc_addr.split('@').next().unwrap().to_string();
    let oc_sec = r_oc["reclaim"].as_str().unwrap().to_string();

    // Oracle 6: While pi1 and oc1 are still LIVE:
    // - Presenting the VALID secret returns `live_elsewhere`
    let (_, pi_conflict) = PiConn::open_raw(
        &node.register_sock,
        json!({ "harness": "pi", "reclaim": { "id": pi_id, "secret": pi_sec } }),
    )
    .await;
    assert_eq!(pi_conflict["status"], "error", "{pi_conflict}");
    assert_eq!(pi_conflict["error"], "live_elsewhere", "{pi_conflict}");

    let mut oc2 = PluginConn::open(&node.register_sock, "opencode").await;
    let oc_conflict = oc2
        .call(json!({
            "action": "register",
            "session": "oc-s1-dup",
            "reclaim": { "id": oc_id, "secret": oc_sec }
        }))
        .await;
    assert_eq!(oc_conflict["status"], "error", "{oc_conflict}");
    assert_eq!(oc_conflict["error"], "live_elsewhere", "{oc_conflict}");

    // - Presenting a WRONG secret on a live ID returns `denied` ("reclaim refused"), NOT `live_elsewhere` (no oracle leak!)
    let (_, pi_wrong_live) = PiConn::open_raw(
        &node.register_sock,
        json!({ "harness": "pi", "reclaim": { "id": pi_id, "secret": "wrong-secret" } }),
    )
    .await;
    assert_eq!(pi_wrong_live["error"], "denied", "{pi_wrong_live}");
    assert_eq!(
        pi_wrong_live["detail"], "reclaim refused",
        "{pi_wrong_live}"
    );

    let oc_wrong_live = oc2
        .call(json!({
            "action": "register",
            "session": "oc-s1-wrong",
            "reclaim": { "id": oc_id, "secret": "wrong-secret" }
        }))
        .await;
    assert_eq!(oc_wrong_live["error"], "denied", "{oc_wrong_live}");
    assert_eq!(
        oc_wrong_live["detail"], "reclaim refused",
        "{oc_wrong_live}"
    );

    // Detach both
    drop(pi1);
    oc1.call(json!({ "action": "detach", "session": "oc-s1" }))
        .await;
    drop(oc1);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Oracle 2: Wrong secret and unknown ID return identical `denied` shape
    let (_, wrong_sec) = PiConn::open_raw(
        &node.register_sock,
        json!({ "harness": "pi", "reclaim": { "id": pi_id, "secret": "bad-secret" } }),
    )
    .await;
    let (_, unknown_id) = PiConn::open_raw(
        &node.register_sock,
        json!({ "harness": "pi", "reclaim": { "id": "00000000-0000-4000-8000-000000000000", "secret": pi_sec } }),
    )
    .await;
    assert_eq!(
        wrong_sec, unknown_id,
        "wrong secret and unknown id must return identical error"
    );
    assert_eq!(wrong_sec["error"], "denied");
    assert_eq!(wrong_sec["detail"], "reclaim refused");

    // Change 4: Cross-harness reclaim (pi secret presented by opencode, opencode secret presented by hermes/pi) is refused with identical `denied`
    let cross_pi_on_oc = oc2
        .call(json!({
            "action": "register",
            "session": "steal-pi",
            "reclaim": { "id": pi_id, "secret": pi_sec }
        }))
        .await;
    assert_eq!(cross_pi_on_oc["error"], "denied", "{cross_pi_on_oc}");
    assert_eq!(
        cross_pi_on_oc["detail"], "reclaim refused",
        "{cross_pi_on_oc}"
    );

    let mut hm = PluginConn::open(&node.register_sock, "hermes").await;
    let cross_oc_on_hm = hm
        .call(json!({
            "action": "register",
            "session": "steal-oc",
            "reclaim": { "id": oc_id, "secret": oc_sec }
        }))
        .await;
    assert_eq!(cross_oc_on_hm["error"], "denied", "{cross_oc_on_hm}");
    assert_eq!(
        cross_oc_on_hm["detail"], "reclaim refused",
        "{cross_oc_on_hm}"
    );

    let (_, cross_oc_on_pi) = PiConn::open_raw(
        &node.register_sock,
        json!({ "harness": "pi", "reclaim": { "id": oc_id, "secret": oc_sec } }),
    )
    .await;
    assert_eq!(cross_oc_on_pi, wrong_sec);
}

// =============================================================================
// Oracle 3: Expired window (`reply_ttl`) refuses reclaim with `denied`.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ha8_oracle_3_expired_window_refused() {
    let node = Node::start(Some(1));
    let (pi1, r1) = PiConn::open(
        &node.register_sock,
        json!({ "harness": "pi", "sessionName": "pi-exp" }),
    )
    .await;
    let pi_id = r1["sessionId"].as_str().unwrap().to_string();
    let pi_sec = r1["reclaim"].as_str().unwrap().to_string();
    drop(pi1);

    let mut oc1 = PluginConn::open(&node.register_sock, "opencode").await;
    let r_oc = oc1
        .call(json!({ "action": "register", "session": "oc-exp" }))
        .await;
    let oc_id = r_oc["address"]
        .as_str()
        .unwrap()
        .split('@')
        .next()
        .unwrap()
        .to_string();
    let oc_sec = r_oc["reclaim"].as_str().unwrap().to_string();
    oc1.call(json!({ "action": "detach", "session": "oc-exp" }))
        .await;

    // Wait past the 1s reply_ttl window
    tokio::time::sleep(Duration::from_millis(2200)).await;

    let (_, exp_pi) = PiConn::open_raw(
        &node.register_sock,
        json!({ "harness": "pi", "reclaim": { "id": pi_id, "secret": pi_sec } }),
    )
    .await;
    assert_eq!(exp_pi["error"], "denied", "{exp_pi}");
    assert_eq!(exp_pi["detail"], "reclaim refused", "{exp_pi}");

    let exp_oc = oc1
        .call(json!({
            "action": "register",
            "session": "oc-exp",
            "reclaim": { "id": oc_id, "secret": oc_sec }
        }))
        .await;
    assert_eq!(exp_oc["error"], "denied", "{exp_oc}");
    assert_eq!(exp_oc["detail"], "reclaim refused", "{exp_oc}");
}

// =============================================================================
// Oracle 7: `continues` moves the address to `S2`, and a subsequent detach +
// reclaim presents the secret for that address and reclaims it for `S2`.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ha8_oracle_7_continues_and_reclaim() {
    let node = Node::start(None);
    let mut hm1 = PluginConn::open(&node.register_sock, "hermes").await;
    let reg = hm1
        .call(json!({ "action": "register", "session": "s1" }))
        .await;
    let addr = reg["address"].as_str().unwrap().to_string();
    let id = addr.split('@').next().unwrap().to_string();
    let sec = reg["reclaim"].as_str().unwrap().to_string();

    let cont = hm1
        .call(json!({ "action": "continues", "from": "s1", "to": "s2" }))
        .await;
    assert_eq!(cont["status"], "ok", "{cont}");
    assert_eq!(cont["address"], addr);

    // Connection closes (process restart)
    drop(hm1);
    for _ in 0..100 {
        if node.list("").await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Reconnect and reclaim as `s2` with the secret minted for `s1`
    let mut hm2 = PluginConn::open(&node.register_sock, "hermes").await;
    let reg2 = hm2
        .call(json!({
            "action": "register",
            "session": "s2",
            "reclaim": { "id": id, "secret": sec }
        }))
        .await;
    assert_eq!(reg2["status"], "ok", "{reg2}");
    assert_eq!(reg2["address"], addr);
}

// =============================================================================
// Change 3 (§3.3) & Change 5:
// - `list` default is live-only; `status=inactive` shows detached reclaimable
//   rows as `parked` and permanently released rows as `closed`; no secret/hash
//   ever appears in `list`.
// - A reclaimable row older than 1 hour (> 3600s) survives `sync_claims` / purge.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ha8_change_3_and_5_list_inactive_and_pruning_survival() {
    let node = Node::start(None);
    let mut oc = PluginConn::open(&node.register_sock, "opencode").await;

    let r_parked = oc
        .call(json!({ "action": "register", "session": "s-parked" }))
        .await;
    let addr_parked = r_parked["address"].as_str().unwrap().to_string();
    let id_parked = addr_parked.split('@').next().unwrap().to_string();
    let sec_parked = r_parked["reclaim"].as_str().unwrap().to_string();

    let r_closed = oc
        .call(json!({ "action": "register", "session": "s-closed" }))
        .await;
    let addr_closed = r_closed["address"].as_str().unwrap().to_string();

    // Detach s-parked, permanently release s-closed
    oc.call(json!({ "action": "detach", "session": "s-parked" }))
        .await;
    oc.call(json!({ "action": "release", "session": "s-closed" }))
        .await;
    drop(oc);

    // Default list is live-only -> empty
    let live = node.list("").await;
    assert!(live.is_empty(), "default list must be live-only: {live:?}");

    // Inactive list shows s-parked as `parked` and s-closed as `closed`
    let inactive = node.list("status=inactive").await;
    let raw_inactive = serde_json::to_string(&inactive).unwrap();
    assert!(
        !raw_inactive.contains(&sec_parked) && !raw_inactive.contains("reclaim"),
        "list output must never contain reclaim secret or hash: {raw_inactive}"
    );
    let e_parked = inactive
        .iter()
        .find(|e| e["address"] == addr_parked)
        .expect("s-parked in inactive list");
    assert_eq!(e_parked["status"], "parked", "{e_parked}");
    let e_closed = inactive
        .iter()
        .find(|e| e["address"] == addr_closed)
        .expect("s-closed in inactive list");
    assert_eq!(e_closed["status"], "closed", "{e_closed}");

    // Change 5: Backdate `last_live` of `id_parked` to 7200s ago (> 1 hour) in SQLite,
    // trigger `list` (which runs `sync_claims` -> `purge_instance_seen`), and verify the
    // row survives and is still reclaimable!
    {
        let conn = rusqlite::Connection::open(&node.db_path).unwrap();
        let old_ts = xmsg::storage::now_epoch_secs() - 7200;
        conn.execute(
            "UPDATE instance_seen SET last_live = ?1 WHERE id = ?2",
            rusqlite::params![old_ts, id_parked],
        )
        .unwrap();
    }

    // Trigger sync_claims + purge_instance_seen via both live and inactive list calls
    node.list("").await;
    let inactive_after = node.list("status=inactive&within=86400").await;
    assert!(
        inactive_after
            .iter()
            .any(|e| e["address"] == addr_parked && e["status"] == "parked"),
        "reclaimable row older than 1h must survive sync_claims/purge: {inactive_after:?}"
    );

    // Reclaim after >1h still succeeds
    let mut oc2 = PluginConn::open(&node.register_sock, "opencode").await;
    let reclaimed = oc2
        .call(json!({
            "action": "register",
            "session": "s-parked",
            "reclaim": { "id": id_parked, "secret": sec_parked }
        }))
        .await;
    assert_eq!(reclaimed["status"], "ok", "{reclaimed}");
    assert_eq!(reclaimed["address"], addr_parked);
}
