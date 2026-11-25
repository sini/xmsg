//! Gating oracles for session capability tags (O1-O8, U3, U5, and 912ca97a compat).

mod agy_env;
#[path = "support/spawn.rs"]
mod spawn;
use agy_env::ScrubAgyEnv;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};
use tempfile::TempDir;
use xmsg::client::{ClientError, ClientOptions, ListQuery, RegisteredService};

const BIN: &str = env!("CARGO_BIN_EXE_xmsg");

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct NodeDir {
    tmp: TempDir,
    run: PathBuf,
    sessions: PathBuf,
    db: PathBuf,
    peers: PathBuf,
    http_sock: PathBuf,
    agent_sock: PathBuf,
    register_sock: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}

impl NodeDir {
    fn new(prefix: &str) -> Self {
        let tmp = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in("/tmp")
            .unwrap();
        let root = tmp.path().to_path_buf();
        let run = root.join("run");
        let sessions = root.join("sessions");
        for d in [&root, &run, &sessions] {
            fs::create_dir_all(d).unwrap();
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            tmp,
            run: run.clone(),
            sessions,
            db: root.join("xmsg.db"),
            peers: root.join("peers.json"),
            http_sock: run.join("http.sock"),
            agent_sock: run.join("agent.sock"),
            register_sock: run.join("register.sock"),
            cert: root.join("node.pem"),
            key: root.join("node.key"),
            ca: root.join("ca.pem"),
        }
    }

    fn cmd(&self, bin: &str) -> Command {
        let mut c = spawn::command(bin);
        c.scrub_agy_env()
            .env("HOME", self.tmp.path())
            .env("XDG_RUNTIME_DIR", &self.run)
            .env("XDG_STATE_HOME", self.tmp.path().join("state"))
            .env("XMSG_HTTP_SOCK", &self.http_sock)
            .env("XMSG_AGENT_SOCK", &self.agent_sock)
            .env("XMSG_REGISTER_SOCK", &self.register_sock)
            .env("XMSG_DB_PATH", &self.db);
        c
    }
}

struct Daemon {
    dir: NodeDir,
    child: Option<Child>,
    port: Option<u16>,
    extra_args: Vec<String>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Daemon {
    fn start(
        dir: NodeDir,
        bin: &str,
        _node_name: &str,
        port: Option<u16>,
        extra_args: Vec<String>,
    ) -> Self {
        let mut d = Self {
            dir,
            child: None,
            port,
            extra_args,
        };
        d.spawn(bin);
        d
    }

    fn spawn(&mut self, bin: &str) {
        let presence_dir = self.dir.run.join("agy-presence");
        let _ = fs::create_dir_all(&presence_dir);
        let mut cmd = self.dir.cmd(bin);
        cmd.env("XMSG_AGY_PRESENCE_DIR", &presence_dir);
        cmd.args([
            "serve",
            "--http-sock",
            &self.dir.http_sock.display().to_string(),
            "--agent-sock",
            &self.dir.agent_sock.display().to_string(),
            "--register-sock",
            &self.dir.register_sock.display().to_string(),
            "--db-path",
            &self.dir.db.display().to_string(),
            "--sessions-dir",
            &self.dir.sessions.display().to_string(),
        ]);
        if let Some(p) = self.port {
            cmd.args([
                "--listen",
                "127.0.0.1:0",
                "--fed-listen",
                &format!("127.0.0.1:{p}"),
            ]);
        } else {
            cmd.args(["--listen", "127.0.0.1:0"]);
        }
        if self.dir.peers.exists() {
            cmd.args(["--peers-file", &self.dir.peers.display().to_string()]);
        }
        if self.dir.cert.exists() && self.dir.key.exists() {
            cmd.args([
                "--fed-cert",
                &self.dir.cert.display().to_string(),
                "--fed-key",
                &self.dir.key.display().to_string(),
            ]);
        }
        cmd.args(&self.extra_args);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let child = cmd.spawn().expect("spawn xmsg serve");
        self.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(15);
        while !self.dir.agent_sock.exists()
            || !self.dir.http_sock.exists()
            || !self.dir.register_sock.exists()
        {
            assert!(Instant::now() < deadline, "daemon sockets did not appear");
            if let Some(ref mut c) = self.child {
                if let Ok(Some(st)) = c.try_wait() {
                    let mut err = String::new();
                    if let Some(mut s) = c.stderr.take() {
                        let _ = std::io::Read::read_to_string(&mut s, &mut err);
                    }
                    panic!("daemon exited early ({st}): {err}");
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            unsafe {
                libc::kill(c.id() as libc::pid_t, libc::SIGTERM);
            }
            let _ = c.wait();
        }
        let _ = fs::remove_file(&self.dir.http_sock);
        let _ = fs::remove_file(&self.dir.agent_sock);
        let _ = fs::remove_file(&self.dir.register_sock);
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct TestCa {
    pem: String,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl TestCa {
    fn new() -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem();
        let issuer = rcgen::Issuer::from_ca_cert_pem(&pem, key).unwrap();
        Self { pem, issuer }
    }

    fn issue(&self, node: &str, user: &str, dir: &NodeDir) -> String {
        let spiffe = format!("spiffe://p1pz.test/host/{node}/user/{user}");
        let mut params =
            rcgen::CertificateParams::new(vec![node.to_string(), "127.0.0.1".to_string()]).unwrap();
        params.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(spiffe).unwrap(),
        ));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        let cert_pem = cert.pem();
        fs::write(&dir.cert, &cert_pem).unwrap();
        fs::write(&dir.key, key.serialize_pem()).unwrap();
        fs::write(&dir.ca, &self.pem).unwrap();
        cert_pem
    }
}

fn spki_pin(cert_pem: &str) -> String {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(&pem.contents).unwrap();
    let spki = parsed.public_key().raw;
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(spki);
    format!("sha256:{}", hex::encode(hash))
}

fn call_agent(sock: &Path, frame: &Value) -> Value {
    let mut s = UnixStream::connect(sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    writeln!(s, "{frame}").unwrap();
    s.flush().unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn call_mcp_tools(dir: &NodeDir, calls: &[Value], extra_env: &[(&str, &str)]) -> Vec<Value> {
    let mut cmd = dir.cmd(BIN);
    cmd.args(["mcp", "--db-path", &dir.db.display().to_string()]);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let init = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": { "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": { "name": "t", "version": "1" } }
    });
    writeln!(stdin, "{init}").unwrap();
    for (i, c) in calls.iter().enumerate() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": i + 2,
            "method": "tools/call",
            "params": c
        });
        writeln!(stdin, "{req}").unwrap();
    }
    stdin.flush().unwrap();
    drop(stdin);
    let mut out = Vec::new();
    for line in BufReader::new(stdout).lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(&line).unwrap();
        if v["id"].as_u64().is_some_and(|id| id >= 2) {
            out.push(v);
        }
    }
    let _ = child.wait();
    out
}

fn parse_mcp_text(resp: &Value) -> Value {
    assert_eq!(
        resp["result"]["isError"], false,
        "unexpected MCP error: {resp}"
    );
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text).unwrap()
}

fn http_get(sock: &Path, path: &str) -> (u16, Value) {
    let (status, text) = xmsg::http::http_get_unix(sock, path).unwrap();
    (status.as_u16(), serde_json::from_str(&text).unwrap())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct LegacyFedListEntry {
    id: String,
    kind: String,
    #[serde(default)]
    harness: Option<String>,
    #[serde(default)]
    label: Option<String>,
    status: String,
    user: String,
    #[serde(default)]
    registered_at: Option<i64>,
    #[serde(default)]
    last_seen: Option<i64>,
    #[serde(default)]
    context: Option<Value>,
}

fn write_claude_session_file(dir: &NodeDir, pid: u32, id: &str) {
    let start = xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), pid).unwrap();
    fs::write(
        dir.sessions.join(format!("{pid}.json")),
        json!({
            "pid": pid,
            "sessionId": id,
            "cwd": dir.sessions.display().to_string(),
            "status": "idle",
            "kind": "interactive",
            "startedAt": 1,
            "updatedAt": 2,
            "procStart": start,
            "messagingSocketPath": dir.run.join(format!("inbox-{pid}.sock")).display().to_string(),
        })
        .to_string(),
    )
    .unwrap();
}

fn spawn_tagged_claude(
    dir: &NodeDir,
    id: &str,
    tags: &[&str],
    subagent: Option<(&str, &str)>,
) -> ChildGuard {
    let mut cmds = format!("set -e; read _; {BIN} list --json >/dev/null;");
    for t in tags {
        cmds.push_str(&format!(" {BIN} tag add {t} --json >/dev/null;"));
    }
    if let Some((agent_id, name)) = subagent {
        let hook_in = json!({
            "hook_event_name": "SubagentStart",
            "session_id": id,
            "agent_id": agent_id,
            "agent_type": name,
        })
        .to_string();
        cmds.push_str(&format!(
            " printf '%s\\n' '{hook_in}' | {BIN} register claude --hook --sock {} >/dev/null;",
            dir.agent_sock.display()
        ));
    }
    cmds.push_str(" echo READY; exec sleep 120");
    let mut cmd = dir.cmd("sh");
    cmd.args(["-c", &cmds])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn tagged claude");
    write_claude_session_file(dir, child.id(), id);
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "go").unwrap();
    stdin.flush().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!(
        line.trim(),
        "READY",
        "tagged claude failed to start: {line}"
    );
    ChildGuard(child)
}

#[test]
fn o1_o4_o8_mesh_federation_and_consumer_inputs() {
    let ca = TestCa::new();
    let dir_h = NodeDir::new("p1h");
    let dir_l = NodeDir::new("p1l");
    let dir_a = NodeDir::new("p1a");
    let port_h = free_port();
    let port_a = free_port();

    let pem_h = ca.issue("H", "alice", &dir_h);
    let pem_l = ca.issue("L", "alice", &dir_l);
    let pem_a = ca.issue("A", "bob", &dir_a);
    let pin_h = spki_pin(&pem_h);
    let pin_l = spki_pin(&pem_l);
    let pin_a = spki_pin(&pem_a);

    fs::write(
        &dir_h.peers,
        json!({
            "L": { "name": "L", "pin": pin_l, "leaf": true, "allow": ["list", "send", "reply"] },
            "A": { "name": "A", "pin": pin_a, "address": format!("127.0.0.1:{port_a}"), "allow": ["list", "send", "reply"] }
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        &dir_l.peers,
        json!({
            "H": { "name": "H", "pin": pin_h, "address": format!("127.0.0.1:{port_h}"), "dial": "outbound", "allow": ["list", "send", "reply"] }
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        &dir_a.peers,
        json!({
            "H": { "name": "H", "pin": pin_h, "address": format!("127.0.0.1:{port_h}"), "allow": ["list", "send", "reply"] }
        })
        .to_string(),
    )
    .unwrap();

    let d_h = Daemon::start(dir_h, BIN, "H", Some(port_h), vec![]);
    let d_l = Daemon::start(dir_l, BIN, "L", None, vec![]);
    let mut d_a = Daemon::start(dir_a, BIN, "A", Some(port_a), vec![]);

    let id_o = "11111111-1111-4111-8111-111111111111";
    let id_decoy = "22222222-2222-4222-8222-222222222222";
    let id_a_holder = "44444444-4444-4444-8444-444444444444";

    let guard_o = spawn_tagged_claude(
        &d_h.dir,
        id_o,
        &["orchestrator.den-ag-design"],
        Some(("sub1", "child")),
    );
    let _guard_decoy = spawn_tagged_claude(
        &d_h.dir,
        id_decoy,
        &["orchestrator.den-ag-design.old"],
        None,
    );

    // O1a: on L, MCP list(tag) gets 1 row (<O>@H), total==1, truncated==false, coverage.complete==true
    // Unfiltered list on L shows <O>/child@H as a live subagent
    let mcp_resps = call_mcp_tools(
        &d_l.dir,
        &[
            json!({ "name": "list", "arguments": { "tag": "orchestrator.den-ag-design" } }),
            json!({ "name": "list", "arguments": {} }),
        ],
        &[],
    );
    let filtered = parse_mcp_text(&mcp_resps[0]);
    assert_eq!(filtered["total"], 1, "O1a total: {filtered}");
    assert_eq!(filtered["truncated"], false, "O1a truncated: {filtered}");
    assert_eq!(
        filtered["coverage"]["complete"], true,
        "O1a coverage: {filtered}"
    );
    assert_eq!(
        filtered["recipients"][0]["address"],
        format!("{id_o}@H"),
        "O1a address: {filtered}"
    );
    let unfiltered = parse_mcp_text(&mcp_resps[1]);
    assert!(
        unfiltered["recipients"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["address"] == format!("{id_o}/sub1@H")),
        "O1a precondition <O>/sub1@H: {unfiltered}"
    );

    // O1f: on L, CLI xmsg list --tag orchestrator.den-ag-design --json
    let cli_out = d_l
        .dir
        .cmd(BIN)
        .args(["list", "--tag", "orchestrator.den-ag-design", "--json"])
        .output()
        .unwrap();
    assert!(cli_out.status.success(), "O1f CLI failed");
    let cli_v: Value = serde_json::from_slice(&cli_out.stdout).unwrap();
    assert_eq!(cli_v["total"], 1, "O1f total: {cli_v}");
    assert_eq!(cli_v["coverage"]["complete"], true, "O1f coverage: {cli_v}");
    assert_eq!(cli_v["recipients"][0]["address"], format!("{id_o}@H"));

    // O1e: local list(tag) on H returns only matching local holder (excludes decoy)
    let (_, h_local) = http_get(
        &d_h.dir.http_sock,
        "/v1/recipients?tag=orchestrator.den-ag-design",
    );
    assert_eq!(h_local["total"], 1, "O1e local total: {h_local}");
    assert_eq!(
        h_local["recipients"][0]["address"],
        format!("{id_o}@alice.H"),
        "O1e address: {h_local}"
    );

    // O4a: v2 direct peer /fed/v2/sessions?v=2 parses under strict LegacyFedListEntry and carries no tags
    {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut pem_bundle = fs::read(&d_a.dir.cert).unwrap();
            pem_bundle.extend_from_slice(&fs::read(&d_a.dir.key).unwrap());
            let identity = reqwest::Identity::from_pem(&pem_bundle).unwrap();
            let ca_cert = reqwest::Certificate::from_pem(&fs::read(&d_a.dir.ca).unwrap()).unwrap();
            let client = reqwest::Client::builder()
                .use_rustls_tls()
                .add_root_certificate(ca_cert)
                .identity(identity)
                .build()
                .unwrap();
            let resp = client
                .get(format!("https://127.0.0.1:{port_h}/fed/v2/sessions?v=2"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            let bytes = resp.bytes().await.unwrap();
            let v2_entries: Vec<LegacyFedListEntry> = serde_json::from_slice(&bytes).expect(
                "O4a /fed/v2/sessions?v=2 must decode under strict LegacyFedListEntry without tags",
            );
            assert!(
                v2_entries.iter().any(|e| e.id == id_o),
                "O4a expected O in v2 entries: {v2_entries:?}"
            );
        });
    }

    // O1d: tag only on A (nothing on H or L) -> L's list(tag) has 0 rows, nodes == [L, H], complete==true
    let _guard_a = spawn_tagged_claude(&d_a.dir, id_a_holder, &["only.on.a"], None);
    let (_, only_a) = http_get(&d_l.dir.http_sock, "/v1/recipients?tag=only.on.a");
    assert_eq!(only_a["total"], 0, "O1d non-transitive: {only_a}");
    let mut node_names: Vec<String> = only_a["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["node"].as_str().unwrap().to_string())
        .collect();
    node_names.sort();
    assert_eq!(
        node_names,
        vec!["H".to_string(), "alice.L".to_string()],
        "O1d nodes: {only_a}"
    );
    assert_eq!(
        only_a["coverage"]["complete"], true,
        "O1d complete: {only_a}"
    );

    // O1c + O8d: on H, list(tag: only.on.a) -> <id_a_holder>@A with user=="bob"
    let (_, h_sees_a) = http_get(&d_h.dir.http_sock, "/v1/recipients?tag=only.on.a");
    assert_eq!(h_sees_a["total"], 1, "O1c: {h_sees_a}");
    assert_eq!(
        h_sees_a["recipients"][0]["address"],
        format!("{id_a_holder}@A")
    );
    assert_eq!(
        h_sees_a["recipients"][0]["user"], "bob",
        "O8d user: {h_sees_a}"
    );

    // O8b + O8c: three holders (O on H, a2 and a3 on A) sharing tag; limit=1 -> total==3, truncated==true
    let _guard_a2 = spawn_tagged_claude(
        &d_a.dir,
        "66666666-6666-4666-8666-666666666666",
        &["orchestrator.den-ag-design"],
        None,
    );
    let _guard_a3 = spawn_tagged_claude(
        &d_a.dir,
        "66666666-6666-4666-8666-666666666667",
        &["orchestrator.den-ag-design"],
        None,
    );
    let (_, trunc) = http_get(
        &d_h.dir.http_sock,
        "/v1/recipients?tag=orchestrator.den-ag-design&limit=1",
    );
    assert_eq!(trunc["total"], 3, "O8c total before limit: {trunc}");
    assert_eq!(trunc["truncated"], true, "O8b truncated: {trunc}");
    assert_eq!(trunc["recipients"].as_array().unwrap().len(), 1);
    assert_eq!(trunc["coverage"]["complete"], true);

    // O4d + O8a: stop A -> H's list(tag) has 1 row (<O>@H), complete==false, unanswered==["A"]
    d_a.stop();
    let (_, incomp) = http_get(
        &d_h.dir.http_sock,
        "/v1/recipients?tag=orchestrator.den-ag-design",
    );
    assert_eq!(incomp["total"], 1, "O8a total: {incomp}");
    assert_eq!(incomp["truncated"], false, "O8a truncated: {incomp}");
    assert_eq!(
        incomp["coverage"]["complete"], false,
        "O8a complete: {incomp}"
    );
    assert_eq!(
        incomp["coverage"]["unanswered"],
        json!(["A"]),
        "O4d/O8a unanswered: {incomp}"
    );

    // O1i: O exits -> list(tag) is empty AND session_tag rows are deleted from sqlite db
    drop(guard_o);
    let (_, after_exit) = http_get(
        &d_h.dir.http_sock,
        "/v1/recipients?tag=orchestrator.den-ag-design",
    );
    assert_eq!(after_exit["total"], 0, "O1i holder closed: {after_exit}");
    {
        let db = rusqlite::Connection::open(&d_h.dir.db).unwrap();
        let rows: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM session_tag WHERE id = ?1",
                [id_o],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            rows, 0,
            "O1i/M1-end: session_tag row must be deleted on end()"
        );
    }

    // O1b: hub asker, leaf holder
    let id_l_holder = "77777777-7777-4777-8777-777777777777";
    let _guard_l = spawn_tagged_claude(&d_l.dir, id_l_holder, &["leaf.tag", "other.tag"], None);
    let (_, h_sees_l) = http_get(&d_h.dir.http_sock, "/v1/recipients?tag=leaf.tag");
    assert_eq!(h_sees_l["total"], 1, "O1b hub sees leaf holder: {h_sees_l}");
    assert_eq!(
        h_sees_l["recipients"][0]["address"],
        format!("{id_l_holder}@L")
    );

    // O5b: MCP HTTP fallback when agent.sock is absent
    let mut no_agent = NodeDir::new("p1o5b");
    no_agent.http_sock = d_h.dir.http_sock.clone();
    no_agent.db = d_h.dir.db.clone();
    no_agent.agent_sock = no_agent.run.join("missing-agent.sock");
    let fb = call_mcp_tools(
        &no_agent,
        &[json!({ "name": "list", "arguments": { "tag": "leaf.tag" } })],
        &[],
    );
    let fb_v = parse_mcp_text(&fb[0]);
    assert_eq!(fb_v["total"], 1, "O5b HTTP fallback list(tag): {fb_v}");
    assert_eq!(fb_v["recipients"][0]["address"], format!("{id_l_holder}@L"));

    // O1g: targets + allow exclusion — configure H2 with peers B (targets excludes holder) and B2 (allow=["send"], no "list").
    {
        let dir_h2 = NodeDir::new("p1o1gh2");
        let dir_b = NodeDir::new("p1o1gb");
        let dir_b2 = NodeDir::new("p1o1gb2");
        let port_h2 = free_port();
        let port_b = free_port();
        let port_b2 = free_port();
        let pem_h2 = ca.issue("H2", "alice", &dir_h2);
        let pem_b = ca.issue("B", "carol", &dir_b);
        let pem_b2 = ca.issue("B2", "dave", &dir_b2);
        let pin_h2 = spki_pin(&pem_h2);
        let pin_b = spki_pin(&pem_b);
        let pin_b2 = spki_pin(&pem_b2);
        fs::write(
            &dir_h2.peers,
            json!({
                "B": { "name": "B", "pin": pin_b, "address": format!("127.0.0.1:{port_b}"), "allow": ["list", "send"] },
                "B2": { "name": "B2", "pin": pin_b2, "address": format!("127.0.0.1:{port_b2}"), "allow": ["list", "send"] }
            })
            .to_string(),
        )
        .unwrap();
        // On B, H2 is allowed to list only a different target id (kills M1-targets at fed.rs:4758)
        fs::write(
            &dir_b.peers,
            json!({ "H2": { "name": "H2", "pin": pin_h2, "address": format!("127.0.0.1:{port_h2}"), "allow": ["list", "send"], "targets": ["97777777-7777-4777-8777-777777777779"] } }).to_string(),
        )
        .unwrap();
        // On B2, H2 has allow=["send"] (no "list") -> denied -> unanswered
        fs::write(
            &dir_b2.peers,
            json!({ "H2": { "name": "H2", "pin": pin_h2, "address": format!("127.0.0.1:{port_h2}"), "allow": ["send"] } }).to_string(),
        )
        .unwrap();
        let _d_h2 = Daemon::start(dir_h2, BIN, "H2", Some(port_h2), vec![]);
        let _d_b = Daemon::start(dir_b, BIN, "B", Some(port_b), vec![]);
        let _d_b2 = Daemon::start(dir_b2, BIN, "B2", Some(port_b2), vec![]);
        let _guard_h2 = spawn_tagged_claude(
            &_d_h2.dir,
            "97777777-7777-4777-8777-777777777771",
            &["h2.only.tag"],
            None,
        );
        let _guard_b = spawn_tagged_claude(
            &_d_b.dir,
            "97777777-7777-4777-8777-777777777777",
            &["excluded.tag"],
            None,
        );
        let _guard_b2 = spawn_tagged_claude(
            &_d_b2.dir,
            "97777777-7777-4777-8777-777777777778",
            &["excluded2.tag"],
            None,
        );
        let (_, h2_list) = http_get(&_d_h2.dir.http_sock, "/v1/recipients?tag=excluded.tag");
        assert_eq!(
            h2_list["total"], 0,
            "O1g: H2 must not see B holder excluded by targets: {h2_list}"
        );
        assert_eq!(
            h2_list["coverage"]["complete"], false,
            "O1g: B2 without list allow makes coverage incomplete: {h2_list}"
        );
        assert_eq!(
            h2_list["coverage"]["unanswered"],
            json!(["B2"]),
            "O1g: B2 without list allow must appear in unanswered (and B must not): {h2_list}"
        );
        let (_, h2_list2) = http_get(&_d_h2.dir.http_sock, "/v1/recipients?tag=excluded2.tag");
        assert_eq!(
            h2_list2["total"], 0,
            "O1g: H2 must not see B2 holder without list allow: {h2_list2}"
        );
        // Positive control on B's own allow=["list"] towards H2
        let (_, b_list) = http_get(&_d_b.dir.http_sock, "/v1/recipients?tag=h2.only.tag");
        assert_eq!(
            b_list["total"], 1,
            "O1g: B with allow=[list] sees H2 holder: {b_list}"
        );
    }
}

#[test]
fn o6_limits_and_o7_refusals() {
    let dir = NodeDir::new("p1lim");
    let d = Daemon::start(dir, BIN, "N", None, vec![]);

    // O7: read_only=true&tag=x -> bad_request
    let (st, body) = http_get(&d.dir.http_sock, "/v1/recipients?read_only=true&tag=x");
    assert_eq!(st, 400, "O7 read_only+tag must be 400: {body}");
    assert_eq!(body["error"], "bad_request");

    // O7: status=inactive&tag=x -> bad_request
    let (st, body) = http_get(&d.dir.http_sock, "/v1/recipients?status=inactive&tag=x");
    assert_eq!(st, 400, "O7 inactive+tag must be 400: {body}");
    assert_eq!(body["error"], "bad_request");

    // O4e: list() without tag has no coverage field
    let (st, body) = http_get(&d.dir.http_sock, "/v1/recipients");
    assert_eq!(st, 200);
    assert!(
        body.get("coverage").is_none(),
        "O4e unexpected coverage: {body}"
    );

    // O4e with tag has coverage
    let (st, body) = http_get(&d.dir.http_sock, "/v1/recipients?tag=nonexistent");
    assert_eq!(st, 200);
    assert_eq!(body["coverage"]["complete"], true);

    // O6: invalid tag names (including uppercase after first byte)
    for bad in [
        "Orch", "aB", "orchA", "a b", "a@b", "a/b", "a:b", ".a", "", "é",
    ] {
        assert!(
            xmsg::session_context::validate_tag(bad).is_err(),
            "O6: '{bad}' should be rejected"
        );
    }
    let s65 = "a".repeat(65);
    assert!(
        xmsg::session_context::validate_tag(&s65).is_err(),
        "O6: 65 bytes rejected"
    );
    assert!(xmsg::session_context::validate_tag("orchestrator.den-ag-design").is_ok());
    let s64 = "a".repeat(64);
    assert!(xmsg::session_context::validate_tag(&s64).is_ok());
}

#[test]
fn o2_self_only_and_codes() {
    if p1pz_child_mode_if_requested() {
        return;
    }
    let dir = NodeDir::new("p1o2");
    let d = Daemon::start(dir, BIN, "N", None, vec![]);

    // O2a: agent.sock tag with session_id or as_agent -> bad_request naming the field
    let r1 = call_agent(
        &d.dir.agent_sock,
        &json!({ "action": "tag", "add": "t", "session_id": "abc" }),
    );
    assert_eq!(r1["error"], "bad_request");
    assert!(
        r1["detail"].as_str().unwrap().contains("session_id"),
        "{r1}"
    );

    let r2 = call_agent(
        &d.dir.agent_sock,
        &json!({ "action": "tag", "add": "t", "as_agent": "abc" }),
    );
    assert_eq!(r2["error"], "bad_request");
    assert!(r2["detail"].as_str().unwrap().contains("as_agent"), "{r2}");

    // O2b: CLI without session ancestry -> denied
    let out = d.dir.cmd(BIN).args(["tag", "add", "t"]).output().unwrap();
    assert!(!out.status.success(), "O2b untraced CLI must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("denied"),
        "O2b expected denied, got: {stderr}"
    );

    // O2g: MCP tag(add, remove), tag(), tag(from) -> tool error
    let resps = call_mcp_tools(
        &d.dir,
        &[
            json!({ "name": "tag", "arguments": { "add": "a", "remove": "b" } }),
            json!({ "name": "tag", "arguments": {} }),
            json!({ "name": "tag", "arguments": { "add": "a", "from": "other" } }),
        ],
        &[],
    );
    for r in resps {
        assert_eq!(r["result"]["isError"], true, "O2g expected tool error: {r}");
    }

    // O2c: pi foreign sessionId -> denied
    let mut pi_sock = UnixStream::connect(&d.dir.register_sock).unwrap();
    pi_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(
        pi_sock,
        "{}",
        json!({ "harness": "pi", "sessionName": "p1" })
    )
    .unwrap();
    let mut pi_reader = BufReader::new(pi_sock.try_clone().unwrap());
    let mut reg_line = String::new();
    pi_reader.read_line(&mut reg_line).unwrap();
    let reg_v: Value = serde_json::from_str(&reg_line).unwrap();
    assert_eq!(reg_v["status"], "ok", "pi register: {reg_v}");

    writeln!(
        pi_sock,
        "{}",
        json!({ "action": "tag", "sessionId": "foreign-id", "add": "t" })
    )
    .unwrap();
    let mut tag_line = String::new();
    pi_reader.read_line(&mut tag_line).unwrap();
    let tag_v: Value = serde_json::from_str(&tag_line).unwrap();
    assert_eq!(tag_v["error"], "denied", "O2c expected denied: {tag_v}");

    // O2d: plugin Tag for unheld session -> denied
    let mut pl_sock = UnixStream::connect(&d.dir.register_sock).unwrap();
    pl_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(pl_sock, "{}", json!({ "harness": "opencode" })).unwrap();
    let mut pl_reader = BufReader::new(pl_sock.try_clone().unwrap());
    let mut pl_line = String::new();
    pl_reader.read_line(&mut pl_line).unwrap();
    writeln!(
        pl_sock,
        "{}",
        json!({ "action": "tag", "request_id": "r1", "session": "not-held", "add": "t" })
    )
    .unwrap();
    let mut pl_tag = String::new();
    pl_reader.read_line(&mut pl_tag).unwrap();
    let pl_v: Value = serde_json::from_str(&pl_tag).unwrap();
    assert_eq!(pl_v["error"], "denied", "O2d expected denied: {pl_v}");

    // O2f + O1h: xmsg tag add/remove as child of Claude fixture session (add two, remove one, keep one)
    let id_c = "55555555-5555-4555-8555-555555555555";
    let script = format!(
        "read _; {BIN} list --json >/dev/null; {BIN} tag add my.tag --json; {BIN} tag add keep.tag --json; {BIN} tag remove my.tag --json"
    );
    let mut sh = d.dir.cmd("sh");
    sh.args(["-c", &script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = sh.spawn().unwrap();
    write_claude_session_file(&d.dir, child.id(), id_c);
    {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "go").unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "O2f/O1h failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<Value> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        lines.len(),
        3,
        "expected two adds and one remove JSON outputs: {stdout}"
    );
    assert_eq!(lines[0]["tags"], json!(["my.tag"]));
    assert_eq!(lines[1]["tags"], json!(["keep.tag", "my.tag"]));
    assert_eq!(lines[2]["tags"], json!(["keep.tag"]));

    // O2e: unregistered agy session (real agy fixture without register agy) -> denied
    {
        let self_exe = std::env::current_exe().unwrap();
        let dir_unreg = NodeDir::new("p1o2eagy");
        let agy_unreg_bin = dir_unreg.run.join("agy-unreg-fixture");
        copy_exe_fixture(&self_exe, &agy_unreg_bin);
        let d_unreg = Daemon::start(
            dir_unreg,
            BIN,
            "AGYU",
            None,
            vec!["--agy-exe".into(), agy_unreg_bin.display().to_string()],
        );
        let unreg_id = "98888888-8888-4888-8888-888888888888";
        let lock_dir = d_unreg.dir.run.join("agy-presence");
        fs::create_dir_all(&lock_dir).unwrap();
        let out = d_unreg
            .dir
            .cmd(agy_unreg_bin.to_str().unwrap())
            .args(["--exact", "o2_self_only_and_codes", "--nocapture"])
            .env("XMSG_P1PZ_CHILD_MODE", "agy-unreg")
            .env(
                "XMSG_P1PZ_LOCK_PATH",
                lock_dir.join(format!("{unreg_id}.lock")),
            )
            .env("ANTIGRAVITY_CONVERSATION_ID", unreg_id)
            .env("ANTIGRAVITY_LS_ADDRESS", "127.0.0.1:33397")
            .env("ANTIGRAVITY_CSRF_TOKEN", "csrf-unreg")
            .output()
            .unwrap();
        assert!(!out.status.success(), "O2e unregistered agy tag must fail");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.contains("denied") || combined.contains("requires"),
            "O2e expected denied from unregistered agy fixture: {combined}"
        );
    }

    // O2b svc arm: registered svc calling agent.sock tag -> denied
    let self_exe = std::env::current_exe().unwrap();
    let dir_svc = NodeDir::new("p1o2svc");
    let _d_svc = Daemon::start(
        dir_svc,
        BIN,
        "SVC",
        None,
        vec!["--svc-exe".into(), format!("bridge={}", self_exe.display())],
    );
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let _reg = RegisteredService::register(ClientOptions {
            register_socket: _d_svc.dir.register_sock.clone(),
            agent_socket: _d_svc.dir.agent_sock.clone(),
            max_frame_bytes: 400_000,
            operation_timeout: Duration::from_secs(5),
            service: "bridge".into(),
            expected_node: None,
            daemon_uid: unsafe { libc::geteuid() },
        })
        .await
        .unwrap();
        let svc_r = call_agent(
            &_d_svc.dir.agent_sock,
            &json!({ "action": "tag", "add": "t" }),
        );
        assert_eq!(
            svc_r["error"], "denied",
            "O2b svc arm expected denied: {svc_r}"
        );
    });
}

#[test]
fn o3_lifecycle_claude_pi_plugin_and_o5c_o5d() {
    let dir = NodeDir::new("p1o3");
    let mut d = Daemon::start(dir, BIN, "N", None, vec![]);

    // O3c: pi session adds tag, daemon restarts, re-registers -> empty before re-add, re-add succeeds
    {
        let mut pi_sock = UnixStream::connect(&d.dir.register_sock).unwrap();
        pi_sock
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        writeln!(
            pi_sock,
            "{}",
            json!({ "harness": "pi", "sessionName": "p1" })
        )
        .unwrap();
        let mut r = BufReader::new(pi_sock.try_clone().unwrap());
        let mut l = String::new();
        r.read_line(&mut l).unwrap();
        writeln!(pi_sock, "{}", json!({ "action": "tag", "add": "pi.tag" })).unwrap();
        l.clear();
        r.read_line(&mut l).unwrap();
        let v: Value = serde_json::from_str(&l).unwrap();
        assert_eq!(v["status"], "ok", "pi tag add: {v}");
        assert_eq!(v["tags"], json!(["pi.tag"]));

        let (_, list_v) = http_get(&d.dir.http_sock, "/v1/recipients?tag=pi.tag");
        assert_eq!(list_v["total"], 1);
    }

    // O3d: opencode plugin adds 8 tags, daemon restarts, reclaims -> tags == [], re-adding 8 succeeds, 9th refused
    {
        let mut pl = UnixStream::connect(&d.dir.register_sock).unwrap();
        pl.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        writeln!(pl, "{}", json!({ "harness": "opencode" })).unwrap();
        let mut r = BufReader::new(pl.try_clone().unwrap());
        let mut l = String::new();
        r.read_line(&mut l).unwrap();
        writeln!(
            pl,
            "{}",
            json!({ "action": "register", "request_id": "1", "session": "oc1" })
        )
        .unwrap();
        l.clear();
        r.read_line(&mut l).unwrap();
        let reg: Value = serde_json::from_str(&l).unwrap();
        let reclaim_token = json!({
            "id": reg["address"],
            "secret": reg["reclaim"],
        });

        for i in 0..8 {
            writeln!(
                pl,
                "{}",
                json!({ "action": "tag", "request_id": format!("t{i}"), "session": "oc1", "add": format!("tag.{i}") })
            )
            .unwrap();
            l.clear();
            r.read_line(&mut l).unwrap();
            let tv: Value = serde_json::from_str(&l).unwrap();
            assert_eq!(tv["status"], "ok", "plugin tag {i}: {tv}");
        }
        // O5c: plugin List with tag
        writeln!(
            pl,
            "{}",
            json!({ "action": "list", "request_id": "l1", "session": "oc1", "tag": "tag.3" })
        )
        .unwrap();
        l.clear();
        r.read_line(&mut l).unwrap();
        let lv: Value = serde_json::from_str(&l).unwrap();
        assert_eq!(lv["total"], 1, "O5c plugin list by tag: {lv}");

        // Restart daemon
        d.stop();
        d.spawn(BIN);

        let mut pl2 = UnixStream::connect(&d.dir.register_sock).unwrap();
        pl2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        writeln!(pl2, "{}", json!({ "harness": "opencode" })).unwrap();
        let mut r2 = BufReader::new(pl2.try_clone().unwrap());
        let mut l2 = String::new();
        r2.read_line(&mut l2).unwrap();
        writeln!(
            pl2,
            "{}",
            json!({ "action": "register", "request_id": "1", "session": "oc1", "reclaim": reclaim_token })
        )
        .unwrap();
        l2.clear();
        r2.read_line(&mut l2).unwrap();
        let reg2: Value = serde_json::from_str(&l2).unwrap();
        assert_eq!(reg2["status"], "ok", "O3d reclaim: {reg2}");

        let (_, after) = http_get(&d.dir.http_sock, "/v1/recipients?tag=tag.0");
        assert_eq!(
            after["total"], 0,
            "O3d tags must be cleared on restart: {after}"
        );
        let (_, pi_after) = http_get(&d.dir.http_sock, "/v1/recipients?tag=pi.tag");
        assert_eq!(
            pi_after["total"], 0,
            "O3c pi tags must be cleared on restart: {pi_after}"
        );

        for i in 0..8 {
            writeln!(
                pl2,
                "{}",
                json!({ "action": "tag", "request_id": format!("rt{i}"), "session": "oc1", "add": format!("tag.{i}") })
            )
            .unwrap();
            l2.clear();
            r2.read_line(&mut l2).unwrap();
            let tv: Value = serde_json::from_str(&l2).unwrap();
            assert_eq!(tv["status"], "ok", "O3d re-add {i}: {tv}");
        }
        writeln!(
            pl2,
            "{}",
            json!({ "action": "tag", "request_id": "rt8", "session": "oc1", "add": "tag.8" })
        )
        .unwrap();
        l2.clear();
        r2.read_line(&mut l2).unwrap();
        let ninth: Value = serde_json::from_str(&l2).unwrap();
        assert_eq!(
            ninth["error"], "bad_request",
            "O3d 9th tag refused: {ninth}"
        );
    }

    // O5d: AgentClient::list against new daemon
    let self_exe = std::env::current_exe().unwrap();
    d.stop();
    d.extra_args = vec!["--svc-exe".into(), format!("bridge={}", self_exe.display())];
    d.spawn(BIN);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let reg = RegisteredService::register(ClientOptions {
            register_socket: d.dir.register_sock.clone(),
            agent_socket: d.dir.agent_sock.clone(),
            max_frame_bytes: 400_000,
            operation_timeout: Duration::from_secs(5),
            service: "bridge".into(),
            expected_node: None,
            daemon_uid: unsafe { libc::geteuid() },
        })
        .await
        .unwrap();
        let res = reg
            .list(ListQuery {
                tag: Some("tag.0".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(res.total, 0);
        assert!(res.coverage.is_some());
        assert!(res.coverage.unwrap().complete);
    });
}

fn copy_exe_fixture(src: &Path, dst: &Path) {
    let st = std::process::Command::new("sh")
        .args([
            "-c",
            "cp \"$1\" \"$2\" && chmod 0755 \"$2\"",
            "_",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(st.success(), "copy_exe_fixture failed: {st}");
}

fn p1pz_child_mode_if_requested() -> bool {
    let Ok(mode) = std::env::var("XMSG_P1PZ_CHILD_MODE") else {
        return false;
    };
    let lock_path = std::env::var("XMSG_P1PZ_LOCK_PATH").unwrap();
    use std::os::unix::io::AsRawFd;
    let _lock_file = {
        let f = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .unwrap();
        let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(
            rc,
            0,
            "child flock failed on {lock_path}: {}",
            std::io::Error::last_os_error()
        );
        f
    };
    match mode.as_str() {
        "codex" => {
            let root_id = std::env::var("XMSG_P1PZ_ROOT_ID").unwrap();
            let source = std::env::var("XMSG_P1PZ_SOURCE").unwrap();
            let cwd = std::env::var("XMSG_P1PZ_CWD").unwrap();
            let sock = std::env::var("XMSG_AGENT_SOCK").unwrap();
            let hook = json!({
                "session_id": root_id,
                "cwd": cwd,
                "hook_event_name": "SessionStart",
                "source": source,
            });
            let mut reg = std::process::Command::new(BIN)
                .args([
                    "register",
                    "codex",
                    "--hook",
                    "--event",
                    "SessionStart",
                    "--sock",
                    &sock,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            writeln!(reg.stdin.take().unwrap(), "{hook}").unwrap();
            let reg_out = reg.wait_with_output().unwrap();
            assert!(reg_out.status.success(), "codex register failed");
            let reg_err = String::from_utf8_lossy(&reg_out.stderr).replace('\n', " ");
            println!("REGISTERED:{reg_err}");

            // Read commands on stdin: "tag <name>" or "quit"
            let stdin = std::io::stdin();
            for line in BufReader::new(stdin.lock()).lines() {
                let cmd = line.unwrap();
                let cmd = cmd.trim();
                if cmd == "quit" {
                    break;
                }
                if let Some(tag) = cmd.strip_prefix("tag ") {
                    let db = std::env::var("XMSG_DB_PATH").unwrap();
                    let http = std::env::var("XMSG_HTTP_SOCK").unwrap();
                    let mut mcp = std::process::Command::new(BIN)
                        .args([
                            "mcp",
                            "--db-path",
                            &db,
                            "--agent-sock",
                            &sock,
                            "--http-sock",
                            &http,
                        ])
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::null())
                        .spawn()
                        .unwrap();
                    let mut min = mcp.stdin.take().unwrap();
                    writeln!(
                        min,
                        "{}",
                        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"codex","version":"1"}}})
                    ).unwrap();
                    writeln!(
                        min,
                        "{}",
                        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tag","arguments":{"add":tag},"_meta":{"sessionId":root_id,"threadId":root_id,"turnId":"t1"}}})
                    ).unwrap();
                    drop(min);
                    let mout = mcp.wait_with_output().unwrap();
                    let mstdout = String::from_utf8_lossy(&mout.stdout).replace('\n', " ");
                    println!("TAGGED:{mstdout}");
                }
            }
        }
        "agy-unreg" => {
            let tag_out = std::process::Command::new(BIN)
                .args(["tag", "add", "t", "--json"])
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&tag_out.stdout);
            let stderr = String::from_utf8_lossy(&tag_out.stderr);
            eprint!("{stderr}");
            print!("{stdout}");
            std::process::exit(if tag_out.status.success() { 0 } else { 1 });
        }
        "agy" => {
            let reg_sock = std::env::var("XMSG_REGISTER_SOCK").unwrap();
            let reg_out = std::process::Command::new(BIN)
                .args(["register", "agy", "--sock", &reg_sock])
                .output()
                .unwrap();
            assert!(
                reg_out.status.success(),
                "register agy failed: {}",
                String::from_utf8_lossy(&reg_out.stderr)
            );
            if let Ok(tag) = std::env::var("XMSG_P1PZ_TAG") {
                let tag_out = std::process::Command::new(BIN)
                    .args(["tag", "add", &tag, "--json"])
                    .output()
                    .unwrap();
                assert!(
                    tag_out.status.success(),
                    "agy tag add failed: {}",
                    String::from_utf8_lossy(&tag_out.stderr)
                );
            }
            println!("AGY_READY");
            let mut buf = String::new();
            let _ = std::io::stdin().read_line(&mut buf);
        }
        other => panic!("unknown XMSG_P1PZ_CHILD_MODE={other}"),
    }
    true
}

#[test]
fn o3_claude_codex_agy_holders_and_lifecycle() {
    if p1pz_child_mode_if_requested() {
        return;
    }
    let dir = NodeDir::new("p1ccal");
    // Copy the test binary itself (real native ELF/Mach-O executable) to distinct fixture names.
    let self_exe = std::env::current_exe().unwrap();
    let codex_bin = dir.run.join("codex-fixture");
    copy_exe_fixture(&self_exe, &codex_bin);
    let agy_bin = dir.run.join("agy-fixture");
    copy_exe_fixture(&self_exe, &agy_bin);

    let codex_home = dir.run.join("codex-home");
    let sessions_dir = codex_home.join("sessions/2026/11/24");
    fs::create_dir_all(&sessions_dir).unwrap();

    let mut d = Daemon::start(
        dir,
        BIN,
        "N",
        None,
        vec![
            "--codex-exe".into(),
            codex_bin.display().to_string(),
            "--codex-home".into(),
            codex_home.display().to_string(),
            "--agy-exe".into(),
            agy_bin.display().to_string(),
        ],
    );

    // 1. O3a + O3b: Claude healthy daemon restart keeps tags; re-adding held tag succeeds (X18); re-claim drops them.
    let id_cl = "91111111-1111-4111-8111-111111111111";
    let mut sh_cl = d.dir.cmd("sh");
    sh_cl
        .args([
            "-c",
            &format!(
                "set -e; read _; {BIN} list --json >/dev/null; {BIN} tag add claude.keep --json >/dev/null; echo READY; read _; {BIN} tag add claude.keep --json; echo READD_DONE; read _"
            ),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child_cl = sh_cl.spawn().unwrap();
    write_claude_session_file(&d.dir, child_cl.id(), id_cl);
    let mut cl_in = child_cl.stdin.take().unwrap();
    let mut cl_out = BufReader::new(child_cl.stdout.take().unwrap());
    writeln!(cl_in, "go").unwrap();
    let mut ready_cl = String::new();
    cl_out.read_line(&mut ready_cl).unwrap();
    assert_eq!(ready_cl.trim(), "READY");

    // Healthy restart while Claude process is still alive
    d.stop();
    d.spawn(BIN);
    let (_, cl_after_restart) = http_get(&d.dir.http_sock, "/v1/recipients?tag=claude.keep");
    assert_eq!(
        cl_after_restart["total"], 1,
        "O3a: healthy restart must keep Claude tags: {cl_after_restart}"
    );
    // O3a (X18): re-adding an already-held tag succeeds idempotently with one row
    writeln!(cl_in, "readd").unwrap();
    let mut readd_json_line = String::new();
    cl_out.read_line(&mut readd_json_line).unwrap();
    let readd_v: Value = serde_json::from_str(&readd_json_line).expect("O3a readd json");
    assert_eq!(
        readd_v["tags"],
        json!(["claude.keep"]),
        "O3a re-add held tag: {readd_v}"
    );
    let mut readd_done = String::new();
    cl_out.read_line(&mut readd_done).unwrap();
    assert_eq!(readd_done.trim(), "READD_DONE");

    // O3b: New Claude process re-claims the same id -> old tag dropped
    writeln!(cl_in, "bye").unwrap();
    let _ = child_cl.wait();
    let mut sh_reclaim = d.dir.cmd("sh");
    sh_reclaim
        .args([
            "-c",
            &format!("read _; {BIN} list --json >/dev/null; echo READY; read _"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child_reclaim = sh_reclaim.spawn().unwrap();
    write_claude_session_file(&d.dir, child_reclaim.id(), id_cl);
    let mut r_in = child_reclaim.stdin.take().unwrap();
    let mut r_out = BufReader::new(child_reclaim.stdout.take().unwrap());
    writeln!(r_in, "go").unwrap();
    let mut ready_line = String::new();
    r_out.read_line(&mut ready_line).unwrap();
    assert_eq!(ready_line.trim(), "READY");

    let (_, cl_after_reclaim) = http_get(&d.dir.http_sock, "/v1/recipients?tag=claude.keep");
    assert_eq!(
        cl_after_reclaim["total"], 0,
        "O3b: re-claim must drop old Claude tags: {cl_after_reclaim}"
    );
    writeln!(r_in, "bye").unwrap();
    let _ = child_reclaim.wait();

    let codex_root = "92222222-2222-4222-8222-222222222222";
    let lock_dir = codex_home.join("thread-writer-locks");
    fs::create_dir_all(&lock_dir).unwrap();
    let lock_path = lock_dir.join(format!("{codex_root}.lock"));
    let rollout_path = sessions_dir.join(format!("rollout-2026-11-24T00-00-00-{codex_root}.jsonl"));
    let meta_line = json!({
        "timestamp": "2026-11-24T00:00:00Z",
        "type": "session_meta",
        "payload": { "id": codex_root, "session_id": codex_root, "cwd": d.dir.run.display().to_string() }
    });
    fs::write(&rollout_path, format!("{meta_line}\n")).unwrap();

    // Negative control: unattested daemon without --codex-exe denies registration
    {
        let dir_unatt = NodeDir::new("p1cxunatt");
        let d_unatt = Daemon::start(dir_unatt, BIN, "UNATT", None, vec![]);
        let hook = json!({
            "session_id": codex_root,
            "cwd": d_unatt.dir.run.display().to_string(),
            "hook_event_name": "SessionStart",
            "source": "startup",
        });
        let mut reg = d_unatt.dir.cmd(BIN);
        reg.args([
            "register",
            "codex",
            "--hook",
            "--event",
            "SessionStart",
            "--sock",
            &d_unatt.dir.agent_sock.display().to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        let mut child = reg.spawn().unwrap();
        writeln!(child.stdin.take().unwrap(), "{hook}").unwrap();
        let out = child.wait_with_output().unwrap();
        let err_s = String::from_utf8_lossy(&out.stderr);
        assert!(
            err_s.contains("does not descend from a trusted --codex-exe process"),
            "negative control must deny unattested codex hook: {err_s}"
        );
    }

    let spawn_codex_owner = |d: &Daemon, source: &str| {
        let mut cmd = d.dir.cmd(codex_bin.to_str().unwrap());
        cmd.args([
            "--exact",
            "o3_claude_codex_agy_holders_and_lifecycle",
            "--nocapture",
        ])
        .env("XMSG_P1PZ_CHILD_MODE", "codex")
        .env("XMSG_P1PZ_LOCK_PATH", &lock_path)
        .env("XMSG_P1PZ_ROOT_ID", codex_root)
        .env("XMSG_P1PZ_SOURCE", source)
        .env("XMSG_P1PZ_CWD", &d.dir.run)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut lines = Vec::new();
        let reg_line = loop {
            let mut l = String::new();
            let n = out.read_line(&mut l).unwrap();
            assert!(n > 0, "codex-fixture EOF before REGISTERED: {lines:?}");
            if l.starts_with("REGISTERED:") {
                break l;
            }
            lines.push(l);
        };
        assert_eq!(
            reg_line.trim(),
            "REGISTERED:",
            "positive codex registration must have no denial notice: {reg_line}"
        );
        (child, out)
    };

    let codex_tag = |cin: &mut std::process::ChildStdin,
                     cout: &mut BufReader<std::process::ChildStdout>,
                     tag: &str|
     -> String {
        writeln!(cin, "tag {tag}").unwrap();
        loop {
            let mut l = String::new();
            let n = cout.read_line(&mut l).unwrap();
            assert!(n > 0, "codex-fixture EOF before TAGGED for {tag}");
            if let Some(rest) = l.strip_prefix("TAGGED:") {
                return rest.to_string();
            }
        }
    };

    let (mut codex_p1, mut codex_out1) = spawn_codex_owner(&d, "startup");
    let mut codex_in1 = codex_p1.stdin.take().unwrap();
    for i in 0..8 {
        let t = format!("cx{i}");
        let resp = codex_tag(&mut codex_in1, &mut codex_out1, &t);
        assert!(
            resp.contains(&t) && !resp.contains("\"isError\":true"),
            "O3g initial tag {t} failed: {resp}"
        );
    }

    let (_, cx_list) = http_get(&d.dir.http_sock, "/v1/recipients?tag=cx0");
    assert_eq!(
        cx_list["total"], 1,
        "O1a codex holder must be listed: {cx_list}"
    );

    // Healthy restart keeps all 8 codex:1 tag rows in session_tag (precondition for O3g)
    d.stop();
    d.spawn(BIN);
    {
        let db = rusqlite::Connection::open(&d.dir.db).unwrap();
        let kept: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM session_tag WHERE id = ?1 AND harness = 'codex' AND reg = 'codex:1'",
                [codex_root],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            kept, 8,
            "O3g precondition: healthy restart must preserve all 8 codex:1 tag rows"
        );
    }

    // O3g + O3e: park (exit owner) and resume on new owner -> generation increments to codex:2;
    // none of the 8 old tags is listed; re-add "t" succeeds with tags == ["t"] (O3e); 8 fresh adds succeed and 9th is refused (O3g, kills M3-gen).
    writeln!(codex_in1, "quit").unwrap();
    drop(codex_in1);
    let _ = codex_p1.wait();
    let (mut codex_p2, mut codex_out2) = spawn_codex_owner(&d, "resume");
    let mut codex_in2 = codex_p2.stdin.take().unwrap();
    for i in 0..8 {
        let (_, cx_resumed) = http_get(&d.dir.http_sock, &format!("/v1/recipients?tag=cx{i}"));
        assert_eq!(
            cx_resumed["total"], 0,
            "O3g codex resume must drop old tag cx{i}: {cx_resumed}"
        );
    }
    let readd_t = codex_tag(&mut codex_in2, &mut codex_out2, "t");
    assert!(
        !readd_t.contains("\"isError\":true") && readd_t.contains("status\\\":\\\"ok\\\""),
        "O3e re-add 't' after resume must succeed: {readd_t}"
    );
    let (_, cx_t_list) = http_get(&d.dir.http_sock, "/v1/recipients?tag=t");
    assert_eq!(
        cx_t_list["total"], 1,
        "O3e: re-added 't' must be listed: {cx_t_list}"
    );
    assert_eq!(
        cx_t_list["recipients"][0]["tags"],
        json!(["t"]),
        "O3e: tags must be [\"t\"]: {cx_t_list}"
    );
    for i in 1..8 {
        let t = format!("r{i}");
        let resp = codex_tag(&mut codex_in2, &mut codex_out2, &t);
        assert!(
            resp.contains(&t) && !resp.contains("\"isError\":true"),
            "O3g fresh tag {t} after resume must succeed: {resp}"
        );
    }
    let ninth = codex_tag(&mut codex_in2, &mut codex_out2, "r8");
    assert!(
        ninth.contains("\"isError\":true")
            || ninth.contains("limit_exceeded")
            || ninth.contains("8"),
        "O3g 9th tag after resume must be refused: {ninth}"
    );
    writeln!(codex_in2, "quit").unwrap();
    drop(codex_in2);
    let _ = codex_p2.wait();

    // 3. O1a agy holder + O3f (agy takeover by new process drops old tags)
    let agy_id = "93333333-3333-4333-8333-333333333333";
    let agy_presence_dir = d.dir.run.join("agy-presence");
    fs::create_dir_all(&agy_presence_dir).unwrap();
    let agy_lock_path = agy_presence_dir.join(format!("{agy_id}.lock"));

    let spawn_agy_holder = |d: &Daemon, tag: Option<&str>| {
        let mut cmd = d.dir.cmd(agy_bin.to_str().unwrap());
        cmd.args([
            "--exact",
            "o3_claude_codex_agy_holders_and_lifecycle",
            "--nocapture",
        ])
        .env("XMSG_P1PZ_CHILD_MODE", "agy")
        .env("XMSG_P1PZ_LOCK_PATH", &agy_lock_path)
        .env("ANTIGRAVITY_CONVERSATION_ID", agy_id)
        .env("ANTIGRAVITY_LS_ADDRESS", "127.0.0.1:33399")
        .env("ANTIGRAVITY_CSRF_TOKEN", "csrf-agy-test")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        if let Some(t) = tag {
            cmd.env("XMSG_P1PZ_TAG", t);
        }
        let mut child = cmd.spawn().unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut l = String::new();
            let n = out.read_line(&mut l).unwrap();
            assert!(n > 0, "agy-fixture EOF before AGY_READY");
            if l.trim() == "AGY_READY" {
                break;
            }
        }
        child
    };

    let mut agy1 = spawn_agy_holder(&d, Some("agy.tag"));
    let (_, agy_list) = http_get(&d.dir.http_sock, "/v1/recipients?tag=agy.tag");
    assert_eq!(
        agy_list["total"], 1,
        "O1a agy holder must be listed: {agy_list}"
    );
    {
        let db = rusqlite::Connection::open(&d.dir.db).unwrap();
        let agy_rows: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM session_tag WHERE id = ?1 AND harness = 'agy' AND tag = 'agy.tag'",
                [agy_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            agy_rows, 1,
            "O3f precondition: session_tag row must exist before takeover"
        );
    }

    // O3f: agy takeover by new process -> drops old tag
    let _ = agy1.kill();
    let _ = agy1.wait();
    let mut agy2 = spawn_agy_holder(&d, None);
    let (_, agy_takeover) = http_get(&d.dir.http_sock, "/v1/recipients?tag=agy.tag");
    assert_eq!(
        agy_takeover["total"], 0,
        "O3f agy takeover drops old tag: {agy_takeover}"
    );
    let _ = agy2.kill();
    let _ = agy2.wait();
}

#[test]
#[ignore = "p1pz compat CI runs with XMSG_PREV_BIN=912ca97a"]
fn compat_912ca97a_oracles() {
    let prev =
        std::env::var("XMSG_PREV_BIN").expect("XMSG_PREV_BIN must point to 912ca97a xmsg binary");
    assert!(Path::new(&prev).exists(), "missing XMSG_PREV_BIN={prev}");

    // O5f: re-pinned AgentClient::list against old daemon succeeds
    let self_exe = std::env::current_exe().unwrap();
    let dir_old = NodeDir::new("p1old");
    let d_old = Daemon::start(
        dir_old,
        &prev,
        "OLD",
        None,
        vec![
            "--svc-exe".into(),
            format!("bridge={}", self_exe.display()),
            "--agy-exe".into(),
            self_exe.display().to_string(),
        ],
    );
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let reg = RegisteredService::register(ClientOptions {
            register_socket: d_old.dir.register_sock.clone(),
            agent_socket: d_old.dir.agent_sock.clone(),
            max_frame_bytes: 400_000,
            operation_timeout: Duration::from_secs(5),
            service: "bridge".into(),
            expected_node: None,
            daemon_uid: unsafe { libc::geteuid() },
        })
        .await
        .unwrap();
        let res = reg.list(ListQuery::default()).await.unwrap();
        assert!(res.coverage.is_none());
    });

    // O5h: new xmsg mcp plain list + HTTP fallback against old daemon succeeds; tag returns bad_request tool error
    let resps = call_mcp_tools(
        &d_old.dir,
        &[
            json!({ "name": "list", "arguments": {} }),
            json!({ "name": "tag", "arguments": { "add": "t" } }),
        ],
        &[],
    );
    assert_eq!(
        resps[0]["result"]["isError"], false,
        "O5h plain list: {}",
        resps[0]
    );
    assert_eq!(
        resps[1]["result"]["isError"], true,
        "O5h tag on old daemon: {}",
        resps[1]
    );

    // O5h HTTP fallback (agent.sock absent)
    let mut no_agent = NodeDir::new("p1noag");
    no_agent.http_sock = d_old.dir.http_sock.clone();
    no_agent.db = d_old.dir.db.clone();
    no_agent.agent_sock = no_agent.run.join("missing-agent.sock");
    let fb = call_mcp_tools(
        &no_agent,
        &[json!({ "name": "list", "arguments": {} })],
        &[],
    );
    assert_eq!(
        fb[0]["result"]["isError"], false,
        "O5h HTTP fallback: {}",
        fb[0]
    );

    // O4b: old direct peer of H -> tag_incapable, unanswered empty, complete == false
    let ca = TestCa::new();
    let dir_h = NodeDir::new("p1ch");
    let dir_p = NodeDir::new("p1cp");
    let port_h = free_port();
    let port_p = free_port();
    let pem_h = ca.issue("H", "alice", &dir_h);
    let pem_p = ca.issue("P", "alice", &dir_p);
    fs::write(
        &dir_h.peers,
        json!({ "P": { "name": "P", "pin": spki_pin(&pem_p), "address": format!("127.0.0.1:{port_p}"), "allow": ["list", "send", "reply"] } }).to_string(),
    ).unwrap();
    fs::write(
        &dir_p.peers,
        json!({ "H": { "name": "H", "pin": spki_pin(&pem_h), "address": format!("127.0.0.1:{port_h}"), "allow": ["list", "send", "reply"] } }).to_string(),
    ).unwrap();
    let _dh = Daemon::start(dir_h, BIN, "H", Some(port_h), vec![]);
    let _dp = Daemon::start(dir_p, &prev, "P", Some(port_p), vec![]);

    let (st, v) = http_get(&_dh.dir.http_sock, "/v1/recipients?tag=t");
    assert_eq!(st, 200, "O4b list(tag) on H: {v}");
    assert_eq!(v["coverage"]["complete"], false, "O4b complete: {v}");
    assert_eq!(
        v["coverage"]["unanswered"],
        json!([]),
        "O4b unanswered: {v}"
    );
    assert_eq!(
        v["coverage"]["tag_incapable"],
        json!(["P"]),
        "O4b tag_incapable: {v}"
    );

    let (st_p, vp) = http_get(&_dp.dir.http_sock, "/v1/recipients");
    assert_eq!(st_p, 200, "O4b old peer's own list of H: {vp}");

    // Also keep ClientError import used for O5d/O5f
    let _ = std::any::type_name::<ClientError>();

    // O4c: old dial-out leaf of H -> tag_incapable, unanswered empty, complete == false; old leaf's list of H succeeds
    {
        let ca2 = TestCa::new();
        let dir_h2 = NodeDir::new("p1c4h");
        let dir_l2 = NodeDir::new("p1c4l");
        let port_h2 = free_port();
        let pem_h2 = ca2.issue("H", "alice", &dir_h2);
        let pem_l2 = ca2.issue("L", "alice", &dir_l2);
        fs::write(
            &dir_h2.peers,
            json!({ "L": { "name": "L", "pin": spki_pin(&pem_l2), "leaf": true, "allow": ["list", "send", "reply"] } }).to_string(),
        ).unwrap();
        fs::write(
            &dir_l2.peers,
            json!({ "H": { "name": "H", "pin": spki_pin(&pem_h2), "address": format!("127.0.0.1:{port_h2}"), "dial": "outbound", "allow": ["list", "send", "reply"] } }).to_string(),
        ).unwrap();
        let _dh2 = Daemon::start(dir_h2, BIN, "H", Some(port_h2), vec![]);
        let _dl2 = Daemon::start(dir_l2, &prev, "L", None, vec![]);
        let (st_h, vh) = http_get(&_dh2.dir.http_sock, "/v1/recipients?tag=t");
        assert_eq!(st_h, 200, "O4c list(tag) on H: {vh}");
        assert_eq!(vh["coverage"]["complete"], false, "O4c complete: {vh}");
        assert_eq!(
            vh["coverage"]["unanswered"],
            json!([]),
            "O4c unanswered: {vh}"
        );
        assert_eq!(
            vh["coverage"]["tag_incapable"],
            json!(["L"]),
            "O4c tag_incapable: {vh}"
        );
        let (st_l, vl) = http_get(&_dl2.dir.http_sock, "/v1/recipients");
        assert_eq!(st_l, 200, "O4c old leaf list of H: {vl}");
    }

    // O4f: old hub, new dial-out leaf -> hub's list shows leaf ok
    {
        let ca3 = TestCa::new();
        let dir_h3 = NodeDir::new("p1c4fh");
        let dir_l3 = NodeDir::new("p1c4fl");
        let port_h3 = free_port();
        let pem_h3 = ca3.issue("H", "alice", &dir_h3);
        let pem_l3 = ca3.issue("L", "alice", &dir_l3);
        fs::write(
            &dir_h3.peers,
            json!({ "L": { "name": "L", "pin": spki_pin(&pem_l3), "leaf": true, "allow": ["list", "send", "reply"] } }).to_string(),
        ).unwrap();
        fs::write(
            &dir_l3.peers,
            json!({ "H": { "name": "H", "pin": spki_pin(&pem_h3), "address": format!("127.0.0.1:{port_h3}"), "dial": "outbound", "allow": ["list", "send", "reply"] } }).to_string(),
        ).unwrap();
        let _dh3 = Daemon::start(dir_h3, &prev, "H", Some(port_h3), vec![]);
        let _dl3 = Daemon::start(dir_l3, BIN, "L", None, vec![]);
        let (st_h, vh) = http_get(&_dh3.dir.http_sock, "/v1/recipients");
        assert_eq!(st_h, 200, "O4f old hub list: {vh}");
        assert!(
            vh["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|n| n["node"] == "L" && n["status"] == "ok"),
            "O4f leaf ok on old hub: {vh}"
        );
    }

    // O5e + O5g: old xmsg mcp against new daemon with tagged holder fails ("invalid list response"),
    // untagged succeeds; old & new xmsg watch both decode.
    {
        let dir_n = NodeDir::new("p1o5eg");
        let dn = Daemon::start(dir_n, BIN, "N", None, vec![]);
        // Untagged: old MCP list succeeds
        let mut old_mcp_cmd = dn.dir.cmd(&prev);
        old_mcp_cmd
            .args(["mcp", "--db-path", &dn.dir.db.display().to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = old_mcp_cmd.spawn().unwrap();
        {
            let mut stdin = child.stdin.take().unwrap();
            writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}})).unwrap();
            writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list","arguments":{}}})).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let resp: Value = stdout
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|v| v["id"] == 2)
            .unwrap();
        assert_eq!(resp["result"]["isError"], false, "O5e(ii) untagged: {resp}");

        // Now add a tagged Claude holder
        let _g = spawn_tagged_claude(
            &dn.dir,
            "88888888-8888-4888-8888-888888888888",
            &["t.o5e"],
            None,
        );

        // O5e(i): old MCP list fails ("invalid list response")
        let mut old_mcp_cmd2 = dn.dir.cmd(&prev);
        old_mcp_cmd2
            .args(["mcp", "--db-path", &dn.dir.db.display().to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child2 = old_mcp_cmd2.spawn().unwrap();
        {
            let mut stdin = child2.stdin.take().unwrap();
            writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}})).unwrap();
            writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list","arguments":{}}})).unwrap();
        }
        let out2 = child2.wait_with_output().unwrap();
        let stdout2 = String::from_utf8_lossy(&out2.stdout);
        let resp2: Value = stdout2
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|v| v["id"] == 2)
            .unwrap();
        assert_eq!(
            resp2["result"]["isError"], true,
            "O5e(i) tagged must fail old MCP: {resp2}"
        );

        // O5g: old and new xmsg watch --once both succeed against tagged daemon
        let w_old = dn
            .dir
            .cmd(&prev)
            .args(["watch", "--once"])
            .output()
            .unwrap();
        assert!(
            w_old.status.success(),
            "O5g old watch failed: {}",
            String::from_utf8_lossy(&w_old.stderr)
        );
        let w_new = dn.dir.cmd(BIN).args(["watch", "--once"]).output().unwrap();
        assert!(
            w_new.status.success(),
            "O5g new watch failed: {}",
            String::from_utf8_lossy(&w_new.stderr)
        );
    }

    // O5h: new xmsg mcp under real Claude and agy fixture sessions against old daemon (912ca97a):
    // assert startup & background worker mcp_start are accepted (status == "ok", not bad_request)
    // and the held connection persists for 10 s against 912ca97a (kills X14).
    {
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        };
        let id_cl_old = "94444444-4444-4444-8444-444444444444";
        let spy_sock = d_old.dir.run.join("spy-agent.sock");
        let real_agent_sock = d_old.dir.agent_sock.clone();
        let spy_listener = std::os::unix::net::UnixListener::bind(&spy_sock).unwrap();
        spy_listener.set_nonblocking(true).unwrap();
        let stop_spy = Arc::new(AtomicBool::new(false));
        let stop_spy_bg = Arc::clone(&stop_spy);
        let ok_count = Arc::new(AtomicUsize::new(0));
        let ok_count_bg = Arc::clone(&ok_count);
        let spy_handle = std::thread::spawn(move || {
            let mut conns = Vec::new();
            while !stop_spy_bg.load(Ordering::Relaxed) {
                match spy_listener.accept() {
                    Ok((mut client, _)) => {
                        let upstream_sock = real_agent_sock.clone();
                        let ok_c = Arc::clone(&ok_count_bg);
                        conns.push(std::thread::spawn(move || {
                            let mut upstream = UnixStream::connect(&upstream_sock).unwrap();
                            let mut cr = BufReader::new(client.try_clone().unwrap());
                            let mut ur = BufReader::new(upstream.try_clone().unwrap());
                            let mut req_line = String::new();
                            if cr.read_line(&mut req_line).unwrap_or(0) == 0 {
                                return;
                            }
                            upstream.write_all(req_line.as_bytes()).unwrap();
                            upstream.flush().unwrap();
                            let mut resp_line = String::new();
                            if ur.read_line(&mut resp_line).unwrap_or(0) == 0 {
                                return;
                            }
                            let _ = client.write_all(resp_line.as_bytes());
                            let _ = client.flush();
                            let resp_v: Value = serde_json::from_str(&resp_line).unwrap();
                            assert_ne!(
                                resp_v.get("error").and_then(Value::as_str),
                                Some("bad_request"),
                                "O5h: 912ca97a daemon must not reject mcp_start as bad_request: req={req_line} resp={resp_v}"
                            );
                            if resp_v.get("error").is_none() {
                                ok_c.fetch_add(1, Ordering::Relaxed);
                            }
                            // Relay any held-connection traffic until EOF
                            let mut up2 = upstream.try_clone().unwrap();
                            let mut cl2 = client.try_clone().unwrap();
                            let t1 = std::thread::spawn(move || {
                                let _ = std::io::copy(&mut cr, &mut up2);
                                let _ = up2.shutdown(std::net::Shutdown::Write);
                            });
                            let _ = std::io::copy(&mut ur, &mut cl2);
                            let _ = cl2.shutdown(std::net::Shutdown::Write);
                            let _ = t1.join();
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
            for h in conns {
                h.join().unwrap();
            }
        });

        let mcp_script = format!(
            "read _; {BIN} list --json >/dev/null 2>&1; (echo '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"claude\",\"version\":\"1\"}}}}}}'; sleep 12) | {BIN} mcp --db-path {} --agent-sock {} --http-sock {} >/dev/null 2>&1 & MCP_PID=$!; echo MCP_STARTED; read _; kill $MCP_PID 2>/dev/null || true; wait $MCP_PID 2>/dev/null || true",
            d_old.dir.db.display(),
            spy_sock.display(),
            d_old.dir.http_sock.display(),
        );
        let mut sh = d_old.dir.cmd("sh");
        sh.args(["-c", &mcp_script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut cl_child = sh.spawn().unwrap();
        write_claude_session_file(&d_old.dir, cl_child.id(), id_cl_old);
        let mut cl_in = cl_child.stdin.take().unwrap();
        let mut cl_out = BufReader::new(cl_child.stdout.take().unwrap());
        writeln!(cl_in, "go").unwrap();
        let mut started_line = String::new();
        cl_out.read_line(&mut started_line).unwrap();
        assert_eq!(started_line.trim(), "MCP_STARTED");

        // Poll up to 3s for Claude registration (asserting spy_sock saw no bad_request)
        let mut registered = false;
        for _ in 0..30 {
            let (_, old_list) = http_get(&d_old.dir.http_sock, "/v1/recipients");
            if old_list["recipients"].as_array().unwrap().iter().any(|r| {
                r["address"]
                    .as_str()
                    .is_some_and(|a| a.starts_with(&format!("{id_cl_old}@")))
            }) {
                registered = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(registered, "O5h: Claude session must register on 912ca97a");
        writeln!(cl_in, "bye").unwrap();
        let _ = cl_child.wait();

        // Agy fixture session against old daemon (912ca97a):
        // background worker mcp_start (mcp.rs:151-168) is accepted (status == "ok") and held for 10 s (kills X14).
        let agy_old_id = "95555555-5555-4555-8555-555555555555";
        let agy_old_presence = d_old.dir.run.join("agy-presence");
        fs::create_dir_all(&agy_old_presence).unwrap();
        let agy_old_lock = agy_old_presence.join(format!("{agy_old_id}.lock"));
        let _agy_old_lock_file = {
            use std::os::unix::io::AsRawFd;
            let f = fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(&agy_old_lock)
                .unwrap();
            let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            assert_eq!(rc, 0);
            f
        };
        let reg_agy_old = d_old
            .dir
            .cmd(BIN)
            .args([
                "register",
                "agy",
                "--sock",
                &d_old.dir.register_sock.display().to_string(),
            ])
            .env("ANTIGRAVITY_CONVERSATION_ID", agy_old_id)
            .env("ANTIGRAVITY_LS_ADDRESS", "127.0.0.1:33398")
            .env("ANTIGRAVITY_CSRF_TOKEN", "csrf-old-agy")
            .output()
            .unwrap();
        assert!(reg_agy_old.status.success(), "O5h register agy failed");

        let ok_before_agy = ok_count.load(Ordering::Relaxed);
        let agy_mcp_script = format!(
            "(echo '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"agy\",\"version\":\"1\"}}}}}}'; sleep 12) | {BIN} mcp --db-path {} --agent-sock {} --http-sock {} >/dev/null 2>&1 & MCP_PID=$!; echo AGY_MCP_STARTED; read _; kill $MCP_PID 2>/dev/null || true; wait $MCP_PID 2>/dev/null || true",
            d_old.dir.db.display(),
            spy_sock.display(),
            d_old.dir.http_sock.display(),
        );
        let mut agy_sh = d_old.dir.cmd("sh");
        agy_sh
            .args(["-c", &agy_mcp_script])
            .env("ANTIGRAVITY_CONVERSATION_ID", agy_old_id)
            .env("ANTIGRAVITY_LS_ADDRESS", "127.0.0.1:33398")
            .env("ANTIGRAVITY_CSRF_TOKEN", "csrf-old-agy")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut agy_child = agy_sh.spawn().unwrap();
        let mut agy_in = agy_child.stdin.take().unwrap();
        let mut agy_out = BufReader::new(agy_child.stdout.take().unwrap());
        let mut agy_started = String::new();
        agy_out.read_line(&mut agy_started).unwrap();
        assert_eq!(agy_started.trim(), "AGY_MCP_STARTED");

        let mut agy_ok = false;
        for _ in 0..30 {
            if ok_count.load(Ordering::Relaxed) > ok_before_agy {
                let (_, old_agy_list) = http_get(&d_old.dir.http_sock, "/v1/recipients");
                if old_agy_list["recipients"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| {
                        r["address"]
                            .as_str()
                            .is_some_and(|a| a.starts_with(&format!("{agy_old_id}@")))
                    })
                {
                    agy_ok = true;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            agy_ok,
            "O5h: agy mcp_start (including background worker) must be accepted (status ok) on 912ca97a: ok_count={}",
            ok_count.load(Ordering::Relaxed)
        );

        std::thread::sleep(Duration::from_secs(10));
        assert!(
            agy_child.try_wait().unwrap().is_none(),
            "O5h: held mcp_start connection must persist for 10 s against 912ca97a"
        );
        let (_, held_agy_list) = http_get(&d_old.dir.http_sock, "/v1/recipients");
        assert!(
            held_agy_list["recipients"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["address"]
                    .as_str()
                    .is_some_and(|a| a.starts_with(&format!("{agy_old_id}@")))),
            "O5h: agy session must remain registered after 10 s hold on 912ca97a: {held_agy_list}"
        );
        writeln!(agy_in, "bye").unwrap();
        let _ = agy_child.wait();
        stop_spy.store(true, Ordering::Relaxed);
        spy_handle.join().unwrap();
    }

    // O3h: Claude rollback to 912ca97a and re-upgrade while holder O stays ALIVE throughout:
    // re-claim under 912ca97a changes created_at (T0 -> T1); after re-upgrade old tag is neither applied nor counted (kills M3-claimkey).
    {
        let dir_rb = NodeDir::new("p1o3h");
        let mut d_rb = Daemon::start(dir_rb, BIN, "RB", None, vec![]);
        let id_rb = "96666666-6666-4666-8666-666666666666";
        let id_other = "96666666-6666-4666-8666-666666666667";
        let rb_script = format!(
            "set -e; while IFS= read -r cmd; do case \"$cmd\" in init) {BIN} list --json >/dev/null; {BIN} tag add rb.tag --json >/dev/null; echo INIT_OK ;; prevlist) {prev} list --json >/dev/null; echo PREV_OK ;; add:*) t=${{cmd#add:}}; if out=$({BIN} tag add \"$t\" --json 2>&1); then echo \"OK:$out\"; else echo \"ERR:$out\"; fi ;; bye) break ;; esac; done"
        );
        let mut sh_rb = d_rb.dir.cmd("sh");
        sh_rb
            .args(["-c", &rb_script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child_rb = sh_rb.spawn().unwrap();
        let rb_pid = child_rb.id();
        write_claude_session_file(&d_rb.dir, rb_pid, id_rb);
        let mut rb_in = child_rb.stdin.take().unwrap();
        let mut rb_out = BufReader::new(child_rb.stdout.take().unwrap());

        writeln!(rb_in, "init").unwrap();
        let mut l = String::new();
        rb_out.read_line(&mut l).unwrap();
        assert_eq!(l.trim(), "INIT_OK");

        let (_, before_rb) = http_get(&d_rb.dir.http_sock, "/v1/recipients?tag=rb.tag");
        assert_eq!(before_rb["total"], 1);
        let created_at_0: i64 = {
            let db_rb = rusqlite::Connection::open(&d_rb.dir.db).unwrap();
            db_rb
                .query_row(
                    "SELECT created_at FROM instance_claims WHERE id = ?1 AND released = 0",
                    [id_rb],
                    |r| r.get(0),
                )
                .unwrap()
        };

        // Rollback to 912ca97a while holder O stays ALIVE, then re-claim id_rb via id_other -> id_rb so created_at advances
        d_rb.stop();
        d_rb.spawn(&prev);
        std::thread::sleep(Duration::from_secs(1));
        write_claude_session_file(&d_rb.dir, rb_pid, id_other);
        writeln!(rb_in, "prevlist").unwrap();
        l.clear();
        rb_out.read_line(&mut l).unwrap();
        assert_eq!(l.trim(), "PREV_OK");

        write_claude_session_file(&d_rb.dir, rb_pid, id_rb);
        writeln!(rb_in, "prevlist").unwrap();
        l.clear();
        rb_out.read_line(&mut l).unwrap();
        assert_eq!(l.trim(), "PREV_OK");

        let created_at_1: i64 = {
            let db_rb = rusqlite::Connection::open(&d_rb.dir.db).unwrap();
            db_rb
                .query_row(
                    "SELECT created_at FROM instance_claims WHERE id = ?1 AND released = 0",
                    [id_rb],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert!(
            created_at_1 > created_at_0,
            "O3h precondition: re-claim under 912ca97a must advance created_at ({created_at_0} -> {created_at_1})"
        );

        // Re-upgrade to new BIN while holder O is STILL ALIVE
        d_rb.stop();
        d_rb.spawn(BIN);
        let (_, live_list) = http_get(&d_rb.dir.http_sock, "/v1/recipients");
        assert!(
            live_list["recipients"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["address"]
                    .as_str()
                    .is_some_and(|a| a.starts_with(&format!("{id_rb}@")))
                    && r.get("tags")
                        .and_then(Value::as_array)
                        .is_none_or(|t| t.is_empty())),
            "O3h: live holder after re-upgrade must have tags == []: {live_list}"
        );
        let (_, after_reup) = http_get(&d_rb.dir.http_sock, "/v1/recipients?tag=rb.tag");
        assert_eq!(
            after_reup["total"], 0,
            "O3h: old tag from pre-rollback T0 must not be counted after re-upgrade: {after_reup}"
        );
        // 8 fresh adds must all succeed (old T0 row not counted toward cap), 9th refused
        for i in 0..8 {
            writeln!(rb_in, "add:t{i}").unwrap();
            l.clear();
            rb_out.read_line(&mut l).unwrap();
            assert!(l.starts_with("OK:"), "O3h fresh tag t{i} must succeed: {l}");
        }
        writeln!(rb_in, "add:t8").unwrap();
        l.clear();
        rb_out.read_line(&mut l).unwrap();
        assert!(
            l.starts_with("ERR:"),
            "O3h 9th fresh tag must be refused: {l}"
        );
        writeln!(rb_in, "bye").unwrap();
        let _ = child_rb.wait();
    }

    println!("p1pz: compat_912ca97a_oracles passed");
}
