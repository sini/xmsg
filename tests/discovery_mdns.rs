//! LAN discovery: the `discovery` key, the mDNS source's logic through its injected
//! backend, the health and announce-posture fields, the doctor checks, and (macOS only)
//! coexistence with mDNSResponder.
//!
//! The engine tests drive `Engine` through a fake `Backend`, so they need no multicast network.
//! Only two tests touch the real network, both gated to macOS, where mDNSResponder is always
//! present: `m1_configured_serve_opens_5353` and `m5_receives_a_record_registered_with_dns_sd`.

mod agy_env;
use agy_env::ScrubAgyEnv;
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::{tempdir, TempDir};

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn http_get(sock: &Path, uri: &str) -> Option<Value> {
    let mut stream = UnixStream::connect(sock).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        stream,
        "GET {uri} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    serde_json::from_str(response.split_once("\r\n\r\n")?.1).ok()
}

/// Whether process `pid` holds a UDP socket bound to `port`.
#[cfg(target_os = "macos")]
fn udp_port_open(pid: u32, port: u16) -> bool {
    // The Nix build's PATH holds only build inputs, so host tools are named by path.
    let out = Command::new("/usr/sbin/lsof")
        .args([
            "-nP",
            "-a",
            "-p",
            &pid.to_string(),
            &format!("-iUDP:{port}"),
        ])
        .output()
        .expect("run lsof");
    String::from_utf8_lossy(&out.stdout).contains("UDP")
}

#[cfg(target_os = "linux")]
#[path = "discovery_mdns/udp_diag.rs"]
mod udp_diag;

#[cfg(target_os = "linux")]
use udp_diag::udp_port_open;

struct Node {
    _tmp: TempDir,
    http_sock: PathBuf,
    agent_sock: PathBuf,
    child: Kill,
}

fn serve(discovery: Option<Value>) -> Node {
    let tmp = tempdir().unwrap();
    let root = tmp.path().to_owned();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let run = root.join("run");
    fs::create_dir_all(&run).unwrap();
    fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
    let (cert, key, _) = xmsg::fed::generate_self_signed_ed25519_pem("node").unwrap();
    let (_, _, other_pin) = xmsg::fed::generate_self_signed_ed25519_pem("other").unwrap();
    fs::write(root.join("cert.pem"), cert).unwrap();
    fs::write(root.join("key.pem"), key).unwrap();
    let mut peers =
        json!({"peers": {"pinned-other": {"address": "127.0.0.1:1", "pin": other_pin}}});
    if let Some(d) = discovery {
        peers["discovery"] = d;
    }
    fs::write(root.join("peers.json"), peers.to_string()).unwrap();
    let http_sock = run.join("http.sock");
    let agent_sock = run.join("agent.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_xmsg"))
        .scrub_agy_env()
        .env("XDG_RUNTIME_DIR", &run)
        .env("HOME", &root)
        .env_remove("XMSG_PEERS_FILE")
        .arg("serve")
        .arg("--peers-file")
        .arg(root.join("peers.json"))
        .arg("--fed-cert")
        .arg(root.join("cert.pem"))
        .arg("--fed-key")
        .arg(root.join("key.pem"))
        .arg("--db-path")
        .arg(root.join("db.sqlite"))
        .arg("--sessions-dir")
        .arg(&root)
        .arg("--agent-sock")
        .arg(&agent_sock)
        .arg("--register-sock")
        .arg(run.join("register.sock"))
        .arg("--http-sock")
        .arg(&http_sock)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn serve");
    let mut node = Node {
        _tmp: tmp,
        http_sock,
        agent_sock,
        child: Kill(child),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Ok(Some(status)) = node.child.0.try_wait() {
            panic!("serve exited: {status}");
        }
        if node.health().is_some_and(|h| h["status"] == "ok") {
            return node;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("serve did not answer health");
}

impl Node {
    fn health(&self) -> Option<Value> {
        http_get(&self.http_sock, "/healthz")
    }
    fn pid(&self) -> u32 {
        self.child.0.id()
    }
}

/// The socket predicate sees a UDP socket this process holds.
#[test]
fn udp_socket_predicate_control() {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    assert!(udp_port_open(std::process::id(), port));
    drop(socket);
}

/// M1: without the key, serve starts no mDNS responder and holds no UDP 5353 socket.
#[test]
fn m1_no_key_no_responder() {
    let node = serve(None);
    std::thread::sleep(Duration::from_millis(500));
    let health = node.health().unwrap();
    assert_eq!(health["discovery"]["mdns"]["state"], "off", "{health}");
    assert_eq!(
        health["discovery"]["mdns"]["announce_state"], "at_rest",
        "{health}"
    );
    assert_eq!(health["discovery"]["mdns"]["candidates"], 0, "{health}");
    assert!(node.agent_sock.exists());
    assert!(
        !udp_port_open(node.pid(), 5353),
        "UDP 5353 open without the key"
    );
}

/// M1's positive arm: with the key, the responder binds 5353, stays browse-only at rest on
/// startup under default `timed` announce, and serve keeps answering health and `agent.sock`.
#[cfg(all(target_os = "macos", feature = "mdns"))]
#[test]
fn m1_configured_serve_opens_5353() {
    let node = serve(Some(json!({"mdns": {}})));
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = Value::Null;
    while Instant::now() < deadline {
        last = node.health().unwrap();
        let state = last["discovery"]["mdns"]["state"].as_str().unwrap_or("");
        if matches!(state, "unverified" | "active" | "permission_suspected")
            && last["discovery"]["mdns"]["announce_state"] == "at_rest"
            && udp_port_open(node.pid(), 5353)
            && node.agent_sock.exists()
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("no at-rest responder on 5353: {last}");
}

/// Without the `mdns` feature the key still loads, and health says the source isn't built in.
#[cfg(not(feature = "mdns"))]
#[test]
fn configured_without_the_feature_reports_off() {
    let node = serve(Some(json!({"mdns": {}})));
    let health = node.health().unwrap();
    assert_eq!(health["discovery"]["mdns"]["state"], "off", "{health}");
    assert_eq!(
        health["discovery"]["mdns"]["announce_state"], "at_rest",
        "{health}"
    );
    assert_eq!(
        health["discovery"]["mdns"]["detail"], "not compiled into this build",
        "{health}"
    );
    assert!(!udp_port_open(node.pid(), 5353));
}

fn check_peers(discovery: Value) -> std::process::Output {
    let tmp = tempdir().unwrap();
    let file = tmp.path().join("peers.json");
    fs::write(
        &file,
        json!({"peers": {}, "discovery": discovery}).to_string(),
    )
    .unwrap();
    Command::new(env!("CARGO_BIN_EXE_xmsg"))
        .arg("check-peers")
        .arg(&file)
        .output()
        .unwrap()
}

#[test]
fn check_peers_validates_the_key() {
    for good in [
        json!({"mdns": {}, "ttl_secs": 300}),
        json!({"mdns": {}, "announce": "timed"}),
        json!({"mdns": {}, "announce": "browse_only"}),
        json!({"mdns": {}, "announce": "always"}),
        json!({"mdns": {"browse": true, "announce": false}, "ttl_secs": 300}),
    ] {
        let ok = check_peers(good.clone());
        assert!(ok.status.success(), "{good}: {ok:?}");
    }
    let tailnet = check_peers(json!({"tailnet": {"ports": [7788]}}));
    assert!(!tailnet.status.success());
    assert!(String::from_utf8_lossy(&tailnet.stderr).contains("not supported by this build"));
    for bad in [
        json!({"mdns": {"brwse": true}}),
        json!({"mdns": {}, "announce": "forever"}),
        json!({"ttl_secs": 601}),
    ] {
        let out = check_peers(bad.clone());
        assert!(!out.status.success(), "{bad} accepted");
    }
}

/// M3: the shared candidate table keeps foreign roots ineligible while unkeyed (`None`) mDNS
/// candidates remain eligible for any rule.
#[test]
fn m3_eligibility_by_root() {
    use xmsg::discovery::{Candidate, CandidateTable, Source};
    let now = Instant::now();
    let mut table = CandidateTable::new();
    let at = |addr: &str, root_fp| Candidate {
        addr: addr.parse().unwrap(),
        source: Source::Mdns,
        hint: None,
        root_fp,
        seen_at: now,
        expires_at: now + Duration::from_secs(60),
    };
    table.upsert(at("10.1.0.1:7788", Some([9; 32])), now);
    table.upsert(at("10.1.0.2:7788", None), now);
    let eligible: Vec<String> = table
        .eligible(&[1; 32], now)
        .iter()
        .map(|c| c.addr.to_string())
        .collect();
    assert_eq!(eligible, vec!["10.1.0.2:7788"]);
}

/// A fake doctor target: `/healthz` answers `health`, everything else 404.
fn doctor_with_health(health: Value) -> Value {
    let tmp = tempdir().unwrap();
    let run = tmp.path().join("run");
    fs::create_dir_all(&run).unwrap();
    fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
    let sock = run.join("http.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    fs::set_permissions(&sock, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopping = stop.clone();
    let server = std::thread::spawn(move || {
        while !stopping.load(std::sync::atomic::Ordering::SeqCst) {
            let Ok((mut stream, _)) = listener.accept() else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]);
            let (code, body) = if request.starts_with("GET /healthz ") {
                (200, health.to_string())
            } else {
                (404, json!({"error": "not_found"}).to_string())
            };
            let _ = write!(stream, "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    let out = Command::new(env!("CARGO_BIN_EXE_xmsg"))
        .env_remove("XMSG_PEERS_FILE")
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", &run)
        .env("XDG_STATE_HOME", tmp.path().join("state"))
        .args(["doctor", "--json", "--http-sock"])
        .arg(&sock)
        .arg("--agent-sock")
        .arg(run.join("agent.sock"))
        .arg("--register-sock")
        .arg(run.join("register.sock"))
        .arg("--db-path")
        .arg(tmp.path().join("db.sqlite"))
        .output()
        .unwrap();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    server.join().unwrap();
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("doctor JSON: {e}: {}", String::from_utf8_lossy(&out.stdout)))
}

fn doctor_check(report: &Value, id: &str) -> Option<Value> {
    report["checks"]
        .as_array()?
        .iter()
        .find(|c| c["id"] == id)
        .cloned()
}

#[test]
fn doctor_reports_the_discovery_state_and_standing_always_notice() {
    let health = |state: &str, announce_state: Value, announce_mode: &str, detail: &str| {
        json!({
            "status": "ok",
            "sessions_dir": "ok",
            "version": "0",
            "build_revision": "x",
            "discovery": {
                "mdns": {
                    "state": state,
                    "announce_state": announce_state,
                    "announce_mode": announce_mode,
                    "detail": detail,
                    "since": 1,
                    "candidates": 3
                }
            }
        })
    };

    // `permission_suspected` warns and names Local Network / UDP 5353.
    let suspected = doctor_with_health(health(
        "permission_suspected",
        json!("at_rest"),
        "timed",
        "outbound multicast failed 3 consecutive times",
    ));
    let check = doctor_check(&suspected, "discovery.mdns").expect("discovery.mdns check");
    assert_eq!(check["status"], "warn", "{check}");
    assert!(
        check["hint"]
            .as_str()
            .unwrap()
            .contains("permission suspected"),
        "{check}"
    );
    assert!(check["hint"].as_str().unwrap().contains("Local Network"));
    assert!(check["message"].as_str().unwrap().contains("3 candidates"));
    assert!(doctor_check(&suspected, "discovery.announce").is_none());

    // `unverified` is the normal at-rest state and reports `info` (never `pass` and never `warn`).
    let unverified = doctor_with_health(health(
        "unverified",
        json!({"window_open": 95}),
        "timed",
        "at rest",
    ));
    let uv = doctor_check(&unverified, "discovery.mdns").unwrap();
    assert_eq!(uv["status"], "info", "unverified must report info: {uv}");
    assert!(
        uv["message"]
            .as_str()
            .unwrap()
            .contains("announce window_open(95s)"),
        "{uv}"
    );

    for (state, status) in [("active", "pass"), ("off", "pass"), ("failed", "warn")] {
        let report = doctor_with_health(health(state, json!("at_rest"), "timed", ""));
        assert_eq!(
            doctor_check(&report, "discovery.mdns").unwrap()["status"],
            status,
            "{state}"
        );
    }

    // Fresh `starting` (<= 15 s) passes; stuck `starting` (> 15 s) warns.
    let fresh = {
        let mut h = health("starting", json!("at_rest"), "timed", "");
        h["discovery"]["mdns"]["since"] = json!(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs());
        doctor_with_health(h)
    };
    assert_eq!(
        doctor_check(&fresh, "discovery.mdns").unwrap()["status"],
        "pass"
    );
    let stuck = doctor_with_health(health("starting", json!("at_rest"), "timed", ""));
    assert_eq!(
        doctor_check(&stuck, "discovery.mdns").unwrap()["status"],
        "warn"
    );

    // `discovery.announce = "always"` produces a standing Warn check naming the setting,
    // even when `discovery.mdns` itself is `active` (Pass).
    let always = doctor_with_health(health("active", json!("always"), "always", ""));
    assert_eq!(
        doctor_check(&always, "discovery.mdns").unwrap()["status"],
        "pass"
    );
    let notice = doctor_check(&always, "discovery.announce")
        .expect("standing discovery.announce notice for 'always'");
    assert_eq!(notice["status"], "warn", "{notice}");
    assert!(
        notice["message"]
            .as_str()
            .unwrap()
            .contains("discovery.announce"),
        "{notice}"
    );
    assert!(
        notice["message"].as_str().unwrap().contains("always"),
        "{notice}"
    );
}

#[cfg(feature = "mdns")]
mod mdns_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use xmsg::discovery::mdns::{
        announce_addrs, build_mdns_a_query, probe_bind, random_id, random_query_name, txt, Backend,
        Engine, Event, Inputs, ProbeOutcome, ANNOUNCE_WINDOW, IP_CHECK_SECS,
        LN_DEBOUNCE_CONSECUTIVE, LN_PROBE_RETRY_INTERVAL, PROTOCOL_VERSION, REGISTER_RETRY_BASE,
        ROTATE_INTERVAL, SERVICE_TYPE,
    };
    use xmsg::discovery::{
        AnnounceMode, AnnounceState, MdnsConfig, SharedCandidates, SharedStatus, State, MDNS_CAP,
    };

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Registration {
        id: String,
        fullname: String,
        host: String,
        port: u16,
        addrs: Vec<IpAddr>,
        txt: Vec<(String, String)>,
    }

    #[derive(Default)]
    struct FakeInner {
        starts: usize,
        stops: usize,
        unregisters: Vec<String>,
        current_registered: Option<String>,
        start_err: Option<String>,
        register_err: Option<String>,
        registers: Vec<Registration>,
        interfaces: Vec<(String, IpAddr)>,
        probe_outcomes: VecDeque<ProbeOutcome>,
        default_probe: Option<ProbeOutcome>,
        probed_queries: Vec<(String, Vec<Ipv4Addr>)>,
    }

    #[derive(Clone, Default)]
    struct Fake(Arc<Mutex<FakeInner>>);

    impl Backend for Fake {
        fn start(&mut self) -> Result<(), String> {
            let mut inner = self.0.lock().unwrap();
            inner.starts += 1;
            match &inner.start_err {
                Some(e) => Err(e.clone()),
                None => Ok(()),
            }
        }

        fn register(
            &mut self,
            id: &str,
            port: u16,
            addrs: &[IpAddr],
            txt: &[(String, String)],
        ) -> Result<(), String> {
            let mut inner = self.0.lock().unwrap();
            if let Some(prev) = inner.current_registered.take() {
                inner.unregisters.push(prev);
            }
            if let Some(e) = &inner.register_err {
                return Err(e.clone());
            }
            let fullname = format!("{id}.{SERVICE_TYPE}");
            let host = format!("{id}.local.");
            inner.current_registered = Some(fullname.clone());
            inner.registers.push(Registration {
                id: id.to_string(),
                fullname,
                host,
                port,
                addrs: addrs.to_vec(),
                txt: txt.to_vec(),
            });
            Ok(())
        }

        fn unregister(&mut self) {
            let mut inner = self.0.lock().unwrap();
            if let Some(prev) = inner.current_registered.take() {
                inner.unregisters.push(prev);
            }
        }

        fn stop(&mut self) {
            let mut inner = self.0.lock().unwrap();
            if let Some(prev) = inner.current_registered.take() {
                inner.unregisters.push(prev);
            }
            inner.stops += 1;
        }

        fn recv(&mut self, _: Duration) -> Option<Event> {
            None
        }

        fn interfaces(&self) -> Vec<(String, IpAddr)> {
            self.0.lock().unwrap().interfaces.clone()
        }

        fn probe_multicast(&mut self, qname: &str, lan_v4: &[Ipv4Addr]) -> ProbeOutcome {
            let mut inner = self.0.lock().unwrap();
            inner
                .probed_queries
                .push((qname.to_string(), lan_v4.to_vec()));
            if let Some(next) = inner.probe_outcomes.pop_front() {
                return next;
            }
            inner.default_probe.clone().unwrap_or(ProbeOutcome::SentOk)
        }
    }

    struct Rig {
        fake: Fake,
        status: SharedStatus,
        candidates: SharedCandidates,
        trigger: Arc<std::sync::atomic::AtomicBool>,
        engine: Engine<Fake>,
        t0: Instant,
    }

    impl Rig {
        fn new() -> Self {
            let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            Self::with_id_gen(Box::new(move || {
                let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                Ok(format!("{n:032x}"))
            }))
        }

        fn with_id_gen(id_gen: xmsg::discovery::mdns::IdGen) -> Self {
            let fake = Fake::default();
            fake.0.lock().unwrap().interfaces = vec![("en0".into(), "10.9.3.2".parse().unwrap())];
            let status = SharedStatus::default();
            let candidates = SharedCandidates::default();
            let trigger = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let engine = Engine::with_trigger(
                fake.clone(),
                id_gen,
                status.clone(),
                candidates.clone(),
                trigger.clone(),
            );
            Self {
                fake,
                status,
                candidates,
                trigger,
                engine,
                t0: Instant::now(),
            }
        }

        fn at(&self, secs: u64) -> Instant {
            self.t0 + Duration::from_secs(secs)
        }

        fn tick(&mut self, inputs: &Inputs, secs: u64) {
            self.engine.reconcile(inputs, self.at(secs));
        }

        fn step(&mut self, inputs: &Inputs, secs: u64) {
            self.engine.step_timers(inputs, self.at(secs));
        }

        fn event(&mut self, event: Event, secs: u64) {
            self.engine.handle(event, self.at(secs));
        }

        fn state(&self) -> (State, String) {
            let s = self.status.lock().unwrap();
            (s.state, s.detail.clone())
        }

        fn announce_state(&self, secs: u64) -> AnnounceState {
            self.status.lock().unwrap().posture.snapshot(self.at(secs))
        }

        fn candidates(&self, secs: u64) -> Vec<SocketAddr> {
            self.candidates
                .read()
                .unwrap()
                .snapshot(self.at(secs))
                .into_iter()
                .map(|c| c.addr)
                .collect()
        }
    }

    fn inputs_mode(browse: bool, mode: AnnounceMode) -> Inputs {
        Inputs {
            mdns: Some(MdnsConfig {
                browse,
                announce: true,
            }),
            announce: mode,
            ttl_secs: 600,
            fed_listen: Some("0.0.0.0:7788".parse().unwrap()),
        }
    }

    fn inputs(browse: bool, announce_bool: bool) -> Inputs {
        Inputs {
            mdns: Some(MdnsConfig {
                browse,
                announce: announce_bool,
            }),
            announce: AnnounceMode::Timed,
            ttl_secs: 600,
            fed_listen: Some("0.0.0.0:7788".parse().unwrap()),
        }
    }

    fn resolved(fullname: &str, addrs: &[&str], txt: &[(&str, &str)]) -> Event {
        Event::Resolved {
            fullname: format!("{fullname}.{SERVICE_TYPE}"),
            port: 7788,
            addrs: addrs
                .iter()
                .map(|a| (a.parse().unwrap(), vec!["en0".into()]))
                .collect(),
            txt: txt
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn m1_no_key_starts_nothing() {
        let mut rig = Rig::new();
        rig.tick(&Inputs::default(), 0);
        assert_eq!(rig.fake.0.lock().unwrap().starts, 0);
        assert!(rig.fake.0.lock().unwrap().probed_queries.is_empty());
        assert_eq!(rig.state().0, State::Off);
        assert_eq!(rig.announce_state(0), AnnounceState::AtRest);
    }

    /// M2: TXT carries only `v=1` and a 128-bit hex `id` — never `root`, node name, user or host
    /// name; incoming `root` keys from peers are ignored (`root_fp == None`).
    #[test]
    fn m2_txt_carries_no_root_or_names_and_ignores_peer_root() {
        let id = random_id().expect("128-bit random handle");
        assert_eq!(id.len(), 32, "expected 128-bit (32 hex) handle: {id}");
        assert!(id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        let records = txt(&id);
        let keys: Vec<&str> = records.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["v", "id"]);
        assert_eq!(records[0].1, PROTOCOL_VERSION);
        assert_eq!(records[1].1, id);
        let host = gethostname::gethostname().to_string_lossy().into_owned();
        for (k, v) in &records {
            assert_ne!(k, "root");
            if host.len() >= 3 {
                assert!(!v.contains(&host), "TXT leaked hostname: {v}");
            }
        }

        let mut rig = Rig::new();
        rig.tick(&inputs(true, true), 0);
        let legacy_root = "ab".repeat(32);
        rig.event(
            resolved(
                "peer",
                &["10.9.4.1"],
                &[
                    ("v", "1"),
                    ("id", "peer-opaque"),
                    ("root", &legacy_root),
                    ("user", "alice"),
                ],
            ),
            1,
        );
        let snap = rig.candidates.read().unwrap().snapshot(rig.at(1));
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].hint.as_deref(), Some("peer-opaque"));
        assert_eq!(
            snap[0].root_fp, None,
            "mDNS receiver must never populate root_fp"
        );
    }

    /// At startup, `timed` (default) is browse-only at rest; local activation opens a 120 s
    /// window, rotates handle + instance + target hostname every 30 s and unregisters the old
    /// record each time, then expires back to `at_rest` (and `Unverified` state).
    #[test]
    fn p14_timed_startup_is_at_rest_rotates_every_30s_and_expires_at_120s() {
        assert_eq!(ANNOUNCE_WINDOW, Duration::from_secs(120));
        assert_eq!(ROTATE_INTERVAL, Duration::from_secs(30));

        let mut rig = Rig::new();
        let cfg = inputs_mode(true, AnnounceMode::Timed);

        // Startup: browse-only at rest — zero registrations, state is Unverified.
        rig.tick(&cfg, 0);
        assert_eq!(rig.announce_state(0), AnnounceState::AtRest);
        assert_eq!(rig.state().0, State::Unverified);
        assert!(
            rig.fake.0.lock().unwrap().registers.is_empty(),
            "timed mode must never announce at startup"
        );

        // Local activation via trigger hook at t = 10 s opens [10, 130).
        // Note: id #1 was used for startup's random deny query, so handle #1 here is id #2.
        rig.trigger.store(true, std::sync::atomic::Ordering::SeqCst);
        rig.step(&cfg, 10);
        assert_eq!(rig.announce_state(10), AnnounceState::WindowOpen(120));
        assert_eq!(rig.announce_state(25), AnnounceState::WindowOpen(105));
        let h1 = rig.engine.active_handle().unwrap().to_string();
        {
            let inner = rig.fake.0.lock().unwrap();
            assert_eq!(inner.registers.len(), 1);
            assert_eq!(inner.registers[0].id, h1);
            assert_eq!(inner.registers[0].fullname, format!("{h1}.{SERVICE_TYPE}"));
            assert_eq!(inner.registers[0].host, format!("{h1}.local."));
            assert!(inner.unregisters.is_empty());
        }

        // Self-echo of active handle on our own LAN IP marks Active and never enters CandidateTable.
        rig.event(resolved(&h1, &["10.9.3.2"], &[("v", "1"), ("id", &h1)]), 15);
        assert!(rig.candidates(15).is_empty(), "own handle entered table");
        assert_eq!(rig.state().0, State::Active);

        // At t = 40 s (+30 s): rotates to a fresh handle and unregisters `h1`.
        rig.step(&cfg, 40);
        let h2 = rig.engine.active_handle().unwrap().to_string();
        assert_ne!(h1, h2);
        {
            let inner = rig.fake.0.lock().unwrap();
            assert_eq!(inner.registers.len(), 2);
            assert_eq!(inner.unregisters, vec![format!("{h1}.{SERVICE_TYPE}")]);
            assert_eq!(inner.registers[1].id, h2);
            assert_eq!(inner.registers[1].fullname, format!("{h2}.{SERVICE_TYPE}"));
            assert_eq!(inner.registers[1].host, format!("{h2}.local."));
        }

        // Delayed cached replay of retired handle `h1` is still ignored.
        rig.event(resolved(&h1, &["10.9.3.2"], &[("v", "1"), ("id", &h1)]), 45);
        assert!(
            rig.candidates(45).is_empty(),
            "retired handle entered table"
        );

        // Rotations at t = 70 s (#3) and t = 100 s (#4).
        rig.step(&cfg, 70);
        rig.step(&cfg, 100);
        assert_eq!(rig.fake.0.lock().unwrap().registers.len(), 4);
        assert_eq!(rig.announce_state(129), AnnounceState::WindowOpen(1));

        // At t = 130 s (120 s elapsed): even if the reprobe's first send fails (N-3), window
        // expiry drops `Active` to `Unverified` immediately without lingering ~4 s.
        rig.fake
            .0
            .lock()
            .unwrap()
            .probe_outcomes
            .push_back(ProbeOutcome::SendBlocked("EHOSTUNREACH".into()));
        rig.step(&cfg, 130);
        assert_eq!(rig.announce_state(130), AnnounceState::AtRest);
        assert_eq!(rig.engine.active_handle(), None);
        assert_eq!(rig.state().0, State::Unverified);
        {
            let inner = rig.fake.0.lock().unwrap();
            assert_eq!(inner.unregisters.len(), 4);
            assert_eq!(inner.current_registered, None);
        }

        // Subsequent 30 s reconcile ticks do NOT re-open the window without a fresh local trigger.
        rig.tick(&cfg, 160);
        assert_eq!(rig.announce_state(160), AnnounceState::AtRest);
        assert_eq!(rig.fake.0.lock().unwrap().registers.len(), 4);
    }

    /// M4 & B1: Complementary Local Network detector arms:
    /// - Deny arm (at all times): 1 transient `EHOSTUNREACH` is debounced; 3 consecutive
    ///   `EHOSTUNREACH` errors report `permission_suspected`, never proven;
    /// - At rest (`SentOk` without an open announce window): reports `unverified`, never `active`;
    /// - Positive arm (only while announcing): own `_xmsg` announcement echo on our own LAN IP
    ///   marks `active`, while loopback or foreign-IP echoes do not.
    #[test]
    fn m4_p15_multicast_detector_debounces_and_requires_own_lan_reply() {
        assert_eq!(LN_DEBOUNCE_CONSECUTIVE, 3);
        assert_eq!(LN_PROBE_RETRY_INTERVAL, Duration::from_secs(2));

        let mut rig = Rig::new();
        {
            let mut inner = rig.fake.0.lock().unwrap();
            // Transient single EHOSTUNREACH (as observed in `allowed-3`), then SentOk.
            inner
                .probe_outcomes
                .push_back(ProbeOutcome::SendBlocked("EHOSTUNREACH".into()));
            inner.probe_outcomes.push_back(ProbeOutcome::SentOk);
        }
        let cfg = inputs_mode(true, AnnounceMode::Timed);

        // t = 0: first EHOSTUNREACH -> still Starting (debounced, streak = 1).
        rig.tick(&cfg, 0);
        assert_eq!(
            rig.state().0,
            State::Starting,
            "single EHOSTUNREACH must be debounced"
        );
        assert_eq!(rig.engine.warnings(), 0);

        // t = 2: retry gets SentOk -> resets streak, state is Unverified at rest (never Active).
        rig.step(&cfg, 2);
        assert_eq!(rig.state().0, State::Unverified);

        // Next reconcile tick: 3 consecutive EHOSTUNREACH at t = 30, 32, 34 -> PermissionSuspected.
        {
            let mut inner = rig.fake.0.lock().unwrap();
            for _ in 0..3 {
                inner
                    .probe_outcomes
                    .push_back(ProbeOutcome::SendBlocked("EHOSTUNREACH".into()));
            }
        }
        rig.tick(&cfg, 30);
        assert_eq!(rig.state().0, State::Unverified, "streak 1 must not trip");
        rig.step(&cfg, 32);
        assert_eq!(rig.state().0, State::Unverified, "streak 2 must not trip");
        rig.step(&cfg, 34);
        let (st, detail) = rig.state();
        assert_eq!(st, State::PermissionSuspected);
        assert!(
            detail.contains("permission suspected"),
            "must label suspected, never proven: {detail}"
        );
        assert_eq!(rig.engine.warnings(), 1);

        // Open a timed announce window at t = 60: loopback or foreign-IP echo of our active
        // handle must NOT mark Active; only our own interface IP (10.9.3.2) marks Active.
        rig.tick(&cfg, 60);
        assert!(rig.engine.activate_announce_window(&cfg, rig.at(60)));
        let active_id = rig.engine.active_handle().unwrap().to_string();
        rig.event(
            resolved(
                &active_id,
                &["127.0.0.1", "10.9.99.99"],
                &[("v", "1"), ("id", &active_id)],
            ),
            61,
        );
        assert_eq!(
            rig.state().0,
            State::Unverified,
            "foreign or loopback echo must not mark Active"
        );

        // N-1: our own LAN IP (10.9.3.2) arriving only over loopback (`via = ["lo0"]`) must NOT
        // mark Active either.
        rig.event(
            Event::Resolved {
                fullname: format!("{active_id}.{SERVICE_TYPE}"),
                port: 7788,
                addrs: vec![("10.9.3.2".parse().unwrap(), vec!["lo0".into()])],
                txt: vec![("v".into(), "1".into()), ("id".into(), active_id.clone())],
            },
            61,
        );
        assert_eq!(
            rig.state().0,
            State::Unverified,
            "loopback-arriving own IP must not mark Active"
        );

        // Genuine own-LAN echo (10.9.3.2 arriving on en0) while window is open -> Active.
        rig.event(
            resolved(&active_id, &["10.9.3.2"], &[("v", "1"), ("id", &active_id)]),
            62,
        );
        assert_eq!(rig.state().0, State::Active);
    }

    /// Privacy: the multicast deny query always uses a fresh CSPRNG opaque label and never
    /// discloses any OS hostname bytes on the wire.
    #[test]
    fn p15_default_query_is_random_label_and_hides_hostname() {
        let mut gen = random_id;
        let q1 = random_query_name(&mut gen).expect("random query label");
        let q2 = random_query_name(&mut gen).expect("random query label");
        assert!(q1.starts_with("xmsg-") && q1.ends_with(".local"), "{q1}");
        assert_ne!(q1, q2, "random-label queries should be freshly generated");

        let pkt = build_mdns_a_query(&q1, 0x1234).expect("encode mDNS A query");
        assert_eq!(&pkt[0..2], &[0x12, 0x34]);
        // Flags = 0x0000 (QR=0, RD=0), QDCOUNT = 1.
        assert_eq!(&pkt[2..6], &[0x00, 0x00, 0x00, 0x01]);
        // Ends with root 0x00, QTYPE = 1 (A), QCLASS = 1 (IN).
        assert_eq!(&pkt[pkt.len() - 5..], &[0x00, 0x00, 0x01, 0x00, 0x01]);

        let host = gethostname::gethostname().to_string_lossy().into_owned();
        let base = host.split('.').next().unwrap_or("");
        if base.len() >= 3 {
            let wire_lossy = String::from_utf8_lossy(&pkt).to_ascii_lowercase();
            assert!(
                !wire_lossy.contains(&base.to_ascii_lowercase()),
                "random-label probe leaked OS hostname '{base}'"
            );
        }
    }

    /// M4 & S2: responder start errors retry on the next tick, and a transient `register` error
    /// retries with bounded backoff (`REGISTER_RETRY_BASE = 2s`) and recovers to the prior state
    /// rather than leaving `Failed` stuck.
    #[test]
    fn m4_responder_failure_is_reported_and_retried() {
        assert_eq!(REGISTER_RETRY_BASE, Duration::from_secs(2));
        let mut rig = Rig::new();
        rig.fake.0.lock().unwrap().start_err = Some("bind 5353: address in use".into());
        rig.tick(&inputs(true, true), 0);
        let (state, detail) = rig.state();
        assert_eq!(state, State::Failed);
        assert!(detail.contains("bind 5353"));
        rig.fake.0.lock().unwrap().start_err = None;
        rig.tick(&inputs(true, true), 30);
        assert_eq!(rig.state().0, State::Unverified);

        // S2 forced control: transient `register` failure once while `Unverified`, followed by
        // success on the 2 s backoff retry -> recovers out of `Failed` to `Unverified`.
        let cfg = inputs_mode(true, AnnounceMode::Timed);
        rig.fake.0.lock().unwrap().register_err = Some("transient register error".into());
        assert!(!rig.engine.activate_announce_window(&cfg, rig.at(35)));
        assert_eq!(rig.state().0, State::Failed);
        assert_eq!(rig.announce_state(35), AnnounceState::WindowOpen(120));

        // Clear the transient error; after 2 s backoff, `step_timers` retries and recovers.
        rig.fake.0.lock().unwrap().register_err = None;
        rig.step(&cfg, 37);
        assert_eq!(
            rig.state().0,
            State::Unverified,
            "transient register failure must recover on retry"
        );
        assert!(rig.engine.active_handle().is_some());

        // N-2: backoff growth (2, 4, 8, 16, 30, 30 s cap), restoring a non-Unverified prior state
        // (`PermissionSuspected`), and window expiry mid-retry.
        let mut rig2 = Rig::new();
        rig2.fake.0.lock().unwrap().default_probe =
            Some(ProbeOutcome::SendBlocked("EHOSTUNREACH".into()));
        rig2.tick(&cfg, 0);
        rig2.step(&cfg, 2);
        rig2.step(&cfg, 4);
        assert_eq!(rig2.state().0, State::PermissionSuspected);

        // Activate window at t = 10 with register failing: backoff steps at +2, +4, +8, +16, +30, +30.
        rig2.fake.0.lock().unwrap().register_err = Some("register busy".into());
        assert!(!rig2.engine.activate_announce_window(&cfg, rig2.at(10)));
        assert_eq!(rig2.state().0, State::Failed);
        for (before, due) in [(11, 12), (15, 16), (23, 24), (39, 40), (69, 70), (99, 100)] {
            rig2.step(&cfg, before);
            assert_eq!(rig2.state().0, State::Failed);
            rig2.step(&cfg, due);
            assert_eq!(rig2.state().0, State::Failed);
        }
        // Clear error before the next 30 s retry; if retry succeeds before expiry (at t = 129? next
        // retry is at 130 == window expiry!). First verify window expiry mid-retry at t = 130
        // restores the prior non-Unverified state (`PermissionSuspected`) and closes the window:
        rig2.step(&cfg, 130);
        assert_eq!(rig2.announce_state(130), AnnounceState::AtRest);
        assert_eq!(
            rig2.state().0,
            State::PermissionSuspected,
            "window expiry mid-retry must restore prior PermissionSuspected state"
        );

        // And when retry succeeds mid-window from prior `PermissionSuspected`, it restores
        // `PermissionSuspected` rather than overwriting with `Unverified`:
        assert!(!rig2.engine.activate_announce_window(&cfg, rig2.at(140)));
        assert_eq!(rig2.state().0, State::Failed);
        rig2.fake.0.lock().unwrap().register_err = None;
        rig2.step(&cfg, 142);
        assert_eq!(rig2.state().0, State::PermissionSuspected);
        assert!(rig2.engine.active_handle().is_some());
    }

    /// M6: interface change re-runs the multicast probe, resets own-echo until the new interface
    /// echoes, and rotates any open announcement handle.
    #[test]
    fn m6_interface_change_reprobes_and_rotates_open_announcement() {
        const { assert!(IP_CHECK_SECS <= 30) };
        let mut rig = Rig::new();
        let cfg = inputs_mode(true, AnnounceMode::Timed);
        rig.tick(&cfg, 0);
        assert!(rig.engine.activate_announce_window(&cfg, rig.at(1)));
        let h1 = rig.engine.active_handle().unwrap().to_string();
        rig.event(resolved(&h1, &["10.9.3.2"], &[("v", "1"), ("id", &h1)]), 2);
        assert_eq!(rig.state().0, State::Active);
        assert_eq!(rig.fake.0.lock().unwrap().registers.len(), 1);
        let probes_before = rig.fake.0.lock().unwrap().probed_queries.len();

        // Roam en0 to a new IP: handle rotates, old echo clears to Unverified until new IP echoes.
        rig.fake.0.lock().unwrap().interfaces = vec![("en0".into(), "10.20.0.5".parse().unwrap())];
        rig.tick(&cfg, 10);
        let h2 = rig.engine.active_handle().unwrap().to_string();
        {
            let inner = rig.fake.0.lock().unwrap();
            assert!(inner.probed_queries.len() > probes_before);
            assert_eq!(
                inner.registers.len(),
                2,
                "interface change must rotate handle"
            );
            assert_eq!(
                inner.registers[1].addrs,
                vec!["10.20.0.5".parse::<IpAddr>().unwrap()]
            );
        }
        assert_eq!(rig.state().0, State::Unverified);
        rig.event(
            resolved(&h2, &["10.20.0.5"], &[("v", "1"), ("id", &h2)]),
            11,
        );
        assert_eq!(rig.state().0, State::Active);
    }

    /// M7: `browse_only` (and `mdns.announce: false`) never registers, ignores local triggers,
    /// and still collects candidates.
    #[test]
    fn m7_browse_only_never_announces_and_still_browses() {
        for cfg in [
            inputs_mode(true, AnnounceMode::BrowseOnly),
            inputs(true, false),
        ] {
            let mut rig = Rig::new();
            rig.tick(&cfg, 0);
            assert!(!rig.engine.activate_announce_window(&cfg, rig.at(1)));
            rig.trigger.store(true, std::sync::atomic::Ordering::SeqCst);
            rig.step(&cfg, 2);
            assert!(rig.fake.0.lock().unwrap().registers.is_empty());
            assert_eq!(rig.announce_state(2), AnnounceState::AtRest);

            rig.event(
                resolved("peer", &["10.9.4.1"], &[("v", "1"), ("id", "peer1")]),
                3,
            );
            assert_eq!(rig.candidates(3), vec!["10.9.4.1:7788".parse().unwrap()]);
        }
    }

    /// Pinned-only / account-free nodes can announce without any CA root when `--fed-listen` has
    /// a dialable LAN address; missing or undialable `--fed-listen` stays at rest.
    #[test]
    fn announce_works_without_ca_root_and_refuses_undialable_listen() {
        let mut rig = Rig::new();
        let cfg = inputs_mode(true, AnnounceMode::Always);
        rig.tick(&cfg, 0);
        assert_eq!(rig.announce_state(0), AnnounceState::Always);
        assert_eq!(rig.fake.0.lock().unwrap().registers.len(), 1);

        // No `--fed-listen`: withdraws announcement and falls back to at_rest.
        rig.tick(
            &Inputs {
                fed_listen: None,
                ..cfg.clone()
            },
            30,
        );
        assert_eq!(rig.announce_state(30), AnnounceState::AtRest);
        assert_eq!(rig.fake.0.lock().unwrap().current_registered, None);

        // `--fed-listen` not on any interface: refused.
        rig.tick(
            &Inputs {
                fed_listen: Some("192.0.2.9:7788".parse().unwrap()),
                ..cfg
            },
            60,
        );
        assert_eq!(rig.announce_state(60), AnnounceState::AtRest);
        assert_eq!(rig.fake.0.lock().unwrap().registers.len(), 1);
    }

    #[test]
    fn s1_flood_is_capped() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, false), 0);
        for i in 0..1000u16 {
            let ip = format!("10.9.{}.{}", i / 250, (i % 250) + 1);
            rig.event(resolved(&format!("peer-{i}"), &[&ip], &[("id", "x")]), 1);
        }
        assert_eq!(rig.candidates(1).len(), MDNS_CAP);
    }

    #[test]
    fn removal_three_times_is_idempotent() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, false), 0);
        rig.event(resolved("sys1", &["10.9.4.1"], &[("id", "sys")]), 1);
        assert_eq!(rig.candidates(1).len(), 1);
        for t in [2, 4, 6] {
            rig.event(
                Event::Removed {
                    fullname: format!("sys1.{SERVICE_TYPE}"),
                },
                t,
            );
            assert!(rig.candidates(t).is_empty());
        }
    }

    #[test]
    fn loopback_and_link_local_are_refused() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, false), 0);
        rig.event(
            resolved(
                "sys1",
                &[
                    "10.9.3.2",
                    "127.0.0.1",
                    "169.254.1.2",
                    "::1",
                    "fe80::1",
                    "fe80::c94:1",
                ],
                &[("id", "sys")],
            ),
            1,
        );
        assert_eq!(rig.candidates(1), vec!["10.9.3.2:7788".parse().unwrap()]);
        assert_eq!(rig.engine.dropped(), 5);
    }

    #[test]
    fn malformed_records_are_ignored_and_extra_keys_dropped() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, false), 0);
        // Unsupported protocol version `v=2`, empty `id`, and oversized `id` are rejected whole.
        rig.event(
            resolved("bad1", &["10.9.4.1"], &[("v", "2"), ("id", "ok")]),
            1,
        );
        rig.event(resolved("bad2", &["10.9.4.2"], &[("id", "")]), 1);
        rig.event(
            resolved("bad3", &["10.9.4.3"], &[("id", &"x".repeat(65))]),
            1,
        );
        rig.event(
            Event::Resolved {
                fullname: format!("bad4.{SERVICE_TYPE}"),
                port: 0,
                addrs: vec![("10.9.4.4".parse().unwrap(), vec!["en0".into()])],
                txt: vec![],
            },
            1,
        );
        assert!(rig.candidates(1).is_empty());
        // Extra keys are ignored while valid address is kept.
        rig.event(
            resolved("good", &["10.9.4.5"], &[("id", "ok"), ("extra", "ignored")]),
            1,
        );
        assert_eq!(rig.candidates(1).len(), 1);
    }

    #[test]
    fn a_resolve_with_fewer_addresses_drops_the_rest() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, false), 0);
        rig.event(resolved("peer", &["10.9.4.1", "10.9.4.2"], &[]), 1);
        assert_eq!(rig.candidates(1).len(), 2);
        rig.event(resolved("peer", &["10.9.4.2"], &[]), 2);
        assert_eq!(rig.candidates(2), vec!["10.9.4.2:7788".parse().unwrap()]);
    }

    #[test]
    fn ttl_bounds_a_candidate_and_ticks_refresh_live_ones() {
        let mut rig = Rig::new();
        let mut cfg = inputs(true, false);
        cfg.ttl_secs = 20;
        rig.tick(&cfg, 0);
        rig.event(resolved("peer", &["10.9.4.1"], &[]), 1);
        assert_eq!(rig.candidates(20).len(), 1);
        assert!(rig.candidates(21).is_empty());
        rig.event(resolved("peer", &["10.9.4.1"], &[]), 22);
        rig.tick(&cfg, 30);
        assert_eq!(rig.candidates(45).len(), 1);
        assert!(rig.candidates(51).is_empty());
    }

    #[test]
    fn turning_the_key_off_stops_and_clears() {
        let mut rig = Rig::new();
        let cfg = inputs_mode(true, AnnounceMode::Always);
        rig.tick(&cfg, 0);
        rig.event(resolved("peer", &["10.9.4.1"], &[]), 1);
        assert_eq!(rig.candidates(1).len(), 1);
        rig.tick(&Inputs::default(), 30);
        assert!(rig.candidates(30).is_empty());
        assert_eq!(rig.state().0, State::Off);
        assert_eq!(rig.announce_state(30), AnnounceState::AtRest);
        assert_eq!(rig.fake.0.lock().unwrap().stops, 1);
    }

    #[test]
    fn a_gone_interface_drops_its_candidates() {
        let mut rig = Rig::new();
        rig.fake.0.lock().unwrap().interfaces = vec![
            ("en0".into(), "10.9.3.2".parse().unwrap()),
            ("en1".into(), "10.8.0.2".parse().unwrap()),
        ];
        rig.tick(&inputs(true, false), 0);
        rig.event(resolved("wifi", &["10.9.4.1"], &[]), 1);
        rig.fake.0.lock().unwrap().interfaces = vec![("en1".into(), "10.8.0.2".parse().unwrap())];
        rig.tick(&inputs(true, false), 30);
        assert!(rig.candidates(30).is_empty());
    }

    /// Review C & N4: a shared address survives one instance removal, and 300 rotated instances
    /// sharing a live address without goodbyes evict the oldest instance rather than wedging the
    /// 256-instance cap.
    #[test]
    fn a_shared_address_survives_one_instance_removal() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, false), 0);
        rig.event(resolved("old", &["10.9.4.1"], &[("id", "1")]), 1);
        rig.event(resolved("new", &["10.9.4.1"], &[("id", "2")]), 2);
        rig.event(
            Event::Removed {
                fullname: format!("old.{SERVICE_TYPE}"),
            },
            3,
        );
        assert_eq!(rig.candidates(3), vec!["10.9.4.1:7788".parse().unwrap()]);
        rig.event(
            Event::Removed {
                fullname: format!("new.{SERVICE_TYPE}"),
            },
            4,
        );
        assert!(rig.candidates(4).is_empty());

        for i in 0..300u64 {
            rig.event(
                resolved(&format!("rot-{i}"), &["10.9.4.2"], &[("id", "rot")]),
                10 + i,
            );
        }
        assert!(rig.engine.instance_count() <= 256);
        rig.event(resolved("fresh-peer", &["10.9.4.99"], &[("id", "f")]), 400);
        let cands = rig.candidates(400);
        assert!(
            cands.contains(&"10.9.4.99:7788".parse().unwrap()),
            "{cands:?}"
        );
    }

    #[test]
    fn a_responder_error_is_failed_not_permission_suspected() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, true), 0);
        rig.event(Event::Failed("recv loop died".into()), 5);
        let (state, detail) = rig.state();
        assert_eq!(state, State::Failed);
        assert!(detail.contains("recv loop died"), "{detail}");
        assert!(rig.candidates(5).is_empty());
    }

    #[test]
    fn the_bind_probe_reports_a_held_port() {
        // 1. Exclusive UDP holder on 0.0.0.0:0 (no drop-and-rebind gap) refuses `probe_bind`.
        let exclusive = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = exclusive.local_addr().unwrap().port();
        let err = probe_bind(port).expect_err("exclusive socket held the port");
        assert!(err.contains(&port.to_string()), "{err}");

        // 2. Forced-race control: dropping `exclusive` returns `port` to the OS ephemeral pool,
        // where a concurrent exclusive `UdpSocket::bind` can grab it before `probe_bind(port)`.
        drop(exclusive);
        if let Ok(_interloper) = std::net::UdpSocket::bind(("0.0.0.0", port)) {
            assert!(
                probe_bind(port).is_err(),
                "forced exclusive interloper must fail probe_bind"
            );
        }

        // 3. Race-free positive arms: `probe_bind(0)` selects a kernel-free port, and a
        // reuse-enabled (`SO_REUSEADDR` + `SO_REUSEPORT`) peer keeps its port out of the OS
        // exclusive ephemeral pool while allowing `probe_bind` to coexist under UDP churn.
        probe_bind(0).expect("kernel-assigned port binds");
        let shared = {
            use std::os::fd::FromRawFd;
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            assert!(fd >= 0, "open UDP socket");
            let one: libc::c_int = 1;
            unsafe {
                assert_eq!(
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_REUSEADDR,
                        (&raw const one).cast(),
                        std::mem::size_of_val(&one) as libc::socklen_t,
                    ),
                    0
                );
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEPORT,
                    (&raw const one).cast(),
                    std::mem::size_of_val(&one) as libc::socklen_t,
                );
                let mut addr: libc::sockaddr_in = std::mem::zeroed();
                #[cfg(target_os = "macos")]
                {
                    addr.sin_len = std::mem::size_of_val(&addr) as u8;
                }
                addr.sin_family = libc::AF_INET as libc::sa_family_t;
                assert_eq!(
                    libc::bind(
                        fd,
                        (&raw const addr).cast(),
                        std::mem::size_of_val(&addr) as libc::socklen_t,
                    ),
                    0
                );
                std::net::UdpSocket::from_raw_fd(fd)
            }
        };
        let shared_port = shared.local_addr().unwrap().port();
        for _ in 0..100 {
            let _churn = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
            probe_bind(shared_port).expect("reuse-shared port binds without ephemeral race");
        }
        drop(shared);
    }

    #[test]
    fn a_failure_warns_once_per_cause() {
        let mut rig = Rig::new();
        rig.fake.0.lock().unwrap().start_err = Some("bind 5353".into());
        for t in [0, 30, 60] {
            rig.tick(&inputs(true, true), t);
        }
        assert_eq!(rig.engine.warnings(), 1);
        rig.fake.0.lock().unwrap().start_err = Some("other".into());
        rig.tick(&inputs(true, true), 90);
        assert_eq!(rig.engine.warnings(), 2);
    }

    #[test]
    fn announced_addresses_are_dialable() {
        let ifs = vec![
            ("en0".into(), "10.9.3.2".parse().unwrap()),
            ("en0".into(), "169.254.3.3".parse().unwrap()),
            ("en0".into(), "fe80::1".parse().unwrap()),
            ("en0".into(), "2001:db8::2".parse().unwrap()),
        ];
        assert_eq!(
            announce_addrs("0.0.0.0:7788".parse().unwrap(), &ifs),
            vec!["10.9.3.2".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            announce_addrs("[::]:7788".parse().unwrap(), &ifs),
            vec![
                "10.9.3.2".parse::<IpAddr>().unwrap(),
                "2001:db8::2".parse().unwrap(),
            ]
        );
        assert_eq!(
            announce_addrs("10.9.3.2:7788".parse().unwrap(), &ifs),
            vec!["10.9.3.2".parse::<IpAddr>().unwrap()]
        );
        assert!(announce_addrs("127.0.0.1:7788".parse().unwrap(), &ifs).is_empty());
        assert!(announce_addrs("169.254.3.3:7788".parse().unwrap(), &ifs).is_empty());

        let mut rig = Rig::new();
        rig.fake.0.lock().unwrap().interfaces =
            vec![("en0".into(), "169.254.3.3".parse().unwrap())];
        rig.tick(
            &Inputs {
                fed_listen: Some("169.254.3.3:7788".parse().unwrap()),
                ..inputs_mode(true, AnnounceMode::Always)
            },
            0,
        );
        assert_eq!(rig.announce_state(0), AnnounceState::AtRest);
        assert!(rig.fake.0.lock().unwrap().registers.is_empty());
    }

    /// Review C & N3: `getrandom` failure skips sending any predictable/all-zero multicast probe,
    /// and at activation or on a 30 s rotation withdraws any active announcement and falls back to
    /// browse-only at rest while keeping browse active.
    #[test]
    fn getrandom_failure_degrades_to_browse_only_at_start_and_rotation() {
        let mut rig = Rig::with_id_gen(Box::new(|| Err("entropy unavailable".into())));
        let cfg = inputs_mode(true, AnnounceMode::Timed);
        rig.tick(&cfg, 0);
        // N3: probe is skipped rather than emitting an all-zero query label.
        assert!(rig.fake.0.lock().unwrap().probed_queries.is_empty());
        assert_eq!(rig.state().0, State::Unverified);
        assert!(!rig.engine.activate_announce_window(&cfg, rig.at(1)));
        assert!(rig.fake.0.lock().unwrap().registers.is_empty());
        assert_eq!(rig.announce_state(1), AnnounceState::AtRest);
        assert_eq!(rig.engine.warnings(), 1);

        // Succeeds for startup probe + first handle (2 calls), fails on the 30 s rotation ->
        // withdraws old record & returns to at_rest.
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut rig2 = Rig::with_id_gen(Box::new(move || {
            let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n < 2 {
                Ok(format!("{:032x}", n + 1))
            } else {
                Err("entropy exhausted".into())
            }
        }));
        rig2.tick(&cfg, 0);
        assert!(rig2.engine.activate_announce_window(&cfg, rig2.at(1)));
        assert_eq!(rig2.announce_state(1), AnnounceState::WindowOpen(120));
        rig2.step(&cfg, 31);
        assert_eq!(rig2.announce_state(31), AnnounceState::AtRest);
        assert_eq!(rig2.fake.0.lock().unwrap().current_registered, None);
    }

    /// End-to-end address-less discovery: with the `mdns` backend compiled in and `discovery.mdns`
    /// enabled, an exact-URI CA peer with no static `address` loads through `PeersMap`, receives a
    /// candidate written by `mdns::Engine` into `FedState.discovery.candidates` (waking
    /// `FedState.discovery.changed` via `notify_one()`), ignores untrusted TXT `root` claims
    /// (`root_fp: None`), and establishes an authenticated direct mutual-TLS connection via
    /// `resolve_dial`. Pin-only and unconfigured address-less entries remain refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn addressless_exact_ca_peer_dials_discovered_mdns_candidate_and_notifies_sweep() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // 1. Build a test CA and issue an exact-URI peer certificate.
        let peer_name = "alice.lanpeer";
        let peer_uri = "spiffe://mdns-e2e.test/host/lanpeer/user/alice";
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "mdns e2e fixture CA");
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();

        let peer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut peer_params = rcgen::CertificateParams::default();
        peer_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, peer_name);
        peer_params.subject_alt_names = vec![rcgen::SanType::URI(
            peer_uri.to_string().try_into().unwrap(),
        )];
        peer_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        peer_params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let peer_cert_der = peer_params
            .signed_by(&peer_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
            .unwrap()
            .der()
            .to_vec();
        let peer_key_der = peer_key.serialize_der();

        let dir = tempdir().unwrap();
        let ca_file = dir.path().join("ca.pem");
        fs::write(&ca_file, &ca_pem).unwrap();

        // 2. Admission contract with mDNS compiled and configured:
        //    - exact-URI CA entry without `address` is accepted when `discovery.mdns` is on;
        //    - pin-only and unconfigured-discovery address-less entries are refused.
        let peers_json = json!({
            "discovery": { "mdns": {}, "ttl_secs": 120 },
            "peers": {
                peer_name: {
                    "ca": ca_file,
                    "identities": [peer_uri],
                    "allow": ["send"]
                }
            }
        });
        let peers = xmsg::fed::PeersMap::load_from_json(&peers_json.to_string())
            .expect("exact-URI CA peer without address must load with mDNS enabled");

        let unconfigured = json!({
            "peers": {
                peer_name: { "ca": ca_file, "identities": [peer_uri], "allow": ["send"] }
            }
        });
        assert!(
            xmsg::fed::PeersMap::load_from_json(&unconfigured.to_string())
                .unwrap_err()
                .contains("missing required field 'address'"),
            "address-less CA peer must fail when discovery is not configured"
        );
        let (_, _, rogue_pin) = xmsg::fed::generate_self_signed_ed25519("pin-only").unwrap();
        let pin_only = json!({
            "discovery": { "mdns": {} },
            "peers": { "pinned": { "pin": rogue_pin, "allow": ["send"] } }
        });
        assert!(
            xmsg::fed::PeersMap::load_from_json(&pin_only.to_string())
                .unwrap_err()
                .contains("missing required field 'address'"),
            "pin-only peer without address must remain refused even with mDNS enabled"
        );

        let (client_cert, client_key, client_pin) =
            xmsg::fed::generate_self_signed_ed25519("mdns-e2e-client").unwrap();
        let db = rusqlite::Connection::open_in_memory().unwrap();
        xmsg::storage::init_db(&db).unwrap();
        let fs = Arc::new(xmsg::fed::FedState {
            discovery: Default::default(),
            node_name: xmsg::node::node_name_from_cert(&client_cert).unwrap(),
            peers: Arc::new(peers).into(),
            cert_der: client_cert,
            cert_chain_der: Vec::new(),
            key_der: client_key,
            rate_limiter: Arc::new(xmsg::fed::RateLimiter::new(60, 20)),
            db: Arc::new(std::sync::Mutex::new(db)),
            sessions_dirs: vec![dir.path().join("sessions")],
            agy_config: xmsg::agy::AgyConfig {
                presence_dir: dir.path().join("presence"),
                brain_dir: dir.path().join("brain"),
                ..Default::default()
            },
            agy_store: xmsg::agy::new_agy_store(),
            pi_store: xmsg::pi::new_pi_store(),
            pi_notify_tx: tokio::sync::broadcast::channel(16).0,
            svc_store: xmsg::svc::new_svc_store(),
            svc_notify_tx: tokio::sync::broadcast::channel(16).0,
            notify_tx: tokio::sync::broadcast::channel(16).0,
            max_body: 65536,
            max_attachment_bytes: 8 * 1024 * 1024,
            is_leaf: false,
            leaf_principal: None,
            outbound_replies_pushed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            dynamic_tls: Default::default(),
            reply_ttl: Duration::from_secs(3600),
            list_queries: Default::default(),
        });

        // 3. Wire `mdns::Engine` directly onto the SOLE `FedState.discovery.{candidates, changed}`
        //    and verify both candidate insertion and removal wake `changed.notified()`.
        let fake = Fake::default();
        fake.0.lock().unwrap().interfaces = vec![("en0".into(), "10.9.3.2".parse().unwrap())];
        let mut engine = Engine::with_notify(
            fake.clone(),
            Box::new(|| Ok("0123456789abcdef0123456789abcdef".into())),
            fs.discovery.mdns_status.clone(),
            fs.discovery.candidates.clone(),
            fs.discovery.changed.clone(),
            fs.discovery.mdns_trigger.clone(),
        );
        let cfg = inputs_mode(true, AnnounceMode::Timed);
        let now = Instant::now();
        engine.reconcile(&cfg, now);

        // Start a real mutual-TLS server for `alice.lanpeer`. Prefer an active non-loopback LAN
        // interface so the candidate flows straight through `mdns::Engine::handle` -> `upsert`;
        // fall back to loopback (`inject_for_test`) only in sandboxed environments with no LAN IP.
        let lan_listener = xmsg::discovery::mdns::MdnsSd::default()
            .interfaces()
            .into_iter()
            .find_map(|(_, ip)| {
                if xmsg::discovery::acceptable_ip(ip) {
                    std::net::TcpListener::bind(SocketAddr::new(ip, 0)).ok()
                } else {
                    None
                }
            });
        let (std_listener, used_lan_ip) = match lan_listener {
            Some(l) => (l, true),
            None => (std::net::TcpListener::bind("127.0.0.1:0").unwrap(), false),
        };
        std_listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
        let peer_addr = listener.local_addr().unwrap();

        let server_peers = Arc::new(
            xmsg::fed::PeersMap::load_from_json(
                &json!({
                    "peers": {
                        "client": { "address": "127.0.0.1:9", "pin": client_pin, "allow": ["send"] }
                    }
                })
                .to_string(),
            )
            .unwrap(),
        );
        let acceptor = xmsg::fed::make_tls_acceptor(
            &[rustls::pki_types::CertificateDer::from(peer_cert_der)],
            &peer_key_der,
            server_peers,
        )
        .unwrap();
        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _tls = acceptor.accept(tcp).await.unwrap();
        });

        // Always verify `mdns::Engine::handle` wakes `fs.discovery.changed` on a dialable LAN IP
        // and strips untrusted TXT `root` claims (`root_fp: None`).
        let probe_addr: SocketAddr = if used_lan_ip {
            peer_addr
        } else {
            "10.9.3.77:7788".parse().unwrap()
        };
        let notified = fs.discovery.changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        engine.handle(
            Event::Resolved {
                fullname: "peer-e2e._xmsg._tcp.local.".into(),
                port: probe_addr.port(),
                addrs: vec![(probe_addr.ip(), vec!["en0".into()])],
                txt: vec![
                    ("v".into(), "1".into()),
                    ("id".into(), "abcdef0123456789abcdef0123456789".into()),
                    ("root".into(), "aa".repeat(32)),
                ],
            },
            now,
        );
        tokio::time::timeout(Duration::from_millis(200), notified)
            .await
            .expect("mdns::Engine candidate upsert must wake FedState.discovery.changed");
        {
            let snap = fs.discovery.candidates.read().unwrap().snapshot(now);
            let inserted = snap
                .iter()
                .find(|c| c.addr == probe_addr)
                .expect("mdns::Engine must write into FedState.discovery.candidates");
            assert_eq!(
                inserted.root_fp, None,
                "mDNS must ignore untrusted TXT root claims"
            );
        }

        if !used_lan_ip {
            // Sandboxed environment (no non-loopback LAN IP): remove the non-dialable probe and
            // verify removal wakes `changed`, then inject the local loopback TLS listener.
            let rem_notified = fs.discovery.changed.notified();
            tokio::pin!(rem_notified);
            rem_notified.as_mut().enable();
            engine.handle(
                Event::Removed {
                    fullname: "peer-e2e._xmsg._tcp.local.".into(),
                },
                now,
            );
            tokio::time::timeout(Duration::from_millis(200), rem_notified)
                .await
                .expect("mdns::Engine candidate removal must wake FedState.discovery.changed");
            fs.discovery
                .candidates
                .write()
                .unwrap()
                .inject_for_test(xmsg::discovery::Candidate {
                    addr: peer_addr,
                    source: xmsg::discovery::Source::Mdns,
                    hint: Some("abcdef0123456789abcdef0123456789".into()),
                    root_fp: None,
                    seen_at: now,
                    expires_at: now + Duration::from_secs(60),
                });
        }

        // 4. End-to-end direct mutual-TLS dial to the address-less exact-URI CA peer!
        let peer_cfg = fs.current_peers().get_peer_config(peer_name).unwrap();
        assert!(peer_cfg.address.is_empty(), "peer has no static address");
        let dial = xmsg::discovery::dial::resolve_dial(&fs, &peer_cfg)
            .await
            .expect("resolve_dial must establish direct mTLS to discovered candidate");
        assert!(
            dial.via_hub().is_none(),
            "discovered peer must dial direct, not via hub"
        );
        let direct = dial
            .into_direct()
            .expect("discovered peer must yield direct TLS stream");
        server_task.await.unwrap();
        drop(direct);
    }

    /// M5 & S-1 (macOS): the real responder binds beside mDNSResponder, receives a record
    /// registered with `dns-sd -R`, and keeps ONE long-lived browse receiver across `register`
    /// rotations so a `ServiceRemoved` queued right before a rotation is still applied.
    #[cfg(target_os = "macos")]
    #[test]
    fn m5_receives_a_record_registered_with_dns_sd() {
        use xmsg::discovery::mdns::MdnsSd;
        let candidates = SharedCandidates::default();
        let status = SharedStatus::default();
        let mut engine = Engine::new(
            MdnsSd::default(),
            Box::new(random_id),
            status,
            candidates.clone(),
        );
        let cfg = inputs_mode(true, AnnounceMode::Timed);
        engine.reconcile(&cfg, Instant::now());
        assert_ne!(
            engine.state(),
            State::Failed,
            "mdns-sd starts beside mDNSResponder"
        );

        let name = format!("xmsg-m5-{}", std::process::id());
        let child = Kill(
            Command::new("/usr/bin/dns-sd")
                .args(["-R", &name, "_xmsg._tcp", "local", "47791", "v=1", "id=m5"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn dns-sd"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut got = None;
        while got.is_none() && Instant::now() < deadline {
            if let Some(ev) = engine.backend.recv(Duration::from_secs(1)) {
                if let Event::Resolved {
                    ref fullname,
                    port,
                    ref txt,
                    ..
                } = ev
                {
                    if fullname.starts_with(&name) {
                        got = Some((port, txt.clone()));
                    }
                }
                engine.handle(ev, Instant::now());
            }
        }
        let (port, got_txt) = got.expect("no record from dns-sd -R within 20 s");
        assert_eq!(port, 47791);
        assert!(got_txt.contains(&("v".into(), "1".into())), "{got_txt:?}");
        assert!(got_txt.contains(&("id".into(), "m5".into())), "{got_txt:?}");

        // Drain any remaining initial events before stopping `dns-sd -R`.
        while let Some(ev) = engine.backend.recv(Duration::from_millis(200)) {
            engine.handle(ev, Instant::now());
        }

        // S-1 forced control: stop `dns-sd -R` so `ServiceRemoved` queues in `backend.events`
        // BEFORE we rotate/register our own service, then rotate, then drain and verify removal.
        drop(child);
        let q_deadline = Instant::now() + Duration::from_secs(15);
        while !engine.backend.has_queued_events() && Instant::now() < q_deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            engine.backend.has_queued_events(),
            "goodbye event did not queue in mdns-sd receiver within 15 s"
        );
        // Let macOS mDNSResponder finish its 3× 2 s goodbye burst into the receiver queue before
        // rotating, so a per-register re-browse would drop all of them.
        std::thread::sleep(Duration::from_millis(4500));

        let rot_id = random_id().unwrap();
        let mut reg_addrs = announce_addrs(
            "0.0.0.0:47792".parse().unwrap(),
            &engine.backend.interfaces(),
        );
        if reg_addrs.is_empty() {
            reg_addrs.push("10.0.0.1".parse().unwrap());
        }
        engine
            .backend
            .register(&rot_id, 47792, &reg_addrs, &txt(&rot_id))
            .expect("register rotation on real MdnsSd");
        engine.backend.unregister();

        let mut saw_removed = false;
        let drain_until = Instant::now() + Duration::from_secs(3);
        while Instant::now() < drain_until {
            let Some(ev) = engine.backend.recv(Duration::from_millis(250)) else {
                if saw_removed {
                    break;
                }
                continue;
            };
            if let Event::Removed { ref fullname } = ev {
                if fullname.starts_with(&name) {
                    saw_removed = true;
                }
            }
            engine.handle(ev, Instant::now());
        }
        engine.backend.stop();
        assert!(
            saw_removed,
            "ServiceRemoved queued before register rotation was lost"
        );
        let remaining: Vec<SocketAddr> = candidates
            .read()
            .unwrap()
            .snapshot(Instant::now())
            .into_iter()
            .map(|c| c.addr)
            .filter(|a| a.port() == 47791)
            .collect();
        assert!(
            remaining.is_empty(),
            "stale candidate survived after queued ServiceRemoved: {remaining:?}"
        );
    }
}
