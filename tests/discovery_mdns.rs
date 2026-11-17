//! LAN discovery: the `discovery` key, the mDNS source's logic through its injected
//! backend, the health and announce-posture fields, the doctor checks, and (macOS only)
//! coexistence with mDNSResponder.
//!
//! The engine tests drive `Engine` through a fake `Backend`, so they need no multicast network.
//! Only two tests touch the real network, both gated to macOS, where mDNSResponder is always
//! present: `m1_configured_serve_opens_5353` and `m5_receives_a_record_registered_with_dns_sd`.

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

/// Whether process `pid` holds a UDP socket bound to `port`.
#[cfg(target_os = "linux")]
fn udp_port_open(pid: u32, port: u16) -> bool {
    let inodes: std::collections::HashSet<String> = fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("read fds")
        .filter_map(|e| fs::read_link(e.ok()?.path()).ok())
        .filter_map(|l| {
            let l = l.to_string_lossy().into_owned();
            Some(l.strip_prefix("socket:[")?.strip_suffix(']')?.to_string())
        })
        .collect();
    let suffix = format!(":{port:04X}");
    ["udp", "udp6"].iter().any(|table| {
        fs::read_to_string(format!("/proc/{pid}/net/{table}"))
            .unwrap_or_default()
            .lines()
            .skip(1)
            .any(|row| {
                let cols: Vec<&str> = row.split_whitespace().collect();
                cols.len() > 9 && cols[1].ends_with(&suffix) && inodes.contains(cols[9])
            })
    })
}

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

    // `unverified` must never read as Pass in doctor's summary (Warn until Info lands on main).
    let unverified = doctor_with_health(health(
        "unverified",
        json!({"window_open": 95}),
        "timed",
        "no own-LAN reply",
    ));
    let uv = doctor_check(&unverified, "discovery.mdns").unwrap();
    assert_eq!(uv["status"], "warn", "unverified must never pass: {uv}");
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
        announce_addrs, build_mdns_a_query, ln_query_name, probe_bind, random_id, txt, Backend,
        Engine, Event, Inputs, LnQueryMode, ProbeOutcome, ANNOUNCE_WINDOW, IP_CHECK_SECS,
        LN_DEBOUNCE_CONSECUTIVE, LN_PROBE_RETRY_INTERVAL, LN_QUERY_MODE, PROTOCOL_VERSION,
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
            inner
                .default_probe
                .clone()
                .unwrap_or(ProbeOutcome::SentNoReply)
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
            let engine = Engine::with_trigger_and_query(
                fake.clone(),
                id_gen,
                LN_QUERY_MODE,
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

    /// M2 & P14: TXT carries only `v=1` and a 128-bit hex `id` — never `root`, node name, user
    /// or host name; incoming `root` keys from peers are ignored (`root_fp == None`).
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

    /// P14: At startup, `timed` (default) is browse-only at rest; `activate_announce_window` (or
    /// the local trigger hook) opens a 120 s window, rotates handle + instance + target hostname
    /// every 30 s and unregisters the old record each time, then expires back to `at_rest`.
    #[test]
    fn p14_timed_startup_is_at_rest_rotates_every_30s_and_expires_at_120s() {
        assert_eq!(ANNOUNCE_WINDOW, Duration::from_secs(120));
        assert_eq!(ROTATE_INTERVAL, Duration::from_secs(30));

        let mut rig = Rig::new();
        let cfg = inputs_mode(true, AnnounceMode::Timed);

        // Startup: browse-only at rest — zero registrations.
        rig.tick(&cfg, 0);
        assert_eq!(rig.announce_state(0), AnnounceState::AtRest);
        assert!(
            rig.fake.0.lock().unwrap().registers.is_empty(),
            "timed mode must never announce at startup"
        );

        // Local activation via trigger hook at t = 10 s opens [10, 130).
        rig.trigger.store(true, std::sync::atomic::Ordering::SeqCst);
        rig.step(&cfg, 10);
        assert_eq!(rig.announce_state(10), AnnounceState::WindowOpen(120));
        assert_eq!(rig.announce_state(25), AnnounceState::WindowOpen(105));
        {
            let inner = rig.fake.0.lock().unwrap();
            assert_eq!(inner.registers.len(), 1);
            assert_eq!(inner.registers[0].id, format!("{:032x}", 1));
            assert_eq!(
                inner.registers[0].fullname,
                format!("{:032x}.{SERVICE_TYPE}", 1)
            );
            assert_eq!(inner.registers[0].host, format!("{:032x}.local.", 1));
            assert!(inner.unregisters.is_empty());
        }

        // Self-echo of active handle must never enter CandidateTable.
        let h1 = format!("{:032x}", 1);
        rig.event(resolved(&h1, &["10.9.3.2"], &[("v", "1"), ("id", &h1)]), 15);
        assert!(rig.candidates(15).is_empty(), "own handle entered table");

        // At t = 40 s (+30 s): rotates to handle #2 and unregisters handle #1.
        rig.step(&cfg, 40);
        {
            let inner = rig.fake.0.lock().unwrap();
            assert_eq!(inner.registers.len(), 2);
            assert_eq!(
                inner.unregisters,
                vec![format!("{:032x}.{SERVICE_TYPE}", 1)]
            );
            assert_eq!(inner.registers[1].id, format!("{:032x}", 2));
            assert_eq!(
                inner.registers[1].fullname,
                format!("{:032x}.{SERVICE_TYPE}", 2)
            );
            assert_eq!(inner.registers[1].host, format!("{:032x}.local.", 2));
        }

        // Delayed cached replay of retired handle #1 is still ignored.
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

        // At t = 130 s (120 s elapsed): window expires, handle #4 unregisters, returns to at_rest.
        rig.step(&cfg, 130);
        assert_eq!(rig.announce_state(130), AnnounceState::AtRest);
        assert_eq!(rig.engine.active_handle(), None);
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

    /// M4 & P15: Debounced non-announcing multicast detector:
    /// - 1 or 2 `EHOSTUNREACH` errors followed by `SentNoReply` reset the streak (debounced);
    /// - 3 consecutive `EHOSTUNREACH` errors report `permission_suspected`, never proven;
    /// - `SentNoReply` reports `unverified`, never `active`;
    /// - only a genuine own-LAN IPv4 reply reports `active` (foreign or loopback replies do not).
    #[test]
    fn m4_p15_multicast_detector_debounces_and_requires_own_lan_reply() {
        assert_eq!(LN_DEBOUNCE_CONSECUTIVE, 3);
        assert_eq!(LN_PROBE_RETRY_INTERVAL, Duration::from_secs(2));

        let mut rig = Rig::new();
        {
            let mut inner = rig.fake.0.lock().unwrap();
            // Transient single EHOSTUNREACH (as observed in `allowed-3`), then SentNoReply.
            inner
                .probe_outcomes
                .push_back(ProbeOutcome::SendBlocked("EHOSTUNREACH".into()));
            inner.probe_outcomes.push_back(ProbeOutcome::SentNoReply);
        }
        let cfg = inputs_mode(true, AnnounceMode::BrowseOnly);

        // t = 0: first EHOSTUNREACH -> still Starting (debounced, streak = 1).
        rig.tick(&cfg, 0);
        assert_eq!(
            rig.state().0,
            State::Starting,
            "single EHOSTUNREACH must be debounced"
        );
        assert_eq!(rig.engine.warnings(), 0);

        // t = 2: retry gets SentNoReply -> resets streak, state is Unverified (never Active).
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

        // Foreign LAN IP reply (not our en0 10.9.3.2) must NOT become Active.
        rig.fake
            .0
            .lock()
            .unwrap()
            .probe_outcomes
            .push_back(ProbeOutcome::OwnLanReply("10.9.99.99".parse().unwrap()));
        rig.tick(&cfg, 60);
        assert_eq!(
            rig.state().0,
            State::Unverified,
            "foreign LAN reply must not mark Active"
        );

        // Genuine own-LAN reply (10.9.3.2 on en0) -> Active.
        rig.fake
            .0
            .lock()
            .unwrap()
            .probe_outcomes
            .push_back(ProbeOutcome::OwnLanReply("10.9.3.2".parse().unwrap()));
        rig.tick(&cfg, 90);
        assert_eq!(rig.state().0, State::Active);
    }

    /// Privacy: default `LN_QUERY_MODE` is `RandomLabel`, and the wire query packet
    /// discloses zero OS hostname bytes while encoding a valid `A IN` (`RD=0`) DNS query.
    #[test]
    fn p15_default_query_is_random_label_and_hides_hostname() {
        assert_eq!(LN_QUERY_MODE, LnQueryMode::RandomLabel);
        let q1 = ln_query_name(LN_QUERY_MODE);
        let q2 = ln_query_name(LN_QUERY_MODE);
        assert!(q1.ends_with(".local"), "{q1}");
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

        // Documented fallback constant produces `<sanitized-host>.local`.
        let fallback = ln_query_name(LnQueryMode::OsHostname);
        assert!(fallback.ends_with(".local"), "{fallback}");
    }

    #[test]
    fn m4_responder_failure_is_reported_and_retried() {
        let mut rig = Rig::new();
        rig.fake.0.lock().unwrap().start_err = Some("bind 5353: address in use".into());
        rig.tick(&inputs(true, true), 0);
        let (state, detail) = rig.state();
        assert_eq!(state, State::Failed);
        assert!(detail.contains("bind 5353"));
        rig.fake.0.lock().unwrap().start_err = None;
        rig.tick(&inputs(true, true), 30);
        assert_eq!(rig.state().0, State::Unverified);
    }

    /// M6: interface change re-runs the multicast probe and rotates any open announcement handle.
    #[test]
    fn m6_interface_change_reprobes_and_rotates_open_announcement() {
        const { assert!(IP_CHECK_SECS <= 30) };
        let mut rig = Rig::new();
        let cfg = inputs_mode(true, AnnounceMode::Timed);
        rig.tick(&cfg, 0);
        assert!(rig.engine.activate_announce_window(&cfg, rig.at(1)));
        assert_eq!(rig.fake.0.lock().unwrap().registers.len(), 1);
        let probes_before = rig.fake.0.lock().unwrap().probed_queries.len();

        // Roam en0 to a new IP and inject an own-LAN reply for the new IP.
        {
            let mut inner = rig.fake.0.lock().unwrap();
            inner.interfaces = vec![("en0".into(), "10.20.0.5".parse().unwrap())];
            inner
                .probe_outcomes
                .push_back(ProbeOutcome::OwnLanReply("10.20.0.5".parse().unwrap()));
        }
        rig.tick(&cfg, 10);
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
        drop(inner);
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
        let held = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        drop(held);
        let exclusive = std::net::UdpSocket::bind(("0.0.0.0", port)).unwrap();
        let err = probe_bind(port).expect_err("exclusive socket held the port");
        assert!(err.contains(&port.to_string()), "{err}");
        drop(exclusive);
        probe_bind(port).expect("free port binds");
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

    /// Review C: `getrandom` failure at activation or on a 30 s rotation withdraws any active
    /// announcement and falls back to browse-only at rest while keeping browse active.
    #[test]
    fn getrandom_failure_degrades_to_browse_only_at_start_and_rotation() {
        let mut rig = Rig::with_id_gen(Box::new(|| Err("entropy unavailable".into())));
        let cfg = inputs_mode(true, AnnounceMode::Timed);
        rig.tick(&cfg, 0);
        assert!(!rig.engine.activate_announce_window(&cfg, rig.at(1)));
        assert!(rig.fake.0.lock().unwrap().registers.is_empty());
        assert_eq!(rig.announce_state(1), AnnounceState::AtRest);
        assert_eq!(rig.engine.warnings(), 1);

        // Succeeds on first handle, fails on the 30 s rotation -> withdraws old record & at_rest.
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut rig2 = Rig::with_id_gen(Box::new(move || {
            if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Ok("11".repeat(16))
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

    /// M5 (macOS): the real responder binds beside mDNSResponder and receives a record
    /// registered with `dns-sd -R`.
    #[cfg(target_os = "macos")]
    #[test]
    fn m5_receives_a_record_registered_with_dns_sd() {
        use xmsg::discovery::mdns::MdnsSd;
        let mut backend = MdnsSd::default();
        backend
            .start()
            .expect("mdns-sd starts beside mDNSResponder");
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
            if let Some(Event::Resolved {
                fullname,
                port,
                txt,
                ..
            }) = backend.recv(Duration::from_secs(1))
            {
                if fullname.starts_with(&name) {
                    got = Some((port, txt));
                }
            }
        }
        drop(child);
        backend.stop();
        let (port, txt) = got.expect("no record from dns-sd -R within 20 s");
        assert_eq!(port, 47791);
        assert!(txt.contains(&("v".into(), "1".into())), "{txt:?}");
        assert!(txt.contains(&("id".into(), "m5".into())), "{txt:?}");
    }
}
