//! LAN discovery: the `discovery` key, the mDNS source's logic through its injected backend,
//! the health field and the doctor check, and (macOS only) coexistence with mDNSResponder.
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
        .arg(run.join("agent.sock"))
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
    assert_eq!(health["discovery"]["mdns"]["candidates"], 0, "{health}");
    assert!(
        !udp_port_open(node.pid(), 5353),
        "UDP 5353 open without the key"
    );
}

/// M1's positive arm: with the key, the same predicate sees the responder's socket, and serve
/// keeps answering. macOS only: a Linux CI build sandbox may have no multicast interface.
#[cfg(all(target_os = "macos", feature = "mdns"))]
#[test]
fn m1_configured_serve_opens_5353() {
    let node = serve(Some(json!({"mdns": {"announce": false}})));
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = Value::Null;
    while Instant::now() < deadline {
        last = node.health().unwrap();
        if last["discovery"]["mdns"]["state"] == "browse_only" && udp_port_open(node.pid(), 5353) {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("no browse-only responder on 5353: {last}");
}

/// Without the `mdns` feature the key still loads, and health says the source isn't built in.
#[cfg(not(feature = "mdns"))]
#[test]
fn configured_without_the_feature_reports_off() {
    let node = serve(Some(json!({"mdns": {}})));
    let health = node.health().unwrap();
    assert_eq!(health["discovery"]["mdns"]["state"], "off", "{health}");
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
    let ok = check_peers(json!({"mdns": {"browse": true, "announce": false}, "ttl_secs": 300}));
    assert!(ok.status.success(), "{ok:?}");
    let tailnet = check_peers(json!({"tailnet": {"ports": [7788]}}));
    assert!(!tailnet.status.success());
    assert!(String::from_utf8_lossy(&tailnet.stderr).contains("not supported by this build"));
    for bad in [json!({"mdns": {"brwse": true}}), json!({"ttl_secs": 601})] {
        let out = check_peers(bad.clone());
        assert!(!out.status.success(), "{bad} accepted");
    }
}

/// M3: a foreign root is ineligible; no root is eligible for every rule.
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
    assert_eq!(eligible, ["10.1.0.2:7788"]);
    assert_eq!(table.eligible(&[9; 32], now).len(), 2);
}

#[test]
fn root_fingerprint_is_the_ca_certificate_der() {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "team CA");
    let ca = params.self_signed(&key).unwrap();
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("ca.pem");
    fs::write(&path, ca.pem()).unwrap();
    let peers = xmsg::fed::PeersMap::load_from_json(
        &json!({"peers": {"sini.patch": {
            "address": "127.0.0.1:1",
            "ca": path,
            "identities": ["spiffe://team/host/patch/user/sini"],
        }}})
        .to_string(),
    )
    .unwrap();
    let expected = ring::digest::digest(&ring::digest::SHA256, ca.der());
    assert_eq!(
        xmsg::discovery::root_fingerprint(&peers).map(|fp| fp.to_vec()),
        Some(expected.as_ref().to_vec())
    );
    let pinned = xmsg::fed::PeersMap::load_from_json(r#"{"peers": {}}"#).unwrap();
    assert_eq!(xmsg::discovery::root_fingerprint(&pinned), None);
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
fn doctor_reports_the_discovery_state() {
    let health = |state: &str, detail: &str| {
        json!({"status": "ok", "sessions_dir": "ok", "version": "0", "build_revision": "x",
            "discovery": {"mdns": {"state": state, "detail": detail, "since": 1, "candidates": 3}}})
    };
    let silent = doctor_with_health(health("lan_silent", "no LAN echo"));
    let check = doctor_check(&silent, "discovery.mdns").expect("discovery.mdns check");
    assert_eq!(check["status"], "warn", "{check}");
    assert!(check["hint"].as_str().unwrap().contains("Local Network"));
    assert!(check["message"].as_str().unwrap().contains("3 candidates"));
    for (state, status) in [
        ("active", "pass"),
        ("off", "pass"),
        ("browse_only", "pass"),
        ("failed", "warn"),
    ] {
        let report = doctor_with_health(health(state, ""));
        assert_eq!(
            doctor_check(&report, "discovery.mdns").unwrap()["status"],
            status,
            "{state}"
        );
    }
    let fresh = {
        let mut h = health("starting", "");
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
    let stuck = doctor_with_health(health("starting", ""));
    let check = doctor_check(&stuck, "discovery.mdns").unwrap();
    assert_eq!(check["status"], "warn", "{check}");
    assert!(check["hint"].as_str().unwrap().contains("still starting"));
    let old = doctor_with_health(json!({"status": "ok", "sessions_dir": "ok", "version": "0"}));
    assert!(doctor_check(&old, "discovery.mdns").is_none());
}

#[cfg(feature = "mdns")]
mod engine {
    use super::*;
    use std::collections::VecDeque;
    use std::net::IpAddr;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use xmsg::discovery::mdns::{
        announce_addrs, probe_bind, Backend, Engine, Event, Inputs, ECHO_DEADLINE, IP_CHECK_SECS,
        TICK,
    };
    use xmsg::discovery::{MdnsConfig, SharedCandidates, SharedStatus, State, MDNS_CAP};

    type Registration = (String, u16, Vec<IpAddr>, Vec<(String, String)>);

    #[derive(Default)]
    struct Log {
        starts: usize,
        stops: usize,
        registers: Vec<Registration>,
        interfaces: Vec<(String, IpAddr)>,
        events: VecDeque<Event>,
        start_error: Option<String>,
    }

    #[derive(Clone, Default)]
    struct Fake(Arc<Mutex<Log>>);

    impl Backend for Fake {
        fn start(&mut self) -> Result<(), String> {
            let mut log = self.0.lock().unwrap();
            log.starts += 1;
            log.start_error.clone().map_or(Ok(()), Err)
        }
        fn register(
            &mut self,
            id: &str,
            port: u16,
            addrs: &[IpAddr],
            txt: &[(String, String)],
        ) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .registers
                .push((id.into(), port, addrs.to_vec(), txt.to_vec()));
            Ok(())
        }
        fn unregister(&mut self) {}
        fn stop(&mut self) {
            self.0.lock().unwrap().stops += 1;
        }
        fn recv(&mut self, _: Duration) -> Option<Event> {
            self.0.lock().unwrap().events.pop_front()
        }
        fn interfaces(&self) -> Vec<(String, IpAddr)> {
            self.0.lock().unwrap().interfaces.clone()
        }
    }

    const ID: &str = "0011223344556677";
    const ROOT: [u8; 32] = [7; 32];

    struct Rig {
        fake: Fake,
        engine: Engine<Fake>,
        status: SharedStatus,
        table: SharedCandidates,
        t0: Instant,
    }

    impl Rig {
        fn new() -> Self {
            let fake = Fake::default();
            fake.0.lock().unwrap().interfaces = vec![("en0".into(), "10.9.3.2".parse().unwrap())];
            let status = SharedStatus::default();
            let table = SharedCandidates::default();
            let engine = Engine::new(fake.clone(), Ok(ID.into()), status.clone(), table.clone());
            Self {
                fake,
                engine,
                status,
                table,
                t0: Instant::now(),
            }
        }
        fn at(&self, secs: u64) -> Instant {
            self.t0 + Duration::from_secs(secs)
        }
        fn tick(&mut self, inputs: &Inputs, secs: u64) {
            let now = self.at(secs);
            self.engine.reconcile(inputs, now);
            self.engine.check_echo(now);
        }
        fn event(&mut self, event: Event, secs: u64) {
            let now = self.at(secs);
            self.engine.handle(event, now);
            self.engine.check_echo(now);
        }
        fn state(&self) -> (State, String) {
            let s = self.status.lock().unwrap();
            (s.state, s.detail.clone())
        }
        fn candidates(&self, secs: u64) -> Vec<SocketAddr> {
            self.table
                .read()
                .unwrap()
                .snapshot(self.at(secs))
                .iter()
                .map(|c| c.addr)
                .collect()
        }
    }

    fn inputs(browse: bool, announce: bool) -> Inputs {
        Inputs {
            mdns: Some(MdnsConfig { browse, announce }),
            ttl_secs: 600,
            root: Some(ROOT),
            fed_listen: Some("0.0.0.0:7788".parse().unwrap()),
        }
    }

    fn resolved(fullname: &str, addrs: &[&str], txt: &[(&str, &str)]) -> Event {
        Event::Resolved {
            fullname: fullname.into(),
            port: 7788,
            addrs: addrs
                .iter()
                .map(|a| (a.parse().unwrap(), vec!["en0".to_string()]))
                .collect(),
            txt: txt
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn own_echo(addrs: &[&str]) -> Event {
        resolved(&format!("{ID}._xmsg._tcp.local."), addrs, &[("id", ID)])
    }

    #[test]
    fn m1_no_key_starts_nothing() {
        let mut rig = Rig::new();
        rig.tick(&Inputs::default(), 0);
        rig.tick(
            &Inputs {
                mdns: Some(MdnsConfig {
                    browse: false,
                    announce: false,
                }),
                ..inputs(false, false)
            },
            30,
        );
        let log = rig.fake.0.lock().unwrap();
        assert_eq!(log.starts, 0);
        assert!(log.registers.is_empty());
        drop(log);
        assert_eq!(rig.state().0, State::Off);
    }

    /// M2: the announced TXT key set is exactly {id, root}.
    #[test]
    fn m2_txt_is_exactly_id_and_root() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, true), 0);
        let log = rig.fake.0.lock().unwrap();
        let (id, port, _, txt) = log.registers.last().expect("announced").clone();
        assert_eq!((id.as_str(), port), (ID, 7788));
        let mut keys: Vec<&str> = txt.iter().map(|(k, _)| k.as_str()).collect();
        keys.sort();
        assert_eq!(keys, ["id", "root"]);
        assert!(txt.contains(&("id".into(), ID.into())));
        assert!(txt.contains(&("root".into(), "07".repeat(32))));
    }

    /// M4: no LAN echo by the deadline gives lan_silent with the remedy; the source keeps
    /// running, and a later echo flips it to active without a restart.
    #[test]
    fn m4_never_lan_echo_is_lan_silent() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, true), 0);
        assert_eq!(rig.state().0, State::Starting);
        rig.event(own_echo(&["127.0.0.1", "::1", "fe80::1"]), 1);
        assert_eq!(
            rig.state().0,
            State::Starting,
            "a loopback echo is not a LAN echo"
        );
        rig.engine.check_echo(rig.at(ECHO_DEADLINE.as_secs() - 1));
        assert_eq!(rig.state().0, State::Starting);
        rig.engine.check_echo(rig.at(ECHO_DEADLINE.as_secs()));
        let (state, detail) = rig.state();
        assert_eq!(state, State::LanSilent);
        if cfg!(target_os = "macos") {
            assert!(
                detail.contains("System Settings › Privacy & Security › Local Network"),
                "{detail}"
            );
        } else {
            assert!(detail.contains("UDP 5353"), "{detail}");
        }
        // The source keeps working: browse still collects, and the next tick re-announces.
        rig.event(resolved("peer._xmsg._tcp.local.", &["10.9.4.4"], &[]), 20);
        assert_eq!(rig.candidates(20), ["10.9.4.4:7788".parse().unwrap()]);
        let before = rig.fake.0.lock().unwrap().registers.len();
        rig.tick(&inputs(true, true), 30);
        assert_eq!(rig.fake.0.lock().unwrap().registers.len(), before + 1);
        assert_eq!(rig.state().0, State::LanSilent);
        rig.event(own_echo(&["127.0.0.1", "10.9.3.2"]), 31);
        assert_eq!(rig.state().0, State::Active);
    }

    /// M4's other arm: a start failure is reported, not fatal, and retried on the next tick.
    #[test]
    fn m4_responder_failure_is_reported_and_retried() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, true), 0);
        rig.event(Event::Failed("bind refused".into()), 1);
        assert_eq!(rig.state(), (State::Failed, "bind refused".into()));
        rig.tick(&inputs(true, true), 30);
        assert_eq!(rig.fake.0.lock().unwrap().starts, 2);
        assert_eq!(rig.state().0, State::Starting);
    }

    /// M6 (partial): an interface-set change re-triggers the echo check.
    #[test]
    fn m6_interface_change_retriggers_the_echo_check() {
        assert!(IP_CHECK_SECS <= 30 && TICK <= Duration::from_secs(30));
        let mut rig = Rig::new();
        rig.tick(&inputs(true, true), 0);
        rig.event(own_echo(&["10.9.3.2"]), 1);
        assert_eq!(rig.state().0, State::Active);
        rig.tick(&inputs(true, true), 30);
        assert_eq!(
            rig.fake.0.lock().unwrap().registers.len(),
            1,
            "no change, no re-announce"
        );
        rig.fake.0.lock().unwrap().interfaces =
            vec![("en1".into(), "192.168.1.20".parse().unwrap())];
        rig.tick(&inputs(true, true), 60);
        assert_eq!(rig.fake.0.lock().unwrap().registers.len(), 2);
        assert_eq!(rig.state().0, State::Starting);
        rig.engine.check_echo(rig.at(60 + ECHO_DEADLINE.as_secs()));
        assert_eq!(rig.state().0, State::LanSilent);
    }

    /// M7: announce off registers nothing, and browse still collects.
    #[test]
    fn m7_announce_off_still_browses() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, false), 0);
        assert_eq!(rig.fake.0.lock().unwrap().starts, 1);
        assert!(rig.fake.0.lock().unwrap().registers.is_empty());
        assert_eq!(rig.state().0, State::BrowseOnly);
        rig.event(
            resolved(
                "peer._xmsg._tcp.local.",
                &["10.9.4.4"],
                &[("id", "p"), ("root", &"07".repeat(32))],
            ),
            1,
        );
        let table = rig.table.read().unwrap().snapshot(rig.at(1));
        assert_eq!(table.len(), 1);
        assert_eq!(table[0].hint.as_deref(), Some("p"));
        assert_eq!(table[0].root_fp, Some(ROOT));
    }

    #[test]
    fn announce_needs_a_root_and_an_interface_listen_address() {
        let mut rig = Rig::new();
        rig.tick(
            &Inputs {
                root: None,
                ..inputs(true, true)
            },
            0,
        );
        assert_eq!(rig.state().0, State::BrowseOnly);
        rig.tick(
            &Inputs {
                fed_listen: Some("192.0.2.1:7788".parse().unwrap()),
                ..inputs(true, true)
            },
            30,
        );
        assert_eq!(rig.state().0, State::BrowseOnly);
        rig.tick(
            &Inputs {
                fed_listen: None,
                ..inputs(true, true)
            },
            60,
        );
        assert_eq!(rig.state().0, State::BrowseOnly);
        assert!(rig.fake.0.lock().unwrap().registers.is_empty());
        rig.tick(
            &Inputs {
                fed_listen: Some("10.9.3.2:7788".parse().unwrap()),
                ..inputs(true, true)
            },
            90,
        );
        assert_eq!(rig.fake.0.lock().unwrap().registers.len(), 1);
    }

    /// S1: a flood of 1000 announcers leaves at most 64 candidates.
    #[test]
    fn s1_flood_is_capped() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, false), 0);
        for i in 0..1000u32 {
            let addr = format!("10.{}.{}.{}", 100 + (i >> 16), (i >> 8) & 0xff, i & 0xff);
            rig.event(
                resolved(&format!("n{i}._xmsg._tcp.local."), &[&addr], &[]),
                1,
            );
        }
        assert!(rig.candidates(1).len() <= MDNS_CAP);
        assert_eq!(rig.candidates(1).len(), MDNS_CAP);
    }

    #[test]
    fn removal_three_times_is_idempotent() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, false), 0);
        rig.event(resolved("a._xmsg._tcp.local.", &["10.9.4.1"], &[]), 1);
        rig.event(resolved("b._xmsg._tcp.local.", &["10.9.4.2"], &[]), 1);
        for _ in 0..3 {
            rig.event(
                Event::Removed {
                    fullname: "a._xmsg._tcp.local.".into(),
                },
                2,
            );
        }
        assert_eq!(rig.candidates(2), ["10.9.4.2:7788".parse().unwrap()]);
    }

    #[test]
    fn loopback_and_link_local_are_refused() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, false), 0);
        rig.event(
            resolved(
                "a._xmsg._tcp.local.",
                &["127.0.0.1", "::1", "fe80::c94:1", "10.9.4.1"],
                &[],
            ),
            1,
        );
        assert_eq!(rig.candidates(1), ["10.9.4.1:7788".parse().unwrap()]);
        assert_eq!(rig.engine.dropped(), 3);
    }

    #[test]
    fn malformed_records_are_ignored_and_extra_keys_dropped() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, false), 0);
        rig.event(
            resolved("bad._xmsg._tcp.local.", &["10.9.4.1"], &[("root", "zz")]),
            1,
        );
        assert!(rig.candidates(1).is_empty());
        rig.event(
            resolved(
                "ok._xmsg._tcp.local.",
                &["10.9.4.2"],
                &[("id", "x"), ("name", "sini.patch")],
            ),
            1,
        );
        let table = rig.table.read().unwrap().snapshot(rig.at(1));
        assert_eq!(table.len(), 1);
        assert_eq!(table[0].hint.as_deref(), Some("x"));
        assert_eq!(table[0].root_fp, None);
    }

    #[test]
    fn a_resolve_with_fewer_addresses_drops_the_rest() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, false), 0);
        rig.event(
            resolved("a._xmsg._tcp.local.", &["10.9.4.1", "2001:db8::1"], &[]),
            1,
        );
        rig.event(resolved("a._xmsg._tcp.local.", &["10.9.4.1"], &[]), 2);
        assert_eq!(rig.candidates(2), ["10.9.4.1:7788".parse().unwrap()]);
    }

    #[test]
    fn ttl_bounds_a_candidate_and_ticks_refresh_live_ones() {
        let mut rig = Rig::new();
        let short = Inputs {
            ttl_secs: 40,
            ..inputs(true, false)
        };
        rig.tick(&short, 0);
        rig.event(resolved("a._xmsg._tcp.local.", &["10.9.4.1"], &[]), 1);
        rig.tick(&short, 30);
        assert_eq!(rig.candidates(65).len(), 1, "refreshed at the 30 s tick");
        rig.event(
            Event::Removed {
                fullname: "a._xmsg._tcp.local.".into(),
            },
            66,
        );
        assert!(rig.candidates(66).is_empty());
    }

    #[test]
    fn turning_the_key_off_stops_and_clears() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, true), 0);
        rig.event(resolved("a._xmsg._tcp.local.", &["10.9.4.1"], &[]), 1);
        rig.tick(&Inputs::default(), 30);
        assert_eq!(rig.fake.0.lock().unwrap().stops, 1);
        assert!(rig.candidates(30).is_empty());
        assert_eq!(rig.state().0, State::Off);
        rig.tick(&inputs(true, false), 60);
        assert_eq!(rig.fake.0.lock().unwrap().starts, 2);
        assert_eq!(rig.state().0, State::BrowseOnly);
    }

    #[test]
    fn a_gone_interface_drops_its_candidates() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, false), 0);
        rig.event(resolved("a._xmsg._tcp.local.", &["10.9.4.1"], &[]), 1);
        rig.fake.0.lock().unwrap().interfaces =
            vec![("en1".into(), "192.168.1.20".parse().unwrap())];
        rig.tick(&inputs(true, false), 30);
        assert!(rig.candidates(30).is_empty());
    }

    /// A restarted peer announcing the same address keeps its candidate when the old
    /// record's removal arrives.
    #[test]
    fn a_shared_address_survives_one_instance_removal() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, false), 0);
        rig.event(resolved("old._xmsg._tcp.local.", &["10.9.4.1"], &[]), 1);
        rig.event(resolved("new._xmsg._tcp.local.", &["10.9.4.1"], &[]), 2);
        for _ in 0..3 {
            rig.event(
                Event::Removed {
                    fullname: "old._xmsg._tcp.local.".into(),
                },
                3,
            );
        }
        assert_eq!(rig.candidates(3), ["10.9.4.1:7788".parse().unwrap()]);
        rig.event(
            Event::Removed {
                fullname: "new._xmsg._tcp.local.".into(),
            },
            4,
        );
        assert!(rig.candidates(4).is_empty());
    }

    /// A responder error (a 5353 bind failure) reads `failed` with its cause, never
    /// `lan_silent`, even past the echo deadline.
    #[test]
    fn a_responder_error_is_failed_not_lan_silent() {
        let mut rig = Rig::new();
        rig.tick(&inputs(true, true), 0);
        rig.event(
            Event::Failed("cannot bind UDP 5353: Address in use".into()),
            1,
        );
        rig.engine.check_echo(rig.at(ECHO_DEADLINE.as_secs() + 1));
        let (state, detail) = rig.state();
        assert_eq!(state, State::Failed);
        assert!(detail.contains("cannot bind UDP 5353"), "{detail}");
    }

    /// The bind probe sees a port it can't share.
    #[test]
    fn the_bind_probe_reports_a_held_port() {
        let held = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = held.local_addr().unwrap().port();
        let error = probe_bind(port).unwrap_err();
        assert!(
            error.contains(&format!("cannot bind UDP {port}")),
            "{error}"
        );
        // Control: a port held with the same reuse options is shared.
        let shared =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        shared.set_reuse_address(true).unwrap();
        shared.set_reuse_port(true).unwrap();
        shared
            .bind(&std::net::SocketAddr::from(([0, 0, 0, 0], 0)).into())
            .unwrap();
        let port = shared.local_addr().unwrap().as_socket().unwrap().port();
        assert_eq!(probe_bind(port), Ok(()));
    }

    #[test]
    fn a_failure_warns_once_per_cause() {
        let mut rig = Rig::new();
        rig.fake.0.lock().unwrap().start_error = Some("cannot bind UDP 5353: busy".into());
        for tick in 0..4 {
            rig.tick(&inputs(true, true), tick * 30);
        }
        assert_eq!(rig.state().0, State::Failed);
        assert_eq!(rig.engine.warnings(), 1);
        rig.fake.0.lock().unwrap().start_error = Some("cannot open a UDP socket".into());
        rig.tick(&inputs(true, true), 150);
        rig.tick(&inputs(true, true), 180);
        assert_eq!(rig.engine.warnings(), 2);
    }

    /// Only dialable addresses are announced, and only in the listener's families.
    #[test]
    fn announced_addresses_are_dialable() {
        let interfaces: Vec<(String, IpAddr)> = [
            ("en0", "10.9.3.2"),
            ("en0", "fe80::c94:1"),
            ("en0", "2001:db8::5"),
            ("en1", "169.254.3.3"),
        ]
        .iter()
        .map(|(n, a)| (n.to_string(), a.parse().unwrap()))
        .collect();
        let at = |listen: &str| -> Vec<String> {
            announce_addrs(listen.parse().unwrap(), &interfaces)
                .iter()
                .map(|a| a.to_string())
                .collect()
        };
        assert_eq!(at("0.0.0.0:7788"), ["10.9.3.2"]);
        assert_eq!(at("[::]:7788"), ["10.9.3.2", "2001:db8::5"]);
        assert_eq!(at("10.9.3.2:7788"), ["10.9.3.2"]);
        assert!(at("169.254.3.3:7788").is_empty());

        let mut rig = Rig::new();
        rig.fake.0.lock().unwrap().interfaces = interfaces.clone();
        rig.tick(
            &Inputs {
                fed_listen: Some("[::]:7788".parse().unwrap()),
                ..inputs(true, true)
            },
            0,
        );
        let announced = rig.fake.0.lock().unwrap().registers[0].2.clone();
        assert_eq!(
            announced,
            [
                "10.9.3.2".parse::<IpAddr>().unwrap(),
                "2001:db8::5".parse().unwrap()
            ]
        );
        let mut rig = Rig::new();
        rig.fake.0.lock().unwrap().interfaces = interfaces;
        rig.tick(
            &Inputs {
                fed_listen: Some("169.254.3.3:7788".parse().unwrap()),
                ..inputs(true, true)
            },
            0,
        );
        assert_eq!(rig.state().0, State::BrowseOnly);
        assert!(rig.fake.0.lock().unwrap().registers.is_empty());
    }

    /// Without a random id the node never announces; it browses and says why.
    #[test]
    fn no_random_id_is_browse_only() {
        let fake = Fake::default();
        fake.0.lock().unwrap().interfaces = vec![("en0".into(), "10.9.3.2".parse().unwrap())];
        let status = SharedStatus::default();
        let mut engine = Engine::new(
            fake.clone(),
            Err("entropy unavailable".into()),
            status.clone(),
            SharedCandidates::default(),
        );
        engine.reconcile(&inputs(true, true), Instant::now());
        assert!(fake.0.lock().unwrap().registers.is_empty());
        let s = status.lock().unwrap();
        assert_eq!(s.state, State::BrowseOnly);
        assert!(s.detail.contains("entropy unavailable"), "{}", s.detail);
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
        let root = "ab".repeat(32);
        let child = Kill(
            Command::new("/usr/bin/dns-sd")
                .args(["-R", &name, "_xmsg._tcp", "local", "47791", "id=m5"])
                .arg(format!("root={root}"))
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
        assert!(txt.contains(&("id".into(), "m5".into())), "{txt:?}");
        assert!(txt.contains(&("root".into(), root)), "{txt:?}");
    }
}
