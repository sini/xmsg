//! The LAN mDNS/DNS-SD source: `_xmsg._tcp.local.` announcements become candidates.
//!
//! [`Engine`] holds the logic and talks to the network only through [`Backend`], so tests can
//! inject resolver results and the interface set. [`MdnsSd`] is the real backend.

use super::{
    acceptable_ip, Candidate, MdnsConfig, SharedCandidates, SharedStatus, Source, State,
    MAX_TTL_SECS,
};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

pub const SERVICE_TYPE: &str = "_xmsg._tcp.local.";
/// How long after each (re-)announce our own record must come back on a LAN address.
pub const ECHO_DEADLINE: Duration = Duration::from_secs(15);
/// The reconcile tick: config, interfaces, the echo re-check and expiry.
pub const TICK: Duration = Duration::from_secs(30);
/// mdns-sd's own interface re-check interval.
pub const IP_CHECK_SECS: u32 = 30;
const MAX_INSTANCES: usize = 256;
const MAX_ID_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// An instance resolved. Each address carries the names of the interfaces it arrived on.
    Resolved {
        fullname: String,
        port: u16,
        addrs: Vec<(IpAddr, Vec<String>)>,
        txt: Vec<(String, String)>,
    },
    Removed {
        fullname: String,
    },
    /// The responder stopped; the next tick restarts it.
    Failed(String),
}

/// The network side of the source.
pub trait Backend {
    /// Start the responder and browse `SERVICE_TYPE`.
    fn start(&mut self) -> Result<(), String>;
    /// (Re-)announce our instance `id` at `addrs` on `port` with `txt`, and replay the browse
    /// cache.
    fn register(
        &mut self,
        id: &str,
        port: u16,
        addrs: &[IpAddr],
        txt: &[(String, String)],
    ) -> Result<(), String>;
    fn unregister(&mut self);
    fn stop(&mut self);
    fn recv(&mut self, timeout: Duration) -> Option<Event>;
    /// The host's up, non-loopback interface addresses, by interface name.
    fn interfaces(&self) -> Vec<(String, IpAddr)>;
}

/// What a reconcile tick reads from the current peers map and the daemon's flags.
#[derive(Clone, Debug, Default)]
pub struct Inputs {
    pub mdns: Option<MdnsConfig>,
    pub ttl_secs: u64,
    pub root: Option<[u8; 32]>,
    pub fed_listen: Option<SocketAddr>,
}

/// The announced TXT record: exactly `id` and `root`.
pub fn txt(id: &str, root: &[u8; 32]) -> Vec<(String, String)> {
    vec![
        ("id".to_string(), id.to_string()),
        ("root".to_string(), hex::encode(root)),
    ]
}

/// The addresses a node listening on `listen` can be dialled at: that IP when it is specific;
/// for `0.0.0.0` the IPv4 interface addresses; for `[::]` both families. Never loopback or
/// link-local.
pub fn announce_addrs(listen: SocketAddr, interfaces: &[(String, IpAddr)]) -> Vec<IpAddr> {
    let ip = listen.ip();
    let mut out: Vec<IpAddr> = if ip.is_unspecified() {
        interfaces
            .iter()
            .map(|(_, a)| *a)
            .filter(|a| ip.is_ipv6() || a.is_ipv4())
            .collect()
    } else {
        vec![ip]
    };
    out.retain(|a| acceptable_ip(*a));
    out.sort();
    out.dedup();
    out
}

fn lan_silent_detail(interfaces: usize) -> String {
    if interfaces == 0 {
        return "no non-loopback network interface (0 interfaces), so LAN discovery is silent"
            .into();
    }
    if cfg!(target_os = "macos") {
        format!("our announcement did not come back on the LAN within {}s ({interfaces} interfaces): allow xmsg in System Settings › Privacy & Security › Local Network", ECHO_DEADLINE.as_secs())
    } else {
        format!("our announcement did not come back on the LAN within {}s ({interfaces} interfaces): check that UDP 5353 is open in the host firewall", ECHO_DEADLINE.as_secs())
    }
}

pub struct Engine<B> {
    pub backend: B,
    id: Result<String, String>,
    status: SharedStatus,
    candidates: SharedCandidates,
    running: bool,
    browse: bool,
    announced: Option<[u8; 32]>,
    echo_seen: bool,
    echo_deadline: Option<Instant>,
    interfaces: Vec<(String, IpAddr)>,
    instances: HashMap<String, Vec<(SocketAddr, Vec<String>)>>,
    ttl: Duration,
    warned: Option<String>,
    warnings: u64,
    dropped: u64,
}

impl<B: Backend> Engine<B> {
    /// `id` is this process's opaque TXT id, or why there is none (then it never announces).
    pub fn new(
        backend: B,
        id: Result<String, String>,
        status: SharedStatus,
        candidates: SharedCandidates,
    ) -> Self {
        Self {
            backend,
            id,
            status,
            candidates,
            running: false,
            browse: false,
            announced: None,
            echo_seen: false,
            echo_deadline: None,
            interfaces: Vec::new(),
            instances: HashMap::new(),
            ttl: Duration::from_secs(MAX_TTL_SECS),
            warned: None,
            warnings: 0,
            dropped: 0,
        }
    }

    pub fn state(&self) -> State {
        self.status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .state
    }

    fn set(&self, state: State, detail: impl Into<String>) {
        self.status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set(state, detail);
    }

    fn table(&self) -> std::sync::RwLockWriteGuard<'_, super::CandidateTable> {
        self.candidates
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Logs `what` once per distinct `cause`; a changed cause logs again.
    fn warn_once(&mut self, cause: &str, what: &str) {
        if self.warned.as_deref() != Some(cause) {
            tracing::warn!(cause = %cause, "{what}");
            self.warned = Some(cause.to_string());
            self.warnings += 1;
        }
    }

    /// Warnings logged so far.
    pub fn warnings(&self) -> u64 {
        self.warnings
    }

    /// Link-local and other unusable addresses dropped so far.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The echo deadline, if one is pending.
    pub fn echo_deadline(&self) -> Option<Instant> {
        self.echo_deadline.filter(|_| !self.echo_seen)
    }

    fn shutdown(&mut self) {
        if self.running {
            self.backend.stop();
        }
        self.running = false;
        self.announced = None;
        self.echo_deadline = None;
        self.forget_all();
    }

    fn forget_all(&mut self) {
        self.instances.clear();
        self.table().clear_source(Source::Mdns);
    }

    /// One reconcile tick: start, stop or toggle from the current config, follow interface
    /// changes, re-check a silent LAN, refresh and expire candidates.
    pub fn reconcile(&mut self, inputs: &Inputs, now: Instant) {
        let Some(config) = inputs.mdns.filter(|m| m.browse || m.announce) else {
            self.shutdown();
            self.set(State::Off, "");
            return;
        };
        self.ttl = Duration::from_secs(inputs.ttl_secs.clamp(1, MAX_TTL_SECS));
        if !self.running {
            self.set(State::Starting, "starting the mDNS responder");
            if let Err(error) = self.backend.start() {
                self.warn_once(&error, "LAN discovery failed to start; serving without it");
                self.set(State::Failed, error);
                return;
            }
            self.running = true;
            self.interfaces = self.backend.interfaces();
        }
        if self.browse && !config.browse {
            self.forget_all();
        }
        self.browse = config.browse;

        let interfaces = self.backend.interfaces();
        let changed = interfaces != self.interfaces;
        if changed {
            self.interfaces = interfaces;
            self.drop_gone_interfaces();
        }

        match (self.announce_refusal(&config, inputs), inputs.root) {
            (None, Some(root)) => {
                if self.announced != Some(root) || changed || self.state() == State::LanSilent {
                    if let Some(listen) = inputs.fed_listen {
                        self.announce(root, listen, now);
                    }
                }
            }
            (refusal, _) => {
                if self.announced.take().is_some() {
                    self.backend.unregister();
                }
                self.echo_deadline = None;
                let reason = refusal.unwrap_or_default();
                if config.announce {
                    self.warn_once(&reason, "LAN discovery is browse-only");
                }
                self.set(State::BrowseOnly, reason);
            }
        }

        let mut table = self.table();
        table.expire(now);
        // Instances mdns-sd still holds stay live; its own record expiry arrives as a removal.
        let live: HashSet<SocketAddr> = self
            .instances
            .values()
            .flatten()
            .map(|(addr, _)| *addr)
            .collect();
        for mut c in table.snapshot(now) {
            if c.source == Source::Mdns && live.contains(&c.addr) {
                c.expires_at = now + self.ttl;
                table.upsert(c, now);
            }
        }
    }

    fn announce_refusal(&self, config: &MdnsConfig, inputs: &Inputs) -> Option<String> {
        if !config.announce {
            return Some("announce is off".into());
        }
        if let Err(error) = &self.id {
            return Some(format!("no random id for the announcement: {error}"));
        }
        if inputs.root.is_none() {
            return Some("no federation CA root to announce".into());
        }
        let Some(listen) = inputs.fed_listen else {
            return Some("no --fed-listen address to announce".into());
        };
        let ip = listen.ip();
        if !ip.is_unspecified() && !self.interfaces.iter().any(|(_, a)| *a == ip) {
            return Some(format!(
                "--fed-listen {ip} is not an address on a LAN interface"
            ));
        }
        if !self.interfaces.is_empty() && announce_addrs(listen, &self.interfaces).is_empty() {
            return Some(format!("--fed-listen {ip} has no dialable LAN address"));
        }
        None
    }

    fn announce(&mut self, root: [u8; 32], listen: SocketAddr, now: Instant) {
        let Ok(id) = self.id.clone() else {
            return;
        };
        let addrs = announce_addrs(listen, &self.interfaces);
        match self
            .backend
            .register(&id, listen.port(), &addrs, &txt(&id, &root))
        {
            Ok(()) => {
                self.announced = Some(root);
                self.echo_seen = false;
                self.echo_deadline = Some(now + ECHO_DEADLINE);
                if self.state() != State::LanSilent {
                    self.set(
                        State::Starting,
                        "waiting for our announcement to come back on the LAN",
                    );
                }
            }
            Err(error) => {
                self.warn_once(&error, "LAN discovery could not announce");
                self.announced = None;
                self.set(State::Failed, error);
            }
        }
    }

    /// Flags a silent LAN once the echo deadline passes without our own LAN echo.
    pub fn check_echo(&mut self, now: Instant) {
        let due = self.echo_deadline.is_some_and(|d| now >= d);
        if self.announced.is_some() && !self.echo_seen && due && self.state() != State::LanSilent {
            let detail = lan_silent_detail(self.interfaces.len());
            tracing::warn!(detail = %detail, "LAN discovery is silent; serving without it");
            self.set(State::LanSilent, detail);
        }
    }

    fn drop_gone_interfaces(&mut self) {
        let names: HashSet<&str> = self.interfaces.iter().map(|(n, _)| n.as_str()).collect();
        let mut gone = Vec::new();
        for addrs in self.instances.values_mut() {
            addrs.retain(|(addr, via)| {
                let keep = via.is_empty() || via.iter().any(|n| names.contains(n.as_str()));
                if !keep {
                    gone.push(*addr);
                }
                keep
            });
        }
        self.instances.retain(|_, addrs| !addrs.is_empty());
        let held = self.held();
        let gone: HashSet<SocketAddr> = gone.into_iter().filter(|a| !held.contains(a)).collect();
        self.table()
            .retain_source(Source::Mdns, |c| !gone.contains(&c.addr));
    }

    /// Addresses some known instance still announces.
    fn held(&self) -> HashSet<SocketAddr> {
        self.instances
            .values()
            .flatten()
            .map(|(addr, _)| *addr)
            .collect()
    }

    pub fn handle(&mut self, event: Event, now: Instant) {
        match event {
            Event::Failed(error) => {
                self.warn_once(&error, "LAN discovery stopped; restarting on the next tick");
                self.backend.stop();
                self.running = false;
                self.announced = None;
                self.forget_all();
                self.set(State::Failed, error);
            }
            Event::Removed { fullname } => self.remove_instance(&fullname),
            Event::Resolved {
                fullname,
                port,
                addrs,
                txt,
            } => self.resolved(fullname, port, addrs, txt, now),
        }
    }

    fn remove_instance(&mut self, fullname: &str) {
        // Another instance (a restarted peer) may announce the same address: keep it then.
        if let Some(addrs) = self.instances.remove(fullname) {
            let held = self.held();
            let mut table = self.table();
            for (addr, _) in addrs {
                if !held.contains(&addr) {
                    table.remove(Source::Mdns, addr);
                }
            }
        }
    }

    fn resolved(
        &mut self,
        fullname: String,
        port: u16,
        addrs: Vec<(IpAddr, Vec<String>)>,
        txt: Vec<(String, String)>,
        now: Instant,
    ) {
        let value = |key: &str| txt.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
        let id = value("id");
        if id.is_some() && id == self.id.as_deref().ok() {
            if self.announced.is_some() && addrs.iter().any(|(ip, _)| acceptable_ip(*ip)) {
                self.echo_seen = true;
                self.warned = None;
                self.set(State::Active, "our announcement came back on the LAN");
            }
            return;
        }
        if !self.browse {
            return;
        }
        // A malformed record is ignored whole; keys outside {id, root} are ignored one by one.
        let root_fp = match value("root") {
            None => None,
            Some(hex_root) => match hex::decode(hex_root).ok().and_then(|b| b.try_into().ok()) {
                Some(fp) => Some(fp),
                None => return,
            },
        };
        if port == 0 || id.is_some_and(|i| i.is_empty() || i.len() > MAX_ID_LEN) {
            return;
        }
        if !self.instances.contains_key(&fullname) && self.instances.len() >= MAX_INSTANCES {
            let table = self
                .candidates
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            let held: HashSet<SocketAddr> = table.snapshot(now).iter().map(|c| c.addr).collect();
            drop(table);
            self.instances
                .retain(|_, addrs| addrs.iter().any(|(a, _)| held.contains(a)));
            if self.instances.len() >= MAX_INSTANCES {
                return;
            }
        }
        let fresh: Vec<(SocketAddr, Vec<String>)> = addrs
            .into_iter()
            .map(|(ip, via)| (SocketAddr::new(ip, port), via))
            .collect();
        let ttl = self.ttl;
        let hint = id.map(str::to_string);
        let previous = self.instances.remove(&fullname).unwrap_or_default();
        let held = self.held();
        let mut kept = Vec::new();
        let mut dropped = 0;
        {
            let mut table = self.table();
            for (addr, _) in &previous {
                if !fresh.iter().any(|(a, _)| a == addr) && !held.contains(addr) {
                    table.remove(Source::Mdns, *addr);
                }
            }
            for (addr, via) in fresh {
                let accepted = table.upsert(
                    Candidate {
                        addr,
                        source: Source::Mdns,
                        hint: hint.clone(),
                        root_fp,
                        seen_at: now,
                        expires_at: now + ttl,
                    },
                    now,
                );
                if accepted {
                    kept.push((addr, via));
                } else {
                    dropped += 1;
                }
            }
        }
        self.dropped += dropped;
        tracing::debug!(
            instance = %fullname,
            kept = kept.len(),
            dropped,
            "LAN discovery candidate"
        );
        if !kept.is_empty() {
            self.instances.insert(fullname, kept);
        }
    }

    /// Runs on the calling thread until [`stop`]: a reconcile every `TICK` from `inputs`,
    /// events in between.
    pub fn run(mut self, mut inputs: impl FnMut() -> Inputs) {
        let mut next_tick = Instant::now();
        loop {
            if STOP.load(Ordering::SeqCst) {
                self.shutdown();
                STOPPED.store(true, Ordering::SeqCst);
                return;
            }
            let now = Instant::now();
            if now >= next_tick {
                self.reconcile(&inputs(), now);
                next_tick = now + TICK;
            }
            self.check_echo(now);
            let until = self
                .echo_deadline()
                .map_or(next_tick, |d| d.min(next_tick))
                .clamp(
                    now + Duration::from_millis(50),
                    now + Duration::from_millis(250),
                );
            if !self.running {
                std::thread::sleep(until - now);
            } else if let Some(event) = self.backend.recv(until - now) {
                self.handle(event, Instant::now());
            }
        }
    }
}

/// The real backend, on mdns-sd. Interface filtering is ours: it never calls
/// `disable_interface`.
#[derive(Default)]
pub struct MdnsSd {
    daemon: Option<mdns_sd::ServiceDaemon>,
    events: Option<mdns_sd::Receiver<mdns_sd::ServiceEvent>>,
    monitor: Option<mdns_sd::Receiver<mdns_sd::DaemonEvent>>,
    registered: Option<String>,
}

/// Binds UDP `port` on 0.0.0.0 with the reuse options mdns-sd uses, then lets it go. mdns-sd
/// only logs its own bind failure, so this is how one is seen.
pub fn probe_bind(port: u16) -> Result<(), String> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(|e| format!("cannot open a UDP socket: {e}"))?;
    socket
        .set_reuse_address(true)
        .map_err(|e| format!("cannot set SO_REUSEADDR: {e}"))?;
    let _ = socket.set_reuse_port(true);
    socket
        .bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())
        .map_err(|e| format!("cannot bind UDP {port}: {e}"))
}

impl Backend for MdnsSd {
    fn start(&mut self) -> Result<(), String> {
        probe_bind(5353)?;
        let daemon = mdns_sd::ServiceDaemon::new()
            .map_err(|e| format!("the mDNS responder failed to start: {e}"))?;
        let _ = daemon.set_ip_check_interval(IP_CHECK_SECS);
        self.monitor = daemon.monitor().ok();
        let events = daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| format!("mDNS browse failed: {e}"))?;
        self.daemon = Some(daemon);
        self.events = Some(events);
        Ok(())
    }

    fn register(
        &mut self,
        id: &str,
        port: u16,
        addrs: &[IpAddr],
        txt: &[(String, String)],
    ) -> Result<(), String> {
        let daemon = self.daemon.as_ref().ok_or("mDNS responder not running")?;
        let host = format!("{id}.local.");
        let info = mdns_sd::ServiceInfo::new(SERVICE_TYPE, id, &host, addrs, port, txt)
            .map_err(|e| format!("invalid mDNS announcement: {e}"))?;
        let fullname = info.get_fullname().to_string();
        daemon
            .register(info)
            .map_err(|e| format!("mDNS announce failed: {e}"))?;
        self.registered = Some(fullname);
        // A fresh browse replays the cache, so a still-cached LAN echo of ours counts again.
        if let Ok(events) = daemon.browse(SERVICE_TYPE) {
            self.events = Some(events);
        }
        Ok(())
    }

    fn unregister(&mut self) {
        if let (Some(daemon), Some(fullname)) = (&self.daemon, self.registered.take()) {
            let _ = daemon.unregister(&fullname);
        }
    }

    fn stop(&mut self) {
        self.unregister();
        self.events = None;
        self.monitor = None;
        if let Some(daemon) = self.daemon.take() {
            let _ = daemon.shutdown();
        }
    }

    fn recv(&mut self, timeout: Duration) -> Option<Event> {
        use mdns_sd::{DaemonEvent, RecvTimeoutError, ServiceEvent};
        if let Some(Ok(DaemonEvent::Error(error))) = self.monitor.as_ref().map(|m| m.try_recv()) {
            return Some(Event::Failed(format!("mDNS responder error: {error}")));
        }
        let events = self.events.as_ref()?;
        match events.recv_timeout(timeout) {
            Ok(ServiceEvent::ServiceResolved(r)) => Some(Event::Resolved {
                fullname: r.fullname.clone(),
                port: r.port,
                addrs: r
                    .addresses
                    .iter()
                    .map(|scoped| {
                        let via = match scoped {
                            mdns_sd::ScopedIp::V4(v4) => {
                                v4.interface_ids().iter().map(|i| i.name.clone()).collect()
                            }
                            mdns_sd::ScopedIp::V6(v6) => vec![v6.scope_id().name.clone()],
                            _ => Vec::new(),
                        };
                        (scoped.to_ip_addr(), via)
                    })
                    .collect(),
                txt: r
                    .txt_properties
                    .iter()
                    .map(|p| (p.key().to_string(), p.val_str().to_string()))
                    .collect(),
            }),
            Ok(ServiceEvent::ServiceRemoved(_, fullname)) => Some(Event::Removed { fullname }),
            Ok(_) | Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => {
                self.events = None;
                Some(Event::Failed("the mDNS responder stopped".into()))
            }
        }
    }

    fn interfaces(&self) -> Vec<(String, IpAddr)> {
        let mut out: Vec<(String, IpAddr)> = if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .filter(|i| i.is_oper_up() && !i.is_loopback() && !i.is_p2p())
            .map(|i| (i.name.clone(), i.ip()))
            .collect();
        out.sort();
        out
    }
}

/// A fresh opaque id for this process's announcement.
pub fn random_id() -> Result<String, String> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|e| e.to_string())?;
    Ok(hex::encode(bytes))
}

static STOP: AtomicBool = AtomicBool::new(false);
static STOPPED: AtomicBool = AtomicBool::new(false);

/// Asks the running source to withdraw its announcement and shut down, waiting at most
/// `bound`.
pub fn stop(bound: Duration) {
    STOP.store(true, Ordering::SeqCst);
    let deadline = Instant::now() + bound;
    while !STOPPED.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Starts the source on its own thread; it reads the current peers map on every tick.
pub fn spawn(
    fed: Arc<crate::fed::FedState>,
    fed_listen: Option<SocketAddr>,
    status: SharedStatus,
    candidates: SharedCandidates,
) {
    let engine = Engine::new(MdnsSd::default(), random_id(), status, candidates);
    let spawned = std::thread::Builder::new()
        .name("xmsg-mdns".into())
        .spawn(move || {
            engine.run(|| {
                let peers = fed.current_peers();
                let mdns = peers
                    .discovery
                    .source_enabled(Source::Mdns)
                    .then_some(peers.discovery.mdns)
                    .flatten();
                Inputs {
                    // Only a running source reads and parses the CA bundle.
                    root: mdns.and_then(|_| super::root_fingerprint(&peers)),
                    mdns,
                    ttl_secs: peers.discovery.ttl_secs,
                    fed_listen,
                }
            })
        });
    if let Err(error) = spawned {
        tracing::warn!(%error, "LAN discovery thread failed to start; serving without it");
    }
}
