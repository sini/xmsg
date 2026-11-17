//! The LAN mDNS/DNS-SD source: `_xmsg._tcp.local.` announcements become candidates.
//!
//! [`Engine`] holds the state machine and talks to the network only through [`Backend`], so tests
//! can inject resolver events, multicast probe outcomes, handle generation and the interface set.
//! [`MdnsSd`] is the live backend.
//!
//! Privacy and Local Network detection:
//! - At startup, enabling `discovery.mdns` with the default `discovery.announce = "timed"` is
//!   browse-only at rest (`AnnouncePosture::AtRest`). An announcement window opens only on local
//!   activation ([`super::trigger_announce`] or [`Engine::activate_announce_window`]) and expires
//!   after [`ANNOUNCE_WINDOW`] (120 s) back to browse-only.
//! - Announcements carry no CA-root hash, node name, user name, host name or stable device ID:
//!   TXT holds only `v=1` and a 128-bit CSPRNG hex handle `id`, rotated together with the DNS-SD
//!   service instance (`<id>._xmsg._tcp.local.`) and SRV target host (`<id>.local.`) every
//!   [`ROTATE_INTERVAL`] (30 s), at window start, and on interface changes, unregistering the
//!   previous record each time.
//! - Outbound multicast reachability / macOS Local Network state is probed without announcing via
//!   an IPv4 multicast DNS `A` query to `224.0.0.251:5353`, debounced across
//!   [`LN_DEBOUNCE_CONSECUTIVE`] consecutive send failures into [`State::PermissionSuspected`].
//!   IPv6 multicast gating and IPv6 link-local (`fe80::/10`) candidates are not probed or dialled
//!   in v1.

use super::{
    acceptable_ip, AnnounceMode, AnnouncePosture, Candidate, MdnsConfig, SharedCandidates,
    SharedStatus, Source, State, ANNOUNCE_WINDOW_SECS, HANDLE_ROTATE_SECS, MAX_TTL_SECS,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

pub const SERVICE_TYPE: &str = "_xmsg._tcp.local.";
pub const PROTOCOL_VERSION: &str = "1";
/// Bounded announcement window opened by a local activation under `discovery.announce = "timed"`.
pub const ANNOUNCE_WINDOW: Duration = Duration::from_secs(ANNOUNCE_WINDOW_SECS);
/// Rotation interval for the 128-bit opaque handle, DNS-SD instance and SRV hostname.
pub const ROTATE_INTERVAL: Duration = Duration::from_secs(HANDLE_ROTATE_SECS);
/// How long retired own handles stay on the self-ignore list to absorb cached browse replays.
pub const RETIRED_HANDLE_RETENTION: Duration = Duration::from_secs(60);
/// The reconcile tick: config reload, interfaces, periodic probe refresh and candidate expiry.
pub const TICK: Duration = Duration::from_secs(30);
/// mdns-sd's own interface re-check interval.
pub const IP_CHECK_SECS: u32 = 30;
/// Consecutive multicast send failures required before reporting `permission_suspected`.
pub const LN_DEBOUNCE_CONSECUTIVE: u32 = 3;
/// Spacing between debounce retries after a multicast send error.
pub const LN_PROBE_RETRY_INTERVAL: Duration = Duration::from_secs(2);
/// Per-probe socket wait bound so a stalled or silent LAN never blocks the discovery thread.
pub const LN_PROBE_RECV_TIMEOUT: Duration = Duration::from_millis(400);
pub const MDNS_MULTICAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_PORT: u16 = 5353;

const MAX_INSTANCES: usize = 256;
const MAX_ID_LEN: usize = 64;

/// Query-name selection for the non-announcing IPv4 multicast Local Network detector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LnQueryMode {
    /// Query `<opaque-hex>.local` so the OS hostname is never disclosed on the LAN.
    /// Gated on an owner-run macOS Deny/Allow check confirming `EHOSTUNREACH` still fires on Deny.
    RandomLabel,
    /// Fallback: query `<os-hostname>.local`, which elicits an own-LAN `A` reply from the system
    /// responder when allowed, at the cost of disclosing the OS hostname.
    OsHostname,
}

/// Single constant controlling the detector's query name (default: [`LnQueryMode::RandomLabel`]).
/// Switch to [`LnQueryMode::OsHostname`] only if owner-run macOS Deny/Allow testing shows random
/// labels do not discriminate explicit Deny.
pub const LN_QUERY_MODE: LnQueryMode = LnQueryMode::RandomLabel;

/// Outcome of one non-announcing IPv4 multicast query to `224.0.0.251:5353`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// A DNS response arrived from one of this host's own non-loopback IPv4 LAN addresses.
    OwnLanReply(Ipv4Addr),
    /// `sendto` succeeded, with no own-LAN response within [`LN_PROBE_RECV_TIMEOUT`].
    SentNoReply,
    /// Host has no up, non-loopback, dialable IPv4 interface to classify against.
    NoLanInterface,
    /// `sendto` or multicast socket setup failed (e.g. `EHOSTUNREACH` under macOS DenyMulticast).
    SendBlocked(String),
}

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
    /// Announce our rotating handle `id` (`<id>._xmsg._tcp.local.`, host `<id>.local.`) at
    /// `addrs` on `port` with `txt`, withdrawing any prior registration first.
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
    /// Send one non-announcing IPv4 multicast DNS `A` query for `qname` to `224.0.0.251:5353`.
    fn probe_multicast(&mut self, qname: &str, lan_v4: &[Ipv4Addr]) -> ProbeOutcome;
}

/// What a reconcile tick reads from the current peers map and the daemon's flags.
#[derive(Clone, Debug)]
pub struct Inputs {
    pub mdns: Option<MdnsConfig>,
    pub announce: AnnounceMode,
    pub ttl_secs: u64,
    pub fed_listen: Option<SocketAddr>,
}

impl Default for Inputs {
    fn default() -> Self {
        Self {
            mdns: None,
            announce: AnnounceMode::Timed,
            ttl_secs: MAX_TTL_SECS,
            fed_listen: None,
        }
    }
}

impl Inputs {
    pub fn effective_announce_mode(&self) -> AnnounceMode {
        match self.mdns {
            Some(m) if !m.announce => AnnounceMode::BrowseOnly,
            Some(_) => self.announce,
            None => AnnounceMode::BrowseOnly,
        }
    }

    pub fn configured(&self) -> bool {
        self.mdns
            .is_some_and(|m| m.browse || self.effective_announce_mode() != AnnounceMode::BrowseOnly)
    }
}

/// The announced TXT record: protocol version `v=1` and rotating 128-bit opaque handle `id`.
/// Never carries a CA-root hash, user name, host name, node name or stable device ID.
pub fn txt(id: &str) -> Vec<(String, String)> {
    vec![
        ("v".to_string(), PROTOCOL_VERSION.to_string()),
        ("id".to_string(), id.to_string()),
    ]
}

/// A fresh 128-bit (32 hex chars) CSPRNG opaque handle for one announcement rotation slice.
pub fn random_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| e.to_string())?;
    Ok(hex::encode(bytes))
}

/// Builds the `.local` query name for the non-announcing multicast detector from `mode`.
pub fn ln_query_name(mode: LnQueryMode) -> String {
    match mode {
        LnQueryMode::RandomLabel => match random_id() {
            Ok(id) => format!("xmsg-{id}.local"),
            Err(_) => "xmsg-00000000000000000000000000000000.local".into(),
        },
        LnQueryMode::OsHostname => {
            let raw = gethostname::gethostname().to_string_lossy().into_owned();
            let base = raw
                .trim_end_matches('.')
                .trim_end_matches(".local")
                .split('.')
                .next()
                .unwrap_or("");
            let clean: String = base
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
                .take(63)
                .collect();
            if clean.is_empty() {
                "localhost.local".into()
            } else {
                format!("{clean}.local")
            }
        }
    }
}

/// Encodes a minimal standard DNS `A` (`IN`, `RD=0`) query packet for `qname`.
pub fn build_mdns_a_query(qname: &str, txid: u16) -> Result<Vec<u8>, String> {
    let trimmed = qname.trim_end_matches('.');
    if trimmed.is_empty() {
        return Err("empty mDNS query name".into());
    }
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&txid.to_be_bytes());
    // Flags = 0x0000 (standard query, RD=0), QDCOUNT = 1, AN/NS/AR = 0.
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("invalid DNS label length in '{qname}'"));
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00);
    if pkt.len() > 267 {
        return Err(format!("DNS query name too long in '{qname}'"));
    }
    // QTYPE = A (1), QCLASS = IN (1).
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    Ok(pkt)
}

/// Sends one IPv4 multicast `A` query to `224.0.0.251:5353` (`IP_MULTICAST_TTL=255`) from an
/// ephemeral UDP socket and waits up to `recv_timeout` for a response from one of `lan_v4`.
/// Never sends unicast-to-self (which answers even when macOS Local Network is denied).
pub fn probe_multicast_ipv4(
    qname: &str,
    lan_v4: &[Ipv4Addr],
    recv_timeout: Duration,
) -> ProbeOutcome {
    if lan_v4.is_empty() {
        return ProbeOutcome::NoLanInterface;
    }
    let mut id_bytes = [0u8; 2];
    let _ = getrandom::fill(&mut id_bytes);
    let txid = u16::from_be_bytes(id_bytes);
    let pkt = match build_mdns_a_query(qname, txid) {
        Ok(p) => p,
        Err(e) => return ProbeOutcome::SendBlocked(e),
    };
    let socket = match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)) {
        Ok(s) => s,
        Err(e) => return ProbeOutcome::SendBlocked(format!("socket: {e}")),
    };
    let _ = socket.set_multicast_ttl_v4(255);
    let dest = SocketAddrV4::new(MDNS_MULTICAST_V4, MDNS_PORT);
    if let Err(e) = socket.send_to(&pkt, dest) {
        let is_unreach = e.kind() == std::io::ErrorKind::HostUnreachable
            || e.raw_os_error() == Some(libc::EHOSTUNREACH);
        let msg = if is_unreach {
            format!("EHOSTUNREACH ({e})")
        } else {
            e.to_string()
        };
        return ProbeOutcome::SendBlocked(msg);
    }
    let deadline = Instant::now() + recv_timeout;
    let mut buf = [0u8; 1500];
    for _ in 0..8 {
        let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        if rem.is_zero() {
            break;
        }
        if socket.set_read_timeout(Some(rem)).is_err() {
            break;
        }
        let Ok((n, from)) = socket.recv_from(&mut buf) else {
            break;
        };
        let IpAddr::V4(src_v4) = from.ip() else {
            continue;
        };
        if src_v4.is_loopback() || !lan_v4.contains(&src_v4) || !acceptable_ip(IpAddr::V4(src_v4)) {
            continue;
        }
        // Require a DNS response (QR=1) matching our query ID or mDNS ID 0.
        if n >= 12 && (buf[2] & 0x80) != 0 {
            let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
            if resp_id == txid || resp_id == 0 {
                return ProbeOutcome::OwnLanReply(src_v4);
            }
        }
    }
    ProbeOutcome::SentNoReply
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

fn lan_ipv4_addrs(interfaces: &[(String, IpAddr)]) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = interfaces
        .iter()
        .filter_map(|(_, ip)| match ip {
            IpAddr::V4(v4) if acceptable_ip(IpAddr::V4(*v4)) => Some(*v4),
            _ => None,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn permission_suspected_detail(cause: &str, streak: u32, v4_ifaces: usize) -> String {
    if cfg!(target_os = "macos") {
        format!(
            "outbound multicast failed {streak} consecutive times ({cause}; {v4_ifaces} IPv4 interfaces): Local Network permission suspected — check System Settings › Privacy & Security › Local Network"
        )
    } else {
        format!(
            "outbound multicast failed {streak} consecutive times ({cause}; {v4_ifaces} IPv4 interfaces): outbound blocked or permission suspected — check that UDP 5353 is open in the host firewall"
        )
    }
}

pub type IdGen = Box<dyn FnMut() -> Result<String, String> + Send>;

pub struct Engine<B> {
    pub backend: B,
    id_gen: IdGen,
    query_mode: LnQueryMode,
    status: SharedStatus,
    candidates: SharedCandidates,
    trigger: Arc<AtomicBool>,
    running: bool,
    browse: bool,
    active_handle: Option<String>,
    retired_handles: VecDeque<(String, Instant)>,
    window_until: Option<Instant>,
    next_rotate: Option<Instant>,
    probe_due: Option<Instant>,
    host_unreach_streak: u32,
    interfaces: Vec<(String, IpAddr)>,
    instances: HashMap<String, Vec<(SocketAddr, Vec<String>)>>,
    ttl: Duration,
    warned: Option<String>,
    warnings: u64,
    dropped: u64,
}

impl<B: Backend> Engine<B> {
    pub fn new(
        backend: B,
        id_gen: IdGen,
        status: SharedStatus,
        candidates: SharedCandidates,
    ) -> Self {
        Self::with_trigger_and_query(
            backend,
            id_gen,
            LN_QUERY_MODE,
            status,
            candidates,
            Arc::new(AtomicBool::new(false)),
        )
    }

    pub fn with_trigger_and_query(
        backend: B,
        id_gen: IdGen,
        query_mode: LnQueryMode,
        status: SharedStatus,
        candidates: SharedCandidates,
        trigger: Arc<AtomicBool>,
    ) -> Self {
        Self {
            backend,
            id_gen,
            query_mode,
            status,
            candidates,
            trigger,
            running: false,
            browse: false,
            active_handle: None,
            retired_handles: VecDeque::new(),
            window_until: None,
            next_rotate: None,
            probe_due: None,
            host_unreach_streak: 0,
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

    pub fn posture(&self) -> AnnouncePosture {
        self.status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .posture
    }

    pub fn active_handle(&self) -> Option<&str> {
        self.active_handle.as_deref()
    }

    fn set(&self, state: State, detail: impl Into<String>) {
        self.status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set(state, detail);
    }

    fn set_posture(&self, posture: AnnouncePosture) {
        self.status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set_posture(posture);
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

    fn prune_retired_handles(&mut self, now: Instant) {
        while let Some((_, until)) = self.retired_handles.front() {
            if now >= *until {
                self.retired_handles.pop_front();
            } else {
                break;
            }
        }
    }

    fn is_own_handle(&self, id: Option<&str>, fullname: &str) -> bool {
        let matches = |h: &str| {
            id == Some(h)
                || fullname
                    .strip_suffix(&format!(".{SERVICE_TYPE}"))
                    .is_some_and(|inst| inst == h)
        };
        if let Some(active) = &self.active_handle {
            if matches(active) {
                return true;
            }
        }
        self.retired_handles.iter().any(|(h, _)| matches(h))
    }

    fn withdraw_announcement(&mut self, now: Instant) {
        if let Some(prev) = self.active_handle.take() {
            self.retired_handles
                .push_back((prev, now + RETIRED_HANDLE_RETENTION));
            self.backend.unregister();
        }
        self.next_rotate = None;
    }

    fn shutdown(&mut self) {
        if self.running {
            self.backend.stop();
        }
        self.running = false;
        self.active_handle = None;
        self.retired_handles.clear();
        self.window_until = None;
        self.next_rotate = None;
        self.probe_due = None;
        self.host_unreach_streak = 0;
        self.set_posture(AnnouncePosture::AtRest);
        self.forget_all();
    }

    fn forget_all(&mut self) {
        self.instances.clear();
        self.table().clear_source(Source::Mdns);
    }

    /// Opens a bounded 120 s announcement window on local activation when running in `timed`
    /// mode. Returns `true` when an announcement is active afterwards.
    pub fn activate_announce_window(&mut self, inputs: &Inputs, now: Instant) -> bool {
        if !self.running || inputs.effective_announce_mode() != AnnounceMode::Timed {
            return false;
        }
        if let Some(reason) = self.announce_precondition_refusal(inputs) {
            self.withdraw_announcement(now);
            self.window_until = None;
            self.set_posture(AnnouncePosture::AtRest);
            self.warn_once(
                &reason,
                "LAN discovery cannot announce; staying browse-only at rest",
            );
            return false;
        }
        let Some(listen) = inputs.fed_listen else {
            return false;
        };
        let until = now + ANNOUNCE_WINDOW;
        self.window_until = Some(until);
        if self.rotate_announcement(listen, now) {
            self.set_posture(AnnouncePosture::WindowOpen { until });
            true
        } else {
            self.window_until = None;
            self.set_posture(AnnouncePosture::AtRest);
            false
        }
    }

    /// One reconcile tick: start, stop or toggle from the current config, follow interface
    /// changes, schedule the non-announcing Local Network probe, refresh and expire candidates.
    pub fn reconcile(&mut self, inputs: &Inputs, now: Instant) {
        self.prune_retired_handles(now);
        if !inputs.configured() {
            let _ = self.trigger.swap(false, Ordering::SeqCst);
            self.shutdown();
            self.set(State::Off, "");
            return;
        }
        self.ttl = Duration::from_secs(inputs.ttl_secs.clamp(1, MAX_TTL_SECS));
        let mdns_cfg = inputs.mdns.unwrap_or(MdnsConfig {
            browse: false,
            announce: false,
        });
        if !self.running {
            self.set(State::Starting, "starting the mDNS responder");
            self.set_posture(AnnouncePosture::AtRest);
            if let Err(error) = self.backend.start() {
                self.warn_once(&error, "LAN discovery failed to start; serving without it");
                self.set(State::Failed, error);
                return;
            }
            self.running = true;
            self.interfaces = self.backend.interfaces();
            self.host_unreach_streak = 0;
            self.probe_due = Some(now);
        }
        if self.browse && !mdns_cfg.browse {
            self.forget_all();
        }
        self.browse = mdns_cfg.browse;

        let interfaces = self.backend.interfaces();
        let changed = interfaces != self.interfaces;
        if changed {
            self.interfaces = interfaces;
            self.drop_gone_interfaces();
            self.probe_due = Some(now);
        } else if self.probe_due.is_none() {
            // Re-probe each tick so toggling macOS Local Network updates state without restart.
            self.probe_due = Some(now);
        }

        self.sync_announce(inputs, changed, now);
        self.step_timers(inputs, now);

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

    fn sync_announce(&mut self, inputs: &Inputs, interfaces_changed: bool, now: Instant) {
        match inputs.effective_announce_mode() {
            AnnounceMode::BrowseOnly => {
                let _ = self.trigger.swap(false, Ordering::SeqCst);
                self.window_until = None;
                self.withdraw_announcement(now);
                self.set_posture(AnnouncePosture::AtRest);
            }
            AnnounceMode::Timed => {
                // At startup and at rest, timed mode never announces until locally activated.
                if let Some(until) = self.window_until {
                    if now >= until {
                        self.window_until = None;
                        self.withdraw_announcement(now);
                        self.set_posture(AnnouncePosture::AtRest);
                    } else if let Some(reason) = self.announce_precondition_refusal(inputs) {
                        self.window_until = None;
                        self.withdraw_announcement(now);
                        self.set_posture(AnnouncePosture::AtRest);
                        self.warn_once(
                            &reason,
                            "LAN discovery cannot announce; returning to browse-only at rest",
                        );
                    } else if interfaces_changed || self.active_handle.is_none() {
                        if let Some(listen) = inputs.fed_listen {
                            if self.rotate_announcement(listen, now) {
                                self.set_posture(AnnouncePosture::WindowOpen { until });
                            } else {
                                self.window_until = None;
                                self.set_posture(AnnouncePosture::AtRest);
                            }
                        }
                    } else {
                        self.set_posture(AnnouncePosture::WindowOpen { until });
                    }
                } else {
                    self.withdraw_announcement(now);
                    self.set_posture(AnnouncePosture::AtRest);
                }
            }
            AnnounceMode::Always => {
                let _ = self.trigger.swap(false, Ordering::SeqCst);
                self.window_until = None;
                if let Some(reason) = self.announce_precondition_refusal(inputs) {
                    self.withdraw_announcement(now);
                    self.set_posture(AnnouncePosture::AtRest);
                    self.warn_once(&reason, "LAN discovery is browse-only");
                } else if let Some(listen) = inputs.fed_listen {
                    if interfaces_changed
                        || self.active_handle.is_none()
                        || self.next_rotate.is_some_and(|r| now >= r)
                    {
                        if self.rotate_announcement(listen, now) {
                            self.set_posture(AnnouncePosture::Always);
                        } else {
                            self.set_posture(AnnouncePosture::AtRest);
                        }
                    } else {
                        self.set_posture(AnnouncePosture::Always);
                    }
                }
            }
        }
    }

    /// Advances due timers between 30 s reconcile ticks: local announce triggers, 120 s window
    /// expiry, 30 s handle rotations, and debounced Local Network multicast probes.
    pub fn step_timers(&mut self, inputs: &Inputs, now: Instant) {
        self.prune_retired_handles(now);
        if !self.running {
            return;
        }
        if self.trigger.swap(false, Ordering::SeqCst) {
            let _ = self.activate_announce_window(inputs, now);
        }
        if let Some(until) = self.window_until {
            if now >= until {
                self.window_until = None;
                self.withdraw_announcement(now);
                self.set_posture(AnnouncePosture::AtRest);
            }
        }
        let announcing = self.window_until.is_some()
            || (inputs.effective_announce_mode() == AnnounceMode::Always
                && self.active_handle.is_some());
        if announcing && self.next_rotate.is_some_and(|r| now >= r) {
            if let Some(listen) = inputs.fed_listen {
                if !self.rotate_announcement(listen, now) {
                    self.window_until = None;
                    self.set_posture(AnnouncePosture::AtRest);
                }
            }
        }
        if self.probe_due.is_some_and(|d| now >= d) {
            self.run_probe_step(now);
        }
    }

    fn announce_precondition_refusal(&self, inputs: &Inputs) -> Option<String> {
        let Some(listen) = inputs.fed_listen else {
            return Some("no --fed-listen address to announce".into());
        };
        let ip = listen.ip();
        if !ip.is_unspecified() && !self.interfaces.iter().any(|(_, a)| *a == ip) {
            return Some(format!(
                "--fed-listen {ip} is not an address on a LAN interface"
            ));
        }
        if self.interfaces.is_empty() || announce_addrs(listen, &self.interfaces).is_empty() {
            return Some(format!("--fed-listen {ip} has no dialable LAN address"));
        }
        None
    }

    /// Unregisters any prior handle, mints a fresh 128-bit handle, and registers the rotated
    /// service instance + target hostname + TXT. On `getrandom` failure, falls back to
    /// browse-only at rest (`warn_once`).
    fn rotate_announcement(&mut self, listen: SocketAddr, now: Instant) -> bool {
        self.withdraw_announcement(now);
        let id = match (self.id_gen)() {
            Ok(id) if !id.is_empty() => id,
            Ok(_) => {
                let reason = "empty random handle for the announcement";
                self.warn_once(reason, "LAN discovery is browse-only");
                return false;
            }
            Err(error) => {
                let reason = format!("no random id for the announcement: {error}");
                self.warn_once(&reason, "LAN discovery is browse-only");
                return false;
            }
        };
        let addrs = announce_addrs(listen, &self.interfaces);
        if addrs.is_empty() {
            let reason = format!("--fed-listen {} has no dialable LAN address", listen.ip());
            self.warn_once(&reason, "LAN discovery is browse-only");
            return false;
        }
        match self.backend.register(&id, listen.port(), &addrs, &txt(&id)) {
            Ok(()) => {
                self.active_handle = Some(id);
                self.next_rotate = Some(now + ROTATE_INTERVAL);
                true
            }
            Err(error) => {
                self.warn_once(&error, "LAN discovery could not announce");
                self.set(State::Failed, error);
                false
            }
        }
    }

    fn run_probe_step(&mut self, now: Instant) {
        let lan_v4 = lan_ipv4_addrs(&self.interfaces);
        let qname = ln_query_name(self.query_mode);
        let outcome = self.backend.probe_multicast(&qname, &lan_v4);
        // If announcing failed (`register` error), don't overwrite `Failed` until next start/announce.
        let preserve_failed = self.state() == State::Failed;
        match outcome {
            ProbeOutcome::OwnLanReply(ip)
                if lan_v4.contains(&ip) && acceptable_ip(IpAddr::V4(ip)) =>
            {
                self.host_unreach_streak = 0;
                self.probe_due = None;
                if !preserve_failed {
                    self.warned = None;
                    self.set(
                        State::Active,
                        format!("multicast query answered from own LAN address {ip}"),
                    );
                }
            }
            ProbeOutcome::OwnLanReply(_) | ProbeOutcome::SentNoReply => {
                self.host_unreach_streak = 0;
                self.probe_due = None;
                if !preserve_failed {
                    self.set(
                        State::Unverified,
                        "outbound multicast sent without error, no own-LAN reply; Local Network permission unverified or no LAN responder",
                    );
                }
            }
            ProbeOutcome::NoLanInterface => {
                self.host_unreach_streak = 0;
                self.probe_due = None;
                if !preserve_failed {
                    self.set(
                        State::Unverified,
                        "no non-loopback IPv4 interface (0 IPv4 interfaces); Local Network permission unverified",
                    );
                }
            }
            ProbeOutcome::SendBlocked(cause) => {
                self.host_unreach_streak = self.host_unreach_streak.saturating_add(1);
                if self.host_unreach_streak >= LN_DEBOUNCE_CONSECUTIVE {
                    self.probe_due = None;
                    let detail =
                        permission_suspected_detail(&cause, self.host_unreach_streak, lan_v4.len());
                    self.warn_once(
                        &detail,
                        "LAN discovery outbound multicast blocked; serving without it",
                    );
                    if !preserve_failed {
                        self.set(State::PermissionSuspected, detail);
                    }
                } else {
                    self.probe_due = Some(now + LN_PROBE_RETRY_INTERVAL);
                }
            }
        }
    }

    fn next_wake(&self, next_tick: Instant) -> Instant {
        [self.window_until, self.next_rotate, self.probe_due]
            .into_iter()
            .flatten()
            .fold(next_tick, Instant::min)
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
                self.active_handle = None;
                self.retired_handles.clear();
                self.window_until = None;
                self.next_rotate = None;
                self.probe_due = None;
                self.set_posture(AnnouncePosture::AtRest);
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
        // Another instance (a restarted or rotated peer) may announce the same address: keep it then.
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
        if self.is_own_handle(id, &fullname) {
            return;
        }
        if !self.browse {
            return;
        }
        // Reject malformed records whole; ignore unknown/legacy TXT keys (including `root`).
        if let Some(ver) = value("v") {
            if ver != PROTOCOL_VERSION {
                return;
            }
        }
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
                        // mDNS never carries or trusts CA-root fingerprints.
                        root_fp: None,
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
    /// bounded timers and events in between.
    pub fn run(mut self, mut inputs: impl FnMut() -> Inputs) {
        let mut current = inputs();
        let mut next_tick = Instant::now();
        loop {
            if STOP.load(Ordering::SeqCst) {
                self.shutdown();
                STOPPED.store(true, Ordering::SeqCst);
                return;
            }
            let now = Instant::now();
            if now >= next_tick {
                current = inputs();
                self.reconcile(&current, now);
                next_tick = now + TICK;
            } else {
                if self.trigger.load(Ordering::SeqCst) {
                    current = inputs();
                }
                self.step_timers(&current, now);
            }
            let wake = self.next_wake(next_tick);
            let wait = wake
                .saturating_duration_since(now)
                .clamp(Duration::from_millis(25), Duration::from_millis(250));
            if !self.running {
                std::thread::sleep(wait);
            } else if let Some(event) = self.backend.recv(wait) {
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
/// only debug-logs its own bind failure, so this is how one is seen.
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
        probe_bind(MDNS_PORT)?;
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
        self.unregister();
        let daemon = self.daemon.as_ref().ok_or("mDNS responder not running")?;
        let host = format!("{id}.local.");
        let info = mdns_sd::ServiceInfo::new(SERVICE_TYPE, id, &host, addrs, port, txt)
            .map_err(|e| format!("invalid mDNS announcement: {e}"))?;
        let fullname = info.get_fullname().to_string();
        daemon
            .register(info)
            .map_err(|e| format!("mDNS announce failed: {e}"))?;
        self.registered = Some(fullname);
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

    fn probe_multicast(&mut self, qname: &str, lan_v4: &[Ipv4Addr]) -> ProbeOutcome {
        probe_multicast_ipv4(qname, lan_v4, LN_PROBE_RECV_TIMEOUT)
    }
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
    trigger: Arc<AtomicBool>,
) {
    let engine = Engine::with_trigger_and_query(
        MdnsSd::default(),
        Box::new(random_id),
        LN_QUERY_MODE,
        status,
        candidates,
        trigger,
    );
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
                    mdns,
                    announce: peers.discovery.announce,
                    ttl_secs: peers.discovery.ttl_secs,
                    fed_listen,
                }
            })
        });
    if let Err(error) = spawned {
        tracing::warn!(%error, "LAN discovery thread failed to start; serving without it");
    }
}
