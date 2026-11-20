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
//! - **Deny arm (always active, zero disclosure):** an IPv4 multicast DNS `A` query for a fresh
//!   random opaque label `xmsg-<32-hex>.local` to `224.0.0.251:5353`, debounced across
//!   [`LN_DEBOUNCE_CONSECUTIVE`] consecutive send failures (`EHOSTUNREACH`) into
//!   [`State::PermissionSuspected`]. The OS hostname is never queried or disclosed.
//! - **Positive arm (only while announcing):** our own `_xmsg._tcp.local.` announcement resolving
//!   back on one of this host's own non-loopback LAN addresses transitions [`State`] to
//!   [`State::Active`]. At rest (no open announce window), the state is [`State::Unverified`].
//! - IPv6 multicast gating and IPv6 link-local (`fe80::/10`) candidates are not probed or dialled.

use super::{
    acceptable_ip, AnnounceMode, AnnouncePosture, Candidate, MdnsConfig, SharedCandidates,
    SharedStatus, Source, State, ANNOUNCE_WINDOW_SECS, HANDLE_ROTATE_SECS, MAX_TTL_SECS,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

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
/// Bounded exponential backoff range for retrying a transient `register` failure.
pub const REGISTER_RETRY_BASE: Duration = Duration::from_secs(2);
pub const REGISTER_RETRY_MAX: Duration = Duration::from_secs(30);
pub const MDNS_MULTICAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_PORT: u16 = 5353;

const MAX_INSTANCES: usize = 256;
const MAX_ID_LEN: usize = 64;

/// Outcome of one non-announcing random-label IPv4 multicast send to `224.0.0.251:5353`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// `sendto` to `224.0.0.251:5353` succeeded without error.
    SentOk,
    /// Host has no up, non-loopback, dialable IPv4 interface to probe on.
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

/// A fresh 128-bit (32 hex chars) CSPRNG opaque handle.
pub fn random_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| e.to_string())?;
    Ok(hex::encode(bytes))
}

/// Builds a fresh random opaque `.local` query name (`xmsg-<32-hex>.local`) for the deny detector.
/// Never falls back to an all-zero or OS-hostname label: if CSPRNG fails, returns `Err` so the
/// caller skips sending the probe packet.
pub fn random_query_name(
    id_gen: &mut dyn FnMut() -> Result<String, String>,
) -> Result<String, String> {
    let id = id_gen()?;
    if id.is_empty() {
        return Err("empty random query label".into());
    }
    Ok(format!("xmsg-{id}.local"))
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
/// ephemeral UDP socket to detect kernel/TCC `EHOSTUNREACH` on explicit Local Network denial.
/// Never queries the OS hostname and never sends unicast-to-self.
pub fn probe_multicast_ipv4(qname: &str, lan_v4: &[Ipv4Addr]) -> ProbeOutcome {
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
    match socket.send_to(&pkt, dest) {
        Ok(_) => ProbeOutcome::SentOk,
        Err(e) => {
            let is_unreach = e.kind() == std::io::ErrorKind::HostUnreachable
                || e.raw_os_error() == Some(libc::EHOSTUNREACH);
            let msg = if is_unreach {
                format!("EHOSTUNREACH ({e})")
            } else {
                e.to_string()
            };
            ProbeOutcome::SendBlocked(msg)
        }
    }
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

#[derive(Clone, Debug)]
struct InstanceEntry {
    addrs: Vec<(SocketAddr, Vec<String>)>,
    seen_at: Instant,
}

pub type IdGen = Box<dyn FnMut() -> Result<String, String> + Send>;

pub struct Engine<B> {
    pub backend: B,
    id_gen: IdGen,
    status: SharedStatus,
    candidates: SharedCandidates,
    changed: Arc<Notify>,
    trigger: Arc<AtomicBool>,
    running: bool,
    browse: bool,
    active_handle: Option<String>,
    retired_handles: VecDeque<(String, Instant)>,
    own_echo_seen: bool,
    window_until: Option<Instant>,
    next_rotate: Option<Instant>,
    register_failures: u32,
    register_retry_at: Option<Instant>,
    prior_state: Option<(State, String)>,
    probe_due: Option<Instant>,
    host_unreach_streak: u32,
    interfaces: Vec<(String, IpAddr)>,
    instances: HashMap<String, InstanceEntry>,
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
        Self::with_trigger(
            backend,
            id_gen,
            status,
            candidates,
            Arc::new(AtomicBool::new(false)),
        )
    }

    pub fn with_trigger(
        backend: B,
        id_gen: IdGen,
        status: SharedStatus,
        candidates: SharedCandidates,
        trigger: Arc<AtomicBool>,
    ) -> Self {
        Self::with_notify(
            backend,
            id_gen,
            status,
            candidates,
            Arc::new(Notify::new()),
            trigger,
        )
    }

    pub fn with_notify(
        backend: B,
        id_gen: IdGen,
        status: SharedStatus,
        candidates: SharedCandidates,
        changed: Arc<Notify>,
        trigger: Arc<AtomicBool>,
    ) -> Self {
        Self {
            backend,
            id_gen,
            status,
            candidates,
            changed,
            trigger,
            running: false,
            browse: false,
            active_handle: None,
            retired_handles: VecDeque::new(),
            own_echo_seen: false,
            window_until: None,
            next_rotate: None,
            register_failures: 0,
            register_retry_at: None,
            prior_state: None,
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

    fn status_pair(&self) -> (State, String) {
        let s = self.status.lock().unwrap_or_else(PoisonError::into_inner);
        (s.state, s.detail.clone())
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

    pub fn instance_count(&self) -> usize {
        self.instances.len()
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

    fn notify_changed(&self) {
        self.changed.notify_one();
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

    fn matches_handle(h: &str, id: Option<&str>, fullname: &str) -> bool {
        id == Some(h)
            || fullname
                .strip_suffix(&format!(".{SERVICE_TYPE}"))
                .is_some_and(|inst| inst == h)
    }

    fn is_active_handle(&self, id: Option<&str>, fullname: &str) -> bool {
        self.active_handle
            .as_deref()
            .is_some_and(|h| Self::matches_handle(h, id, fullname))
    }

    fn is_own_handle(&self, id: Option<&str>, fullname: &str) -> bool {
        self.is_active_handle(id, fullname)
            || self
                .retired_handles
                .iter()
                .any(|(h, _)| Self::matches_handle(h, id, fullname))
    }

    /// Withdraws any active announcement and, when exiting an announce window to at-rest, drops
    /// `own_echo_seen` so at-rest state honestly reports `Unverified` (unless `PermissionSuspected`).
    fn stop_announcing(&mut self, now: Instant) {
        if let Some(prev) = self.active_handle.take() {
            self.retired_handles
                .push_back((prev, now + RETIRED_HANDLE_RETENTION));
            self.backend.unregister();
        }
        self.next_rotate = None;
        let had_echo = std::mem::replace(&mut self.own_echo_seen, false);
        let recovering_failed = self.register_failures > 0;
        let restored = self.prior_state.take();
        self.register_failures = 0;
        self.register_retry_at = None;
        if had_echo && self.state() == State::Active {
            self.set(
                State::Unverified,
                "announcement stopped; Local Network permission unverified while at rest",
            );
            self.probe_due = Some(now);
        } else if recovering_failed && self.state() == State::Failed {
            if let Some((prev_state, prev_detail)) = restored {
                self.set(prev_state, prev_detail);
            } else {
                self.set(
                    State::Unverified,
                    "announcement window closed; Local Network permission unverified while at rest",
                );
            }
            self.probe_due = Some(now);
        }
    }

    fn unregister_for_rotation(&mut self, now: Instant) {
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
        self.own_echo_seen = false;
        self.window_until = None;
        self.next_rotate = None;
        self.register_failures = 0;
        self.register_retry_at = None;
        self.prior_state = None;
        self.probe_due = None;
        self.host_unreach_streak = 0;
        self.set_posture(AnnouncePosture::AtRest);
        self.forget_all();
    }

    fn forget_all(&mut self) {
        self.instances.clear();
        let changed = {
            let mut table = self.table();
            let before = table.len();
            table.clear_source(Source::Mdns);
            table.len() != before
        };
        if changed {
            self.notify_changed();
        }
    }

    /// Opens a bounded 120 s announcement window on local activation when running in `timed`
    /// mode. Returns `true` when an announcement is immediately registered (a transient `register`
    /// failure keeps the window open and retries with bounded backoff).
    pub fn activate_announce_window(&mut self, inputs: &Inputs, now: Instant) -> bool {
        if !self.running || inputs.effective_announce_mode() != AnnounceMode::Timed {
            return false;
        }
        if let Some(reason) = self.announce_precondition_refusal(inputs) {
            self.window_until = None;
            self.stop_announcing(now);
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
        self.own_echo_seen = false;
        self.set_posture(AnnouncePosture::WindowOpen { until });
        match self.rotate_announcement(listen, now) {
            AnnounceAttempt::Registered => true,
            AnnounceAttempt::TransientError => false,
            AnnounceAttempt::Unusable => {
                self.window_until = None;
                self.stop_announcing(now);
                self.set_posture(AnnouncePosture::AtRest);
                false
            }
        }
    }

    /// One reconcile tick: start, stop or toggle from the current config, follow interface
    /// changes, schedule the non-announcing Local Network deny probe, refresh and expire candidates.
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
            self.own_echo_seen = false;
            self.drop_gone_interfaces();
            self.probe_due = Some(now);
        } else if self.probe_due.is_none() {
            // Re-probe each tick so toggling macOS Local Network updates state without restart.
            self.probe_due = Some(now);
        }

        self.sync_announce(inputs, changed, now);
        self.step_timers(inputs, now);

        let expired = {
            let mut table = self.table();
            let before = table.len();
            table.expire(now);
            let expired = table.len() != before;
            // Instances mdns-sd still holds stay live; its own record expiry arrives as a removal.
            let live: HashSet<SocketAddr> = self
                .instances
                .values()
                .flat_map(|entry| entry.addrs.iter().map(|(addr, _)| *addr))
                .collect();
            for mut c in table.snapshot(now) {
                if c.source == Source::Mdns && live.contains(&c.addr) {
                    c.expires_at = now + self.ttl;
                    table.upsert(c, now);
                }
            }
            expired
        };
        if expired {
            self.notify_changed();
        }
    }

    fn sync_announce(&mut self, inputs: &Inputs, interfaces_changed: bool, now: Instant) {
        match inputs.effective_announce_mode() {
            AnnounceMode::BrowseOnly => {
                let _ = self.trigger.swap(false, Ordering::SeqCst);
                self.window_until = None;
                self.stop_announcing(now);
                self.set_posture(AnnouncePosture::AtRest);
            }
            AnnounceMode::Timed => {
                // At startup and at rest, timed mode never announces until locally activated.
                if let Some(until) = self.window_until {
                    if now >= until {
                        self.window_until = None;
                        self.stop_announcing(now);
                        self.set_posture(AnnouncePosture::AtRest);
                    } else if let Some(reason) = self.announce_precondition_refusal(inputs) {
                        self.window_until = None;
                        self.stop_announcing(now);
                        self.set_posture(AnnouncePosture::AtRest);
                        self.warn_once(
                            &reason,
                            "LAN discovery cannot announce; returning to browse-only at rest",
                        );
                    } else if interfaces_changed
                        || (self.active_handle.is_none() && self.register_retry_at.is_none())
                    {
                        if let Some(listen) = inputs.fed_listen {
                            if self.rotate_announcement(listen, now) == AnnounceAttempt::Unusable {
                                self.window_until = None;
                                self.stop_announcing(now);
                                self.set_posture(AnnouncePosture::AtRest);
                            } else {
                                self.set_posture(AnnouncePosture::WindowOpen { until });
                            }
                        }
                    } else {
                        self.set_posture(AnnouncePosture::WindowOpen { until });
                    }
                } else {
                    self.stop_announcing(now);
                    self.set_posture(AnnouncePosture::AtRest);
                }
            }
            AnnounceMode::Always => {
                let _ = self.trigger.swap(false, Ordering::SeqCst);
                self.window_until = None;
                if let Some(reason) = self.announce_precondition_refusal(inputs) {
                    self.stop_announcing(now);
                    self.set_posture(AnnouncePosture::AtRest);
                    self.warn_once(&reason, "LAN discovery is browse-only");
                } else if let Some(listen) = inputs.fed_listen {
                    let retry_ready = self.register_retry_at.is_none_or(|t| now >= t);
                    let need_register = interfaces_changed
                        || (self.active_handle.is_none() && retry_ready)
                        || self.next_rotate.is_some_and(|r| now >= r);
                    if need_register {
                        match self.rotate_announcement(listen, now) {
                            AnnounceAttempt::Registered | AnnounceAttempt::TransientError => {
                                self.set_posture(AnnouncePosture::Always);
                            }
                            AnnounceAttempt::Unusable => {
                                self.stop_announcing(now);
                                self.set_posture(AnnouncePosture::AtRest);
                            }
                        }
                    } else {
                        self.set_posture(AnnouncePosture::Always);
                    }
                }
            }
        }
    }

    /// Advances due timers between 30 s reconcile ticks: local announce triggers, 120 s window
    /// expiry, 30 s handle rotations, bounded `register` retries, and debounced deny probes.
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
                self.stop_announcing(now);
                self.set_posture(AnnouncePosture::AtRest);
            }
        }
        let should_announce = self.window_until.is_some()
            || (inputs.effective_announce_mode() == AnnounceMode::Always
                && self.announce_precondition_refusal(inputs).is_none());
        let retry_due = self.register_retry_at.is_some_and(|t| now >= t);
        let rotate_due = self.active_handle.is_some() && self.next_rotate.is_some_and(|r| now >= r);
        if should_announce && (retry_due || rotate_due) {
            if let Some(listen) = inputs.fed_listen {
                if self.rotate_announcement(listen, now) == AnnounceAttempt::Unusable {
                    self.window_until = None;
                    self.stop_announcing(now);
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
    /// browse-only (`Unusable`). On transient `register` failure, schedules bounded backoff
    /// retry (`TransientError`) and restores the prior non-failed state once retry succeeds.
    fn rotate_announcement(&mut self, listen: SocketAddr, now: Instant) -> AnnounceAttempt {
        self.unregister_for_rotation(now);
        let id = match (self.id_gen)() {
            Ok(id) if !id.is_empty() => id,
            Ok(_) => {
                let reason = "empty random handle for the announcement";
                self.warn_once(reason, "LAN discovery is browse-only");
                return AnnounceAttempt::Unusable;
            }
            Err(error) => {
                let reason = format!("no random id for the announcement: {error}");
                self.warn_once(&reason, "LAN discovery is browse-only");
                return AnnounceAttempt::Unusable;
            }
        };
        let addrs = announce_addrs(listen, &self.interfaces);
        if addrs.is_empty() {
            let reason = format!("--fed-listen {} has no dialable LAN address", listen.ip());
            self.warn_once(&reason, "LAN discovery is browse-only");
            return AnnounceAttempt::Unusable;
        }
        match self.backend.register(&id, listen.port(), &addrs, &txt(&id)) {
            Ok(()) => {
                self.active_handle = Some(id);
                self.next_rotate = Some(now + ROTATE_INTERVAL);
                self.register_retry_at = None;
                if self.register_failures > 0 {
                    self.register_failures = 0;
                    self.warned = None;
                    if let Some((prev_state, prev_detail)) = self.prior_state.take() {
                        self.set(prev_state, prev_detail);
                    } else {
                        self.set(
                            State::Unverified,
                            "announcement registered after retry; Local Network permission unverified",
                        );
                    }
                    self.probe_due = Some(now);
                }
                AnnounceAttempt::Registered
            }
            Err(error) => {
                if self.register_failures == 0 && self.state() != State::Failed {
                    let cur = self.status_pair();
                    if cur.0 != State::Starting {
                        self.prior_state = Some(cur);
                    }
                }
                self.register_failures = self.register_failures.saturating_add(1);
                let shift = (self.register_failures - 1).min(4);
                let backoff = (REGISTER_RETRY_BASE * (1 << shift)).min(REGISTER_RETRY_MAX);
                self.register_retry_at = Some(now + backoff);
                self.warn_once(&error, "LAN discovery could not announce; retrying");
                self.set(State::Failed, error);
                AnnounceAttempt::TransientError
            }
        }
    }

    fn run_probe_step(&mut self, now: Instant) {
        let lan_v4 = lan_ipv4_addrs(&self.interfaces);
        let preserve_failed = self.register_failures > 0 && self.state() == State::Failed;
        if lan_v4.is_empty() {
            self.host_unreach_streak = 0;
            self.probe_due = None;
            self.own_echo_seen = false;
            if !preserve_failed {
                self.set(
                    State::Unverified,
                    "no non-loopback IPv4 interface (0 IPv4 interfaces); Local Network permission unverified",
                );
            }
            return;
        }
        let qname = match random_query_name(&mut *self.id_gen) {
            Ok(q) => q,
            Err(error) => {
                // N3: never fall back to an all-zero or predictable label; skip the probe instead.
                self.probe_due = None;
                if !preserve_failed && !(self.active_handle.is_some() && self.own_echo_seen) {
                    self.set(
                        State::Unverified,
                        format!("multicast deny probe skipped (no random label: {error}); Local Network permission unverified"),
                    );
                }
                return;
            }
        };
        match self.backend.probe_multicast(&qname, &lan_v4) {
            ProbeOutcome::SentOk => {
                self.host_unreach_streak = 0;
                self.probe_due = None;
                // Keep `Active` while an open announcement has already echoed on our own LAN IP;
                // otherwise at rest (or before our _xmsg echo arrives) report `Unverified`.
                if !preserve_failed && !(self.active_handle.is_some() && self.own_echo_seen) {
                    self.set(
                        State::Unverified,
                        "outbound multicast sent without error; Local Network permission unverified while at rest",
                    );
                }
            }
            ProbeOutcome::NoLanInterface => {
                self.host_unreach_streak = 0;
                self.probe_due = None;
                self.own_echo_seen = false;
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
                    self.own_echo_seen = false;
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
        [
            self.window_until,
            self.next_rotate,
            self.register_retry_at,
            self.probe_due,
        ]
        .into_iter()
        .flatten()
        .fold(next_tick, Instant::min)
    }

    fn drop_gone_interfaces(&mut self) {
        let names: HashSet<&str> = self.interfaces.iter().map(|(n, _)| n.as_str()).collect();
        let mut gone = Vec::new();
        for entry in self.instances.values_mut() {
            entry.addrs.retain(|(addr, via)| {
                let keep = via.is_empty() || via.iter().any(|n| names.contains(n.as_str()));
                if !keep {
                    gone.push(*addr);
                }
                keep
            });
        }
        self.instances.retain(|_, entry| !entry.addrs.is_empty());
        let held = self.held();
        let gone: HashSet<SocketAddr> = gone.into_iter().filter(|a| !held.contains(a)).collect();
        let changed = {
            let mut table = self.table();
            let before = table.len();
            table.retain_source(Source::Mdns, |c| !gone.contains(&c.addr));
            table.len() != before
        };
        if changed {
            self.notify_changed();
        }
    }

    /// Addresses some known instance still announces.
    fn held(&self) -> HashSet<SocketAddr> {
        self.instances
            .values()
            .flat_map(|entry| entry.addrs.iter().map(|(addr, _)| *addr))
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
                self.own_echo_seen = false;
                self.window_until = None;
                self.next_rotate = None;
                self.register_failures = 0;
                self.register_retry_at = None;
                self.prior_state = None;
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
        if let Some(entry) = self.instances.remove(fullname) {
            let held = self.held();
            let mut changed = false;
            {
                let mut table = self.table();
                for (addr, _) in entry.addrs {
                    if !held.contains(&addr) && table.remove(Source::Mdns, addr) {
                        changed = true;
                    }
                }
            }
            if changed {
                self.notify_changed();
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
            // Positive Local Network arm (only while actively announcing): our own _xmsg
            // announcement resolving back over a non-loopback LAN interface (`via`) with one of
            // our own non-loopback LAN interface addresses.
            if self.is_active_handle(id, &fullname) {
                let own_lan_ip = addrs.iter().find_map(|(ip, via)| {
                    let on_lan_iface = via
                        .iter()
                        .any(|ifname| self.interfaces.iter().any(|(n, _)| n == ifname));
                    (on_lan_iface
                        && acceptable_ip(*ip)
                        && self.interfaces.iter().any(|(_, iface_ip)| *iface_ip == *ip))
                    .then_some(*ip)
                });
                if let Some(ip) = own_lan_ip {
                    self.own_echo_seen = true;
                    self.host_unreach_streak = 0;
                    if self.register_failures == 0 {
                        self.warned = None;
                        self.set(
                            State::Active,
                            format!("own _xmsg announcement echoed on LAN address {ip}"),
                        );
                    }
                }
            }
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
                .retain(|_, entry| entry.addrs.iter().any(|(a, _)| held.contains(a)));
            // N4: lost goodbyes from rotated handles sharing a live address must not wedge the
            // instance cap; evict the oldest instance sighting to make room.
            if self.instances.len() >= MAX_INSTANCES {
                if let Some(oldest_name) = self
                    .instances
                    .iter()
                    .min_by_key(|(_, entry)| entry.seen_at)
                    .map(|(name, _)| name.clone())
                {
                    self.remove_instance(&oldest_name);
                }
            }
        }
        let fresh: Vec<(SocketAddr, Vec<String>)> = addrs
            .into_iter()
            .map(|(ip, via)| (SocketAddr::new(ip, port), via))
            .collect();
        let ttl = self.ttl;
        let hint = id.map(str::to_string);
        let previous = self
            .instances
            .remove(&fullname)
            .map(|e| e.addrs)
            .unwrap_or_default();
        let held = self.held();
        let mut kept = Vec::new();
        let mut dropped = 0;
        let mut table_changed = false;
        {
            let mut table = self.table();
            for (addr, _) in &previous {
                if !fresh.iter().any(|(a, _)| a == addr)
                    && !held.contains(addr)
                    && table.remove(Source::Mdns, *addr)
                {
                    table_changed = true;
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
                    table_changed = true;
                    kept.push((addr, via));
                } else {
                    dropped += 1;
                }
            }
        }
        if table_changed {
            self.notify_changed();
        }
        self.dropped += dropped;
        tracing::debug!(
            instance = %fullname,
            kept = kept.len(),
            dropped,
            "LAN discovery candidate"
        );
        if !kept.is_empty() {
            self.instances.insert(
                fullname,
                InstanceEntry {
                    addrs: kept,
                    seen_at: now,
                },
            );
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnnounceAttempt {
    Registered,
    TransientError,
    Unusable,
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

impl MdnsSd {
    /// Whether any browse event is currently queued in the long-lived receiver.
    pub fn has_queued_events(&self) -> bool {
        self.events.as_ref().is_some_and(|rx| !rx.is_empty())
    }
}

/// Binds UDP `port` on `0.0.0.0` with the reuse options `mdns-sd` uses, then closes it.
/// `mdns-sd` 0.21.7 only debug-logs bind errors on startup, and treats `[::]:5353` bind failures
/// as non-fatal on IPv4-only / IPv6-disabled hosts, so probing IPv4 `0.0.0.0:5353` catches an
/// exclusive UDP 5353 holder without false-failing IPv4-only environments.
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
        probe_multicast_ipv4(qname, lan_v4)
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

/// Starts the source on its own thread; it reads the current peers map on every tick and writes
/// directly into `fed.discovery`.
pub fn spawn(fed: Arc<crate::fed::FedState>, fed_listen: Option<SocketAddr>) {
    STOP.store(false, Ordering::SeqCst);
    STOPPED.store(false, Ordering::SeqCst);
    let engine = Engine::with_notify(
        MdnsSd::default(),
        Box::new(random_id),
        fed.discovery.mdns_status.clone(),
        fed.discovery.candidates.clone(),
        fed.discovery.changed.clone(),
        fed.discovery.mdns_trigger.clone(),
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
