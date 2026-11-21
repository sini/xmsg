//! Process inspection behind a `proc_root` seam.
//!
//! Every caller passes a `proc_root`. A synthetic root (a test fixture directory)
//! is always read as a Linux-style procfs tree, on every platform. The live root
//! [`LIVE_PROC_ROOT`] is read from `/proc` on Linux and from the kernel through
//! `proc_pidinfo(2)` / `sysctl(3)` on macOS, which has no procfs.
//!
//! Start times are opaque strings compared for equality: on Linux the
//! `/proc/<pid>/stat` field 22 (clock ticks since boot), on macOS the process
//! start as microseconds since the epoch. Both only identify a process together
//! with its PID, so a reused PID never matches a stored start time.
//!
//! [`Ancestry`] also orders a parent against its child. On Linux it orders by the
//! same field 22, which is monotonic. The macOS token is wall-clock time and steps
//! back with the clock, so on macOS the walk orders by `ri_proc_start_abstime`
//! from `proc_pid_rusage(2)` instead, a `mach_absolute_time` reading taken at fork.

use std::fs;
use std::io;
use std::path::Path;

/// The proc root that means "the running system".
pub const LIVE_PROC_ROOT: &str = "/proc";

fn is_live(proc_root: &Path) -> bool {
    cfg!(target_os = "macos") && proc_root == Path::new(LIVE_PROC_ROOT)
}

/// Fields after the `(comm)` of `/proc/<pid>/stat`. Field 3 (state) is index 0.
fn stat_fields(proc_root: &Path, pid: u32) -> io::Result<Vec<String>> {
    let content = fs::read_to_string(proc_root.join(pid.to_string()).join("stat"))?;
    // comm can contain spaces or closing parens, so split at the LAST ')'
    let Some(rparen) = content.rfind(')') else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid stat"));
    };
    Ok(content[rparen + 1..]
        .split_whitespace()
        .map(str::to_string)
        .collect())
}

/// Returns the start time of `pid`, an opaque token stable for the process lifetime.
pub fn starttime(proc_root: &Path, pid: u32) -> io::Result<String> {
    if is_live(proc_root) {
        #[cfg(target_os = "macos")]
        return macos::bsdinfo(pid).map(|i| macos::starttime_token(&i));
    }
    let fields = stat_fields(proc_root, pid)?;
    // Field 22 (starttime) is index 19 after the closing paren
    fields
        .get(19)
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stat too short"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StartTimeProbe {
    Known(String),
    Unavailable,
    Gone,
}

fn classify_starttime_error(error: io::Error) -> io::Result<StartTimeProbe> {
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(StartTimeProbe::Gone),
        Some(libc::EPERM | libc::EACCES | libc::ENOSYS | libc::EOPNOTSUPP) => {
            Ok(StartTimeProbe::Unavailable)
        }
        _ => Err(error),
    }
}

pub(crate) fn probe_starttime(proc_root: &Path, pid: u32) -> io::Result<StartTimeProbe> {
    if pid == 0 {
        return Ok(StartTimeProbe::Gone);
    }
    #[cfg(target_os = "macos")]
    if is_live(proc_root) {
        return macos::probe_starttime(pid);
    }
    match starttime(proc_root, pid) {
        Ok(token) => Ok(StartTimeProbe::Known(token)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A missing peer is not evidence of death when the proc backend itself is absent.
            Ok(if starttime(proc_root, std::process::id()).is_ok() {
                StartTimeProbe::Gone
            } else {
                StartTimeProbe::Unavailable
            })
        }
        Err(error) => classify_starttime_error(error),
    }
}

/// One read of a process: its parent, its start token (as [`starttime`] returns it) and the
/// number its start is ordered by, `None` when that is not a number.
struct Link {
    ppid: u32,
    start: String,
    order: Option<u64>,
}

fn read_link(proc_root: &Path, pid: u32) -> Option<Link> {
    if is_live(proc_root) {
        #[cfg(target_os = "macos")]
        return macos::link(pid);
    }
    let fields = stat_fields(proc_root, pid).ok()?;
    let start = fields.get(19)?.clone();
    Some(Link {
        ppid: fields.get(1)?.parse().ok()?,
        order: start.parse().ok(),
        start,
    })
}

/// Why an [`Ancestry`] walk stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkEnd {
    /// The next parent is PID 0 or 1.
    Root,
    /// The stat or start time of `pid` cannot be read, or the start is not a number.
    Unreadable(u32),
    /// `parent` started after `child`, so it is a PID reused before it was read.
    Younger { parent: u32, child: u32 },
    /// `pid` no longer has the start time read when it was taken as a parent: reused since.
    Reused(u32),
}

#[derive(Debug, Clone)]
enum PeerPin {
    #[cfg(target_os = "linux")]
    Visible(std::sync::Arc<std::os::fd::OwnedFd>),
    #[cfg(target_os = "linux")]
    Unmapped(std::sync::Arc<std::os::fd::OwnedFd>),
    #[cfg(target_os = "linux")]
    Dead,
    Unpinned,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PidfdState {
    /// Exited / reaped process (`Pid: -1` in `/proc/self/fdinfo/<pidfd>`), or malformed /
    /// missing `Pid:` in a readable `fdinfo`.
    Dead,
    /// `/proc/self/fdinfo/<pidfd>` could not be read (e.g. `/proc` unmounted, sandbox without
    /// procfs, or hardened host): cannot pin via `pidfd`.
    Unreadable,
    /// Live process in a PID namespace not visible to the reader (`Pid: 0`).
    Unmapped,
    /// Live process visible in the reader's PID namespace (`Pid: > 0`).
    Visible(u32),
}

/// Credentials and root-PID pin for a peer connected over a Unix stream socket.
///
/// On Linux kernels supporting `SO_PEERPIDFD` (>= 6.5), holds an `OwnedFd` `pidfd` referring
/// to the peer's kernel `struct pid`. Because the kernel cannot recycle numeric PID `P` while
/// `/proc/self/fdinfo/<pidfd>` reports `Pid:\t<P>` (`P > 0`), checking the `pidfd` before and
/// after reading the root's `<proc_root>/<P>/stat` guarantees the walk starts from the peer
/// process that called `connect()`, never a replacement process that reused `P`. A live peer in
/// a separate PID namespace reports `Pid:\t0` ([`PidfdState::Unmapped`]) while alive and
/// `Pid:\t-1` ([`PidfdState::Dead`]) once reaped.
#[derive(Debug, Clone)]
pub struct PeerCred {
    pub uid: u32,
    pub pid: Option<u32>,
    pin: PeerPin,
}

#[cfg(target_os = "linux")]
static PEERPIDFD_FALLBACK_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "linux")]
static FORCE_PEERPIDFD_ERRNO: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

#[cfg(target_os = "linux")]
static FORCE_PIDFD_PID: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(i64::MIN);

#[cfg(target_os = "linux")]
static FORCE_PIDFD_FDINFO_FILE: std::sync::Mutex<Option<std::path::PathBuf>> =
    std::sync::Mutex::new(None);

/// Test seam: forces `getsockopt(SO_PEERPIDFD)` to fail with `errno` (or `0` to use the kernel).
pub fn set_force_peerpidfd_errno_for_test(errno: i32) {
    #[cfg(target_os = "linux")]
    {
        FORCE_PEERPIDFD_ERRNO.store(errno, std::sync::atomic::Ordering::SeqCst);
        if errno != 0 {
            PEERPIDFD_FALLBACK_WARNED.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = errno;
}

/// Test seam: forces `pidfd_state` to observe `pid` (`Some(0)` for alive-unmapped,
/// `Some(-1)` for dead, `Some(p)` for visible, or `None` to read kernel fdinfo).
pub fn set_force_pidfd_pid_for_test(pid: Option<i64>) {
    #[cfg(target_os = "linux")]
    {
        FORCE_PIDFD_PID.store(pid.unwrap_or(i64::MIN), std::sync::atomic::Ordering::SeqCst);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = pid;
}

/// Test seam: returns whether the `SO_PEERPIDFD` unavailable fallback path was taken since reset.
pub fn peerpidfd_fallback_warned_for_test() -> bool {
    #[cfg(target_os = "linux")]
    {
        PEERPIDFD_FALLBACK_WARNED.load(std::sync::atomic::Ordering::SeqCst)
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// Test seam: redirects `pidfd_state`'s fdinfo read from `/proc/self/fdinfo/<pidfd>` to `file`
/// (e.g. a nonexistent path for no-`/proc` tests, or a synthetic fdinfo file for `Pid: -1` and
/// malformed-line tests). Pass `None` to restore `/proc/self/fdinfo/<pidfd>`.
pub fn set_force_pidfd_fdinfo_file_for_test(file: Option<std::path::PathBuf>) {
    #[cfg(target_os = "linux")]
    {
        if file.is_some() {
            PEERPIDFD_FALLBACK_WARNED.store(false, std::sync::atomic::Ordering::SeqCst);
        }
        *FORCE_PIDFD_FDINFO_FILE.lock().unwrap() = file;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = file;
}

#[cfg(target_os = "linux")]
fn pidfd_state(fd: &std::os::fd::OwnedFd) -> PidfdState {
    use std::os::fd::AsRawFd;
    let forced = FORCE_PIDFD_PID.load(std::sync::atomic::Ordering::SeqCst);
    if forced != i64::MIN {
        return match forced {
            0 => PidfdState::Unmapped,
            p if p > 0 => u32::try_from(p)
                .map(PidfdState::Visible)
                .unwrap_or(PidfdState::Dead),
            _ => PidfdState::Dead,
        };
    }
    let fdinfo_path = FORCE_PIDFD_FDINFO_FILE
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| {
            std::path::PathBuf::from(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))
        });
    let Ok(content) = fs::read_to_string(fdinfo_path) else {
        return PidfdState::Unreadable;
    };
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Pid:") {
            let Ok(pid) = rest.trim().parse::<i64>() else {
                return PidfdState::Dead;
            };
            return match pid {
                0 => PidfdState::Unmapped,
                p if p > 0 => u32::try_from(p)
                    .map(PidfdState::Visible)
                    .unwrap_or(PidfdState::Dead),
                _ => PidfdState::Dead,
            };
        }
    }
    PidfdState::Dead
}

#[cfg(target_os = "linux")]
fn getsockopt_peerpidfd(stream: &tokio::net::UnixStream) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let forced = FORCE_PEERPIDFD_ERRNO.load(std::sync::atomic::Ordering::SeqCst);
    if forced != 0 {
        return Err(io::Error::from_raw_os_error(forced));
    }
    let mut pidfd: libc::c_int = -1;
    let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `stream.as_raw_fd()` is a valid socket fd; `pidfd` and `len` are properly aligned.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&mut pidfd as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    if pidfd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "SO_PEERPIDFD returned negative fd",
        ));
    }
    // SAFETY: the kernel returned a fresh file descriptor owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
}

/// Reads the peer's UID and pins its PID via `SO_PEERPIDFD` on Linux, falling back to
/// `SO_PEERCRED` (with a one-time warning log) only when the kernel does not support
/// `SO_PEERPIDFD` (`ENOPROTOOPT` / `ENOSYS` / `EOPNOTSUPP`), when `/proc/self/fdinfo/<pidfd>`
/// cannot be read, or on non-Linux targets.
pub fn peer_cred(stream: &tokio::net::UnixStream) -> io::Result<PeerCred> {
    let ucred = stream.peer_cred()?;
    let uid = ucred.uid();
    let fallback_pid = ucred
        .pid()
        .and_then(|p| u32::try_from(p).ok())
        .filter(|&p| p > 0);

    #[cfg(target_os = "linux")]
    {
        match getsockopt_peerpidfd(stream) {
            Ok(fd) => match pidfd_state(&fd) {
                PidfdState::Visible(live_pid) => Ok(PeerCred {
                    uid,
                    pid: Some(live_pid),
                    pin: PeerPin::Visible(std::sync::Arc::new(fd)),
                }),
                PidfdState::Unmapped => Ok(PeerCred {
                    uid,
                    pid: None,
                    pin: PeerPin::Unmapped(std::sync::Arc::new(fd)),
                }),
                PidfdState::Unreadable => {
                    if !PEERPIDFD_FALLBACK_WARNED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                        tracing::warn!(
                            "/proc/self/fdinfo/<pidfd> unreadable; falling back to SO_PEERCRED for peer PID resolution"
                        );
                    }
                    Ok(PeerCred {
                        uid,
                        pid: fallback_pid,
                        pin: PeerPin::Unpinned,
                    })
                }
                PidfdState::Dead => Ok(PeerCred {
                    uid,
                    pid: fallback_pid,
                    pin: PeerPin::Dead,
                }),
            },
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENOPROTOOPT | libc::ENOSYS | libc::EOPNOTSUPP)
                ) =>
            {
                if !PEERPIDFD_FALLBACK_WARNED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    tracing::warn!(
                        "SO_PEERPIDFD unavailable on this kernel ({e}); falling back to SO_PEERCRED for peer PID resolution"
                    );
                }
                Ok(PeerCred {
                    uid,
                    pid: fallback_pid,
                    pin: PeerPin::Unpinned,
                })
            }
            Err(_) => Ok(PeerCred {
                uid,
                pid: fallback_pid,
                pin: PeerPin::Dead,
            }),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(PeerCred {
            uid,
            pid: fallback_pid,
            pin: PeerPin::Unpinned,
        })
    }
}

impl PeerCred {
    pub(crate) fn service_pin_liveness(&self) -> Option<bool> {
        match &self.pin {
            #[cfg(target_os = "linux")]
            PeerPin::Dead => Some(false),
            #[cfg(target_os = "linux")]
            PeerPin::Visible(fd) => match pidfd_state(fd) {
                PidfdState::Visible(pid) => Some(self.pid == Some(pid)),
                PidfdState::Dead | PidfdState::Unmapped => Some(false),
                PidfdState::Unreadable => None,
            },
            #[cfg(target_os = "linux")]
            PeerPin::Unmapped(fd) => match pidfd_state(fd) {
                PidfdState::Unmapped => Some(true),
                PidfdState::Dead | PidfdState::Visible(_) => Some(false),
                PidfdState::Unreadable => None,
            },
            PeerPin::Unpinned => {
                if self.pid.is_some_and(|pid| pid > 0) {
                    None
                } else {
                    Some(false)
                }
            }
        }
    }

    /// Constructs an unpinned `PeerCred` from a bare `(uid, pid)` pair (for non-socket callers
    /// and unit tests that supply a numeric PID directly).
    pub fn unpinned(uid: u32, pid: u32) -> Self {
        PeerCred {
            uid,
            pid: (pid > 0).then_some(pid),
            pin: PeerPin::Unpinned,
        }
    }

    pub fn pid_or_zero(&self) -> u32 {
        self.pid.unwrap_or(0)
    }

    pub fn is_pinned(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            matches!(self.pin, PeerPin::Visible(_) | PeerPin::Unmapped(_))
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Whether this peer is pinned by `SO_PEERPIDFD` in another PID namespace (`Pid: 0`).
    pub fn is_unmapped(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            matches!(self.pin, PeerPin::Unmapped(_))
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    pub fn is_pin_alive(&self) -> bool {
        match &self.pin {
            #[cfg(target_os = "linux")]
            PeerPin::Dead => false,
            #[cfg(target_os = "linux")]
            PeerPin::Unmapped(fd) => pidfd_state(fd) == PidfdState::Unmapped,
            #[cfg(target_os = "linux")]
            PeerPin::Visible(fd) => self
                .pid
                .is_some_and(|p| p > 0 && pidfd_state(fd) == PidfdState::Visible(p)),
            PeerPin::Unpinned => self.pid.is_some_and(|p| p > 0),
        }
    }

    fn check_pin_alive(&self, expected_pid: u32) -> bool {
        match &self.pin {
            #[cfg(target_os = "linux")]
            PeerPin::Dead | PeerPin::Unmapped(_) => false,
            PeerPin::Unpinned => expected_pid > 0,
            #[cfg(target_os = "linux")]
            PeerPin::Visible(fd) => pidfd_state(fd) == PidfdState::Visible(expected_pid),
        }
    }

    /// Reads the start time of this peer in `proc_root`, bracketed by `pidfd` liveness checks
    /// when pinned so a recycled numeric PID is never read.
    pub fn starttime(&self, proc_root: &Path) -> io::Result<String> {
        let pid = self
            .pid
            .filter(|&p| p > 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "peer has no valid PID"))?;
        if !self.check_pin_alive(pid) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("peer process {pid} already reaped"),
            ));
        }
        let st = starttime(proc_root, pid)?;
        if !self.check_pin_alive(pid) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("peer process {pid} reaped during starttime read"),
            ));
        }
        Ok(st)
    }

    /// Reads the executable path of this peer in `proc_root`, bracketed by `pidfd` liveness checks.
    pub fn exe_path(&self, proc_root: &Path) -> io::Result<std::path::PathBuf> {
        let pid = self
            .pid
            .filter(|&p| p > 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "peer has no valid PID"))?;
        if !self.check_pin_alive(pid) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("peer process {pid} already reaped"),
            ));
        }
        let exe = exe_path(proc_root, pid)?;
        if !self.check_pin_alive(pid) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("peer process {pid} reaped during exe_path read"),
            ));
        }
        Ok(exe)
    }

    /// Checks that the peer is still alive with `expected_start`.
    pub fn is_alive(&self, proc_root: &Path, expected_start: &str) -> bool {
        #[cfg(target_os = "linux")]
        if let PeerPin::Unmapped(fd) = &self.pin {
            return expected_start == "0" && pidfd_state(fd) == PidfdState::Unmapped;
        }
        self.starttime(proc_root).ok().as_deref() == Some(expected_start)
    }
}

/// The ancestry walk every identity-attributing caller takes: yields `(pid, start)` for the
/// start PID and then each ancestor, where `start` is the token to match the process against.
/// Match against it rather than re-reading the start: a re-read can see a reused PID.
///
/// Each step reads the parent once and records its start. When the walk reaches the parent it
/// reads it again and requires the recorded start, so a PID reused after the step ends the
/// walk ([`WalkEnd::Reused`]) instead of continuing from the new process's parent. The walk
/// yields nothing past a failed step, and [`Ancestry::end`] says why it stopped.
pub struct Ancestry<'a> {
    proc_root: &'a Path,
    /// The PID to yield next and the start recorded when it was read as a parent.
    next: Option<(u32, Option<String>)>,
    root_pin: Option<PeerCred>,
    end: Option<WalkEnd>,
}

impl<'a> Ancestry<'a> {
    pub fn new(proc_root: &'a Path, start_pid: u32) -> Self {
        Ancestry {
            proc_root,
            next: Some((start_pid, None)),
            root_pin: None,
            end: None,
        }
    }

    /// Starts an ancestry walk pinned to `peer` (whose root PID is guarded by `SO_PEERPIDFD`
    /// on Linux when available). If the peer process has already been reaped before or during
    /// the root step's `read_link`, the walk yields nothing and [`Ancestry::end`] is
    /// [`WalkEnd::Reused`].
    pub fn from_peer(proc_root: &'a Path, peer: &PeerCred) -> Self {
        let Some(start_pid) = peer.pid.filter(|&p| p > 0) else {
            return Ancestry {
                proc_root,
                next: None,
                root_pin: None,
                end: Some(WalkEnd::Unreadable(0)),
            };
        };
        if !peer.check_pin_alive(start_pid) {
            return Ancestry {
                proc_root,
                next: None,
                root_pin: None,
                end: Some(WalkEnd::Reused(start_pid)),
            };
        }
        Ancestry {
            proc_root,
            next: Some((start_pid, None)),
            root_pin: Some(peer.clone()),
            end: None,
        }
    }

    /// Why the walk stopped; `None` while it can still go on.
    pub fn end(&self) -> Option<WalkEnd> {
        self.end
    }
}

impl Iterator for Ancestry<'_> {
    type Item = (u32, String);

    fn next(&mut self) -> Option<(u32, String)> {
        let (pid, recorded) = self.next.take()?;
        let root_pin = self.root_pin.take();
        if let Some(ref peer) = root_pin {
            if !peer.check_pin_alive(pid) {
                self.end = Some(WalkEnd::Reused(pid));
                return None;
            }
        }
        let Some(link) = read_link(self.proc_root, pid) else {
            self.end = Some(WalkEnd::Unreadable(pid));
            return None;
        };
        if let Some(ref peer) = root_pin {
            if !peer.check_pin_alive(pid) {
                self.end = Some(WalkEnd::Reused(pid));
                return None;
            }
        }
        if recorded.is_some_and(|r| r != link.start) {
            self.end = Some(WalkEnd::Reused(pid));
            return None;
        }
        let ppid = link.ppid;
        self.end = if ppid <= 1 {
            Some(WalkEnd::Root)
        } else {
            match read_link(self.proc_root, ppid) {
                None => Some(WalkEnd::Unreadable(ppid)),
                Some(parent) => match (parent.order, link.order) {
                    (None, _) => Some(WalkEnd::Unreadable(ppid)),
                    (_, None) => Some(WalkEnd::Unreadable(pid)),
                    // A parent starts no later than its child, so a later start is a reused
                    // PID. `<=`, not `<`: a child forked within its parent's clock tick (10 ms
                    // on Linux) has an equal start. The cost: a PID reused within the child's
                    // own start tick also passes.
                    (Some(p), Some(c)) if p <= c => {
                        self.next = Some((ppid, Some(parent.start)));
                        None
                    }
                    _ => Some(WalkEnd::Younger {
                        parent: ppid,
                        child: pid,
                    }),
                },
            }
        };
        Some((pid, link.start))
    }
}

/// Returns the parent PID of `pid`, or `None` when the process cannot be read.
pub fn parent_pid(proc_root: &Path, pid: u32) -> Option<u32> {
    if is_live(proc_root) {
        #[cfg(target_os = "macos")]
        return macos::bsdinfo(pid).ok().map(|i| i.pbi_ppid);
    }
    // Field 4 (ppid) is index 1 after the closing paren
    stat_fields(proc_root, pid).ok()?.get(1)?.parse().ok()
}

/// Returns the argument vector of `pid`.
pub fn cmdline(proc_root: &Path, pid: u32) -> io::Result<Vec<String>> {
    if is_live(proc_root) {
        #[cfg(target_os = "macos")]
        return macos::procargs(pid);
    }
    let raw = fs::read_to_string(proc_root.join(pid.to_string()).join("cmdline"))?;
    Ok(raw
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

/// Checks that `pid` is alive and is the process Claude Code recorded as
/// `procStart` in its session file.
///
/// On Linux Claude records the stat starttime, so this is plain equality. On
/// macOS Claude records `LC_ALL=C TZ=UTC ps -o lstart=` text (e.g.
/// `Mon Oct  5 07:58:56 2026`), which is matched against the kernel start time
/// to the second, in UTC only. A value equal to [`starttime`] is accepted on
/// every platform.
pub fn claude_proc_start_matches(proc_root: &Path, pid: u32, expected: &str) -> bool {
    starttime(proc_root, pid).is_ok_and(|st| claude_start_token_matches(proc_root, &st, expected))
}

/// Whether `token`, a start time [`starttime`] read from `proc_root`, is the process Claude
/// Code recorded as `expected`, by the rules of [`claude_proc_start_matches`].
pub fn claude_start_token_matches(proc_root: &Path, token: &str, expected: &str) -> bool {
    if token == expected {
        return true;
    }
    #[cfg(target_os = "macos")]
    if is_live(proc_root) {
        return token
            .parse::<i64>()
            .is_ok_and(|us| macos::lstart_matches(us.div_euclid(1_000_000), expected));
    }
    let _ = proc_root;
    false
}

/// The children of `pid`. On a procfs root, from `<pid>/task/<tid>/children` over all of its
/// threads (a child is listed under the thread that forked it); on live macOS, from
/// `proc_listchildpids(3)`. `None` where the kernel provides no such file (`CONFIG_PROC_CHILDREN`
/// off) or the process is gone.
pub fn child_pids(proc_root: &Path, pid: u32) -> Option<Vec<u32>> {
    if is_live(proc_root) {
        #[cfg(target_os = "macos")]
        return macos::child_pids(pid);
    }
    let tasks = fs::read_dir(proc_root.join(pid.to_string()).join("task")).ok()?;
    let mut found = false;
    let mut kids = Vec::new();
    for task in tasks.flatten() {
        if let Ok(s) = fs::read_to_string(task.path().join("children")) {
            found = true;
            kids.extend(s.split_whitespace().filter_map(|t| t.parse::<u32>().ok()));
        }
    }
    found.then_some(kids)
}

/// The environment of `pid` as NUL-terminated `KEY=value` strings, the format of Linux
/// `/proc/<pid>/environ`. On live macOS it is the environment section of `KERN_PROCARGS2`,
/// which the kernel strips for Apple platform binaries.
pub fn environ(proc_root: &Path, pid: u32) -> io::Result<Vec<u8>> {
    if is_live(proc_root) {
        #[cfg(target_os = "macos")]
        return macos::environ(pid);
    }
    fs::read(proc_root.join(pid.to_string()).join("environ"))
}

/// The PIDs whose effective UID is this process's, from `proc_listpids(PROC_UID_ONLY)`.
#[cfg(target_os = "macos")]
pub fn same_uid_pids() -> io::Result<Vec<u32>> {
    macos::same_uid_pids()
}

/// Returns the current working directory of `pid`.
///
/// On Linux live systems, reads the `/proc/<pid>/cwd` symlink.
/// On macOS live systems, queries `proc_pidvnodepathinfo`.
/// On synthetic test fixtures, reads `<proc_root>/<pid>/cwd`.
pub fn cwd(proc_root: &Path, pid: u32) -> io::Result<std::path::PathBuf> {
    if is_live(proc_root) {
        #[cfg(target_os = "macos")]
        return macos::cwd(pid);
    }
    let cwd_link = proc_root.join(pid.to_string()).join("cwd");
    match fs::read_link(&cwd_link) {
        Ok(target) => Ok(target),
        Err(_) if proc_root != Path::new(LIVE_PROC_ROOT) && cwd_link.is_file() => {
            let s = fs::read_to_string(&cwd_link)?;
            Ok(std::path::PathBuf::from(s.trim()))
        }
        Err(e) => Err(e),
    }
}

/// Returns the executable path of `pid`.
///
/// On Linux live systems, reads the `/proc/<pid>/exe` symlink.
/// On macOS live systems, queries the kernel via `proc_pidpath(2)`.
/// On synthetic test fixtures, reads `<proc_root>/<pid>/exe`.
pub fn exe_path(proc_root: &Path, pid: u32) -> io::Result<std::path::PathBuf> {
    if is_live(proc_root) {
        #[cfg(target_os = "macos")]
        return macos::pidpath(pid);
    }
    let exe_link = proc_root.join(pid.to_string()).join("exe");
    match fs::read_link(&exe_link) {
        Ok(target) => Ok(target),
        Err(_) if proc_root != Path::new(LIVE_PROC_ROOT) && exe_link.is_file() => Ok(exe_link),
        Err(e) => Err(e),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExeMatch {
    /// Candidate canonical path matches a configured canonical path.
    ExactPath,
    /// Candidate canonical file_name matches a configured canonical file_name,
    /// while its canonical path differs from all configured paths (admitted in default mode).
    NameOnly,
    /// Candidate canonical file_name matches a configured canonical file_name,
    /// while its canonical path differs and strict mode refused it.
    RefusedPathDrift,
    /// Candidate canonical file_name does not match any configured canonical file_name.
    NoMatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExeDriftRecord {
    pub pid: u32,
    pub starttime: String,
    pub canonical_path: std::path::PathBuf,
    pub strict: bool,
    pub observed_at: i64,
}

pub type ExeDriftSlot = std::sync::Arc<std::sync::Mutex<Option<ExeDriftRecord>>>;

pub fn new_exe_drift_slot() -> ExeDriftSlot {
    std::sync::Arc::new(std::sync::Mutex::new(None))
}

/// Evaluates `candidate_canon` (an already-canonicalized process executable path) against
/// `trusted_exes`. Default (`!strict`) admits on exact `file_name()` equality of canonical paths;
/// `strict` requires exact canonical path equality.
pub fn evaluate_trusted_exe(
    trusted_exes: &[std::path::PathBuf],
    candidate_canon: &Path,
    strict: bool,
) -> ExeMatch {
    if trusted_exes.is_empty() {
        return ExeMatch::NoMatch;
    }
    let mut name_matched = false;
    let cand_name = candidate_canon.file_name().filter(|n| !n.is_empty());
    for t in trusted_exes {
        let canon_t = fs::canonicalize(t).unwrap_or_else(|_| t.clone());
        if canon_t == candidate_canon || t == candidate_canon {
            return ExeMatch::ExactPath;
        }
        if let Some(cn) = cand_name {
            if canon_t.file_name() == Some(cn) {
                name_matched = true;
            }
        }
    }
    if name_matched {
        if strict {
            ExeMatch::RefusedPathDrift
        } else {
            ExeMatch::NameOnly
        }
    } else {
        ExeMatch::NoMatch
    }
}

pub fn record_exe_drift(
    slot: &ExeDriftSlot,
    pid: u32,
    starttime: &str,
    canonical_path: std::path::PathBuf,
    strict: bool,
    observed_at: i64,
) {
    if let Ok(mut guard) = slot.lock() {
        *guard = Some(ExeDriftRecord {
            pid,
            starttime: starttime.to_string(),
            canonical_path,
            strict,
            observed_at,
        });
    }
}

pub fn clear_exe_drift_if_replaced(slot: &ExeDriftSlot, proc_root: &Path, pid: u32) {
    if let Ok(mut guard) = slot.lock() {
        if guard
            .as_ref()
            .is_some_and(|rec| rec.pid == pid || !is_drift_record_live(proc_root, rec))
        {
            *guard = None;
        }
    }
}

fn is_drift_record_live(proc_root: &Path, rec: &ExeDriftRecord) -> bool {
    if rec.pid == 0 {
        return false;
    }
    match probe_starttime(proc_root, rec.pid) {
        Ok(StartTimeProbe::Gone) => false,
        Ok(StartTimeProbe::Known(cur)) => rec.starttime.is_empty() || cur == rec.starttime,
        Ok(StartTimeProbe::Unavailable) | Err(_) => true,
    }
}

/// Read-only inspection of the last recorded executable path drift for a harness, returning
/// `Some` only while the observed process remains live.
pub fn live_exe_drift(slot: &ExeDriftSlot, proc_root: &Path) -> Option<ExeDriftRecord> {
    let guard = slot.lock().ok()?;
    let rec = guard.as_ref()?;
    is_drift_record_live(proc_root, rec).then(|| rec.clone())
}

/// One open file descriptor vnode entry read for a process (`P3`: shared across `agy` and `codex`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenVnode {
    pub dev: u64,
    pub ino: u64,
    pub path: std::path::PathBuf,
    pub mode: libc::mode_t,
    pub uid: u32,
    pub nlink: u64,
    pub has_flock: bool,
}

/// Test seam: forces the post-scan `starttime` check in [`open_file_vnodes`] on macOS to see a
/// mismatched start token (`M1a`), or `None` to use the live kernel read.
pub fn set_force_post_scan_starttime_for_test(token: Option<String>) {
    #[cfg(target_os = "macos")]
    macos::set_force_post_scan_starttime(token);
    #[cfg(not(target_os = "macos"))]
    let _ = token;
}

/// Test seam: forces `macos::link` on macOS to report `order_override` for `target_pid` (`M4`),
/// or `None` to use the live kernel `proc_pid_rusage` read.
pub fn set_force_link_order_for_test(override_pair: Option<(u32, u64)>) {
    #[cfg(target_os = "macos")]
    macos::set_force_link_order(override_pair);
    #[cfg(not(target_os = "macos"))]
    let _ = override_pair;
}

/// Returns all open regular/vnode file descriptors for `pid`, including `(dev, ino, path, mode, uid, nlink)`.
///
/// On Linux live systems and synthetic test fixtures, reads `<proc_root>/<pid>/fd/` symlinks and `stat`s
/// each target. On macOS live systems, queries `proc_pidinfo(PROC_PIDLISTFDS)` and
/// `proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)` in a single shared loop (`P3`). When `expected_starttime`
/// is `Some(st)`, verifies `starttime(proc_root, pid) == st` before and after the descriptor scan so a
/// PID recycled mid-scan returns `Err`.
pub fn open_file_vnodes(
    proc_root: &Path,
    pid: u32,
    expected_starttime: Option<&str>,
) -> io::Result<Vec<OpenVnode>> {
    if let Some(expected) = expected_starttime {
        if starttime(proc_root, pid).ok().as_deref() != Some(expected) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("process {pid} starttime mismatch before fd scan"),
            ));
        }
    }
    if is_live(proc_root) {
        #[cfg(target_os = "macos")]
        return macos::open_file_vnodes(pid, expected_starttime);
    }
    let fd_dir = proc_root.join(pid.to_string()).join("fd");
    let entries = fs::read_dir(fd_dir)?;
    let mut vnodes = Vec::new();
    for entry in entries.flatten() {
        use std::os::unix::fs::MetadataExt;
        let fd_path = entry.path();
        let Ok(target) = fs::read_link(&fd_path) else {
            continue;
        };
        let Ok(meta) = fs::metadata(&fd_path) else {
            continue;
        };
        vnodes.push(OpenVnode {
            dev: meta.dev(),
            ino: meta.ino(),
            path: target,
            mode: meta.mode() as libc::mode_t,
            uid: meta.uid(),
            nlink: meta.nlink(),
            has_flock: true,
        });
    }
    if let Some(expected) = expected_starttime {
        if starttime(proc_root, pid).ok().as_deref() != Some(expected) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("process {pid} starttime mismatch after fd scan"),
            ));
        }
    }
    Ok(vnodes)
}

/// Returns the device and inode pairs `(dev, ino)` of all open file descriptors for `pid`.
///
/// Delegates to [`open_file_vnodes`] (`P3`).
pub fn open_file_ids(proc_root: &Path, pid: u32) -> io::Result<Vec<(u64, u64)>> {
    Ok(open_file_vnodes(proc_root, pid, None)?
        .into_iter()
        .map(|v| (v.dev, v.ino))
        .collect())
}

/// Returns the per-user runtime directory used when `XDG_RUNTIME_DIR` is unset:
/// the Darwin user temp dir (`confstr(_CS_DARWIN_USER_TEMP_DIR)`) on macOS, a
/// 0700 directory owned by the user. `None` on other platforms.
pub fn fallback_runtime_dir() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    return macos::darwin_user_temp_dir();
    #[cfg(not(target_os = "macos"))]
    None
}

#[cfg(target_os = "macos")]
mod macos {
    use std::cell::RefCell;
    use std::ffi::{CStr, OsStr};
    use std::io;
    use std::mem::{size_of, MaybeUninit};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    thread_local! {
        static FORCE_POST_SCAN_STARTTIME: RefCell<Option<String>> = const { RefCell::new(None) };
        static FORCE_LINK_ORDER: RefCell<Option<(u32, u64)>> = const { RefCell::new(None) };
    }

    pub fn set_force_post_scan_starttime(token: Option<String>) {
        FORCE_POST_SCAN_STARTTIME.with(|cell| *cell.borrow_mut() = token);
    }

    pub fn set_force_link_order(override_pair: Option<(u32, u64)>) {
        FORCE_LINK_ORDER.with(|cell| *cell.borrow_mut() = override_pair);
    }

    enum BsdInfoError {
        Syscall(io::Error),
        Short,
    }

    fn bsdinfo_raw(pid: u32) -> Result<libc::proc_bsdinfo, BsdInfoError> {
        let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: the buffer is a properly sized and aligned proc_bsdinfo.
        let n = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if n <= 0 {
            return Err(BsdInfoError::Syscall(io::Error::last_os_error()));
        }
        if n != size {
            return Err(BsdInfoError::Short);
        }
        // SAFETY: proc_pidinfo filled all `size` bytes.
        Ok(unsafe { info.assume_init() })
    }

    pub fn bsdinfo(pid: u32) -> io::Result<libc::proc_bsdinfo> {
        bsdinfo_raw(pid).map_err(|error| match error {
            BsdInfoError::Syscall(_) => io::Error::new(
                io::ErrorKind::NotFound,
                format!("cannot read process {pid}"),
            ),
            BsdInfoError::Short => io::Error::new(
                io::ErrorKind::InvalidData,
                format!("short proc_bsdinfo for {pid}"),
            ),
        })
    }

    pub(super) fn probe_starttime(pid: u32) -> io::Result<super::StartTimeProbe> {
        match bsdinfo_raw(pid) {
            Ok(info) => Ok(super::StartTimeProbe::Known(starttime_token(&info))),
            Err(BsdInfoError::Syscall(error)) => super::classify_starttime_error(error),
            Err(BsdInfoError::Short) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short native start-time reply",
            )),
        }
    }

    pub fn starttime_token(info: &libc::proc_bsdinfo) -> String {
        (info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec).to_string()
    }

    /// The `mach_absolute_time` the kernel recorded when `pid` forked.
    fn start_abstime(pid: u32) -> Option<u64> {
        let mut ri = MaybeUninit::<libc::rusage_info_v2>::zeroed();
        // SAFETY: the buffer is a properly sized and aligned rusage_info_v2, the struct the
        // RUSAGE_INFO_V2 flavor fills.
        let rc = unsafe {
            libc::proc_pid_rusage(
                pid as libc::c_int,
                libc::RUSAGE_INFO_V2,
                ri.as_mut_ptr().cast(),
            )
        };
        // SAFETY: proc_pid_rusage returned 0, so it filled the struct.
        (rc == 0).then(|| unsafe { ri.assume_init() }.ri_proc_start_abstime)
    }

    /// One read of `pid` for [`super::Ancestry`], ordered by the monotonic fork time. The two
    /// `proc_bsdinfo` reads bracket the `proc_pid_rusage` one, so all of it is one process.
    pub fn link(pid: u32) -> Option<super::Link> {
        let info = bsdinfo(pid).ok()?;
        let order = FORCE_LINK_ORDER
            .with(|cell| *cell.borrow())
            .filter(|(target, _)| *target == pid)
            .map(|(_, forced)| forced)
            .or_else(|| start_abstime(pid));
        let start = starttime_token(&info);
        (starttime_token(&bsdinfo(pid).ok()?) == start).then_some(super::Link {
            ppid: info.pbi_ppid,
            start,
            order,
        })
    }

    /// Parses `Www Mmm dd hh:mm:ss yyyy` as UTC and compares it to `secs`.
    ///
    /// Claude Code writes `procStart` with `LC_ALL=C TZ=UTC`, so the text is
    /// always UTC with English month names. Accepting local time as well would
    /// let a process started exactly one UTC offset away from a dead session's
    /// start match it after PID reuse.
    pub fn lstart_matches(secs: i64, lstart: &str) -> bool {
        lstart_to_epoch(lstart) == Some(secs)
    }

    /// Converts UTC `ps -o lstart` text to seconds since the epoch. The weekday
    /// is ignored; out-of-range fields are rejected rather than normalised.
    pub fn lstart_to_epoch(lstart: &str) -> Option<i64> {
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let parts: Vec<&str> = lstart.split_whitespace().collect();
        let [_wday, mon, mday, hms, year] = parts[..] else {
            return None;
        };
        let mon = MONTHS.iter().position(|m| *m == mon)? as i64 + 1;
        let hms: Vec<&str> = hms.split(':').collect();
        let [h, m, s] = hms[..] else {
            return None;
        };
        let (mday, year): (i64, i64) = (mday.parse().ok()?, year.parse().ok()?);
        let (h, m, s): (i64, i64, i64) = (h.parse().ok()?, m.parse().ok()?, s.parse().ok()?);
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let month_days = [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        if !(1..=month_days[mon as usize - 1]).contains(&mday)
            || !(0..24).contains(&h)
            || !(0..60).contains(&m)
            || !(0..60).contains(&s)
        {
            return None;
        }
        // Days from the civil date (Howard Hinnant's days_from_civil),
        // proleptic Gregorian calendar.
        let y = if mon <= 2 { year - 1 } else { year };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let mp = (mon + 9) % 12;
        let doy = (153 * mp + 2) / 5 + mday - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        Some(days * 86_400 + h * 3_600 + m * 60 + s)
    }

    pub fn procargs(pid: u32) -> io::Result<Vec<String>> {
        parse_procargs2(&procargs2_raw(pid)?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid KERN_PROCARGS2"))
    }

    pub fn environ(pid: u32) -> io::Result<Vec<u8>> {
        parse_procargs2_env(&procargs2_raw(pid)?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid KERN_PROCARGS2"))
    }

    /// Grows the buffer until the listing fits: `proc_listpids(3)` returns bytes written.
    fn list_pids(kind: u32, arg: u32) -> io::Result<Vec<u32>> {
        let mut cap = 1024usize;
        loop {
            let mut buf = vec![0 as libc::pid_t; cap];
            let bytes = (cap * size_of::<libc::pid_t>()) as libc::c_int;
            // SAFETY: buf has `bytes` writable bytes.
            let n = unsafe { libc::proc_listpids(kind, arg, buf.as_mut_ptr().cast(), bytes) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if n < bytes {
                buf.truncate(n as usize / size_of::<libc::pid_t>());
                return Ok(buf
                    .into_iter()
                    .filter(|&p| p > 0)
                    .map(|p| p as u32)
                    .collect());
            }
            cap *= 2;
        }
    }

    const PROC_UID_ONLY: u32 = 4;

    pub fn same_uid_pids() -> io::Result<Vec<u32>> {
        // SAFETY: geteuid cannot fail.
        list_pids(PROC_UID_ONLY, unsafe { libc::geteuid() })
    }

    /// `proc_listchildpids(3)` returns a pid count and reports a gone parent as childless, so a
    /// parent that cannot be read is `None`.
    pub fn child_pids(pid: u32) -> Option<Vec<u32>> {
        bsdinfo(pid).ok()?;
        let mut cap = 256usize;
        loop {
            let mut buf = vec![0 as libc::pid_t; cap];
            let bytes = (cap * size_of::<libc::pid_t>()) as libc::c_int;
            // SAFETY: buf has `bytes` writable bytes.
            let n = unsafe {
                libc::proc_listchildpids(pid as libc::pid_t, buf.as_mut_ptr().cast(), bytes)
            };
            if n < 0 {
                return None;
            }
            if (n as usize) < cap {
                buf.truncate(n as usize);
                return Some(
                    buf.into_iter()
                        .filter(|&p| p > 0)
                        .map(|p| p as u32)
                        .collect(),
                );
            }
            cap *= 2;
        }
    }

    fn procargs2_raw(pid: u32) -> io::Result<Vec<u8>> {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
        let mut size: libc::size_t = 0;
        // SAFETY: a null buffer asks sysctl for the required size.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; size];
        // SAFETY: buf has `size` writable bytes.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                buf.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(size);
        Ok(buf)
    }

    /// Pointer size the exec path area is padded to.
    const PROCARGS2_ALIGN: usize = 8;

    /// KERN_PROCARGS2 layout: `int argc`, then the exec path and its NUL padded
    /// with NULs to a multiple of 8 bytes (the pointer size), then argc
    /// NUL-terminated arguments, then the environment.
    ///
    /// argv starts at that computed offset, not at the first non-NUL byte: an
    /// empty argument is a lone NUL that looks exactly like padding, so
    /// skipping NULs would swallow leading empty arguments and `argc` would
    /// then reach into the environment. If the padding is not all NULs the
    /// layout is not the expected one, and parsing fails instead of guessing.
    /// The padding rule was measured on macOS 26 (arm64) for every exec path
    /// length mod 8. Empty arguments count towards argc but are dropped, as
    /// [`super::cmdline`] does with `/proc/<pid>/cmdline` on Linux.
    pub fn parse_procargs2(buf: &[u8]) -> Option<Vec<String>> {
        split_procargs2(buf).map(|(args, _)| args)
    }

    /// The environment section of a KERN_PROCARGS2 buffer: the strings after argv up to the
    /// first empty one, each NUL-terminated. The kernel's own `apple[]` strings
    /// (`executable_path=`, `ptr_munge=`) follow that empty string and are not the environment.
    pub fn parse_procargs2_env(buf: &[u8]) -> Option<Vec<u8>> {
        let (_, mut rest) = split_procargs2(buf)?;
        let mut env = Vec::new();
        while let Some(end) = rest.iter().position(|&b| b == 0) {
            if end == 0 {
                break;
            }
            env.extend_from_slice(&rest[..=end]);
            rest = &rest[end + 1..];
        }
        Some(env)
    }

    /// argv, and the bytes after it.
    fn split_procargs2(buf: &[u8]) -> Option<(Vec<String>, &[u8])> {
        let argc = usize::try_from(i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?)).ok()?;
        let strings = &buf[4..];
        let path_len = strings.iter().position(|&b| b == 0)?;
        let argv_start = (path_len + 1).next_multiple_of(PROCARGS2_ALIGN);
        if strings.get(path_len..argv_start)?.iter().any(|&b| b != 0) {
            return None;
        }
        let mut rest = &strings[argv_start..];
        let mut args = Vec::new();
        for _ in 0..argc {
            let end = rest.iter().position(|&b| b == 0)?;
            if end > 0 {
                args.push(String::from_utf8_lossy(&rest[..end]).into_owned());
            }
            rest = &rest[end + 1..];
        }
        Some((args, rest))
    }

    pub fn darwin_user_temp_dir() -> Option<PathBuf> {
        let mut buf = vec![0 as libc::c_char; libc::PATH_MAX as usize];
        // SAFETY: buf has buf.len() writable bytes; confstr NUL-terminates.
        let n =
            unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, buf.as_mut_ptr(), buf.len()) };
        if n == 0 || n > buf.len() {
            return None;
        }
        // SAFETY: confstr wrote a NUL-terminated string within buf.
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
        Some(PathBuf::from(OsStr::from_bytes(s.to_bytes())))
    }

    pub fn pidpath(pid: u32) -> io::Result<PathBuf> {
        let mut buf = vec![0 as libc::c_char; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let n = unsafe {
            libc::proc_pidpath(
                pid as libc::c_int,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
            )
        };
        if n <= 0 {
            return Err(io::Error::last_os_error());
        }
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
        Ok(PathBuf::from(OsStr::from_bytes(s.to_bytes())))
    }

    #[repr(C)]
    pub struct proc_fileinfo {
        pub fi_openflags: u32,
        pub fi_status: u32,
        pub fi_offset: i64,
        pub fi_type: i32,
        pub fi_guardflags: u32,
    }

    #[repr(C)]
    pub struct vnode_fdinfowithpath {
        pub pfi: proc_fileinfo,
        pub pvip: libc::vnode_info_path,
    }

    pub const PROC_PIDFDVNODEPATHINFO: libc::c_int = 2;

    pub fn open_file_vnodes(
        pid: u32,
        expected_starttime: Option<&str>,
    ) -> io::Result<Vec<super::OpenVnode>> {
        if let Some(expected) = expected_starttime {
            let pre_st = starttime_token(&bsdinfo(pid)?);
            if pre_st != expected {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("process {pid} starttime mismatch before fd scan"),
                ));
            }
        }
        let size_needed = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDLISTFDS,
                0,
                std::ptr::null_mut(),
                0,
            )
        };
        if size_needed <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("cannot list fds for process {pid}"),
            ));
        }
        let alloc_bytes = (size_needed as usize)
            .saturating_mul(2)
            .max(size_needed as usize);
        let count = alloc_bytes / std::mem::size_of::<libc::proc_fdinfo>();
        let mut fd_list: Vec<libc::proc_fdinfo> = Vec::with_capacity(count);
        let buf_bytes = (count * std::mem::size_of::<libc::proc_fdinfo>()) as libc::c_int;
        let n = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDLISTFDS,
                0,
                fd_list.as_mut_ptr().cast(),
                buf_bytes,
            )
        };
        if n <= 0 {
            return Err(io::Error::last_os_error());
        }
        let num_fds = n as usize / std::mem::size_of::<libc::proc_fdinfo>();
        unsafe { fd_list.set_len(num_fds) };

        let mut vnodes = Vec::new();
        let vnode_size = std::mem::size_of::<vnode_fdinfowithpath>() as libc::c_int;

        for fd_info in fd_list {
            if fd_info.proc_fdtype as libc::c_int == libc::PROX_FDTYPE_VNODE {
                let mut vnode_info = MaybeUninit::<vnode_fdinfowithpath>::zeroed();
                let rc = unsafe {
                    libc::proc_pidfdinfo(
                        pid as libc::c_int,
                        fd_info.proc_fd,
                        PROC_PIDFDVNODEPATHINFO,
                        vnode_info.as_mut_ptr().cast(),
                        vnode_size,
                    )
                };
                if rc == vnode_size {
                    let vi = unsafe { vnode_info.assume_init() };
                    let dev = vi.pvip.vip_vi.vi_stat.vst_dev as u64;
                    let ino = vi.pvip.vip_vi.vi_stat.vst_ino;
                    let mode = vi.pvip.vip_vi.vi_stat.vst_mode as libc::mode_t;
                    let uid = vi.pvip.vip_vi.vi_stat.vst_uid;
                    let nlink = u64::from(vi.pvip.vip_vi.vi_stat.vst_nlink);
                    let c_str = unsafe { CStr::from_ptr(vi.pvip.vip_path.as_ptr().cast()) };
                    let path = PathBuf::from(OsStr::from_bytes(c_str.to_bytes()));
                    const DARWIN_FWRITE: u32 = 0x0000_0002;
                    const DARWIN_FWASLOCKED: u32 = 0x0000_4000;
                    let has_flock = (vi.pfi.fi_openflags & (DARWIN_FWASLOCKED | DARWIN_FWRITE))
                        == (DARWIN_FWASLOCKED | DARWIN_FWRITE);
                    vnodes.push(super::OpenVnode {
                        dev,
                        ino,
                        path,
                        mode,
                        uid,
                        nlink,
                        has_flock,
                    });
                }
            }
        }
        if let Some(expected) = expected_starttime {
            let post_st = FORCE_POST_SCAN_STARTTIME
                .with(|cell| cell.borrow().clone())
                .unwrap_or_else(|| {
                    bsdinfo(pid)
                        .map(|i| starttime_token(&i))
                        .unwrap_or_default()
                });
            if post_st != expected {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("process {pid} starttime mismatch after fd scan"),
                ));
            }
        }
        Ok(vnodes)
    }

    #[repr(C)]
    pub struct proc_vnodepathinfo {
        pub pvi_cdir: libc::vnode_info_path,
        pub pvi_rdir: libc::vnode_info_path,
    }

    pub const PROC_PIDVNODEPATHINFO: libc::c_int = 9;

    pub fn cwd(pid: u32) -> io::Result<std::path::PathBuf> {
        let mut vpi = MaybeUninit::<proc_vnodepathinfo>::zeroed();
        let size = std::mem::size_of::<proc_vnodepathinfo>() as libc::c_int;
        let rc = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                PROC_PIDVNODEPATHINFO,
                0,
                vpi.as_mut_ptr().cast(),
                size,
            )
        };
        if rc != size {
            return Err(io::Error::last_os_error());
        }
        let info = unsafe { vpi.assume_init() };
        let c_str = unsafe { std::ffi::CStr::from_ptr(info.pvi_cdir.vip_path.as_ptr().cast()) };
        let s = c_str
            .to_str()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(std::path::PathBuf::from(s))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Builds a KERN_PROCARGS2 buffer the way the kernel lays it out.
        fn procargs2(path: &str, argv: &[&str], env: &[&str]) -> Vec<u8> {
            let mut buf = (argv.len() as i32).to_ne_bytes().to_vec();
            buf.extend_from_slice(path.as_bytes());
            let padded = (path.len() + 1).next_multiple_of(PROCARGS2_ALIGN);
            buf.resize(4 + padded, 0);
            for s in argv.iter().chain(env) {
                buf.extend_from_slice(s.as_bytes());
                buf.push(0);
            }
            buf
        }

        #[test]
        fn procargs2_skips_exec_path_and_padding() {
            // Path lengths 13 (2 padding NULs), 15 (none) and 16 (7).
            for path in ["/usr/bin/node", "/usr/bin/nodejs", "/usr/bin/nodejsx"] {
                let buf = procargs2(path, &["node", "/opt/pi.js"], &["HOME=/x"]);
                assert_eq!(parse_procargs2(&buf).unwrap(), ["node", "/opt/pi.js"]);
            }
        }

        #[test]
        fn procargs2_env_stops_before_apple_strings() {
            // As measured live: env, an empty string, padding, then the kernel's apple[] strings.
            let mut buf = procargs2("./e", &["./e", "x", ""], &["A=1", "B=2", "", "", ""]);
            buf.extend_from_slice(b"ptr_munge=\0executable_path=./e\0");
            assert_eq!(parse_procargs2_env(&buf).unwrap(), b"A=1\0B=2\0");
            let none = procargs2("./e", &["./e"], &["", "executable_path=./e"]);
            assert_eq!(parse_procargs2_env(&none).unwrap(), b"");
        }

        #[test]
        fn procargs2_empty_args_do_not_pull_in_env() {
            // Leading, middle and trailing empty arguments, as measured live.
            let buf = procargs2("/bin/hold", &["", "", "x", "", "y", ""], &["HOME=/x"]);
            assert_eq!(parse_procargs2(&buf).unwrap(), ["x", "y"]);
        }

        #[test]
        fn procargs2_rejects_unexpected_layouts() {
            let mut bad_padding = procargs2("/bin/hold", &["a"], &[]);
            bad_padding[4 + 10] = b'!';
            assert_eq!(parse_procargs2(&bad_padding), None);
            // argc promises more arguments than the buffer holds.
            let mut short = procargs2("/bin/hold", &["a", "b"], &[]);
            short.truncate(short.len() - 2);
            assert_eq!(parse_procargs2(&short), None);
            let mut negative = procargs2("/bin/hold", &[], &[]);
            negative[..4].copy_from_slice(&(-1i32).to_ne_bytes());
            assert_eq!(parse_procargs2(&negative), None);
        }

        #[test]
        fn lstart_matches_utc() {
            // 2026-10-05T07:58:56Z
            assert!(lstart_matches(1791187136, "Mon Oct  5 07:58:56 2026"));
            assert!(!lstart_matches(1791187137, "Mon Oct  5 07:58:56 2026"));
            assert!(!lstart_matches(1791187136, "garbage"));
        }

        #[test]
        fn lstart_rejects_local_time_renderings() {
            // The same instant rendered in a zone east (+02:00) and west
            // (-05:00) of UTC must not match, whatever the host's TZ is.
            assert!(!lstart_matches(1791187136, "Mon Oct  5 09:58:56 2026"));
            assert!(!lstart_matches(1791187136, "Mon Oct  5 02:58:56 2026"));
        }

        #[test]
        fn lstart_to_epoch_edges() {
            assert_eq!(lstart_to_epoch("Thu Jan  1 00:00:00 1970"), Some(0));
            assert_eq!(
                lstart_to_epoch("Thu Feb 29 12:00:00 2024"),
                Some(1709208000)
            );
            assert_eq!(
                lstart_to_epoch("Thu Dec 31 23:59:59 2026"),
                Some(1798761599)
            );
            // Out-of-range fields are rejected, not normalised into another date.
            assert_eq!(lstart_to_epoch("Sat Feb 29 12:00:00 2025"), None);
            assert_eq!(lstart_to_epoch("Mon Oct 32 00:00:00 2026"), None);
            assert_eq!(lstart_to_epoch("Mon Oct  5 24:00:00 2026"), None);
            assert_eq!(lstart_to_epoch("Mon Okt  5 07:58:56 2026"), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_self_is_readable() {
        let root = Path::new(LIVE_PROC_ROOT);
        let me = std::process::id();
        let st = starttime(root, me).unwrap();
        assert!(!st.is_empty());
        assert!(claude_proc_start_matches(root, me, &st));
        assert!(!claude_proc_start_matches(root, me, "0"));
        assert_eq!(
            parent_pid(root, me),
            Some(std::os::unix::process::parent_id())
        );
        assert!(!cmdline(root, me).unwrap().is_empty());
    }

    #[test]
    fn live_exe_path_and_open_file_ids() {
        use std::os::unix::fs::MetadataExt;
        let root = Path::new(LIVE_PROC_ROOT);
        let me = std::process::id();
        let exe = exe_path(root, me).expect("read self exe");
        assert!(exe.exists());

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let meta = std::fs::metadata(tmp.path()).unwrap();
        let expected_dev_ino = (meta.dev(), meta.ino());

        let fds = open_file_ids(root, me).expect("open file ids for self");
        assert!(
            fds.contains(&expected_dev_ino),
            "open_file_ids should contain named temp file"
        );
    }

    #[test]
    fn fixture_exe_path_and_open_file_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path();
        let pid_dir = proc_root.join("123");
        let fd_dir = pid_dir.join("fd");
        fs::create_dir_all(&fd_dir).unwrap();

        let dummy_exe = tmp.path().join("bin_agy");
        fs::write(&dummy_exe, "binary").unwrap();
        std::os::unix::fs::symlink(&dummy_exe, pid_dir.join("exe")).unwrap();

        let dummy_file = tmp.path().join("open_file.txt");
        fs::write(&dummy_file, "contents").unwrap();
        std::os::unix::fs::symlink(&dummy_file, fd_dir.join("3")).unwrap();

        use std::os::unix::fs::MetadataExt;
        let file_meta = fs::metadata(&dummy_file).unwrap();
        let expected = (file_meta.dev(), file_meta.ino());

        let resolved_exe = exe_path(proc_root, 123).unwrap();
        assert_eq!(resolved_exe, dummy_exe);

        let ids = open_file_ids(proc_root, 123).unwrap();
        assert_eq!(ids, vec![expected]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn live_cmdline_drops_empty_args_without_env() {
        use std::os::unix::process::CommandExt;
        // `; :` stops sh from exec'ing sleep, so the argv stays sh's own.
        let mut child = std::process::Command::new("/bin/sh")
            .arg0("")
            .args(["-c", "sleep 5; :", "", "y"])
            .env_clear()
            .env("XMSG_TEST_ENV", "leak")
            .spawn()
            .expect("spawn sh");
        let args = cmdline(Path::new(LIVE_PROC_ROOT), child.id());
        child.kill().ok();
        child.wait().ok();
        assert_eq!(args.unwrap(), ["-c", "sleep 5; :", "y"]);
    }
}

#[cfg(test)]
mod service_start_tests {
    use super::*;

    #[test]
    fn gone_is_distinct_from_unavailable() {
        assert_eq!(
            classify_starttime_error(io::Error::from_raw_os_error(libc::ESRCH)).unwrap(),
            StartTimeProbe::Gone
        );
        for errno in [libc::EPERM, libc::EACCES, libc::ENOSYS, libc::EOPNOTSUPP] {
            assert_eq!(
                classify_starttime_error(io::Error::from_raw_os_error(errno)).unwrap(),
                StartTimeProbe::Unavailable
            );
        }
        assert!(classify_starttime_error(io::Error::from_raw_os_error(libc::EIO)).is_err());
    }
}
pub use strict_peer::{
    strict_peer_cred_from_fd, strict_process_link, strict_revalidate, StrictPeer, StrictPeerBranch,
    StrictPeerError, StrictProcessLink,
};

mod strict_peer {
    use super::{PeerCred, PeerPin};
    use crate::client::caller_attribution::FailureReason;
    use std::io::Read;
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    pub type StrictPeerError = FailureReason;
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum StrictPeerBranch {
        LinuxPinned,
        LinuxUnsupportedFallback,
        MacWeaker,
    }
    #[derive(Debug, Clone)]
    pub struct StrictPeer {
        pub peer: PeerCred,
        pub branch: StrictPeerBranch,
        pub captured_start: String,
    }
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StrictProcessLink {
        pub pid: u32,
        pub parent_pid: u32,
        pub start: String,
        pub order: u64,
    }

    fn option_i32(fd: BorrowedFd<'_>, level: i32, option: i32) -> Result<i32, FailureReason> {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                level,
                option,
                (&mut value as *mut libc::c_int).cast(),
                &mut len,
            )
        } != 0
            || len as usize != std::mem::size_of_val(&value)
        {
            return Err(FailureReason::Endpoint);
        }
        Ok(value)
    }
    fn socket_metadata(fd: BorrowedFd<'_>) -> Result<(), FailureReason> {
        if option_i32(fd, libc::SOL_SOCKET, libc::SO_TYPE)? != libc::SOCK_STREAM
            || option_i32(fd, libc::SOL_SOCKET, libc::SO_ACCEPTCONN)? != 0
        {
            return Err(FailureReason::Endpoint);
        }
        let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&address) as libc::socklen_t;
        if unsafe {
            libc::getpeername(
                fd.as_raw_fd(),
                (&mut address as *mut libc::sockaddr_storage).cast(),
                &mut len,
            )
        } != 0
            || address.ss_family as libc::c_int != libc::AF_UNIX
        {
            return Err(FailureReason::Endpoint);
        }
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: 0,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 0) } < 0 {
            return Err(FailureReason::AuthorityUnavailable);
        }
        #[cfg(test)]
        if let Some(revents) =
            TEST_READINGS.with(|r| r.borrow().as_ref().and_then(|x| x.socket_revents))
        {
            poll.revents = revents;
        }
        if poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(FailureReason::DeadPeer);
        }
        Ok(())
    }
    fn credentials(fd: BorrowedFd<'_>) -> Result<(u32, u32), FailureReason> {
        #[cfg(target_os = "linux")]
        {
            let mut value: libc::ucred = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut value as *mut libc::ucred).cast(),
                    &mut len,
                )
            } != 0
                || len as usize != std::mem::size_of_val(&value)
            {
                return Err(FailureReason::AuthorityUnavailable);
            }
            #[cfg(test)]
            TEST_READINGS.with(|r| {
                if let Some(raw) = r.borrow().as_ref().and_then(|x| x.credential_pid) {
                    value.pid = raw;
                }
            });
            let pid = u32::try_from(value.pid)
                .ok()
                .filter(|p| *p > 0)
                .ok_or(FailureReason::MissingPid)?;
            Ok((value.uid, pid))
        }
        #[cfg(target_os = "macos")]
        {
            let mut uid = 0;
            let mut gid = 0;
            if unsafe { libc::getpeereid(fd.as_raw_fd(), &mut uid, &mut gid) } != 0 {
                return Err(FailureReason::AuthorityUnavailable);
            }
            let pid = option_i32(fd, 0, libc::LOCAL_PEERPID)?;
            #[cfg(test)]
            let pid = TEST_READINGS.with(|r| {
                r.borrow()
                    .as_ref()
                    .and_then(|x| x.credential_pid)
                    .unwrap_or(pid)
            });
            let pid = u32::try_from(pid)
                .ok()
                .filter(|p| *p > 0)
                .ok_or(FailureReason::MissingPid)?;
            Ok((uid, pid))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = fd;
            Err(FailureReason::Unsupported)
        }
    }

    #[cfg(target_os = "linux")]
    fn native_peer_pin(fd: BorrowedFd<'_>) -> std::io::Result<std::os::fd::OwnedFd> {
        use std::os::fd::FromRawFd;
        #[cfg(test)]
        if let Some(errno) = TEST_READINGS.with(|r| r.borrow().as_ref().and_then(|x| x.pidfd_errno))
        {
            return Err(std::io::Error::from_raw_os_error(errno));
        }
        let mut raw = -1;
        let mut len = std::mem::size_of_val(&raw) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                (&mut raw as *mut libc::c_int).cast(),
                &mut len,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if raw < 0 {
            return Err(std::io::Error::other("negative SO_PEERPIDFD"));
        }
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        if len as usize != std::mem::size_of_val(&raw) {
            return Err(std::io::Error::other("short SO_PEERPIDFD"));
        }
        Ok(owned)
    }
    #[cfg(target_os = "linux")]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum PinReading {
        Visible(u32),
        Dead,
        Unmapped,
        Unreadable,
    }
    #[cfg(target_os = "linux")]
    fn pin_reading(pin: &std::os::fd::OwnedFd) -> PinReading {
        #[cfg(test)]
        if let Some(value) = TEST_READINGS.with(|r| r.borrow().as_ref().and_then(|x| x.pin)) {
            return value;
        }
        let mut poll = libc::pollfd {
            fd: pin.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 0) } < 0 {
            return PinReading::Unreadable;
        }
        if poll.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            return PinReading::Dead;
        }
        if poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return PinReading::Unreadable;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(format!("/proc/self/fdinfo/{}", pin.as_raw_fd()));
        let Ok(file) = file else {
            return PinReading::Unreadable;
        };
        let mut bytes = Vec::new();
        if file.take(8193).read_to_end(&mut bytes).is_err() || bytes.len() > 8192 {
            return PinReading::Unreadable;
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return PinReading::Unreadable;
        };
        let mut values = text.lines().filter_map(|l| l.strip_prefix("Pid:"));
        let Some(value) = values.next() else {
            return PinReading::Unreadable;
        };
        if values.next().is_some() {
            return PinReading::Unreadable;
        }
        match value.trim().parse::<i64>() {
            Ok(-1) => PinReading::Dead,
            Ok(0) => PinReading::Unmapped,
            Ok(p) if p > 0 => u32::try_from(p)
                .map(PinReading::Visible)
                .unwrap_or(PinReading::Unreadable),
            _ => PinReading::Unreadable,
        }
    }
    #[cfg(target_os = "linux")]
    fn pin_matches(pin: &std::os::fd::OwnedFd, pid: u32) -> Result<(), FailureReason> {
        match pin_reading(pin) {
            PinReading::Visible(observed) if observed == pid => Ok(()),
            PinReading::Visible(_) => Err(FailureReason::ContradictoryPeer),
            PinReading::Dead => Err(FailureReason::DeadPeer),
            PinReading::Unmapped => Err(FailureReason::UnmappedPeer),
            PinReading::Unreadable => Err(FailureReason::FdinfoUnavailable),
        }
    }

    pub fn strict_process_link(
        proc_root: &Path,
        pid: u32,
    ) -> Result<StrictProcessLink, FailureReason> {
        if pid == 0 {
            return Err(FailureReason::MissingPid);
        }
        #[cfg(target_os = "macos")]
        if super::is_live(proc_root) {
            let before =
                super::macos::bsdinfo(pid).map_err(|_| FailureReason::AuthorityUnavailable)?;
            if before.pbi_status == libc::SZOMB {
                return Err(FailureReason::DeadPeer);
            }
            let mut info = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
            if unsafe {
                libc::proc_pid_rusage(
                    pid as libc::c_int,
                    libc::RUSAGE_INFO_V2,
                    info.as_mut_ptr().cast(),
                )
            } != 0
            {
                return Err(FailureReason::AuthorityUnavailable);
            }
            let info = unsafe { info.assume_init() };
            let start = super::macos::starttime_token(&before);
            let after =
                super::macos::bsdinfo(pid).map_err(|_| FailureReason::AuthorityUnavailable)?;
            if super::macos::starttime_token(&after) != start {
                return Err(FailureReason::Changed);
            }
            return Ok(StrictProcessLink {
                pid,
                parent_pid: before.pbi_ppid,
                start,
                order: info.ri_proc_start_abstime,
            });
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(proc_root.join(pid.to_string()).join("stat"))
            .map_err(|_| FailureReason::AuthorityUnavailable)?;
        if !file
            .metadata()
            .map_err(|_| FailureReason::AuthorityUnavailable)?
            .is_file()
        {
            return Err(FailureReason::AuthorityUnavailable);
        }
        let mut bytes = Vec::new();
        file.take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| FailureReason::AuthorityUnavailable)?;
        if bytes.len() > 65536 {
            return Err(FailureReason::Limit);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| FailureReason::AuthorityUnavailable)?;
        let close = text.rfind(')').ok_or(FailureReason::AuthorityUnavailable)?;
        let fields: Vec<_> = text[close + 1..].split_whitespace().collect();
        if matches!(fields.first(), Some(&"Z" | &"X" | &"x")) {
            return Err(FailureReason::DeadPeer);
        }
        let parent_pid = fields
            .get(1)
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or(FailureReason::AuthorityUnavailable)?;
        let start = fields
            .get(19)
            .ok_or(FailureReason::AuthorityUnavailable)?
            .to_string();
        let order = start
            .parse()
            .map_err(|_| FailureReason::AuthorityUnavailable)?;
        Ok(StrictProcessLink {
            pid,
            parent_pid,
            start,
            order,
        })
    }

    pub fn strict_peer_cred_from_fd(
        fd: BorrowedFd<'_>,
        proc_root: &Path,
    ) -> Result<StrictPeer, StrictPeerError> {
        socket_metadata(fd)?;
        let (uid, pid) = credentials(fd)?;
        #[cfg(target_os = "linux")]
        let (pin, branch) = match native_peer_pin(fd) {
            Ok(pin) => {
                pin_matches(&pin, pid)?;
                (
                    PeerPin::Visible(std::sync::Arc::new(pin)),
                    StrictPeerBranch::LinuxPinned,
                )
            }
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOPROTOOPT | libc::ENOSYS | libc::EOPNOTSUPP)
                ) =>
            {
                (
                    PeerPin::Unpinned,
                    StrictPeerBranch::LinuxUnsupportedFallback,
                )
            }
            Err(_) => return Err(FailureReason::AuthorityUnavailable),
        };
        #[cfg(target_os = "macos")]
        let (pin, branch) = (PeerPin::Unpinned, StrictPeerBranch::MacWeaker);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let (pin, branch) = {
            return Err(FailureReason::Unsupported);
        };
        let captured_start = strict_process_link(proc_root, pid)?.start;
        let peer = StrictPeer {
            peer: PeerCred {
                uid,
                pid: Some(pid),
                pin,
            },
            branch,
            captured_start,
        };
        strict_revalidate(&peer, fd, proc_root)?;
        Ok(peer)
    }
    pub fn strict_revalidate(
        peer: &StrictPeer,
        fd: BorrowedFd<'_>,
        proc_root: &Path,
    ) -> Result<(), StrictPeerError> {
        socket_metadata(fd)?;
        let (uid, pid) = credentials(fd)?;
        if peer.peer.uid != uid || peer.peer.pid != Some(pid) {
            return Err(FailureReason::ContradictoryPeer);
        }
        #[cfg(target_os = "linux")]
        match &peer.peer.pin {
            PeerPin::Visible(pin) => pin_matches(pin, pid)?,
            PeerPin::Unpinned if peer.branch == StrictPeerBranch::LinuxUnsupportedFallback => {}
            _ => return Err(FailureReason::DeadPeer),
        }
        if strict_process_link(proc_root, pid)?.start != peer.captured_start {
            return Err(FailureReason::Changed);
        }
        #[cfg(target_os = "linux")]
        if let PeerPin::Visible(pin) = &peer.peer.pin {
            pin_matches(pin, pid)?;
        }
        socket_metadata(fd)?;
        if credentials(fd)? != (uid, pid) {
            return Err(FailureReason::ContradictoryPeer);
        }
        Ok(())
    }

    #[cfg(test)]
    #[derive(Debug, Clone, Default)]
    pub(crate) struct TestReadings {
        pub credential_pid: Option<i32>,
        pub pidfd_errno: Option<i32>,
        #[cfg(target_os = "linux")]
        pub pin: Option<PinReading>,
        pub socket_revents: Option<i16>,
    }
    #[cfg(test)]
    thread_local! {pub(crate) static TEST_READINGS:std::cell::RefCell<Option<TestReadings>>=const{std::cell::RefCell::new(None)};}
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::{Read, Write};
        use std::os::fd::{AsFd, OwnedFd};
        fn reset() {
            TEST_READINGS.with(|r| *r.borrow_mut() = None);
        }
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                reset();
            }
        }
        #[test]
        fn strict_peer_metadata_preserves_bytes_and_flags() {
            let (mut sender, mut original) = std::os::unix::net::UnixStream::pair().unwrap();
            sender.write_all(b"untouched-lifecycle").unwrap();
            let flags = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFL) };
            let read_timeout = original.read_timeout().unwrap();
            let write_timeout = original.write_timeout().unwrap();
            let peer =
                strict_peer_cred_from_fd(original.as_fd(), Path::new(super::super::LIVE_PROC_ROOT))
                    .unwrap();
            strict_revalidate(
                &peer,
                original.as_fd(),
                Path::new(super::super::LIVE_PROC_ROOT),
            )
            .unwrap();
            assert_eq!(
                unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFL) },
                flags
            );
            assert_eq!(original.read_timeout().unwrap(), read_timeout);
            assert_eq!(original.write_timeout().unwrap(), write_timeout);
            let mut bytes = [0; 19];
            original.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"untouched-lifecycle");
        }
        #[test]
        fn strict_peer_write_half_close_is_not_full_hup() {
            let (sender, original) = std::os::unix::net::UnixStream::pair().unwrap();
            sender.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(
                strict_peer_cred_from_fd(original.as_fd(), Path::new(super::super::LIVE_PROC_ROOT))
                    .is_ok(),
                "valid write-half-close refused"
            );
            sender.shutdown(std::net::Shutdown::Both).unwrap();
            assert_eq!(
                strict_peer_cred_from_fd(original.as_fd(), Path::new(super::super::LIVE_PROC_ROOT))
                    .err(),
                Some(FailureReason::DeadPeer)
            );
        }
        #[test]
        fn strict_peer_regular_file_and_datagram_are_not_stream_peers() {
            let file = std::fs::File::open("/dev/null").unwrap();
            assert_eq!(
                strict_peer_cred_from_fd(file.as_fd(), Path::new(super::super::LIVE_PROC_ROOT))
                    .err(),
                Some(FailureReason::Endpoint)
            );
            let (datagram, _) = std::os::unix::net::UnixDatagram::pair().unwrap();
            assert_eq!(
                strict_peer_cred_from_fd(datagram.as_fd(), Path::new(super::super::LIVE_PROC_ROOT))
                    .err(),
                Some(FailureReason::Endpoint)
            );
        }
        #[test]
        fn strict_process_link_keeps_pid_one_visible() {
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir(root.path().join("1")).unwrap();
            let mut fields = vec!["0"; 20];
            fields[0] = "S";
            fields[19] = "1";
            std::fs::write(
                root.path().join("1/stat"),
                format!("1 (fixture) {}\n", fields.join(" ")),
            )
            .unwrap();
            let link = strict_process_link(root.path(), 1).unwrap();
            assert_eq!(link.pid, 1);
            assert_eq!(link.parent_pid, 0);
            assert_eq!(link.start, "1");
        }
        #[cfg(target_os = "linux")]
        #[test]
        fn strict_peer_only_three_unsupported_errnos_are_weaker() {
            let _reset = Reset;
            let (_sender, original) = std::os::unix::net::UnixStream::pair().unwrap();
            for errno in [libc::ENOPROTOOPT, libc::ENOSYS, libc::EOPNOTSUPP] {
                TEST_READINGS.with(|r| {
                    *r.borrow_mut() = Some(TestReadings {
                        pidfd_errno: Some(errno),
                        ..Default::default()
                    })
                });
                let result = strict_peer_cred_from_fd(
                    original.as_fd(),
                    Path::new(super::super::LIVE_PROC_ROOT),
                );
                assert_eq!(
                    result.unwrap().branch,
                    StrictPeerBranch::LinuxUnsupportedFallback
                );
            }
            for errno in [libc::EINVAL, libc::EIO, libc::EBADF, libc::EPERM] {
                TEST_READINGS.with(|r| {
                    *r.borrow_mut() = Some(TestReadings {
                        pidfd_errno: Some(errno),
                        ..Default::default()
                    })
                });
                assert_eq!(
                    strict_peer_cred_from_fd(
                        original.as_fd(),
                        Path::new(super::super::LIVE_PROC_ROOT)
                    )
                    .err(),
                    Some(FailureReason::AuthorityUnavailable),
                    "unexpected pidfd error became fallback"
                );
            }
        }
        #[test]
        fn strict_peer_missing_pid_never_becomes_uid_only() {
            let _reset = Reset;
            let (_sender, original) = std::os::unix::net::UnixStream::pair().unwrap();
            TEST_READINGS.with(|r| {
                *r.borrow_mut() = Some(TestReadings {
                    credential_pid: Some(0),
                    ..Default::default()
                })
            });
            assert_eq!(
                credentials(original.as_fd()).err(),
                Some(FailureReason::MissingPid),
                "missing PID became UID-only credentials"
            );
            assert_eq!(
                strict_peer_cred_from_fd(original.as_fd(), Path::new(super::super::LIVE_PROC_ROOT))
                    .err(),
                Some(FailureReason::MissingPid),
                "missing PID constructed a strict peer"
            );
        }
        #[test]
        fn strict_peer_changed_kernel_observation_never_becomes_authority() {
            let _reset = Reset;
            let root = tempfile::tempdir().unwrap();
            let pid = std::process::id();
            for value in [pid, pid + 1] {
                std::fs::create_dir(root.path().join(value.to_string())).unwrap();
                let mut fields = vec!["0"; 20];
                fields[0] = "S";
                fields[19] = "42";
                std::fs::write(
                    root.path().join(value.to_string()).join("stat"),
                    format!("{value} (fixture) {}\n", fields.join(" ")),
                )
                .unwrap();
            }
            let (_sender, original) = std::os::unix::net::UnixStream::pair().unwrap();
            TEST_READINGS.with(|r| {
                *r.borrow_mut() = Some(TestReadings {
                    pidfd_errno: Some(libc::ENOPROTOOPT),
                    ..Default::default()
                })
            });
            let peer = strict_peer_cred_from_fd(original.as_fd(), root.path()).unwrap();
            TEST_READINGS.with(|r| {
                *r.borrow_mut() = Some(TestReadings {
                    credential_pid: Some(pid as i32 + 1),
                    pidfd_errno: Some(libc::ENOPROTOOPT),
                    ..Default::default()
                })
            });
            assert_eq!(
                strict_revalidate(&peer, original.as_fd(), root.path()).err(),
                Some(FailureReason::ContradictoryPeer),
                "changed kernel peer observation constructed authority"
            );
        }
        #[test]
        fn strict_peer_dead_socket_metadata_never_becomes_authority() {
            let _reset = Reset;
            let (_sender, original) = std::os::unix::net::UnixStream::pair().unwrap();
            TEST_READINGS.with(|r| {
                *r.borrow_mut() = Some(TestReadings {
                    socket_revents: Some(libc::POLLHUP),
                    ..Default::default()
                })
            });
            assert_eq!(
                strict_peer_cred_from_fd(original.as_fd(), Path::new(super::super::LIVE_PROC_ROOT))
                    .err(),
                Some(FailureReason::DeadPeer),
                "dead socket metadata constructed authority"
            );
        }
        #[cfg(target_os = "linux")]
        #[test]
        fn strict_peer_pin_contradiction_dead_unmapped_and_unreadable_refuse() {
            let _reset = Reset;
            let pin: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
            let pid = std::process::id();
            for (reading, expected) in [
                (
                    PinReading::Visible(pid + 1),
                    FailureReason::ContradictoryPeer,
                ),
                (PinReading::Dead, FailureReason::DeadPeer),
                (PinReading::Unmapped, FailureReason::UnmappedPeer),
                (PinReading::Unreadable, FailureReason::FdinfoUnavailable),
            ] {
                TEST_READINGS.with(|r| {
                    *r.borrow_mut() = Some(TestReadings {
                        pin: Some(reading),
                        ..Default::default()
                    })
                });
                assert_eq!(
                    pin_matches(&pin, pid).err(),
                    Some(expected),
                    "invalid pin reading constructed authority"
                );
            }
        }
        #[test]
        fn strict_peer_changed_start_token_refuses() {
            let root = tempfile::tempdir().unwrap();
            let pid = std::process::id();
            std::fs::create_dir(root.path().join(pid.to_string())).unwrap();
            let mut fields = vec!["0"; 20];
            fields[0] = "S";
            fields[19] = "42";
            let stat = root.path().join(pid.to_string()).join("stat");
            std::fs::write(&stat, format!("{pid} (fixture) {}\n", fields.join(" "))).unwrap();
            let (_sender, original) = std::os::unix::net::UnixStream::pair().unwrap();
            let peer = strict_peer_cred_from_fd(original.as_fd(), root.path()).unwrap();
            fields[19] = "43";
            std::fs::write(stat, format!("{pid} (fixture) {}\n", fields.join(" "))).unwrap();
            assert_eq!(
                strict_revalidate(&peer, original.as_fd(), root.path()).err(),
                Some(FailureReason::Changed),
                "changed process token survived revalidation"
            );
        }
    }
}
pub fn strict_open_file_vnodes(
    proc_root: &Path,
    pid: u32,
    expected_start: &str,
    deadline: std::time::Instant,
) -> Result<Vec<OpenVnode>, crate::client::caller_attribution::FailureReason> {
    use crate::client::caller_attribution::FailureReason;
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    if std::time::Instant::now() >= deadline {
        return Err(FailureReason::Deadline);
    }
    if strict_process_link(proc_root, pid)?.start != expected_start {
        return Err(FailureReason::Changed);
    }
    #[cfg(target_os = "macos")]
    if is_live(proc_root) {
        use std::os::unix::ffi::OsStrExt;
        let entry_size = std::mem::size_of::<libc::proc_fdinfo>();
        let bytes = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDLISTFDS,
                0,
                std::ptr::null_mut(),
                0,
            )
        };
        if bytes <= 0 {
            return Err(FailureReason::AuthorityUnavailable);
        }
        let count = (bytes as usize)
            .checked_mul(2)
            .ok_or(FailureReason::Limit)?
            / entry_size;
        if count > 4096 {
            return Err(FailureReason::Limit);
        }
        let mut entries: Vec<libc::proc_fdinfo> = Vec::with_capacity(count);
        let size = count * entry_size;
        let filled = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDLISTFDS,
                0,
                entries.as_mut_ptr().cast(),
                size as libc::c_int,
            )
        };
        if filled <= 0 || filled as usize >= size || filled as usize % entry_size != 0 {
            return Err(FailureReason::AuthorityUnavailable);
        }
        unsafe {
            entries.set_len(filled as usize / entry_size);
        }
        let mut result = Vec::new();
        for entry in entries {
            if std::time::Instant::now() >= deadline {
                return Err(FailureReason::Deadline);
            }
            if entry.proc_fdtype as libc::c_int != libc::PROX_FDTYPE_VNODE {
                continue;
            }
            let mut info = std::mem::MaybeUninit::<macos::vnode_fdinfowithpath>::zeroed();
            let size = std::mem::size_of_val(&info) as libc::c_int;
            if unsafe {
                libc::proc_pidfdinfo(
                    pid as libc::c_int,
                    entry.proc_fd,
                    macos::PROC_PIDFDVNODEPATHINFO,
                    info.as_mut_ptr().cast(),
                    size,
                )
            } != size
            {
                return Err(FailureReason::AuthorityUnavailable);
            }
            let info = unsafe { info.assume_init() };
            let raw = info.pvip.vip_path.as_slice();
            let end = raw
                .iter()
                .position(|b| *b == 0)
                .ok_or(FailureReason::AuthorityUnavailable)?;
            let bytes: Vec<u8> = raw[..end].iter().map(|b| *b as u8).collect();
            let stat = info.pvip.vip_vi.vi_stat;
            result.push(OpenVnode {
                dev: stat.vst_dev as u64,
                ino: stat.vst_ino,
                path: std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&bytes)),
                mode: stat.vst_mode as libc::mode_t,
                uid: stat.vst_uid,
                nlink: u64::from(stat.vst_nlink),
                has_flock: info.pfi.fi_openflags & 0x4002 == 0x4002,
            });
        }
        if strict_process_link(proc_root, pid)?.start != expected_start {
            return Err(FailureReason::Changed);
        }
        return Ok(result);
    }
    use std::os::unix::fs::MetadataExt;
    let directory = proc_root.join(pid.to_string());
    let listing =
        std::fs::read_dir(directory.join("fd")).map_err(|_| FailureReason::AuthorityUnavailable)?;
    let mut result = Vec::new();
    let mut seen = 0;
    for entry in listing {
        if std::time::Instant::now() >= deadline {
            return Err(FailureReason::Deadline);
        }
        seen += 1;
        if seen > 4096 {
            return Err(FailureReason::Limit);
        }
        let entry = entry.map_err(|_| FailureReason::AuthorityUnavailable)?;
        if entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
            .is_none()
        {
            return Err(FailureReason::AuthorityUnavailable);
        }
        let target =
            std::fs::read_link(entry.path()).map_err(|_| FailureReason::AuthorityUnavailable)?;
        let meta =
            std::fs::metadata(entry.path()).map_err(|_| FailureReason::AuthorityUnavailable)?;
        if !meta.is_file() {
            continue;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(directory.join("fdinfo").join(entry.file_name()))
            .map_err(|_| FailureReason::AuthorityUnavailable)?;
        let mut bytes = Vec::new();
        std::io::Read::take(file, 65537)
            .read_to_end(&mut bytes)
            .map_err(|_| FailureReason::AuthorityUnavailable)?;
        if bytes.len() > 65536 {
            return Err(FailureReason::Limit);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| FailureReason::AuthorityUnavailable)?;
        let mut holders = std::collections::HashSet::new();
        for line in text.lines().filter_map(|l| l.strip_prefix("lock:")) {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 4 {
                return Err(FailureReason::AuthorityUnavailable);
            }
            if fields[1] != "FLOCK" || fields[3] != "WRITE" {
                continue;
            }
            let Some((holder, major, minor, inode)) = crate::agy::parse_locks_line(line) else {
                return Err(FailureReason::AuthorityUnavailable);
            };
            if (major, minor, inode)
                == (
                    crate::agy::dev_major(meta.dev()),
                    crate::agy::dev_minor(meta.dev()),
                    meta.ino(),
                )
            {
                holders.insert(holder);
            }
        }
        if holders.len() > 1 {
            return Err(FailureReason::Ambiguous);
        }
        result.push(OpenVnode {
            dev: meta.dev(),
            ino: meta.ino(),
            path: target,
            mode: meta.mode() as libc::mode_t,
            uid: meta.uid(),
            nlink: meta.nlink(),
            has_flock: holders.contains(&pid),
        });
    }
    if strict_process_link(proc_root, pid)?.start != expected_start {
        return Err(FailureReason::Changed);
    }
    if std::time::Instant::now() >= deadline {
        return Err(FailureReason::Deadline);
    }
    Ok(result)
}

#[cfg(test)]
mod strict_vnode_tests {
    #[test]
    fn non_flock_metadata_is_not_a_failed_writer_lease_parse() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let pid = 100;
        std::fs::create_dir_all(root.path().join("100/fd")).unwrap();
        std::fs::create_dir_all(root.path().join("100/fdinfo")).unwrap();
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[19] = "42";
        std::fs::write(
            root.path().join("100/stat"),
            format!("{pid} (fixture) {}\n", fields.join(" ")),
        )
        .unwrap();
        let target = root.path().join("regular");
        std::fs::write(&target, b"fixture").unwrap();
        symlink(&target, root.path().join("100/fd/4")).unwrap();
        std::fs::write(
            root.path().join("100/fdinfo/4"),
            "lock: 1: POSIX ADVISORY WRITE 100 00:00:1 0 EOF\n",
        )
        .unwrap();
        let rows = super::strict_open_file_vnodes(
            root.path(),
            pid,
            "42",
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].has_flock);
        std::fs::write(
            root.path().join("100/fdinfo/4"),
            "lock: 1: FLOCK ADVISORY WRITE invalid\n",
        )
        .unwrap();
        assert_eq!(
            super::strict_open_file_vnodes(
                root.path(),
                pid,
                "42",
                std::time::Instant::now() + std::time::Duration::from_secs(1)
            )
            .err(),
            Some(crate::client::caller_attribution::FailureReason::AuthorityUnavailable)
        );
    }
}
