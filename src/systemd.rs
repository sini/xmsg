use std::collections::HashSet;
use std::net::SocketAddr;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::path::Path;

pub const SD_LISTEN_FDS_START: RawFd = 3;

const CANONICAL_SLOTS: &[&str] = &["fed", "listen", "agent", "register", "http"];

#[derive(Debug, Clone, Copy)]
pub struct ActivatedConfig<'a> {
    pub fed_listen: Option<SocketAddr>,
    pub listen: Option<&'a str>,
    pub agent_sock: Option<&'a Path>,
    pub register_sock: &'a Path,
    pub http_sock: Option<&'a Path>,
}

#[derive(Default)]
pub struct ActivatedSockets {
    pub fed: Option<tokio::net::TcpListener>,
    pub listen: Option<tokio::net::TcpListener>,
    pub agent: Option<tokio::net::UnixListener>,
    pub register: Option<tokio::net::UnixListener>,
    pub http: Option<tokio::net::UnixListener>,
}

/// Inspects `LISTEN_FDS`, `LISTEN_PID`, and `LISTEN_FDNAMES` according to the systemd socket
/// activation protocol (XF4, S-1, S-2, S-5).
///
/// - Unsets `LISTEN_FDS`, `LISTEN_PID`, and `LISTEN_FDNAMES` from the process environment so
///   spawned child processes never inherit them.
/// - Without `LISTEN_FDS`, returns `Ok(ActivatedSockets::default())`.
/// - When `LISTEN_PID` does not match `std::process::id()`, ignores the passed descriptors and
///   returns `Ok(ActivatedSockets::default())`.
/// - Validates each passed descriptor's socket type (`SOCK_STREAM`), listening state
///   (`SO_ACCEPTCONN` on Linux), address family (`AF_INET`/`AF_INET6` vs `AF_UNIX`), and bound
///   address/path against `ActivatedConfig` (S-2). Any unknown/duplicate/unconfigured slot name,
///   wrong descriptor type/family, or address/path mismatch returns `Err(...)`.
pub fn take_activated_sockets(cfg: &ActivatedConfig<'_>) -> Result<ActivatedSockets, String> {
    let raw_fds = std::env::var("LISTEN_FDS").ok();
    let raw_pid = std::env::var("LISTEN_PID").ok();
    let raw_names = std::env::var("LISTEN_FDNAMES").ok();

    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDNAMES");

    let fds_str = match raw_fds {
        Some(s) if !s.trim().is_empty() => s,
        _ => return Ok(ActivatedSockets::default()),
    };

    let listen_pid = raw_pid
        .as_deref()
        .and_then(|s| s.trim().parse::<u32>().ok());
    if listen_pid != Some(std::process::id()) {
        tracing::warn!(
            listen_pid = ?raw_pid,
            self_pid = std::process::id(),
            "ignoring LISTEN_FDS because LISTEN_PID does not match current process"
        );
        return Ok(ActivatedSockets::default());
    }

    let n: usize = fds_str
        .trim()
        .parse()
        .map_err(|e| format!("invalid LISTEN_FDS='{fds_str}': {e}"))?;
    if n == 0 {
        return Ok(ActivatedSockets::default());
    }
    if n > 64 {
        return Err(format!(
            "LISTEN_FDS={n} exceeds maximum supported count (64)"
        ));
    }

    let slot_names: Vec<String> = match raw_names {
        Some(ref s) if !s.trim().is_empty() => {
            let parts: Vec<String> = s.split(':').map(|p| p.to_string()).collect();
            if parts.len() != n {
                return Err(format!(
                    "LISTEN_FDNAMES has {} entries ({s:?}) but LISTEN_FDS={n}",
                    parts.len()
                ));
            }
            parts
        }
        _ => {
            // S-1: The only default allowed: LISTEN_FDS=1, no LISTEN_FDNAMES, and exactly one
            // TCP listener configured => that slot. Anything else needs names.
            if n != 1 {
                return Err(format!(
                    "LISTEN_FDS={n} without LISTEN_FDNAMES is refused; provide colon-separated canonical slot names in LISTEN_FDNAMES"
                ));
            }
            match (cfg.fed_listen.is_some(), cfg.listen.is_some()) {
                (true, false) => vec!["fed".to_string()],
                (false, true) => vec!["listen".to_string()],
                (false, false) => {
                    return Err(
                        "LISTEN_FDS=1 without LISTEN_FDNAMES requires a configured TCP listener (--fed-listen or --listen)".to_string(),
                    );
                }
                (true, true) => {
                    return Err(
                        "LISTEN_FDS=1 without LISTEN_FDNAMES is ambiguous when both --fed-listen and --listen are configured".to_string(),
                    );
                }
            }
        }
    };

    let mut seen_slots = HashSet::new();
    let mut out = ActivatedSockets::default();

    for (idx, slot) in slot_names.iter().enumerate() {
        if !CANONICAL_SLOTS.contains(&slot.as_str()) {
            return Err(format!(
                "unknown LISTEN_FDNAMES slot '{slot}' at index {idx} (expected one of: fed, listen, agent, register, http)"
            ));
        }
        if !seen_slots.insert(slot.clone()) {
            return Err(format!(
                "duplicate LISTEN_FDNAMES slot '{slot}' at index {idx}"
            ));
        }

        let fd: RawFd = SD_LISTEN_FDS_START + (idx as RawFd);
        set_cloexec_and_nonblock(fd, slot)?;
        let family = validate_listening_stream_socket(fd, slot)?;

        match slot.as_str() {
            "fed" => {
                let expected = cfg.fed_listen.ok_or_else(|| {
                    "LISTEN_FDS provided slot 'fed', but --fed-listen is not configured".to_string()
                })?;
                let listener = adopt_tcp_listener(fd, family, "fed", expected)?;
                out.fed = Some(listener);
            }
            "listen" => {
                let raw_listen = cfg.listen.ok_or_else(|| {
                    "LISTEN_FDS provided slot 'listen', but --listen is not configured".to_string()
                })?;
                let expected: SocketAddr = raw_listen.parse().map_err(|e| {
                    format!("invalid --listen address '{raw_listen}' for socket activation: {e}")
                })?;
                let listener = adopt_tcp_listener(fd, family, "listen", expected)?;
                out.listen = Some(listener);
            }
            "agent" => {
                let expected = cfg.agent_sock.ok_or_else(|| {
                    "LISTEN_FDS provided slot 'agent', but agent.sock is not used in --leaf mode"
                        .to_string()
                })?;
                let listener = adopt_unix_listener(fd, family, "agent", expected)?;
                out.agent = Some(listener);
            }
            "register" => {
                let listener = adopt_unix_listener(fd, family, "register", cfg.register_sock)?;
                out.register = Some(listener);
            }
            "http" => {
                let expected = cfg.http_sock.ok_or_else(|| {
                    "LISTEN_FDS provided slot 'http', but http.sock is not used in --leaf mode"
                        .to_string()
                })?;
                let listener = adopt_unix_listener(fd, family, "http", expected)?;
                out.http = Some(listener);
            }
            _ => unreachable!(),
        }
    }

    Ok(out)
}

fn set_cloexec_and_nonblock(fd: RawFd, slot: &str) -> Result<(), String> {
    let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if fd_flags < 0 {
        return Err(format!(
            "LISTEN_FDS fd {fd} for slot '{slot}' is not a valid open file descriptor: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) } < 0 {
        return Err(format!(
            "failed to set FD_CLOEXEC on LISTEN_FDS fd {fd} for slot '{slot}': {}",
            std::io::Error::last_os_error()
        ));
    }

    let fl_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if fl_flags < 0 {
        return Err(format!(
            "failed to read F_GETFL on LISTEN_FDS fd {fd} for slot '{slot}': {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, fl_flags | libc::O_NONBLOCK) } < 0 {
        return Err(format!(
            "failed to set O_NONBLOCK on LISTEN_FDS fd {fd} for slot '{slot}': {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn validate_listening_stream_socket(fd: RawFd, slot: &str) -> Result<libc::c_int, String> {
    let mut sock_type: libc::c_int = 0;
    let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut sock_type as *mut libc::c_int).cast(),
            &mut optlen,
        )
    };
    if rc != 0 {
        return Err(format!(
            "LISTEN_FDS fd {fd} for slot '{slot}' is not a socket: {}",
            std::io::Error::last_os_error()
        ));
    }
    if sock_type != libc::SOCK_STREAM {
        return Err(format!(
            "LISTEN_FDS fd {fd} for slot '{slot}' has socket type {sock_type}, expected SOCK_STREAM ({})",
            libc::SOCK_STREAM
        ));
    }

    #[cfg(target_os = "linux")]
    {
        let mut acceptconn: libc::c_int = 0;
        let mut alen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let arc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ACCEPTCONN,
                (&mut acceptconn as *mut libc::c_int).cast(),
                &mut alen,
            )
        };
        if arc != 0 || acceptconn != 1 {
            return Err(format!(
                "LISTEN_FDS fd {fd} for slot '{slot}' is not a listening socket (SO_ACCEPTCONN={acceptconn})"
            ));
        }
    }

    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut slen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let grc = unsafe {
        libc::getsockname(
            fd,
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            &mut slen,
        )
    };
    if grc != 0 {
        return Err(format!(
            "getsockname failed on LISTEN_FDS fd {fd} for slot '{slot}': {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(storage.ss_family as libc::c_int)
}

fn adopt_tcp_listener(
    fd: RawFd,
    family: libc::c_int,
    slot: &str,
    expected: SocketAddr,
) -> Result<tokio::net::TcpListener, String> {
    if family != libc::AF_INET && family != libc::AF_INET6 {
        return Err(format!(
            "LISTEN_FDS fd {fd} for TCP slot '{slot}' has address family {family}, expected AF_INET or AF_INET6"
        ));
    }
    let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    let actual = std_listener.local_addr().map_err(|e| {
        format!("failed to read local_addr on adopted TCP socket for slot '{slot}': {e}")
    })?;

    // S-2: Adopted TCP socket IP must equal configured IP, and port must equal configured port
    // unless configured port is 0.
    if actual.ip() != expected.ip() || (expected.port() != 0 && actual.port() != expected.port()) {
        return Err(format!(
            "adopted '{slot}' socket address {actual} does not match configured address {expected}"
        ));
    }

    tokio::net::TcpListener::from_std(std_listener)
        .map_err(|e| format!("failed to wrap adopted TCP socket for slot '{slot}' in tokio: {e}"))
}

fn adopt_unix_listener(
    fd: RawFd,
    family: libc::c_int,
    slot: &str,
    expected: &Path,
) -> Result<tokio::net::UnixListener, String> {
    if family != libc::AF_UNIX {
        return Err(format!(
            "LISTEN_FDS fd {fd} for Unix slot '{slot}' has address family {family}, expected AF_UNIX"
        ));
    }
    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    let local = std_listener.local_addr().map_err(|e| {
        format!("failed to read local_addr on adopted Unix socket for slot '{slot}': {e}")
    })?;
    let actual_path = local.as_pathname().ok_or_else(|| {
        format!(
            "adopted Unix socket for slot '{slot}' is unbound or unnamed, expected '{}'",
            expected.display()
        )
    })?;

    // S-2: Adopted Unix socket path must equal configured path.
    if actual_path != expected {
        return Err(format!(
            "adopted '{slot}' socket path '{}' does not match configured path '{}'",
            actual_path.display(),
            expected.display()
        ));
    }

    tokio::net::UnixListener::from_std(std_listener)
        .map_err(|e| format!("failed to wrap adopted Unix socket for slot '{slot}' in tokio: {e}"))
}

fn monotonic_usec() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc == 0 && ts.tv_sec >= 0 && ts.tv_nsec >= 0 {
        (ts.tv_sec as u64)
            .saturating_mul(1_000_000)
            .saturating_add((ts.tv_nsec as u64) / 1_000)
    } else {
        0
    }
}

/// Sends a datagram to `NOTIFY_SOCKET` if set in the environment.
/// Without `NOTIFY_SOCKET`, this is a no-op.
pub fn sd_notify(state: &str) {
    let raw = match std::env::var("NOTIFY_SOCKET") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => return,
    };
    let sock = match UnixDatagram::unbound() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("sd_notify: failed to create unbound UnixDatagram: {e}");
            return;
        }
    };

    #[cfg(target_os = "linux")]
    if let Some(abstract_name) = raw.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        if let Ok(addr) =
            std::os::unix::net::SocketAddr::from_abstract_name(abstract_name.as_bytes())
        {
            let _ = sock.send_to_addr(state.as_bytes(), &addr);
        }
        return;
    }

    let _ = sock.send_to(state.as_bytes(), &raw);
}

pub fn notify_ready() {
    sd_notify("READY=1");
}

pub fn notify_ready_with_status(status: &str) {
    sd_notify(&format!("READY=1\nSTATUS={status}"));
}

pub fn notify_reloading() {
    let usec = monotonic_usec();
    sd_notify(&format!("RELOADING=1\nMONOTONIC_USEC={usec}"));
}

pub fn notify_reload_failed(reason: &str) {
    sd_notify(&format!("READY=1\nSTATUS=reload failed: {reason}"));
}

pub fn notify_stopping() {
    sd_notify("STOPPING=1");
}
