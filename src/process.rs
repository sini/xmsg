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
    if is_live(proc_root) {
        #[cfg(target_os = "macos")]
        return match macos::bsdinfo(pid) {
            Ok(info) => {
                macos::starttime_token(&info) == expected
                    || macos::lstart_matches(info.pbi_start_tvsec as i64, expected)
            }
            Err(_) => false,
        };
    }
    matches!(starttime(proc_root, pid), Ok(st) if st == expected)
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

/// Returns the device and inode pairs `(dev, ino)` of all open file descriptors for `pid`.
///
/// On Linux live systems and synthetic test fixtures, stats each entry in `<proc_root>/<pid>/fd/`.
/// On macOS live systems, queries `proc_pidinfo(PROC_PIDLISTFDS)` and `proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)`
/// for vnode file descriptors.
pub fn open_file_ids(proc_root: &Path, pid: u32) -> io::Result<Vec<(u64, u64)>> {
    if is_live(proc_root) {
        #[cfg(target_os = "macos")]
        return macos::open_file_ids(pid);
    }
    let fd_dir = proc_root.join(pid.to_string()).join("fd");
    let entries = fs::read_dir(fd_dir)?;
    let mut ids = Vec::new();
    for entry in entries.flatten() {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = fs::metadata(entry.path()) {
            ids.push((meta.dev(), meta.ino()));
        }
    }
    Ok(ids)
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
    use std::ffi::{CStr, OsStr};
    use std::io;
    use std::mem::{size_of, MaybeUninit};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    pub fn bsdinfo(pid: u32) -> io::Result<libc::proc_bsdinfo> {
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
            // Fails for missing PIDs and, without root, for other users' processes.
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("cannot read process {pid}"),
            ));
        }
        if n != size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("short proc_bsdinfo for {pid}"),
            ));
        }
        // SAFETY: proc_pidinfo filled all `size` bytes.
        Ok(unsafe { info.assume_init() })
    }

    pub fn starttime_token(info: &libc::proc_bsdinfo) -> String {
        (info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec).to_string()
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
        parse_procargs2(&buf)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid KERN_PROCARGS2"))
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
        Some(args)
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

    pub fn open_file_ids(pid: u32) -> io::Result<Vec<(u64, u64)>> {
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
        let count = size_needed as usize / std::mem::size_of::<libc::proc_fdinfo>();
        let mut fd_list: Vec<libc::proc_fdinfo> = Vec::with_capacity(count);
        let n = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDLISTFDS,
                0,
                fd_list.as_mut_ptr().cast(),
                size_needed,
            )
        };
        if n <= 0 {
            return Err(io::Error::last_os_error());
        }
        let num_fds = n as usize / std::mem::size_of::<libc::proc_fdinfo>();
        unsafe { fd_list.set_len(num_fds) };

        let mut ids = Vec::new();
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
                    ids.push((dev, ino));
                }
            }
        }
        Ok(ids)
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
