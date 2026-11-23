/// Marks every descriptor above stdio close-on-exec in the child. Apple targets set CLOEXEC on new
/// sockets and pipes in a second step, so a concurrent spawn can otherwise inherit them. Setting
/// the flag rather than closing keeps std's exec-failure pipe working.
#[cfg(target_os = "macos")]
pub fn cloexec_inherited_fds(cmd: &mut tokio::process::Command) {
    const CAP: libc::rlim_t = 65536;
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes only into the rlimit we pass.
    let soft = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0 {
        lim.rlim_cur.min(CAP)
    } else {
        CAP
    };
    let max_fd = soft as libc::c_int;
    // SAFETY: the closure captures one integer and calls only fcntl, which is async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            for fd in 3..max_fd {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags >= 0 {
                    libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
                }
            }
            Ok(())
        });
    }
}

#[cfg(all(target_os = "macos", feature = "daemon"))]
pub(crate) mod darwin;
