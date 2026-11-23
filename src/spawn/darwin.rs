//! Darwin delivery starts with an explicit exec-time descriptor allowlist.

use std::ffi::{CString, OsStr};
use std::io;
use std::os::{
    fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    unix::{ffi::OsStrExt, net::UnixStream, process::ExitStatusExt},
};
use std::process::{Command, ExitStatus, Output};
use std::time::Duration;
use tokio::io::AsyncReadExt;

fn check(code: libc::c_int) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code))
    }
}

struct Attributes(libc::posix_spawnattr_t);
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe { libc::posix_spawnattr_destroy(&mut self.0) };
    }
}

struct Actions(libc::posix_spawn_file_actions_t);
impl Drop for Actions {
    fn drop(&mut self) {
        unsafe { libc::posix_spawn_file_actions_destroy(&mut self.0) };
    }
}

fn duplicate(fd: RawFd) -> io::Result<OwnedFd> {
    let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}

fn cstring(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| io::ErrorKind::InvalidInput.into())
}

pub(crate) fn spawn(command: &Command) -> io::Result<Child> {
    #[cfg(test)]
    assert!(
        crate::client::caller_attribution::inheritance_gate_held_for_test(),
        "actual Darwin delivery spawned outside the shared receive-to-fcntl gate"
    );

    let program = cstring(command.get_program())?;
    let arguments = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(cstring)
        .collect::<io::Result<Vec<_>>>()?;
    let mut environment: std::collections::BTreeMap<_, _> = std::env::vars_os().collect();
    for (key, value) in command.get_envs() {
        if let Some(value) = value {
            environment.insert(key.to_owned(), value.to_owned());
        } else {
            environment.remove(key);
        }
    }
    let environment = environment
        .into_iter()
        .map(|(key, value)| {
            let mut entry = key;
            entry.push("=");
            entry.push(value);
            cstring(&entry)
        })
        .collect::<io::Result<Vec<_>>>()?;
    let pointers = |entries: &[CString]| {
        entries
            .iter()
            .map(|entry| entry.as_ptr().cast_mut())
            .chain(std::iter::once(std::ptr::null_mut()))
            .collect::<Vec<_>>()
    };
    let args = pointers(&arguments);
    let env = pointers(&environment);

    let input = match duplicate(libc::STDIN_FILENO) {
        Ok(fd) => fd,
        Err(error) if error.raw_os_error() == Some(libc::EBADF) => {
            duplicate(std::fs::File::open("/dev/null")?.as_raw_fd())?
        }
        Err(error) => return Err(error),
    };
    let (out, child_out) = UnixStream::pair()?;
    let (err, child_err) = UnixStream::pair()?;
    let child_out = duplicate(child_out.as_raw_fd())?;
    let child_err = duplicate(child_err.as_raw_fd())?;
    out.set_nonblocking(true)?;
    err.set_nonblocking(true)?;
    let stdout = tokio::net::UnixStream::from_std(out)?;
    let stderr = tokio::net::UnixStream::from_std(err)?;

    let mut attributes = std::ptr::null_mut();
    let mut actions = std::ptr::null_mut();
    unsafe { check(libc::posix_spawnattr_init(&mut attributes))? };
    let mut attributes = Attributes(attributes);
    unsafe { check(libc::posix_spawn_file_actions_init(&mut actions))? };
    let mut actions = Actions(actions);
    unsafe {
        let mut signals: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&mut signals) != 0 || libc::sigaddset(&mut signals, libc::SIGPIPE) != 0
        {
            return Err(io::Error::last_os_error());
        }
        check(libc::posix_spawnattr_setsigdefault(
            &mut attributes.0,
            &signals,
        ))?;
        check(libc::posix_spawnattr_setflags(
            &mut attributes.0,
            (libc::POSIX_SPAWN_CLOEXEC_DEFAULT | libc::POSIX_SPAWN_SETSIGDEF) as _,
        ))?;
        for (source, target) in [
            (input.as_raw_fd(), libc::STDIN_FILENO),
            (child_out.as_raw_fd(), libc::STDOUT_FILENO),
            (child_err.as_raw_fd(), libc::STDERR_FILENO),
        ] {
            check(libc::posix_spawn_file_actions_adddup2(
                &mut actions.0,
                source,
                target,
            ))?;
        }
    }
    let mut pid = 0;
    unsafe {
        check(libc::posix_spawnp(
            &mut pid,
            program.as_ptr(),
            &actions.0,
            &attributes.0,
            args.as_ptr(),
            env.as_ptr(),
        ))?;
    }
    Ok(Child {
        pid: Pid(Some(pid)),
        stdout,
        stderr,
    })
}

struct Pid(Option<libc::pid_t>);

impl Pid {
    async fn wait(&mut self) -> io::Result<ExitStatus> {
        let pid = self.0.expect("child is owned until wait");
        loop {
            let mut status = 0;
            match unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } {
                0 => tokio::time::sleep(Duration::from_millis(10)).await,
                -1 => {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    if error.raw_os_error() == Some(libc::ECHILD) {
                        self.0 = None;
                    }
                    return Err(error);
                }
                _ => {
                    self.0 = None;
                    return Ok(ExitStatus::from_raw(status));
                }
            }
        }
    }
}
impl Drop for Pid {
    fn drop(&mut self) {
        let Some(pid) = self.0.take() else { return };
        unsafe { libc::kill(pid, libc::SIGKILL) };
        tokio::task::spawn_blocking(move || {
            while unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) } < 0 {
                if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    break;
                }
            }
        });
    }
}

pub(crate) struct Child {
    pid: Pid,
    stdout: tokio::net::UnixStream,
    stderr: tokio::net::UnixStream,
}

impl Child {
    pub(crate) async fn wait_with_output(mut self) -> io::Result<Output> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let (status, _, _) = tokio::try_join!(
            self.pid.wait(),
            self.stdout.read_to_end(&mut stdout),
            self.stderr.read_to_end(&mut stderr),
        )?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}
