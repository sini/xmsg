use super::ClientError;
use std::io;
use std::os::fd::RawFd;
#[cfg(target_os = "macos")]
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::Mutex;

pub(super) struct RegistrationHealth {
    descriptor: Mutex<Option<RawFd>>,
}

impl RegistrationHealth {
    pub(super) fn new(fd: RawFd) -> Self {
        Self {
            descriptor: Mutex::new(Some(fd)),
        }
    }

    pub(super) fn dispose(&self) {
        *self.descriptor.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub(super) fn check(&self) -> Result<(), ClientError> {
        let mut descriptor = self.descriptor.lock().unwrap_or_else(|e| e.into_inner());
        let fd = descriptor.ok_or(ClientError::Disconnected)?;
        if shutdown(fd)? {
            *descriptor = None;
            return Err(ClientError::Disconnected);
        }
        let mut byte = 0_u8;
        // The lifetime mutex prevents disposal and descriptor reuse during this probe.
        let result = unsafe {
            libc::recv(
                fd,
                (&mut byte as *mut u8).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if result == 0 {
            *descriptor = None;
            Err(ClientError::Disconnected)
        } else if result > 0 {
            Ok(())
        } else {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                Ok(())
            } else {
                Err(error.into())
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn shutdown(fd: RawFd) -> io::Result<bool> {
    let mut event = libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLRDHUP,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut event, 1, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if event.revents & libc::POLLNVAL != 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    Ok(event.revents & (libc::POLLHUP | libc::POLLRDHUP) != 0)
}

#[cfg(target_os = "macos")]
fn shutdown(fd: RawFd) -> io::Result<bool> {
    let queue = unsafe { libc::kqueue() };
    if queue < 0 {
        return Err(io::Error::last_os_error());
    }
    let _queue = unsafe { OwnedFd::from_raw_fd(queue) };
    let change = libc::kevent {
        ident: fd as libc::uintptr_t,
        filter: libc::EVFILT_READ,
        flags: libc::EV_ADD | libc::EV_ENABLE,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    let mut event = change;
    let wait = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let result = unsafe { libc::kevent(queue, &change, 1, &mut event, 1, &wait) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if result > 0 && event.flags & libc::EV_ERROR != 0 {
        return Err(io::Error::from_raw_os_error(event.data as i32));
    }
    Ok(result > 0 && event.flags & libc::EV_EOF != 0)
}
