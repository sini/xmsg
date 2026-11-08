use super::ClientError;
use std::io;
use std::os::fd::RawFd;
#[cfg(target_os = "macos")]
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::Mutex;

pub(super) struct RegistrationHealth {
    pub(super) descriptor: Mutex<Option<RawFd>>,
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
        if disconnected(fd)? {
            *descriptor = None;
            return Err(ClientError::Disconnected);
        }
        Ok(())
    }
}

fn disconnected(fd: RawFd) -> io::Result<bool> {
    Ok(shutdown(fd)? || peek_eof(fd)?)
}

fn peek_eof(fd: RawFd) -> io::Result<bool> {
    let mut byte = 0_u8;
    // The caller holds the descriptor-lifetime mutex throughout this probe.
    let result = unsafe {
        libc::recv(
            fd,
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if result >= 0 {
        Ok(result == 0)
    } else {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            Ok(false)
        } else {
            Err(error)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn peek_observes_idle_data_and_eof_without_consumption() {
        for half_close in [false, true] {
            let (mut reader, mut writer) = UnixStream::pair().unwrap();
            assert!(!peek_eof(reader.as_raw_fd()).unwrap());
            writer.write_all(b"frame\n").unwrap();
            for _ in 0..3 {
                assert!(!peek_eof(reader.as_raw_fd()).unwrap());
            }
            if half_close {
                writer.shutdown(std::net::Shutdown::Write).unwrap();
            } else {
                drop(writer);
            }
            assert!(!peek_eof(reader.as_raw_fd()).unwrap());
            let mut frame = [0; 6];
            reader.read_exact(&mut frame).unwrap();
            assert_eq!(&frame, b"frame\n");
            assert!(
                peek_eof(reader.as_raw_fd()).unwrap(),
                "zero-byte peek observes EOF"
            );
        }
    }

    #[test]
    fn closed_peer_keeps_complete_and_partial_frames_readable() {
        for frame in [
            b"{\"action\":\"timeout\"}\n".as_slice(),
            b"{\"action\":".as_slice(),
        ] {
            let (mut reader, mut writer) = UnixStream::pair().unwrap();
            let guard = RegistrationHealth::new(reader.as_raw_fd());
            guard.check().unwrap();
            writer.write_all(frame).unwrap();
            drop(writer);
            assert!(
                matches!(guard.check(), Err(ClientError::Disconnected)),
                "shutdown behind data"
            );
            let mut received = Vec::new();
            reader.read_to_end(&mut received).unwrap();
            assert_eq!(received, frame, "normal reader preserves pre-EOF bytes");
            assert_eq!(reader.read(&mut [0; 1]).unwrap(), 0);
        }
    }

    #[test]
    fn disposed_descriptor_cannot_become_a_new_registration() {
        let (original, _peer) = UnixStream::pair().unwrap();
        let guard = RegistrationHealth::new(original.as_raw_fd());
        guard.check().unwrap();
        guard.dispose();
        let (replacement, _replacement_peer) = UnixStream::pair().unwrap();
        // Both descriptor numbers remain owned throughout the forced reuse.
        assert_eq!(
            unsafe { libc::dup2(replacement.as_raw_fd(), original.as_raw_fd()) },
            original.as_raw_fd()
        );
        assert!(matches!(guard.check(), Err(ClientError::Disconnected)));
    }
}
