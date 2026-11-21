use std::{
    io::{Read, Write},
    os::{
        fd::{AsFd, AsRawFd},
        unix::net::UnixStream,
    },
    path::Path,
    time::Duration,
};

#[test]
fn strict_original_metadata_retains_nondefault_timeouts_flags_and_bytes() {
    let (mut peer, mut original) = UnixStream::pair().unwrap();
    original
        .set_read_timeout(Some(Duration::from_millis(710)))
        .unwrap();
    original
        .set_write_timeout(Some(Duration::from_millis(1310)))
        .unwrap();
    let read = original.read_timeout().unwrap();
    let write = original.write_timeout().unwrap();
    let flags = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFL) };
    peer.write_all(b"private-original-canary").unwrap();
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    let witness = crate::process::strict_peer_cred_from_fd(
        original.as_fd(),
        Path::new(crate::process::LIVE_PROC_ROOT),
    )
    .unwrap();
    crate::process::strict_revalidate(
        &witness,
        original.as_fd(),
        Path::new(crate::process::LIVE_PROC_ROOT),
    )
    .unwrap();
    assert_eq!(
        original.read_timeout().unwrap(),
        read,
        "original receive timeout changed"
    );
    assert_eq!(
        original.write_timeout().unwrap(),
        write,
        "original send timeout changed"
    );
    assert_eq!(
        unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFL) },
        flags,
        "original file status flags changed"
    );
    let mut bytes = [0; 23];
    let read = original.read_exact(&mut bytes);
    assert!(
        read.is_ok(),
        "original bytes consumed by metadata query: {read:?}"
    );
    assert_eq!(
        &bytes, b"private-original-canary",
        "original bytes consumed by metadata query"
    );
    let write = original.write_all(b"still-live");
    assert!(
        write.is_ok(),
        "metadata query shut down original transport: {write:?}"
    );
    let mut back = [0; 10];
    peer.read_exact(&mut back).unwrap();
    assert_eq!(
        &back, b"still-live",
        "metadata query shut down original transport"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn strict_original_error_path_does_not_clear_pending_socket_error() {
    fn pending() -> UnixStream {
        let (mut original, peer) = UnixStream::pair().unwrap();
        original.write_all(b"unread-pending-error").unwrap();
        drop(peer);
        original
    }
    fn error(stream: &UnixStream) -> i32 {
        let mut value: libc::c_int = 0;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut value as *mut libc::c_int).cast(),
                    &mut length,
                )
            },
            0
        );
        value
    }
    let control = pending();
    let expected = error(&control);
    assert_ne!(expected, 0, "pending socket error control did not fire");
    let original = pending();
    let result = crate::process::strict_peer_cred_from_fd(
        original.as_fd(),
        Path::new(crate::process::LIVE_PROC_ROOT),
    );
    assert!(result.is_err());
    assert_eq!(
        error(&original),
        expected,
        "metadata query cleared original SO_ERROR"
    );
}
