//! Bounded local attribution transport; replies are not bearer authority.

use serde::{Deserialize, Serialize};
use std::{
    io,
    os::{
        fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt, net::UnixStream},
    },
    path::Path,
    time::Instant,
};

pub const VERSION: u8 = 1;
pub const MAX_BODY: usize = 4096;
pub const CONTEXT_DOMAIN: &[u8] = b"xmsg.executor.caller-context.v1\0";
const QUERY_MARKER: u8 = 0xa1;
const REPLY_MARKER: u8 = 0xa2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CallerContext {
    Codex {
        session_id: String,
        thread_id: String,
        turn_id: Option<String>,
    },
}
impl CallerContext {
    pub fn normalize(self) -> Result<Self, FailureReason> {
        match self {
            Self::Codex {
                session_id,
                thread_id,
                turn_id,
            } => {
                let session_id = session_id.trim().to_owned();
                let thread_id = thread_id.trim().to_owned();
                if !super::is_uuid_shaped(&session_id) || !super::is_uuid_shaped(&thread_id) {
                    return Err(FailureReason::Context);
                }
                let turn_id = turn_id
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty());
                if turn_id
                    .as_ref()
                    .is_some_and(|s| s.len() > 256 || s.chars().any(char::is_control))
                {
                    return Err(FailureReason::Context);
                }
                Ok(Self::Codex {
                    session_id,
                    thread_id,
                    turn_id,
                })
            }
        }
    }
}
pub fn context_bytes(context: &Option<CallerContext>) -> Result<Vec<u8>, FailureReason> {
    serde_json::to_vec(context).map_err(|_| FailureReason::Protocol)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    Unqualified,
    Unsupported,
    PeerUid,
    MissingPid,
    DeadPeer,
    UnmappedPeer,
    ContradictoryPeer,
    FdinfoUnavailable,
    Endpoint,
    Protocol,
    Ancillary,
    Limit,
    Deadline,
    Busy,
    AuthorityUnavailable,
    Ambiguous,
    Changed,
    Context,
    ExecutorLineage,
    Internal,
}
impl std::fmt::Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for FailureReason {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityStamp {
    pub source: String,
    pub matched_pid: u32,
    pub matched_start: String,
    pub registration_digest: String,
    pub root_generation: Option<u64>,
    pub child_generation: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub v: u8,
    pub runtime_epoch: String,
    pub call_nonce: u64,
    pub input_digest: String,
    pub context: Option<CallerContext>,
    pub context_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Ok {
        v: u8,
        runtime_epoch: String,
        call_nonce: u64,
        input_digest: String,
        context_digest: String,
        peer_uid: u32,
        peer_pid: u32,
        principal: String,
        authority_stamp: Box<AuthorityStamp>,
    },
    Unavailable {
        v: u8,
        reason: FailureReason,
    },
}
fn hex_bytes(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
impl Query {
    pub fn validate(&self) -> Result<(), FailureReason> {
        if self.v != VERSION
            || self.call_nonce == 0
            || !hex_bytes(&self.runtime_epoch, 32)
            || !hex_bytes(&self.input_digest, 64)
            || !hex_bytes(&self.context_digest, 64)
        {
            return Err(FailureReason::Protocol);
        }
        if let Some(context) = &self.context {
            if context.clone().normalize()? != *context {
                return Err(FailureReason::Context);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointIdentity {
    dev: u64,
    ino: u64,
}
pub fn private_socket(path: &Path, uid: u32) -> Result<EndpointIdentity, FailureReason> {
    if !path.is_absolute() {
        return Err(FailureReason::Endpoint);
    }
    let mut prefix = std::path::PathBuf::new();
    for part in path.components() {
        prefix.push(part.as_os_str());
        if std::fs::symlink_metadata(&prefix)
            .map_err(|_| FailureReason::Endpoint)?
            .file_type()
            .is_symlink()
        {
            return Err(FailureReason::Endpoint);
        }
    }
    let parent = std::fs::symlink_metadata(path.parent().ok_or(FailureReason::Endpoint)?)
        .map_err(|_| FailureReason::Endpoint)?;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| FailureReason::Endpoint)?;
    use std::os::unix::fs::FileTypeExt;
    if !parent.is_dir()
        || parent.uid() != uid
        || parent.mode() & 0o7777 != 0o700
        || !metadata.file_type().is_socket()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(FailureReason::Endpoint);
    }
    Ok(EndpointIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}
pub fn socket_peer(fd: BorrowedFd<'_>) -> io::Result<(u32, Option<u32>)> {
    #[cfg(target_os = "linux")]
    {
        let mut value: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut value as *mut libc::ucred).cast(),
                &mut length,
            )
        } < 0
            || length as usize != std::mem::size_of_val(&value)
        {
            return Err(io::Error::last_os_error());
        }
        Ok((
            value.uid,
            u32::try_from(value.pid).ok().filter(|pid| *pid > 0),
        ))
    }
    #[cfg(target_os = "macos")]
    {
        let mut uid = 0;
        let mut gid = 0;
        if unsafe { libc::getpeereid(fd.as_raw_fd(), &mut uid, &mut gid) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut pid: libc::pid_t = 0;
        let mut length = std::mem::size_of_val(&pid) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                0,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut length,
            )
        };
        Ok((
            uid,
            (result == 0 && length as usize == std::mem::size_of_val(&pid))
                .then(|| u32::try_from(pid).ok().filter(|pid| *pid > 0))
                .flatten(),
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = fd;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "peer credentials unavailable",
        ))
    }
}
pub fn original_endpoint(fd: BorrowedFd<'_>, expected: &Path) -> Result<(), FailureReason> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    } < 0
        || value != libc::SOCK_STREAM
    {
        return Err(FailureReason::Endpoint);
    }
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    } < 0
        || value != 0
    {
        return Err(FailureReason::Endpoint);
    }
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    length = std::mem::size_of_val(&address) as _;
    if unsafe {
        libc::getpeername(
            fd.as_raw_fd(),
            (&mut address as *mut libc::sockaddr_un).cast(),
            &mut length,
        )
    } < 0
        || address.sun_family as i32 != libc::AF_UNIX
    {
        return Err(FailureReason::Endpoint);
    }
    address = unsafe { std::mem::zeroed() };
    length = std::mem::size_of_val(&address) as _;
    if unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            (&mut address as *mut libc::sockaddr_un).cast(),
            &mut length,
        )
    } < 0
        || address.sun_family as i32 != libc::AF_UNIX
    {
        return Err(FailureReason::Endpoint);
    }
    let offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    let available = (length as usize)
        .saturating_sub(offset)
        .min(address.sun_path.len());
    let bytes: Vec<u8> = address.sun_path[..available]
        .iter()
        .map(|c| *c as u8)
        .take_while(|c| *c != 0)
        .collect();
    if bytes != expected.as_os_str().as_bytes() {
        return Err(FailureReason::Endpoint);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
static INHERITANCE_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub fn with_fd_inheritance_gate<T>(operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    #[cfg(target_os = "macos")]
    let _guard = INHERITANCE_GATE
        .lock()
        .map_err(|_| io::Error::other("FD inheritance gate poisoned"))?;
    operation()
}
fn receive_gate<T>(deadline: Instant, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    #[cfg(target_os = "macos")]
    let _guard = loop {
        match INHERITANCE_GATE.try_lock() {
            Ok(guard) => break guard,
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(io::Error::other("FD inheritance gate poisoned"))
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "attribution deadline",
                    ));
                }
                std::thread::yield_now();
            }
        }
    };
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "attribution deadline",
        ));
    }
    operation()
}
fn failure(error: io::Error) -> FailureReason {
    if error.kind() == io::ErrorKind::TimedOut {
        FailureReason::Deadline
    } else {
        FailureReason::Protocol
    }
}
fn wait(fd: RawFd, event: i16, deadline: Instant) -> io::Result<()> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "attribution deadline",
            ));
        }
        let mut descriptor = libc::pollfd {
            fd,
            events: event,
            revents: 0,
        };
        let millis = i32::try_from(left.as_millis().saturating_add(1)).unwrap_or(i32::MAX);
        let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if result > 0 {
            return Ok(());
        }
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
}
fn mark_cloexec(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub fn connect(path: &Path, deadline: Instant) -> Result<UnixStream, FailureReason> {
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
        return Err(FailureReason::Endpoint);
    }
    address.sun_family = libc::AF_UNIX as _;
    for (dst, src) in address.sun_path.iter_mut().zip(bytes) {
        *dst = *src as _;
    }
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    #[cfg(target_os = "macos")]
    {
        address.sun_len = length as _;
    }
    let fd = receive_gate(deadline, || {
        let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        mark_cloexec(raw)?;
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(target_os = "macos")]
        {
            let yes: libc::c_int = 1;
            if unsafe {
                libc::setsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    (&yes as *const libc::c_int).cast(),
                    std::mem::size_of_val(&yes) as _,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(fd)
    })
    .map_err(failure)?;
    let result = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            length as _,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EINPROGRESS | libc::EAGAIN)) {
            return Err(FailureReason::Endpoint);
        }
        wait(fd.as_raw_fd(), libc::POLLOUT, deadline).map_err(failure)?;
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut value as *mut libc::c_int).cast(),
                &mut len,
            )
        } < 0
            || value != 0
        {
            return Err(FailureReason::Endpoint);
        }
    }
    Ok(UnixStream::from(fd))
}

fn frame<T: Serialize>(marker: u8, value: &T) -> Result<Vec<u8>, FailureReason> {
    let body = serde_json::to_vec(value).map_err(|_| FailureReason::Protocol)?;
    if body.len() > MAX_BODY {
        return Err(FailureReason::Limit);
    }
    let mut output = Vec::with_capacity(body.len() + 5);
    output.push(marker);
    output.extend_from_slice(&(body.len() as u32).to_be_bytes());
    output.extend_from_slice(&body);
    Ok(output)
}
fn send(
    stream: &UnixStream,
    bytes: &[u8],
    descriptor: Option<BorrowedFd<'_>>,
    deadline: Instant,
) -> Result<(), FailureReason> {
    let mut written = 0;
    while written < bytes.len() {
        wait(stream.as_raw_fd(), libc::POLLOUT, deadline).map_err(failure)?;
        let mut vector = libc::iovec {
            iov_base: bytes[written..].as_ptr().cast_mut().cast(),
            iov_len: bytes.len() - written,
        };
        let mut control = [0usize; 4];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        if written == 0 {
            if let Some(fd) = descriptor {
                message.msg_control = control.as_mut_ptr().cast();
                message.msg_controllen =
                    unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as _) } as _;
                unsafe {
                    let header = libc::CMSG_FIRSTHDR(&message);
                    (*header).cmsg_level = libc::SOL_SOCKET;
                    (*header).cmsg_type = libc::SCM_RIGHTS;
                    (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as _) as _;
                    std::ptr::write_unaligned(
                        libc::CMSG_DATA(header).cast::<RawFd>(),
                        fd.as_raw_fd(),
                    );
                }
            }
        }
        #[cfg(target_os = "linux")]
        let flags = libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT;
        #[cfg(not(target_os = "linux"))]
        let flags = libc::MSG_DONTWAIT;
        let result = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, flags) };
        if result > 0 {
            written += result as usize;
        } else if result == 0 {
            return Err(FailureReason::Protocol);
        } else {
            let error = io::Error::last_os_error();
            if !matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return Err(failure(error));
            }
        }
    }
    stream.shutdown(std::net::Shutdown::Write).map_err(failure)
}
fn receive(
    stream: &UnixStream,
    marker: u8,
    expect_fd: bool,
    deadline: Instant,
) -> Result<(Vec<u8>, Vec<OwnedFd>), FailureReason> {
    let mut data = Vec::new();
    let mut descriptors = Vec::new();
    let mut expected_len = None;
    loop {
        wait(stream.as_raw_fd(), libc::POLLIN, deadline).map_err(failure)?;
        let mut bytes = [0u8; MAX_BODY + 6];
        let result = receive_gate(deadline, || {
            let mut control = [0usize; 4];
            let mut vector = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &mut vector;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen =
                unsafe { libc::CMSG_SPACE((2 * std::mem::size_of::<RawFd>()) as _) } as _;
            #[cfg(target_os = "linux")]
            let flags = libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC;
            #[cfg(not(target_os = "linux"))]
            let flags = libc::MSG_DONTWAIT;
            let count = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, flags) };
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut received = Vec::new();
            let mut malformed = false;
            unsafe {
                let mut header = libc::CMSG_FIRSTHDR(&message);
                while !header.is_null() {
                    let base = libc::CMSG_LEN(0) as usize;
                    let length = (*header).cmsg_len as usize;
                    let offset = header as usize - message.msg_control as usize;
                    if length < base || offset + length > message.msg_controllen as usize {
                        malformed = true;
                        break;
                    }
                    if (*header).cmsg_level == libc::SOL_SOCKET
                        && (*header).cmsg_type == libc::SCM_RIGHTS
                    {
                        let payload = length - base;
                        if !payload.is_multiple_of(std::mem::size_of::<RawFd>()) {
                            malformed = true;
                        }
                        for index in 0..payload / std::mem::size_of::<RawFd>() {
                            let raw = std::ptr::read_unaligned(
                                libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                            );
                            if raw < 0 {
                                malformed = true;
                                continue;
                            }
                            received.push(OwnedFd::from_raw_fd(raw));
                        }
                    } else {
                        malformed = true;
                    }
                    header = libc::CMSG_NXTHDR(&message, header);
                }
            }
            for owned in &received {
                mark_cloexec(owned.as_raw_fd())?;
            }
            if message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
                malformed = true;
            }
            Ok((count as usize, received, malformed))
        });
        let (count, received, malformed) = match result {
            Ok(value) => value,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(error) => return Err(failure(error)),
        };
        if malformed || (!data.is_empty() && !received.is_empty()) {
            return Err(FailureReason::Ancillary);
        }
        descriptors.extend(received);
        if descriptors.len() > usize::from(expect_fd) {
            return Err(FailureReason::Ancillary);
        }
        if count == 0 {
            if descriptors.len() != usize::from(expect_fd) || expected_len != Some(data.len()) {
                return Err(FailureReason::Protocol);
            }
            return Ok((data.split_off(5), descriptors));
        }
        data.extend_from_slice(&bytes[..count]);
        if data.len() > MAX_BODY + 5 {
            return Err(FailureReason::Limit);
        }
        if data[0] != marker {
            return Err(FailureReason::Protocol);
        }
        if data.len() >= 5 && expected_len.is_none() {
            let length =
                u32::from_be_bytes(data[1..5].try_into().map_err(|_| FailureReason::Protocol)?)
                    as usize;
            if length > MAX_BODY {
                return Err(FailureReason::Limit);
            }
            expected_len = Some(length + 5);
        }
        if expected_len.is_some_and(|length| data.len() > length) {
            return Err(FailureReason::Protocol);
        }
    }
}
pub fn send_query(
    stream: &UnixStream,
    original: BorrowedFd<'_>,
    query: &Query,
    deadline: Instant,
) -> Result<(), FailureReason> {
    query.validate()?;
    send(
        stream,
        &frame(QUERY_MARKER, query)?,
        Some(original),
        deadline,
    )
}
pub fn receive_query(
    stream: &UnixStream,
    deadline: Instant,
) -> Result<(Query, OwnedFd), FailureReason> {
    let (body, mut fds) = receive(stream, QUERY_MARKER, true, deadline)?;
    let query: Query = serde_json::from_slice(&body).map_err(|_| FailureReason::Protocol)?;
    query.validate()?;
    Ok((query, fds.pop().ok_or(FailureReason::Ancillary)?))
}
pub fn send_reply(
    stream: &UnixStream,
    reply: &Reply,
    deadline: Instant,
) -> Result<(), FailureReason> {
    send(stream, &frame(REPLY_MARKER, reply)?, None, deadline)
}
pub fn receive_reply(stream: &UnixStream, deadline: Instant) -> Result<Reply, FailureReason> {
    let (body, _) = receive(stream, REPLY_MARKER, false, deadline)?;
    serde_json::from_slice(&body).map_err(|_| FailureReason::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::fd::AsFd, time::Duration};
    fn query() -> Query {
        Query {
            v: VERSION,
            runtime_epoch: "a".repeat(32),
            call_nonce: 1,
            input_digest: "b".repeat(64),
            context: None,
            context_digest: "c".repeat(64),
        }
    }
    #[test]
    fn attribution_wire_passes_one_descriptor_without_consuming_original() {
        let (client, server) = UnixStream::pair().unwrap();
        let (mut original, mut original_peer) = UnixStream::pair().unwrap();
        use std::io::{Read, Write};
        original_peer.write_all(b"untouched").unwrap();
        let expected = query();
        std::thread::scope(|scope| {
            let sender = scope.spawn(|| {
                send_query(
                    &client,
                    original.as_fd(),
                    &expected,
                    Instant::now() + Duration::from_secs(2),
                )
                .unwrap()
            });
            let (actual, received) =
                receive_query(&server, Instant::now() + Duration::from_secs(2)).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(
                socket_peer(received.as_fd()).unwrap().0,
                super::super::current_uid()
            );
            drop(received);
            sender.join().unwrap();
        });
        let mut bytes = [0; 9];
        original.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"untouched");
    }
    #[test]
    fn attribution_wire_requires_descriptor_and_exact_eof() {
        let (client, server) = UnixStream::pair().unwrap();
        let body = frame(QUERY_MARKER, &query()).unwrap();
        send(
            &client,
            &body,
            None,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert!(receive_query(&server, Instant::now() + Duration::from_secs(2)).is_err());
        let (client, server) = UnixStream::pair().unwrap();
        let (original, _other) = UnixStream::pair().unwrap();
        let mut body = frame(QUERY_MARKER, &query()).unwrap();
        body.push(b'x');
        send(
            &client,
            &body,
            Some(original.as_fd()),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert!(matches!(
            receive_query(&server, Instant::now() + Duration::from_secs(2)),
            Err(FailureReason::Protocol)
        ));
    }
    #[test]
    fn attribution_reply_rejects_trailing_bytes_before_decode() {
        let (client, server) = UnixStream::pair().unwrap();
        let mut bytes = frame(
            REPLY_MARKER,
            &Reply::Unavailable {
                v: VERSION,
                reason: FailureReason::Unqualified,
            },
        )
        .unwrap();
        bytes.extend_from_slice(b"extra");
        send(
            &server,
            &bytes,
            None,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert!(matches!(
            receive_reply(&client, Instant::now() + Duration::from_secs(2)),
            Err(FailureReason::Protocol)
        ));
    }
    #[test]
    fn attribution_wrong_marker_closes_received_original() {
        use std::io::Read;
        let (client, server) = UnixStream::pair().unwrap();
        let (original, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let body = frame(0x11, &query()).unwrap();
        send(
            &client,
            &body,
            Some(original.as_fd()),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        drop(original);
        assert!(
            receive_query(&server, Instant::now() + Duration::from_secs(2)).is_err(),
            "wrong query marker accepted"
        );
        assert!(
            matches!(peer.read(&mut [0]), Ok(0)),
            "malformed query leaked received descriptor"
        );
    }
    #[test]
    fn attribution_cleanup_eof_waits_for_an_independent_transient_holder() {
        use std::io::Read;
        let (client, server) = UnixStream::pair().unwrap();
        let (original, mut peer) = UnixStream::pair().unwrap();
        let held = original.try_clone().unwrap();
        let (release_rx, release_tx) = std::sync::mpsc::sync_channel::<()>(0);
        let holder = std::thread::spawn(move || {
            release_tx.recv().unwrap();
            drop(held);
        });
        send(
            &client,
            &frame(0x11, &query()).unwrap(),
            Some(original.as_fd()),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        drop(original);
        let refused = receive_query(&server, Instant::now() + Duration::from_secs(2)).is_err();
        peer.set_nonblocking(true).unwrap();
        let postponed =
            matches!(peer.read(&mut[0]),Err(error) if error.kind()==io::ErrorKind::WouldBlock);
        release_rx.send(()).unwrap();
        holder.join().unwrap();
        assert!(refused);
        assert!(
            postponed,
            "independent holder must postpone EOF despite receiver cleanup"
        );
        peer.set_nonblocking(false).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        assert!(
            matches!(peer.read(&mut [0]), Ok(0)),
            "receiver cleanup leaked after independent holder was released"
        );
    }
    #[test]
    fn attribution_oversized_header_is_rejected_before_body() {
        let (client, server) = UnixStream::pair().unwrap();
        let (original, _peer) = UnixStream::pair().unwrap();
        let mut body = vec![QUERY_MARKER];
        body.extend_from_slice(&((MAX_BODY + 1) as u32).to_be_bytes());
        send(
            &client,
            &body,
            Some(original.as_fd()),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert!(
            matches!(
                receive_query(&server, Instant::now() + Duration::from_secs(2)),
                Err(FailureReason::Limit)
            ),
            "oversized attribution body header accepted"
        );
    }
    fn extra_fd_frame(client: &UnixStream, descriptors: &[RawFd], bytes: &[u8]) {
        let mut control = [0usize; 16];
        let mut vector = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen =
            unsafe { libc::CMSG_SPACE(std::mem::size_of_val(descriptors) as _) } as _;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(descriptors) as _) as _;
            std::ptr::copy_nonoverlapping(
                descriptors.as_ptr(),
                libc::CMSG_DATA(header).cast::<RawFd>(),
                descriptors.len(),
            );
            assert_eq!(
                libc::sendmsg(client.as_raw_fd(), &message, 0),
                bytes.len() as libc::ssize_t
            );
        }
        client.shutdown(std::net::Shutdown::Write).unwrap();
    }
    #[test]
    fn attribution_extra_descriptors_are_rejected_and_all_closed() {
        use std::io::Read;
        let (client, server) = UnixStream::pair().unwrap();
        let (first, mut first_peer) = UnixStream::pair().unwrap();
        let (second, mut second_peer) = UnixStream::pair().unwrap();
        for peer in [&first_peer, &second_peer] {
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        }
        extra_fd_frame(
            &client,
            &[first.as_raw_fd(), second.as_raw_fd()],
            &frame(QUERY_MARKER, &query()).unwrap(),
        );
        drop(first);
        drop(second);
        assert!(
            matches!(
                receive_query(&server, Instant::now() + Duration::from_secs(2)),
                Err(FailureReason::Ancillary)
            ),
            "multiple original descriptors accepted"
        );
        assert!(
            matches!(first_peer.read(&mut [0]), Ok(0)),
            "first excess descriptor leaked"
        );
        assert!(
            matches!(second_peer.read(&mut [0]), Ok(0)),
            "second excess descriptor leaked"
        );
    }
    #[test]
    fn attribution_truncated_ancillary_closes_visible_and_hidden_rights() {
        use std::io::Read;
        let (client, server) = UnixStream::pair().unwrap();
        let (a, mut ap) = UnixStream::pair().unwrap();
        let (b, mut bp) = UnixStream::pair().unwrap();
        let (c, mut cp) = UnixStream::pair().unwrap();
        for peer in [&ap, &bp, &cp] {
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        }
        extra_fd_frame(
            &client,
            &[a.as_raw_fd(), b.as_raw_fd(), c.as_raw_fd()],
            &frame(QUERY_MARKER, &query()).unwrap(),
        );
        drop(a);
        drop(b);
        drop(c);
        assert!(
            matches!(
                receive_query(&server, Instant::now() + Duration::from_secs(2)),
                Err(FailureReason::Ancillary)
            ),
            "truncated rights accepted"
        );
        for peer in [&mut ap, &mut bp, &mut cp] {
            assert!(
                matches!(peer.read(&mut [0]), Ok(0)),
                "truncated rights leaked descriptor"
            );
        }
    }
    #[test]
    fn attribution_reply_without_eof_cannot_be_decoded() {
        use std::io::Write;
        let (client, mut server) = UnixStream::pair().unwrap();
        let reply = Reply::Ok {
            v: VERSION,
            runtime_epoch: "a".repeat(32),
            call_nonce: 1,
            input_digest: "b".repeat(64),
            context_digest: "c".repeat(64),
            peer_uid: super::super::current_uid(),
            peer_pid: std::process::id(),
            principal: "caller@node".into(),
            authority_stamp: Box::new(AuthorityStamp {
                source: "test".into(),
                matched_pid: std::process::id(),
                matched_start: "test".into(),
                registration_digest: "d".repeat(64),
                root_generation: None,
                child_generation: None,
            }),
        };
        server
            .write_all(&frame(REPLY_MARKER, &reply).unwrap())
            .unwrap();
        assert!(
            matches!(
                receive_reply(&client, Instant::now() + Duration::from_millis(100)),
                Err(FailureReason::Deadline)
            ),
            "response principal boundary ignored missing EOF"
        );
    }
}
