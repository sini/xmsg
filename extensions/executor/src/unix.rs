use crate::{
    auth::PeerWitness,
    control::{AdminCommand, ControlReply, ControlService, ErrorCode},
    framing::MAX_FRAME_BYTES,
    protocol::ControlRequest,
};
use serde::Serialize;
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum WireReply<T: Serialize> {
    Ok { result: T },
    Error { code: ErrorCode },
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

pub(crate) fn private_parent(file_path: &Path, uid: u32) -> Result<PathBuf, ErrorCode> {
    let parent = file_path
        .parent()
        .ok_or(ErrorCode::InvalidConfiguration)?
        .canonicalize()
        .map_err(|_| ErrorCode::InvalidConfiguration)?;
    let meta = std::fs::symlink_metadata(&parent).map_err(|_| ErrorCode::InvalidConfiguration)?;
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o777 != 0o700 {
        return Err(ErrorCode::InvalidConfiguration);
    }
    Ok(parent.join(
        file_path
            .file_name()
            .ok_or(ErrorCode::InvalidConfiguration)?,
    ))
}

pub fn bind_private_socket(socket_path: &Path) -> Result<UnixListener, ErrorCode> {
    let socket_path = private_parent(socket_path, xmsg::client::current_uid())?;
    if socket_path
        .try_exists()
        .map_err(|_| ErrorCode::InvalidConfiguration)?
    {
        return Err(ErrorCode::InvalidConfiguration);
    }
    let listener = UnixListener::bind(&socket_path).map_err(|_| ErrorCode::InvalidConfiguration)?;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| ErrorCode::InvalidConfiguration)?;
    Ok(listener)
}
pub(crate) fn peer(stream: &UnixStream) -> Result<PeerWitness, ErrorCode> {
    #[cfg(target_os = "linux")]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        } != 0
            || len as usize != std::mem::size_of::<libc::ucred>()
        {
            return Err(ErrorCode::PeerUid);
        }
        Ok(PeerWitness {
            uid: cred.uid,
            pid: u32::try_from(cred.pid).ok(),
        })
    }
    #[cfg(target_os = "macos")]
    {
        let mut uid = 0;
        let mut gid = 0;
        if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(ErrorCode::PeerUid);
        }
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                0,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut len,
            )
        };
        Ok(PeerWitness {
            uid,
            pid: if result == 0 {
                u32::try_from(pid).ok()
            } else {
                None
            },
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = stream;
        Err(ErrorCode::PeerUid)
    }
}
fn line(reader: &mut impl BufRead, limit: usize) -> Result<Vec<u8>, ErrorCode> {
    let mut bytes = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| ErrorCode::MalformedFrame)?;
    if bytes.len() > limit || bytes.last() != Some(&b'\n') {
        return Err(ErrorCode::MalformedFrame);
    }
    bytes.pop();
    Ok(bytes)
}
fn reply<T: Serialize>(
    stream: &mut UnixStream,
    result: Result<T, ErrorCode>,
) -> Result<(), ErrorCode> {
    let response = match result {
        Ok(result) => WireReply::Ok { result },
        Err(code) => WireReply::Error { code },
    };
    let mut bytes = serde_json::to_vec(&response).map_err(|_| ErrorCode::Storage)?;
    if bytes.len() + 1 > MAX_FRAME_BYTES {
        return Err(ErrorCode::Storage);
    }
    bytes.push(b'\n');
    stream.write_all(&bytes).map_err(|_| ErrorCode::Storage)
}
fn prepare(stream: &UnixStream) -> Result<(), ErrorCode> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| ErrorCode::Storage)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| ErrorCode::Storage)
}

impl ControlService {
    pub fn handle_lifecycle_connection(&self, mut stream: UnixStream) -> Result<(), ErrorCode> {
        prepare(&stream)?;
        let peer = peer(&stream)?;
        let mut reader = BufReader::new(stream.try_clone().map_err(|_| ErrorCode::Storage)?);
        let result = (|| {
            let body = line(&mut reader, MAX_FRAME_BYTES)?;
            let request: ControlRequest =
                serde_json::from_slice(&body).map_err(|_| ErrorCode::MalformedFrame)?;
            self.lifecycle(peer, request, now())
        })();
        reply(&mut stream, result)
    }
    pub fn handle_owner_connection(&self, mut stream: UnixStream) -> Result<(), ErrorCode> {
        prepare(&stream)?;
        let peer = peer(&stream)?;
        let mut reader = BufReader::new(stream.try_clone().map_err(|_| ErrorCode::Storage)?);
        let result = (|| {
            let proof = line(&mut reader, 256)?;
            let body = line(&mut reader, MAX_FRAME_BYTES)?;
            let command: AdminCommand =
                serde_json::from_slice(&body).map_err(|_| ErrorCode::MalformedFrame)?;
            self.admin(peer, &proof, command, now())
        })();
        reply(&mut stream, result)
    }
    pub fn handle_human_connection(&self, mut stream: UnixStream) -> Result<(), ErrorCode> {
        prepare(&stream)?;
        let peer = peer(&stream)?;
        let mut reader = BufReader::new(stream.try_clone().map_err(|_| ErrorCode::Storage)?);
        let result: Result<ControlReply, ErrorCode> = (|| {
            let proof = line(&mut reader, 256)?;
            let body = line(&mut reader, MAX_FRAME_BYTES)?;
            let request: ControlRequest =
                serde_json::from_slice(&body).map_err(|_| ErrorCode::MalformedFrame)?;
            self.human(peer, &proof, request, now())
        })();
        reply(&mut stream, result)
    }
}
