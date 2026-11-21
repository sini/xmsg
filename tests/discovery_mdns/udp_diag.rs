use std::collections::HashSet;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const HEADER: usize = std::mem::size_of::<libc::nlmsghdr>();
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const REQUEST_BYTES: usize = HEADER + 56;
const INODE_OFFSET: usize = HEADER + 68;

pub(super) fn udp_port_open(pid: u32, port: u16) -> bool {
    let inodes: HashSet<u32> = fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("read process file descriptors")
        .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
        .filter_map(|target| {
            target
                .to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')?
                .parse()
                .ok()
        })
        .collect();

    [libc::AF_INET, libc::AF_INET6].into_iter().any(|family| {
        matching_socket(family, port, &inodes)
            .unwrap_or_else(|err| panic!("UDP SOCK_DIAG unavailable or incomplete: {err}"))
    })
}

fn matching_socket(family: libc::c_int, port: u16, inodes: &HashSet<u32>) -> io::Result<bool> {
    // The kernel filters by local port before emitting results, avoiding procfs pagination under churn.
    let mut request = [0u8; REQUEST_BYTES];
    request[..4].copy_from_slice(&(REQUEST_BYTES as u32).to_ne_bytes());
    request[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    request[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    request[HEADER] = family as u8;
    request[HEADER + 1] = libc::IPPROTO_UDP as u8;
    request[HEADER + 4..HEADER + 8].copy_from_slice(&u32::MAX.to_ne_bytes());
    request[HEADER + 8..HEADER + 10].copy_from_slice(&port.to_be_bytes());

    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let fd = socket.as_raw_fd();
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    let set_timeout = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            std::mem::size_of_val(&timeout) as libc::socklen_t,
        )
    };
    if set_timeout < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut destination: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    destination.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let sent = unsafe {
        libc::sendto(
            fd,
            request.as_ptr().cast(),
            request.len(),
            0,
            (&raw const destination).cast(),
            std::mem::size_of_val(&destination) as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != request.len() {
        return Err(invalid_reply());
    }

    let mut buffer = [0u8; 8192];
    let mut matched = false;
    loop {
        let length = unsafe {
            libc::recv(
                fd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
            )
        };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        if length == 0 || length as usize > buffer.len() {
            return Err(invalid_reply());
        }
        let mut packet = &buffer[..length as usize];
        while !packet.is_empty() {
            if packet.len() < HEADER {
                return Err(invalid_reply());
            }
            let size = u32::from_ne_bytes(packet[..4].try_into().unwrap()) as usize;
            let kind = u16::from_ne_bytes(packet[4..6].try_into().unwrap());
            let flags = u16::from_ne_bytes(packet[6..8].try_into().unwrap());
            if size < HEADER || size > packet.len() || flags & libc::NLM_F_DUMP_INTR as u16 != 0 {
                return Err(invalid_reply());
            }
            match kind as i32 {
                libc::NLMSG_DONE if size == HEADER => return Ok(matched),
                libc::NLMSG_DONE | libc::NLMSG_ERROR if size >= HEADER + 4 => {
                    let error = i32::from_ne_bytes(packet[HEADER..HEADER + 4].try_into().unwrap());
                    return match (kind as i32, error) {
                        (libc::NLMSG_DONE, 0) => Ok(matched),
                        (_, error) if error < 0 => {
                            Err(io::Error::from_raw_os_error(error.saturating_neg()))
                        }
                        _ => Err(invalid_reply()),
                    };
                }
                message
                    if message == i32::from(SOCK_DIAG_BY_FAMILY) && size >= INODE_OFFSET + 4 =>
                {
                    let inode = u32::from_ne_bytes(
                        packet[INODE_OFFSET..INODE_OFFSET + 4].try_into().unwrap(),
                    );
                    matched |= inodes.contains(&inode);
                }
                _ => return Err(invalid_reply()),
            }
            let aligned = (size + 3) & !3;
            packet = packet.get(aligned..).ok_or_else(invalid_reply)?;
        }
    }
}

fn invalid_reply() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid SOCK_DIAG reply")
}
