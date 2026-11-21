use super::*;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
};

const ANCESTOR: &str = "11111111-1111-4111-8111-111111111111";
const CALLER: &str = "22222222-2222-4222-8222-222222222222";
const CONTROL_LIMIT: usize = 16384;
const FIXTURE_LIMIT: Duration = Duration::from_secs(30);

#[derive(Debug, Serialize, Deserialize)]
struct Witness {
    ancestor_pid: u32,
    executor_pid: u32,
    caller_pid: u32,
    reply: Reply,
}
struct OwnedProcess {
    child: Child,
    control: UnixStream,
    group: bool,
}
impl OwnedProcess {
    fn finish(&mut self, deadline: Instant) {
        let _ = send_byte(&mut self.control, b'X', deadline);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => {}
            }
            std::thread::yield_now();
        }
        self.terminate_owned();
    }
    fn terminate_owned(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => {}
        }
        if self.group {
            if let Ok(pid) = i32::try_from(self.child.id()) {
                if unsafe { libc::getpgid(pid) } == pid {
                    unsafe { libc::kill(-pid, libc::SIGKILL) };
                }
            }
        } else {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        self.finish(Instant::now() + Duration::from_secs(3));
    }
}
fn remaining(deadline: Instant) -> std::io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "lineage fixture absolute deadline",
            )
        })
}
fn send_byte(stream: &mut UnixStream, byte: u8, deadline: Instant) -> std::io::Result<()> {
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    stream.write_all(&[byte])
}
fn read_byte(stream: &mut UnixStream, deadline: Instant) -> std::io::Result<u8> {
    stream.set_read_timeout(Some(remaining(deadline)?))?;
    let mut byte = [0];
    stream.read_exact(&mut byte)?;
    Ok(byte[0])
}
fn send_value<T: Serialize>(stream: &mut UnixStream, value: &T, deadline: Instant) {
    let body = serde_json::to_vec(value).unwrap();
    assert!(body.len() <= CONTROL_LIMIT);
    stream
        .set_write_timeout(Some(remaining(deadline).unwrap()))
        .unwrap();
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .unwrap();
    stream
        .set_write_timeout(Some(remaining(deadline).unwrap()))
        .unwrap();
    stream.write_all(&body).unwrap();
}
fn receive_value<T: serde::de::DeserializeOwned>(stream: &mut UnixStream, deadline: Instant) -> T {
    let mut length = [0; 4];
    stream
        .set_read_timeout(Some(remaining(deadline).unwrap()))
        .unwrap();
    stream.read_exact(&mut length).unwrap();
    let size = u32::from_be_bytes(length) as usize;
    assert!(size <= CONTROL_LIMIT);
    let mut body = vec![0; size];
    stream
        .set_read_timeout(Some(remaining(deadline).unwrap()))
        .unwrap();
    stream.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}
fn process(role: &str, root: &Path, new_group: bool, existing_daemon: bool) -> OwnedProcess {
    let (parent, child) = UnixStream::pair().unwrap();
    let descriptor = child.as_raw_fd();
    let mut command = Command::new(std::env::current_exe().unwrap());
    let entry = if existing_daemon {
        "caller_attribution::tests::fixture_process"
    } else {
        "caller_attribution::lineage_tests::lineage_process"
    };
    command
        .args(["--ignored", "--exact", entry, "--nocapture"])
        .env("XMSG_ATTRIBUTION_FIXTURE_ROLE", role)
        .env("XMSG_ATTRIBUTION_FIXTURE_ROOT", root)
        .env("XMSG_ATTRIBUTION_FIXTURE_FD", descriptor.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if new_group {
        command.process_group(0);
    }
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(descriptor, libc::F_GETFD);
            if flags < 0 || libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child_process = command.spawn().unwrap();
    drop(child);
    OwnedProcess {
        child: child_process,
        control: parent,
        group: new_group,
    }
}
fn register_self(root: &Path, id: &str) {
    let pid = std::process::id();
    let start = crate::process::starttime(Path::new(crate::process::LIVE_PROC_ROOT), pid).unwrap();
    std::fs::create_dir_all(root.join("sessions")).unwrap();
    let entry = serde_json::json!({"sessionId":id,"pid":pid,"procStart":start,"cwd":"/","status":"idle","kind":"interactive","startedAt":1,"updatedAt":1,"messagingSocketPath":root.join(format!("lineage-{id}.sock"))});
    std::fs::write(
        root.join("sessions").join(format!("{id}.json")),
        serde_json::to_vec(&entry).unwrap(),
    )
    .unwrap();
}
#[test]
#[ignore = "owned test-only process entrypoint"]
fn lineage_process() {
    let role = std::env::var("XMSG_ATTRIBUTION_FIXTURE_ROLE").unwrap();
    let root = PathBuf::from(std::env::var_os("XMSG_ATTRIBUTION_FIXTURE_ROOT").unwrap());
    let descriptor: i32 = std::env::var("XMSG_ATTRIBUTION_FIXTURE_FD")
        .unwrap()
        .parse()
        .unwrap();
    let mut control = unsafe { UnixStream::from_raw_fd(descriptor) };
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) },
        0
    );
    let deadline = Instant::now() + FIXTURE_LIMIT;
    if role == "ancestor" || role == "ancestor-registered-child" {
        register_self(&root, ANCESTOR);
        let executor_role = if role == "ancestor" {
            "executor"
        } else {
            "executor-registered-child"
        };
        let mut executor = process(executor_role, &root, false, false);
        assert_eq!(read_byte(&mut executor.control, deadline).unwrap(), b'L');
        send_byte(&mut control, b'L', deadline).unwrap();
        assert_eq!(read_byte(&mut control, deadline).unwrap(), b'G');
        send_byte(&mut executor.control, b'G', deadline).unwrap();
        let mut witness: Witness = receive_value(&mut executor.control, deadline);
        witness.ancestor_pid = std::process::id();
        executor.finish(deadline);
        send_value(&mut control, &witness, deadline);
        assert_eq!(read_byte(&mut control, deadline).unwrap(), b'X');
        return;
    }
    if role == "caller" || role == "registered-caller" {
        if role == "registered-caller" {
            register_self(&root, CALLER);
        }
        let mut lifecycle = UnixStream::connect(root.join("life.sock")).unwrap();
        send_byte(&mut lifecycle, b'R', deadline).unwrap();
        send_byte(&mut control, b'R', deadline).unwrap();
        assert_eq!(read_byte(&mut lifecycle, deadline).unwrap(), b'D');
        return;
    }
    assert!(role == "executor" || role == "executor-registered-child");
    let listener = UnixListener::bind(root.join("life.sock")).unwrap();
    std::fs::set_permissions(
        root.join("life.sock"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    listener.set_nonblocking(true).unwrap();
    send_byte(&mut control, b'L', deadline).unwrap();
    assert_eq!(read_byte(&mut control, deadline).unwrap(), b'G');
    let caller_role = if role == "executor" {
        "caller"
    } else {
        "registered-caller"
    };
    let mut caller = process(caller_role, &root, false, false);
    assert_eq!(read_byte(&mut caller.control, deadline).unwrap(), b'R');
    let (mut original, _) = listener.accept().unwrap();
    assert_eq!(read_byte(&mut original, deadline).unwrap(), b'R');
    let query_deadline = Instant::now() + AUTHORITY_BUDGET;
    let query = wire::connect(&root.join("query.sock"), query_deadline).unwrap();
    let mut context_hash = Sha256::new();
    context_hash.update(wire::CONTEXT_DOMAIN);
    context_hash.update(wire::context_bytes(&None).unwrap());
    let request = wire::Query {
        v: wire::VERSION,
        runtime_epoch: "c".repeat(32),
        call_nonce: 1,
        input_digest: "d".repeat(64),
        context: None,
        context_digest: hex::encode(context_hash.finalize()),
    };
    wire::send_query(&query, original.as_fd(), &request, query_deadline).unwrap();
    let reply = wire::receive_reply(&query, query_deadline).unwrap();
    let witness = Witness {
        ancestor_pid: 0,
        executor_pid: std::process::id(),
        caller_pid: caller.child.id(),
        reply,
    };
    send_byte(&mut original, b'D', deadline).unwrap();
    caller.finish(deadline);
    send_value(&mut control, &witness, deadline);
    assert_eq!(read_byte(&mut control, deadline).unwrap(), b'X');
}
fn roundtrip(registered_child: bool) -> Witness {
    let directory = tempfile::Builder::new()
        .prefix("xb7-")
        .tempdir_in(Path::new("/tmp").canonicalize().unwrap())
        .unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let deadline = Instant::now() + FIXTURE_LIMIT;
    let role = if registered_child {
        "ancestor-registered-child"
    } else {
        "ancestor"
    };
    let mut ancestor = process(role, directory.path(), true, false);
    assert_eq!(read_byte(&mut ancestor.control, deadline).unwrap(), b'L');
    let mut daemon = process("daemon", directory.path(), true, true);
    assert_eq!(read_byte(&mut daemon.control, deadline).unwrap(), b'R');
    send_byte(&mut ancestor.control, b'G', deadline).unwrap();
    let witness = receive_value(&mut ancestor.control, deadline);
    ancestor.finish(deadline);
    daemon.finish(deadline);
    witness
}
#[test]
fn actual_executor_incarnation_blocks_unregistered_descendant_at_producer() {
    let witness = roundtrip(false);
    assert_ne!(witness.ancestor_pid, witness.executor_pid);
    assert_ne!(witness.executor_pid, witness.caller_pid);
    assert!(
        matches!(
            witness.reply,
            Reply::Unavailable {
                reason: FailureReason::ExecutorLineage,
                ..
            }
        ),
        "executor descendant published ancestor authority at producer: {:?}",
        witness.reply
    );
}
#[test]
fn actual_registered_descendant_resolves_before_executor_stop() {
    let witness = roundtrip(true);
    match witness.reply {
        Reply::Ok {
            principal,
            peer_pid,
            ..
        } => {
            assert_eq!(principal, format!("{CALLER}@attribution-test"));
            assert_eq!(peer_pid, witness.caller_pid);
        }
        other => panic!("registered child below executor failed producer: {other:?}"),
    }
}
