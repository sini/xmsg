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
#[cfg(target_os = "linux")]
#[derive(Debug, Serialize, Deserialize)]
struct OrphanWitness {
    ancestor_pid: u32,
    intermediate_pid: Option<u32>,
    executor_pid: u32,
    spawning_shell_pid: u32,
    caller_pid: u32,
    reaper_pid: u32,
    reply: Reply,
}
#[cfg(target_os = "linux")]
#[derive(Serialize, Deserialize)]
struct SpawnedGrandchild {
    shell_pid: u32,
    caller_pid: u32,
}
#[cfg(target_os = "linux")]
#[derive(Serialize, Deserialize)]
struct Adoption {
    spawning_shell_pid: u32,
    reaper_pid: u32,
}

#[cfg(target_os = "linux")]
fn orphan_spawn(role: &str, root: &Path, new_group: bool, extra: Option<i32>) -> OwnedProcess {
    let (parent, child) = UnixStream::pair().unwrap();
    let descriptor = child.as_raw_fd();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            "caller_attribution::lineage_tests::orphan_process",
            "--nocapture",
        ])
        .env("XMSG_ATTRIBUTION_FIXTURE_ROLE", role)
        .env("XMSG_ATTRIBUTION_FIXTURE_ROOT", root)
        .env("XMSG_ATTRIBUTION_FIXTURE_FD", descriptor.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if let Some(extra) = extra {
        command.env("XMSG_ATTRIBUTION_ORPHAN_FD", extra.to_string());
    } else {
        command.env_remove("XMSG_ATTRIBUTION_ORPHAN_FD");
    }
    if new_group {
        command.process_group(0);
    }
    unsafe {
        command.pre_exec(move || {
            for fd in std::iter::once(descriptor).chain(extra) {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let process = command.spawn().unwrap();
    drop(child);
    OwnedProcess {
        child: process,
        control: parent,
        group: new_group,
    }
}
#[cfg(target_os = "linux")]
fn set_subreaper() {
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    let mut observed: libc::c_int = 0;
    assert_eq!(
        unsafe {
            libc::prctl(
                libc::PR_GET_CHILD_SUBREAPER,
                &mut observed as *mut libc::c_int,
                0,
                0,
                0,
            )
        },
        0
    );
    assert_eq!(observed, 1);
}
#[cfg(target_os = "linux")]
fn reap_adopted(pid: u32, deadline: Instant) {
    let pid = libc::pid_t::try_from(pid).unwrap();
    let mut status = 0;
    loop {
        assert!(
            Instant::now() < deadline,
            "owned adopted child did not exit before fixture deadline"
        );
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid {
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
            return;
        }
        assert_eq!(
            result, 0,
            "captured orphan was not adopted by the expected fixture reaper"
        );
        std::thread::yield_now();
    }
}
#[cfg(target_os = "linux")]
fn orphan_query(root: &Path, original: &UnixStream) -> Reply {
    let deadline = Instant::now() + AUTHORITY_BUDGET;
    let stream = wire::connect(&root.join("query.sock"), deadline).unwrap();
    let mut digest = Sha256::new();
    digest.update(wire::CONTEXT_DOMAIN);
    digest.update(wire::context_bytes(&None).unwrap());
    let query = wire::Query {
        v: wire::VERSION,
        runtime_epoch: "e".repeat(32),
        call_nonce: 1,
        input_digest: "f".repeat(64),
        context: None,
        context_digest: hex::encode(digest.finalize()),
    };
    wire::send_query(&stream, original.as_fd(), &query, deadline).unwrap();
    wire::receive_reply(&stream, deadline).unwrap()
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "owned orphan/reaper qualification-observation process entrypoint"]
fn orphan_process() {
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
    if matches!(
        role.as_str(),
        "session-init" | "session-subreaper" | "session-middle" | "middle"
    ) {
        let is_middle = role == "middle";
        let is_reaper = is_middle || role == "session-subreaper";
        if !is_middle {
            register_self(&root, ANCESTOR);
        }
        if is_reaper {
            set_subreaper();
        }
        let child_role = if role == "session-middle" {
            "middle"
        } else {
            "executor"
        };
        let mut descendant = orphan_spawn(child_role, &root, false, None);
        assert_eq!(read_byte(&mut descendant.control, deadline).unwrap(), b'L');
        send_byte(&mut control, b'L', deadline).unwrap();
        assert_eq!(read_byte(&mut control, deadline).unwrap(), b'G');
        send_byte(&mut descendant.control, b'G', deadline).unwrap();
        let mut witness: OrphanWitness = receive_value(&mut descendant.control, deadline);
        descendant.finish(deadline);
        if is_reaper {
            assert_eq!(
                witness.reaper_pid,
                std::process::id(),
                "grandchild did not move to the explicitly configured fixture reaper"
            );
            reap_adopted(witness.caller_pid, deadline);
        }
        if is_middle {
            witness.intermediate_pid = Some(std::process::id());
        } else {
            witness.ancestor_pid = std::process::id();
        }
        send_value(&mut control, &witness, deadline);
        assert_eq!(read_byte(&mut control, deadline).unwrap(), b'X');
        return;
    }
    if role == "shell" {
        let extra: i32 = std::env::var("XMSG_ATTRIBUTION_ORPHAN_FD")
            .unwrap()
            .parse()
            .unwrap();
        let grandchild = orphan_spawn("grandchild", &root, false, Some(extra));
        let spawned = SpawnedGrandchild {
            shell_pid: std::process::id(),
            caller_pid: grandchild.child.id(),
        };
        send_value(&mut control, &spawned, deadline);
        assert_eq!(read_byte(&mut control, deadline).unwrap(), b'X');
        std::mem::forget(grandchild);
        return;
    }
    if role == "grandchild" {
        let extra: i32 = std::env::var("XMSG_ATTRIBUTION_ORPHAN_FD")
            .unwrap()
            .parse()
            .unwrap();
        let mut channel = unsafe { UnixStream::from_raw_fd(extra) };
        let flags = unsafe { libc::fcntl(extra, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(extra, libc::F_SETFD, flags | libc::FD_CLOEXEC) },
            0
        );
        let shell = unsafe { libc::getppid() };
        send_byte(&mut channel, b'B', deadline).unwrap();
        let reaper = loop {
            let current = unsafe { libc::getppid() };
            if current != shell {
                break current;
            }
            assert!(
                Instant::now() < deadline,
                "grandchild never became orphan before its call"
            );
            std::thread::yield_now();
        };
        assert!(reaper > 0);
        send_value(
            &mut channel,
            &Adoption {
                spawning_shell_pid: shell as u32,
                reaper_pid: reaper as u32,
            },
            deadline,
        );
        let mut original = UnixStream::connect(root.join("life.sock")).unwrap();
        send_byte(&mut original, b'R', deadline).unwrap();
        send_byte(&mut channel, b'R', deadline).unwrap();
        assert_eq!(read_byte(&mut original, deadline).unwrap(), b'D');
        send_byte(&mut channel, b'Q', deadline).unwrap();
        return;
    }
    assert_eq!(role, "executor");
    let listener = UnixListener::bind(root.join("life.sock")).unwrap();
    std::fs::set_permissions(
        root.join("life.sock"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    listener.set_nonblocking(true).unwrap();
    send_byte(&mut control, b'L', deadline).unwrap();
    assert_eq!(read_byte(&mut control, deadline).unwrap(), b'G');
    let (mut grandchild_channel, grandchild_end) = UnixStream::pair().unwrap();
    let mut shell = orphan_spawn("shell", &root, false, Some(grandchild_end.as_raw_fd()));
    drop(grandchild_end);
    let spawned: SpawnedGrandchild = receive_value(&mut shell.control, deadline);
    assert_eq!(read_byte(&mut grandchild_channel, deadline).unwrap(), b'B');
    send_byte(&mut shell.control, b'X', deadline).unwrap();
    shell.finish(deadline);
    let adoption: Adoption = receive_value(&mut grandchild_channel, deadline);
    assert_eq!(adoption.spawning_shell_pid, spawned.shell_pid);
    assert_ne!(
        adoption.reaper_pid, spawned.shell_pid,
        "call preceded kernel reparenting barrier"
    );
    assert_eq!(read_byte(&mut grandchild_channel, deadline).unwrap(), b'R');
    let (mut original, _) = listener.accept().unwrap();
    assert_eq!(read_byte(&mut original, deadline).unwrap(), b'R');
    let reply = orphan_query(&root, &original);
    send_byte(&mut original, b'D', deadline).unwrap();
    assert_eq!(read_byte(&mut grandchild_channel, deadline).unwrap(), b'Q');
    send_value(
        &mut control,
        &OrphanWitness {
            ancestor_pid: 0,
            intermediate_pid: None,
            executor_pid: std::process::id(),
            spawning_shell_pid: spawned.shell_pid,
            caller_pid: spawned.caller_pid,
            reaper_pid: adoption.reaper_pid,
            reply,
        },
        deadline,
    );
    assert_eq!(read_byte(&mut control, deadline).unwrap(), b'X');
}

#[cfg(target_os = "linux")]
fn orphan_roundtrip(role: &str) -> OrphanWitness {
    let root = tempfile::Builder::new()
        .prefix("xb7-orphan-")
        .tempdir_in(Path::new("/tmp").canonicalize().unwrap())
        .unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let deadline = Instant::now() + FIXTURE_LIMIT;
    let mut ancestor = orphan_spawn(role, root.path(), true, None);
    assert_eq!(read_byte(&mut ancestor.control, deadline).unwrap(), b'L');
    let mut daemon = process("daemon", root.path(), true, true);
    assert_eq!(read_byte(&mut daemon.control, deadline).unwrap(), b'R');
    send_byte(&mut ancestor.control, b'G', deadline).unwrap();
    let witness = receive_value(&mut ancestor.control, deadline);
    ancestor.finish(deadline);
    daemon.finish(deadline);
    witness
}
#[cfg(target_os = "linux")]
fn record_residual(witness: &OrphanWitness, kind: &str) {
    eprintln!("qualification observation only, not a security PASS or enablement: kind={kind} S={} R={:?} E={} shell={} g={} reaper={} init={}",witness.ancestor_pid,witness.intermediate_pid,witness.executor_pid,witness.spawning_shell_pid,witness.caller_pid,witness.reaper_pid,witness.reaper_pid==1);
}
#[cfg(target_os = "linux")]
#[test]
fn orphan_unregistered_reaper_control_constructs_no_principal_observation() {
    let witness = orphan_roundtrip("session-init");
    record_residual(&witness, "unregistered-current-reaper");
    assert_ne!(witness.reaper_pid, witness.spawning_shell_pid);
    assert_ne!(witness.reaper_pid, witness.ancestor_pid);
    assert!(
        matches!(witness.reply, Reply::Unavailable { .. }),
        "unregistered reaper path constructed an ancestor principal: {:?}",
        witness.reply
    );
}
#[cfg(target_os = "linux")]
#[test]
fn orphan_registered_subreaper_residual_is_not_enablement() {
    let witness = orphan_roundtrip("session-subreaper");
    record_residual(&witness, "registered-S-subreaper-residual");
    assert_eq!(witness.reaper_pid, witness.ancestor_pid);
    assert_ne!(witness.reaper_pid, witness.spawning_shell_pid);
    match witness.reply {
        Reply::Ok { principal, .. } => {
            assert_eq!(principal, format!("{ANCESTOR}@attribution-test"))
        }
        other => panic!("registered reaper residual not observed: {other:?}"),
    }
}
#[cfg(target_os = "linux")]
#[test]
fn orphan_unregistered_intermediate_subreaper_is_walked_residual_not_enablement() {
    let witness = orphan_roundtrip("session-middle");
    record_residual(&witness, "unregistered-R-before-registered-S-residual");
    assert_eq!(Some(witness.reaper_pid), witness.intermediate_pid);
    assert_ne!(witness.reaper_pid, witness.spawning_shell_pid);
    match witness.reply {
        Reply::Ok { principal, .. } => {
            assert_eq!(principal, format!("{ANCESTOR}@attribution-test"))
        }
        other => panic!("walk did not continue through unregistered fixture reaper: {other:?}"),
    }
}
