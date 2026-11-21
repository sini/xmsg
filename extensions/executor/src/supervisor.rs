use crate::{
    control::{ControlService, ErrorCode},
    execution::{ExecutionIdentity, ExecutionObservation, ExecutionState, LaunchLease},
    workspace::{
        OwnedWorkspaceIdentity, OwnerWorkspaceBinding, PreparedWorkspace, WorkspaceError,
        WorkspacePlan,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::{
        fd::{AsRawFd, RawFd},
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

const MAX_CONTROL: usize = 16384;
#[derive(Debug, thiserror::Error)]
pub(crate) enum SupervisorError {
    #[error("backend unavailable")]
    BackendUnavailable,
    #[error("execution ownership is unknown")]
    Unknown,
    #[error("execution already has an owner")]
    Busy,
    #[error("supervisor protocol or identity mismatch")]
    Protocol,
    #[error("unsafe owner runtime directory")]
    Directory,
    #[error("supervisor I/O failed")]
    Io(#[from] std::io::Error),
    #[error("journal rejected execution: {0}")]
    Journal(#[from] ErrorCode),
    #[error("workspace refused execution: {0}")]
    Workspace(#[from] WorkspaceError),
}
#[derive(Clone)]
pub(crate) struct OwnerRuntimeConfig {
    root: PathBuf,
    workspace: Arc<OwnerWorkspaceBinding>,
    #[cfg(test)]
    fixture: Option<FixtureProgram>,
    #[cfg(test)]
    barrier: Option<FixtureBarrier>,
}
impl OwnerRuntimeConfig {
    pub(crate) fn new(
        root: PathBuf,
        workspace: Arc<OwnerWorkspaceBinding>,
    ) -> Result<Self, SupervisorError> {
        let root = root.canonicalize()?;
        private_directory(&root)?;
        Ok(Self {
            root,
            workspace,
            #[cfg(test)]
            fixture: None,
            #[cfg(test)]
            barrier: None,
        })
    }
    fn program(&self) -> Result<TrustedProgram, SupervisorError> {
        #[cfg(test)]
        if let Some(p) = &self.fixture {
            return Ok(TrustedProgram {
                executable: p.executable.clone(),
                args: vec![
                    "--ignored".into(),
                    "--exact".into(),
                    "supervisor::tests::fixture_process_entrypoint".into(),
                    "--nocapture".into(),
                ],
                backend: p.backend.clone(),
                python: p.python.clone(),
            });
        }
        Err(SupervisorError::BackendUnavailable)
    }
}
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct FixtureProgram {
    pub(crate) executable: PathBuf,
    pub(crate) backend: PathBuf,
    pub(crate) python: PathBuf,
}
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct FixtureBarrier {
    pub(crate) point: String,
    pub(crate) fd: RawFd,
}
struct TrustedProgram {
    executable: PathBuf,
    args: Vec<String>,
    backend: PathBuf,
    python: PathBuf,
}
fn private_directory(path: &Path) -> Result<(), SupervisorError> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != xmsg::client::current_uid() || m.mode() & 0o777 != 0o700 {
        return Err(SupervisorError::Directory);
    }
    Ok(())
}
fn component(session: &str, generation: u64) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "{}-{generation}",
        hex::encode(&Sha256::digest(session.as_bytes())[..12])
    )
}
struct ExecutionLock {
    file: File,
    directory: PathBuf,
}
impl ExecutionLock {
    fn acquire(root: &Path, session: &str, generation: u64) -> Result<Self, SupervisorError> {
        private_directory(root)?;
        let directory = root.join(component(session, generation));
        match fs::create_dir(&directory) {
            Ok(()) => fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        };
        private_directory(&directory)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.join("execution.lock"))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(SupervisorError::Busy);
        }
        Ok(Self { file, directory })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SupervisorHello {
    pub(crate) identity: ExecutionIdentity,
    pub(crate) event_cursor: u64,
    pub(crate) diagnostic_pid: u32,
    pub(crate) stopped: bool,
    pub(crate) events: Vec<SupervisorEvent>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SupervisorEvent {
    pub(crate) cursor: u64,
    pub(crate) frame: serde_json::Value,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum SupervisorRequest {
    Attach {
        identity: ExecutionIdentity,
    },
    Stop {
        identity: ExecutionIdentity,
    },
    ReadEvents {
        identity: ExecutionIdentity,
        after: u64,
        max: u16,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildManifest {
    identity: ExecutionIdentity,
    socket: PathBuf,
    lock_fd: RawFd,
    startup_fd: RawFd,
    max_wall_ms: u64,
    max_content_bytes: u32,
    workspace: PathBuf,
    backend: PathBuf,
    python: PathBuf,
}
fn frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), SupervisorError> {
    let mut data = serde_json::to_vec(value).map_err(|_| SupervisorError::Protocol)?;
    if data.len() + 1 > MAX_CONTROL {
        return Err(SupervisorError::Protocol);
    }
    data.push(b'\n');
    stream.write_all(&data)?;
    Ok(())
}
fn read_frame<T: serde::de::DeserializeOwned>(stream: &UnixStream) -> Result<T, SupervisorError> {
    let mut data = Vec::new();
    BufReader::new(stream.try_clone()?)
        .take((MAX_CONTROL + 1) as u64)
        .read_until(b'\n', &mut data)?;
    if data.len() > MAX_CONTROL || data.last() != Some(&b'\n') {
        return Err(SupervisorError::Protocol);
    }
    serde_json::from_slice(&data).map_err(|_| SupervisorError::Protocol)
}
fn call(
    socket: &Path,
    expected: &ExecutionIdentity,
    stop: bool,
) -> Result<SupervisorHello, SupervisorError> {
    let meta = fs::symlink_metadata(socket)?;
    if !meta.file_type().is_socket()
        || meta.uid() != xmsg::client::current_uid()
        || meta.mode() & 0o077 != 0
    {
        return Err(SupervisorError::Protocol);
    }
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    if crate::unix::peer(&stream)?.uid != xmsg::client::current_uid() {
        return Err(SupervisorError::Protocol);
    }
    let request = if stop {
        SupervisorRequest::Stop {
            identity: expected.clone(),
        }
    } else {
        SupervisorRequest::Attach {
            identity: expected.clone(),
        }
    };
    frame(&mut stream, &request)?;
    let hello: SupervisorHello = read_frame(&stream)?;
    if hello.identity != *expected {
        return Err(SupervisorError::Protocol);
    }
    Ok(hello)
}
struct OwnedProcessGroup {
    child: Child,
    startup: UnixStream,
}
impl OwnedProcessGroup {
    fn spawn(
        program: TrustedProgram,
        identity: &ExecutionIdentity,
        workspace: &Path,
        lock: &ExecutionLock,
        budget: &crate::protocol::ResourceBudget,
    ) -> Result<Self, SupervisorError> {
        let socket = lock.directory.join("supervisor.sock");
        if fs::symlink_metadata(&socket).is_ok() {
            return Err(SupervisorError::Unknown);
        }
        let (startup, child_startup) = UnixStream::pair()?;
        startup.set_read_timeout(Some(Duration::from_secs(10)))?;
        let manifest = ChildManifest {
            identity: identity.clone(),
            socket,
            lock_fd: lock.file.as_raw_fd(),
            startup_fd: child_startup.as_raw_fd(),
            max_wall_ms: budget.max_wall_ms,
            max_content_bytes: budget.max_content_bytes,
            workspace: workspace.into(),
            backend: program.backend,
            python: program.python,
        };
        let encoded = serde_json::to_string(&manifest).map_err(|_| SupervisorError::Protocol)?;
        let fds = [lock.file.as_raw_fd(), child_startup.as_raw_fd()];
        let mut command = Command::new(program.executable);
        command
            .args(program.args)
            .env_clear()
            .env("LANG", "C")
            .env("XMSG_EXECUTOR_FIXTURE_ROLE", "supervisor")
            .env("XMSG_EXECUTOR_FIXTURE_MANIFEST", encoded)
            .current_dir(workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        unsafe {
            command.pre_exec(move || {
                for fd in fds {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        Ok(Self {
            child: command.spawn()?,
            startup,
        })
    }
    fn abort_owned(&mut self) -> Result<(), SupervisorError> {
        if self.child.try_wait()?.is_some() {
            return Err(SupervisorError::Unknown);
        }
        let pgid = i32::try_from(self.child.id()).map_err(|_| SupervisorError::Unknown)?;
        if unsafe { libc::kill(-pgid, libc::SIGKILL) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        self.child.wait()?;
        Ok(())
    }
}

pub(crate) struct SupervisorController {
    config: OwnerRuntimeConfig,
}
impl SupervisorController {
    pub(crate) fn new(config: OwnerRuntimeConfig) -> Self {
        Self { config }
    }
    pub(crate) fn start_admitted(
        &self,
        service: &ControlService,
        admission_id: i64,
        now: i64,
    ) -> Result<ExecutionObservation, SupervisorError> {
        let program = self.config.program()?;
        let (session, generation) = service
            .journal
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .dispatch_identity(admission_id, now)?;
        let lock = ExecutionLock::acquire(&self.config.root, &session, generation)?;
        let existing = {
            let journal = service.journal.lock().map_err(|_| ErrorCode::Storage)?;
            journal.execution(&session, generation)?
        };
        if let Some(observation) = existing {
            if observation.state != ExecutionState::Reserved {
                if observation.state != ExecutionState::Stopped {
                    service
                        .journal
                        .lock()
                        .map_err(|_| ErrorCode::Storage)?
                        .mark_execution(&observation.identity, false)?;
                }
                return Err(SupervisorError::Unknown);
            }
        }
        let lease = service
            .journal
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .reserve_launch(admission_id, now)?;
        let workspace = self.prepare_workspace(service, &lease, now)?;
        let mut journal = service.journal.lock().map_err(|_| ErrorCode::Storage)?;
        #[cfg(test)]
        self.fixture_pause("before_spawn", 0)?;
        journal.commit_spawn_intent(&lease, now)?;
        let mut group = match OwnedProcessGroup::spawn(
            program,
            &lease.identity,
            workspace.path(),
            &lock,
            &lease.resolved.budget,
        ) {
            Ok(g) => g,
            Err(e) => {
                journal.mark_execution(&lease.identity, false)?;
                return Err(e);
            }
        };
        journal.db.execute("UPDATE executions SET diagnostic_pid=?1 WHERE session_id=?2 AND generation=?3 AND state='spawn_intent'",rusqlite::params![i64::from(group.child.id()),lease.identity.session_id,i64::try_from(lease.identity.generation).map_err(|_|ErrorCode::InvalidConfiguration)?]).map_err(|_|ErrorCode::Storage)?;
        drop(journal);
        let hello: SupervisorHello = match read_frame::<SupervisorHello>(&group.startup) {
            Ok(hello)
                if hello.identity == lease.identity && hello.diagnostic_pid == group.child.id() =>
            {
                hello
            }
            _ => {
                let _ = group.abort_owned();
                service
                    .journal
                    .lock()
                    .map_err(|_| ErrorCode::Storage)?
                    .mark_execution(&lease.identity, false)?;
                return Err(SupervisorError::Unknown);
            }
        };
        #[cfg(test)]
        self.fixture_pause("after_spawn", group.child.id())?;
        service
            .journal
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .mark_running(
                &lease.identity,
                hello.diagnostic_pid,
                hello.event_cursor,
                now,
            )?;
        Ok(ExecutionObservation {
            identity: lease.identity,
            state: ExecutionState::Running,
            cursor: hello.event_cursor,
            diagnostic_pid: Some(group.child.id()),
        })
    }
    fn prepare_workspace(
        &self,
        service: &ControlService,
        lease: &LaunchLease,
        now: i64,
    ) -> Result<PreparedWorkspace, SupervisorError> {
        let stored: Option<String> = service
            .journal
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .db
            .query_row(
                "SELECT workspace FROM executions WHERE session_id=?1 AND generation=?2",
                rusqlite::params![
                    lease.identity.session_id,
                    i64::try_from(lease.identity.generation)
                        .map_err(|_| ErrorCode::InvalidConfiguration)?
                ],
                |r| r.get(0),
            )
            .map_err(|_| ErrorCode::Storage)?;
        if let Some(stored) = stored {
            let identity: OwnedWorkspaceIdentity =
                serde_json::from_str(&stored).map_err(|_| SupervisorError::Protocol)?;
            return Ok(PreparedWorkspace::recover(
                &self.config.workspace,
                identity,
            )?);
        }
        let plan = WorkspacePlan::prepare(
            &self.config.workspace,
            &lease.resolved.workspace,
            &component(&lease.identity.session_id, lease.identity.generation),
            &lease.identity.launch_nonce,
        )?;
        service
            .journal
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .validate_reserved(lease, now)?;
        let intended = plan.destination().to_string_lossy().into_owned();
        service
            .journal
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .db
            .execute(
                "INSERT INTO execution_events VALUES(?1,?2,0,?3)",
                rusqlite::params![
                    lease.identity.session_id,
                    i64::try_from(lease.identity.generation)
                        .map_err(|_| ErrorCode::InvalidConfiguration)?,
                    serde_json::to_string(
                        &serde_json::json!({"kind":"workspace_intent","destination":intended})
                    )
                    .map_err(|_| SupervisorError::Protocol)?
                ],
            )
            .map_err(|_| ErrorCode::Storage)?;
        let workspace = plan.create()?;
        let metadata:Vec<_>=workspace.contexts().iter().map(|c|serde_json::json!({"reference":c.reference,"sha256":c.sha256,"bytes":c.bytes.len()})).collect();
        service.journal.lock().map_err(|_|ErrorCode::Storage)?.db.execute("UPDATE execution_events SET event=?1 WHERE session_id=?2 AND generation=?3 AND cursor=0",rusqlite::params![serde_json::to_string(&serde_json::json!({"kind":"workspace_prepared","contexts":metadata})).map_err(|_|SupervisorError::Protocol)?,lease.identity.session_id,i64::try_from(lease.identity.generation).map_err(|_|ErrorCode::InvalidConfiguration)?]).map_err(|_|ErrorCode::Storage)?;
        service.journal.lock().map_err(|_|ErrorCode::Storage)?.db.execute("UPDATE executions SET workspace=?1 WHERE session_id=?2 AND generation=?3 AND state='reserved'",rusqlite::params![serde_json::to_string(workspace.identity()).map_err(|_|SupervisorError::Protocol)?,lease.identity.session_id,i64::try_from(lease.identity.generation).map_err(|_|ErrorCode::InvalidConfiguration)?]).map_err(|_|ErrorCode::Storage)?;
        Ok(workspace)
    }
    pub(crate) fn reconcile(
        &self,
        service: &ControlService,
        session: &str,
        generation: u64,
        now: i64,
    ) -> Result<ExecutionObservation, SupervisorError> {
        let old = service
            .journal
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .execution(session, generation)?
            .ok_or(ErrorCode::UnknownTarget)?;
        let socket = self
            .config
            .root
            .join(component(session, generation))
            .join("supervisor.sock");
        let administrative_stop = service
            .journal
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .administrative_stop_needed(&old.identity)?;
        if administrative_stop {
            return match call(&socket, &old.identity, true) {
                Ok(hello) if hello.stopped => {
                    service
                        .journal
                        .lock()
                        .map_err(|_| ErrorCode::Storage)?
                        .mark_execution(&old.identity, true)?;
                    Ok(ExecutionObservation {
                        identity: old.identity,
                        state: ExecutionState::Stopped,
                        cursor: hello.event_cursor,
                        diagnostic_pid: Some(hello.diagnostic_pid),
                    })
                }
                _ => {
                    service
                        .journal
                        .lock()
                        .map_err(|_| ErrorCode::Storage)?
                        .mark_execution(&old.identity, false)?;
                    Ok(ExecutionObservation {
                        state: ExecutionState::Unknown,
                        ..old
                    })
                }
            };
        }
        match call(&socket, &old.identity, false) {
            Ok(hello) => {
                service
                    .journal
                    .lock()
                    .map_err(|_| ErrorCode::Storage)?
                    .mark_running(&old.identity, hello.diagnostic_pid, hello.event_cursor, now)?;
                Ok(ExecutionObservation {
                    identity: old.identity,
                    state: ExecutionState::Running,
                    cursor: hello.event_cursor,
                    diagnostic_pid: Some(hello.diagnostic_pid),
                })
            }
            Err(_) => {
                service
                    .journal
                    .lock()
                    .map_err(|_| ErrorCode::Storage)?
                    .mark_execution(&old.identity, false)?;
                Ok(ExecutionObservation {
                    state: ExecutionState::Unknown,
                    ..old
                })
            }
        }
    }
    pub(crate) fn stop_owned(
        &self,
        service: &ControlService,
        admission_id: i64,
        now: i64,
    ) -> Result<ExecutionObservation, SupervisorError> {
        let identity = service
            .journal
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .authorize_stop(admission_id, now)?;
        let socket = self
            .config
            .root
            .join(component(&identity.session_id, identity.generation))
            .join("supervisor.sock");
        match call(&socket, &identity, true) {
            Ok(hello) if hello.stopped => {
                service
                    .journal
                    .lock()
                    .map_err(|_| ErrorCode::Storage)?
                    .mark_execution(&identity, true)?;
                Ok(ExecutionObservation {
                    identity,
                    state: ExecutionState::Stopped,
                    cursor: hello.event_cursor,
                    diagnostic_pid: Some(hello.diagnostic_pid),
                })
            }
            _ => {
                service
                    .journal
                    .lock()
                    .map_err(|_| ErrorCode::Storage)?
                    .mark_execution(&identity, false)?;
                Ok(ExecutionObservation {
                    identity,
                    state: ExecutionState::Unknown,
                    cursor: 0,
                    diagnostic_pid: None,
                })
            }
        }
    }
    #[cfg(test)]
    fn fixture_pause(&self, point: &str, pid: u32) -> Result<(), SupervisorError> {
        use std::os::fd::FromRawFd;
        if let Some(b) = &self.config.barrier {
            if b.point == point {
                let fd = unsafe { libc::dup(b.fd) };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
                stream.set_read_timeout(Some(Duration::from_secs(30)))?;
                frame(&mut stream, &serde_json::json!({"point":point,"pid":pid}))?;
                let mut byte = [0];
                stream.read_exact(&mut byte)?;
            }
        }
        Ok(())
    }
    pub(crate) fn cleanup_stopped(
        &self,
        service: &ControlService,
        session: &str,
        generation: u64,
    ) -> Result<(), SupervisorError> {
        let journal = service.journal.lock().map_err(|_| ErrorCode::Storage)?;
        let observation = journal
            .execution(session, generation)?
            .ok_or(ErrorCode::UnknownTarget)?;
        if observation.state != ExecutionState::Stopped {
            return Err(SupervisorError::Unknown);
        }
        let data: String = journal
            .db
            .query_row(
                "SELECT workspace FROM executions WHERE session_id=?1 AND generation=?2",
                rusqlite::params![
                    session,
                    i64::try_from(generation).map_err(|_| ErrorCode::InvalidConfiguration)?
                ],
                |r| r.get(0),
            )
            .map_err(|_| ErrorCode::Storage)?;
        drop(journal);
        PreparedWorkspace::recover(
            &self.config.workspace,
            serde_json::from_str(&data).map_err(|_| SupervisorError::Protocol)?,
        )?
        .cleanup()?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "supervisor_tests.rs"]
mod tests;

fn run_supervisor_process(manifest: ChildManifest) -> Result<(), SupervisorError> {
    use std::os::fd::FromRawFd;
    let _lock = unsafe { File::from_raw_fd(manifest.lock_fd) };
    let mut startup = unsafe { UnixStream::from_raw_fd(manifest.startup_fd) };
    private_directory(manifest.socket.parent().ok_or(SupervisorError::Directory)?)?;
    let listener = UnixListener::bind(&manifest.socket)?;
    fs::set_permissions(&manifest.socket, fs::Permissions::from_mode(0o600))?;
    let mut backend = Command::new(&manifest.python)
        .arg(&manifest.backend)
        .env_clear()
        .env("LANG", "C")
        .current_dir(&manifest.workspace)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut input = backend.stdin.take().ok_or(SupervisorError::Protocol)?;
    let output = backend.stdout.take().ok_or(SupervisorError::Protocol)?;
    let mut reader = crate::framing::FrameReader::new(BufReader::new(output));
    let mut events = Vec::<SupervisorEvent>::new();
    let mut event_bytes = 0usize;
    let mut log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(
            manifest
                .socket
                .parent()
                .ok_or(SupervisorError::Directory)?
                .join("events.jsonl"),
        )?;
    for (id, method, params) in [
        (
            1,
            "initialize",
            serde_json::json!({"protocolVersion":1,"clientCapabilities":{}}),
        ),
        (
            2,
            "session/new",
            serde_json::json!({"cwd":manifest.workspace,"mcpServers":[]}),
        ),
    ] {
        let request = crate::framing::Frame::Request(crate::framing::Request {
            jsonrpc: "2.0".into(),
            id: crate::framing::RequestId::Number(id),
            method: method.into(),
            params: Some(params),
        });
        crate::framing::write_frame(&mut input, &request).map_err(|_| SupervisorError::Protocol)?;
        match reader.next_frame().map_err(|_| SupervisorError::Protocol)? {
            Some(crate::framing::Frame::Success(response))
                if response.id == crate::framing::RequestId::Number(id) =>
            {
                let event = SupervisorEvent {
                    cursor: events.len() as u64 + 1,
                    frame: serde_json::to_value(response).map_err(|_| SupervisorError::Protocol)?,
                };
                let raw = serde_json::to_vec(&event).map_err(|_| SupervisorError::Protocol)?;
                event_bytes = event_bytes
                    .checked_add(raw.len() + 1)
                    .ok_or(SupervisorError::Protocol)?;
                if event_bytes > manifest.max_content_bytes as usize {
                    return Err(SupervisorError::Protocol);
                }
                log.write_all(&raw)?;
                log.write_all(b"\n")?;
                log.sync_data()?;
                events.push(event);
            }
            _ => {
                let _ = backend.kill();
                let _ = backend.wait();
                return Err(SupervisorError::Protocol);
            }
        }
    }
    let mut hello = SupervisorHello {
        identity: manifest.identity.clone(),
        event_cursor: 2,
        diagnostic_pid: std::process::id(),
        stopped: false,
        events: Vec::new(),
    };
    let _ = frame(&mut startup, &hello);
    drop(startup);
    listener.set_nonblocking(true)?;
    let expires = std::time::Instant::now()
        .checked_add(Duration::from_millis(manifest.max_wall_ms))
        .ok_or(SupervisorError::Protocol)?;
    loop {
        let remaining = expires.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            if backend.try_wait()?.is_none() {
                backend.kill()?;
            }
            backend.wait()?;
            return Ok(());
        }
        let mut poll = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let wait = i32::try_from(remaining.as_millis().min(i32::MAX as u128)).unwrap_or(i32::MAX);
        let ready = unsafe { libc::poll(&mut poll, 1, wait) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(std::io::Error::last_os_error().into());
        }
        if ready == 0 {
            continue;
        }
        let (mut stream, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        };
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        if crate::unix::peer(&stream)?.uid != xmsg::client::current_uid() {
            continue;
        }
        let request: SupervisorRequest = match read_frame(&stream) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let expected = match &request {
            SupervisorRequest::Attach { identity }
            | SupervisorRequest::Stop { identity }
            | SupervisorRequest::ReadEvents { identity, .. } => identity,
        };
        if expected != &manifest.identity {
            continue;
        }
        if let SupervisorRequest::ReadEvents { after, max, .. } = request {
            if max == 0 || max > 32 || after > hello.event_cursor {
                continue;
            }
            let mut response = hello.clone();
            response.events = events
                .iter()
                .filter(|e| e.cursor > after)
                .take(usize::from(max))
                .cloned()
                .collect();
            frame(&mut stream, &response)?;
            continue;
        }
        if matches!(request, SupervisorRequest::Stop { .. }) {
            // Only the held child is signalled; stored diagnostic PIDs are never ownership.
            if backend.try_wait()?.is_none() {
                backend.kill()?;
            }
            backend.wait()?;
            hello.event_cursor += 1;
            hello.stopped = true;
            frame(&mut stream, &hello)?;
            return Ok(());
        }
        frame(&mut stream, &hello)?;
    }
}
