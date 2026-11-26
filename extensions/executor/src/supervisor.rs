use crate::{
    control::{ControlService, ErrorCode},
    execution::{ExecutionIdentity, ExecutionObservation, ExecutionState, LaunchLease},
    workspace::{
        OwnedWorkspaceIdentity, OwnerWorkspaceBinding, PreparedWorkspace, WorkspaceError,
        WorkspacePlan,
    },
};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::os::unix::{fs::PermissionsExt, net::UnixListener};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::{
        fd::{AsRawFd, RawFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

const MAX_CONTROL: usize = crate::framing::MAX_FRAME_BYTES;
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
    #[error("socket path {bytes} bytes exceeds {platform} capacity {capacity} including its terminating NUL; use a shorter runtime_root with OwnerRuntimeConfig::new or OwnerRuntimeConfig::for_user")]
    SocketPath {
        bytes: usize,
        capacity: usize,
        platform: &'static str,
    },
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
    namespace_identity: Option<Vec<u8>>,
    private_parent: Option<PathBuf>,
    #[cfg(test)]
    pub(crate) fixture: Option<FixtureProgram>,
    #[cfg(test)]
    barrier: Option<FixtureBarrier>,
}
impl OwnerRuntimeConfig {
    pub(crate) fn new(
        root: PathBuf,
        workspace: Arc<OwnerWorkspaceBinding>,
    ) -> Result<Self, SupervisorError> {
        private_directory(&root)?;
        let root = root.canonicalize()?;
        Ok(Self {
            root,
            workspace,
            namespace_identity: None,
            private_parent: None,
            #[cfg(test)]
            fixture: None,
            #[cfg(test)]
            barrier: None,
        })
    }
    pub(crate) fn for_user(
        journal: &Path,
        workspace: Arc<OwnerWorkspaceBinding>,
    ) -> Result<Self, SupervisorError> {
        use sha2::{Digest, Sha256};
        let journal = journal.canonicalize()?;
        let metadata = fs::symlink_metadata(&journal)?;
        let identity = serde_json::to_vec(&(
            journal.as_os_str().as_bytes(),
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
        ))
        .map_err(|_| SupervisorError::Directory)?;
        let parent = user_runtime_parent()?;
        let private_parent =
            if cfg!(target_os = "linux") && std::env::var_os("XDG_RUNTIME_DIR").is_some() {
                Some(parent.clone())
            } else {
                None
            };
        let root = parent.join(format!(
            "xe-{}-{}",
            xmsg::client::current_uid(),
            hex::encode(&Sha256::digest(&identity)[..6])
        ));
        Ok(Self {
            root,
            workspace,
            namespace_identity: Some(identity),
            private_parent,
            #[cfg(test)]
            fixture: None,
            #[cfg(test)]
            barrier: None,
        })
    }
    fn ensure_root(&self) -> Result<(), SupervisorError> {
        let Some(identity) = &self.namespace_identity else {
            return private_directory(&self.root);
        };
        if let Some(parent) = &self.private_parent {
            private_directory(parent)?;
        }
        let created = match fs::DirBuilder::new().mode(0o700).create(&self.root) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(e) => return Err(e.into()),
        };
        private_directory(&self.root)?;
        let marker = self.root.join("journal.identity");
        if created {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&marker)?;
            file.write_all(identity)?;
            file.sync_all()?;
        }
        let metadata = fs::symlink_metadata(&marker)?;
        if !metadata.is_file()
            || metadata.uid() != xmsg::client::current_uid()
            || metadata.mode() & 0o7777 != 0o600
            || fs::read(marker)? != *identity
        {
            return Err(SupervisorError::Directory);
        }
        Ok(())
    }
    fn program(
        &self,
        service: &ControlService,
        admission: i64,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
    ) -> Result<TrustedProgram, SupervisorError> {
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
                backend: if let Some(configuration) = &p.acp_configuration {
                    let policy = service
                        .journal
                        .lock()
                        .map_err(|_| ErrorCode::Storage)?
                        .runtime_policy
                        .clone()
                        .ok_or(SupervisorError::BackendUnavailable)?;
                    crate::runtime_process::Backend::Acp {
                        configuration: Box::new(configuration.clone()),
                        admission_id: admission,
                        load_native: None,
                        fixture_records: Some(policy.fixture_records()),
                    }
                } else {
                    crate::runtime_process::Backend::Fixture {
                        script: p.backend.clone(),
                        python: p.python.clone(),
                    }
                },
                #[cfg(test)]
                accept_probe: p.accept_probe.clone(),
                environment: p
                    .acp_configuration
                    .as_ref()
                    .map(|c| c.launch_environment.snapshot())
                    .transpose()?,
            });
        }
        let journal = service.journal.lock().map_err(|_| ErrorCode::Storage)?;
        let policy = journal
            .runtime_policy
            .clone()
            .ok_or(SupervisorError::BackendUnavailable)?;
        drop(journal);
        let environment = policy.configuration.launch_environment.snapshot()?;
        let mut journal = service.journal.lock().map_err(|_| ErrorCode::Storage)?;
        let now = clock()?;
        let tx = journal
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| ErrorCode::Storage)?;
        let selected = crate::execution::revalidate_dispatch(&tx, admission, now)?;
        let configuration = crate::journal::config(&tx)?;
        policy.require(
            &selected,
            configuration.revision,
            now,
            crate::journal::runtime_disabled(&tx)?,
        )?;
        if policy.configuration.paths.runtime_root.canonicalize()? != self.root {
            return Err(SupervisorError::Directory);
        }
        Ok(TrustedProgram {
            executable: std::env::current_exe()?,
            args: vec!["runtime".into()],
            backend: crate::runtime_process::Backend::Acp {
                configuration: Box::new(policy.configuration.clone()),
                admission_id: admission,
                load_native: None,
                #[cfg(test)]
                fixture_records: Some(policy.fixture_records()),
            },
            #[cfg(test)]
            accept_probe: None,
            environment: Some(environment),
        })
    }
}
fn user_runtime_parent() -> Result<PathBuf, SupervisorError> {
    #[cfg(target_os = "linux")]
    if let Some(root) = std::env::var_os("XDG_RUNTIME_DIR") {
        return checked_xdg_parent(Path::new(&root));
    }
    Ok(Path::new("/tmp").canonicalize()?)
}
#[cfg(any(target_os = "linux", test))]
fn checked_xdg_parent(root: &Path) -> Result<PathBuf, SupervisorError> {
    if !root.is_absolute() {
        return Err(SupervisorError::Directory);
    }
    private_directory(root)?;
    Ok(root.canonicalize()?)
}
fn validate_socket_path(socket: &Path) -> Result<(), SupervisorError> {
    let capacity = unsafe { std::mem::zeroed::<libc::sockaddr_un>() }
        .sun_path
        .len();
    let bytes = socket.as_os_str().as_bytes();
    if bytes.contains(&0) || bytes.len() >= capacity {
        return Err(SupervisorError::SocketPath {
            bytes: bytes.len(),
            capacity,
            platform: if cfg!(target_os = "macos") {
                "macOS"
            } else {
                std::env::consts::OS
            },
        });
    }
    Ok(())
}
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct FixtureProgram {
    pub(crate) executable: PathBuf,
    pub(crate) backend: PathBuf,
    pub(crate) python: PathBuf,
    pub(crate) accept_probe: Option<PathBuf>,
    pub(crate) acp_configuration: Option<crate::runtime_config::RuntimeConfig>,
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
    backend: crate::runtime_process::Backend,
    environment: Option<Vec<(std::ffi::OsString, std::ffi::OsString)>>,
    #[cfg(test)]
    accept_probe: Option<PathBuf>,
}
fn private_directory(path: &Path) -> Result<(), SupervisorError> {
    let mut prefix = PathBuf::new();
    for part in path.components() {
        prefix.push(part.as_os_str());
        if fs::symlink_metadata(&prefix)?.file_type().is_symlink() {
            return Err(SupervisorError::Directory);
        }
    }
    let m = fs::symlink_metadata(path)?;
    if !private_directory_metadata(m.is_dir(), m.uid(), m.mode(), xmsg::client::current_uid()) {
        return Err(SupervisorError::Directory);
    }
    Ok(())
}
fn private_directory_metadata(is_dir: bool, uid: u32, mode: u32, expected_uid: u32) -> bool {
    is_dir && uid == expected_uid && mode & 0o7777 == 0o700
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
        match fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {}
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
    pub(crate) running: bool,
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
pub(crate) enum SupervisorRequest {
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
    SubmitNative {
        identity: ExecutionIdentity,
        admission_id: i64,
        transport_epoch: String,
    },
    SubmitDecision {
        identity: ExecutionIdentity,
        approval_id: String,
        transport_epoch: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChildManifest {
    pub(crate) identity: ExecutionIdentity,
    pub(crate) socket: PathBuf,
    pub(crate) lock_fd: RawFd,
    pub(crate) startup_fd: RawFd,
    #[cfg(test)]
    accept_probe: Option<PathBuf>,
    pub(crate) max_wall_ms: u64,
    pub(crate) max_content_bytes: u32,
    pub(crate) workspace: PathBuf,
    pub(crate) backend: crate::runtime_process::Backend,
}
pub(crate) struct DeadlineIo<'a, T: AsRawFd> {
    inner: &'a mut T,
    expires: std::time::Instant,
    original_flags: i32,
    #[cfg(test)]
    before_poll: Option<Box<dyn FnOnce() + Send>>,
}
impl<'a, T: AsRawFd> DeadlineIo<'a, T> {
    pub(crate) fn set_deadline(&mut self, expires: std::time::Instant) {
        self.expires = expires;
    }
    pub(crate) fn limit_to(&mut self, expires: std::time::Instant) {
        self.expires = self.expires.min(expires);
    }
    pub(crate) fn new(inner: &'a mut T, expires: std::time::Instant) -> std::io::Result<Self> {
        let fd = inner.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            inner,
            expires,
            original_flags: flags,
            #[cfg(test)]
            before_poll: None,
        })
    }
    #[cfg(test)]
    pub(crate) fn fixture_before_poll(&mut self, callback: impl FnOnce() + Send + 'static) {
        self.before_poll = Some(Box::new(callback));
    }
    fn ready(&mut self, event: i16) -> std::io::Result<()> {
        #[cfg(test)]
        if let Some(callback) = self.before_poll.take() {
            callback();
        }
        loop {
            let left = self
                .expires
                .saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "execution deadline",
                ));
            }
            let wait = i32::try_from(left.as_millis().saturating_add(1).min(i32::MAX as u128))
                .unwrap_or(i32::MAX);
            let mut p = libc::pollfd {
                fd: self.inner.as_raw_fd(),
                events: event,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut p, 1, wait) };
            if n > 0 {
                return Ok(());
            }
            if n < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
}
impl<T: AsRawFd> Drop for DeadlineIo<'_, T> {
    fn drop(&mut self) {
        unsafe {
            libc::fcntl(self.inner.as_raw_fd(), libc::F_SETFL, self.original_flags);
        }
    }
}
impl<T: Read + AsRawFd> Read for DeadlineIo<'_, T> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.ready(libc::POLLIN)?;
            match self.inner.read(bytes) {
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                other => return other,
            }
        }
    }
}
impl<T: Write + AsRawFd> Write for DeadlineIo<'_, T> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        loop {
            self.ready(libc::POLLOUT)?;
            match self.inner.write(bytes) {
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                other => return other,
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
pub(crate) fn frame_until<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    expires: std::time::Instant,
) -> Result<(), SupervisorError> {
    let mut data = serde_json::to_vec(value).map_err(|_| SupervisorError::Protocol)?;
    if data.len() + 1 > MAX_CONTROL {
        return Err(SupervisorError::Protocol);
    }
    data.push(b'\n');
    DeadlineIo::new(stream, expires)?.write_all(&data)?;
    Ok(())
}
fn frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), SupervisorError> {
    frame_until(
        stream,
        value,
        std::time::Instant::now() + Duration::from_secs(3),
    )
}
pub(crate) fn read_frame_until<T: serde::de::DeserializeOwned>(
    stream: &UnixStream,
    expires: std::time::Instant,
) -> Result<T, SupervisorError> {
    let mut copy =
        xmsg::client::caller_attribution::with_fd_inheritance_gate(|| stream.try_clone())?;
    let mut data = Vec::new();
    BufReader::new(DeadlineIo::new(&mut copy, expires)?)
        .take((MAX_CONTROL + 1) as u64)
        .read_until(b'\n', &mut data)?;
    if data.len() > MAX_CONTROL || data.last() != Some(&b'\n') {
        return Err(SupervisorError::Protocol);
    }
    serde_json::from_slice(&data).map_err(|_| SupervisorError::Protocol)
}
fn read_frame<T: serde::de::DeserializeOwned>(stream: &UnixStream) -> Result<T, SupervisorError> {
    read_frame_until(stream, std::time::Instant::now() + Duration::from_secs(3))
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
    let expires = std::time::Instant::now() + Duration::from_secs(3);
    let mut stream = xmsg::client::caller_attribution::connect(socket, expires)
        .map_err(|_| SupervisorError::Unknown)?;
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
    frame_until(&mut stream, &request, expires)?;
    let hello: SupervisorHello = read_frame_until(&stream, expires)?;
    if hello.identity != *expected {
        return Err(SupervisorError::Protocol);
    }
    Ok(hello)
}

pub(crate) fn attach_existing(
    root: &Path,
    identity: &ExecutionIdentity,
) -> Result<SupervisorHello, SupervisorError> {
    call(
        &root
            .join(component(&identity.session_id, identity.generation))
            .join("supervisor.sock"),
        identity,
        false,
    )
}
struct OwnedProcessGroup {
    child: Child,
    startup: UnixStream,
    bootstrap: Option<ChildManifest>,
}

fn negative_owned_group(group: i32) -> Result<i32, SupervisorError> {
    if group <= 1 {
        return Err(SupervisorError::Unknown);
    }
    group.checked_neg().ok_or(SupervisorError::Unknown)
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
        let (startup, child_startup) =
            xmsg::client::caller_attribution::with_fd_inheritance_gate(UnixStream::pair)?;
        startup.set_read_timeout(Some(Duration::from_secs(10)))?;
        let manifest = ChildManifest {
            identity: identity.clone(),
            socket,
            lock_fd: lock.file.as_raw_fd(),
            startup_fd: child_startup.as_raw_fd(),
            #[cfg(test)]
            accept_probe: program.accept_probe,
            max_wall_ms: budget.max_wall_ms,
            max_content_bytes: budget.max_content_bytes,
            workspace: workspace.into(),
            backend: program.backend,
        };
        let encoded = serde_json::to_string(&manifest).map_err(|_| SupervisorError::Protocol)?;
        if encoded.len() + 1 > MAX_CONTROL {
            return Err(SupervisorError::Protocol);
        }
        let fds = [lock.file.as_raw_fd(), child_startup.as_raw_fd()];
        let mut command = Command::new(program.executable);
        command
            .args(program.args)
            .env_clear()
            .env("LANG", "C")
            .current_dir(workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        if let Some(environment) = program.environment {
            command.env_remove("LANG").envs(environment);
        }
        #[cfg(test)]
        let fixture_entry = command.get_args().any(|arg| arg == "--ignored");
        #[cfg(not(test))]
        let fixture_entry = false;
        #[cfg(test)]
        if fixture_entry {
            crate::proof_processes::configure(&mut command);
            command
                .stderr(Stdio::inherit())
                .env("XMSG_EXECUTOR_FIXTURE_ROLE", "supervisor")
                .env("XMSG_EXECUTOR_FIXTURE_MANIFEST", &encoded);
        }
        if !fixture_entry
            && matches!(
                manifest.backend,
                crate::runtime_process::Backend::Acp { .. }
            )
        {
            command
                .arg("--manifest-fd")
                .arg(child_startup.as_raw_fd().to_string())
                .arg("--max-wall-ms")
                .arg(manifest.max_wall_ms.to_string());
        }
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
        let child = xmsg::client::caller_attribution::with_fd_inheritance_gate(|| command.spawn())?;
        #[cfg(test)]
        crate::proof_processes::record(&child);
        drop(child_startup);
        let bootstrap = match manifest.backend {
            crate::runtime_process::Backend::Acp { .. } => Some(manifest),
            #[cfg(test)]
            crate::runtime_process::Backend::Fixture { .. } => None,
        };
        Ok(Self {
            child,
            startup,
            bootstrap,
        })
    }
    fn begin_bootstrap(&mut self) -> Result<(), SupervisorError> {
        if let Some(manifest) = self.bootstrap.take() {
            if let Err(error) = frame_until(
                &mut self.startup,
                &manifest,
                std::time::Instant::now() + Duration::from_secs(2),
            ) {
                let _ = self.abort_owned();
                return Err(error);
            }
        }
        Ok(())
    }
    fn abort_owned(&mut self) -> Result<(), SupervisorError> {
        if self.child.try_wait()?.is_some() {
            return Err(SupervisorError::Unknown);
        }
        let pgid = i32::try_from(self.child.id()).map_err(|_| SupervisorError::Unknown)?;
        if unsafe { libc::kill(negative_owned_group(pgid)?, libc::SIGKILL) } != 0 {
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
        self.start_admitted_at(service, admission_id, &|| Ok(now))
    }
    pub(crate) fn start_admitted_at(
        &self,
        service: &ControlService,
        admission_id: i64,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
    ) -> Result<ExecutionObservation, SupervisorError> {
        let program = self.config.program(service, admission_id, clock)?;
        let (session, generation) = service
            .journal
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .dispatch_identity(admission_id, clock()?)?;
        validate_socket_path(
            &self
                .config
                .root
                .join(component(&session, generation))
                .join("supervisor.sock"),
        )?;
        self.config.ensure_root()?;
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
            .reserve_launch(admission_id, clock()?)?;
        let workspace = self.prepare_workspace(service, &lease, clock)?;
        let mut journal = service.journal.lock().map_err(|_| ErrorCode::Storage)?;
        #[cfg(test)]
        self.fixture_pause("before_spawn", 0)?;
        journal.commit_spawn_intent(&lease, clock()?)?;
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
        if let Err(error) = group.begin_bootstrap() {
            service
                .journal
                .lock()
                .map_err(|_| ErrorCode::Storage)?
                .mark_execution(&lease.identity, false)?;
            return Err(error);
        }
        #[cfg(test)]
        let startup_wait = std::time::Instant::now();
        let hello: SupervisorHello = match read_frame::<SupervisorHello>(&group.startup) {
            Ok(hello)
                if hello.identity == lease.identity
                    && hello.diagnostic_pid == group.child.id()
                    && hello.running =>
            {
                hello
            }
            _invalid => {
                #[cfg(test)]
                {
                    let receipt = serde_json::json!({"error":_invalid.as_ref().err().map(|error|format!("{error:?}")),"hello_received":_invalid.is_ok(),"elapsed_ms":startup_wait.elapsed().as_millis()});
                    let _ = fs::write(
                        lock.directory.join("startup-error.json"),
                        serde_json::to_vec(&receipt).unwrap(),
                    );
                }
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
                clock()?,
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
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
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
            .validate_reserved(lease, clock()?)?;
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
        if matches!(
            old.state,
            ExecutionState::Stopped | ExecutionState::Reserved
        ) {
            return Ok(old);
        }
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
            let _ = call(&socket, &old.identity, true);
            service
                .journal
                .lock()
                .map_err(|_| ErrorCode::Storage)?
                .mark_execution(&old.identity, false)?;
            return Ok(ExecutionObservation {
                state: ExecutionState::Unknown,
                ..old
            });
        }
        match call(&socket, &old.identity, false) {
            Ok(hello) => {
                if !hello.running {
                    service
                        .journal
                        .lock()
                        .map_err(|_| ErrorCode::Storage)?
                        .mark_execution(&old.identity, false)?;
                    return Ok(ExecutionObservation {
                        state: ExecutionState::Unknown,
                        ..old
                    });
                }
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
            Ok(hello) => {
                let mut journal = service.journal.lock().map_err(|_| ErrorCode::Storage)?;
                journal.mark_execution(&identity, false)?;
                journal.db.execute("UPDATE executions SET cursor=MAX(cursor,?1) WHERE session_id=?2 AND generation=?3 AND identity=?4",rusqlite::params![i64::try_from(hello.event_cursor).map_err(|_|ErrorCode::InvalidConfiguration)?,identity.session_id,i64::try_from(identity.generation).map_err(|_|ErrorCode::InvalidConfiguration)?,serde_json::to_string(&identity).map_err(|_|SupervisorError::Protocol)?]).map_err(|_|ErrorCode::Storage)?;
                Ok(ExecutionObservation {
                    identity,
                    state: ExecutionState::Unknown,
                    cursor: hello.event_cursor,
                    diagnostic_pid: Some(hello.diagnostic_pid),
                })
            }
            Err(_) => {
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

pub(crate) fn terminate_owned_backend_group(backend: &mut Child) -> Result<(), SupervisorError> {
    let own = i32::try_from(std::process::id()).map_err(|_| SupervisorError::Unknown)?;
    if unsafe { libc::getpgrp() } != own {
        return Err(SupervisorError::Unknown);
    }
    let target = negative_owned_group(own)?;
    if unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) } == libc::SIG_ERR {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::kill(target, libc::SIGTERM) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if backend.try_wait()?.is_none() {
        backend.kill()?;
    }
    backend.wait()?;
    Ok(())
}

pub(crate) fn backend_live(backend: &mut Child, output_fd: RawFd) -> Result<bool, SupervisorError> {
    if backend.try_wait()?.is_some() {
        return Ok(false);
    }
    let mut pipe = libc::pollfd {
        fd: output_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut pipe, 1, 0) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(pipe.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) == 0)
}
fn run_supervisor_process(manifest: ChildManifest) -> Result<(), SupervisorError> {
    run_supervisor_process_at(manifest, std::time::Instant::now())
}

fn run_supervisor_process_at(
    manifest: ChildManifest,
    started: std::time::Instant,
) -> Result<(), SupervisorError> {
    let expires = started
        .checked_add(Duration::from_millis(manifest.max_wall_ms))
        .ok_or(SupervisorError::Protocol)?;
    #[cfg(test)]
    let diagnostic_path = match &manifest.backend {
        crate::runtime_process::Backend::Acp {
            configuration,
            fixture_records: Some(_),
            ..
        } => configuration
            .programs
            .first()
            .and_then(|p| p.arguments.get(1))
            .map(|trace| PathBuf::from(trace).with_extension("runtime-result")),
        _ => None,
    };
    let result = run_supervisor_until(manifest, expires);
    #[cfg(test)]
    if let Some(destination) = diagnostic_path {
        let receipt = serde_json::json!({"error":result.as_ref().err().map(|e|format!("{e:?}")),"elapsed_ms":started.elapsed().as_millis(),"pid":std::process::id()});
        let _ = fs::write(destination, serde_json::to_vec(&receipt).unwrap());
    }
    let group = unsafe { libc::getpgrp() };
    if group == i32::try_from(std::process::id()).unwrap_or(-1) {
        if let Ok(target) = negative_owned_group(group) {
            unsafe {
                libc::kill(target, libc::SIGKILL);
            }
        }
    }
    result
}

pub(crate) fn run_inherited(fd: RawFd, max_wall_ms: u64) -> Result<(), SupervisorError> {
    use std::os::fd::{FromRawFd, IntoRawFd};
    let started = std::time::Instant::now();
    if fd <= 2 || max_wall_ms == 0 {
        return Err(SupervisorError::Protocol);
    }
    let own = i32::try_from(std::process::id()).map_err(|_| SupervisorError::Unknown)?;
    let group = unsafe { libc::getpgrp() };
    if group != own {
        return Err(SupervisorError::Unknown);
    }
    negative_owned_group(group)?;
    let mut kind: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&kind) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut length,
        )
    } != 0
        || kind != libc::SOCK_STREAM
    {
        return Err(SupervisorError::Protocol);
    }
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut address_length = std::mem::size_of_val(&address) as libc::socklen_t;
    if unsafe {
        libc::getpeername(
            fd,
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut address_length,
        )
    } != 0
        || i32::from(address.ss_family) != libc::AF_UNIX
    {
        return Err(SupervisorError::Protocol);
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    if crate::unix::peer(&stream)?.uid != xmsg::client::current_uid() {
        return Err(ErrorCode::PeerUid.into());
    }
    xmsg::client::caller_attribution::with_fd_inheritance_gate(|| restore_startup_cloexec(fd))?;
    let deadline = started
        .checked_add(Duration::from_millis(max_wall_ms))
        .ok_or(SupervisorError::Protocol)?
        .min(started + Duration::from_secs(2));
    let mut manifest: ChildManifest = read_frame_until(&stream, deadline)?;
    if manifest.startup_fd != fd {
        return Err(SupervisorError::Protocol);
    }
    manifest.max_wall_ms = manifest.max_wall_ms.min(max_wall_ms);
    if std::time::Instant::now()
        >= started
            .checked_add(Duration::from_millis(manifest.max_wall_ms))
            .ok_or(SupervisorError::Protocol)?
    {
        return Err(ErrorCode::DeadlineExpired.into());
    }
    let _owned = stream.into_raw_fd();
    run_supervisor_process_at(manifest, started)
}
fn run_supervisor_until(
    manifest: ChildManifest,
    expires: std::time::Instant,
) -> Result<(), SupervisorError> {
    #[cfg(test)]
    if matches!(
        manifest.backend,
        crate::runtime_process::Backend::Fixture { .. }
    ) {
        return run_fixture_supervisor_until(manifest, expires);
    }
    crate::runtime_process::run_until(manifest, expires)
}

#[cfg(test)]
fn run_fixture_supervisor_until(
    manifest: ChildManifest,
    expires: std::time::Instant,
) -> Result<(), SupervisorError> {
    use std::os::fd::FromRawFd;
    let _lock = unsafe { File::from_raw_fd(manifest.lock_fd) };
    let mut startup = unsafe { UnixStream::from_raw_fd(manifest.startup_fd) };
    private_directory(manifest.socket.parent().ok_or(SupervisorError::Directory)?)?;
    let listener = UnixListener::bind(&manifest.socket)?;
    fs::set_permissions(&manifest.socket, fs::Permissions::from_mode(0o600))?;
    let crate::runtime_process::Backend::Fixture { python, script } = &manifest.backend else {
        return Err(SupervisorError::Protocol);
    };
    let mut backend = Command::new(python)
        .arg(script)
        .env_clear()
        .env("LANG", "C")
        .current_dir(&manifest.workspace)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut input = backend.stdin.take().ok_or(SupervisorError::Protocol)?;
    let mut output = backend.stdout.take().ok_or(SupervisorError::Protocol)?;
    let output_fd = output.as_raw_fd();
    let mut reader =
        crate::framing::FrameReader::new(BufReader::new(DeadlineIo::new(&mut output, expires)?));
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
        crate::framing::write_frame(&mut DeadlineIo::new(&mut input, expires)?, &request)
            .map_err(|_| SupervisorError::Protocol)?;
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
        running: backend_live(&mut backend, output_fd)?,
        events: Vec::new(),
    };
    let _ = frame_until(&mut startup, &hello, expires);
    drop(startup);
    listener.set_nonblocking(true)?;
    loop {
        let remaining = expires.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            terminate_owned_backend_group(&mut backend)?;
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
        #[cfg(test)]
        if let Some(probe) = &manifest.accept_probe {
            let mut signal = UnixStream::connect(probe)?;
            frame_until(&mut signal, &"accepted", expires)?;
        }
        let request_deadline = expires.min(std::time::Instant::now() + Duration::from_secs(3));
        let request: SupervisorRequest = match read_frame_until(&stream, request_deadline) {
            Ok(r) => r,
            Err(_) => continue,
        };
        hello.running = backend_live(&mut backend, output_fd)?;
        let expected = match &request {
            SupervisorRequest::Attach { identity }
            | SupervisorRequest::Stop { identity }
            | SupervisorRequest::ReadEvents { identity, .. }
            | SupervisorRequest::SubmitNative { identity, .. }
            | SupervisorRequest::SubmitDecision { identity, .. } => identity,
        };
        if expected != &manifest.identity {
            continue;
        }
        if matches!(
            request,
            SupervisorRequest::SubmitNative { .. } | SupervisorRequest::SubmitDecision { .. }
        ) {
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
            frame_until(&mut stream, &response, request_deadline)?;
            continue;
        }
        if matches!(request, SupervisorRequest::Stop { .. }) {
            terminate_owned_backend_group(&mut backend)?;
            hello.event_cursor += 1;
            let event = SupervisorEvent {
                cursor: hello.event_cursor,
                frame: serde_json::json!({"kind":"owned_backend_stop_attempt"}),
            };
            let raw = serde_json::to_vec(&event).map_err(|_| SupervisorError::Protocol)?;
            if event_bytes
                .checked_add(raw.len() + 1)
                .is_none_or(|n| n > manifest.max_content_bytes as usize)
            {
                return Err(SupervisorError::Protocol);
            }
            log.write_all(&raw)?;
            log.write_all(b"\n")?;
            log.sync_data()?;
            hello.running = false;
            hello.stopped = false;
            frame_until(&mut stream, &hello, request_deadline)?;
            return Ok(());
        }
        frame_until(&mut stream, &hello, request_deadline)?;
    }
}

fn restore_startup_cloexec(fd: libc::c_int) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
