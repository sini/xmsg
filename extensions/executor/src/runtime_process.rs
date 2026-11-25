use crate::{
    acp::{Adapter, Driver, Event},
    framing::{Frame, FrameReader, RequestId},
    journal::Journal,
    lifecycle::NativeBinding,
    supervisor::{ChildManifest, DeadlineIo, SupervisorEvent, SupervisorHello, SupervisorRequest},
};
use crate::{control::ErrorCode, runtime_config::RuntimeConfig, supervisor::SupervisorError};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::BufReader,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            net::UnixStream,
        },
    },
    process::{Child, ChildStdin, ChildStdout, Command as ProcessCommand, Stdio},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Backend {
    Acp {
        configuration: Box<RuntimeConfig>,
        admission_id: i64,
        load_native: Option<String>,
        #[cfg(test)]
        fixture_records: Option<Vec<crate::eligibility::AdapterQualification>>,
    },
    #[cfg(test)]
    Fixture {
        python: std::path::PathBuf,
        script: std::path::PathBuf,
    },
}

pub(crate) fn run_until(manifest: ChildManifest, expires: Instant) -> Result<(), SupervisorError> {
    let (configuration, admission, load_native) = match &manifest.backend {
        Backend::Acp {
            configuration,
            admission_id,
            load_native,
            ..
        } => (configuration, *admission_id, load_native),
        #[cfg(test)]
        _ => return Err(SupervisorError::Protocol),
    };
    #[cfg(test)]
    let policy = if let Backend::Acp {
        fixture_records: Some(records),
        ..
    } = &manifest.backend
    {
        let executor = std::sync::Arc::new(crate::runtime_config::ExecutableArtifact::observe(
            &std::env::current_exe()?,
        )?);
        crate::runtime_policy::RuntimePolicy::fixture(
            configuration.as_ref().clone(),
            records.clone(),
            executor,
        )
    } else {
        crate::runtime_policy::RuntimePolicy::reviewed(configuration.as_ref().clone())?
    };
    #[cfg(not(test))]
    let policy = crate::runtime_policy::RuntimePolicy::reviewed(configuration.as_ref().clone())?;
    let mut journal = Journal::open_existing(&configuration.paths.journal)?;
    #[cfg(test)]
    if matches!(
        &manifest.backend,
        Backend::Acp {
            fixture_records: Some(_),
            ..
        }
    ) {
        policy.callers.restore_fixture(&journal.db)?;
    }
    journal.runtime_policy = Some(std::sync::Arc::new(policy));
    let selected = journal.validate_bootstrap(
        admission,
        &manifest.identity,
        &manifest.workspace,
        unix_now()?,
    )?;
    if manifest.max_wall_ms > selected.budget.max_wall_ms
        || manifest.max_content_bytes > selected.budget.max_content_bytes
        || Instant::now() >= expires
    {
        return Err(ErrorCode::ResourceLimit.into());
    }
    let _lock = inherited_lock(&manifest)?;
    let mut startup = unsafe { UnixStream::from_raw_fd(manifest.startup_fd) };
    let workspace = configuration
        .workspaces
        .iter()
        .find(|w| {
            w.repo_id == selected.workspace.repo_identity
                && w.destination_selector == selected.workspace.destination_selector
        })
        .ok_or(ErrorCode::InvalidConfiguration)?;
    let owner = crate::workspace::OwnerWorkspaceBinding::new(
        &workspace.repo_id,
        &workspace.repository,
        &workspace.approved_root,
        &workspace.base_revision,
        &workspace.destination_selector,
    )?;
    let stored: String = journal
        .db
        .query_row(
            "SELECT workspace FROM executions WHERE admission_id=?1",
            [admission],
            |r| r.get(0),
        )
        .map_err(|_| ErrorCode::Storage)?;
    let prepared = crate::workspace::PreparedWorkspace::recover(
        &owner,
        serde_json::from_str(&stored).map_err(|_| ErrorCode::Storage)?,
    )?;
    if prepared.path() != manifest.workspace {
        return Err(SupervisorError::Protocol);
    }
    let program = configuration.program_for(&selected)?;
    let mut command = ProcessCommand::new(&program.adapter.path);
    configuration.launch_environment.apply(&mut command)?;
    command
        .args(&program.arguments)
        .current_dir(&manifest.workspace)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    match selected.harness {
        crate::protocol::Harness::Claude => {
            command.env("CLAUDE_CODE_EXECUTABLE", &program.native.path);
        }
        crate::protocol::Harness::Codex => {
            command.env("CODEX_PATH", &program.native.path);
        }
        crate::protocol::Harness::Agy => {}
    }
    journal.validate_bootstrap(
        admission,
        &manifest.identity,
        &manifest.workspace,
        unix_now()?,
    )?;
    if Instant::now() >= expires {
        return Err(ErrorCode::DeadlineExpired.into());
    }
    #[cfg(target_os = "macos")]
    native_descriptors_cloexec(&mut command);
    let mut backend =
        journal.spawn_native_backend(admission, &manifest.identity, &unix_now, &mut command)?;
    let mut input = backend.stdin.take().ok_or(SupervisorError::Protocol)?;
    let mut output = backend.stdout.take().ok_or(SupervisorError::Protocol)?;
    let output_fd = output.as_raw_fd();
    let mut reader = FrameReader::new(BufReader::new(DeadlineIo::new(&mut output, expires)?));
    let pin = crate::capability::builtin_pins()
        .map_err(|_| ErrorCode::InvalidConfiguration)?
        .pins
        .into_iter()
        .find(|p| p.pin.id == selected.qualification.pin_id)
        .ok_or(ErrorCode::NotSupported)?
        .pin;
    let mut driver = Driver::new(Adapter::for_pin(&pin).map_err(|_| ErrorCode::NotSupported)?);
    let id = initialize_command(
        &mut journal,
        &manifest,
        &mut driver,
        &mut input,
        crate::acp::Command::Initialize {
            client_name: "xmsg-executor".into(),
        },
        expires,
    )?;
    finish_initialization(&mut reader, &mut driver, &id, &mut input, expires)?;
    let mut content = RuntimeContent::prepare(configuration, &manifest)?;
    let mcp_servers = content
        .as_ref()
        .map(|content| vec![content.descriptor.clone()])
        .unwrap_or_default();
    let session = match load_native {
        Some(id) => crate::acp::Command::LoadSession {
            native_session_id: id.clone(),
            cwd: manifest.workspace.to_string_lossy().into_owned(),
            mcp_servers: mcp_servers.clone(),
        },
        None => crate::acp::Command::NewSession {
            cwd: manifest.workspace.to_string_lossy().into_owned(),
            mcp_servers,
        },
    };
    let id = initialize_command(
        &mut journal,
        &manifest,
        &mut driver,
        &mut input,
        session,
        expires,
    )?;
    finish_initialization(&mut reader, &mut driver, &id, &mut input, expires)?;
    let native_session_id = driver
        .native_session_id()
        .ok_or(ErrorCode::NotSupported)?
        .to_owned();
    for operation in [
        crate::acp::Command::SetMode {
            native_session_id: native_session_id.clone(),
            mode_id: program.native_mode.clone(),
        },
        crate::acp::Command::SetModel {
            native_session_id: native_session_id.clone(),
            model_id: program.native_model_id.clone(),
        },
    ] {
        let id = initialize_command(
            &mut journal,
            &manifest,
            &mut driver,
            &mut input,
            operation,
            expires,
        )?;
        finish_initialization(&mut reader, &mut driver, &id, &mut input, expires)?;
    }
    if !driver.human_mode_observed()
        || driver.observed_model_id() != Some(program.native_model_id.as_str())
    {
        return Err(ErrorCode::NotSupported.into());
    }
    let mut epoch = [0; 16];
    getrandom::fill(&mut epoch).map_err(|_| ErrorCode::Storage)?;
    let binding = NativeBinding {
        identity: manifest.identity.clone(),
        native_session_id,
        transport_epoch: hex::encode(epoch),
        native_mode: program.native_mode.clone(),
        native_model_id: driver
            .observed_model_id()
            .ok_or(ErrorCode::NotSupported)?
            .into(),
        expires_at: unix_now()?.saturating_add(
            i64::try_from(
                expires
                    .saturating_duration_since(Instant::now())
                    .as_secs()
                    .saturating_add(1),
            )
            .map_err(|_| ErrorCode::ResourceLimit)?,
        ),
    };
    journal.bind_native(&binding, unix_now()?)?;
    let listener = crate::unix::bind_private_socket(&manifest.socket)?;
    listener.set_nonblocking(true)?;
    let mut session = Session {
        journal,
        driver,
        backend,
        input,
        binding,
        expires,
        content: content.take(),
        #[cfg(test)]
        refresh_caller_fixtures: matches!(
            &manifest.backend,
            Backend::Acp {
                fixture_records: Some(_),
                ..
            }
        ),
    };
    crate::supervisor::frame_until(
        &mut startup,
        &session.hello()?,
        expires.min(Instant::now() + Duration::from_secs(2)),
    )?;
    drop(startup);
    #[cfg(test)]
    let mut held_buffer = false;
    loop {
        if Instant::now() >= expires {
            let _ = crate::supervisor::terminate_owned_backend_group(&mut session.backend);
            return Err(SupervisorError::Unknown);
        }
        if !crate::supervisor::backend_live(&mut session.backend, output_fd)? {
            session.driver.transport_lost();
            session.journal.native_transport_unknown(&session.binding)?;
            return Err(SupervisorError::Unknown);
        }
        if session
            .journal
            .administrative_stop_needed(&session.binding.identity)?
        {
            let _ = crate::supervisor::terminate_owned_backend_group(&mut session.backend);
            session.journal.native_transport_unknown(&session.binding)?;
            return Err(SupervisorError::Unknown);
        }
        let buffered = !reader.inner_mut().buffer().is_empty();
        #[cfg(test)]
        if buffered && !held_buffer {
            fixture_notice(&manifest, b'B', true, expires)?;
            held_buffer = true;
        }
        if buffered {
            let frame = native_frame(&mut reader, expires)?;
            #[cfg(test)]
            let is_end = fixture_batch_end(&frame);
            #[cfg(test)]
            let is_injected = fixture_steer_observed(&frame);
            session.observe(frame)?;
            #[cfg(test)]
            if is_end {
                fixture_notice(&manifest, b'E', false, expires)?;
            }
            #[cfg(test)]
            if is_injected {
                fixture_notice(&manifest, b'I', false, expires)?;
            }
        }
        let mut ready = [
            libc::pollfd {
                fd: output_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let wait = i32::try_from(
            expires
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(if buffered { 0 } else { 25 }),
        )
        .map_err(|_| SupervisorError::Protocol)?;
        let count = unsafe { libc::poll(ready.as_mut_ptr(), ready.len() as libc::nfds_t, wait) };
        if count < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(std::io::Error::last_os_error().into());
        }
        if !buffered && ready[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let frame = native_frame(&mut reader, expires)?;
            #[cfg(test)]
            let is_end = fixture_batch_end(&frame);
            #[cfg(test)]
            let is_injected = fixture_steer_observed(&frame);
            session.observe(frame)?;
            #[cfg(test)]
            if is_end {
                fixture_notice(&manifest, b'E', false, expires)?;
            }
            #[cfg(test)]
            if is_injected {
                fixture_notice(&manifest, b'I', false, expires)?;
            }
        }
        if ready[1].revents & libc::POLLIN != 0 {
            if let Ok((stream, _)) =
                xmsg::client::caller_attribution::with_fd_inheritance_gate(|| listener.accept())
            {
                if session.control(stream).unwrap_or(false) {
                    return Err(SupervisorError::Unknown);
                }
            }
        }
        session.schedule()?;
        session.start_content()?;
    }
}

#[cfg(test)]
fn fixture_batch_end(frame: &Frame) -> bool {
    matches!(frame,Frame::Notification(n) if n.params.as_ref().is_some_and(|p|p["update"]["content"]["text"]=="batch-end"))
}

#[cfg(test)]
fn fixture_steer_observed(frame: &Frame) -> bool {
    matches!(frame,Frame::Success(reply) if reply.result["outcome"]=="injected")
}

#[cfg(test)]
fn fixture_notice(
    manifest: &ChildManifest,
    notice: u8,
    wait: bool,
    expires: Instant,
) -> Result<(), SupervisorError> {
    use std::io::{Read, Write};
    let Backend::Acp { configuration, .. } = &manifest.backend else {
        return Ok(());
    };
    let Some(program) = configuration.programs.first() else {
        return Ok(());
    };
    if program.arguments.get(3).map(String::as_str) != Some("fairness") {
        return Ok(());
    }
    let destination = program.arguments.get(4).ok_or(SupervisorError::Protocol)?;
    let mut stream = UnixStream::connect(destination)?;
    let mut bounded = DeadlineIo::new(
        &mut stream,
        expires.min(Instant::now() + Duration::from_secs(2)),
    )?;
    bounded.write_all(&[notice])?;
    if wait {
        let mut release = [0];
        bounded.read_exact(&mut release)?;
        if release[0] != b'R' {
            return Err(SupervisorError::Protocol);
        }
    }
    Ok(())
}

fn inherited_lock(manifest: &ChildManifest) -> Result<File, SupervisorError> {
    if manifest.lock_fd <= 2 || manifest.lock_fd == manifest.startup_fd {
        return Err(SupervisorError::Protocol);
    }
    let expected = manifest
        .socket
        .parent()
        .ok_or(SupervisorError::Directory)?
        .join("execution.lock");
    if unsafe { libc::fcntl(manifest.lock_fd, libc::F_GETFD) } < 0 {
        return Err(SupervisorError::Unknown);
    }
    let duplicate = xmsg::client::caller_attribution::with_fd_inheritance_gate(|| {
        let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(manifest.lock_fd) };
        fd.try_clone_to_owned().map(File::from)
    })?;
    let metadata = duplicate.metadata()?;
    let path = std::fs::symlink_metadata(&expected)?;
    if !path.is_file()
        || !metadata.is_file()
        || path.uid() != xmsg::client::current_uid()
        || path.mode() & 0o7777 != 0o600
        || path.dev() != metadata.dev()
        || path.ino() != metadata.ino()
    {
        return Err(SupervisorError::Unknown);
    }
    let other = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(expected)?;
    if unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        let _ = unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_UN) };
        return Err(SupervisorError::Unknown);
    }
    if std::io::Error::last_os_error().kind() != std::io::ErrorKind::WouldBlock
        || unsafe { libc::flock(manifest.lock_fd, libc::LOCK_EX | libc::LOCK_NB) } != 0
    {
        return Err(SupervisorError::Unknown);
    }
    xmsg::client::caller_attribution::with_fd_inheritance_gate(|| {
        let flags = unsafe { libc::fcntl(manifest.lock_fd, libc::F_GETFD) };
        if flags < 0
            || unsafe { libc::fcntl(manifest.lock_fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    })?;
    Ok(unsafe { File::from_raw_fd(manifest.lock_fd) })
}

fn native_frame(
    reader: &mut FrameReader<BufReader<DeadlineIo<'_, ChildStdout>>>,
    expires: Instant,
) -> Result<Frame, SupervisorError> {
    reader
        .inner_mut()
        .get_mut()
        .set_deadline(expires.min(Instant::now() + Duration::from_secs(2)));
    reader
        .next_frame()
        .map_err(|_| SupervisorError::Protocol)?
        .ok_or(SupervisorError::Unknown)
}

fn write_native(
    input: &mut ChildStdin,
    frame: &Frame,
    expires: Instant,
) -> Result<(), SupervisorError> {
    crate::framing::write_frame(
        &mut DeadlineIo::new(input, expires.min(Instant::now() + Duration::from_secs(2)))?,
        frame,
    )
    .map_err(|_| SupervisorError::Protocol)
}

fn negative_native_reply(event: &Event) -> Option<Frame> {
    match event {
        Event::PermissionAutoCancelled { response, .. } => Some(response.clone()),
        Event::UnsupportedRequest { request_id, .. } => {
            Some(Frame::Failure(crate::framing::Failure {
                jsonrpc: "2.0".into(),
                id: request_id.clone(),
                error: crate::framing::RpcError {
                    code: -32601,
                    message: "unsupported native request".into(),
                    data: None,
                },
            }))
        }
        _ => None,
    }
}

fn initialize_command(
    journal: &mut Journal,
    manifest: &ChildManifest,
    driver: &mut Driver,
    input: &mut ChildStdin,
    command: crate::acp::Command,
    expires: Instant,
) -> Result<RequestId, SupervisorError> {
    journal.validate_bootstrap(
        match &manifest.backend {
            Backend::Acp { admission_id, .. } => *admission_id,
            #[cfg(test)]
            _ => return Err(SupervisorError::Protocol),
        },
        &manifest.identity,
        &manifest.workspace,
        unix_now()?,
    )?;
    if Instant::now() >= expires {
        return Err(ErrorCode::DeadlineExpired.into());
    }
    let frame = driver
        .begin(command)
        .map_err(|_| SupervisorError::Protocol)?;
    let Frame::Request(request) = &frame else {
        return Err(SupervisorError::Protocol);
    };
    let id = request.id.clone();
    let mut writer = DeadlineIo::new(input, expires.min(Instant::now() + Duration::from_secs(2)))?;
    journal.write_bootstrap_frame(
        match &manifest.backend {
            Backend::Acp { admission_id, .. } => *admission_id,
            #[cfg(test)]
            _ => return Err(SupervisorError::Protocol),
        },
        &manifest.identity,
        &unix_now,
        &frame,
        &mut writer,
    )?;
    Ok(id)
}

fn finish_initialization(
    reader: &mut FrameReader<BufReader<DeadlineIo<'_, ChildStdout>>>,
    driver: &mut Driver,
    expected: &RequestId,
    input: &mut ChildStdin,
    expires: Instant,
) -> Result<(), SupervisorError> {
    loop {
        let frame = native_frame(reader, expires)?;
        let done = matches!(&frame,Frame::Success(reply) if &reply.id==expected);
        let events = driver
            .observe(frame)
            .map_err(|_| SupervisorError::Protocol)?;
        for event in events {
            if let Some(response) = negative_native_reply(&event) {
                write_native(input, &response, expires)?;
                continue;
            }
            match event {
                Event::RequestFailed { .. } | Event::PendingPermission { .. } => {
                    return Err(SupervisorError::Protocol)
                }
                _ => {}
            }
        }
        if done {
            return Ok(());
        }
    }
}

pub(crate) fn unix_now() -> Result<i64, ErrorCode> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .filter(|s| *s > 0)
        .ok_or(ErrorCode::DeadlineExpired)
}

struct Session {
    journal: Journal,
    driver: Driver,
    backend: Child,
    input: ChildStdin,
    binding: NativeBinding,
    expires: Instant,
    content: Option<RuntimeContent>,
    #[cfg(test)]
    refresh_caller_fixtures: bool,
}

struct RuntimeContent {
    config: crate::content::BusConfig,
    listener: Option<std::os::unix::net::UnixListener>,
    service: Option<crate::content::ContentServiceHandle>,
    journal: std::path::PathBuf,
    descriptor: serde_json::Value,
}
impl RuntimeContent {
    fn prepare(
        configuration: &RuntimeConfig,
        manifest: &ChildManifest,
    ) -> Result<Option<Self>, SupervisorError> {
        let Some(config) = &configuration.bus else {
            return Ok(None);
        };
        config
            .validate()
            .map_err(|_| ErrorCode::InvalidConfiguration)?;
        let socket = manifest
            .socket
            .parent()
            .ok_or(SupervisorError::Directory)?
            .join("content.sock");
        let listener = crate::unix::bind_private_socket(&socket)?;
        let executable = std::env::current_exe()?;
        let command = executable.to_str().ok_or(ErrorCode::InvalidConfiguration)?;
        let socket_name = socket.to_str().ok_or(ErrorCode::InvalidConfiguration)?;
        Ok(Some(Self {
            config: config.clone(),
            listener: Some(listener),
            service: None,
            journal: configuration.paths.journal.clone(),
            descriptor: serde_json::json!({"name":"xmsg","command":command,"args":["content-mcp","--socket",socket_name],"env":[]}),
        }))
    }
}
impl Session {
    #[cfg(test)]
    fn refresh_fixture_callers(&self) -> Result<(), SupervisorError> {
        if self.refresh_caller_fixtures {
            self.journal
                .runtime_policy
                .as_deref()
                .ok_or(ErrorCode::NotSupported)?
                .callers
                .restore_fixture(&self.journal.db)?;
        }
        Ok(())
    }
    fn start_content(&mut self) -> Result<(), SupervisorError> {
        let Some(content) = &mut self.content else {
            return Ok(());
        };
        if let Some(service) = &mut content.service {
            let _ = service.status();
            return Ok(());
        }
        let binding = match self.journal.proxy_binding(&self.binding.identity) {
            Ok(binding) => binding,
            Err(ErrorCode::StaleGeneration) => return Ok(()),
            Err(code) => return Err(code.into()),
        };
        let mut journal = Journal::open_existing(&content.journal)?;
        journal.runtime_policy = self.journal.runtime_policy.clone();
        let store = crate::content_admission::BoundContentJournal::new(
            journal,
            self.binding.clone(),
            self.expires,
        );
        let listener = content.listener.take().ok_or(SupervisorError::Unknown)?;
        content.service = Some(
            crate::content::start_content_service(content.config.clone(), binding, store, listener)
                .map_err(|_| ErrorCode::Storage)?,
        );
        Ok(())
    }
    fn hello(&mut self) -> Result<SupervisorHello, SupervisorError> {
        let cursor: i64 = self
            .journal
            .db
            .query_row(
                "SELECT cursor FROM executions WHERE session_id=?1 AND generation=?2",
                rusqlite::params![
                    self.binding.identity.session_id,
                    i64::try_from(self.binding.identity.generation)
                        .map_err(|_| ErrorCode::Storage)?
                ],
                |r| r.get(0),
            )
            .map_err(|_| ErrorCode::Storage)?;
        Ok(SupervisorHello {
            identity: self.binding.identity.clone(),
            event_cursor: u64::try_from(cursor).map_err(|_| ErrorCode::Storage)?,
            diagnostic_pid: std::process::id(),
            running: self.backend.try_wait()?.is_none(),
            stopped: false,
            events: vec![],
        })
    }
    fn observe(&mut self, frame: Frame) -> Result<(), SupervisorError> {
        let rpc = match &frame {
            Frame::Success(reply) => Some(reply.id.clone()),
            Frame::Failure(reply) => Some(reply.id.clone()),
            _ => None,
        };
        let events = match self.driver.observe(frame) {
            Ok(events) => events,
            Err(_) => {
                self.driver.transport_lost();
                self.journal.native_transport_unknown(&self.binding)?;
                return Err(SupervisorError::Protocol);
            }
        };
        for event in events {
            if let Some(response) = negative_native_reply(&event) {
                write_native(&mut self.input, &response, self.expires)?;
                continue;
            }
            let pending = matches!(event, Event::PendingPermission { .. });
            let result = self.journal.observe_native(
                &self.binding,
                &self.driver,
                &event,
                rpc.as_ref(),
                &unix_now,
            );
            if let Err(error) = result {
                if pending {
                    if let Event::PendingPermission { request_id, .. } = &event {
                        if let Ok(frame) = self.driver.answer_permission(
                            request_id.clone(),
                            crate::acp::PermissionDecision::Cancel,
                        ) {
                            write_native(&mut self.input, &frame, self.expires)?;
                        }
                    }
                } else {
                    return Err(error.into());
                }
            }
        }
        Ok(())
    }
    fn submit(&mut self, id: i64) -> Result<(), SupervisorError> {
        let (_, _, target) = crate::lifecycle::effect_request(&self.journal.db, id)?;
        let matches = match target {
            crate::protocol::Target::Execution {
                session_id,
                generation,
            }
            | crate::protocol::Target::Turn {
                session_id,
                generation,
                ..
            } => {
                session_id == self.binding.identity.session_id
                    && generation == self.binding.identity.generation
            }
            _ => false,
        };
        if !matches {
            return Err(ErrorCode::StaleGeneration.into());
        }
        self.journal.queue_native(id, &unix_now)?;
        let mut writer = DeadlineIo::new(
            &mut self.input,
            self.expires.min(Instant::now() + Duration::from_secs(2)),
        )?;
        self.journal.submit_native(
            id,
            &mut self.driver,
            &self.binding.transport_epoch,
            &unix_now,
            &mut writer,
        )?;
        Ok(())
    }
    fn decide(&mut self, id: &str) -> Result<(), SupervisorError> {
        let raw: String = self
            .journal
            .db
            .query_row(
                "SELECT record FROM native_pending WHERE approval_id=?1",
                [id],
                |r| r.get(0),
            )
            .map_err(|_| ErrorCode::Storage)?;
        let pending: crate::approval::NativePending =
            serde_json::from_str(&raw).map_err(|_| ErrorCode::Storage)?;
        if pending.binding != self.binding {
            return Err(ErrorCode::PendingMismatch.into());
        }
        let mut writer = DeadlineIo::new(
            &mut self.input,
            self.expires.min(Instant::now() + Duration::from_secs(2)),
        )?;
        self.journal.submit_native_decision(
            id,
            &mut self.driver,
            &self.binding.transport_epoch,
            &unix_now,
            &mut writer,
        )?;
        Ok(())
    }
    fn schedule(&mut self) -> Result<(), SupervisorError> {
        #[cfg(test)]
        self.refresh_fixture_callers()?;
        let running:bool=self.journal.db.query_row("SELECT EXISTS(SELECT 1 FROM executions WHERE session_id=?1 AND generation=?2 AND state='running')",rusqlite::params![self.binding.identity.session_id,i64::try_from(self.binding.identity.generation).map_err(|_|ErrorCode::Storage)?],|r|r.get(0)).map_err(|_|ErrorCode::Storage)?;
        if !running {
            return Ok(());
        }
        let decision:Option<String>=self.journal.db.query_row("SELECT approval_id FROM native_pending WHERE session_id=?1 AND generation=?2 AND transport_epoch=?3 AND state='decision_recorded' ORDER BY rowid LIMIT 1",rusqlite::params![self.binding.identity.session_id,i64::try_from(self.binding.identity.generation).map_err(|_|ErrorCode::Storage)?,self.binding.transport_epoch],|r|r.get(0)).optional().map_err(|_|ErrorCode::Storage)?;
        if let Some(id) = decision {
            let _ = self.decide(&id);
        }
        let next:Option<i64>=self.journal.db.query_row("SELECT a.id FROM admissions a LEFT JOIN native_operations n ON n.admission_id=a.id WHERE n.admission_id IS NULL AND (a.session_id=?1 OR json_extract(a.target,'$.session_id')=?1) AND a.verb IN('\"dispatch\"','\"send\"','\"steer\"','\"interrupt\"') ORDER BY CASE a.verb WHEN '\"interrupt\"' THEN 0 WHEN '\"steer\"' THEN 1 ELSE 2 END,a.id LIMIT 1",[&self.binding.identity.session_id],|r|r.get(0)).optional().map_err(|_|ErrorCode::Storage)?;
        if let Some(id) = next {
            let _ = self.journal.queue_native(id, &unix_now);
        }
        let queued:Option<i64>=self.journal.db.query_row("SELECT n.admission_id FROM native_operations n JOIN admissions a ON a.id=n.admission_id WHERE n.session_id=?1 AND n.generation=?2 AND n.transport_epoch=?3 AND n.state='queued' ORDER BY CASE a.verb WHEN '\"interrupt\"' THEN 0 WHEN '\"steer\"' THEN 1 ELSE 2 END,n.admission_id LIMIT 1",rusqlite::params![self.binding.identity.session_id,i64::try_from(self.binding.identity.generation).map_err(|_|ErrorCode::Storage)?,self.binding.transport_epoch],|r|r.get(0)).optional().map_err(|_|ErrorCode::Storage)?;
        if let Some(id) = queued {
            let _ = self.submit(id);
        }
        if self
            .content
            .as_ref()
            .is_some_and(|content| content.config.auto_input)
        {
            let mut writer = DeadlineIo::new(
                &mut self.input,
                self.expires.min(Instant::now() + Duration::from_secs(2)),
            )?;
            let _ = self.journal.submit_content(
                &self.binding,
                &mut self.driver,
                &unix_now,
                &mut writer,
            );
        }
        Ok(())
    }
    fn control(&mut self, mut stream: UnixStream) -> Result<bool, SupervisorError> {
        #[cfg(test)]
        self.refresh_fixture_callers()?;
        if crate::unix::peer(&stream)?.uid != xmsg::client::current_uid() {
            return Err(ErrorCode::PeerUid.into());
        }
        let deadline = self.expires.min(Instant::now() + Duration::from_secs(2));
        let request: SupervisorRequest = crate::supervisor::read_frame_until(&stream, deadline)?;
        let identity = match &request {
            SupervisorRequest::Attach { identity }
            | SupervisorRequest::Stop { identity }
            | SupervisorRequest::ReadEvents { identity, .. }
            | SupervisorRequest::SubmitNative { identity, .. }
            | SupervisorRequest::SubmitDecision { identity, .. } => identity,
        };
        if identity != &self.binding.identity {
            return Err(SupervisorError::Protocol);
        }
        let mut stop = false;
        match request {
            SupervisorRequest::Stop { .. } => {
                crate::supervisor::terminate_owned_backend_group(&mut self.backend)?;
                self.driver.transport_lost();
                self.journal.native_transport_unknown(&self.binding)?;
                stop = true;
            }
            SupervisorRequest::SubmitNative {
                admission_id,
                transport_epoch,
                ..
            } => {
                if transport_epoch != self.binding.transport_epoch {
                    return Err(ErrorCode::PendingMismatch.into());
                }
                self.submit(admission_id)?;
            }
            SupervisorRequest::SubmitDecision {
                approval_id,
                transport_epoch,
                ..
            } => {
                if transport_epoch != self.binding.transport_epoch {
                    return Err(ErrorCode::PendingMismatch.into());
                }
                self.decide(&approval_id)?;
            }
            SupervisorRequest::ReadEvents { after, max, .. } => {
                let mut hello = self.hello()?;
                if max == 0 || max > 32 || after > hello.event_cursor {
                    return Err(SupervisorError::Protocol);
                }
                let mut query=self.journal.db.prepare("SELECT cursor,event FROM execution_events WHERE session_id=?1 AND generation=?2 AND cursor>?3 ORDER BY cursor LIMIT ?4").map_err(|_|ErrorCode::Storage)?;
                let rows = query
                    .query_map(
                        rusqlite::params![
                            self.binding.identity.session_id,
                            i64::try_from(self.binding.identity.generation)
                                .map_err(|_| ErrorCode::Storage)?,
                            i64::try_from(after).map_err(|_| ErrorCode::Storage)?,
                            max
                        ],
                        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                    )
                    .map_err(|_| ErrorCode::Storage)?;
                let mut bytes = 0usize;
                for row in rows {
                    let (cursor, raw) = row.map_err(|_| ErrorCode::Storage)?;
                    bytes = bytes
                        .checked_add(raw.len())
                        .ok_or(ErrorCode::ResourceLimit)?;
                    if bytes > crate::framing::MAX_FRAME_BYTES / 2 {
                        break;
                    }
                    hello.events.push(SupervisorEvent {
                        cursor: u64::try_from(cursor).map_err(|_| ErrorCode::Storage)?,
                        frame: serde_json::from_str(&raw).map_err(|_| ErrorCode::Storage)?,
                    });
                }
                crate::supervisor::frame_until(&mut stream, &hello, deadline)?;
                return Ok(false);
            }
            SupervisorRequest::Attach { .. } => {}
        }
        let mut hello = self.hello()?;
        if stop {
            hello.running = false;
        }
        crate::supervisor::frame_until(&mut stream, &hello, deadline)?;
        Ok(stop)
    }
}

#[cfg(any(target_os = "macos", test))]
fn native_descriptors_cloexec(command: &mut ProcessCommand) {
    use std::os::unix::process::CommandExt;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let maximum = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
        limit.rlim_cur.min(65536) as libc::c_int
    } else {
        65536
    };
    // Marking rather than closing preserves std's exec-error pipe.
    unsafe {
        command.pre_exec(move || {
            for fd in 3..maximum {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags >= 0 && libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::process::CommandExt;

    #[test]
    fn native_exec_excludes_an_inheritable_unowned_socket() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let fd = socket.as_raw_fd();
        let metadata = File::from(std::os::fd::OwnedFd::from(socket.try_clone().unwrap()))
            .metadata()
            .unwrap();
        let python =
            std::env::var_os("XMSG_EXECUTOR_FIXTURE_PYTHON").unwrap_or_else(|| "python3".into());
        let mut command = ProcessCommand::new(python);
        command
            .args([
                "-c",
                "import os,sys
sys.stdin.buffer.read(1)
try:
 s=os.fstat(int(sys.argv[1])); inherited=(s.st_dev,s.st_ino)==(int(sys.argv[2]),int(sys.argv[3]))
except OSError:
 inherited=False
sys.exit(23 if inherited else 0)",
            ])
            .arg(fd.to_string())
            .arg(metadata.dev().to_string())
            .arg(metadata.ino().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        native_descriptors_cloexec(&mut command);
        crate::proof_processes::configure(&mut command);
        let mut child = command.spawn().unwrap();
        crate::proof_processes::record(&child);
        child.stdin.take().unwrap().write_all(b"x").unwrap();
        let status = child.wait().unwrap();
        assert!(
            status.success(),
            "native exec inherited the deliberately unowned socket: {status}"
        );
    }
}
