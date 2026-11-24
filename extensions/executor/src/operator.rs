use crate::{
    control::{ControlService, DaemonAttributionConfig, ErrorCode},
    runtime_config::RuntimeConfig,
};
use std::{
    ffi::OsString,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Call(PathBuf),
    Serve(PathBuf),
    Check(PathBuf),
    Runtime {
        fd: i32,
        max_wall_ms: u64,
    },
    ContentMcp(PathBuf),
    Human {
        config: PathBuf,
        session: String,
        generation: u64,
    },
    OwnerDisable {
        config: PathBuf,
        revision: u64,
    },
    Version,
}
fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Invocation, ErrorCode> {
    let args: Vec<OsString> = arguments.into_iter().collect();
    if args.len() == 1 && args[0] == "--version" {
        return Ok(Invocation::Version);
    }
    if args.len() == 3 && args[0] == "call" && args[1] == "--config" {
        let file = PathBuf::from(&args[2]);
        if !file.is_absolute() {
            return Err(ErrorCode::MalformedFrame);
        }
        return Ok(Invocation::Call(file));
    }
    if args.len() == 5
        && args[0] == "owner-disable"
        && args[1] == "--config"
        && args[3] == "--expected-revision"
    {
        let config = PathBuf::from(&args[2]);
        let revision = args[4]
            .to_str()
            .and_then(|r| r.parse::<u64>().ok())
            .filter(|r| *r > 0)
            .ok_or(ErrorCode::MalformedFrame)?;
        if !config.is_absolute() {
            return Err(ErrorCode::MalformedFrame);
        }
        return Ok(Invocation::OwnerDisable { config, revision });
    }
    if args.len() == 7
        && args[0] == "human"
        && args[1] == "--config"
        && args[3] == "--session"
        && args[5] == "--generation"
    {
        let config = PathBuf::from(&args[2]);
        let session = args[4]
            .to_str()
            .ok_or(ErrorCode::MalformedFrame)?
            .to_owned();
        let generation = args[6]
            .to_str()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .ok_or(ErrorCode::MalformedFrame)?;
        if !config.is_absolute()
            || session.is_empty()
            || session.len() > 256
            || session.chars().any(char::is_control)
        {
            return Err(ErrorCode::MalformedFrame);
        }
        return Ok(Invocation::Human {
            config,
            session,
            generation,
        });
    }
    if args.len() == 3 && args[0] == "content-mcp" && args[1] == "--socket" {
        let socket = PathBuf::from(&args[2]);
        if !socket.is_absolute() {
            return Err(ErrorCode::InvalidConfiguration);
        }
        return Ok(Invocation::ContentMcp(socket));
    }
    if args.len() == 3
        && args[1] == "--config"
        && matches!(args[0].to_str(), Some("serve" | "check-config"))
    {
        let file = PathBuf::from(&args[2]);
        if !file.is_absolute() {
            return Err(ErrorCode::InvalidConfiguration);
        }
        return Ok(if args[0] == "serve" {
            Invocation::Serve(file)
        } else {
            Invocation::Check(file)
        });
    }
    if args.len() == 5
        && args[0] == "runtime"
        && args[1] == "--manifest-fd"
        && args[3] == "--max-wall-ms"
    {
        let fd = args[2]
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
            .filter(|n| *n > 2)
            .ok_or(ErrorCode::InvalidConfiguration)?;
        let max_wall_ms = args[4]
            .to_str()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n > 0)
            .ok_or(ErrorCode::InvalidConfiguration)?;
        return Ok(Invocation::Runtime { fd, max_wall_ms });
    }
    Err(ErrorCode::InvalidConfiguration)
}

pub fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), ErrorCode> {
    match parse(arguments)? {
        Invocation::Call(file) => crate::lifecycle_client::run(&file),
        Invocation::Version => {
            println!("xmsg-executor {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Invocation::Check(file) => {
            RuntimeConfig::read(&file)?;
            println!("configuration valid; runtime activation unavailable");
            Ok(())
        }
        Invocation::ContentMcp(socket) => {
            crate::content::run_stdio(&socket).map_err(|_| ErrorCode::Storage)
        }
        Invocation::Human {
            config,
            session,
            generation,
        } => crate::human_operator::run(RuntimeConfig::read(&config)?, session, generation),
        Invocation::OwnerDisable { config, revision } => {
            let configuration = RuntimeConfig::read(&config)?;
            let proof = configuration.owner_proof()?;
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).map_err(|_| ErrorCode::Storage)?;
            let command = crate::control::AdminCommand::DisableRuntime {
                request_id: format!("disable-{}", hex::encode(nonce)),
                expected_revision: revision,
            };
            let changed: u64 = crate::human_operator::request(
                &configuration.paths.owner_socket,
                &proof,
                &command,
            )?;
            println!(
                "runtime disabled at policy revision {changed}; native stopping is not confirmed"
            );
            Ok(())
        }
        Invocation::Serve(file) => serve(RuntimeConfig::read(&file)?),
        Invocation::Runtime { fd, max_wall_ms } => {
            crate::supervisor::run_inherited(fd, max_wall_ms)
                .map_err(|_| ErrorCode::AttestationUnavailable)
        }
    }
}

struct Listener {
    socket: std::os::unix::net::UnixListener,
    file: PathBuf,
    identity: (u64, u64),
}
impl Listener {
    fn bind(file: &std::path::Path) -> Result<Self, ErrorCode> {
        use std::os::unix::fs::MetadataExt;
        let file = crate::unix::private_parent(file, xmsg::client::current_uid())?;
        let socket = crate::unix::bind_private_socket(&file)?;
        socket
            .set_nonblocking(true)
            .map_err(|_| ErrorCode::Storage)?;
        let metadata = std::fs::symlink_metadata(&file).map_err(|_| ErrorCode::Storage)?;
        Ok(Self {
            socket,
            file,
            identity: (metadata.dev(), metadata.ino()),
        })
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if let Ok(metadata) = std::fs::symlink_metadata(&self.file) {
            if metadata.file_type().is_socket() && (metadata.dev(), metadata.ino()) == self.identity
            {
                let _ = std::fs::remove_file(&self.file);
            }
        }
    }
}

fn serve(configuration: RuntimeConfig) -> Result<(), ErrorCode> {
    let uid = xmsg::client::current_uid();
    let service = ControlService::open_with_daemon_attribution(
        &configuration.paths.journal,
        uid,
        configuration.control.clone(),
        configuration.credentials()?,
        DaemonAttributionConfig {
            query_socket: configuration.paths.attribution_socket.clone(),
            lifecycle_socket: crate::unix::private_parent(
                &configuration.paths.lifecycle_socket,
                uid,
            )?,
            expected_uid: uid,
        },
    )?
    .with_runtime_configuration(configuration.clone())?;
    let listeners = [
        Listener::bind(&configuration.paths.lifecycle_socket)?,
        Listener::bind(&configuration.paths.owner_socket)?,
        Listener::bind(&configuration.paths.human_socket)?,
    ];
    let service = Arc::new(service);
    let workers = Arc::new(AtomicUsize::new(0));
    let dispatch_service = service.clone();
    std::thread::spawn(move || loop {
        dispatch_once(&dispatch_service, &configuration);
        std::thread::sleep(Duration::from_millis(25));
    });
    loop {
        for (kind, listener) in listeners.iter().enumerate() {
            if workers.load(Ordering::Acquire) >= 4 {
                break;
            }
            match xmsg::client::caller_attribution::with_fd_inheritance_gate(|| {
                listener.socket.accept()
            }) {
                Ok((stream, _)) => {
                    workers.fetch_add(1, Ordering::AcqRel);
                    let service = service.clone();
                    let workers = workers.clone();
                    std::thread::spawn(move || {
                        struct Count(Arc<AtomicUsize>);
                        impl Drop for Count {
                            fn drop(&mut self) {
                                self.0.fetch_sub(1, Ordering::AcqRel);
                            }
                        }
                        let _count = Count(workers);
                        let _ = match kind {
                            0 => service.handle_lifecycle_connection(stream),
                            1 => service.handle_owner_connection(stream),
                            _ => service.handle_native_human_connection(stream),
                        };
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err(ErrorCode::Storage),
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn dispatch_once(service: &ControlService, configuration: &RuntimeConfig) {
    #[cfg(test)]
    let _ = dispatch_once_inner(service, configuration, None);
    #[cfg(not(test))]
    let _ = dispatch_once_inner(service, configuration);
}

pub(crate) fn dispatch_once_inner(
    service: &ControlService,
    configuration: &RuntimeConfig,
    #[cfg(test)] fixture: Option<crate::supervisor::FixtureProgram>,
) -> Result<Option<crate::execution::ExecutionObservation>, ErrorCode> {
    use rusqlite::OptionalExtension;
    let selected: Result<Option<(i64, String)>, ErrorCode> = (|| {
        let journal = service.journal.lock().map_err(|_| ErrorCode::Storage)?;
        journal.db.query_row("SELECT a.id,a.resolved FROM admissions a LEFT JOIN executions e ON e.admission_id=a.id WHERE a.verb='\"dispatch\"' AND e.admission_id IS NULL AND NOT EXISTS(SELECT 1 FROM pre_launch_failures f WHERE f.admission_id=a.id) ORDER BY a.id LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_|ErrorCode::Storage)
    })();
    let Some((id, raw)) = selected? else {
        return Ok(None);
    };
    let result = (|| {
        let resolved = serde_json::from_str::<crate::capability::ResolvedDispatch>(&raw)
            .map_err(|_| ErrorCode::Storage)?;
        let workspace = configuration
            .workspaces
            .iter()
            .find(|w| {
                w.repo_id == resolved.workspace.repo_identity
                    && w.destination_selector == resolved.workspace.destination_selector
            })
            .ok_or(ErrorCode::InvalidConfiguration)?;
        let owner = crate::workspace::OwnerWorkspaceBinding::new(
            &workspace.repo_id,
            &workspace.repository,
            &workspace.approved_root,
            &workspace.base_revision,
            &workspace.destination_selector,
        )
        .map_err(|_| ErrorCode::InvalidConfiguration)?;
        let runtime = crate::supervisor::OwnerRuntimeConfig::new(
            configuration.paths.runtime_root.clone(),
            Arc::new(owner),
        )
        .map_err(|_| ErrorCode::InvalidConfiguration)?;
        #[cfg(test)]
        let runtime = {
            let mut runtime = runtime;
            runtime.fixture = fixture;
            runtime
        };
        crate::supervisor::SupervisorController::new(runtime)
            .start_admitted_at(service, id, &crate::runtime_process::unix_now)
            .map_err(|_| ErrorCode::AttestationUnavailable)
    })();
    if let Err(code) = result {
        service
            .journal
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .fail_before_launch(id, code, crate::runtime_process::unix_now()?)?;
    }
    result.map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }
    #[test]
    fn prelaunch_failure_is_diagnostic_and_cannot_claim_submission() {
        let failure = serde_json::json!({"state":"failed","admission_id":1,"code":"invalid_configuration","submission":"not_attempted"});
        assert!(
            serde_json::from_value::<crate::control::PreLaunchFailure>(failure.clone()).is_ok()
        );
        let mut submitted = failure.clone();
        submitted["submission"] = "submitted".into();
        assert!(serde_json::from_value::<crate::control::PreLaunchFailure>(submitted).is_err());
        let mut forged = failure;
        forged["principal"] = "caller-asserted".into();
        assert!(serde_json::from_value::<crate::control::PreLaunchFailure>(forged).is_err());
    }
    #[test]
    fn entrypoints_refuse_activation_flags_and_unowned_standard_descriptors() {
        assert!(matches!(
            parse(args(&["call", "--config", "/fixture/config"])),
            Ok(Invocation::Call(_))
        ));
        assert!(parse(args(&[
            "call",
            "--config",
            "/fixture/config",
            "--principal",
            "owner"
        ]))
        .is_err());
        assert!(matches!(
            parse(args(&[
                "owner-disable",
                "--config",
                "/fixture/config",
                "--expected-revision",
                "1"
            ])),
            Ok(Invocation::OwnerDisable { revision: 1, .. })
        ));
        assert!(parse(args(&["owner-restore", "--config", "/fixture/config"])).is_err());
        assert!(matches!(
            parse(args(&[
                "human",
                "--config",
                "/fixture/config",
                "--session",
                "session-1",
                "--generation",
                "1"
            ])),
            Ok(Invocation::Human { generation: 1, .. })
        ));
        assert!(parse(args(&[
            "human",
            "--config",
            "/fixture/config",
            "--session",
            "session-1",
            "--generation",
            "1",
            "--yes"
        ]))
        .is_err());
        assert_eq!(
            parse(args(&["content-mcp", "--socket", "/fixture/content"])).unwrap(),
            Invocation::ContentMcp("/fixture/content".into())
        );
        assert!(parse(args(&["content-mcp", "--socket", "relative"])).is_err());
        assert!(parse(args(&[
            "content-mcp",
            "--socket",
            "/fixture/content",
            "--as-agent",
            "other"
        ]))
        .is_err());
        assert_eq!(
            parse(args(&["check-config", "--config", "/fixture/config"])).unwrap(),
            Invocation::Check("/fixture/config".into())
        );
        assert_eq!(
            parse(args(&[
                "runtime",
                "--manifest-fd",
                "3",
                "--max-wall-ms",
                "500"
            ]))
            .unwrap(),
            Invocation::Runtime {
                fd: 3,
                max_wall_ms: 500
            }
        );
        for bad in [
            args(&["serve", "--enable-unqualified"]),
            args(&["runtime", "--manifest-fd", "0", "--max-wall-ms", "500"]),
            args(&["serve", "--config", "relative"]),
        ] {
            assert!(parse(bad).is_err());
        }
    }
}
