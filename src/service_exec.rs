use clap::{Args, Subcommand};
use std::ffi::OsString;
use std::future::Future;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use xmsg::client::{ClientError, ClientOptions, RegisteredService};

#[derive(Args, Debug)]
pub struct ServiceArgs {
    #[command(subcommand)]
    command: ServiceCommand,
}

#[derive(Subcommand, Debug)]
enum ServiceCommand {
    /// Reply to each request with a configured command's stdout
    Exec(ExecArgs),
}

#[derive(Args, Debug)]
struct ExecArgs {
    #[arg(long, value_parser = service_name)]
    name: String,
    /// Absolute registration socket (defaults to the daemon's runtime directory)
    #[arg(long, env = "XMSG_REGISTER_SOCK")]
    register_sock: Option<PathBuf>,
    /// Absolute agent socket (defaults beside the registration socket)
    #[arg(long, env = "XMSG_AGENT_SOCK")]
    agent_sock: Option<PathBuf>,
    /// Maximum command runtime, including stdout collection
    #[arg(long, default_value_t = 75000, value_parser = clap::value_parser!(u64).range(1..))]
    timeout_ms: u64,
    /// Maximum stdout bytes (also bounded by the daemon's message limit)
    #[arg(long, default_value_t = 65536, value_parser = clap::value_parser!(u32).range(64..=1048576))]
    max_output_bytes: u32,
    /// Program and literal arguments; request text is not passed to the program
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<OsString>,
}

fn service_name(value: &str) -> Result<String, String> {
    xmsg::client::validate_service_name(value)?;
    Ok(value.to_owned())
}

#[derive(Clone, Copy)]
enum Failure {
    Timeout,
    OutputLimit,
    CommandFailed,
    EmptyOutput,
    InvalidUtf8,
    Shutdown,
}

impl Failure {
    fn reply(self) -> String {
        let code = match self {
            Self::Timeout => "timeout",
            Self::OutputLimit => "output_limit",
            Self::CommandFailed => "command_failed",
            Self::EmptyOutput => "empty_output",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::Shutdown => "shutdown",
        };
        serde_json::json!({"status":"unknown", "error":code}).to_string()
    }
}

async fn invoke(
    args: &ExecArgs,
    limit: usize,
    shutdown: &mut (impl Future<Output = ()> + Unpin),
) -> Result<String, Failure> {
    let mut child = tokio::process::Command::new(&args.command[0])
        .args(&args.command[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| Failure::CommandFailed)?;
    let stdout = child.stdout.take().expect("stdout is piped");
    let operation = async {
        let mut output = Vec::new();
        stdout
            .take(limit as u64 + 1)
            .read_to_end(&mut output)
            .await
            .map_err(|_| Failure::CommandFailed)?;
        if output.len() > limit {
            return Err(Failure::OutputLimit);
        }
        let status = child.wait().await.map_err(|_| Failure::CommandFailed)?;
        if !status.success() {
            return Err(Failure::CommandFailed);
        }
        if output.is_empty() {
            return Err(Failure::EmptyOutput);
        }
        String::from_utf8(output).map_err(|_| Failure::InvalidUtf8)
    };
    let result = tokio::select! {
        _ = &mut *shutdown => Err(Failure::Shutdown),
        result = tokio::time::timeout(Duration::from_millis(args.timeout_ms), operation) => {
            result.unwrap_or(Err(Failure::Timeout))
        }
    };
    if result.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    result
}

struct Pending {
    message_id: String,
    text: String,
    key: String,
    replied: bool,
}

async fn flush(service: &mut RegisteredService, pending: &mut Pending) -> Result<(), ClientError> {
    if !pending.replied {
        service
            .reply(&pending.message_id, &pending.text, Some(&pending.key))
            .await?;
        pending.replied = true;
    }
    service.ack(&pending.message_id).await
}

fn retryable(error: &ClientError) -> bool {
    match error {
        ClientError::Configuration | ClientError::Peer => false,
        ClientError::Refused { code } => matches!(
            code.as_str(),
            "unavailable"
                | "service_unavailable"
                | "inbox_unavailable"
                | "inbox_timeout"
                | "peer_unreachable"
                | "rate_limited"
                | "peer_mailbox_full"
                | "credentials_stale"
                | "internal"
                | "process_already_registered"
        ),
        _ => true,
    }
}

async fn reconnect(
    options: &ClientOptions,
    shutdown: &mut (impl Future<Output = ()> + Unpin),
) -> Result<Option<RegisteredService>, ClientError> {
    loop {
        tokio::select! {
            _ = &mut *shutdown => return Ok(None),
            _ = tokio::time::sleep(Duration::from_secs(1)) => {},
        }
        tokio::select! {
            _ = &mut *shutdown => return Ok(None),
            result = RegisteredService::register(options.clone()) => match result {
                Ok(service) => return Ok(Some(service)),
                Err(error) if !retryable(&error) => return Err(error),
                Err(_) => {},
            },
        }
    }
}

pub async fn run(args: ServiceArgs) -> Result<(), Box<dyn std::error::Error>> {
    let ServiceCommand::Exec(args) = args.command;
    let register_socket = match &args.register_sock {
        Some(socket) => socket.clone(),
        None => xmsg::agent::default_register_sock_path()?,
    };
    let agent_socket = match &args.agent_sock {
        Some(socket) => socket.clone(),
        None => register_socket
            .parent()
            .ok_or("register socket has no parent")?
            .join("agent.sock"),
    };
    let options = ClientOptions {
        register_socket,
        agent_socket,
        // The supported stdout cap can expand sixfold in a JSON reply frame.
        max_frame_bytes: 16 * 1024 * 1024,
        operation_timeout: Duration::from_secs(5),
        service: args.name.clone(),
        expected_node: None,
        daemon_uid: xmsg::client::current_uid(),
    };
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut shutdown = Box::pin(async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    });
    let mut service = tokio::select! {
        _ = &mut shutdown => return Ok(()),
        result = RegisteredService::register(options.clone()) => result?,
    };
    let mut pending: Option<Pending> = None;
    loop {
        let limit = service
            .max_body_bytes()
            .unwrap_or(args.max_output_bytes as usize)
            .min(args.max_output_bytes as usize);
        if limit < 64
            || pending
                .as_ref()
                .is_some_and(|pending| pending.text.len() > limit)
        {
            return Err("daemon message limit cannot carry the service response".into());
        }
        let exchange = if let Some(response) = pending.as_mut() {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                result = flush(&mut service, response) => result.map(|()| None),
            }
        } else {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                result = service.poll(30) => result,
            }
        };
        match exchange {
            Ok(Some(delivery)) => {
                let text = match invoke(&args, limit, &mut shutdown).await {
                    Ok(text) => text,
                    Err(Failure::Shutdown) => return Ok(()),
                    Err(failure) => failure.reply(),
                };
                pending = Some(Pending {
                    key: format!("service-exec:{}:{}", args.name, delivery.message_id()),
                    message_id: delivery.message_id().to_owned(),
                    text,
                    replied: false,
                });
            }
            Ok(None) => pending = None,
            Err(error) => {
                if !retryable(&error) {
                    return Err("command service: permanent transport failure".into());
                }
                eprintln!("command service: transport interrupted; reconnecting");
                drop(service);
                service = match reconnect(&options, &mut shutdown)
                    .await
                    .map_err(|_| "command service: registration rejected")?
                {
                    Some(service) => service,
                    None => return Ok(()),
                };
            }
        }
    }
}
