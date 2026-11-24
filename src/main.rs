use clap::{Parser, Subcommand};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::info;
use tracing_subscriber::EnvFilter;

use xmsg::http::{build_router, build_unix_router_with_enrollment, AppState};
use xmsg::mcp::{run_mcp_loop, McpConfig};
use xmsg::registry::resolve_sessions_dirs;
use xmsg::storage;

mod doctor;
mod operator;
mod service_exec;
mod watch;

#[derive(Parser, Debug)]
#[command(
    name = "xmsg",
    version,
    about = "Fast, lightweight local HTTP bridge into live agent sessions"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Args, Debug)]
struct ActivityArgs {
    #[command(subcommand)]
    command: ActivitySubcommand,
}

#[derive(clap::Subcommand, Debug)]
enum ActivitySubcommand {
    /// Fail-open bounded hook handler for a harness
    Hook {
        /// Harness name: claude, codex, agy, opencode, pi, hermes
        harness: String,
        /// Enable correlated tool-id resolution
        #[arg(long)]
        correlated: bool,
        /// Override agent.sock path
        #[arg(long, env = "XMSG_AGENT_SOCK")]
        sock: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Collect authorized read-only observation metadata
    ObserveCollector(xmsg::observe_collector::Args),

    /// Inspect the Mission Control fleet after device approval
    MissionControl(xmsg::mission_control_client::Args),

    /// Session activity hook helpers
    Activity(ActivityArgs),

    /// List mesh recipients and node status
    List(operator::ListArgs),

    /// Find a session without attaching or resuming it
    Locate(operator::LocateArgs),

    /// Inspect local setup without repairing state
    Doctor(doctor::DoctorArgs),

    /// Preview a reversible per-user harness adapter; writes require --apply
    Install {
        #[command(subcommand)]
        adapter: xmsg::install::Adapter,
    },
    /// Preview removal of unchanged owned adapter entries; writes require --apply
    Uninstall {
        #[command(subcommand)]
        adapter: xmsg::install::Adapter,
    },

    /// Watch recipients and local message observations
    Watch(watch::WatchArgs),

    /// Send a message through the local daemon
    Send(operator::SendArgs),

    /// Read replies to a message
    Replies(operator::RepliesArgs),

    /// Show stored message metadata and replies
    Show(operator::ShowArgs),

    /// Run an ordinary command-backed service
    Service(service_exec::ServiceArgs),

    /// Start the HTTP bridge server
    Serve(Box<ServeArgs>),

    /// Run the stdio MCP server for agent harnesses
    Mcp(McpArgs),

    /// Register credentials with running xmsg server
    Register(RegisterArgs),

    /// Explicitly revoke or unregister a session (e.g. `--codex-session <P>`)
    Unregister(UnregisterArgs),

    /// Load a peers file with every rule `serve` applies, and exit 0 or name the failure
    #[command(
        long_about = "Validate a peers file (the same rules `serve` applies at startup); exit 0 if valid, otherwise print the failing rule. Use it in CI or before a deploy."
    )]
    CheckPeers(CheckPeersArgs),
    /// Enroll this machine through an OIDC identity provider
    Enroll(xmsg::enroll_cli::Args),
    /// Manage the local enrollment authority
    EnrollCa(EnrollCaArgs),

    /// Manage declared plugin harness descriptors on the local daemon
    Harness(operator::HarnessArgs),
}

#[derive(Parser, Debug)]
pub struct UnregisterArgs {
    /// Deliberately revoke a Codex root session ID (`RevokedByOperator`, sticky across resume)
    #[arg(long = "codex-session")]
    pub codex_session: String,

    /// Agent socket path (defaults to $XDG_RUNTIME_DIR/xmsg/agent.sock)
    #[arg(long, env = "XMSG_AGENT_SOCK")]
    pub sock: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct EnrollCaArgs {
    #[arg(long = "enroll-ca-dir")]
    pub ca_dir: Option<PathBuf>,
    #[arg(long, env = "XMSG_HTTP_SOCK")]
    pub http_sock: Option<PathBuf>,
    #[arg(long = "enroll-policy")]
    pub policy: Option<PathBuf>,
    #[arg(long = "db-path", env = "XMSG_DB_PATH")]
    pub db_path: Option<PathBuf>,
    #[command(subcommand)]
    pub action: EnrollCaAction,
}
#[derive(Subcommand, Debug)]
pub enum EnrollCaAction {
    Init,
    List,
    Bind {
        user: String,
        provider: String,
        sub: String,
    },
    Unbind {
        user: String,
    },
    Pending,
    Approve {
        #[arg(allow_hyphen_values = true)]
        request_id: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        spki_sha256: String,
    },
    Deny {
        #[arg(allow_hyphen_values = true)]
        request_id: String,
    },
}

#[derive(Parser, Debug)]
pub struct CheckPeersArgs {
    /// Path to the peers file (JSON)
    pub peers_file: PathBuf,

    /// This node's federation certificate (PEM); with it, the peers file is also checked
    /// against this node's own name and key
    #[arg(long)]
    pub fed_cert: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct RegisterArgs {
    #[command(subcommand)]
    pub harness: RegisterHarness,
}

#[derive(Subcommand, Debug)]
pub enum RegisterHarness {
    /// Register Antigravity session credentials
    Agy(RegisterAgyArgs),

    /// Claude Code subagent hook handler (PreToolUse, SubagentStart, PostToolUse, SubagentStop)
    Claude(RegisterClaudeArgs),

    /// Codex CLI lifecycle and subagent hook handler
    Codex(RegisterCodexArgs),
}

#[derive(Parser, Debug)]
pub struct RegisterCodexArgs {
    /// Hook mode for Codex hooks
    #[arg(long)]
    pub hook: bool,

    /// Hook event when `--hook` is passed
    #[arg(long, default_value = "")]
    pub event: String,

    /// Deliberately revoke a Codex root session ID (`RevokedByOperator`, sticky across resume)
    #[arg(long, conflicts_with = "unrevoke")]
    pub revoke: Option<String>,

    /// Clear `RevokedByOperator` on a Codex root session ID back to `StaleAfterResume`
    #[arg(long, conflicts_with = "revoke")]
    pub unrevoke: Option<String>,

    /// Agent socket path (defaults to $XDG_RUNTIME_DIR/xmsg/agent.sock)
    #[arg(long, env = "XMSG_AGENT_SOCK")]
    pub sock: Option<PathBuf>,

    /// Optional label override to assign to the registered Codex session
    #[arg(long, env = "XMSG_CODEX_LABEL")]
    pub label: Option<String>,
}

#[derive(Parser, Debug)]
pub struct RegisterClaudeArgs {
    /// Hook mode for Claude Code hooks
    #[arg(long)]
    pub hook: bool,

    /// Agent socket override (otherwise resolved from the selected installation)
    #[arg(long, env = "XMSG_AGENT_SOCK")]
    pub sock: Option<PathBuf>,

    /// Database selecting the same state-derived endpoint set as serve
    #[arg(long, env = "XMSG_DB_PATH")]
    pub db_path: Option<PathBuf>,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgyHookEvent {
    PreInvocation,
    PreToolUse,
    Stop,
}

#[derive(Parser, Debug)]
pub struct RegisterAgyArgs {
    /// Registration socket path (defaults to $XDG_RUNTIME_DIR/xmsg/register.sock; on macOS without it, the Darwin user temp dir)
    #[arg(long, env = "XMSG_REGISTER_SOCK")]
    pub sock: Option<PathBuf>,

    /// Agent socket path for subagent hook frames (defaults to the directory of `--sock` or $XDG_RUNTIME_DIR/xmsg/agent.sock)
    #[arg(long, env = "XMSG_AGENT_SOCK")]
    pub agent_sock: Option<PathBuf>,

    /// Hook mode for agy hooks
    #[arg(long)]
    pub hook: bool,

    /// Hook event when `--hook` is passed
    #[arg(long, value_enum, default_value_t = AgyHookEvent::PreInvocation)]
    pub event: AgyHookEvent,

    /// URL of xmsg HTTP server (for checking session credentials in hook mode)
    #[arg(long, env = "XMSG_URL", default_value = "http://127.0.0.1:7787")]
    pub url: String,

    /// Label to assign to the registered Antigravity session
    #[arg(long, env = "XMSG_AGY_LABEL", default_value = "agy")]
    pub label: String,
}

#[derive(Parser, Debug)]
pub struct ServeArgs {
    /// Opt in to an owner-local attribution query for this lifecycle socket; qualification remains unavailable by default.
    #[arg(long)]
    pub executor_lifecycle_socket: Option<PathBuf>,

    /// Override the attribution query socket path (requires the lifecycle endpoint).
    #[arg(long, requires = "executor_lifecycle_socket")]
    pub executor_attribution_sock: Option<PathBuf>,
    /// Read session context tags and masking policy from a TOML file.
    #[arg(long, env = "XMSG_CONTEXT_TAGS_CONFIG")]
    pub context_tags_config: Option<PathBuf>,

    /// Disable collection and publication of session context tags.
    #[arg(long, env = "XMSG_NO_CONTEXT_TAGS")]
    pub no_context_tags: bool,

    /// Omit a context field (or * for all fields) on local, federation, or observe output.
    #[arg(
        long = "context-mask",
        env = "XMSG_CONTEXT_MASK",
        value_delimiter = ','
    )]
    pub context_mask: Vec<String>,

    /// Optional TCP listen address (IP:PORT), for environments like Kubernetes pods where loopback is a private netns. With no flag, no TCP socket is bound.
    #[arg(long, env = "XMSG_LISTEN")]
    pub listen: Option<String>,

    /// Run as a leaf node (in-pod sidecar, loopback HTTP only, outbound-only federation client)
    #[arg(long, env = "XMSG_LEAF")]
    pub leaf: bool,

    /// Principal to attribute all local requests to in leaf mode (e.g. "svc:matrix")
    #[arg(long, env = "XMSG_LEAF_PRINCIPAL")]
    pub leaf_principal: Option<String>,

    /// Path to unix domain socket for HTTP server (defaults to $XDG_RUNTIME_DIR/xmsg/http.sock; on macOS without it, the Darwin user temp dir)
    #[arg(long, env = "XMSG_HTTP_SOCK")]
    pub http_sock: Option<PathBuf>,

    /// Path to session metadata directory (repeatable, or separated by ':' in env XMSG_SESSIONS_DIR; defaults to ~/.claude/sessions)
    #[arg(
        long = "sessions-dir",
        env = "XMSG_SESSIONS_DIR",
        value_delimiter = ':'
    )]
    pub sessions_dirs: Vec<PathBuf>,

    /// Maximum request body size in bytes
    #[arg(
        long,
        env = "XMSG_MAX_BODY",
        default_value_t = storage::DEFAULT_MAX_BODY_BYTES
    )]
    pub max_body: usize,

    /// Maximum attachment size in bytes
    #[arg(long, env = "XMSG_MAX_ATTACHMENT_BYTES", default_value_t = 8 * 1024 * 1024)]
    pub max_attachment_bytes: usize,

    /// Path to SQLite database
    #[arg(long, env = "XMSG_DB_PATH")]
    pub db_path: Option<PathBuf>,

    /// Reply TTL in seconds (default 7 days: 604800)
    #[arg(long, env = "XMSG_REPLY_TTL", default_value_t = 604800)]
    pub reply_ttl: u64,

    /// Idempotency key retention window in seconds (default 24h: 86400)
    #[arg(long, env = "XMSG_IDEMPOTENCY_TTL", default_value_t = 86400)]
    pub idempotency_ttl: u64,

    /// Per-service pending queue capacity (default: 100)
    #[arg(
        long,
        env = "XMSG_SVC_QUEUE_CAP",
        default_value_t = storage::MAX_SVC_QUEUE_PER_SESSION
    )]
    pub svc_queue_cap: usize,

    /// Maximum stored rows for each leaf peer's mailbox (0 refuses new rows)
    #[arg(long, env = "XMSG_PEER_MAILBOX_MAX_ROWS", default_value_t = storage::DEFAULT_PEER_MAILBOX_MAX_ROWS, value_parser=clap::value_parser!(u64).range(..=i64::MAX as u64))]
    pub peer_mailbox_max_rows: u64,

    /// Maximum stored payload/metadata bytes for each leaf peer's mailbox
    #[arg(long, env = "XMSG_PEER_MAILBOX_MAX_BYTES", default_value_t = storage::DEFAULT_PEER_MAILBOX_MAX_BYTES, value_parser=clap::value_parser!(u64).range(..=i64::MAX as u64))]
    pub peer_mailbox_max_bytes: u64,

    /// Maximum stored rows across all pattern-admitted leaf mailboxes
    #[arg(long, default_value_t = storage::DEFAULT_ADMITTED_MAILBOX_MAX_ROWS, value_parser=clap::value_parser!(u64).range(..=i64::MAX as u64))]
    pub admitted_mailbox_max_rows: u64,

    /// Maximum stored bytes across all pattern-admitted leaf mailboxes
    #[arg(long, default_value_t = storage::DEFAULT_ADMITTED_MAILBOX_MAX_BYTES, value_parser=clap::value_parser!(u64).range(..=i64::MAX as u64))]
    pub admitted_mailbox_max_bytes: u64,

    /// Registration socket path (defaults to $XDG_RUNTIME_DIR/xmsg/register.sock; on macOS without it, the Darwin user temp dir)
    #[arg(long, env = "XMSG_REGISTER_SOCK")]
    pub register_sock: Option<PathBuf>,

    /// Agent socket path (defaults to $XDG_RUNTIME_DIR/xmsg/agent.sock; on macOS without it, the Darwin user temp dir)
    #[arg(long, env = "XMSG_AGENT_SOCK")]
    pub agent_sock: Option<PathBuf>,

    /// Leaf register socket path (defaults to $XDG_RUNTIME_DIR/xmsg/register.sock)
    #[arg(long, env = "XMSG_LEAF_REGISTER_SOCK")]
    pub leaf_register_sock: Option<PathBuf>,

    /// Trusted Antigravity executable paths (comma-separated or multiple flags; matched by canonical file name unless --agy-exe-strict is set)
    #[arg(long = "agy-exe", env = "XMSG_AGY_EXE", value_delimiter = ',')]
    pub agy_exes: Vec<PathBuf>,

    /// Require exact canonical path match for --agy-exe instead of default file-name match
    #[arg(long = "agy-exe-strict", env = "XMSG_AGY_EXE_STRICT")]
    pub agy_exe_strict: bool,

    /// Trusted Codex executable paths (comma-separated or multiple flags; matched by canonical file name unless --codex-exe-strict is set)
    #[arg(long = "codex-exe", env = "XMSG_CODEX_EXE", value_delimiter = ',')]
    pub codex_exes: Vec<PathBuf>,

    /// Require exact canonical path match for --codex-exe instead of default file-name match
    #[arg(long = "codex-exe-strict", env = "XMSG_CODEX_EXE_STRICT")]
    pub codex_exe_strict: bool,

    /// Trusted Codex home directories (repeatable, or separated by ':' in env XMSG_CODEX_HOME; defaults to $CODEX_HOME or ~/.codex)
    #[arg(long = "codex-home", env = "XMSG_CODEX_HOME", value_delimiter = ':')]
    pub codex_homes: Vec<PathBuf>,

    /// Trusted Svc daemon executable paths per name (format: NAME=PATH, repeatable or comma-separated)
    #[arg(long = "svc-exe", env = "XMSG_SVC_EXE", value_delimiter = ',')]
    pub svc_exes: Vec<String>,

    /// Path to peers configuration file (JSON)
    #[arg(long, env = "XMSG_PEERS_FILE")]
    pub peers_file: Option<PathBuf>,

    /// Optional path to declared plugin harness descriptors file (JSON)
    #[arg(long, env = "XMSG_HARNESSES_FILE")]
    pub harnesses_file: Option<PathBuf>,

    /// Federation listen address (IP:PORT), e.g. <ts-ip>:7788
    #[arg(long, env = "XMSG_FED_LISTEN")]
    pub fed_listen: Option<String>,

    /// Path to federation TLS certificate (PEM)
    #[arg(long, env = "XMSG_FED_CERT")]
    pub fed_cert: Option<PathBuf>,

    /// Path to federation TLS private key (PEM)
    #[arg(long, env = "XMSG_FED_KEY")]
    pub fed_key: Option<PathBuf>,

    /// Dynamic federation TLS credential and CA reload interval in seconds (default: 30)
    #[arg(long, env = "XMSG_FED_RELOAD_INTERVAL_SECS", default_value = "30")]
    pub fed_reload_interval_secs: u64,
    /// Separate optional enrollment HTTPS listener (IP:PORT)
    #[arg(long)]
    pub enroll_listen: Option<std::net::SocketAddr>,
    /// Owner-private enrollment root directory
    #[arg(long)]
    pub enroll_ca_dir: Option<PathBuf>,

    /// Enable optional session activity export (off by default)
    #[arg(long, env = "XMSG_ACTIVITY")]
    pub activity: bool,

    /// Use correlated PostToolUse prompt resolution when native IDs are proven (off by default)
    #[arg(long, env = "XMSG_ACTIVITY_CORRELATED")]
    pub activity_correlated: bool,
    /// Enrollment provider and issuance policy JSON
    #[arg(long)]
    pub enroll_policy: Option<PathBuf>,
    /// Existing enrolled identity directory and automatic renewal state
    #[arg(long)]
    pub enroll_state: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct McpArgs {
    /// Database selecting the same state-derived endpoint set as serve
    #[arg(long, env = "XMSG_DB_PATH")]
    pub db_path: Option<PathBuf>,
    /// Path to session metadata directory (repeatable, or separated by ':' in env XMSG_SESSIONS_DIR; defaults to ~/.claude/sessions)
    #[arg(
        long = "sessions-dir",
        env = "XMSG_SESSIONS_DIR",
        value_delimiter = ':'
    )]
    pub sessions_dirs: Vec<PathBuf>,

    /// URL of xmsg HTTP server
    #[arg(long, env = "XMSG_URL", default_value = "http://127.0.0.1:7787")]
    pub xmsg_url: String,

    /// HTTP unix socket path
    #[arg(long, env = "XMSG_HTTP_SOCK")]
    pub http_sock: Option<PathBuf>,

    /// Agent socket override (otherwise resolved from the selected installation)
    #[arg(long, env = "XMSG_AGENT_SOCK")]
    pub agent_sock: Option<PathBuf>,

    /// Expose only the reply tool (no list, no send)
    #[arg(long, env = "XMSG_REPLY_ONLY")]
    pub reply_only: bool,
}

fn resolve_db_path(path: Option<PathBuf>) -> PathBuf {
    resolve_db_path_checked(path).unwrap_or_else(|_| PathBuf::new())
}

fn resolve_db_path_checked(
    path: Option<PathBuf>,
) -> Result<PathBuf, xmsg::install_paths::InstallError> {
    let lookup = xmsg::install_paths::SystemHomeLookup;
    let env = xmsg::install_paths::ResolveEnv::from_process(&lookup);
    match path {
        Some(p) => xmsg::install_paths::expand_explicit_path(&p, &env),
        None => Ok(xmsg::install_paths::default_state_root(&env)?.join("xmsg.db")),
    }
}

async fn enrollment_operator(
    socket: PathBuf,
    action: &EnrollCaAction,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let http = reqwest::Client::builder()
        .unix_socket(socket)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;
    let request_path = |id: &str, operation: &str| -> Result<String, Box<dyn std::error::Error>> {
        if id.len() != 32
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err("invalid enrollment request ID".into());
        }
        Ok(format!("http://localhost/v1/enrollment/{id}/{operation}"))
    };
    let request = match action {
        EnrollCaAction::Pending => http.get("http://localhost/v1/enrollment/pending"),
        EnrollCaAction::Approve {
            request_id,
            user,
            host,
            spki_sha256,
        } => http
            .post(request_path(request_id, "approve")?)
            .json(&serde_json::json!({"user":user,"host":host,"spki_sha256":spki_sha256})),
        EnrollCaAction::Deny { request_id } => http.post(request_path(request_id, "deny")?),
        _ => return Err("not a live enrollment operator action".into()),
    };
    let mut response = request.send().await?;
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > 131072 {
            return Err("enrollment operator response too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if !status.is_success() {
        return Err(format!("enrollment operator request failed ({status}): {value}").into());
    }
    Ok(value)
}

fn run_install_adapter(adapter: xmsg::install::Adapter, action: xmsg::install::Action) -> bool {
    #[cfg(test)]
    if let Some(context) = claude_install_cli_tests::context() {
        let xmsg::install::Adapter::Claude(args) = adapter;
        let lookup = xmsg::install_paths::FixtureHomeLookup(Some(context.account_home));
        let env = xmsg::install_paths::ResolveEnv::from_process(&lookup);
        let request = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|_| xmsg::install::Error::Unsafe)
            .and_then(|executable| {
                xmsg::install::request_from_environment(
                    &args,
                    &env,
                    executable,
                    std::env::var_os("CLAUDE_CONFIG_DIR").map(PathBuf::from),
                )
            })
            .map(|request| request.with_fixture_policy_roots(context.policy_roots));
        return xmsg::install::run_cli_request(&args, action, request);
    }
    xmsg::install::run_cli(adapter, action)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    main_from_args(std::env::args_os())
}

fn main_from_args(
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Keep the Mach-O __DATA,__xmsg_rev metadata section live across LTO and symbol stripping.
    xmsg::build_meta::retain_embedded_revision();
    // Restrict newly created state, config, log, and socket files to owner-only before any write.
    xmsg::install_paths::apply_process_umask();
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    let adapter_command = arguments
        .get(1)
        .is_some_and(|command| command == "install" || command == "uninstall");
    let cli = match Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error) => {
            if adapter_command
                && !matches!(
                    error.kind(),
                    clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
                )
            {
                eprintln!("claude: refused invalid_arguments");
                std::process::exit(2);
            }
            error.exit()
        }
    };

    match cli.command {
        Commands::ObserveCollector(args) => {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(xmsg::observe_collector::run(args))?;
        }
        Commands::MissionControl(args) => {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(xmsg::mission_control_client::run(args))?;
        }
        Commands::List(args) => operator::list(args)?,
        Commands::Locate(args) => operator::locate(args)?,
        Commands::Harness(args) => operator::harness(args)?,
        Commands::Watch(args) => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(watch::run(args))?;
        }
        Commands::Doctor(args) => {
            if doctor::run(args)? {
                std::process::exit(1);
            }
        }
        Commands::Install { adapter } => {
            if !run_install_adapter(adapter, xmsg::install::Action::Install) {
                std::process::exit(2);
            }
        }
        Commands::Uninstall { adapter } => {
            if !run_install_adapter(adapter, xmsg::install::Action::Uninstall) {
                std::process::exit(2);
            }
        }
        Commands::Activity(args) => match args.command {
            ActivitySubcommand::Hook {
                harness,
                correlated,
                sock,
            } => {
                let agent_sock = sock.or_else(|| xmsg::agent::default_agent_sock_path().ok());
                let (code, stdout_str) = xmsg::activity::hook::run_activity_hook(
                    &harness,
                    agent_sock.as_deref(),
                    correlated,
                );
                if !stdout_str.is_empty() {
                    print!("{stdout_str}");
                }
                std::process::exit(code);
            }
        },
        Commands::Send(args) => operator::send(args)?,
        Commands::Replies(args) => operator::replies(args)?,
        Commands::Show(args) => operator::show(args)?,

        Commands::Service(args) => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(service_exec::run(args))?;
        }
        Commands::Enroll(args) => {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(xmsg::enroll_cli::run(args))
                .map_err(|error| error.to_string())?;
        }
        Commands::EnrollCa(args) => {
            use xmsg::enroll::Clock;
            let now = xmsg::enroll::WallClock.now();
            if matches!(
                &args.action,
                EnrollCaAction::Pending
                    | EnrollCaAction::Approve { .. }
                    | EnrollCaAction::Deny { .. }
            ) {
                let socket = match args.http_sock {
                    Some(socket) => socket,
                    None => xmsg::http::default_http_sock_path()?,
                };
                let value = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(enrollment_operator(socket, &args.action))?;
                println!("{}", serde_json::to_string_pretty(&value)?);
                return Ok(());
            }
            let directory = args
                .ca_dir
                .ok_or("--enroll-ca-dir is required for init/list/bind/unbind")?;
            if matches!(args.action, EnrollCaAction::Init) {
                let pem = xmsg::enroll_ca::initialize_ca_dir(&directory, now)?;
                use rustls::pki_types::pem::PemObject;
                use sha2::Digest;
                let root = rustls::pki_types::CertificateDer::from_pem_slice(pem.as_bytes())?;
                println!(
                    "{}",
                    serde_json::json!({"root_file":directory.join("root.crt"),"fingerprint":format!("sha256:{}",hex::encode(sha2::Sha256::digest(root.as_ref())))})
                );
            } else {
                let policy = args.policy.ok_or("--enroll-policy is required")?;
                if !directory.join("root.key").exists() {
                    return Err("run enroll-ca init first".into());
                }
                let lookup = xmsg::install_paths::SystemHomeLookup;
                let resolve_env = xmsg::install_paths::ResolveEnv::from_process(&lookup);
                let my_uid = xmsg::agent::current_uid();
                let resolved = xmsg::install_paths::resolve_install(
                    &xmsg::install_paths::ResolveRequest {
                        db_path: args.db_path,
                        writable: true,
                        enforce_legacy_guard: true,
                        ..Default::default()
                    },
                    &resolve_env,
                )?;
                if resolved.state_root_explicit {
                    xmsg::install_paths::ensure_explicit_private_dir(&resolved.state_root, my_uid)?;
                } else {
                    xmsg::install_paths::ensure_default_private_dir(&resolved.state_root, my_uid)?;
                }
                let db_file = resolved.db_path;
                let connection = rusqlite::Connection::open(&db_file)?;
                storage::init_db(&connection)?;
                let ca = xmsg::enroll_ca::EnrollCa::open(
                    &directory,
                    Arc::new(Mutex::new(connection)),
                    policy,
                    String::new(),
                )?;
                match args.action {
                    EnrollCaAction::Init => unreachable!(),
                    EnrollCaAction::Pending
                    | EnrollCaAction::Approve { .. }
                    | EnrollCaAction::Deny { .. } => unreachable!(),
                    EnrollCaAction::List => {
                        println!("{}", serde_json::to_string_pretty(&ca.list()?)?)
                    }
                    EnrollCaAction::Bind {
                        user,
                        provider,
                        sub,
                    } => ca.bind(&user, &provider, &sub, now)?,
                    EnrollCaAction::Unbind { user } => ca.unbind(&user)?,
                }
            }
        }
        Commands::Serve(args) => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(run_serve(*args))?;
        }
        Commands::Mcp(args) => {
            let (agent_sock, http_sock) = if let Some(db) = args.db_path.as_deref() {
                (
                    Some(xmsg::install_paths::resolve_client_endpoint(
                        "agent",
                        args.agent_sock.as_deref(),
                        Some(db),
                        false,
                    )?),
                    Some(xmsg::install_paths::resolve_client_endpoint(
                        "http",
                        args.http_sock.as_deref(),
                        Some(db),
                        false,
                    )?),
                )
            } else {
                (args.agent_sock, args.http_sock)
            };
            let sessions_dirs = resolve_sessions_dirs(args.sessions_dirs);
            let mut config = McpConfig::new(sessions_dirs, args.xmsg_url);
            config.reply_only = args.reply_only;
            if let Some(sock) = http_sock {
                config.http_sock = Some(sock);
            }
            if let Some(sock) = agent_sock {
                config.agent_sock = sock;
            }
            let stdin = io::stdin();
            let stdout = io::stdout();
            run_mcp_loop(&config, stdin.lock(), stdout.lock())?;
        }
        Commands::Register(args) => match args.harness {
            RegisterHarness::Agy(agy_args) => {
                run_register_agy(agy_args)?;
            }
            RegisterHarness::Claude(claude_args) => {
                run_register_claude(claude_args);
            }
            RegisterHarness::Codex(codex_args) => {
                run_register_codex(codex_args);
            }
        },
        Commands::Unregister(args) => {
            if let Err(e) =
                xmsg::agent::run_codex_revoke(&args.codex_session, true, args.sock.as_deref())
            {
                eprintln!("xmsg unregister error: {e}");
                std::process::exit(1);
            }
            println!("revoked codex session {}", args.codex_session.trim());
        }
        Commands::CheckPeers(args) => {
            let own = match &args.fed_cert {
                Some(cert) => Some(own_node_from_cert_file(cert)?),
                None => None,
            };
            let peers = xmsg::fed::PeersMap::load_from_file_for(&args.peers_file, own.as_ref())
                .map_err(|e| format!("peers file {}: {e}", args.peers_file.display()))?;
            for class in peers.ambiguous_alias_classes() {
                eprintln!(
                    "warning: pattern admits ambiguous aliases; give pods concrete CA leaf entries; alias={:?} forms={:?} multiple_domains={}",
                    class.alias, class.forms, class.multiple_domains
                );
            }
            match own {
                Some(own) => println!(
                    "peers file {} loads for node {}",
                    args.peers_file.display(),
                    own.name
                ),
                None => println!("peers file {} loads", args.peers_file.display()),
            }
        }
    }

    Ok(())
}

/// This node's name and pin, from the leaf (first) certificate of a PEM chain.
fn own_node_from_cert_file(
    cert_path: &std::path::Path,
) -> Result<xmsg::fed::OwnNode, Box<dyn std::error::Error>> {
    use rustls::pki_types::pem::PemObject;
    let pem = std::fs::read(cert_path)
        .map_err(|e| format!("failed to read fed cert at {}: {e}", cert_path.display()))?;
    let leaf = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
        .next()
        .ok_or("cert file contains 0 certificates")?
        .map_err(|e| format!("failed to parse cert pem: {e}"))?;
    own_node_from_der(&leaf)
}

fn own_node_from_der(leaf: &[u8]) -> Result<xmsg::fed::OwnNode, Box<dyn std::error::Error>> {
    let name = xmsg::node::node_name_from_cert(leaf)
        .map_err(|e| format!("cannot derive this node's name from --fed-cert: {e}"))?;
    let pin = xmsg::fed::spki_sha256_from_der(leaf)?;
    Ok(xmsg::fed::OwnNode {
        name,
        pin: Some(pin),
    })
}

fn run_register_claude(args: RegisterClaudeArgs) {
    use std::io::Read;
    if !args.hook {
        eprintln!("xmsg register claude error: --hook is required");
        std::process::exit(2);
    }
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("xmsg register claude error: failed to read stdin: {e}");
        std::process::exit(2);
    }
    let selected = if args.db_path.is_some() {
        match xmsg::install_paths::resolve_client_endpoint(
            "agent",
            args.sock.as_deref(),
            args.db_path.as_deref(),
            false,
        ) {
            Ok(path) => Some(path),
            Err(_) => {
                eprintln!("xmsg register claude error: endpoint_resolution");
                std::process::exit(2);
            }
        }
    } else {
        args.sock
    };
    match xmsg::agent::run_claude_hook(&input, selected.as_deref()) {
        Ok(out) => {
            println!("{out}");
        }
        Err(e) => {
            eprintln!("xmsg register claude error: {e}");
            std::process::exit(2);
        }
    }
}

fn run_register_codex(args: RegisterCodexArgs) {
    use std::io::Read;
    if let Some(ref sid) = args.revoke {
        if let Err(e) = xmsg::agent::run_codex_revoke(sid, true, args.sock.as_deref()) {
            eprintln!("xmsg register codex error: {e}");
            std::process::exit(1);
        }
        println!("revoked codex session {}", sid.trim());
        return;
    }
    if let Some(ref sid) = args.unrevoke {
        if let Err(e) = xmsg::agent::run_codex_revoke(sid, false, args.sock.as_deref()) {
            eprintln!("xmsg register codex error: {e}");
            std::process::exit(1);
        }
        println!("unrevoked codex session {}", sid.trim());
        return;
    }
    if !args.hook || args.event.trim().is_empty() {
        eprintln!("xmsg register codex error: --hook --event <EVENT> (or --revoke/--unrevoke) is required");
        std::process::exit(2);
    }
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("xmsg register codex notice: failed to read stdin: {e}");
        return;
    }
    let stdout = std::io::stdout();
    if let Err(e) = xmsg::agent::run_codex_hook(
        &args.event,
        args.label.as_deref(),
        &input,
        args.sock.as_deref(),
        stdout.lock(),
    ) {
        eprintln!("xmsg register codex error: {e}");
        std::process::exit(2);
    }
}

fn run_register_agy(args: RegisterAgyArgs) -> Result<(), Box<dyn std::error::Error>> {
    if args.hook {
        return run_hook_agy(args);
    }

    enum RegisterAttempt {
        Ok,
        Refused(String),
    }

    let result = (|| -> Result<RegisterAttempt, Box<dyn std::error::Error>> {
        let conv_id = std::env::var("ANTIGRAVITY_CONVERSATION_ID")
            .map_err(|_| "ANTIGRAVITY_CONVERSATION_ID not set")?;
        let ls_addr = std::env::var("ANTIGRAVITY_LS_ADDRESS")
            .map_err(|_| "ANTIGRAVITY_LS_ADDRESS not set")?;
        let csrf_token = std::env::var("ANTIGRAVITY_CSRF_TOKEN")
            .map_err(|_| "ANTIGRAVITY_CSRF_TOKEN not set")?;

        let sock_path = match args.sock {
            Some(p) => p,
            None => xmsg::agent::default_register_sock_path()?,
        };

        let my_uid = xmsg::agent::current_uid();
        if let Some(parent) = sock_path.parent() {
            xmsg::agent::ensure_secure_socket_dir(parent, my_uid)?;
        }

        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let mut stream = UnixStream::connect(&sock_path)?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;

        let payload = serde_json::json!({
            "conversation_id": conv_id,
            "ls_address": ls_addr,
            "csrf_token": csrf_token,
            "label": args.label,
            "env": xmsg::locator::own_environment(),
        });

        writeln!(stream, "{payload}")?;
        stream.flush()?;

        let mut resp = String::new();
        let _ = stream.read_to_string(&mut resp);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&resp) {
            if val.get("status").and_then(|s| s.as_str()) == Some("error") {
                let detail = val
                    .get("detail")
                    .and_then(|d| d.as_str())
                    .or_else(|| val.get("error").and_then(|e| e.as_str()))
                    .unwrap_or("unknown error");
                return Ok(RegisterAttempt::Refused(format!(
                    "registration rejected by server: {detail}"
                )));
            }
        }
        Ok(RegisterAttempt::Ok)
    })();

    match result {
        Ok(RegisterAttempt::Ok) => {
            println!("{{\"injectSteps\":[]}}");
            Ok(())
        }
        Ok(RegisterAttempt::Refused(msg)) => {
            eprintln!("xmsg register agy error: {msg}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("xmsg register agy notice: {e}");
            println!("{{\"injectSteps\":[]}}");
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SessionCheckResult {
    pub has_credentials: bool,
    pub watching: bool,
    pub stand_down: bool,
    pub refusal_detail: Option<String>,
}

fn check_session_has_credentials(
    sock_path: &std::path::Path,
    conv_id: &str,
    url: &str,
    label: &str,
) -> Result<SessionCheckResult, Box<dyn std::error::Error>> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    // First try Unix socket
    if let Ok(mut stream) = UnixStream::connect(sock_path) {
        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let payload = serde_json::json!({
            "action": "check",
            "conversation_id": conv_id,
            "label": label,
        });
        if writeln!(stream, "{payload}").is_ok() && stream.flush().is_ok() {
            let mut reader = BufReader::new(stream);
            let mut resp = String::new();
            if reader.read_line(&mut resp).is_ok() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp) {
                    if v.get("status").and_then(|s| s.as_str()) == Some("error") {
                        let detail = v
                            .get("detail")
                            .and_then(|d| d.as_str())
                            .or_else(|| v.get("error").and_then(|e| e.as_str()))
                            .unwrap_or("unknown error")
                            .to_string();
                        return Ok(SessionCheckResult {
                            has_credentials: false,
                            watching: false,
                            stand_down: false,
                            refusal_detail: Some(detail),
                        });
                    }
                    let has_creds = v
                        .get("hasCredentials")
                        .or_else(|| v.get("has_credentials"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let watching = v.get("watching").and_then(|v| v.as_bool()).unwrap_or(false);
                    let stand_down = v
                        .get("stand_down")
                        .or_else(|| v.get("standDown"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    return Ok(SessionCheckResult {
                        has_credentials: has_creds,
                        watching,
                        stand_down,
                        refusal_detail: None,
                    });
                }
            }
        }
    }

    // Fallback to HTTP (try http.sock first, then url)
    if let Ok(sock) = xmsg::http::default_http_sock_path() {
        if sock.exists() {
            if let Ok((status, body)) =
                xmsg::http::http_get_unix(&sock, &format!("/v1/sessions/{conv_id}"))
            {
                if status.is_success() {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body) {
                        if let Some(reg) = val.get("registered").and_then(|r| r.as_bool()) {
                            return Ok(SessionCheckResult {
                                has_credentials: reg,
                                watching: false,
                                stand_down: false,
                                refusal_detail: None,
                            });
                        }
                    }
                }
            }
        }
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()?;
    let req_url = format!("{}/v1/sessions/{}", url.trim_end_matches('/'), conv_id);
    let resp = client.get(&req_url).send()?;
    if resp.status().is_success() {
        let val: serde_json::Value = resp.json()?;
        if let Some(reg) = val.get("registered").and_then(|r| r.as_bool()) {
            return Ok(SessionCheckResult {
                has_credentials: reg,
                watching: false,
                stand_down: false,
                refusal_detail: None,
            });
        }
    }

    Ok(SessionCheckResult::default())
}

fn run_hook_agy_pre_tool_use(input: &str) -> serde_json::Value {
    let deny = || {
        serde_json::json!({
            "decision": "deny",
            "reason": "xmsg: hook could not stamp the caller",
        })
    };
    let val: serde_json::Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(_) => return deny(),
    };
    let Some(conv_id) = val
        .get("conversationId")
        .or_else(|| val.get("conversation_id"))
        .and_then(|c| c.as_str())
        .filter(|s| !s.trim().is_empty())
    else {
        return deny();
    };
    let Some(tool_call) = val.get("toolCall").and_then(|t| t.as_object()) else {
        return deny();
    };
    let Some(tool_name) = tool_call.get("name").and_then(|n| n.as_str()) else {
        return deny();
    };
    let Some(args) = tool_call.get("args").and_then(|a| a.as_object()) else {
        return deny();
    };

    if tool_name == "call_mcp_tool" {
        let Some(server_name) = args.get("ServerName").and_then(|s| s.as_str()) else {
            return deny();
        };
        if server_name != "xmsg" {
            // OQ3: non-xmsg MCP calls get no overwrite and never "allow"; "ask" passes
            // through agy 1.3.6's pre-tool hook without refusing the call.
            return serde_json::json!({ "decision": "ask" });
        }
        let Some(raw_arguments) = args.get("Arguments") else {
            return deny();
        };
        let is_subagent = xmsg::agy::find_agy_subagent_descriptor(conv_id).is_some();
        match raw_arguments {
            serde_json::Value::Object(obj) => {
                if is_subagent {
                    if obj.get("as_agent").and_then(|v| v.as_str()) == Some(conv_id) {
                        return serde_json::json!({ "decision": "allow" });
                    }
                    let mut updated = obj.clone();
                    updated.insert(
                        "as_agent".to_string(),
                        serde_json::Value::String(conv_id.to_string()),
                    );
                    serde_json::json!({
                        "decision": "allow",
                        "overwrite": {
                            "Arguments": serde_json::Value::Object(updated),
                        }
                    })
                } else if obj.contains_key("as_agent") {
                    let mut updated = obj.clone();
                    updated.remove("as_agent");
                    serde_json::json!({
                        "decision": "allow",
                        "overwrite": {
                            "Arguments": serde_json::Value::Object(updated),
                        }
                    })
                } else {
                    serde_json::json!({ "decision": "allow" })
                }
            }
            serde_json::Value::String(s) => {
                let parsed: serde_json::Value = match serde_json::from_str(s) {
                    Ok(v) => v,
                    Err(_) => return deny(),
                };
                let Some(obj) = parsed.as_object() else {
                    return deny();
                };
                if is_subagent {
                    if obj.get("as_agent").and_then(|v| v.as_str()) == Some(conv_id) {
                        return serde_json::json!({ "decision": "allow" });
                    }
                    let mut updated = obj.clone();
                    updated.insert(
                        "as_agent".to_string(),
                        serde_json::Value::String(conv_id.to_string()),
                    );
                    let Ok(re_serialized) = serde_json::to_string(&updated) else {
                        return deny();
                    };
                    serde_json::json!({
                        "decision": "allow",
                        "overwrite": {
                            "Arguments": serde_json::Value::String(re_serialized),
                        }
                    })
                } else if obj.contains_key("as_agent") {
                    let mut updated = obj.clone();
                    updated.remove("as_agent");
                    let Ok(re_serialized) = serde_json::to_string(&updated) else {
                        return deny();
                    };
                    serde_json::json!({
                        "decision": "allow",
                        "overwrite": {
                            "Arguments": serde_json::Value::String(re_serialized),
                        }
                    })
                } else {
                    serde_json::json!({ "decision": "allow" })
                }
            }
            _ => deny(),
        }
    } else if tool_name.starts_with("mcp_xmsg_") {
        let is_subagent = xmsg::agy::find_agy_subagent_descriptor(conv_id).is_some();
        if is_subagent {
            if args.get("as_agent").and_then(|v| v.as_str()) == Some(conv_id) {
                serde_json::json!({ "decision": "allow" })
            } else {
                serde_json::json!({
                    "decision": "allow",
                    "overwrite": {
                        "as_agent": conv_id,
                    }
                })
            }
        } else if args.contains_key("as_agent") {
            serde_json::json!({
                "decision": "allow",
                "overwrite": {
                    "as_agent": "",
                }
            })
        } else {
            serde_json::json!({ "decision": "allow" })
        }
    } else {
        serde_json::json!({ "decision": "ask" })
    }
}

fn resolve_agy_hook_agent_sock(args: &RegisterAgyArgs) -> Option<PathBuf> {
    if let Some(ref p) = args.agent_sock {
        return Some(p.clone());
    }
    if let Some(ref reg_sock) = args.sock {
        if let Some(parent) = reg_sock.parent() {
            return Some(parent.join("agent.sock"));
        }
    }
    xmsg::agent::default_agent_sock_path().ok()
}

fn run_hook_agy(args: RegisterAgyArgs) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;

    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        if args.event == AgyHookEvent::PreToolUse {
            println!("{}", run_hook_agy_pre_tool_use(""));
        } else {
            eprintln!("xmsg register agy notice: failed to read stdin: {e}");
            println!("{{}}");
        }
        return Ok(());
    }

    if args.event == AgyHookEvent::PreToolUse {
        println!("{}", run_hook_agy_pre_tool_use(&input));
        return Ok(());
    }

    let val: serde_json::Value = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("xmsg register agy notice: malformed stdin json: {e}");
            println!("{{}}");
            return Ok(());
        }
    };

    let conv_id = match val
        .get("conversationId")
        .or_else(|| val.get("conversation_id"))
        .and_then(|c| c.as_str())
    {
        Some(cid) if !cid.is_empty() => cid.to_string(),
        _ => {
            eprintln!("xmsg register agy notice: missing conversationId in hook input");
            println!("{{}}");
            return Ok(());
        }
    };

    if args.event == AgyHookEvent::Stop {
        if let Some(agent_sock) = resolve_agy_hook_agent_sock(&args) {
            let frame = serde_json::json!({
                "action": "subagent",
                "schema_version": xmsg::surface::MCP_SCHEMA_VERSION,
                "event": "stop",
                "agent_id": conv_id,
            });
            let _ = xmsg::mcp::call_agent_sock(&agent_sock, &frame);
        }
        println!("{{}}");
        return Ok(());
    }

    // PreInvocation: first send subagent start on agent.sock (HA9-A.agy §2.4, G3).
    // When the caller is a subagent under a registered parent P, the server answers
    // `{"status":"ok","role":"subagent",...}` and we print `{}` so the child gets no
    // registration ask.
    if let Some(agent_sock) = resolve_agy_hook_agent_sock(&args) {
        let frame = serde_json::json!({
            "action": "subagent",
            "schema_version": xmsg::surface::MCP_SCHEMA_VERSION,
            "event": "start",
            "agent_id": conv_id,
        });
        if let Ok(resp) = xmsg::mcp::call_agent_sock(&agent_sock, &frame) {
            if resp.get("role").and_then(|r| r.as_str()) == Some("subagent") {
                println!("{{}}");
                return Ok(());
            }
        }
    }

    let sock_path = match &args.sock {
        Some(p) => p.clone(),
        None => match xmsg::agent::default_register_sock_path() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("xmsg register agy notice: cannot get register socket path: {e}");
                println!("{{}}");
                return Ok(());
            }
        },
    };

    let check = match check_session_has_credentials(&sock_path, &conv_id, &args.url, &args.label) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("xmsg register agy notice: failed to check credentials: {e}");
            println!("{{}}");
            return Ok(());
        }
    };

    if check.has_credentials || check.stand_down {
        println!("{{}}");
    } else {
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("xmsg"));
        let exe_str = exe.to_string_lossy();
        let sock_arg = match &args.sock {
            Some(s) => format!(" --sock {}", s.display()),
            None => String::new(),
        };
        let label_arg = if args.label != "agy" {
            let escaped = if args
                .label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            {
                args.label.clone()
            } else {
                format!("'{}'", args.label.replace('\'', "'\\''"))
            };
            format!(" --label {escaped}")
        } else {
            String::new()
        };
        let ephemeral = match check.refusal_detail {
            Some(ref detail) => {
                eprintln!("xmsg register agy notice: {detail}");
                format!(
                    "xmsg registration check failed ({detail}). Please run `{} register agy{}{}` before anything else. This is xmsg's automatic registration request and needs no reply.",
                    exe_str, sock_arg, label_arg
                )
            }
            None => format!(
                "Please run `{} register agy{}{}` before anything else. This is xmsg's automatic registration request and needs no reply.",
                exe_str, sock_arg, label_arg
            ),
        };
        let resp = serde_json::json!({
            "injectSteps": [
                {
                    "ephemeralMessage": ephemeral
                }
            ]
        });
        println!("{resp}");
    }

    Ok(())
}

async fn run_serve(mut args: ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Sample actual effective kernel umask before spawning concurrent work (A3 / M-S9d).
    let effective_umask = xmsg::install_paths::sample_effective_umask();

    if let Some(directory) = &args.enroll_state {
        if args.fed_cert.is_some() || args.fed_key.is_some() {
            return Err("--enroll-state conflicts with explicit --fed-cert/--fed-key".into());
        }
        args.fed_cert = Some(directory.join("fed.crt"));
        args.fed_key = Some(directory.join("fed.key"));
        if args.peers_file.is_none() && directory.join("peers.json").exists() {
            args.peers_file = Some(directory.join("peers.json"));
        }
    }
    if !matches!(
        usize::from(args.enroll_listen.is_some())
            + usize::from(args.enroll_ca_dir.is_some())
            + usize::from(args.enroll_policy.is_some()),
        0 | 3
    ) {
        return Err(
            "--enroll-listen, --enroll-ca-dir and --enroll-policy must be supplied together".into(),
        );
    }
    if let Some(directory) = &args.enroll_ca_dir {
        use xmsg::enroll::Clock;
        xmsg::enroll_ca::initialize_ca_dir(directory, xmsg::enroll::WallClock.now())?;
    }

    if args.leaf {
        if args.fed_listen.is_some() {
            return Err(
                "`--leaf` cannot be used with `--fed-listen` (leaf mode is outbound-only)"
                    .to_string()
                    .into(),
            );
        }
        if args.listen.is_none() {
            return Err("`--leaf` requires `--listen`".to_string().into());
        }
        if args.leaf_principal.is_none() {
            return Err("`--leaf` requires `--leaf-principal`".to_string().into());
        }
        if !args.svc_exes.is_empty() {
            return Err(
                "`--leaf` cannot be used with `--svc-exe` (leaf mode admits only --leaf-principal by UID, without exe attestation)"
                    .to_string()
                    .into(),
            );
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .and_then(|v| EnvFilter::try_new(v).ok())
                .unwrap_or_else(|| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    // A9: nothing assigns a node name by hand. The flag is gone (clap refuses it); the
    // environment variable that fed it is refused here rather than silently ignored.
    if std::env::var_os("XMSG_HOST_LABEL").is_some() {
        return Err(
            "XMSG_HOST_LABEL is no longer read: a node's name comes from its federation certificate, or from its user and host"
                .to_string()
                .into(),
        );
    }
    let my_uid = xmsg::agent::current_uid();
    let sessions_dirs = resolve_sessions_dirs(args.sessions_dirs);
    let lookup = xmsg::install_paths::SystemHomeLookup;
    let resolve_env = xmsg::install_paths::ResolveEnv::from_process(&lookup);
    let resolved = xmsg::install_paths::resolve_install(
        &xmsg::install_paths::ResolveRequest {
            leaf: args.leaf,
            db_path: args.db_path.clone(),
            enroll_state: args.enroll_state.clone(),
            peers_file: args.peers_file.clone(),
            http_sock: args.http_sock.clone(),
            agent_sock: args.agent_sock.clone(),
            register_sock: args.register_sock.clone(),
            leaf_register_sock: args.leaf_register_sock.clone(),
            writable: true,
            enforce_legacy_guard: true,
        },
        &resolve_env,
    )?;

    let canon_state_root = if resolved.state_root_explicit {
        xmsg::install_paths::ensure_explicit_private_dir(&resolved.state_root, my_uid)?
    } else {
        xmsg::install_paths::ensure_default_private_dir(&resolved.state_root, my_uid)?
    };
    let db_path = canon_state_root.join(
        resolved
            .db_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("xmsg.db")),
    );

    // Acquire exclusive per-state lock BEFORE opening the database or touching sockets.
    let state_lock = Arc::new(xmsg::runtime_lock::StateLock::try_acquire(
        &canon_state_root,
    )?);
    let manager_hint = detect_process_manager_hint();
    let mut owner_record = xmsg::runtime_lock::OwnerRecord::load(&canon_state_root)?
        .unwrap_or_else(|| xmsg::runtime_lock::OwnerRecord::new(my_uid, manager_hint.clone()));
    owner_record.pid = std::process::id();
    owner_record.uid = my_uid;
    owner_record.started_at_unix = storage::now_epoch_secs();
    owner_record.manager_hint = manager_hint;

    if let (Some(ns_dir), Some(ns_id)) = (&resolved.runtime_namespace, &resolved.namespace_identity)
    {
        xmsg::runtime_lock::ensure_managed_runtime_dir(
            &state_lock,
            &canon_state_root,
            ns_dir,
            ns_id,
            &mut owner_record,
            my_uid,
        )?;
    } else {
        owner_record.runtime_dir = None;
        owner_record.save(&canon_state_root)?;
    }

    // Validate or exclusively create missing final parents for every manual endpoint (H1/H2/K1).
    for ep in resolved.enabled_endpoints() {
        if ep.kind == xmsg::install_paths::BindingKind::Manual {
            if let Some(parent) = ep.path.parent() {
                xmsg::install_paths::ensure_explicit_private_dir(parent, my_uid)?;
            }
        }
    }

    let http_sock_path = resolved
        .http_sock
        .as_ref()
        .map(|e| e.path.clone())
        .unwrap_or_default();
    let agent_sock_path = resolved
        .agent_sock
        .as_ref()
        .expect("agent endpoint enabled in all modes")
        .path
        .clone();
    let register_sock_path = resolved
        .register_sock
        .as_ref()
        .map(|e| e.path.clone())
        .unwrap_or_default();
    let leaf_reg_sock_path = resolved.leaf_register_sock.as_ref().map(|e| e.path.clone());

    let fed_listen_addr: Option<std::net::SocketAddr> = match &args.fed_listen {
        Some(s) => Some(
            s.parse()
                .map_err(|e| format!("invalid --fed-listen address '{s}': {e}"))?,
        ),
        None => None,
    };

    let mut activated = xmsg::systemd::take_activated_sockets(&xmsg::systemd::ActivatedConfig {
        fed_listen: fed_listen_addr,
        listen: args.listen.as_deref(),
        agent_sock: Some(agent_sock_path.as_path()),
        register_sock: if args.leaf {
            leaf_reg_sock_path.as_deref().unwrap_or(&register_sock_path)
        } else {
            register_sock_path.as_path()
        },
        http_sock: if args.leaf {
            None
        } else {
            Some(http_sock_path.as_path())
        },
    })?;

    // Systemd activation requires explicit endpoint paths; collect adopted Unix paths to lock
    // and exclude from legacy probe, bind, publication, and cleanup (G3 / M-S1g).
    let mut adopted_unix_paths: Vec<PathBuf> = Vec::new();
    if activated.http.is_some() {
        let ep = resolved
            .http_sock
            .as_ref()
            .ok_or("systemd http listener adopted in leaf mode")?;
        if !ep.explicit {
            return Err("systemd activation for http requires an explicit --http-sock pin".into());
        }
        adopted_unix_paths.push(ep.path.clone());
    }
    if activated.agent.is_some() {
        let ep = resolved
            .agent_sock
            .as_ref()
            .ok_or("systemd agent listener missing endpoint")?;
        if !ep.explicit {
            return Err(
                "systemd activation for agent requires an explicit --agent-sock pin".into(),
            );
        }
        adopted_unix_paths.push(ep.path.clone());
    }
    if activated.register.is_some() {
        let ep = if args.leaf {
            resolved.leaf_register_sock.as_ref()
        } else {
            resolved.register_sock.as_ref()
        }
        .ok_or("systemd register listener missing endpoint")?;
        if !ep.explicit {
            return Err(
                "systemd activation for register requires an explicit --register-sock / --leaf-register-sock pin"
                    .into(),
            );
        }
        adopted_unix_paths.push(ep.path.clone());
    }

    // Acquire sorted per-endpoint locks for all manual bindings and adopted systemd listeners
    // before probing legacy listeners or opening the database.
    let mut endpoint_lock_targets: Vec<PathBuf> = resolved
        .enabled_endpoints()
        .into_iter()
        .filter(|ep| ep.kind == xmsg::install_paths::BindingKind::Manual)
        .map(|ep| ep.path.clone())
        .collect();
    endpoint_lock_targets.extend(adopted_unix_paths.iter().cloned());
    let endpoint_locks =
        xmsg::runtime_lock::acquire_endpoint_locks_sorted(&endpoint_lock_targets, my_uid)?;
    let endpoint_lock_by_path: std::collections::HashMap<PathBuf, usize> = endpoint_locks
        .iter()
        .enumerate()
        .map(|(i, l)| (l.path.clone(), i))
        .collect();

    // Probe legacy default/known endpoints read-only, excluding validated adopted listeners.
    xmsg::install_paths::probe_legacy_listeners(&resolved, &resolve_env, &adopted_unix_paths, &[])?;

    info!(
        http_sock = %http_sock_path.display(),
        agent_sock = %agent_sock_path.display(),
        effective_umask = format!("{effective_umask:03o}"),
        sessions_dirs = ?sessions_dirs,
        db_path = %db_path.display(),
        max_body = args.max_body,
        reply_ttl = args.reply_ttl,
        "starting xmsg server"
    );

    let conn = rusqlite::Connection::open(&db_path)?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600));
    }
    storage::init_db(&conn)?;
    let context_config = args.context_tags_config.clone();
    let no_context_tags = args.no_context_tags;
    let context_mask = args.context_mask.clone();
    let apply_context_policy =
        move |db: &rusqlite::Connection| -> Result<(), Box<dyn std::error::Error>> {
            let policy = context_config
                .as_ref()
                .map(std::fs::read_to_string)
                .transpose()?
                .map(|content| toml::from_str::<xmsg::session_context::Config>(&content))
                .transpose()?
                .unwrap_or_default();
            policy.apply(db, no_context_tags, &context_mask)?;
            Ok(())
        };
    apply_context_policy(&conn)?;
    xmsg::session_context::reset(&conn)?;

    let db = Arc::new(Mutex::new(conn));
    let (notify_tx, _) = broadcast::channel(1024);
    let (pi_notify_tx, _) = broadcast::channel(1024);
    let (svc_notify_tx, _) = broadcast::channel(1024);

    let agy_config = xmsg::agy::AgyConfig {
        trusted_agy_exes: args.agy_exes,
        agy_exe_strict: args.agy_exe_strict,
        ..Default::default()
    };
    let agy_store = xmsg::agy::new_agy_store();
    let pi_store = xmsg::pi::new_pi_store();
    let svc_store = xmsg::svc::new_svc_store();

    let mut trusted_svc_exes: std::collections::HashMap<String, PathBuf> =
        std::collections::HashMap::new();
    for entry in args.svc_exes {
        if let Some((name, path)) = entry.split_once('=') {
            let name = name
                .trim()
                .strip_prefix("svc:")
                .unwrap_or(name.trim())
                .to_string();
            let path = PathBuf::from(path.trim());
            trusted_svc_exes.insert(name, path);
        }
    }

    let reply_ttl = Duration::from_secs(args.reply_ttl);
    let idempotency_ttl = Duration::from_secs(args.idempotency_ttl);
    storage::set_svc_queue_cap(&db, args.svc_queue_cap);
    storage::set_peer_mailbox_limits(
        &db,
        storage::PeerMailboxLimits {
            max_rows: args.peer_mailbox_max_rows,
            max_bytes: args.peer_mailbox_max_bytes,
        },
    );

    storage::set_admitted_mailbox_limits(
        &db,
        storage::PeerMailboxLimits {
            max_rows: args.admitted_mailbox_max_rows,
            max_bytes: args.admitted_mailbox_max_bytes,
        },
    );

    let sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut bg_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let mailbox_ttl = args.reply_ttl;

    if (args.peers_file.is_some() || args.fed_listen.is_some())
        && (args.fed_cert.is_none() || args.fed_key.is_none())
    {
        return Err(
            "Federation requires both --fed-cert and --fed-key when --peers-file or --fed-listen is provided"
                .to_string()
                .into(),
        );
    }
    if args.fed_listen.is_some() && args.peers_file.is_none() {
        return Err("--fed-listen requires --peers-file".to_string().into());
    }

    let fed_listener = if let Some(addr) = fed_listen_addr {
        let listener = match activated.fed.take() {
            Some(listener) => listener,
            None => tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| format!("failed to bind federation listener on {addr}: {e}"))?,
        };
        let actual_addr = listener
            .local_addr()
            .map_err(|e| format!("failed to query federation listener local_addr: {e}"))?;
        info!(listen = %actual_addr, "bound federation mTLS listener");
        Some((listener, actual_addr))
    } else {
        None
    };

    let (cert_der, cert_chain_der, key_der) =
        if let (Some(cert_path), Some(key_path)) = (&args.fed_cert, &args.fed_key) {
            let cert_pem = std::fs::read(cert_path)
                .map_err(|e| format!("failed to read fed cert at {}: {e}", cert_path.display()))?;
            let key_pem = std::fs::read(key_path)
                .map_err(|e| format!("failed to read fed key at {}: {e}", key_path.display()))?;

            use rustls::pki_types::pem::PemObject;
            let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
                rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("failed to parse cert pem: {e}"))?;
            if certs.is_empty() {
                return Err("cert file contains 0 certificates".to_string().into());
            }
            let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_pem)
                .map_err(|e| format!("failed to parse key pem: {e}"))?;
            let cert_der = certs[0].to_vec();
            let cert_chain_der: Vec<Vec<u8>> = certs.into_iter().map(|c| c.to_vec()).collect();
            let key_der = key.secret_der().to_vec();
            (cert_der, cert_chain_der, key_der)
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

    // A9 / B5 / D4: the node's own name.
    let own = if cert_der.is_empty() {
        None
    } else {
        Some(own_node_from_der(&cert_der).map_err(|e| e.to_string())?)
    };
    let node_name = match &own {
        Some(own) => own.name.clone(),
        None => xmsg::node::local_node_name(),
    };
    info!(node_name = %node_name, "node name");

    let mut observe_path = db_path.as_os_str().to_os_string();
    observe_path.push(".observe.sqlite");
    let _observer = xmsg::observe::Observer::start(
        &db,
        &PathBuf::from(observe_path),
        &node_name,
        xmsg::observe::Config::default(),
    );

    if args.activity {
        let resolver = xmsg::activity::DbOwnerResolver {
            db: db.clone(),
            sessions_dirs: sessions_dirs.clone(),
        };
        let proofs = xmsg::activity::ProofFlags {
            correlated_mode: args.activity_correlated,
            ..Default::default()
        };
        let now_secs = storage::now_epoch_secs();
        let now_mono = tokio::time::Instant::now();
        let (engine, restart_transitions, had_rows) = {
            let mut conn = db.lock().map_err(|e| e.to_string())?;
            xmsg::activity::ActivityEngine::load_or_init(
                &mut conn, true, proofs, &resolver, now_secs, now_mono,
            )
            .map_err(|e| format!("failed to initialize activity engine: {e}"))?
        };
        let engine = Arc::new(std::sync::Mutex::new(engine));
        let (act_tx, mut act_rx) = tokio::sync::mpsc::channel::<xmsg::activity::ActivityFrame>(
            xmsg::activity::model::ACTIVITY_INGEST_QUEUE_CAP,
        );
        xmsg::activity::register_runtime(
            &db,
            xmsg::activity::ActivityRuntime {
                engine: engine.clone(),
                tx: act_tx,
            },
        );
        if had_rows {
            _observer.publish(vec![xmsg::observe::Observation {
                kind: "gap".to_owned(),
                reason: Some("writer_restart".to_owned()),
                body_availability: "not_recorded".to_owned(),
                ..Default::default()
            }]);
        }
        let mut obs_init = Vec::new();
        for tr in restart_transitions {
            obs_init.push(xmsg::observe::Observation {
                kind: "activity_changed".to_owned(),
                from: Some(tr.address),
                body_availability: "not_recorded".to_owned(),
                activity: Some(tr.descriptor),
                ..Default::default()
            });
        }
        if !obs_init.is_empty() {
            _observer.publish(obs_init);
        }
        let act_db = db.clone();
        let act_obs = _observer.clone();
        let act_engine = engine.clone();
        bg_tasks.push(tokio::spawn(async move {
            let mut queue = xmsg::activity::ActivityIngestQueue::default();
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut bucket_tokens: u32 = xmsg::activity::ACTIVITY_RATE_LIMIT_PER_SEC;
            let mut bucket_last = tokio::time::Instant::now();
            loop {
                tokio::select! {
                    maybe = act_rx.recv() => {
                        let Some(first) = maybe else { break; };
                        let key = format!("{}:{}", first.harness.as_str(), first.session);
                        if let Some(dropped_key) = queue.push(key, first) {
                            if let Ok(mut conn) = act_db.lock() {
                                if let Ok(mut eng) = act_engine.lock() {
                                    let _ = eng.mark_evidence_lost(&mut conn, &dropped_key, storage::now_epoch_secs(), tokio::time::Instant::now());
                                }
                            }
                        }
                        while let Ok(more) = act_rx.try_recv() {
                            let key = format!("{}:{}", more.harness.as_str(), more.session);
                            if let Some(dropped_key) = queue.push(key, more) {
                                if let Ok(mut conn) = act_db.lock() {
                                    if let Ok(mut eng) = act_engine.lock() {
                                        let _ = eng.mark_evidence_lost(&mut conn, &dropped_key, storage::now_epoch_secs(), tokio::time::Instant::now());
                                    }
                                }
                            }
                        }
                        let mut transitions = Vec::new();
                        if let (Ok(mut conn), Ok(mut eng)) = (act_db.lock(), act_engine.lock()) {
                            let now_s = storage::now_epoch_secs();
                            let now_m = tokio::time::Instant::now();
                            while let Some((_, f)) = queue.pop() {
                                if let Ok(Some(tr)) = eng.ingest(&mut conn, &f, &resolver, now_s, now_m) {
                                    transitions.push(tr);
                                }
                            }
                        }
                        if !transitions.is_empty() {
                            let now_m = tokio::time::Instant::now();
                            let elapsed_secs = now_m.saturating_duration_since(bucket_last).as_secs() as u32;
                            if elapsed_secs > 0 {
                                bucket_tokens = (bucket_tokens + elapsed_secs * xmsg::activity::ACTIVITY_RATE_LIMIT_PER_SEC)
                                    .min(xmsg::activity::ACTIVITY_RATE_LIMIT_PER_SEC);
                                bucket_last = now_m;
                            }
                            let mut out = Vec::new();
                            let mut coalesced = false;
                            for tr in transitions {
                                if bucket_tokens > 0 {
                                    bucket_tokens -= 1;
                                    out.push(xmsg::observe::Observation {
                                        kind: "activity_changed".to_owned(),
                                        from: Some(tr.address),
                                        body_availability: "not_recorded".to_owned(),
                                        activity: Some(tr.descriptor),
                                        ..Default::default()
                                    });
                                } else {
                                    coalesced = true;
                                }
                            }
                            if coalesced {
                                out.push(xmsg::observe::Observation {
                                    kind: "gap".to_owned(),
                                    reason: Some("capture_overflow".to_owned()),
                                    body_availability: "not_recorded".to_owned(),
                                    ..Default::default()
                                });
                            }
                            if !out.is_empty() {
                                act_obs.publish(out);
                            }
                        }
                    }
                    _ = interval.tick() => {
                        let now_s = storage::now_epoch_secs();
                        let now_m = tokio::time::Instant::now();
                        let mut transitions = Vec::new();
                        if let (Ok(mut conn), Ok(mut eng)) = (act_db.lock(), act_engine.lock()) {
                            let _ = xmsg::activity::store::prune_ended_incarnations(&conn, now_s);
                            if let Ok(trs) = eng.tick_aging(&mut conn, &resolver, now_s, now_m) {
                                transitions = trs;
                            }
                        }
                        if !transitions.is_empty() {
                            let out: Vec<_> = transitions.into_iter().map(|tr| xmsg::observe::Observation {
                                kind: "activity_changed".to_owned(),
                                from: Some(tr.address),
                                body_availability: "not_recorded".to_owned(),
                                activity: Some(tr.descriptor),
                                ..Default::default()
                            }).collect();
                            act_obs.publish(out);
                        }
                    }
                }
            }
        }));
    }

    // Keys a stopped server left `pending` are settled before anything is served.
    {
        let conn = db.lock().map_err(|e| e.to_string())?;
        let settled = xmsg::observe_effects::autocommit_registered(&conn, |conn| {
            storage::reconcile_pending_keys(conn, &node_name)
        })
        .map_err(|e| format!("cannot settle pending idempotency keys: {e}"))?;
        if settled > 0 {
            info!(
                settled,
                "settled idempotency keys left pending by a stopped server"
            );
        }
    }

    let active_pull_loops = Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    let mut reloader_for_sighup: Option<Arc<xmsg::fed::CredentialReloader>> = None;

    let enrollment_hub_addr = fed_listener
        .as_ref()
        .map(|(_, address)| address.to_string());
    let discovery_listen = fed_listener.as_ref().map(|(_, address)| *address);
    let fed_state = if let Some(peers_file) = args.peers_file {
        let mut peers = xmsg::fed::PeersMap::load_from_file_for(&peers_file, own.as_ref())
            .map_err(|e| format!("failed to load peers file: {e}"))?;
        {
            let conn = db.lock().unwrap_or_else(|e| e.into_inner());
            xmsg::fed::startup_pairing_authority(&conn, &mut peers, &cert_der)
                .map_err(|e| format!("failed to apply pairing authority: {e}"))?;
        }
        let peers_arc = Arc::new(peers);

        if !args.leaf {
            for (peer_name, peer_cfg) in peers_arc.iter() {
                if peer_cfg.is_outbound() {
                    active_pull_loops.lock().unwrap().insert(peer_name.clone());
                }
            }
        }

        let fs = Arc::new(xmsg::fed::FedState {
            discovery: Default::default(),
            max_attachment_bytes: args.max_attachment_bytes,
            node_name: node_name.clone(),
            peers: peers_arc.clone().into(),
            cert_der: cert_der.clone(),
            cert_chain_der: cert_chain_der.clone(),
            key_der: key_der.clone(),
            rate_limiter: Arc::new(xmsg::fed::RateLimiter::new(60, 20)),
            db: db.clone(),
            sessions_dirs: sessions_dirs.clone(),
            agy_config: agy_config.clone(),
            agy_store: agy_store.clone(),
            pi_store: pi_store.clone(),
            pi_notify_tx: pi_notify_tx.clone(),
            svc_store: svc_store.clone(),
            svc_notify_tx: svc_notify_tx.clone(),
            notify_tx: notify_tx.clone(),
            max_body: args.max_body,
            is_leaf: args.leaf,
            leaf_principal: args.leaf_principal.clone(),
            outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
            dynamic_tls: Default::default(),
            reply_ttl,
            list_queries: Default::default(),
        });

        if let (Some(cert_path), Some(key_path)) = (&args.fed_cert, &args.fed_key) {
            let reloader = Arc::new(
                xmsg::fed::CredentialReloader::new_full(
                    cert_path.clone(),
                    key_path.clone(),
                    Some(peers_file.clone()),
                    own.clone(),
                    peers_arc.clone(),
                    Some(fs.clone()),
                    active_pull_loops.clone(),
                )
                .map_err(|e| format!("failed to initialize credential reloader: {e}"))?,
            );

            reloader_for_sighup = Some(reloader.clone());

            if args.fed_reload_interval_secs > 0 {
                reloader.start_watcher(Duration::from_secs(args.fed_reload_interval_secs));
            }
        }

        bg_tasks.push(xmsg::discovery::dial::spawn_sweep(&fs));

        if let Some((listener, listen_addr)) = fed_listener {
            let acceptor = match fs.get_tls_acceptor() {
                Some(a) => a,
                None => xmsg::fed::make_tls_acceptor(&fs.cert_chain(), &key_der, peers_arc.clone())
                    .map_err(|e| format!("failed to initialize federation TLS acceptor: {e}"))?,
            };
            let fs_clone = fs.clone();
            bg_tasks.push(tokio::spawn(async move {
                info!(listen = %listen_addr, "starting federation mTLS listener");
                if let Err(e) =
                    xmsg::fed::run_fed_listener_with_acceptor(listener, fs_clone, acceptor).await
                {
                    tracing::error!("federation listener error: {e}");
                }
            }));
        }

        Some(fs)
    } else {
        if fed_listener.is_some() {
            return Err("--fed-listen requires --peers-file".to_string().into());
        }
        None
    };

    if let Some(directory) = args.enroll_state {
        let reloader = reloader_for_sighup
            .clone()
            .ok_or("--enroll-state requires federation credentials and peers")?;
        bg_tasks.push(tokio::spawn(xmsg::enroll_cli::auto_renew(
            directory, reloader,
        )));
    }
    if let Some(address) = args.enroll_listen {
        use xmsg::enroll::Clock;
        let fed = fed_state
            .clone()
            .ok_or("enrollment requires federation state")?;
        let listener_address = enrollment_hub_addr.ok_or("enrollment requires --fed-listen")?;
        let ca = Arc::new(xmsg::enroll_ca::EnrollCa::open(
            args.enroll_ca_dir.as_ref().unwrap(),
            db.clone(),
            args.enroll_policy.as_ref().unwrap(),
            fed.node_name.clone(),
        )?);
        if args.leaf
            && ca
                .policy()
                .providers
                .values()
                .any(|provider| provider.device_enabled())
        {
            return Err("device enrollment requires the local UID-protected HTTP socket".into());
        }
        let hub_address = ca.policy().hub_address.clone().unwrap_or(listener_address);
        let (entry, _) = xmsg::enroll::hub_entry(&fed, &hub_address, xmsg::enroll::WallClock.now())
            .map_err(str::to_owned)?;
        let identity = ca.reserved_uri();
        let service = Arc::new(xmsg::enroll::Service::new(
            ca,
            fed,
            Arc::new(xmsg::enroll::WallClock),
            entry,
            identity,
        )?);
        if !args.leaf {
            service.register_local_approval()?;
        }
        let config = xmsg::enroll::tls_config(&service).map_err(|error| error.to_string())?;
        let listener = tokio::net::TcpListener::bind(address).await?;
        info!(listen = %listener.local_addr()?, "bound enrollment https listener");
        bg_tasks.push(tokio::spawn(async move {
            if xmsg::enroll::listen_with_config(listener, service, config)
                .await
                .is_err()
            {
                tracing::error!(
                    class = "enroll_listener_failed",
                    "enrollment listener stopped"
                );
            }
        }));
    }

    let mailbox_db = db.clone();
    let mailbox_peers = fed_state.clone();
    let maintenance_state_lock = state_lock.clone();
    let maintenance_runtime_dir = owner_record.runtime_dir.clone();
    bg_tasks.push(tokio::spawn(async move {
        let cadence = Duration::from_secs(mailbox_ttl.clamp(1, 600));
        let mut timer = tokio::time::interval(cadence);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        timer.tick().await;
        loop {
            timer.tick().await;
            if let Some(ref rt_rec) = maintenance_runtime_dir {
                match xmsg::runtime_lock::verify_and_restamp_runtime_marker(
                    &maintenance_state_lock,
                    rt_rec,
                    my_uid,
                ) {
                    Ok(true) => info!(
                        runtime_dir = %rt_rec.path.display(),
                        "re-stamped missing runtime identity.json marker under state lock"
                    ),
                    Ok(false) => {}
                    Err(e) => tracing::warn!("runtime marker verification failed: {e}"),
                }
            }
            let Ok(db) = mailbox_db.lock() else {
                break;
            };
            if xmsg::session_context::prune(&db, storage::now_epoch_secs()).is_err() {
                tracing::warn!("session context TTL purge failed");
            }
            if storage::purge_peer_mailbox(&db, mailbox_ttl).is_err() {
                tracing::warn!("peer mailbox TTL purge failed");
            }
            if let Some(state) = &mailbox_peers {
                if state
                    .current_peers()
                    .prune_admitted_clients(&db, storage::now_epoch_secs())
                    .is_err()
                {
                    tracing::warn!("admitted client prune failed");
                }
            }
        }
    }));

    let harnesses_reg = match args.harnesses_file {
        Some(ref path) => {
            let reg = xmsg::harnesses::HarnessRegistry::load_file(path)
                .map_err(|e| format!("failed to load --harnesses-file: {e}"))?;
            xmsg::harnesses::init_for_db(&db, reg)
        }
        None => xmsg::harnesses::HarnessRegistry::disabled(),
    };

    {
        let reloader_sighup = reloader_for_sighup.clone();
        let context_db = db.clone();
        let harnesses_sighup = harnesses_reg.clone();
        bg_tasks.push(tokio::spawn(async move {
            while sighup.recv().await.is_some() {
                info!("SIGHUP received, reloading configuration");
                let context_reload = context_db
                    .lock()
                    .ok()
                    .is_some_and(|db| apply_context_policy(&db).is_ok());
                if !context_reload {
                    tracing::error!("SIGHUP session context config reload failed");
                }
                let mut reloaded_any = false;
                if let Some(ref reloader) = reloader_sighup {
                    reloaded_any = true;
                    if let Err(e) = reloader.force_reload() {
                        tracing::error!("SIGHUP credential reload failed: {e}");
                    }
                }
                if harnesses_sighup.is_configured() {
                    reloaded_any = true;
                    if let Err(e) = harnesses_sighup.reload() {
                        tracing::error!(
                            "SIGHUP harnesses reload failed (retaining previous snapshot): {e}"
                        );
                    }
                }
                if !reloaded_any {
                    xmsg::systemd::notify_reloading();
                    xmsg::systemd::notify_ready_with_status("nothing to reload");
                }
            }
        }));
    }

    let state = Arc::new(AppState {
        sessions_dirs,
        agy_config: agy_config.clone(),
        agy_store: agy_store.clone(),
        pi_store: pi_store.clone(),
        pi_notify_tx: pi_notify_tx.clone(),
        svc_store: svc_store.clone(),
        svc_notify_tx: svc_notify_tx.clone(),
        node_name,
        max_body: args.max_body,
        max_attachment_bytes: args.max_attachment_bytes,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl,
        idempotency_ttl,
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: fed_state.clone(),
    });

    {
        let codex_homes = if args.codex_homes.is_empty() {
            if let Ok(env_home) = std::env::var("CODEX_HOME") {
                if !env_home.trim().is_empty() {
                    vec![xmsg::install_paths::expand_explicit_path(
                        std::path::Path::new(env_home.trim()),
                        &resolve_env,
                    )?]
                } else {
                    xmsg::install_paths::resolve_optional_home(&resolve_env)
                        .map(|h| vec![h.join(".codex")])
                        .unwrap_or_default()
                }
            } else {
                xmsg::install_paths::resolve_optional_home(&resolve_env)
                    .map(|h| vec![h.join(".codex")])
                    .unwrap_or_default()
            }
        } else {
            let mut expanded = Vec::with_capacity(args.codex_homes.len());
            for p in args.codex_homes {
                expanded.push(xmsg::install_paths::expand_explicit_path(&p, &resolve_env)?);
            }
            expanded
        };
        let codex_config = xmsg::codex::CodexConfig {
            trusted_codex_exes: args.codex_exes,
            codex_exe_strict: args.codex_exe_strict,
            codex_homes,
            proc_root: agy_config.proc_root.clone(),
            ..Default::default()
        };
        let enabled = !codex_config.trusted_codex_exes.is_empty();
        let _ = xmsg::codex::init_for_state(&state, codex_config);
        if enabled {
            bg_tasks.push(tokio::spawn(xmsg::codex::run_restart_recovery(
                state.clone(),
            )));
        }
    }

    let find_endpoint_lock =
        |ep_path: &std::path::Path| -> Option<&xmsg::runtime_lock::EndpointLock> {
            let lp = xmsg::runtime_lock::EndpointLock::lock_path_for(ep_path).ok()?;
            let canon_lp = xmsg::install_paths::canonicalize_best_effort(&lp).unwrap_or(lp);
            endpoint_lock_by_path
                .get(&canon_lp)
                .map(|&idx| &endpoint_locks[idx])
        };

    let attribution = if let Some(lifecycle_socket) = args.executor_lifecycle_socket {
        let query_socket = args.executor_attribution_sock.unwrap_or_else(|| {
            agent_sock_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("/"))
                .join("executor-attribution.sock")
        });
        Some(xmsg::caller_attribution::bind_unqualified(
            xmsg::caller_attribution::ServerConfig {
                query_socket,
                lifecycle_socket,
                expected_uid: my_uid,
            },
            state.clone(),
        )?)
    } else {
        None
    };

    // Initialize handoff observer channel before starting listeners/claim watchers so early
    // session observations are never dropped during synchronous socket publication.
    if !args.leaf {
        bg_tasks.push(xmsg::handoff::spawn(state.clone()));
    }

    if !args.leaf {
        if let Some(ref fs) = fed_state {
            for (peer_name, peer_cfg) in fs.current_peers().iter() {
                if peer_cfg.is_outbound() {
                    let fs_clone = fs.clone();
                    let peer_clone = peer_name.clone();
                    let active_clone = active_pull_loops.clone();
                    bg_tasks.push(tokio::spawn(async move {
                        xmsg::fed::run_outbound_peer_pull_loop(fs_clone, peer_clone.clone()).await;
                        active_clone.lock().unwrap().remove(&peer_clone);
                    }));
                }
            }
        }
    }

    let agent_ep = resolved.agent_sock.as_ref().expect("agent endpoint");
    let agent_listener = match activated.agent.take() {
        Some(listener) => listener,
        None => {
            let (listener, _) = xmsg::runtime_lock::bind_and_publish_socket(
                &state_lock,
                find_endpoint_lock(&agent_ep.path),
                &canon_state_root,
                agent_ep.name,
                &agent_ep.path,
                agent_ep.kind,
                &mut owner_record,
                my_uid,
            )?;
            listener
        }
    };
    let agent_state = state.clone();
    bg_tasks.push(tokio::spawn(async move {
        if let Err(e) =
            xmsg::agent::run_agent_server_with_listener(agent_listener, agent_state, my_uid).await
        {
            tracing::error!("agent server error: {e}");
        }
    }));

    if !args.leaf {
        let reg_ep = resolved.register_sock.as_ref().expect("register endpoint");
        let reg_listener = match activated.register.take() {
            Some(listener) => listener,
            None => {
                let (listener, _) = xmsg::runtime_lock::bind_and_publish_socket(
                    &state_lock,
                    find_endpoint_lock(&reg_ep.path),
                    &canon_state_root,
                    reg_ep.name,
                    &reg_ep.path,
                    reg_ep.kind,
                    &mut owner_record,
                    my_uid,
                )?;
                listener
            }
        };
        let reg_state = state.clone();
        let reg_trusted_svc_exes = trusted_svc_exes.clone();
        bg_tasks.push(tokio::spawn(async move {
            if let Err(e) = xmsg::agy::run_register_server_with_listener(
                reg_listener,
                reg_state,
                my_uid,
                reg_trusted_svc_exes,
            )
            .await
            {
                tracing::error!("register server error: {e}");
            }
        }));
    }

    let app = build_router(state.clone());

    if args.leaf {
        let leaf_ep = resolved
            .leaf_register_sock
            .as_ref()
            .expect("leaf_register endpoint");
        let leaf_reg_listener = match activated.register.take() {
            Some(listener) => listener,
            None => {
                let (listener, _) = xmsg::runtime_lock::bind_and_publish_socket(
                    &state_lock,
                    find_endpoint_lock(&leaf_ep.path),
                    &canon_state_root,
                    leaf_ep.name,
                    &leaf_ep.path,
                    leaf_ep.kind,
                    &mut owner_record,
                    my_uid,
                )?;
                listener
            }
        };
        let leaf_p = args.leaf_principal.clone().unwrap();
        let leaf_state = state.clone();

        bg_tasks.push(tokio::spawn(async move {
            if let Err(e) = xmsg::svc::run_leaf_register_server_with_listener(
                leaf_reg_listener,
                leaf_state,
                my_uid,
                leaf_p,
            )
            .await
            {
                tracing::error!("leaf register server error: {e}");
            }
        }));

        if let Some(ref fs) = fed_state {
            for peer_name in fs.current_peers().keys() {
                let fs_clone = fs.clone();
                let peer_clone = peer_name.clone();
                let leaf_p_clone = args.leaf_principal.clone().unwrap();
                let db_clone = db.clone();
                let svc_notify_tx_clone = svc_notify_tx.clone();
                bg_tasks.push(tokio::spawn(async move {
                    xmsg::svc::run_leaf_inbox_task(
                        fs_clone,
                        peer_clone,
                        leaf_p_clone,
                        db_clone,
                        svc_notify_tx_clone,
                    )
                    .await;
                }));
            }
        }

        let tcp_addr = args.listen.as_deref().unwrap();
        let tcp_listener = match activated.listen.take() {
            Some(listener) => listener,
            None => tokio::net::TcpListener::bind(tcp_addr).await?,
        };
        let actual_tcp_addr = tcp_listener.local_addr()?;
        info!(listen = %actual_tcp_addr, "starting leaf tcp http server");
        let mut shutdown_rx_leaf = shutdown_rx.clone();
        let leaf_task = tokio::spawn(async move {
            let server = axum::serve(tcp_listener, app);
            let shutdown_fut = async move {
                let _ = shutdown_rx_leaf.wait_for(|&v| v).await;
            };
            if let Err(e) = server.with_graceful_shutdown(shutdown_fut).await {
                tracing::error!("leaf tcp http server error: {e}");
            }
        });

        xmsg::discovery::spawn(fed_state.clone(), discovery_listen);
        xmsg::systemd::notify_ready();
        run_shutdown_drain(sigterm, sigint, shutdown_tx, bg_tasks, vec![leaf_task], db).await?;
        drop(endpoint_locks);
        drop(state_lock);
        return Ok(());
    }

    let mut server_tasks = Vec::new();

    if let Some(ref tcp_addr) = args.listen {
        let tcp_listener = match activated.listen.take() {
            Some(listener) => listener,
            None => tokio::net::TcpListener::bind(tcp_addr.as_str()).await?,
        };
        let actual_tcp_addr = tcp_listener.local_addr()?;
        info!(listen = %actual_tcp_addr, "bound tcp http server");
        let tcp_app = app.clone();
        let mut shutdown_rx_tcp = shutdown_rx.clone();
        server_tasks.push(tokio::spawn(async move {
            let server = axum::serve(tcp_listener, tcp_app);
            let shutdown_fut = async move {
                let _ = shutdown_rx_tcp.wait_for(|&v| v).await;
            };
            if let Err(e) = server.with_graceful_shutdown(shutdown_fut).await {
                tracing::error!("tcp http server error: {e}");
            }
        }));
    }

    let http_ep = resolved.http_sock.as_ref().expect("http endpoint");
    let ucred_listener = match activated.http.take() {
        Some(listener) => xmsg::http::adopt_ucred_unix_listener(listener, my_uid, None),
        None => {
            test_hold("http-sock-bind").await;
            let (listener, _) = xmsg::runtime_lock::bind_and_publish_socket(
                &state_lock,
                find_endpoint_lock(&http_ep.path),
                &canon_state_root,
                http_ep.name,
                &http_ep.path,
                http_ep.kind,
                &mut owner_record,
                my_uid,
            )?;
            xmsg::http::adopt_ucred_unix_listener(listener, my_uid, None)
        }
    };
    let unix_app = build_unix_router_with_enrollment(
        state.clone(),
        xmsg::ca_health::Config {
            enabled: Some(args.enroll_listen.is_some()),
            ca_dir: args.enroll_ca_dir.clone(),
        },
    );
    let mut shutdown_rx_unix = shutdown_rx.clone();
    server_tasks.push(tokio::spawn(async move {
        // A15: only http.sock carries the peer credentials a caller is traced by.
        let server = axum::serve(
            ucred_listener,
            unix_app.into_make_service_with_connect_info::<xmsg::http::HttpPeer>(),
        );
        let shutdown_fut = async move {
            let _ = shutdown_rx_unix.wait_for(|&v| v).await;
        };
        if let Err(e) = server.with_graceful_shutdown(shutdown_fut).await {
            tracing::error!("unix http server error: {e}");
        }
    }));

    if let Some(attribution) = attribution {
        let mut shutdown_rx_attribution = shutdown_rx.clone();
        server_tasks.push(tokio::spawn(async move {
            let _ = shutdown_rx_attribution.wait_for(|&value| value).await;
            attribution.stop();
        }));
    }

    xmsg::discovery::spawn(fed_state.clone(), discovery_listen);
    xmsg::systemd::notify_ready();
    run_shutdown_drain(sigterm, sigint, shutdown_tx, bg_tasks, server_tasks, db).await?;
    drop(endpoint_locks);
    drop(state_lock);
    Ok(())
}

/// Test seam: waits while `$XMSG_TEST_HOLD_DIR/<point>` exists, to widen a startup window.
#[cfg(feature = "test-hooks")]
async fn test_hold(point: &str) {
    if let Some(dir) = std::env::var_os("XMSG_TEST_HOLD_DIR") {
        let hold = std::path::Path::new(&dir).join(point);
        while hold.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

#[cfg(not(feature = "test-hooks"))]
#[inline(always)]
async fn test_hold(_point: &str) {}

fn detect_process_manager_hint() -> Option<String> {
    if std::env::var_os("INVOCATION_ID").is_some() {
        return Some("systemd_user".to_string());
    }
    if let Ok(xpc) = std::env::var("XPC_SERVICE_NAME") {
        if xpc.contains("homebrew.mxcl.xmsg") {
            return Some("homebrew_launchagent".to_string());
        }
    }
    Some("foreground".to_string())
}

async fn run_shutdown_drain(
    mut sigterm: tokio::signal::unix::Signal,
    mut sigint: tokio::signal::unix::Signal,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    bg_tasks: Vec<tokio::task::JoinHandle<()>>,
    server_tasks: Vec<tokio::task::JoinHandle<()>>,
    db: Arc<Mutex<rusqlite::Connection>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Wait for first signal
    let sig_name = tokio::select! {
        _ = sigterm.recv() => "SIGTERM",
        _ = sigint.recv() => "SIGINT",
    };
    xmsg::systemd::notify_stopping();
    info!("shutdown signal received ({sig_name}), starting graceful drain");

    // Spawn listener for second signal to exit immediately non-zero
    tokio::spawn(async move {
        tokio::select! {
            _ = sigterm.recv() => {
                tracing::warn!("second SIGTERM received during shutdown, exiting immediately");
                std::process::exit(128 + 15);
            }
            _ = sigint.recv() => {
                tracing::warn!("second SIGINT received during shutdown, exiting immediately");
                std::process::exit(128 + 2);
            }
        }
    });

    let _ = tokio::task::spawn_blocking(|| xmsg::discovery::stop(Duration::from_secs(1))).await;
    // 1. Notify axum servers to stop accepting connections and drain
    let _ = shutdown_tx.send(true);

    // 2. Stop pull loops and background listeners immediately
    for handle in bg_tasks {
        handle.abort();
    }

    // 3. Drain in-flight HTTP requests bounded by 5s
    // Rationale: local HTTP/IPC requests in xmsg take <10ms; 5s provides ample headroom
    // for in-flight requests and TLS handshakes while staying well under container stop
    // grace periods (e.g. 30s) to prevent SIGKILL.
    let drain_bound = Duration::from_secs(5);
    let servers_fut = async {
        for t in server_tasks {
            let _ = t.await;
        }
    };

    if tokio::time::timeout(drain_bound, servers_fut)
        .await
        .is_err()
    {
        tracing::warn!("drain timeout (5s) reached, completing shutdown");
    }

    // 4. Close database cleanly: checkpoint WAL to main db file
    if let Ok(conn) = db.lock() {
        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    }

    // 5. Log completion line and exit 0
    info!("shutdown complete, exiting cleanly");
    Ok(())
}

#[cfg(test)]
mod claude_install_cli_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{
        cell::RefCell,
        collections::BTreeMap,
        fs,
        os::unix::{
            fs::{symlink, DirBuilderExt, MetadataExt, PermissionsExt},
            process::CommandExt,
        },
        path::Path,
        process::{Child, Command, Output, Stdio},
        time::Instant,
    };

    #[derive(Clone)]
    pub(super) struct FixtureContext {
        pub(super) account_home: PathBuf,
        pub(super) policy_roots: Vec<PathBuf>,
    }
    thread_local! {
        static CONTEXT: RefCell<Option<FixtureContext>> = const { RefCell::new(None) };
    }
    pub(super) fn context() -> Option<FixtureContext> {
        CONTEXT.with(|context| context.borrow().clone())
    }

    struct OwnedProcess(Option<Child>);
    impl Drop for OwnedProcess {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                if child.try_wait().ok().flatten().is_none() {
                    if let Ok(pid) = i32::try_from(child.id()) {
                        if unsafe { libc::getpgid(pid) } == pid {
                            unsafe { libc::kill(-pid, libc::SIGKILL) };
                        }
                    }
                    let _ = child.kill();
                }
                let _ = child.wait();
            }
        }
    }

    fn fingerprint(root: &Path) -> BTreeMap<PathBuf, String> {
        fn collect(root: &Path, item: &Path, out: &mut BTreeMap<PathBuf, String>) {
            let meta = fs::symlink_metadata(item).unwrap();
            let content = if meta.is_file() {
                hex::encode(Sha256::digest(fs::read(item).unwrap()))
            } else {
                String::new()
            };
            out.insert(
                item.strip_prefix(root).unwrap().to_path_buf(),
                format!(
                    "{:?}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{content}",
                    meta.created().ok(),
                    meta.dev(),
                    meta.ino(),
                    meta.mode(),
                    meta.uid(),
                    meta.gid(),
                    meta.len(),
                    meta.mtime(),
                    meta.mtime_nsec(),
                    meta.ctime(),
                    meta.ctime_nsec()
                ),
            );
            if meta.is_dir() {
                for entry in fs::read_dir(item).unwrap() {
                    collect(root, &entry.unwrap().path(), out);
                }
            }
        }
        let mut out = BTreeMap::new();
        collect(root, root, &mut out);
        out
    }

    fn cli_child(home: &Path, lookup: &Path, policy: &Path, runtime: &Path) -> Output {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "claude_install_cli_tests::cli_process_fixture",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("HOME", home)
            .env("XDG_RUNTIME_DIR", runtime)
            .env("XMSG_CLAUDE_FIXTURE_ACCOUNT_HOME", lookup)
            .env("XMSG_CLAUDE_FIXTURE_POLICY_ROOT", policy)
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(marker) = std::env::var_os("NIX_BUILD_TOP") {
            command.env("NIX_BUILD_TOP", marker);
        }
        let mut child = OwnedProcess(Some(command.spawn().unwrap()));
        let deadline = Instant::now() + Duration::from_secs(20);
        while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "owned CLI fixture process did not finish"
            );
            std::thread::yield_now();
        }
        child.0.take().unwrap().wait_with_output().unwrap()
    }

    fn report(output: &Output) -> serde_json::Value {
        let text = String::from_utf8_lossy(&output.stdout);
        let reports = text
            .lines()
            .filter_map(|line| {
                line.find('{').and_then(|start| {
                    serde_json::from_str::<serde_json::Value>(&line[start..]).ok()
                })
            })
            .filter(|value| value["action"] == "install")
            .collect::<Vec<_>>();
        assert_eq!(
            reports.len(),
            1,
            "actual CLI did not emit exactly one install report: {output:?}"
        );
        reports.into_iter().next().unwrap()
    }

    #[test]
    #[ignore = "owned subprocess entry; executed and reaped by process_cli_repeat_and_home_aliases_keep_pins_and_metadata"]
    fn cli_process_fixture() {
        let account_home = std::env::var_os("XMSG_CLAUDE_FIXTURE_ACCOUNT_HOME")
            .map(PathBuf::from)
            .expect("fixture account home is required");
        let policy = std::env::var_os("XMSG_CLAUDE_FIXTURE_POLICY_ROOT")
            .map(PathBuf::from)
            .expect("fixture policy root is required");
        let lookup = xmsg::install_paths::FixtureHomeLookup(Some(account_home.clone()));
        let env = xmsg::install_paths::ResolveEnv::from_process(&lookup);
        let classification = match xmsg::install_paths::resolve_account_home(&env) {
            Ok(_) => "matched",
            Err(xmsg::install_paths::InstallError::HomeMismatch { .. }) => "home_mismatch",
            Err(_) => "other",
        };
        eprintln!("fixture-home-class={classification}");
        CONTEXT.with(|context| {
            *context.borrow_mut() = Some(FixtureContext {
                account_home,
                policy_roots: vec![policy],
            })
        });
        main_from_args(
            ["xmsg", "install", "claude", "--apply", "--json"].map(std::ffi::OsString::from),
        )
        .unwrap();
    }

    #[test]
    fn process_cli_repeat_and_home_aliases_keep_pins_and_metadata() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
        let canonical = fs::canonicalize(&home).unwrap();
        let policy = canonical.join("fixture-managed-policy");
        fs::DirBuilder::new().mode(0o700).create(&policy).unwrap();
        let runtime = tempfile::Builder::new()
            .prefix("cli-rt-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(fs::canonicalize("/tmp").unwrap())
            .unwrap();
        let mut native_var = false;
        #[cfg(target_os = "macos")]
        let native_raw = canonical
            .strip_prefix("/private/var/folders")
            .ok()
            .map(|suffix| Path::new("/var/folders").join(suffix));
        #[cfg(not(target_os = "macos"))]
        let native_raw: Option<PathBuf> = None;
        let raw = if let Some(raw) = native_raw {
            native_var = true;
            assert_eq!(fs::canonicalize(&raw).unwrap(), canonical);
            raw
        } else {
            let alias = root.path().join("raw-home");
            symlink(&canonical, &alias).unwrap();
            alias
        };
        eprintln!("cli-process-native-var-alias={native_var}");
        let cases = [(&raw, &raw), (&raw, &canonical), (&canonical, &raw)];
        let mut baseline_pins = None;
        for (index, (env_home, account_home)) in cases.into_iter().enumerate() {
            eprintln!("cli-process-case={index} fixture_HOME={env_home:?} fixture_account={account_home:?} canonical_target={canonical:?}");
            let before = fingerprint(&canonical);
            let first = cli_child(env_home, account_home, &policy, runtime.path());
            let first_report = report(&first);
            if !first.status.success() {
                assert!(
                    index != 0
                        && first.status.code() == Some(2)
                        && String::from_utf8_lossy(&first.stderr)
                            .contains("fixture-home-class=home_mismatch"),
                    "actual CLI failed unexpectedly: {first:?}"
                );
                assert_eq!(first_report["status"], "refused");
                assert_eq!(
                    fingerprint(&canonical),
                    before,
                    "refused home alias wrote files"
                );
                let second = cli_child(env_home, account_home, &policy, runtime.path());
                assert_eq!(second.status.code(), Some(2));
                assert!(String::from_utf8_lossy(&second.stderr)
                    .contains("fixture-home-class=home_mismatch"));
                assert_eq!(report(&second), first_report);
                assert_eq!(fingerprint(&canonical), before);
                continue;
            }
            assert_eq!(
                first_report["status"],
                if index == 0 { "applied" } else { "no_op" }
            );
            let mcp = fs::read(canonical.join(".claude.json")).unwrap();
            let hooks = fs::read(canonical.join(".claude/settings.json")).unwrap();
            let pins = (mcp, hooks);
            if let Some(baseline) = &baseline_pins {
                assert_eq!(
                    &pins, baseline,
                    "home aliases changed accepted command pins"
                );
            } else {
                baseline_pins = Some(pins.clone());
            }
            let installed = fingerprint(&canonical);
            let second = cli_child(env_home, account_home, &policy, runtime.path());
            assert!(
                second.status.success(),
                "second actual CLI failed: {second:?}"
            );
            assert_eq!(
                report(&second)["status"],
                "no_op",
                "identical process CLI inputs were not a no-op"
            );
            assert_eq!(
                fingerprint(&canonical),
                installed,
                "second process CLI rewrote content or metadata"
            );
            assert_eq!(fs::read(canonical.join(".claude.json")).unwrap(), pins.0);
            assert_eq!(
                fs::read(canonical.join(".claude/settings.json")).unwrap(),
                pins.1
            );
            eprintln!("cli-process-case={index} accepted identical-input second=no_op pins-and-metadata=unchanged");
        }
    }
    #[test]
    fn mcp_and_claude_hook_accept_literal_database_pin() {
        for arguments in [
            vec!["xmsg", "mcp", "--db-path", "/synthetic/state/xmsg.db"],
            vec![
                "xmsg",
                "register",
                "claude",
                "--hook",
                "--db-path",
                "/synthetic/state/xmsg.db",
            ],
        ] {
            assert!(
                Cli::try_parse_from(arguments).is_ok(),
                "installed harness command refused its literal database pin"
            );
        }
    }
}
