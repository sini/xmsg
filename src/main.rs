use clap::{Parser, Subcommand};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::info;
use tracing_subscriber::EnvFilter;

use xmsg::http::{build_router, AppState};
use xmsg::mcp::{run_mcp_loop, McpConfig};
use xmsg::registry::resolve_sessions_dirs;
use xmsg::storage;

mod operator;
mod service_exec;

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

#[derive(Subcommand, Debug)]
enum Commands {
    /// List mesh recipients and node status
    List(operator::ListArgs),

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

    /// Agent socket path (defaults to $XDG_RUNTIME_DIR/xmsg/agent.sock)
    #[arg(long, env = "XMSG_AGENT_SOCK")]
    pub sock: Option<PathBuf>,
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

    /// Registration socket path (defaults to $XDG_RUNTIME_DIR/xmsg/register.sock; on macOS without it, the Darwin user temp dir)
    #[arg(long, env = "XMSG_REGISTER_SOCK")]
    pub register_sock: Option<PathBuf>,

    /// Agent socket path (defaults to $XDG_RUNTIME_DIR/xmsg/agent.sock; on macOS without it, the Darwin user temp dir)
    #[arg(long, env = "XMSG_AGENT_SOCK")]
    pub agent_sock: Option<PathBuf>,

    /// Leaf register socket path (defaults to $XDG_RUNTIME_DIR/xmsg/register.sock)
    #[arg(long, env = "XMSG_LEAF_REGISTER_SOCK")]
    pub leaf_register_sock: Option<PathBuf>,

    /// Trusted Antigravity executable paths (comma-separated or multiple flags)
    #[arg(long = "agy-exe", env = "XMSG_AGY_EXE", value_delimiter = ',')]
    pub agy_exes: Vec<PathBuf>,

    /// Trusted Codex executable paths (comma-separated or multiple flags)
    #[arg(long = "codex-exe", env = "XMSG_CODEX_EXE", value_delimiter = ',')]
    pub codex_exes: Vec<PathBuf>,

    /// Trusted Codex home directories (repeatable, or separated by ':' in env XMSG_CODEX_HOME; defaults to $CODEX_HOME or ~/.codex)
    #[arg(long = "codex-home", env = "XMSG_CODEX_HOME", value_delimiter = ':')]
    pub codex_homes: Vec<PathBuf>,

    /// Trusted Svc daemon executable paths per name (format: NAME=PATH, repeatable or comma-separated)
    #[arg(long = "svc-exe", env = "XMSG_SVC_EXE", value_delimiter = ',')]
    pub svc_exes: Vec<String>,

    /// Path to peers configuration file (JSON)
    #[arg(long, env = "XMSG_PEERS_FILE")]
    pub peers_file: Option<PathBuf>,

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
}

#[derive(Parser, Debug)]
pub struct McpArgs {
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

    /// Agent socket path (defaults to $XDG_RUNTIME_DIR/xmsg/agent.sock; on macOS without it, the Darwin user temp dir)
    #[arg(long, env = "XMSG_AGENT_SOCK")]
    pub agent_sock: Option<PathBuf>,

    /// Expose only the reply tool (no list, no send)
    #[arg(long, env = "XMSG_REPLY_ONLY")]
    pub reply_only: bool,
}

fn resolve_db_path(path: Option<PathBuf>) -> PathBuf {
    match path {
        Some(p) => {
            if let Ok(stripped) = p.strip_prefix("~/") {
                if let Ok(home) = std::env::var("HOME") {
                    return PathBuf::from(home).join(stripped);
                }
            }
            p
        }
        None => {
            if let Ok(state_home) = std::env::var("XDG_STATE_HOME") {
                PathBuf::from(state_home).join("xmsg").join("xmsg.db")
            } else {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                PathBuf::from(home)
                    .join(".local")
                    .join("state")
                    .join("xmsg")
                    .join("xmsg.db")
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::List(args) => operator::list(args)?,
        Commands::Send(args) => operator::send(args)?,
        Commands::Replies(args) => operator::replies(args)?,
        Commands::Show(args) => operator::show(args)?,

        Commands::Service(args) => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(service_exec::run(args))?;
        }
        Commands::Serve(args) => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(run_serve(*args))?;
        }
        Commands::Mcp(args) => {
            let sessions_dirs = resolve_sessions_dirs(args.sessions_dirs);
            let mut config = McpConfig::new(sessions_dirs, args.xmsg_url);
            config.reply_only = args.reply_only;
            if let Some(sock) = args.http_sock {
                config.http_sock = Some(sock);
            }
            if let Some(sock) = args.agent_sock {
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
            xmsg::fed::PeersMap::load_from_file_for(&args.peers_file, own.as_ref())
                .map_err(|e| format!("peers file {}: {e}", args.peers_file.display()))?;
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
    match xmsg::agent::run_claude_hook(&input, args.sock.as_deref()) {
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

async fn run_serve(args: ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
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
    let sessions_dirs = resolve_sessions_dirs(args.sessions_dirs);
    let db_path = resolve_db_path(args.db_path);

    if let Some(parent) = db_path.parent() {
        let _ = xmsg::agent::create_private_dir(parent);
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }

    let http_sock_path = match args.http_sock {
        Some(p) => p,
        None => xmsg::http::default_http_sock_path()
            .map_err(|e| format!("cannot determine http socket path: {e}"))?,
    };

    info!(
        http_sock = %http_sock_path.display(),
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

    let db = Arc::new(Mutex::new(conn));
    let (notify_tx, _) = broadcast::channel(1024);
    let (pi_notify_tx, _) = broadcast::channel(1024);
    let (svc_notify_tx, _) = broadcast::channel(1024);

    let agy_config = xmsg::agy::AgyConfig {
        trusted_agy_exes: args.agy_exes,
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

    let my_uid = xmsg::agent::current_uid();
    let register_sock_path = match &args.register_sock {
        Some(p) => p.clone(),
        None => xmsg::agent::default_register_sock_path()
            .map_err(|e| format!("cannot determine register socket path: {e}"))?,
    };
    let leaf_reg_sock_path = if args.leaf {
        Some(
            args.leaf_register_sock
                .clone()
                .or_else(|| args.register_sock.clone())
                .unwrap_or_else(|| register_sock_path.clone()),
        )
    } else {
        None
    };
    let agent_sock_path = match args.agent_sock {
        Some(p) => p,
        None => leaf_reg_sock_path
            .as_ref()
            .and_then(|p| p.parent().map(|d| d.join("agent.sock")))
            .map(Ok)
            .unwrap_or_else(xmsg::agent::default_agent_sock_path)
            .map_err(|e| format!("cannot determine agent socket path: {e}"))?,
    };

    let reply_ttl = Duration::from_secs(args.reply_ttl);
    let idempotency_ttl = Duration::from_secs(args.idempotency_ttl);
    storage::set_svc_queue_cap(&db, args.svc_queue_cap);

    let sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut bg_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

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

    // Keys a stopped server left `pending` are settled before anything is served.
    {
        let conn = db.lock().map_err(|e| e.to_string())?;
        let settled = storage::reconcile_pending_keys(&conn, &node_name)
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

    let fed_state = if let Some(peers_file) = args.peers_file {
        let peers = xmsg::fed::PeersMap::load_from_file_for(&peers_file, own.as_ref())
            .map_err(|e| format!("failed to load peers file: {e}"))?;
        let peers_arc = Arc::new(peers);

        for (peer_name, peer_cfg) in peers_arc.iter() {
            if peer_cfg.is_outbound() {
                active_pull_loops.lock().unwrap().insert(peer_name.clone());
            }
        }

        let fs = Arc::new(xmsg::fed::FedState {
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

    {
        let reloader_sighup = reloader_for_sighup.clone();
        bg_tasks.push(tokio::spawn(async move {
            while sighup.recv().await.is_some() {
                info!("SIGHUP received, reloading configuration");
                if let Some(ref reloader) = reloader_sighup {
                    if let Err(e) = reloader.force_reload() {
                        tracing::error!("SIGHUP credential reload failed: {e}");
                    }
                } else {
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
                    vec![PathBuf::from(env_home)]
                } else if let Ok(home) = std::env::var("HOME") {
                    vec![PathBuf::from(home).join(".codex")]
                } else {
                    Vec::new()
                }
            } else if let Ok(home) = std::env::var("HOME") {
                vec![PathBuf::from(home).join(".codex")]
            } else {
                Vec::new()
            }
        } else {
            args.codex_homes
                .into_iter()
                .map(|p| {
                    if let Ok(stripped) = p.strip_prefix("~/") {
                        if let Ok(home) = std::env::var("HOME") {
                            return PathBuf::from(home).join(stripped);
                        }
                    }
                    p
                })
                .collect()
        };
        let codex_config = xmsg::codex::CodexConfig {
            trusted_codex_exes: args.codex_exes,
            codex_homes,
            proc_root: agy_config.proc_root.clone(),
        };
        let _ = xmsg::codex::init_for_state(&state, codex_config);
    }

    let agent_listener = match activated.agent.take() {
        Some(listener) => listener,
        None => xmsg::agent::bind_agent_listener(&agent_sock_path, my_uid).await?,
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
        let reg_listener = match activated.register.take() {
            Some(listener) => listener,
            None => xmsg::agy::bind_register_listener(&register_sock_path, my_uid).await?,
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

        if let Some(ref fs) = fed_state {
            bg_tasks.push(xmsg::handoff::spawn(state.clone()));
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

    let app = build_router(state.clone());

    if args.leaf {
        let leaf_reg_sock = leaf_reg_sock_path.expect("leaf_reg_sock_path");
        let leaf_reg_listener = match activated.register.take() {
            Some(listener) => listener,
            None => xmsg::svc::bind_leaf_register_listener(&leaf_reg_sock, my_uid)?,
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

        xmsg::systemd::notify_ready();
        run_shutdown_drain(sigterm, sigint, shutdown_tx, bg_tasks, vec![leaf_task], db).await?;
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

    let ucred_listener = match activated.http.take() {
        Some(listener) => xmsg::http::adopt_ucred_unix_listener(listener, my_uid, None),
        None => xmsg::http::bind_ucred_unix_listener(&http_sock_path, my_uid, None)?,
    };
    let mut shutdown_rx_unix = shutdown_rx.clone();
    server_tasks.push(tokio::spawn(async move {
        // A15: only http.sock carries the peer credentials a caller is traced by.
        let server = axum::serve(
            ucred_listener,
            app.into_make_service_with_connect_info::<xmsg::http::HttpPeer>(),
        );
        let shutdown_fut = async move {
            let _ = shutdown_rx_unix.wait_for(|&v| v).await;
        };
        if let Err(e) = server.with_graceful_shutdown(shutdown_fut).await {
            tracing::error!("unix http server error: {e}");
        }
    }));

    xmsg::systemd::notify_ready();
    run_shutdown_drain(sigterm, sigint, shutdown_tx, bg_tasks, server_tasks, db).await?;
    Ok(())
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
