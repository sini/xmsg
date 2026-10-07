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
use xmsg::storage;

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
    /// Start the HTTP bridge server
    Serve(ServeArgs),

    /// Run the stdio MCP server for agent harnesses
    Mcp(McpArgs),

    /// Register credentials with running xmsg server
    Register(RegisterArgs),
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
}

#[derive(Parser, Debug)]
pub struct RegisterAgyArgs {
    /// Registration socket path (defaults to $XDG_RUNTIME_DIR/xmsg/register.sock; on macOS without it, the Darwin user temp dir)
    #[arg(long, env = "XMSG_REGISTER_SOCK")]
    pub sock: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct ServeArgs {
    /// Listen address (IP:PORT)
    #[arg(long, env = "XMSG_LISTEN", default_value = "127.0.0.1:7787")]
    pub listen: String,

    /// Host label for sender envelope prefix (defaults to hostname)
    #[arg(long, env = "XMSG_HOST_LABEL")]
    pub host_label: Option<String>,

    /// Path to session metadata directory (defaults to ~/.claude/sessions)
    #[arg(long, env = "XMSG_SESSIONS_DIR")]
    pub sessions_dir: Option<PathBuf>,

    /// Maximum request body size in bytes
    #[arg(long, env = "XMSG_MAX_BODY", default_value_t = 65536)]
    pub max_body: usize,

    /// Path to SQLite database
    #[arg(long, env = "XMSG_DB_PATH")]
    pub db_path: Option<PathBuf>,

    /// Reply TTL in seconds (default 7 days: 604800)
    #[arg(long, env = "XMSG_REPLY_TTL", default_value_t = 604800)]
    pub reply_ttl: u64,

    /// Registration socket path (defaults to $XDG_RUNTIME_DIR/xmsg/register.sock; on macOS without it, the Darwin user temp dir)
    #[arg(long, env = "XMSG_REGISTER_SOCK")]
    pub register_sock: Option<PathBuf>,

    /// Agent socket path (defaults to $XDG_RUNTIME_DIR/xmsg/agent.sock; on macOS without it, the Darwin user temp dir)
    #[arg(long, env = "XMSG_AGENT_SOCK")]
    pub agent_sock: Option<PathBuf>,

    /// Trusted Antigravity executable paths (comma-separated or multiple flags)
    #[arg(long = "agy-exe", env = "XMSG_AGY_EXE", value_delimiter = ',')]
    pub agy_exes: Vec<PathBuf>,

    /// Trusted Pi entrypoint script paths (comma-separated or multiple flags)
    #[arg(
        long = "pi-entrypoint",
        env = "XMSG_PI_ENTRYPOINT",
        value_delimiter = ','
    )]
    pub pi_entrypoints: Vec<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct McpArgs {
    /// Path to session metadata directory (defaults to ~/.claude/sessions)
    #[arg(long, env = "XMSG_SESSIONS_DIR")]
    pub sessions_dir: Option<PathBuf>,

    /// URL of xmsg HTTP server
    #[arg(long, env = "XMSG_URL", default_value = "http://127.0.0.1:7787")]
    pub xmsg_url: String,

    /// Agent socket path (defaults to $XDG_RUNTIME_DIR/xmsg/agent.sock; on macOS without it, the Darwin user temp dir)
    #[arg(long, env = "XMSG_AGENT_SOCK")]
    pub agent_sock: Option<PathBuf>,
}

fn resolve_sessions_dir(dir: Option<PathBuf>) -> PathBuf {
    match dir {
        Some(p) => {
            if let Ok(stripped) = p.strip_prefix("~/") {
                if let Ok(home) = std::env::var("HOME") {
                    return PathBuf::from(home).join(stripped);
                }
            }
            p
        }
        None => {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".claude").join("sessions")
        }
    }
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
        Commands::Serve(args) => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(run_serve(args))?;
        }
        Commands::Mcp(args) => {
            let sessions_dir = resolve_sessions_dir(args.sessions_dir);
            let mut config = McpConfig::new(sessions_dir, args.xmsg_url);
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
        },
    }

    Ok(())
}

fn run_register_agy(args: RegisterAgyArgs) -> Result<(), Box<dyn std::error::Error>> {
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
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
                    .unwrap_or("unknown error");
                return Err(format!("registration rejected by server: {detail}").into());
            }
        }
        Ok(())
    })();

    if let Err(e) = result {
        eprintln!("xmsg register agy notice: {e}");
    }

    println!("{{\"injectSteps\":[]}}");
    Ok(())
}

async fn run_serve(args: ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let host_label = args
        .host_label
        .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().to_string());
    let sessions_dir = resolve_sessions_dir(args.sessions_dir);
    let db_path = resolve_db_path(args.db_path);

    if let Some(parent) = db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }

    info!(
        listen = %args.listen,
        host_label = %host_label,
        sessions_dir = %sessions_dir.display(),
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

    let agy_config = xmsg::agy::AgyConfig {
        trusted_agy_exes: args.agy_exes,
        ..Default::default()
    };
    let pi_entrypoints = args.pi_entrypoints;
    let agy_store = xmsg::agy::new_agy_store();
    let pi_store = xmsg::pi::new_pi_store();
    let my_uid = xmsg::agent::current_uid();
    let register_sock_path = match args.register_sock {
        Some(p) => p,
        None => xmsg::agent::default_register_sock_path()
            .map_err(|e| format!("cannot determine register socket path: {e}"))?,
    };
    let agent_sock_path = match args.agent_sock {
        Some(p) => p,
        None => xmsg::agent::default_agent_sock_path()
            .map_err(|e| format!("cannot determine agent socket path: {e}"))?,
    };

    let reg_config = agy_config.clone();
    let reg_store = agy_store.clone();
    let reg_pi_store = pi_store.clone();
    let reg_pi_entrypoints = pi_entrypoints.clone();
    let reg_sock = register_sock_path.clone();
    let reg_db = db.clone();
    let reg_pi_notify_tx = pi_notify_tx.clone();
    let reply_ttl = Duration::from_secs(args.reply_ttl);

    tokio::spawn(async move {
        if let Err(e) = xmsg::agy::run_register_server(
            reg_sock,
            reg_config,
            reg_store,
            reg_pi_store,
            reg_pi_entrypoints,
            reg_db,
            reg_pi_notify_tx,
            reply_ttl,
            my_uid,
        )
        .await
        {
            tracing::error!("register server error: {e}");
        }
    });

    let state = Arc::new(AppState {
        sessions_dir,
        agy_config,
        agy_store,
        pi_store,
        pi_notify_tx,
        host_label,
        max_body: args.max_body,
        request_counter: AtomicU64::new(1),
        db,
        notify_tx,
        reply_ttl,
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
    });

    let agent_sock = agent_sock_path.clone();
    let agent_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = xmsg::agent::run_agent_server(agent_sock, agent_state, my_uid).await {
            tracing::error!("agent server error: {e}");
        }
    });

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
