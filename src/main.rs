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
}

#[derive(Parser, Debug)]
pub struct McpArgs {
    /// Path to session metadata directory (defaults to ~/.claude/sessions)
    #[arg(long, env = "XMSG_SESSIONS_DIR")]
    pub sessions_dir: Option<PathBuf>,

    /// URL of xmsg HTTP server
    #[arg(long, env = "XMSG_URL", default_value = "http://127.0.0.1:7787")]
    pub xmsg_url: String,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve(args) => {
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
            storage::init_db(&conn)?;

            let (notify_tx, _) = broadcast::channel(1024);

            let state = Arc::new(AppState {
                sessions_dir,
                host_label,
                max_body: args.max_body,
                request_counter: AtomicU64::new(1),
                db: Arc::new(Mutex::new(conn)),
                notify_tx,
                reply_ttl: Duration::from_secs(args.reply_ttl),
            });

            let app = build_router(state);
            let listener = tokio::net::TcpListener::bind(&args.listen).await?;
            axum::serve(listener, app).await?;
        }
        Commands::Mcp(args) => {
            let sessions_dir = resolve_sessions_dir(args.sessions_dir);
            let config = McpConfig::new(sessions_dir, args.xmsg_url);
            let stdin = io::stdin();
            let stdout = io::stdout();
            run_mcp_loop(&config, stdin.lock(), stdout.lock())?;
        }
    }

    Ok(())
}
