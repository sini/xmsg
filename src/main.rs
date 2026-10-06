use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;

use xmsg::http::{build_router, AppState};

#[derive(Parser, Debug)]
#[command(name = "xmsg", version, about = "Fast, lightweight local HTTP bridge into live agent sessions")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the HTTP bridge server
    Serve(ServeArgs),
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Serve(args) => {
            let host_label = args.host_label.unwrap_or_else(|| {
                gethostname::gethostname().to_string_lossy().to_string()
            });
            let sessions_dir = resolve_sessions_dir(args.sessions_dir);

            info!(
                listen = %args.listen,
                host_label = %host_label,
                sessions_dir = %sessions_dir.display(),
                max_body = args.max_body,
                "starting xmsg server"
            );

            let state = Arc::new(AppState {
                sessions_dir,
                host_label,
                max_body: args.max_body,
                request_counter: AtomicU64::new(1),
            });

            let app = build_router(state);
            let listener = tokio::net::TcpListener::bind(&args.listen).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}
