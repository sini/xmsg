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
    Serve(Box<ServeArgs>),

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

    /// Hook mode for agy PreInvocation
    #[arg(long)]
    pub hook: bool,

    /// URL of xmsg HTTP server (for checking session credentials in hook mode)
    #[arg(long, env = "XMSG_URL", default_value = "http://127.0.0.1:7787")]
    pub url: String,
}

#[derive(Parser, Debug)]
pub struct ServeArgs {
    /// Optional TCP listen address (IP:PORT), for environments like Kubernetes pods where loopback is a private netns. With no flag, no TCP socket is bound.
    #[arg(long, env = "XMSG_LISTEN")]
    pub listen: Option<String>,

    /// Path to unix domain socket for HTTP server (defaults to $XDG_RUNTIME_DIR/xmsg/http.sock; on macOS without it, the Darwin user temp dir)
    #[arg(long, env = "XMSG_HTTP_SOCK")]
    pub http_sock: Option<PathBuf>,

    /// Host label for sender envelope prefix (defaults to hostname)
    #[arg(long, env = "XMSG_HOST_LABEL")]
    pub host_label: Option<String>,

    /// Path to session metadata directory (repeatable, or separated by ':' in env XMSG_SESSIONS_DIR; defaults to ~/.claude/sessions)
    #[arg(
        long = "sessions-dir",
        env = "XMSG_SESSIONS_DIR",
        value_delimiter = ':'
    )]
    pub sessions_dirs: Vec<PathBuf>,

    /// Maximum request body size in bytes
    #[arg(long, env = "XMSG_MAX_BODY", default_value_t = 65536)]
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

    /// Trusted Node executable paths for Pi (defaults to accepting any executable named node/nodejs)
    #[arg(long = "pi-node-bin", env = "XMSG_PI_NODE_BIN", value_delimiter = ',')]
    pub pi_node_bins: Vec<PathBuf>,

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
        },
    }

    Ok(())
}

fn run_register_agy(args: RegisterAgyArgs) -> Result<(), Box<dyn std::error::Error>> {
    if args.hook {
        return run_hook_agy(args);
    }

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

fn check_session_has_credentials(
    sock_path: &std::path::Path,
    conv_id: &str,
    url: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    // First try Unix socket
    if let Ok(mut stream) = UnixStream::connect(sock_path) {
        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let payload = serde_json::json!({
            "action": "check",
            "conversation_id": conv_id,
        });
        if writeln!(stream, "{payload}").is_ok() && stream.flush().is_ok() {
            let mut reader = BufReader::new(stream);
            let mut resp = String::new();
            if reader.read_line(&mut resp).is_ok() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp) {
                    if let Some(b) = v
                        .get("hasCredentials")
                        .or_else(|| v.get("has_credentials"))
                        .and_then(|v| v.as_bool())
                    {
                        return Ok(b);
                    }
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
                            return Ok(reg);
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
            return Ok(reg);
        }
    }

    Ok(false)
}

fn run_hook_agy(args: RegisterAgyArgs) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;

    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("xmsg register agy notice: failed to read stdin: {e}");
        println!("{{}}");
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

    let has_credentials = match check_session_has_credentials(&sock_path, &conv_id, &args.url) {
        Ok(has) => has,
        Err(e) => {
            eprintln!("xmsg register agy notice: failed to check credentials: {e}");
            println!("{{}}");
            return Ok(());
        }
    };

    if has_credentials {
        println!("{{}}");
    } else {
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("xmsg"));
        let exe_str = exe.to_string_lossy();
        let sock_arg = match &args.sock {
            Some(s) => format!(" --sock {}", s.display()),
            None => String::new(),
        };
        let resp = serde_json::json!({
            "injectSteps": [
                {
                    "ephemeralMessage": format!(
                        "Please run `{} register agy{}` before anything else, and reply with nothing about it.",
                        exe_str, sock_arg
                    )
                }
            ]
        });
        println!("{resp}");
    }

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
    let sessions_dirs = resolve_sessions_dirs(args.sessions_dirs);
    let db_path = resolve_db_path(args.db_path);

    if let Some(parent) = db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }

    let http_sock_path = match args.http_sock {
        Some(p) => p,
        None => xmsg::http::default_http_sock_path()
            .map_err(|e| format!("cannot determine http socket path: {e}"))?,
    };

    info!(
        listen = ?args.listen,
        http_sock = %http_sock_path.display(),
        host_label = %host_label,
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
    let pi_entrypoints = args.pi_entrypoints;
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
    let reg_pi_node_bins = args.pi_node_bins.clone();
    let reg_sock = register_sock_path.clone();
    let reg_db = db.clone();
    let reg_pi_notify_tx = pi_notify_tx.clone();
    let reg_svc_store = svc_store.clone();
    let reg_trusted_svc_exes = trusted_svc_exes.clone();
    let reg_svc_notify_tx = svc_notify_tx.clone();
    let reply_ttl = Duration::from_secs(args.reply_ttl);
    let idempotency_ttl = Duration::from_secs(args.idempotency_ttl);

    tokio::spawn(async move {
        if let Err(e) = xmsg::agy::run_register_server(
            reg_sock,
            reg_config,
            reg_store,
            reg_pi_store,
            reg_pi_entrypoints,
            reg_pi_node_bins,
            reg_db,
            reg_pi_notify_tx,
            reply_ttl,
            my_uid,
            reg_svc_store,
            reg_trusted_svc_exes,
            reg_svc_notify_tx,
        )
        .await
        {
            tracing::error!("register server error: {e}");
        }
    });

    if (args.peers_file.is_some() || args.fed_listen.is_some())
        && (args.fed_cert.is_none() || args.fed_key.is_none())
    {
        return Err(
            "Federation requires both --fed-cert and --fed-key when --peers-file or --fed-listen is provided"
                .to_string()
                .into(),
        );
    }

    let fed_listener = if let Some(ref fed_listen_addr) = args.fed_listen {
        let addr: std::net::SocketAddr = fed_listen_addr
            .parse()
            .map_err(|e| format!("invalid --fed-listen address '{fed_listen_addr}': {e}"))?;
        if addr.ip().is_unspecified() {
            return Err(format!(
                "unspecified address '{}' is forbidden for --fed-listen",
                addr.ip()
            )
            .into());
        }
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("failed to bind federation listener on {fed_listen_addr}: {e}"))?;
        info!(listen = %fed_listen_addr, "bound federation mTLS listener");
        Some((listener, fed_listen_addr.clone()))
    } else {
        None
    };

    let (cert_der, key_der) =
        if let (Some(cert_path), Some(key_path)) = (args.fed_cert, args.fed_key) {
            let cert_pem = std::fs::read(&cert_path)
                .map_err(|e| format!("failed to read fed cert at {}: {e}", cert_path.display()))?;
            let key_pem = std::fs::read(&key_path)
                .map_err(|e| format!("failed to read fed key at {}: {e}", key_path.display()))?;

            use rustls::pki_types::pem::PemObject;
            let cert = rustls::pki_types::CertificateDer::from_pem_slice(&cert_pem)
                .map_err(|e| format!("failed to parse cert pem: {e}"))?;
            let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_pem)
                .map_err(|e| format!("failed to parse key pem: {e}"))?;
            (cert.to_vec(), key.secret_der().to_vec())
        } else {
            (Vec::new(), Vec::new())
        };

    let fed_state = if let Some(peers_file) = args.peers_file {
        let peers = xmsg::fed::load_peers_file(&peers_file)
            .map_err(|e| format!("failed to load peers file: {e}"))?;
        let peers_arc = Arc::new(peers);

        let fs = Arc::new(xmsg::fed::FedState {
            host_label: host_label.clone(),
            peers: peers_arc.clone(),
            cert_der: cert_der.clone(),
            key_der: key_der.clone(),
            rate_limiter: Arc::new(xmsg::fed::RateLimiter::new(60, 20)),
            db: db.clone(),
            sessions_dir: sessions_dirs.first().cloned().unwrap_or_default(),
            agy_config: agy_config.clone(),
            agy_store: agy_store.clone(),
            pi_store: pi_store.clone(),
            pi_notify_tx: pi_notify_tx.clone(),
            notify_tx: notify_tx.clone(),
            max_body: args.max_body,
        });

        if let Some((listener, listen_addr)) = fed_listener {
            let allowed_pins = Arc::new(peers_arc.allowed_pins());
            let acceptor = xmsg::fed::make_tls_acceptor(&cert_der, &key_der, allowed_pins)
                .map_err(|e| format!("failed to initialize federation TLS acceptor: {e}"))?;
            let fs_clone = fs.clone();
            tokio::spawn(async move {
                info!(listen = %listen_addr, "starting federation mTLS listener");
                if let Err(e) =
                    xmsg::fed::run_fed_listener_with_acceptor(listener, fs_clone, acceptor).await
                {
                    tracing::error!("federation listener error: {e}");
                }
            });
        }

        Some(fs)
    } else {
        if fed_listener.is_some() {
            return Err("--fed-listen requires --peers-file".to_string().into());
        }
        None
    };

    let state = Arc::new(AppState {
        sessions_dirs,
        agy_config,
        agy_store,
        pi_store,
        pi_notify_tx,
        svc_store,
        svc_notify_tx,
        host_label,
        max_body: args.max_body,
        request_counter: AtomicU64::new(1),
        db,
        notify_tx,
        reply_ttl,
        idempotency_ttl,
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state,
    });

    let agent_sock = agent_sock_path.clone();
    let agent_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = xmsg::agent::run_agent_server(agent_sock, agent_state, my_uid).await {
            tracing::error!("agent server error: {e}");
        }
    });

    let app = build_router(state);

    if let Some(ref tcp_addr) = args.listen {
        let tcp_listener = tokio::net::TcpListener::bind(tcp_addr).await?;
        let tcp_app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = axum::serve(tcp_listener, tcp_app).await {
                tracing::error!("tcp http server error: {e}");
            }
        });
    }

    let ucred_listener = xmsg::http::bind_ucred_unix_listener(&http_sock_path, my_uid, None)?;
    axum::serve(ucred_listener, app).await?;
    Ok(())
}
