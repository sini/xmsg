use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct McpConfig {
    pub sessions_dirs: Vec<PathBuf>,
    pub xmsg_url: String,
    pub http_sock: Option<PathBuf>,
    pub agent_sock: PathBuf,
    pub proc_root: PathBuf,
    pub presence_dir: PathBuf,
    pub proc_locks_path: PathBuf,
    pub reply_only: bool,
}

impl McpConfig {
    pub fn new(sessions_dirs: Vec<PathBuf>, xmsg_url: String) -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let agent_sock = std::env::var("XMSG_AGENT_SOCK")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                crate::agent::default_agent_sock_path()
                    .unwrap_or_else(|_| PathBuf::from("/nonexistent/agent.sock"))
            });
        let http_sock = std::env::var("XMSG_HTTP_SOCK")
            .map(PathBuf::from)
            .ok()
            .or_else(|| crate::http::default_http_sock_path().ok());
        Self {
            sessions_dirs,
            xmsg_url,
            http_sock,
            agent_sock,
            proc_root: PathBuf::from(crate::process::LIVE_PROC_ROOT),
            presence_dir: PathBuf::from(home).join(".gemini/antigravity-cli/presence"),
            proc_locks_path: PathBuf::from(crate::agy::LIVE_PROC_LOCKS),
            reply_only: false,
        }
    }

    pub fn with_agent_sock(mut self, agent_sock: PathBuf) -> Self {
        self.agent_sock = agent_sock;
        self
    }
}

pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2024-11-05"];
pub const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";

pub struct RegistrationWorkerGuard {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for RegistrationWorkerGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub fn spawn_registration_worker(
    config: &McpConfig,
    stop: Arc<AtomicBool>,
) -> io::Result<RegistrationWorkerGuard> {
    let config_clone = config.clone();
    let stop_clone = stop.clone();
    let handle = std::thread::Builder::new()
        .name("xmsg-mcp-reregister".to_string())
        .spawn(move || {
            run_registration_loop(&config_clone, stop_clone);
        })?;
    Ok(RegistrationWorkerGuard {
        stop,
        handle: Some(handle),
    })
}

enum RegResult {
    Ok(UnixStream),
    Unattested,
    Io,
}

fn connect_and_register(config: &McpConfig, stop: &AtomicBool) -> RegResult {
    if stop.load(Ordering::Relaxed) {
        return RegResult::Io;
    }

    let sock_path = &config.agent_sock;
    let my_uid = crate::agent::current_uid();
    if let Some(parent) = sock_path.parent() {
        if crate::agent::ensure_secure_socket_dir(parent, my_uid).is_err() {
            return RegResult::Io;
        }
    }

    let stream = match UnixStream::connect(sock_path) {
        Ok(s) => s,
        Err(_) => return RegResult::Io,
    };

    if stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .is_err()
        || stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .is_err()
    {
        return RegResult::Io;
    }

    let payload = json!({
        "action": "mcp_start",
        "schema_version": crate::surface::MCP_SCHEMA_VERSION,
    });
    let line = format!("{payload}\n");
    let mut writer = &stream;
    if writer.write_all(line.as_bytes()).is_err() || writer.flush().is_err() {
        return RegResult::Io;
    }

    let mut reader = BufReader::new(&stream);
    let mut resp_line = String::new();
    if reader.read_line(&mut resp_line).is_err() {
        return RegResult::Io;
    }

    let resp_val: Value = match serde_json::from_str(&resp_line) {
        Ok(v) => v,
        Err(_) => return RegResult::Io,
    };

    if resp_val.get("status").and_then(Value::as_str) == Some("ok") {
        RegResult::Ok(stream)
    } else {
        let err = resp_val.get("error").and_then(Value::as_str).unwrap_or("");
        if err == "unattested" {
            RegResult::Unattested
        } else {
            RegResult::Io
        }
    }
}

fn hold_connection(stream: &mut UnixStream, stop: &AtomicBool) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    let mut buf = [0u8; 64];
    while !stop.load(Ordering::Relaxed) {
        match stream.read(&mut buf) {
            Ok(0) => {
                tracing::debug!("xmsg agent socket EOF; will reconnect");
                break;
            }
            Ok(_) => {}
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                tracing::debug!("xmsg agent socket read error: {e}; will reconnect");
                break;
            }
        }
    }
}

fn sleep_with_stop_check(duration: Duration, stop: &AtomicBool) {
    let step = Duration::from_millis(50);
    let mut elapsed = Duration::ZERO;
    while elapsed < duration && !stop.load(Ordering::Relaxed) {
        let to_sleep = (duration - elapsed).min(step);
        std::thread::sleep(to_sleep);
        elapsed += to_sleep;
    }
}

fn run_registration_loop(config: &McpConfig, stop: Arc<AtomicBool>) {
    let min_backoff = Duration::from_millis(100);
    let max_backoff = Duration::from_secs(1);
    let mut backoff = min_backoff;
    let mut consecutive_unattested = 0;

    while !stop.load(Ordering::Relaxed) {
        match connect_and_register(config, &stop) {
            RegResult::Ok(mut stream) => {
                backoff = min_backoff;
                consecutive_unattested = 0;
                hold_connection(&mut stream, &stop);
            }
            RegResult::Unattested => {
                consecutive_unattested += 1;
                let delay = if consecutive_unattested > 5 {
                    Duration::from_secs(5)
                } else {
                    backoff
                };
                sleep_with_stop_check(delay, &stop);
                backoff = (backoff * 2).min(max_backoff);
            }
            RegResult::Io => {
                sleep_with_stop_check(backoff, &stop);
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}

pub fn run_mcp_loop<R: BufRead, W: Write>(
    config: &McpConfig,
    mut reader: R,
    mut writer: W,
) -> io::Result<()> {
    // Attempt to register caller identity with agent server at MCP startup
    let _ = call_agent_sock(
        &config.agent_sock,
        &json!({
            "action": "mcp_start",
            "schema_version": crate::surface::MCP_SCHEMA_VERSION,
        }),
    );

    // Spawn background worker to hold connection and re-register if server restarts
    let stop = Arc::new(AtomicBool::new(false));
    let _worker_guard = spawn_registration_worker(config, stop)?;

    let client = reqwest::blocking::Client::new();
    let mut line = String::new();
    while reader.read_line(&mut line)? > 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        let msg: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": format!("parse error: {e}") }
                });
                writeln!(writer, "{}", serde_json::to_string(&err_resp)?)?;
                writer.flush()?;
                line.clear();
                continue;
            }
        };

        if let Some(resp) = handle_jsonrpc(config, &client, &msg) {
            writeln!(writer, "{}", serde_json::to_string(&resp)?)?;
            writer.flush()?;
        }

        line.clear();
    }

    Ok(())
}

pub fn handle_jsonrpc(
    config: &McpConfig,
    client: &reqwest::blocking::Client,
    msg: &Value,
) -> Option<Value> {
    let method = msg.get("method").and_then(Value::as_str)?;
    let id = msg.get("id").cloned();

    match method {
        "initialize" => id.map(|id| {
            let client_version = msg
                .get("params")
                .and_then(|p| p.get("protocolVersion"))
                .and_then(Value::as_str);

            let protocol_version = match client_version {
                Some(v) if SUPPORTED_PROTOCOL_VERSIONS.contains(&v) => v,
                _ => DEFAULT_PROTOCOL_VERSION,
            };

            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": protocol_version,
                    "capabilities": {
                        "tools": { "listChanged": false }
                    },
                    "serverInfo": {
                        "name": "xmsg",
                        "version": "0.1.0"
                    }
                }
            })
        }),
        "notifications/initialized" | "notifications/cancelled" => None,
        "ping" => id.map(|id| {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {}
            })
        }),
        "tools/list" => id.map(|id| {
            let tools: Vec<Value> = tool_definitions()
                .into_iter()
                .filter(|t| {
                    !config.reply_only
                        || REPLY_ONLY_TOOLS.contains(&t["name"].as_str().unwrap_or(""))
                })
                .collect();
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": tools
                }
            })
        }),
        "tools/call" => id.map(|id| {
            let params = msg.get("params");
            let name = params
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let args = params
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(json!({}));

            let res = execute_tool(config, client, name, &args);
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": res
            })
        }),
        _ => id.map(|id| {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("method not found: {method}") }
            })
        }),
    }
}

fn tool_ok(text: String) -> Value {
    json!({
        "content": [{ "type": "text", "text": text }],
        "isError": false
    })
}

fn tool_err(text: String) -> Value {
    json!({
        "content": [{ "type": "text", "text": text }],
        "isError": true
    })
}

fn call_agent_sock(sock_path: &std::path::Path, payload: &Value) -> Result<Value, String> {
    call_agent_sock_within(sock_path, payload, Duration::from_secs(5))
}

fn call_agent_sock_within(
    sock_path: &std::path::Path,
    payload: &Value,
    read_timeout: Duration,
) -> Result<Value, String> {
    let my_uid = crate::agent::current_uid();
    if let Some(parent) = sock_path.parent() {
        crate::agent::ensure_secure_socket_dir(parent, my_uid)
            .map_err(|e| format!("insecure agent socket directory: {e}"))?;
    }

    let mut stream = UnixStream::connect(sock_path).map_err(|e| {
        format!(
            "failed to connect to agent socket at {}: {e}",
            sock_path.display()
        )
    })?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|e| e.to_string())?;

    let line = format!("{payload}\n");
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("failed to write to agent socket: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("failed to flush agent socket: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    reader
        .read_line(&mut resp_line)
        .map_err(|e| format!("failed to read response from agent socket: {e}"))?;

    let resp_val: Value = serde_json::from_str(&resp_line)
        .map_err(|e| format!("invalid response JSON from agent socket: {e}"))?;

    if resp_val.get("status").and_then(Value::as_str) == Some("error") {
        let err_kind = resp_val
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("error");
        let detail = resp_val
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        Err(format!("{err_kind}: {detail}"))
    } else {
        Ok(resp_val)
    }
}

/// The tools reply-only mode offers.
pub const REPLY_ONLY_TOOLS: &[&str] = &["reply", "replies"];

/// A13's four tools. MCP carries no `idempotency_key`: agents don't retry a send by
/// accident, and programs that retry use HTTP or `agent.sock`.
pub fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "list",
            "description": "List the recipients you can message, on this node and every node it can reach. By default (`status` omitted or \"live\"), shows only live recipients, each carrying `registered_at` (epoch seconds when it registered on its node). With `status: \"inactive\"`, shows parked and closed instances seen within `within` seconds (default 86400 = 24h, capped at the reply TTL), each carrying `last_seen` (a peer older than XL1 lists no inactive entries). Each entry gives its address (`id@node` for an instance, `name@node` for a service), kind (`service` or `instance`), label, status (`live`, `parked` or `closed`), user, and `registered_at` or `last_seen`; `nodes` gives each node asked as `ok`, `unreachable` or `timeout` (a node that withholds list is `unreachable`, detail `withholds list`). Filter by `name`, `node` or `kind`; `node` asks only that node.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Only recipients with this label or service name" },
                    "node": { "type": "string", "description": "Ask only this node (this one or a federated peer)" },
                    "kind": { "type": "string", "enum": ["service", "instance"], "description": "Only services or only instances" },
                    "status": { "type": "string", "enum": ["live", "inactive"], "description": "Whether to list live recipients (default) or inactive (parked and closed) instances" },
                    "within": { "type": "integer", "minimum": 0, "description": "For status='inactive', include entries seen within this many seconds (default 86400 = 24h, capped at reply TTL)" }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "send",
            "description": "Send a message. `to` is an instance ID (a UUID, optionally ~n), a service name or an instance label, optionally followed by @node to reach another node (one @ at most). A name resolves among services first and only when exactly one live recipient carries it; otherwise the error lists the candidates. Returns the message ID, the resolved address (use it for follow-ups) and the outcome. Your identity is derived from your session; replies are pushed to you.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "to": { "type": "string", "description": "<id or name>[@<node>]" },
                    "text": { "type": "string", "description": "Message content" }
                },
                "required": ["to", "text"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "reply",
            "description": "Reply to a message you received, by its message_id. Your identity is derived from your session.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "message_id": { "type": "string", "description": "ID of the message being replied to" },
                    "text": { "type": "string", "description": "Reply text" }
                },
                "required": ["message_id", "text"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "replies",
            "description": "Read the stored replies to a message you sent, waiting up to `wait` seconds (at most 60) for the first. Use it after a restart or a missed push, or to send and then block for the answer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "message_id": { "type": "string", "description": "ID of the message you sent" },
                    "wait": { "type": "integer", "minimum": 0, "description": "Seconds to wait for a first reply (capped at 60)" }
                },
                "required": ["message_id"],
                "additionalProperties": false
            }
        }),
    ]
}

/// Refuses an argument the tool's schema does not declare.
fn check_args(name: &str, args: &Value) -> Result<(), String> {
    let allowed: Vec<String> = tool_definitions()
        .into_iter()
        .find(|t| t["name"] == name)
        .and_then(|t| t["inputSchema"]["properties"].as_object().cloned())
        .map(|p| p.keys().cloned().collect())
        .unwrap_or_default();
    match args.as_object() {
        Some(obj) => match obj.keys().find(|k| !allowed.contains(k)) {
            // Invariant: a caller-supplied sender is refused (§8.3a).
            Some(k) if k == "from" => Err("error: 'from' argument is forbidden; sender identity is automatically derived from the calling session".to_string()),
            Some(k) if name == "send" && k == "ref" => Err("error: unknown argument 'ref' for tool 'send'; use 'to' instead".to_string()),
            Some(k) if name == "list" && k == "host" => Err("error: unknown argument 'host' for tool 'list'; use 'node' instead (or omit it to list all nodes)".to_string()),
            Some(k) => Err(format!("error: unknown argument '{k}' for tool '{name}'")),
            None => Ok(()),
        },
        None => Err(format!("error: arguments for tool '{name}' must be an object")),
    }
}

/// Runs one `agent.sock` frame for a tool; the result is the frame's `key` member, or the
/// whole answer without its `status` when `key` is `None`.
fn agent_tool(
    config: &McpConfig,
    payload: &Value,
    key: Option<&str>,
    read_timeout: Duration,
) -> Value {
    match call_agent_sock_within(&config.agent_sock, payload, read_timeout) {
        Ok(mut resp) => {
            if let Some(obj) = resp.as_object_mut() {
                obj.remove("status");
            }
            let result = match key {
                Some(k) => resp.get(k).cloned().unwrap_or(Value::Null),
                None => resp,
            };
            tool_ok(result.to_string())
        }
        Err(e) => tool_err(e),
    }
}

pub fn execute_tool(
    config: &McpConfig,
    client: &reqwest::blocking::Client,
    name: &str,
    args: &Value,
) -> Value {
    if config.reply_only && !REPLY_ONLY_TOOLS.contains(&name) {
        return tool_err(format!("tool '{name}' is not available in reply-only mode"));
    }
    if !tool_definitions().iter().any(|t| t["name"] == name) {
        return tool_err(format!("unknown tool: {name}"));
    }
    if let Err(e) = check_args(name, args) {
        return tool_err(e);
    }
    let str_arg = |k: &str| args.get(k).and_then(Value::as_str);

    match name {
        "list" => {
            let mut url = reqwest::Url::parse("http://xmsg/v1/recipients").expect("static url");
            for k in ["name", "node", "kind", "status"] {
                if let Some(v) = str_arg(k) {
                    url.query_pairs_mut().append_pair(k, v);
                }
            }
            if let Some(within_val) = args.get("within") {
                match within_val.as_u64() {
                    Some(w) => {
                        url.query_pairs_mut().append_pair("within", &w.to_string());
                    }
                    None => {
                        return tool_err("error: 'within' must be a non-negative integer".to_string());
                    }
                }
            }
            let path = match url.query() {
                Some(q) => format!("{}?{q}", url.path()),
                None => url.path().to_string(),
            };
            let sock_path = config
                .http_sock
                .clone()
                .or_else(|| crate::http::default_http_sock_path().ok());
            if let Some(ref sock) = sock_path {
                if sock.exists() {
                    match crate::http::http_get_unix(sock, &path) {
                        Ok((status, text)) if status.is_success() => return tool_ok(text),
                        Ok((status, text)) => return tool_err(format!("HTTP {status}: {text}")),
                        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                            tracing::warn!(
                                "http.sock list request failed, falling back to TCP: {e}"
                            )
                        }
                        Err(e) => tracing::debug!("failed to query http.sock for list: {e}"),
                    }
                }
            }

            let url = format!("{}{path}", config.xmsg_url.trim_end_matches('/'));
            match client.get(&url).send() {
                Ok(resp) => {
                    let status = resp.status();
                    let text = resp.text().unwrap_or_default();
                    if status.is_success() {
                        tool_ok(text)
                    } else {
                        tool_err(format!("HTTP {status}: {text}"))
                    }
                }
                Err(e) => tool_err(format!("failed to connect to xmsg server at {url}: {e}")),
            }
        }
        "send" => {
            let (Some(to), Some(text)) = (str_arg("to"), str_arg("text")) else {
                return tool_err("missing required string arguments 'to' and 'text'".to_string());
            };
            let payload = json!({
                "action": "send",
                "schema_version": crate::surface::MCP_SCHEMA_VERSION,
                "to": to,
                "text": text,
            });
            agent_tool(config, &payload, None, Duration::from_secs(5))
        }
        "reply" => {
            let (Some(message_id), Some(text)) = (str_arg("message_id"), str_arg("text")) else {
                return tool_err(
                    "missing required string arguments 'message_id' and 'text'".to_string(),
                );
            };
            let payload = json!({
                "action": "reply",
                "schema_version": crate::surface::MCP_SCHEMA_VERSION,
                "message_id": message_id,
                "text": text,
            });
            // NOTE (XU1 Gate 4 / Amendment 6): MCP tool result is reshaped to
            // {bytes, messageId, inReplyTo, outcome} to save model context and unify
            // messageId meaning ("the id of what I just sent"). The agent-socket and
            // HTTP reply frames retain ReplyRecord (with pushedMessageId and text)
            // so external callers (such as matrix-xmsg) continue reading pushedMessageId.
            match call_agent_sock_within(&config.agent_sock, &payload, Duration::from_secs(5)) {
                Ok(resp) => {
                    let reply_val = resp.get("reply").cloned().unwrap_or(Value::Null);
                    let new_id = match reply_val
                        .get("pushedMessageId")
                        .and_then(Value::as_str)
                    {
                        Some(id) => id,
                        None => {
                            return tool_err(
                                "reply failed: missing 'pushedMessageId' in socket response"
                                    .to_string(),
                            );
                        }
                    };
                    let outcome = match reply_val.get("pushOutcome").and_then(Value::as_str) {
                        Some(o) => o,
                        None => {
                            return tool_err(
                                "reply failed: missing 'pushOutcome' in socket response".to_string(),
                            );
                        }
                    };
                    let mcp_res = json!({
                        "bytes": text.len(),
                        "messageId": new_id,
                        "inReplyTo": message_id,
                        "outcome": outcome,
                    });
                    tool_ok(mcp_res.to_string())
                }
                Err(e) => tool_err(e),
            }
        }
        "replies" => {
            let Some(message_id) = str_arg("message_id") else {
                return tool_err("missing required string argument 'message_id'".to_string());
            };
            let wait = args
                .get("wait")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .min(crate::surface::MAX_WAIT_SECS);
            let payload = json!({
                "action": "replies",
                "schema_version": crate::surface::MCP_SCHEMA_VERSION,
                "message_id": message_id,
                "wait": wait,
            });
            agent_tool(
                config,
                &payload,
                Some("replies"),
                Duration::from_secs(wait + 5),
            )
        }
        _ => tool_err(format!("unknown tool: {name}")),
    }
}
