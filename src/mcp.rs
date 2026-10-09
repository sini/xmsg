use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct McpConfig {
    pub sessions_dirs: Vec<PathBuf>,
    pub xmsg_url: String,
    pub agent_sock: PathBuf,
    pub proc_root: PathBuf,
    pub presence_dir: PathBuf,
    pub proc_locks_path: PathBuf,
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
        Self {
            sessions_dirs,
            xmsg_url,
            agent_sock,
            proc_root: PathBuf::from(crate::process::LIVE_PROC_ROOT),
            presence_dir: PathBuf::from(home).join(".gemini/antigravity-cli/presence"),
            proc_locks_path: PathBuf::from(crate::agy::LIVE_PROC_LOCKS),
        }
    }

    pub fn with_agent_sock(mut self, agent_sock: PathBuf) -> Self {
        self.agent_sock = agent_sock;
        self
    }
}

pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2024-11-05"];
pub const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";

pub fn run_mcp_loop<R: BufRead, W: Write>(
    config: &McpConfig,
    mut reader: R,
    mut writer: W,
) -> io::Result<()> {
    // Attempt to register caller identity with agent server at MCP startup
    let _ = call_agent_sock(&config.agent_sock, &json!({ "action": "mcp_start" }));

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

fn handle_jsonrpc(
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
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {
                            "name": "list",
                            "description": "List active agent sessions on the local host",
                            "inputSchema": {
                                "type": "object",
                                "properties": {},
                                "additionalProperties": false
                            }
                        },
                        {
                            "name": "send",
                            "description": "Send a message to a session by ID, PID, or name. Sender identity is automatically derived from the calling session.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "ref": { "type": "string", "description": "Target session ID, PID, or name" },
                                    "text": { "type": "string", "description": "Message content" },
                                    "push_replies": { "type": "boolean", "description": "Whether to push replies back to the sender session (default: true). Set false for poll-only replies." }
                                },
                                "required": ["ref", "text"],
                                "additionalProperties": false
                            }
                        },
                        {
                            "name": "reply",
                            "description": "Reply to a received message by message_id. Sender identity is automatically derived from the calling session.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "message_id": { "type": "string", "description": "ID of the message being replied to" },
                                    "text": { "type": "string", "description": "Reply text" }
                                },
                                "required": ["message_id", "text"],
                                "additionalProperties": false
                            }
                        }
                    ]
                }
            })
        }),
        "tools/call" => id.map(|id| {
            let params = msg.get("params");
            let name = params.and_then(|p| p.get("name")).and_then(Value::as_str).unwrap_or("");
            let args = params.and_then(|p| p.get("arguments")).cloned().unwrap_or(json!({}));

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
    let my_uid = crate::agent::current_uid();
    if let Some(parent) = sock_path.parent() {
        crate::agent::ensure_secure_socket_dir(parent, my_uid)
            .map_err(|e| format!("insecure agent socket directory: {e}"))?;
    }

    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

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
        .set_read_timeout(Some(Duration::from_secs(5)))
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

fn execute_tool(
    config: &McpConfig,
    client: &reqwest::blocking::Client,
    name: &str,
    args: &Value,
) -> Value {
    match name {
        "list" => {
            let url = format!("{}/v1/sessions", config.xmsg_url);
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
            // Invariant: Reject any caller-supplied 'from' argument (§8.3a)
            if args.get("from").is_some() {
                return tool_err("error: 'from' argument is forbidden; sender identity is automatically derived from the calling session".to_string());
            }

            let Some(target_ref) = args.get("ref").and_then(Value::as_str) else {
                return tool_err("missing required string argument 'ref'".to_string());
            };
            let Some(text) = args.get("text").and_then(Value::as_str) else {
                return tool_err("missing required string argument 'text'".to_string());
            };
            let push_replies = args
                .get("push_replies")
                .and_then(Value::as_bool)
                .unwrap_or(true);

            let payload = json!({
                "action": "send",
                "ref": target_ref,
                "text": text,
                "push_replies": push_replies,
            });

            match call_agent_sock(&config.agent_sock, &payload) {
                Ok(resp) => {
                    let delivery_val = resp.get("delivery").cloned().unwrap_or(resp);
                    tool_ok(delivery_val.to_string())
                }
                Err(e) => tool_err(e),
            }
        }
        "reply" => {
            let Some(message_id) = args.get("message_id").and_then(Value::as_str) else {
                return tool_err("missing required string argument 'message_id'".to_string());
            };
            let Some(text) = args.get("text").and_then(Value::as_str) else {
                return tool_err("missing required string argument 'text'".to_string());
            };

            let payload = json!({
                "action": "reply",
                "messageId": message_id,
                "text": text
            });

            match call_agent_sock(&config.agent_sock, &payload) {
                Ok(resp) => {
                    let reply_val = resp.get("reply").cloned().unwrap_or(resp);
                    tool_ok(reply_val.to_string())
                }
                Err(e) => tool_err(e),
            }
        }
        _ => tool_err(format!("unknown tool: {name}")),
    }
}
