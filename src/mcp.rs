use crate::registry;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct McpConfig {
    pub sessions_dir: PathBuf,
    pub xmsg_url: String,
    pub proc_root: PathBuf,
}

impl McpConfig {
    pub fn new(sessions_dir: PathBuf, xmsg_url: String) -> Self {
        Self {
            sessions_dir,
            xmsg_url,
            proc_root: PathBuf::from("/proc"),
        }
    }
}

pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2024-11-05"];
pub const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";

pub fn run_mcp_loop<R: BufRead, W: Write>(
    config: &McpConfig,
    mut reader: R,
    mut writer: W,
) -> io::Result<()> {
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
                                    "text": { "type": "string", "description": "Message content" }
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

            // Derive caller identity via ancestor walk
            let caller = match registry::find_ancestor_session_in(
                &config.proc_root,
                &config.sessions_dir,
                std::process::id(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    return tool_err(format!("failed to derive caller session identity: {e}"))
                }
            };

            let from_name = caller.name.unwrap_or(caller.session_id);

            let url = format!("{}/v1/sessions/{}/messages", config.xmsg_url, target_ref);
            let payload = json!({
                "from": from_name,
                "text": text
            });

            match client.post(&url).json(&payload).send() {
                Ok(resp) => {
                    let status = resp.status();
                    let resp_text = resp.text().unwrap_or_default();
                    if status.is_success() {
                        tool_ok(resp_text)
                    } else {
                        tool_err(format!("HTTP {status}: {resp_text}"))
                    }
                }
                Err(e) => tool_err(format!("failed to connect to xmsg server at {url}: {e}")),
            }
        }
        "reply" => {
            let Some(message_id) = args.get("message_id").and_then(Value::as_str) else {
                return tool_err("missing required string argument 'message_id'".to_string());
            };
            let Some(text) = args.get("text").and_then(Value::as_str) else {
                return tool_err("missing required string argument 'text'".to_string());
            };

            // Derive caller identity via ancestor walk
            let caller = match registry::find_ancestor_session_in(
                &config.proc_root,
                &config.sessions_dir,
                std::process::id(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    return tool_err(format!("failed to derive caller session identity: {e}"))
                }
            };

            let url = format!("{}/v1/messages/{}/replies", config.xmsg_url, message_id);
            let payload = json!({
                "sessionRef": caller.session_id,
                "text": text
            });

            match client.post(&url).json(&payload).send() {
                Ok(resp) => {
                    let status = resp.status();
                    let resp_text = resp.text().unwrap_or_default();
                    if status.is_success() {
                        tool_ok(resp_text)
                    } else {
                        tool_err(format!("HTTP {status}: {resp_text}"))
                    }
                }
                Err(e) => tool_err(format!("failed to connect to xmsg server at {url}: {e}")),
            }
        }
        _ => tool_err(format!("unknown tool: {name}")),
    }
}
