use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{timeout_at, Instant};

/// Maximum size in bytes of any single WebSocket frame or JSON-RPC message on the relay.
pub const MAX_RELAY_FRAME_BYTES: usize = 1_048_576;

/// Maximum wall-clock time for a single relay handoff attempt (§2.4: 2 seconds).
pub const RELAY_HANDOFF_TIMEOUT: Duration = Duration::from_secs(2);

/// Typed input for a single restricted Codex relay delivery (§2.4).
///
/// Constructed exclusively by the xmsg server after target resolution. Callers,
/// models, hooks, and remote peers cannot supply an upstream method, endpoint,
/// response ID, policy, callback, or thread selector.
#[derive(Debug, Clone)]
pub struct CodexDeliveryJob {
    pub root_id: String,
    pub root_generation: u64,
    pub codex_home: PathBuf,
    pub owner_pid: u32,
    pub owner_starttime: String,
    pub message_id: String,
    pub rendered_envelope: String,
    pub proc_root: PathBuf,
}

/// Outcome of a single relay delivery attempt (§2.4, §2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayOutcome {
    /// Matching `turn/start` result received and peer/lease revalidated.
    Accepted { turn_id: Option<String> },
    /// No reachable endpoint for `O`, or `P` is not in `thread/loaded/list` (queue-only).
    QueueOnly { reason: String },
    /// Explicit pre-write rejection or explicit JSON-RPC error refusal from upstream;
    /// safe to release `inflight -> pending` for hook drain.
    Rejected { reason: String },
    /// Timeout, EOF, oversized frame, or post-write validation failure after `turn/start`
    /// bytes may have been sent; must transition `inflight -> unknown` (`delivery_unknown`).
    Uncertain { reason: String },
}

#[derive(Serialize)]
struct InitializeRequest<'a> {
    jsonrpc: &'static str,
    id: &'a str,
    method: &'static str,
    params: InitializeParams<'a>,
}

#[derive(Serialize)]
struct InitializeParams<'a> {
    #[serde(rename = "clientInfo")]
    client_info: ClientInfo<'a>,
    capabilities: InitializeCapabilities,
}

#[derive(Serialize)]
struct ClientInfo<'a> {
    name: &'a str,
    version: &'a str,
}

#[derive(Serialize)]
struct InitializeCapabilities {
    #[serde(rename = "experimentalApi")]
    experimental_api: bool,
}

#[derive(Serialize)]
struct InitializedNotification {
    jsonrpc: &'static str,
    method: &'static str,
}

#[derive(Serialize)]
struct LoadedListRequest<'a> {
    jsonrpc: &'static str,
    id: &'a str,
    method: &'static str,
    params: LoadedListParams<'a>,
}

#[derive(Serialize)]
struct LoadedListParams<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<&'a str>,
}

/// The only application request the restricted relay can ever emit (§2.4).
#[derive(Serialize)]
struct TurnStartRequest<'a> {
    jsonrpc: &'static str,
    id: &'a str,
    method: &'static str,
    params: TurnStartParams<'a>,
}

#[derive(Serialize)]
struct TurnStartParams<'a> {
    #[serde(rename = "threadId")]
    thread_id: &'a str,
    input: [TurnStartTextInput<'a>; 1],
}

#[derive(Serialize)]
struct TurnStartTextInput<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    text: &'a str,
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Validate and resolve `<H>/app-server-control/app-server-control.sock` against the
/// canonical trusted home `H` and effective UID (§2.4 step 1).
pub fn resolve_validated_control_socket(codex_home: &Path) -> std::result::Result<PathBuf, String> {
    let euid = effective_uid();
    let canon_home = std::fs::canonicalize(codex_home).map_err(|e| {
        format!(
            "cannot canonicalize codex home {}: {e}",
            codex_home.display()
        )
    })?;
    let home_meta = std::fs::symlink_metadata(&canon_home)
        .map_err(|e| format!("cannot stat codex home {}: {e}", canon_home.display()))?;
    if !home_meta.is_dir() || home_meta.uid() != euid {
        return Err("codex home is not a directory owned by current uid".to_string());
    }

    let ctrl_dir = canon_home.join("app-server-control");
    let ctrl_meta = std::fs::symlink_metadata(&ctrl_dir)
        .map_err(|e| format!("app-server-control directory missing: {e}"))?;
    if ctrl_meta.file_type().is_symlink() || !ctrl_meta.is_dir() {
        return Err("app-server-control is not a real directory".to_string());
    }
    if ctrl_meta.uid() != euid {
        return Err("app-server-control directory is not owned by current uid".to_string());
    }
    if (ctrl_meta.mode() & 0o077) != 0 {
        return Err(format!(
            "app-server-control directory has overly broad permissions {:o}",
            ctrl_meta.mode() & 0o777
        ));
    }
    let canon_ctrl = std::fs::canonicalize(&ctrl_dir)
        .map_err(|e| format!("cannot canonicalize app-server-control: {e}"))?;
    if !canon_ctrl.starts_with(&canon_home) || canon_ctrl != ctrl_dir {
        return Err("app-server-control escapes canonical codex home".to_string());
    }

    let rendezvous_path = canon_ctrl.join("app-server-control.sock");
    let rendezvous_meta = std::fs::symlink_metadata(&rendezvous_path)
        .map_err(|e| format!("app-server-control.sock missing: {e}"))?;
    if rendezvous_meta.uid() != euid {
        return Err("app-server-control.sock rendezvous is not owned by current uid".to_string());
    }

    let sock_path = if rendezvous_meta.file_type().is_symlink() {
        std::fs::canonicalize(&rendezvous_path)
            .map_err(|e| format!("cannot canonicalize app-server-control.sock target: {e}"))?
    } else {
        rendezvous_path
    };

    let sock_meta = std::fs::symlink_metadata(&sock_path)
        .map_err(|e| format!("resolved app-server-control.sock missing: {e}"))?;
    if sock_meta.file_type().is_symlink() {
        return Err("resolved app-server-control.sock must not be a symlink".to_string());
    }
    if (sock_meta.mode() & libc::S_IFMT) != libc::S_IFSOCK {
        return Err("app-server-control.sock is not a unix socket".to_string());
    }
    if sock_meta.uid() != euid {
        return Err("app-server-control.sock is not owned by current uid".to_string());
    }
    if (sock_meta.mode() & 0o077) != 0 {
        return Err(format!(
            "app-server-control.sock has overly broad permissions {:o}",
            sock_meta.mode() & 0o777
        ));
    }

    let Some(sock_parent) = sock_path.parent() else {
        return Err("app-server-control.sock has no parent directory".to_string());
    };
    let parent_meta = std::fs::symlink_metadata(sock_parent)
        .map_err(|e| format!("app-server-control.sock parent missing: {e}"))?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        return Err("app-server-control.sock parent is not a real directory".to_string());
    }
    if parent_meta.uid() != euid {
        return Err("app-server-control.sock parent is not owned by current uid".to_string());
    }
    if (parent_meta.mode() & 0o077) != 0 {
        return Err(format!(
            "app-server-control.sock parent has overly broad permissions {:o}",
            parent_meta.mode() & 0o777
        ));
    }

    Ok(sock_path)
}

/// Verify that the connected `UnixStream` peer matches the expected owner `(pid, starttime)`
/// and current UID (§2.4 step 2).
fn verify_stream_peer(
    stream: &UnixStream,
    proc_root: &Path,
    expected_pid: u32,
    expected_starttime: &str,
) -> std::result::Result<(), String> {
    let creds = crate::process::peer_cred(stream)
        .map_err(|e| format!("SO_PEERCRED failed on app-server-control.sock: {e}"))?;
    let euid = effective_uid();
    if creds.uid != euid {
        return Err(format!(
            "socket peer uid {} != effective uid {}",
            creds.uid, euid
        ));
    }
    let peer_pid = creds.pid_or_zero();
    if peer_pid != expected_pid {
        return Err(format!(
            "socket peer pid {peer_pid} != admitted owner pid {expected_pid}"
        ));
    }
    if !creds.is_alive(proc_root, expected_starttime) {
        return Err(format!(
            "socket peer pid {peer_pid} does not match admitted owner starttime {expected_starttime}"
        ));
    }
    Ok(())
}

/// Perform client WebSocket upgrade on `stream` before `deadline`.
async fn ws_client_handshake(
    stream: &mut UnixStream,
    deadline: Instant,
) -> std::result::Result<Vec<u8>, String> {
    let req = b"GET / HTTP/1.1\r\n\
Host: localhost\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\r\n";

    timeout_at(deadline, stream.write_all(req))
        .await
        .map_err(|_| "timeout writing websocket upgrade".to_string())?
        .map_err(|e| format!("error writing websocket upgrade: {e}"))?;

    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 256];
    loop {
        if buf.len() > 16_384 {
            return Err("websocket upgrade response headers exceeded 16 KiB".to_string());
        }
        let n = timeout_at(deadline, stream.read(&mut chunk))
            .await
            .map_err(|_| "timeout reading websocket upgrade".to_string())?
            .map_err(|e| format!("error reading websocket upgrade: {e}"))?;
        if n == 0 {
            return Err("eof during websocket upgrade".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_bytes = &buf[..pos];
            let header_str = std::str::from_utf8(header_bytes)
                .map_err(|_| "non-utf8 websocket upgrade headers".to_string())?;
            let first_line = header_str.lines().next().unwrap_or("");
            if !first_line.contains("101") {
                return Err(format!("websocket upgrade rejected: {first_line}"));
            }
            let leftover = buf[pos + 4..].to_vec();
            return Ok(leftover);
        }
    }
}

/// Write a masked client WebSocket text frame (`opcode = 0x1`, `FIN = 1`).
async fn ws_write_text_frame(
    stream: &mut UnixStream,
    payload: &[u8],
    deadline: Instant,
) -> std::result::Result<(), String> {
    if payload.len() > MAX_RELAY_FRAME_BYTES {
        return Err(format!(
            "outbound frame {} bytes exceeds 1 MiB cap",
            payload.len()
        ));
    }
    let mut mask = [0u8; 4];
    getrandom::fill(&mut mask).map_err(|e| format!("getrandom failed: {e}"))?;

    let len = payload.len();
    let mut frame = Vec::with_capacity(14 + len);
    frame.push(0x81); // FIN=1, opcode=1 (text)
    if len < 126 {
        frame.push(0x80 | (len as u8));
    } else if len <= 65535 {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    for (i, &b) in payload.iter().enumerate() {
        frame.push(b ^ mask[i & 3]);
    }

    timeout_at(deadline, stream.write_all(&frame))
        .await
        .map_err(|_| "timeout writing websocket frame".to_string())?
        .map_err(|e| format!("error writing websocket frame: {e}"))
}

async fn read_exact_buffered(
    stream: &mut UnixStream,
    leftover: &mut Vec<u8>,
    n: usize,
    deadline: Instant,
) -> std::result::Result<Vec<u8>, String> {
    while leftover.len() < n {
        let mut tmp = [0u8; 4096];
        let got = timeout_at(deadline, stream.read(&mut tmp))
            .await
            .map_err(|_| "timeout reading websocket frame".to_string())?
            .map_err(|e| format!("error reading websocket frame: {e}"))?;
        if got == 0 {
            return Err("eof reading websocket frame".to_string());
        }
        leftover.extend_from_slice(&tmp[..got]);
    }
    let out: Vec<u8> = leftover.drain(..n).collect();
    Ok(out)
}

/// Read the next WebSocket text frame (`opcode = 0x1`) from `stream`, assembling fragmented
/// frames if any and enforcing the 1 MiB cap (`MAX_RELAY_FRAME_BYTES`).
async fn ws_read_text_frame(
    stream: &mut UnixStream,
    leftover: &mut Vec<u8>,
    deadline: Instant,
) -> std::result::Result<String, String> {
    let mut assembled = Vec::new();
    let mut collecting_fragments = false;

    loop {
        let hdr = read_exact_buffered(stream, leftover, 2, deadline).await?;
        let fin = (hdr[0] & 0x80) != 0;
        let opcode = hdr[0] & 0x0f;
        let masked = (hdr[1] & 0x80) != 0;
        let mut len = (hdr[1] & 0x7f) as usize;

        if len == 126 {
            let ext = read_exact_buffered(stream, leftover, 2, deadline).await?;
            len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
        } else if len == 127 {
            let ext = read_exact_buffered(stream, leftover, 8, deadline).await?;
            let len64 = u64::from_be_bytes([
                ext[0], ext[1], ext[2], ext[3], ext[4], ext[5], ext[6], ext[7],
            ]);
            if len64 > MAX_RELAY_FRAME_BYTES as u64 {
                return Err(format!(
                    "inbound websocket frame {len64} bytes exceeds 1 MiB cap"
                ));
            }
            len = len64 as usize;
        }

        if len > MAX_RELAY_FRAME_BYTES
            || assembled.len().saturating_add(len) > MAX_RELAY_FRAME_BYTES
        {
            return Err("inbound websocket message exceeds 1 MiB cap".to_string());
        }

        let mask = if masked {
            let m = read_exact_buffered(stream, leftover, 4, deadline).await?;
            Some([m[0], m[1], m[2], m[3]])
        } else {
            None
        };

        let mut payload = read_exact_buffered(stream, leftover, len, deadline).await?;
        if let Some(m) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= m[i & 3];
            }
        }

        match opcode {
            0x8 => return Err("websocket closed by peer".to_string()),
            0x9 | 0xA => {
                // Ignore ping/pong control frames; do not emit unsolicited frames.
                continue;
            }
            0x1 => {
                assembled.extend_from_slice(&payload);
                if fin {
                    return String::from_utf8(assembled)
                        .map_err(|_| "non-utf8 websocket text frame".to_string());
                }
                collecting_fragments = true;
            }
            0x0 if collecting_fragments => {
                assembled.extend_from_slice(&payload);
                if fin {
                    return String::from_utf8(assembled)
                        .map_err(|_| "non-utf8 websocket text frame".to_string());
                }
            }
            _ => continue,
        }
    }
}

/// Wait for a JSON-RPC response whose `"id"` equals `expected_id` and has no `"method"` field.
///
/// Per §2.4:
/// - Unrelated notifications (`"method"` present, `"id"` absent) are discarded.
/// - Unsolicited server requests/callbacks (`"method"` present AND `"id"` present, such as
///   approval, elicitation, tool, or clock callbacks) are discarded and NEVER answered.
/// - Mismatched response IDs (`"id"` != `expected_id`) are discarded and NEVER accepted.
async fn wait_for_matching_response(
    stream: &mut UnixStream,
    leftover: &mut Vec<u8>,
    expected_id: &str,
    deadline: Instant,
) -> std::result::Result<Value, String> {
    loop {
        let text = ws_read_text_frame(stream, leftover, deadline).await?;
        let val: Value = serde_json::from_str(&text)
            .map_err(|e| format!("invalid json from app-server: {e}"))?;
        let Some(obj) = val.as_object() else {
            return Err("non-object json from app-server".to_string());
        };
        if obj.contains_key("method") {
            continue;
        }
        let Some(id_val) = obj.get("id") else {
            continue;
        };
        if id_val.as_str() == Some(expected_id) {
            return Ok(val);
        }
    }
}

/// Execute mode detection and restricted `turn/start` delivery on a fresh pinned connection (§2.4).
///
/// `revalidate` is called before connection, before sending `turn/start`, and after receiving
/// the `turn/start` response before acknowledging acceptance.
pub async fn deliver_via_codex_relay<F>(job: &CodexDeliveryJob, mut revalidate: F) -> RelayOutcome
where
    F: FnMut() -> std::result::Result<(), String>,
{
    let deadline = Instant::now() + RELAY_HANDOFF_TIMEOUT;

    if let Err(reason) = revalidate() {
        return RelayOutcome::Rejected { reason };
    }

    if job.rendered_envelope.len() > MAX_RELAY_FRAME_BYTES {
        return RelayOutcome::Rejected {
            reason: "rendered envelope exceeds 1 MiB relay frame bound".to_string(),
        };
    }

    let sock_path = match resolve_validated_control_socket(&job.codex_home) {
        Ok(p) => p,
        Err(reason) => return RelayOutcome::QueueOnly { reason },
    };

    let mut stream = match timeout_at(deadline, UnixStream::connect(&sock_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return RelayOutcome::QueueOnly {
                reason: format!("cannot connect {}: {e}", sock_path.display()),
            };
        }
        Err(_) => {
            return RelayOutcome::QueueOnly {
                reason: "timeout connecting app-server-control.sock".to_string(),
            };
        }
    };

    // Pin the Unix peer PID and starttime to the admitted owner O (§2.4 step 2).
    if let Err(reason) =
        verify_stream_peer(&stream, &job.proc_root, job.owner_pid, &job.owner_starttime)
    {
        return RelayOutcome::QueueOnly { reason };
    }

    let mut leftover = match ws_client_handshake(&mut stream, deadline).await {
        Ok(buf) => buf,
        Err(reason) => return RelayOutcome::QueueOnly { reason },
    };

    // Send static initialize + initialized (§2.4: experimentalApi = false).
    let init_id = format!("xmsg-init-{}", job.message_id);
    let init_req = InitializeRequest {
        jsonrpc: "2.0",
        id: &init_id,
        method: "initialize",
        params: InitializeParams {
            client_info: ClientInfo {
                name: "xmsg-relay",
                version: env!("CARGO_PKG_VERSION"),
            },
            capabilities: InitializeCapabilities {
                experimental_api: false,
            },
        },
    };
    let init_bytes = match serde_json::to_vec(&init_req) {
        Ok(b) => b,
        Err(e) => {
            return RelayOutcome::Rejected {
                reason: format!("serialize initialize: {e}"),
            };
        }
    };
    if let Err(reason) = ws_write_text_frame(&mut stream, &init_bytes, deadline).await {
        return RelayOutcome::QueueOnly { reason };
    }
    let init_resp =
        match wait_for_matching_response(&mut stream, &mut leftover, &init_id, deadline).await {
            Ok(v) => v,
            Err(reason) => return RelayOutcome::QueueOnly { reason },
        };
    if init_resp.get("error").is_some_and(|e| !e.is_null()) || init_resp.get("result").is_none() {
        return RelayOutcome::QueueOnly {
            reason: "app-server rejected initialize".to_string(),
        };
    }

    let initialized_msg = InitializedNotification {
        jsonrpc: "2.0",
        method: "initialized",
    };
    let initialized_bytes = match serde_json::to_vec(&initialized_msg) {
        Ok(b) => b,
        Err(e) => {
            return RelayOutcome::Rejected {
                reason: format!("serialize initialized: {e}"),
            };
        }
    };
    if let Err(reason) = ws_write_text_frame(&mut stream, &initialized_bytes, deadline).await {
        return RelayOutcome::QueueOnly { reason };
    }

    // Discover loaded threads via thread/loaded/list (with bounded pagination within deadline).
    let mut cursor: Option<String> = None;
    let mut page = 0usize;
    let mut root_loaded = false;
    loop {
        page += 1;
        if page > 32 {
            return RelayOutcome::QueueOnly {
                reason: "thread/loaded/list exceeded page bound".to_string(),
            };
        }
        let list_id = format!("xmsg-list-{}-{}", job.message_id, page);
        let list_req = LoadedListRequest {
            jsonrpc: "2.0",
            id: &list_id,
            method: "thread/loaded/list",
            params: LoadedListParams {
                cursor: cursor.as_deref(),
            },
        };
        let list_bytes = match serde_json::to_vec(&list_req) {
            Ok(b) => b,
            Err(e) => {
                return RelayOutcome::Rejected {
                    reason: format!("serialize thread/loaded/list: {e}"),
                };
            }
        };
        if let Err(reason) = ws_write_text_frame(&mut stream, &list_bytes, deadline).await {
            return RelayOutcome::QueueOnly { reason };
        }
        let list_resp = match wait_for_matching_response(
            &mut stream,
            &mut leftover,
            &list_id,
            deadline,
        )
        .await
        {
            Ok(v) => v,
            Err(reason) => return RelayOutcome::QueueOnly { reason },
        };
        if list_resp.get("error").is_some_and(|e| !e.is_null()) {
            return RelayOutcome::QueueOnly {
                reason: "thread/loaded/list returned error".to_string(),
            };
        }
        let Some(res_obj) = list_resp.get("result").and_then(|v| v.as_object()) else {
            return RelayOutcome::QueueOnly {
                reason: "thread/loaded/list missing result object".to_string(),
            };
        };
        let Some(data_arr) = res_obj.get("data").and_then(|v| v.as_array()) else {
            return RelayOutcome::QueueOnly {
                reason: "thread/loaded/list missing data array".to_string(),
            };
        };
        for item in data_arr {
            let tid = item
                .as_str()
                .or_else(|| item.get("id").and_then(|v| v.as_str()));
            if tid == Some(job.root_id.as_str()) {
                root_loaded = true;
                break;
            }
        }
        if root_loaded {
            break;
        }
        match res_obj.get("nextCursor").and_then(|v| v.as_str()) {
            Some(next) if !next.is_empty() => {
                cursor = Some(next.to_string());
            }
            _ => break,
        }
    }

    if !root_loaded {
        return RelayOutcome::QueueOnly {
            reason: format!("root {} is not loaded on owner app-server", job.root_id),
        };
    }

    // Revalidate peer and lease immediately before sending turn/start (§2.4).
    if let Err(reason) =
        verify_stream_peer(&stream, &job.proc_root, job.owner_pid, &job.owner_starttime)
    {
        return RelayOutcome::Rejected { reason };
    }
    if let Err(reason) = revalidate() {
        return RelayOutcome::Rejected { reason };
    }

    let turn_req_id = format!("xmsg-turn-{}", job.message_id);
    let turn_req = TurnStartRequest {
        jsonrpc: "2.0",
        id: &turn_req_id,
        method: "turn/start",
        params: TurnStartParams {
            thread_id: &job.root_id,
            input: [TurnStartTextInput {
                kind: "text",
                text: &job.rendered_envelope,
            }],
        },
    };
    let turn_bytes = match serde_json::to_vec(&turn_req) {
        Ok(b) => b,
        Err(e) => {
            return RelayOutcome::Rejected {
                reason: format!("serialize turn/start: {e}"),
            };
        }
    };
    if turn_bytes.len() > MAX_RELAY_FRAME_BYTES {
        return RelayOutcome::Rejected {
            reason: "turn/start frame exceeds 1 MiB cap".to_string(),
        };
    }

    // Once we begin writing turn/start, any I/O error or timeout means the request may have
    // been delivered to the upstream daemon; mark uncertain rather than risking duplicate retry.
    if let Err(reason) = ws_write_text_frame(&mut stream, &turn_bytes, deadline).await {
        return RelayOutcome::Uncertain {
            reason: format!("write turn/start failed or timed out: {reason}"),
        };
    }

    let turn_resp = match wait_for_matching_response(
        &mut stream,
        &mut leftover,
        &turn_req_id,
        deadline,
    )
    .await
    {
        Ok(v) => v,
        Err(reason) => {
            return RelayOutcome::Uncertain {
                reason: format!("awaiting turn/start response failed: {reason}"),
            };
        }
    };

    if let Some(err_val) = turn_resp.get("error").filter(|v| !v.is_null()) {
        return RelayOutcome::Rejected {
            reason: format!("turn/start refused by upstream: {err_val}"),
        };
    }

    let Some(result_obj) = turn_resp.get("result").and_then(|v| v.as_object()) else {
        return RelayOutcome::Uncertain {
            reason: "turn/start response missing result object".to_string(),
        };
    };

    // Revalidate peer and lease after response before acknowledging acceptance (§2.4).
    if let Err(reason) =
        verify_stream_peer(&stream, &job.proc_root, job.owner_pid, &job.owner_starttime)
    {
        return RelayOutcome::Uncertain {
            reason: format!("post-response peer revalidation failed: {reason}"),
        };
    }
    if let Err(reason) = revalidate() {
        return RelayOutcome::Uncertain {
            reason: format!("post-response lease revalidation failed: {reason}"),
        };
    }

    let turn_id = result_obj
        .get("turn")
        .and_then(|t| t.get("id"))
        .and_then(|v| v.as_str())
        .map(String::from);

    RelayOutcome::Accepted { turn_id }
}
