use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::time::timeout;
use unicode_general_category::{get_general_category, GeneralCategory};

use crate::error::AppError;

pub const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxLine {
    pub r#type: String, // "user"
    pub message: InboxMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxMessage {
    pub role: String, // "user"
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryResponse {
    pub session_id: String,
    pub from_name: String,
    pub bytes: usize,
    #[serde(alias = "message_id")]
    pub message_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
}

/// The longest label shown, in characters. Only the label is cut; the attested
/// `id@node` part is never truncated.
pub const LABEL_MAX_CHARS: usize = 64;

/// Sanitizes the `from` parameter for unauthenticated HTTP senders and renders A12's
/// anonymous label, `<from> · anon@<node>`:
/// - Rejects ':', '/' and '@' outright (returns AppError::BadSender); '@' could imitate
///   the attested part (AM-8), and '·' is already refused as non-ASCII.
/// - Enforces strictly printable ASCII characters (0x20 to 0x7E).
/// - Strips quotes (") and angle brackets (<, >).
/// - Collapses whitespace runs to a single space.
/// - Trims leading and trailing whitespace.
/// - Truncates the name to `LABEL_MAX_CHARS` and appends ` · anon@<node-name>`.
pub fn sanitize_from(node_name: &str, raw_from: &str) -> Result<String, AppError> {
    if raw_from.contains(':') || raw_from.contains('/') || raw_from.contains('@') {
        return Err(AppError::BadSender(
            "sender name cannot contain ':', '/' or '@'".to_string(),
        ));
    }

    if raw_from.chars().any(|c| !(' '..='~').contains(&c)) {
        return Err(AppError::BadSender(
            "sender name must contain only printable ASCII characters".to_string(),
        ));
    }

    let mut cleaned = String::with_capacity(raw_from.len());
    let mut prev_whitespace = false;

    for c in raw_from.chars() {
        if c == '"' || c == '<' || c == '>' {
            continue;
        }

        if c == ' ' {
            if !prev_whitespace {
                cleaned.push(' ');
                prev_whitespace = true;
            }
        } else {
            cleaned.push(c);
            prev_whitespace = false;
        }
    }

    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadSender(
            "sender name is empty after sanitization".to_string(),
        ));
    }

    let label: String = trimmed.chars().take(LABEL_MAX_CHARS).collect();
    Ok(format!("{} · anon@{node_name}", label.trim_end()))
}

/// A sender's own label, cleaned for display, or `None` when it shows no label.
/// A label containing `@` or `·` is dropped whole, so it cannot imitate the attested
/// `id@node` part (AM-8; plan §6 D8). Otherwise it is cleaned: `"`, `<`, `>`, CR and LF
/// and the Unicode categories Cc, Cf, Cs, Zl and Zp are stripped, any other non-ASCII
/// character becomes `_`, whitespace runs collapse to one space, the ends are trimmed,
/// and it is cut to `LABEL_MAX_CHARS`.
pub fn clean_label(raw: &str) -> Option<String> {
    if raw.contains('@') || raw.contains('·') {
        return None;
    }
    let mut cleaned = String::with_capacity(raw.len());
    let mut prev_whitespace = false;

    for c in raw.chars() {
        if c == '"' || c == '<' || c == '>' || c == '\n' || c == '\r' {
            continue;
        }

        if !c.is_ascii() {
            cleaned.push('_');
            prev_whitespace = false;
            continue;
        }

        let cat = get_general_category(c);
        if matches!(
            cat,
            GeneralCategory::Control
                | GeneralCategory::Format
                | GeneralCategory::Surrogate
                | GeneralCategory::LineSeparator
                | GeneralCategory::ParagraphSeparator
        ) {
            continue;
        }

        if c.is_whitespace() {
            if !prev_whitespace {
                cleaned.push(' ');
                prev_whitespace = true;
            }
        } else {
            cleaned.push(c);
            prev_whitespace = false;
        }
    }

    let capped: String = cleaned.trim().chars().take(LABEL_MAX_CHARS).collect();
    let capped = capped.trim_end();
    if capped.is_empty() {
        None
    } else {
        Some(capped.to_string())
    }
}

/// A12's one render of an attested local sender, as its receiver sees it:
/// - a service: `name@node`, all of it attested (its `id` is its name);
/// - an instance: `label · id@node`, where `id` is the instance address, a fork's `~n`
///   included, and `label` is the sender's own description; `id@node` alone when the
///   sender has no label, or one `clean_label` drops.
///
/// The harness is not shown.
pub fn sender_label(node_name: &str, harness: &str, id: &str, label: Option<&str>) -> String {
    if harness == "svc" {
        return format!("{id}@{node_name}");
    }
    match label.and_then(clean_label).filter(|l| l != id) {
        Some(label) => format!("{label} · {id}@{node_name}"),
        None => format!("{id}@{node_name}"),
    }
}

/// Sanitizes the message body:
/// Every `<` that begins `/?cross-session-message` (case-insensitive) anywhere in the body becomes `<\`.
/// Nothing else changes.
pub fn sanitize_body(body: &str) -> String {
    // Regex matching case-insensitive '<' followed by optional '/' and 'cross-session-message'
    // Replaces '<' with '<\', preserving the captured tag text.
    let re = Regex::new(r"(?i)<(/?cross-session-message)").expect("valid regex");
    re.replace_all(body, r"<\$1").to_string()
}

/// Assembles the inner envelope string.
/// Escapes `"` in `from_name` to prevent XML attribute breakout.
pub fn assemble_envelope(from_name: &str, sanitized_body: &str) -> String {
    let safe_from_name = from_name.replace('"', "&quot;");
    format!("<cross-session-message from-name=\"{safe_from_name}\">\n{sanitized_body}\n</cross-session-message>")
}

/// Encodes the complete transport line:
/// Serializes typed `InboxLine` into JSON with serde_json, appending a single `\n`.
/// Never uses format! or string concatenation for the JSON structure.
pub fn encode_transport_line(from_name: &str, raw_body: &str) -> Result<String, AppError> {
    crate::fed::validate_no_control_chars("from_name", from_name)?;
    let sanitized_body = sanitize_body(raw_body);
    let envelope = assemble_envelope(from_name, &sanitized_body);

    let line_struct = InboxLine {
        r#type: "user".to_string(),
        message: InboxMessage {
            role: "user".to_string(),
            content: envelope,
        },
    };

    let mut json_str = serde_json::to_string(&line_struct)
        .map_err(|e| AppError::Internal(format!("failed to serialize inbox line: {e}")))?;
    json_str.push('\n');
    Ok(json_str)
}

/// Delivers a single newline-delimited JSON line to the target Unix domain socket.
pub async fn deliver_to_socket(socket_path: &Path, line: &str) -> Result<(), AppError> {
    crate::registry::validate_messaging_socket_path(socket_path)
        .map_err(|e| AppError::InboxUnavailable(format!("invalid messaging socket path: {e}")))?;

    let connect_fut = UnixStream::connect(socket_path);
    let mut stream = match timeout(SOCKET_TIMEOUT, connect_fut).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(AppError::InboxUnavailable(format!(
                "socket connect failed: {e}"
            )))
        }
        Err(_) => return Err(AppError::InboxTimeout),
    };

    let write_fut = async {
        stream.write_all(line.as_bytes()).await?;
        stream.flush().await?;
        Ok::<(), std::io::Error>(())
    };

    match timeout(SOCKET_TIMEOUT, write_fut).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(AppError::InboxUnavailable(format!(
            "socket write failed: {e}"
        ))),
        Err(_) => Err(AppError::InboxTimeout),
    }
}
