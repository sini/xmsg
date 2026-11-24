use hyper::{header, Method, Request, StatusCode};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::admission::{self, Refusal, Route};
use super::authority::{Grants, Record, Scope};
use super::cursor::Partition;
use super::hub::Snapshot;
use super::protocol::{Attention, Node, Projection};
use super::request;
use super::upstream::ReadHub;
use super::{response, Issuer, WebResponse};

const SNAPSHOT_PREFIX: &str = "/v1/mission-control/snapshot/";

#[derive(Serialize)]
pub(super) struct SnapshotMessage<'a> {
    pub(super) v: u8,
    pub(super) r#type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) sub: Option<&'a str>,
    pub(super) part: u32,
    #[serde(rename = "final")]
    pub(super) final_part: bool,
    pub(super) stream_epoch: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) cursor: Option<&'a str>,
    pub(super) server_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) truncated: Option<bool>,
    pub(super) nodes: &'a [Node],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) attention: Option<&'a [Attention]>,
}

pub(super) fn grants(record: &Record) -> &[Scope] {
    match &record.grants {
        Grants::Owner => &[Scope::Fleet],
        Grants::Machine { scope, .. } => scope,
        Grants::Delegated { grant } => grant.read_scope.as_deref().unwrap_or_default(),
    }
}

pub(super) fn partition(scope: &Scope, record: &Record) -> Result<Partition, Refusal> {
    let bytes = serde_json::to_vec(scope).map_err(|_| Refusal::UNAVAILABLE)?;
    Ok(Partition::new(
        &bytes,
        record.record_id.as_bytes(),
        record.policy_generation,
    ))
}

pub(crate) fn is_snapshot(path: &str) -> bool {
    path.starts_with(SNAPSHOT_PREFIX)
}

pub(crate) async fn snapshot(
    issuer: &Issuer,
    hub: &ReadHub,
    request: Request<hyper::body::Incoming>,
) -> WebResponse {
    let head = request.method() == Method::HEAD;
    let result = snapshot_response(issuer, hub, request).await;
    let result = result.unwrap_or_else(error);
    if head {
        let (parts, _) = result.into_parts();
        WebResponse::from_parts(parts, http_body_util::Full::default())
    } else {
        result
    }
}

async fn snapshot_response(
    issuer: &Issuer,
    hub: &ReadHub,
    request: Request<hyper::body::Incoming>,
) -> Result<WebResponse, Refusal> {
    if !matches!(*request.method(), Method::GET | Method::HEAD) || request.uri().query().is_some() {
        return Err(Refusal::INVALID);
    }
    let path = request
        .uri()
        .path()
        .strip_prefix(SNAPSHOT_PREFIX)
        .ok_or(Refusal::INVALID)?;
    let scope = parse_scope(path)?;
    let record = admission::authenticate(issuer, Route::Snapshot, request.headers()).await?;
    let _slot = hub.budgets.take(
        &record,
        super::budgets::Mode::Snapshot,
        &issuer.config.session_limits,
    )?;
    let grants = grants(&record);
    if grants.is_empty() {
        return Err(Refusal::FORBIDDEN);
    }
    let masked = issuer.authority.masked_nodes()?;
    let projection = Projection {
        scope: &scope,
        grants,
        masked: &|node| masked.contains(node),
        activity: true,
    };
    let (snapshot, epoch) = hub
        .snapshot(&projection)
        .map_err(|_| Refusal::UNAVAILABLE)?
        .ok_or(Refusal::NOT_FOUND)?;
    let key = partition(&scope, &record)?;
    let cursor = hub
        .cursor(snapshot.watermark, &key)
        .map_err(|_| Refusal::UNAVAILABLE)?;
    let digest = Sha256::digest(cursor.as_bytes());
    let etag = format!("\"{}\"", hex::encode(digest));
    let mut tags = request.headers().get_all(header::IF_NONE_MATCH).iter();
    let unchanged = tags
        .next()
        .is_some_and(|tag| tag.as_bytes() == etag.as_bytes())
        && tags.next().is_none();
    let mut result = if unchanged {
        response(StatusCode::NOT_MODIFIED, "application/json", "")
    } else {
        let body = encode_snapshot(
            &snapshot,
            &epoch,
            &cursor,
            issuer.config.session_limits.snapshot_max_bytes,
        )?;
        #[cfg(test)]
        if let Some(delay) = hub.snapshot_hold() {
            tokio::time::sleep(delay).await;
        }
        response(StatusCode::OK, "application/json", body)
    };
    result.headers_mut().insert(
        header::ETAG,
        header::HeaderValue::from_str(&etag).map_err(|_| Refusal::UNAVAILABLE)?,
    );
    Ok(result)
}

pub(super) fn encode_snapshot(
    snapshot: &Snapshot,
    epoch: &str,
    cursor: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, Refusal> {
    let stamp = crate::storage::now_epoch_secs().saturating_mul(1000);
    let render = |nodes: usize, attention: Option<usize>, truncated: bool| {
        serde_json::to_vec(&SnapshotMessage {
            v: 1,
            r#type: "snapshot",
            sub: None,
            part: 0,
            final_part: true,
            stream_epoch: epoch,
            cursor: Some(cursor),
            server_at: stamp,
            truncated: Some(truncated),
            nodes: &snapshot.nodes[..nodes],
            attention: snapshot
                .attention
                .as_ref()
                .zip(attention)
                .map(|(items, count)| &items[..count]),
        })
        .map_err(|_| Refusal::UNAVAILABLE)
    };
    let nodes = snapshot.nodes.len();
    let attention = snapshot.attention.as_ref().map(Vec::len);
    let whole = render(nodes, attention, false)?;
    if whole.len() <= max_bytes {
        return Ok(whole);
    }
    let (mut low, mut high) = (0, attention.unwrap_or(nodes));
    let mut best = render(0, attention.map(|_| 0), true)?;
    if best.len() > max_bytes {
        return Err(Refusal::UNAVAILABLE);
    }
    while low < high {
        let count = low + (high - low).div_ceil(2);
        let candidate = render(
            if attention.is_some() { 0 } else { count },
            attention.map(|_| count),
            true,
        )?;
        if candidate.len() > max_bytes {
            high = count - 1;
        } else {
            low = count;
            best = candidate;
        }
    }
    Ok(best)
}

pub(super) fn parse_scope(value: &str) -> Result<Scope, Refusal> {
    let scope = match value {
        "fleet" => Scope::Fleet,
        "attention" => Scope::Attention,
        _ => {
            let mut segments = value.split('/');
            match (
                segments.next(),
                segments.next(),
                segments.next(),
                segments.next(),
            ) {
                (Some("node"), Some(node), None, None) => Scope::Node {
                    node: node.to_owned(),
                },
                (Some("session"), Some(node), Some(endpoint), None) => Scope::Session {
                    node: node.to_owned(),
                    endpoint: decode_segment(endpoint)?,
                },
                _ => return Err(Refusal::INVALID),
            }
        }
    };
    if !request::valid_scope(&scope) {
        return Err(Refusal::INVALID);
    }
    Ok(scope)
}

fn decode_segment(value: &str) -> Result<String, Refusal> {
    if value.len() > 3 * 512 {
        return Err(Refusal::INVALID);
    }
    let mut bytes = value.bytes();
    let mut output = Vec::new();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let hi = bytes
                .next()
                .and_then(|b| (b as char).to_digit(16))
                .ok_or(Refusal::INVALID)?;
            let lo = bytes
                .next()
                .and_then(|b| (b as char).to_digit(16))
                .ok_or(Refusal::INVALID)?;
            output.push(((hi << 4) | lo) as u8);
        } else {
            output.push(byte);
        }
    }
    String::from_utf8(output).map_err(|_| Refusal::INVALID)
}

pub(super) fn error(refusal: Refusal) -> WebResponse {
    let body =
        serde_json::json!({"v":1,"type":"error","code":refusal.code,"fatal":true}).to_string();
    let mut response = response(refusal.status, "application/json", body);
    if refusal == Refusal::RATE_LIMIT {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, header::HeaderValue::from_static("60"));
    }
    response
}

pub(crate) fn busy() -> WebResponse {
    error(Refusal::UNAVAILABLE)
}
