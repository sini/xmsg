use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, Read, Write};

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const ACP_VERSION: u16 = 1;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame exceeds byte bound")]
    TooLarge,
    #[error("incomplete newline-delimited frame")]
    Truncated,
    #[error("reader is poisoned after a fatal frame error")]
    Poisoned,
    #[error("unsupported JSON-RPC version")]
    Version,
    #[error("invalid frame: {0}")]
    Json(#[from] serde_json::Error),
    #[error("frame I/O: {0}")]
    Io(#[from] std::io::Error),
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RequestId {
    Text(String),
    Number(i64),
    Null(()),
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub jsonrpc: String,
    pub id: RequestId,
    pub method: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "structured_params"
    )]
    pub params: Option<Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Notification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "structured_params"
    )]
    pub params: Option<Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Success {
    pub jsonrpc: String,
    pub id: RequestId,
    pub result: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    pub jsonrpc: String,
    pub id: RequestId,
    pub error: RpcError,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Frame {
    Request(Request),
    Notification(Notification),
    Success(Success),
    Failure(Failure),
}
fn structured_params<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    let value = Value::deserialize(d)?;
    if !value.is_object() && !value.is_array() {
        return Err(serde::de::Error::custom(
            "params must be an object or array",
        ));
    }
    Ok(Some(value))
}

pub struct FrameReader<R> {
    inner: R,
    poisoned: bool,
}
impl<R: BufRead> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            poisoned: false,
        }
    }
    pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        if self.poisoned {
            return Err(FrameError::Poisoned);
        }
        let result = read_frame(&mut self.inner);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl Frame {
    pub fn validate(&self) -> Result<(), FrameError> {
        let version = match self {
            Self::Request(r) => &r.jsonrpc,
            Self::Notification(n) => &n.jsonrpc,
            Self::Success(r) => &r.jsonrpc,
            Self::Failure(r) => &r.jsonrpc,
        };
        if version != "2.0" {
            return Err(FrameError::Version);
        }
        let params = match self {
            Self::Request(r) => r.params.as_ref(),
            Self::Notification(n) => n.params.as_ref(),
            _ => None,
        };
        if params.is_some_and(|p| !p.is_object() && !p.is_array()) {
            return Err(FrameError::Json(
                <serde_json::Error as serde::de::Error>::custom(
                    "params must be an object or array",
                ),
            ));
        }
        Ok(())
    }
}

fn read_frame(reader: &mut impl BufRead) -> Result<Option<Frame>, FrameError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_FRAME_BYTES + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    if bytes.last() != Some(&b'\n') {
        return Err(FrameError::Truncated);
    }
    let frame: Frame = serde_json::from_slice(&bytes)?;
    frame.validate()?;
    Ok(Some(frame))
}

pub fn write_frame(writer: &mut impl Write, frame: &Frame) -> Result<(), FrameError> {
    frame.validate()?;
    let bytes = serde_json::to_vec(frame)?;
    if bytes.len() + 1 > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    writer.write_all(&bytes)?;
    writer.write_all(b"\n")?;
    Ok(())
}
