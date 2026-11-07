//! Bounded, same-process service transport shared by xmsg consumers.

mod health;
mod origin;
pub(crate) mod wire;

pub use origin::Origin;
pub use wire::{ListResult, NodeStatus, Recipient, Registration, ReplyRecord, SendResult};

use health::RegistrationHealth;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::timeout;
use wire::{AgentFrame, DeliveryFrame, ServiceResponse, SvcFrame, SvcRegisterRequest};

/// Returns the real process UID used by the daemon's same-user service checks.
pub fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

pub(crate) fn is_uuid_shaped(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

pub(crate) fn is_instance_ref(s: &str) -> bool {
    match s.split_once('~') {
        Some((base, n)) => n.parse::<u32>().is_ok() && is_uuid_shaped(base),
        None => is_uuid_shaped(s),
    }
}

pub(crate) fn split_subaddress(ref_str: &str) -> Option<(&str, &str)> {
    let (parent, child) = ref_str.split_once('/')?;
    if is_instance_ref(parent) {
        Some((parent, child))
    } else {
        None
    }
}

/// Validates a service name across consumer configuration (`xmsg::client::validate_service_name`),
/// service registration (`register.sock` in `src/svc.rs`), subagent names (`validate_subagent_name`),
/// and origin checking (`check_origin` in `src/fed.rs`):
/// - non-empty and at most 32 bytes;
/// - not the reserved `"xmsg"`;
/// - no collision with the instance or subagent namespace (`is_instance_ref`, `split_subaddress`, or `'/'`);
/// - no forbidden address/delimiter characters (`@`, `·`, `~`, `.`, `:`, `/`) and only ASCII `[A-Za-z0-9_-]`.
pub fn validate_service_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("service name must not be empty".to_string());
    }
    if name.len() > 32 {
        return Err(format!(
            "service name '{name}' exceeds maximum length of 32 bytes"
        ));
    }
    if name == "xmsg" {
        return Err("service name 'xmsg' is reserved".to_string());
    }
    if is_instance_ref(name) || split_subaddress(name).is_some() {
        return Err(format!(
            "service name '{name}' is UUID-shaped or collides with the instance/subagent namespace"
        ));
    }
    if name.contains('@')
        || name.contains('·')
        || name.contains('~')
        || name.contains('.')
        || name.contains(':')
        || name.contains('/')
    {
        return Err(format!(
            "service name '{name}' contains forbidden character (@, ·, ~, ., : or /)"
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(format!("invalid service name '{name}'"));
    }
    Ok(())
}

pub const SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid client configuration")]
    Configuration,
    #[error("untrusted local socket")]
    Peer,
    #[error("xmsg transport I/O failed")]
    Io(#[from] std::io::Error),
    #[error("xmsg transport deadline exceeded; submission may be unknown")]
    Timeout,
    #[error("invalid xmsg protocol response")]
    Protocol,
    #[error("xmsg refused request: {code}")]
    Refused { code: String },
    #[error("service is disconnected")]
    Disconnected,
}

#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub register_socket: PathBuf,
    pub agent_socket: PathBuf,
    pub max_frame_bytes: usize,
    pub operation_timeout: Duration,
    pub service: String,
    pub expected_node: Option<String>,
    pub daemon_uid: u32,
}

#[derive(Clone, Debug, Default)]
pub struct ListQuery {
    pub name: Option<String>,
    pub node: Option<String>,
    pub kind: Option<String>,
    pub status: Option<String>,
    pub within: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Delivery(DeliveryFrame);

impl Delivery {
    pub fn message_id(&self) -> &str {
        &self.0.message_id
    }
    pub fn from_name(&self) -> &str {
        &self.0.from_name
    }
    pub fn text(&self) -> &str {
        &self.0.text
    }
    pub fn envelope(&self) -> &str {
        &self.0.envelope
    }
    pub fn origin(&self) -> &Origin {
        &self.0.origin
    }
    pub fn in_reply_to(&self) -> Option<&str> {
        self.0.in_reply_to.as_deref()
    }
}

struct Connection {
    stream: BufReader<UnixStream>,
    max_frame_bytes: usize,
    registration: Option<Arc<RegistrationHealth>>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(live) = &self.registration {
            live.dispose();
        }
    }
}

impl Connection {
    async fn connect(
        file: &Path,
        options: &ClientOptions,
        expected_uid: u32,
    ) -> Result<Self, ClientError> {
        let parent = file.parent().ok_or(ClientError::Configuration)?;
        let dir = tokio::fs::symlink_metadata(parent).await?;
        let socket = tokio::fs::symlink_metadata(file).await?;
        if !dir.is_dir()
            || dir.uid() != expected_uid
            || dir.permissions().mode() & 0o077 != 0
            || !socket.file_type().is_socket()
            || socket.uid() != expected_uid
        {
            return Err(ClientError::Peer);
        }
        let stream = UnixStream::connect(file).await?;
        if stream.peer_cred()?.uid() != expected_uid {
            return Err(ClientError::Peer);
        }
        Ok(Self {
            stream: BufReader::new(stream),
            max_frame_bytes: options.max_frame_bytes,
            registration: None,
        })
    }

    async fn exchange(&mut self, request: &impl Serialize) -> Result<Value, ClientError> {
        let mut bytes = serde_json::to_vec(request).map_err(|_| ClientError::Protocol)?;
        bytes.push(b'\n');
        if bytes.len() > self.max_frame_bytes {
            return Err(ClientError::Protocol);
        }
        self.stream.get_mut().write_all(&bytes).await?;
        self.stream.get_mut().flush().await?;
        let mut response = Vec::new();
        (&mut self.stream)
            .take(self.max_frame_bytes as u64 + 1)
            .read_until(b'\n', &mut response)
            .await?;
        if response.len() > self.max_frame_bytes || !response.ends_with(b"\n") {
            return Err(ClientError::Protocol);
        }
        let value: Value = serde_json::from_slice(&response).map_err(|_| ClientError::Protocol)?;
        if value.get("status").and_then(Value::as_str) == Some("error") {
            let code = value
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("error");
            if code.len() > 64 || !code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Err(ClientError::Protocol);
            }
            return Err(ClientError::Refused {
                code: code.to_owned(),
            });
        }
        Ok(value)
    }
}

pub struct RegisteredService {
    connection: Option<Connection>,
    options: ClientOptions,
    registration: Registration,
    live: Arc<RegistrationHealth>,
}

#[derive(Clone)]
pub struct AgentClient {
    options: ClientOptions,
    live: Arc<RegistrationHealth>,
}

impl RegisteredService {
    pub async fn register(options: ClientOptions) -> Result<Self, ClientError> {
        if options.max_frame_bytes == 0
            || options.max_frame_bytes > 16 * 1024 * 1024
            || options.operation_timeout.is_zero()
            || !options.register_socket.is_absolute()
            || !options.agent_socket.is_absolute()
            || options.service.is_empty()
            || options.service.contains('@')
            || options
                .expected_node
                .as_ref()
                .is_some_and(|node| node.is_empty())
        {
            return Err(ClientError::Configuration);
        }
        let (mut connection, registration) = timeout(options.operation_timeout, async {
            let mut connection =
                Connection::connect(&options.register_socket, &options, options.daemon_uid).await?;
            let response = connection
                .exchange(&SvcRegisterRequest {
                    harness: Some("svc".to_owned()),
                    name: options.service.clone(),
                    cwd: Some("/".to_owned()),
                })
                .await?;
            let registration: Registration =
                serde_json::from_value(response).map_err(|_| ClientError::Protocol)?;
            if registration.status != "ok"
                || registration.node.is_empty()
                || options
                    .expected_node
                    .as_ref()
                    .is_some_and(|node| node != &registration.node)
                || registration.address != format!("{}@{}", options.service, registration.node)
            {
                return Err(ClientError::Peer);
            }
            Ok((connection, registration))
        })
        .await
        .map_err(|_| ClientError::Timeout)??;
        let live = Arc::new(RegistrationHealth::new(
            connection.stream.get_ref().as_raw_fd(),
        ));
        connection.registration = Some(live.clone());
        Ok(Self {
            connection: Some(connection),
            options,
            registration,
            live,
        })
    }

    pub fn registration(&self) -> Option<&Registration> {
        self.connection.as_ref().map(|_| &self.registration)
    }
    /// Non-consuming, point-in-time health of the registration transport.
    pub fn health(&self) -> Result<(), ClientError> {
        self.live.check()
    }
    pub fn address(&self) -> Option<&str> {
        self.connection
            .as_ref()
            .map(|_| self.registration.address.as_str())
    }
    pub fn node(&self) -> Option<&str> {
        self.connection
            .as_ref()
            .map(|_| self.registration.node.as_str())
    }
    pub fn reply_ttl_secs(&self) -> Option<u64> {
        self.connection
            .as_ref()
            .and(self.registration.reply_ttl_secs)
    }
    pub fn idempotency_ttl_secs(&self) -> Option<u64> {
        self.connection
            .as_ref()
            .and(self.registration.idempotency_ttl_secs)
    }
    pub fn svc_queue_cap(&self) -> Option<usize> {
        self.connection
            .as_ref()
            .and(self.registration.svc_queue_cap)
    }
    /// Effective maximum message body length in BYTES (`--max-body` / `XMSG_MAX_BODY`),
    /// sourced from `state.max_body` enforced by `surface::send` and `surface::reply`,
    /// or `None` when disconnected or when an older daemon omitted the field.
    pub fn max_body_bytes(&self) -> Option<usize> {
        self.connection
            .as_ref()
            .and(self.registration.max_body_bytes)
    }

    async fn service_exchange(
        &mut self,
        frame: SvcFrame,
        wait: Duration,
    ) -> Result<Value, ClientError> {
        // Taking ownership makes cancellation and timeout discard the partially read stream.
        let mut connection = self.connection.take().ok_or(ClientError::Disconnected)?;
        let response = timeout(wait, connection.exchange(&frame))
            .await
            .map_err(|_| ClientError::Timeout)??;
        self.connection = Some(connection);
        Ok(response)
    }

    pub async fn poll(&mut self, wait_secs: u64) -> Result<Option<Delivery>, ClientError> {
        if wait_secs > 60 {
            return Err(ClientError::Configuration);
        }
        let wait = self
            .options
            .operation_timeout
            .checked_add(Duration::from_secs(wait_secs))
            .ok_or(ClientError::Configuration)?;
        let response = self
            .service_exchange(
                SvcFrame::Poll {
                    wait_secs: Some(wait_secs),
                },
                wait,
            )
            .await?;
        let parsed: ServiceResponse = match serde_json::from_value(response) {
            Ok(parsed) => parsed,
            Err(_) => {
                self.connection = None;
                return Err(ClientError::Protocol);
            }
        };
        match parsed {
            ServiceResponse::Timeout => Ok(None),
            ServiceResponse::Deliver(frame) => {
                if frame.message_id.is_empty()
                    || frame.origin.node.is_empty()
                    || (frame.origin.id.is_some() && frame.origin.service.is_some())
                {
                    self.connection = None;
                    return Err(ClientError::Protocol);
                }
                Ok(Some(Delivery(*frame)))
            }
        }
    }

    pub async fn ack(&mut self, message_id: &str) -> Result<(), ClientError> {
        let response = self
            .service_exchange(
                SvcFrame::Ack {
                    message_id: message_id.to_owned(),
                },
                self.options.operation_timeout,
            )
            .await?;
        if response.get("status").and_then(Value::as_str) != Some("ok") {
            self.connection = None;
            return Err(ClientError::Protocol);
        }
        Ok(())
    }

    pub fn agent_client(&self) -> AgentClient {
        AgentClient {
            options: self.options.clone(),
            live: self.live.clone(),
        }
    }
    pub async fn send(
        &self,
        to: &str,
        text: &str,
        key: Option<&str>,
    ) -> Result<SendResult, ClientError> {
        self.agent_client().send(to, text, key).await
    }
    pub async fn reply(
        &self,
        message_id: &str,
        text: &str,
        key: Option<&str>,
    ) -> Result<ReplyRecord, ClientError> {
        self.agent_client().reply(message_id, text, key).await
    }
    pub async fn list(&self, query: ListQuery) -> Result<ListResult, ClientError> {
        self.agent_client().list(query).await
    }
}

impl AgentClient {
    /// Non-consuming, point-in-time health shared with the registration owner.
    pub fn health(&self) -> Result<(), ClientError> {
        self.live.check()
    }

    async fn agent(&self, request: AgentFrame) -> Result<Value, ClientError> {
        self.health()?;
        let result = timeout(self.options.operation_timeout, async {
            let mut connection = Connection::connect(
                &self.options.agent_socket,
                &self.options,
                self.options.daemon_uid,
            )
            .await?;
            let result = connection.exchange(&request).await?;
            if result.get("status").and_then(Value::as_str) != Some("ok") {
                return Err(ClientError::Protocol);
            }
            Ok(result)
        })
        .await
        .map_err(|_| ClientError::Timeout)
        .and_then(|result| result);
        if result.is_err() {
            self.health()?;
        }
        result
    }

    pub async fn send(
        &self,
        to: &str,
        text: &str,
        key: Option<&str>,
    ) -> Result<SendResult, ClientError> {
        let response = self
            .agent(AgentFrame::Send {
                schema_version: Some(SCHEMA_VERSION),
                to: to.to_owned(),
                text: text.to_owned(),
                idempotency_key: key.map(str::to_owned),
                as_agent: None,
                codex_session: None,
                codex_thread: None,
                codex_turn: None,
            })
            .await?;
        let mut value = response;
        value
            .as_object_mut()
            .ok_or(ClientError::Protocol)?
            .remove("status");
        serde_json::from_value(value).map_err(|_| ClientError::Protocol)
    }

    pub async fn reply(
        &self,
        message_id: &str,
        text: &str,
        key: Option<&str>,
    ) -> Result<ReplyRecord, ClientError> {
        let response = self
            .agent(AgentFrame::Reply {
                schema_version: Some(SCHEMA_VERSION),
                message_id: message_id.to_owned(),
                text: text.to_owned(),
                idempotency_key: key.map(str::to_owned),
                as_agent: None,
                codex_session: None,
                codex_thread: None,
                codex_turn: None,
            })
            .await?;
        serde_json::from_value(
            response
                .get("reply")
                .cloned()
                .ok_or(ClientError::Protocol)?,
        )
        .map_err(|_| ClientError::Protocol)
    }

    pub async fn list(&self, query: ListQuery) -> Result<ListResult, ClientError> {
        let mut value = self
            .agent(AgentFrame::List {
                schema_version: Some(SCHEMA_VERSION),
                name: query.name,
                node: query.node,
                kind: query.kind,
                status: query.status,
                within: query.within,
                as_agent: None,
                codex_session: None,
                codex_thread: None,
                codex_turn: None,
            })
            .await?;
        value
            .as_object_mut()
            .ok_or(ClientError::Protocol)?
            .remove("status");
        serde_json::from_value(value).map_err(|_| ClientError::Protocol)
    }
}

#[cfg(test)]
mod feature_tests {
    #[test]
    #[ignore = "client-only CI explicitly executes this feature-leak sentinel"]
    fn no_daemon() {
        #[cfg(feature = "daemon")]
        panic!("daemon leaked into client-only tests");
    }
}
