use crate::{
    framing::{RequestId, MAX_FRAME_BYTES},
    membership::{ContentProxy, ContentStore, ProxyBinding},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, value::RawValue, Value};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    io::{self, BufRead, Read, Write},
    os::unix::{fs::MetadataExt, net::UnixListener as StdListener},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};
use xmsg::client::{AgentClient, ClientError, ClientOptions, ListQuery};

const PREAMBLE: &[u8] = b"XMSG-EXECUTOR-CONTENT/1\n";
const SDK_TIMEOUT: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_WORKERS: usize = 4;
const MAX_TEXT_BYTES: usize = 64 * 1024;
const PROTOCOL: &str = "2025-06-18";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BusConfig {
    pub node: String,
    pub register_socket: PathBuf,
    pub agent_socket: PathBuf,
    #[serde(default)]
    pub auto_input: bool,
}
impl BusConfig {
    pub fn validate(&self) -> Result<(), ContentError> {
        if self.node.is_empty()
            || self.node.len() > 256
            || self.node.chars().any(char::is_control)
            || !self.register_socket.is_absolute()
            || !self.agent_socket.is_absolute()
            || self.register_socket == self.agent_socket
        {
            return Err(ContentError::Configuration);
        }
        Ok(())
    }
    pub(crate) fn client_options(&self) -> Result<ClientOptions, ContentError> {
        self.validate()?;
        Ok(ClientOptions {
            register_socket: self.register_socket.clone(),
            agent_socket: self.agent_socket.clone(),
            max_frame_bytes: MAX_FRAME_BYTES,
            operation_timeout: SDK_TIMEOUT,
            service: String::new(),
            expected_node: Some(self.node.clone()),
            daemon_uid: xmsg::client::current_uid(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ContentError {
    #[error("invalid content bridge configuration")]
    Configuration,
    #[error("untrusted content socket")]
    Peer,
    #[error("content transport failed")]
    Io(#[from] io::Error),
    #[error("content frame invalid or exceeds limit")]
    Frame,
    #[error("content bus unavailable")]
    Bus,
    #[error("content service shutdown is uncertain")]
    ShutdownUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ContentStatus {
    Starting,
    Ready { address: String },
    Failed,
    Stopped,
}

pub(crate) struct ContentServiceHandle {
    stop: Arc<AtomicBool>,
    ready: mpsc::Receiver<Result<String, ()>>,
    done: mpsc::Receiver<()>,
    thread: Option<thread::JoinHandle<()>>,
    status: ContentStatus,
}
impl ContentServiceHandle {
    pub(crate) fn status(&mut self) -> ContentStatus {
        match self.ready.try_recv() {
            Ok(Ok(address)) => self.status = ContentStatus::Ready { address },
            Ok(Err(())) => self.status = ContentStatus::Failed,
            Err(_) => {}
        }
        if self
            .thread
            .as_ref()
            .is_some_and(|thread| thread.is_finished())
        {
            self.status = if self.stop.load(Ordering::Acquire) {
                ContentStatus::Stopped
            } else {
                ContentStatus::Failed
            };
        }
        self.status.clone()
    }
    pub(crate) fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
    }
    pub(crate) fn shutdown(&mut self, bound: Duration) -> Result<(), ContentError> {
        self.request_stop();
        self.done
            .recv_timeout(bound)
            .map_err(|_| ContentError::ShutdownUnknown)?;
        if let Some(handle) = self.thread.take() {
            handle.join().map_err(|_| ContentError::ShutdownUnknown)?;
        }
        Ok(())
    }
}
impl Drop for ContentServiceHandle {
    fn drop(&mut self) {
        self.request_stop();
    }
}

pub(crate) fn start_content_service<S: ContentStore + Send + 'static>(
    config: BusConfig,
    binding: ProxyBinding,
    store: S,
    listener: StdListener,
) -> Result<ContentServiceHandle, ContentError> {
    config.validate()?;
    let socket = listener
        .local_addr()?
        .as_pathname()
        .ok_or(ContentError::Configuration)?
        .to_owned();
    if socket == config.register_socket || socket == config.agent_socket {
        return Err(ContentError::Configuration);
    }
    private_socket(&socket)?;
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let running = stop.clone();
    let (ready_tx, ready) = mpsc::sync_channel(1);
    let (done_tx, done) = mpsc::sync_channel(1);
    let handle = thread::Builder::new()
        .name("executor-content".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            let result = match runtime {
                Ok(runtime) => runtime.block_on(run_content_service(
                    config, binding, store, listener, running, &ready_tx,
                )),
                Err(_) => Err(ContentError::Bus),
            };
            if result.is_err() {
                let _ = ready_tx.try_send(Err(()));
            }
            let _ = done_tx.try_send(());
        })?;
    Ok(ContentServiceHandle {
        stop,
        ready,
        done,
        thread: Some(handle),
        status: ContentStatus::Starting,
    })
}

async fn run_content_service<S: ContentStore + Send + 'static>(
    config: BusConfig,
    binding: ProxyBinding,
    mut store: S,
    listener: StdListener,
    stop: Arc<AtomicBool>,
    ready: &mpsc::SyncSender<Result<String, ()>>,
) -> Result<(), ContentError> {
    let mut proxy = ContentProxy::register(config.client_options()?, binding.clone())
        .await
        .map_err(|_| ContentError::Bus)?;
    let bus = proxy.agent_client().map_err(|_| ContentError::Bus)?;
    let listener = UnixListener::from_std(listener)?;
    let _ = ready.try_send(Ok(proxy.address().to_owned()));
    let mut input_task = None;
    let retained_proxy;
    if config.auto_input {
        let input_stop = stop.clone();
        input_task = Some(tokio::spawn(async move {
            while !input_stop.load(Ordering::Acquire) {
                proxy
                    .receive_once(&mut store, 0)
                    .await
                    .map_err(|_| ContentError::Bus)?;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok::<(), ContentError>(())
        }));
        retained_proxy = None;
    } else {
        retained_proxy = Some(proxy);
    }
    let mut workers = Vec::<tokio::task::JoinHandle<()>>::new();
    while !stop.load(Ordering::Acquire) {
        if bus.health().is_err() || input_task.as_ref().is_some_and(|task| task.is_finished()) {
            for worker in workers {
                worker.abort();
            }
            if let Some(task) = input_task {
                task.abort();
            }
            return Err(ContentError::Bus);
        }
        workers.retain(|worker| !worker.is_finished());
        match tokio::time::timeout(Duration::from_millis(50), listener.accept()).await {
            Ok(Ok((stream, _))) if workers.len() < MAX_WORKERS => {
                let client = bus.clone();
                let bound = binding.clone();
                workers.push(tokio::spawn(async move {
                    let _ = tokio::time::timeout(
                        REQUEST_TIMEOUT,
                        serve_connection(stream, &client, &bound),
                    )
                    .await;
                }));
            }
            Ok(Err(_)) => return Err(ContentError::Bus),
            _ => {}
        }
    }
    for worker in workers {
        worker.abort();
    }
    if let Some(task) = input_task {
        task.abort();
    }
    drop(retained_proxy);
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "tool",
    content = "arguments",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ContentCall {
    List(ListArgs),
    Send(SendArgs),
    Reply(ReplyArgs),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArgs {
    name: Option<String>,
    node: Option<String>,
    kind: Option<String>,
    status: Option<String>,
    within: Option<u64>,
    #[serde(default = "default_limit")]
    limit: u16,
}
fn default_limit() -> u16 {
    50
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SendArgs {
    to: String,
    text: String,
    request_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyArgs {
    message_id: String,
    text: String,
    request_id: String,
}
impl ContentCall {
    fn validate(&self) -> Result<(), ContentError> {
        fn token(value: &str) -> bool {
            !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
        }
        fn key(value: &str) -> bool {
            token(value) && value.len() <= 128
        }
        match self {
            Self::List(args) => {
                if !(1..=500).contains(&args.limit)
                    || [&args.name, &args.node]
                        .iter()
                        .any(|v| v.as_ref().is_some_and(|s| !token(s)))
                    || args
                        .kind
                        .as_ref()
                        .is_some_and(|s| !matches!(s.as_str(), "service" | "instance" | "subagent"))
                    || args
                        .status
                        .as_ref()
                        .is_some_and(|s| !matches!(s.as_str(), "live" | "inactive"))
                {
                    return Err(ContentError::Frame);
                }
            }
            Self::Send(args) => {
                if !token(&args.to) || !key(&args.request_id) || args.text.len() > MAX_TEXT_BYTES {
                    return Err(ContentError::Frame);
                }
            }
            Self::Reply(args) => {
                if !token(&args.message_id)
                    || !key(&args.request_id)
                    || args.text.len() > MAX_TEXT_BYTES
                {
                    return Err(ContentError::Frame);
                }
            }
        }
        Ok(())
    }
}
trait TextBus: Sync {
    fn list(&self, args: &ListArgs) -> impl Future<Output = Result<Value, ClientError>> + Send;
    fn send(
        &self,
        args: &SendArgs,
        key: &str,
    ) -> impl Future<Output = Result<Value, ClientError>> + Send;
    fn reply(
        &self,
        args: &ReplyArgs,
        key: &str,
    ) -> impl Future<Output = Result<Value, ClientError>> + Send;
}
impl TextBus for AgentClient {
    async fn list(&self, a: &ListArgs) -> Result<Value, ClientError> {
        serde_json::to_value(
            AgentClient::list(
                self,
                ListQuery {
                    name: a.name.clone(),
                    node: a.node.clone(),
                    kind: a.kind.clone(),
                    status: a.status.clone(),
                    within: a.within,
                    limit: Some(usize::from(a.limit)),
                },
            )
            .await?,
        )
        .map_err(|_| ClientError::Protocol)
    }
    async fn send(&self, a: &SendArgs, key: &str) -> Result<Value, ClientError> {
        serde_json::to_value(AgentClient::send(self, &a.to, &a.text, Some(key)).await?)
            .map_err(|_| ClientError::Protocol)
    }
    async fn reply(&self, a: &ReplyArgs, key: &str) -> Result<Value, ClientError> {
        serde_json::to_value(AgentClient::reply(self, &a.message_id, &a.text, Some(key)).await?)
            .map_err(|_| ClientError::Protocol)
    }
}
fn idempotency_key(binding: &ProxyBinding, request_id: &str) -> String {
    let bytes = serde_json::to_vec(&(
        "executor-content-v1",
        binding.session_id(),
        binding.generation(),
        request_id,
    ))
    .expect("fixed tuple serializes");
    hex::encode(Sha256::digest(bytes))
}
async fn dispatch(bus: &impl TextBus, binding: &ProxyBinding, call: &ContentCall) -> Value {
    if call.validate().is_err() {
        return json!({"ok":false,"error":"invalid_content_call"});
    }
    let operation = async {
        match call {
            ContentCall::List(a) => bus.list(a).await,
            ContentCall::Send(a) => bus.send(a, &idempotency_key(binding, &a.request_id)).await,
            ContentCall::Reply(a) => bus.reply(a, &idempotency_key(binding, &a.request_id)).await,
        }
    };
    match tokio::time::timeout(SDK_TIMEOUT, operation).await {
        Ok(Ok(result)) => json!({"ok":true,"result":result}),
        Ok(Err(ClientError::Timeout)) | Err(_) => {
            json!({"ok":false,"error":"content_submission_unknown"})
        }
        Ok(Err(_)) => json!({"ok":false,"error":"content_bus_unavailable"}),
    }
}
async fn read_async_line(
    reader: &mut (impl tokio::io::AsyncBufRead + Unpin),
    limit: usize,
) -> Result<Vec<u8>, ContentError> {
    let mut line = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut line)
        .await?;
    if line.len() > limit || line.last() != Some(&b'\n') {
        return Err(ContentError::Frame);
    }
    Ok(line)
}
async fn serve_connection(
    stream: UnixStream,
    bus: &impl TextBus,
    binding: &ProxyBinding,
) -> Result<(), ContentError> {
    if stream.peer_cred()?.uid() != xmsg::client::current_uid() {
        return Err(ContentError::Peer);
    }
    let mut reader = BufReader::new(stream);
    if read_async_line(&mut reader, PREAMBLE.len()).await? != PREAMBLE {
        return Err(ContentError::Frame);
    }
    reader.get_mut().write_all(PREAMBLE).await?;
    let bytes = read_async_line(&mut reader, MAX_FRAME_BYTES).await?;
    let response = match serde_json::from_slice::<ContentCall>(&bytes) {
        Ok(call) => dispatch(bus, binding, &call).await,
        Err(_) => json!({"ok":false,"error":"invalid_content_call"}),
    };
    let mut bytes = serde_json::to_vec(&response).map_err(|_| ContentError::Frame)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ContentError::Frame);
    }
    reader.get_mut().write_all(&bytes).await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpFrame {
    jsonrpc: String,
    #[serde(default)]
    id: IncomingId,
    method: String,
    params: Option<Box<RawValue>>,
}
#[derive(Default)]
enum IncomingId {
    #[default]
    Absent,
    Present(RequestId),
}
impl<'de> Deserialize<'de> for IncomingId {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        RequestId::deserialize(decoder).map(Self::Present)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolParams {
    name: String,
    arguments: Box<RawValue>,
}
enum LocalAction {
    Response(Value),
    Forward { id: RequestId, call: ContentCall },
    Ignore,
}
fn rpc_error(id: RequestId, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn tool_result(id: RequestId, result: Value) -> Value {
    let error = result.get("ok").and_then(Value::as_bool) != Some(true);
    let text = if error {
        result
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("invalid_content_response")
            .to_owned()
    } else {
        result.get("result").unwrap_or(&Value::Null).to_string()
    };
    json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":text}],"isError":error}})
}
fn tool_definitions() -> Value {
    json!([
        {"name":"list","description":"List bus recipients; narrow filters or raise limit.","inputSchema":{"type":"object","properties":{"name":{"type":"string"},"node":{"type":"string"},"kind":{"enum":["service","instance","subagent"]},"status":{"enum":["live","inactive"]},"within":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":500,"default":50}},"additionalProperties":false}},
        {"name":"send","description":"Send text as this execution's ordinary bus service.","inputSchema":{"type":"object","properties":{"to":{"type":"string"},"text":{"type":"string","maxLength":65536},"request_id":{"type":"string","maxLength":128}},"required":["to","text","request_id"],"additionalProperties":false}},
        {"name":"reply","description":"Reply with text as this execution's ordinary bus service.","inputSchema":{"type":"object","properties":{"message_id":{"type":"string"},"text":{"type":"string","maxLength":65536},"request_id":{"type":"string","maxLength":128}},"required":["message_id","text","request_id"],"additionalProperties":false}}
    ])
}
fn local_action(bytes: &[u8]) -> LocalAction {
    let frame = match serde_json::from_slice::<McpFrame>(bytes) {
        Ok(frame) => frame,
        Err(_) => {
            return LocalAction::Response(rpc_error(
                RequestId::Null(()),
                -32700,
                "invalid content MCP frame",
            ))
        }
    };
    let IncomingId::Present(id) = frame.id else {
        return LocalAction::Ignore;
    };
    if frame.jsonrpc != "2.0" {
        return LocalAction::Response(rpc_error(id, -32600, "invalid JSON-RPC version"));
    }
    match frame.method.as_str() {
        "notifications/initialized" | "notifications/cancelled" => LocalAction::Ignore,
        "initialize" => LocalAction::Response(
            json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":PROTOCOL,"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"xmsg-executor-content","version":env!("CARGO_PKG_VERSION")}}}),
        ),
        "ping" => LocalAction::Response(json!({"jsonrpc":"2.0","id":id,"result":{}})),
        "tools/list" => LocalAction::Response(
            json!({"jsonrpc":"2.0","id":id,"result":{"tools":tool_definitions()}}),
        ),
        "tools/call" => {
            let parsed = frame
                .params
                .as_ref()
                .and_then(|p| serde_json::from_str::<ToolParams>(p.get()).ok());
            let Some(params) = parsed else {
                return LocalAction::Response(rpc_error(
                    id,
                    -32602,
                    "invalid text-only tool arguments",
                ));
            };
            let parsed = match params.name.as_str() {
                "list" => {
                    serde_json::from_str::<ListArgs>(params.arguments.get()).map(ContentCall::List)
                }
                "send" => {
                    serde_json::from_str::<SendArgs>(params.arguments.get()).map(ContentCall::Send)
                }
                "reply" => serde_json::from_str::<ReplyArgs>(params.arguments.get())
                    .map(ContentCall::Reply),
                _ => return LocalAction::Response(rpc_error(id, -32601, "unknown content tool")),
            };
            match parsed {
                Ok(call) if call.validate().is_ok() => LocalAction::Forward { id, call },
                _ => {
                    LocalAction::Response(rpc_error(id, -32602, "invalid text-only tool arguments"))
                }
            }
        }
        _ => LocalAction::Response(rpc_error(id, -32601, "unknown content MCP method")),
    }
}
fn private_socket(socket: &Path) -> Result<(), ContentError> {
    let parent = socket.parent().ok_or(ContentError::Configuration)?;
    let dir = std::fs::symlink_metadata(parent)?;
    let entry = std::fs::symlink_metadata(socket)?;
    use std::os::unix::fs::FileTypeExt;
    let uid = xmsg::client::current_uid();
    if !dir.is_dir()
        || dir.uid() != uid
        || dir.mode() & 0o077 != 0
        || !entry.file_type().is_socket()
        || entry.uid() != uid
        || entry.mode() & 0o077 != 0
    {
        return Err(ContentError::Peer);
    }
    Ok(())
}
fn forward(socket: &Path, call: &ContentCall) -> Result<Value, ContentError> {
    private_socket(socket)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            let mut stream = UnixStream::connect(socket).await?;
            if stream.peer_cred()?.uid() != xmsg::client::current_uid() {
                return Err(ContentError::Peer);
            }
            // The static preamble is a protocol discriminator, never an identity credential.
            stream.write_all(PREAMBLE).await?;
            let mut reader = BufReader::new(stream);
            if read_async_line(&mut reader, PREAMBLE.len()).await? != PREAMBLE {
                return Err(ContentError::Peer);
            }
            let mut request = serde_json::to_vec(call).map_err(|_| ContentError::Frame)?;
            request.push(b'\n');
            if request.len() > MAX_FRAME_BYTES {
                return Err(ContentError::Frame);
            }
            reader.get_mut().write_all(&request).await?;
            serde_json::from_slice(&read_async_line(&mut reader, MAX_FRAME_BYTES).await?)
                .map_err(|_| ContentError::Frame)
        })
        .await
        .map_err(|_| ContentError::Bus)?
    })
}
fn read_line(reader: &mut impl BufRead, limit: usize) -> Result<Vec<u8>, ContentError> {
    let mut line = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut line)?;
    if line.len() > limit || line.last() != Some(&b'\n') {
        return Err(ContentError::Frame);
    }
    Ok(line)
}
pub(crate) fn run_stdio(socket: &Path) -> Result<(), ContentError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_stdio_with(socket, stdin.lock(), stdout.lock())
}
fn run_stdio_with(
    socket: &Path,
    mut input: impl BufRead,
    mut output: impl Write,
) -> Result<(), ContentError> {
    loop {
        if input.fill_buf()?.is_empty() {
            return Ok(());
        }
        let line = read_line(&mut input, MAX_FRAME_BYTES)?;
        let response = match local_action(&line) {
            LocalAction::Response(value) => Some(value),
            LocalAction::Ignore => None,
            LocalAction::Forward { id, call } => Some(tool_result(
                id,
                forward(socket, &call)
                    .unwrap_or_else(|_| json!({"ok":false,"error":"content_bus_unavailable"})),
            )),
        };
        if let Some(response) = response {
            let mut bytes = serde_json::to_vec(&response).map_err(|_| ContentError::Frame)?;
            bytes.push(b'\n');
            if bytes.len() > MAX_FRAME_BYTES {
                return Err(ContentError::Frame);
            }
            output.write_all(&bytes)?;
            output.flush()?;
        }
    }
}

#[cfg(test)]
#[path = "content_tests.rs"]
mod tests;
