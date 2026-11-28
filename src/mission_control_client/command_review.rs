use super::{MAX_WIRE, SUBPROTOCOL};
use futures_util::{SinkExt, StreamExt};
use reqwest::Url;
use serde_json::{json, Value};
use std::{cell::Cell, fmt::Write as _, io::Write, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http, Message},
    MaybeTlsStream, WebSocketStream,
};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ClientError {
    Connection,
    Protocol,
    Review,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommitResult {
    Withheld,
    Receipt(Value),
    EffectUnknown,
}

pub(crate) struct CommandReview {
    prepare: Value,
    sent_commit: Option<Value>,
}

impl CommandReview {
    pub(crate) fn new(prepare: Value) -> Self {
        Self {
            prepare,
            sent_commit: None,
        }
    }

    pub(crate) async fn review_session(
        &mut self,
        origin: &Url,
        handle: &str,
        output: &mut impl Write,
        review_budget: usize,
        read_key: impl FnOnce() -> Option<char>,
    ) -> Result<CommitResult, ClientError> {
        if self.sent_commit.is_some() {
            return Err(ClientError::Protocol);
        }
        let mut socket = connect(origin, handle).await?;
        send(&mut socket, &self.prepare).await?;
        let prepared = receive(&mut socket).await?;
        let review = presentation(&self.prepare, &prepared)?;
        if review.len() > review_budget {
            return Ok(CommitResult::Withheld);
        }
        output
            .write_all(review.as_bytes())
            .and_then(|()| output.flush())
            .map_err(|_| ClientError::Review)?;
        if read_key() != Some('\n') {
            return Ok(CommitResult::Withheld);
        }

        // A failed write can still have reached the server.
        let commit = json!({
            "v": 1, "type": "commit", "id": 3,
            "request_id": self.prepare["request_id"],
            "intent": prepared["intent"],
            "digest": prepared["digest"]
        });
        self.sent_commit = Some(commit.clone());
        if send(&mut socket, &commit).await.is_err() {
            return Ok(CommitResult::EffectUnknown);
        }
        match receive(&mut socket).await {
            Ok(receipt) => {
                check_receipt(&receipt, &self.prepare["request_id"], 3)?;
                Ok(CommitResult::Receipt(receipt))
            }
            Err(ClientError::Connection) => Ok(CommitResult::EffectUnknown),
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn reconcile(&self, origin: &Url, handle: &str) -> Result<Value, ClientError> {
        if self.sent_commit.is_none() {
            return Err(ClientError::Protocol);
        }
        let mut socket = connect(origin, handle).await?;
        let lookup = json!({
            "v": 1, "type": "lookup", "id": 2,
            "request_id": self.prepare["request_id"]
        });
        send(&mut socket, &lookup).await?;
        let receipt = receive(&mut socket).await?;
        check_receipt(&receipt, &self.prepare["request_id"], 2)?;
        if receipt["lookup"] != true {
            return Err(ClientError::Protocol);
        }
        Ok(receipt)
    }
}

pub(crate) async fn assert_exact_collector_review(
    origin: &Url,
    handle: &str,
    prepare: Value,
    expected_review: &str,
) -> Value {
    let mut command = CommandReview::new(prepare);
    let flushed = Cell::new(false);
    let mut output = ReviewOutput::new(&flushed);
    let result = command
        .review_session(origin, handle, &mut output, MAX_WIRE, || {
            assert!(
                flushed.get(),
                "the full review must be flushed before the key"
            );
            Some('\n')
        })
        .await
        .expect("real collector command review");
    assert_eq!(output.bytes, expected_review.as_bytes());
    let CommitResult::Receipt(receipt) = result else {
        panic!("expected real collector receipt, got {result:?}");
    };
    assert_eq!(receipt["outcome"], "refused");
    assert_eq!(receipt["code"], "unattested");
    assert!(receipt.get("target").is_none() && receipt.get("text").is_none());

    let recovered = command
        .reconcile(origin, handle)
        .await
        .expect("real collector receipt lookup");
    let mut expected = receipt.clone();
    expected["re"] = json!(2);
    expected["lookup"] = json!(true);
    assert_eq!(recovered, expected);
    receipt
}

struct ReviewOutput<'a> {
    bytes: Vec<u8>,
    flushed: &'a Cell<bool>,
}

impl<'a> ReviewOutput<'a> {
    fn new(flushed: &'a Cell<bool>) -> Self {
        Self {
            bytes: Vec::new(),
            flushed,
        }
    }
}

impl Write for ReviewOutput<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flushed.set(true);
        Ok(())
    }
}

fn presentation(request: &Value, prepared: &Value) -> Result<String, ClientError> {
    if prepared["v"] != 1
        || prepared["type"] != "prepared"
        || prepared["request_id"] != request["request_id"]
        || prepared["re"] != request["id"]
        || prepared["intent"].as_str().is_none()
        || prepared["digest"].as_str().is_none()
    {
        return Err(ClientError::Protocol);
    }
    let presentation = &prepared["presentation"];
    let target = &request["target"];
    let text = request["params"]["text"]
        .as_str()
        .ok_or(ClientError::Protocol)?;
    if presentation["verb"] != "send"
        || request["verb"] != "send"
        || presentation["params"] != json!([{"name":"text","value":text}])
        || ["node", "endpoint", "state_epoch", "incarnation", "selector"]
            .iter()
            .any(|field| presentation[*field] != target[*field])
    {
        return Err(ClientError::Protocol);
    }
    let node = presentation["node"].as_str().ok_or(ClientError::Protocol)?;
    let endpoint = presentation["endpoint"]
        .as_str()
        .ok_or(ClientError::Protocol)?;
    let epoch = presentation["state_epoch"]
        .as_str()
        .ok_or(ClientError::Protocol)?;
    let incarnation = presentation["incarnation"]
        .as_u64()
        .ok_or(ClientError::Protocol)?;
    let selector = &presentation["selector"];
    let session = selector["session_id"]
        .as_str()
        .ok_or(ClientError::Protocol)?;
    let generation = selector["generation"]
        .as_u64()
        .filter(|generation| (1..=(1 << 53) - 1).contains(generation))
        .ok_or(ClientError::Protocol)?;
    if selector["kind"] != "execution" {
        return Err(ClientError::Protocol);
    }
    Ok(format!(
        "Send to {} on {}\nEpoch {} incarnation {}\nExecution {} generation {}\nText: {}\n",
        inert(endpoint),
        inert(node),
        inert(epoch),
        incarnation,
        inert(session),
        generation,
        inert(text),
    ))
}

fn inert(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => output.push_str("\\\\"),
            ch if ch.is_control()
                || matches!(
                    ch,
                    '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{206f}' | '\u{2028}' | '\u{2029}'
                ) =>
            {
                write!(output, "\\u{{{:x}}}", u32::from(ch)).expect("write to String");
            }
            ch => output.push(ch),
        }
    }
    output
}

fn check_receipt(receipt: &Value, request_id: &Value, reply: u32) -> Result<(), ClientError> {
    if receipt["v"] != 1
        || receipt["type"] != "receipt"
        || receipt["request_id"] != *request_id
        || receipt["re"] != reply
        || receipt["receipt_id"].as_str().is_none()
    {
        return Err(ClientError::Protocol);
    }
    Ok(())
}

async fn connect(origin: &Url, handle: &str) -> Result<Socket, ClientError> {
    let mut url = origin
        .join("/v1/mission-control/session")
        .map_err(|_| ClientError::Protocol)?;
    let scheme = if origin.scheme() == "https" {
        "wss"
    } else {
        "ws"
    };
    url.set_scheme(scheme).map_err(|()| ClientError::Protocol)?;
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|_| ClientError::Protocol)?;
    request.headers_mut().insert(
        http::header::SEC_WEBSOCKET_PROTOCOL,
        http::HeaderValue::from_static(SUBPROTOCOL),
    );
    request.headers_mut().insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!("Bearer {handle}"))
            .map_err(|_| ClientError::Protocol)?,
    );
    let (mut socket, _) = timeout(Duration::from_secs(5), connect_async(request))
        .await
        .map_err(|_| ClientError::Connection)?
        .map_err(|_| ClientError::Connection)?;
    send(
        &mut socket,
        &json!({"v":1,"type":"hello","id":1,"protocol":1,"capabilities":["commands"],"require":["commands"]}),
    )
    .await?;
    let reply = receive(&mut socket).await?;
    if reply["type"] != "hello"
        || reply["re"] != 1
        || !reply["capabilities"]
            .as_array()
            .is_some_and(|values| values.iter().any(|value| value == "commands"))
    {
        return Err(ClientError::Protocol);
    }
    Ok(socket)
}

async fn send(socket: &mut Socket, value: &Value) -> Result<(), ClientError> {
    timeout(
        Duration::from_secs(5),
        socket.send(Message::Text(value.to_string().into())),
    )
    .await
    .map_err(|_| ClientError::Connection)?
    .map_err(|_| ClientError::Connection)
}

async fn receive(socket: &mut Socket) -> Result<Value, ClientError> {
    timeout(Duration::from_secs(5), async {
        while let Some(Ok(message)) = socket.next().await {
            match message {
                Message::Text(text) if text.len() <= MAX_WIRE => {
                    return serde_json::from_str(text.as_str()).map_err(|_| ClientError::Protocol);
                }
                Message::Ping(_) | Message::Pong(_) => (),
                Message::Close(_) => break,
                _ => return Err(ClientError::Protocol),
            }
        }
        Err(ClientError::Connection)
    })
    .await
    .map_err(|_| ClientError::Connection)?
}

mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::handshake::server::{Request, Response},
    };

    fn prepare(text: &str) -> Value {
        json!({
            "v":1,"type":"prepare","id":2,
            "request_id":"6f1e2d3c4b5a69788796a5b4c3d2e1f0",
            "requested_at":1795000000500u64,"verb":"send",
            "target":{
                "node":"laptop","endpoint":"claude-1@laptop",
                "state_epoch":"0a1b2c3d4e5f60718293a4b5c6d7e8f9","incarnation":3,
                "selector":{"kind":"execution","session_id":"exec-alpha","generation":7}
            },
            "params":{"text":text}
        })
    }

    fn prepared(request: &Value) -> Value {
        let mut presentation = request["target"].clone();
        presentation["verb"] = json!("send");
        presentation["params"] = json!([{"name":"text","value":request["params"]["text"]}]);
        json!({
            "v":1,"type":"prepared","re":request["id"],"request_id":request["request_id"],
            "intent":"AAECAwQFBgcICQoLDA0ODw",
            "digest":"sha256:f50895db882b71402f0073153a3692984018a1bd4be18f248d6913b12edb1fe31",
            "presentation":presentation
        })
    }

    #[allow(clippy::result_large_err)]
    async fn accept(listener: &TcpListener) -> WebSocketStream<TcpStream> {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_hdr_async(stream, |_: &Request, mut response: Response| {
            response.headers_mut().insert(
                http::header::SEC_WEBSOCKET_PROTOCOL,
                http::HeaderValue::from_static(SUBPROTOCOL),
            );
            Ok(response)
        })
        .await
        .unwrap();
        assert_eq!(read(&mut socket).await["type"], "hello");
        reply(
            &mut socket,
            json!({"v":1,"type":"hello","re":1,"capabilities":["commands"]}),
        )
        .await;
        socket
    }

    async fn read(socket: &mut WebSocketStream<TcpStream>) -> Value {
        let frame = socket.next().await.unwrap().unwrap();
        serde_json::from_str(frame.into_text().unwrap().as_str()).unwrap()
    }

    async fn reply(socket: &mut WebSocketStream<TcpStream>, value: Value) {
        socket
            .send(Message::Text(value.to_string().into()))
            .await
            .unwrap();
    }

    async fn listener() -> (TcpListener, Url) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let origin = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        (listener, origin)
    }

    #[tokio::test]
    async fn sc5_reconnect_sends_only_lookup_after_lost_commit_response() {
        let (listener, origin) = listener().await;
        let server = tokio::spawn(async move {
            let mut socket = accept(&listener).await;
            let request = read(&mut socket).await;
            let answer = prepared(&request);
            reply(&mut socket, answer.clone()).await;
            let commit = read(&mut socket).await;
            assert_eq!(commit["type"], "commit");
            assert_eq!(commit["intent"], answer["intent"]);
            assert_eq!(commit["digest"], answer["digest"]);
            drop(socket);

            let mut reconnected = accept(&listener).await;
            let lookup = read(&mut reconnected).await;
            assert_eq!(lookup["type"], "lookup");
            assert_eq!(lookup["request_id"], request["request_id"]);
            reply(
                &mut reconnected,
                json!({
                    "v":1,"type":"receipt","re":lookup["id"],"request_id":lookup["request_id"],
                    "receipt_id":"r_01","outcome":"effect_unknown","lookup":true
                }),
            )
            .await;
            assert!(!matches!(
                reconnected.next().await,
                Some(Ok(Message::Text(_)))
            ));
        });

        let mut review = CommandReview::new(prepare("Check the task status."));
        let mut output = Vec::new();
        assert_eq!(
            review
                .review_session(&origin, "fixture", &mut output, MAX_WIRE, || Some('\n'))
                .await
                .unwrap(),
            CommitResult::EffectUnknown
        );
        assert_eq!(
            review
                .review_session(&origin, "fixture", &mut output, MAX_WIRE, || Some('\n'))
                .await,
            Err(ClientError::Protocol)
        );
        assert_eq!(
            review.reconcile(&origin, "fixture").await.unwrap()["receipt_id"],
            "r_01"
        );
        timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn sc13_full_escaped_review_precedes_key_and_commit() {
        let (listener, origin) = listener().await;
        let server = tokio::spawn(async move {
            let mut socket = accept(&listener).await;
            let request = read(&mut socket).await;
            reply(&mut socket, prepared(&request)).await;
            let commit = read(&mut socket).await;
            assert_eq!(commit["type"], "commit");
            assert_eq!(commit.as_object().unwrap().len(), 6);
            reply(
                &mut socket,
                json!({
                    "v":1,"type":"receipt","re":commit["id"],"request_id":commit["request_id"],
                    "receipt_id":"r_01","outcome":"effect_unknown"
                }),
            )
            .await;
        });

        let mut review = CommandReview::new(prepare(concat!(
            "<b>**verbatim**</b>\x1b\u{202e}\n",
            "\u{061c}\u{200e}\u{200f}\u{2066}\u{2067}\u{2068}\u{2069}\u{2028}\u{2029}end"
        )));
        let witness = Cell::new(false);
        let mut output = ReviewOutput::new(&witness);
        let result = review
            .review_session(&origin, "fixture", &mut output, MAX_WIRE, || {
                assert!(
                    witness.get(),
                    "the full review must be flushed before the key"
                );
                Some('\n')
            })
            .await
            .unwrap();
        assert!(matches!(result, CommitResult::Receipt(_)));
        assert_eq!(
            String::from_utf8(output.bytes).unwrap(),
            concat!(
                "Send to claude-1@laptop on laptop\n",
                "Epoch 0a1b2c3d4e5f60718293a4b5c6d7e8f9 incarnation 3\n",
                "Execution exec-alpha generation 7\n",
                "Text: <b>**verbatim**</b>\\u{1b}\\u{202e}\\u{a}",
                "\\u{61c}\\u{200e}\\u{200f}\\u{2066}\\u{2067}\\u{2068}\\u{2069}",
                "\\u{2028}\\u{2029}end\n"
            ),
            "full review left control or bidi characters unescaped"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sc13_incomplete_review_or_nonconfirm_key_withholds_commit() {
        for (budget, key) in [(10, Some('\n')), (MAX_WIRE, Some('n'))] {
            let (listener, origin) = listener().await;
            let server = tokio::spawn(async move {
                let mut socket = accept(&listener).await;
                let request = read(&mut socket).await;
                reply(&mut socket, prepared(&request)).await;
                assert!(!matches!(socket.next().await, Some(Ok(Message::Text(_)))));
            });
            let mut review = CommandReview::new(prepare("Check the task status."));
            let mut output = Vec::new();
            let pressed = Cell::new(false);
            let result = review
                .review_session(&origin, "fixture", &mut output, budget, || {
                    pressed.set(true);
                    key
                })
                .await
                .unwrap();
            assert_eq!(result, CommitResult::Withheld);
            assert_eq!(pressed.get(), budget == MAX_WIRE);
            assert_eq!(!output.is_empty(), budget == MAX_WIRE);
            timeout(Duration::from_secs(5), server)
                .await
                .unwrap()
                .unwrap();
        }
    }
    #[tokio::test]
    async fn sc13_mismatched_destination_never_reaches_review_or_commit() {
        let (listener, origin) = listener().await;
        let server = tokio::spawn(async move {
            let mut socket = accept(&listener).await;
            let request = read(&mut socket).await;
            let mut answer = prepared(&request);
            answer["presentation"]["selector"]["generation"] = json!(8);
            reply(&mut socket, answer).await;
            assert!(!matches!(socket.next().await, Some(Ok(Message::Text(_)))));
        });
        let mut review = CommandReview::new(prepare("Check the task status."));
        let mut output = Vec::new();
        assert_eq!(
            review
                .review_session(&origin, "fixture", &mut output, MAX_WIRE, || {
                    panic!("key requested for a mismatched destination")
                })
                .await,
            Err(ClientError::Protocol)
        );
        assert!(output.is_empty());
        timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }
}
