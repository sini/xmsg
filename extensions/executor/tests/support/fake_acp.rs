use serde_json::{json, Value};
use xmsg_executor::{
    framing::{Failure, Frame, Request, RpcError, Success},
    protocol::ContentEnvelope,
};

#[derive(Default)]
pub struct FakePeer {
    pub prompts: usize,
    pub injections: usize,
    pub child_observations: usize,
    pub hard_denials: usize,
    pub pending_requests: Vec<String>,
    pub content: Vec<ContentEnvelope>,
    pub active: Option<(u64, String)>,
    pub wedged_cancel: bool,
}
impl FakePeer {
    pub fn content(&mut self, delivery: ContentEnvelope) {
        self.content.push(delivery);
    }
    pub fn frame(&mut self, frame: Frame) -> Option<Frame> {
        match frame {
            Frame::Request(request) => Some(self.request(request)),
            Frame::Notification(note) => {
                match note.params.as_ref().and_then(|p| p["kind"].as_str()) {
                    Some("session_message") => self.child_observations += 1,
                    Some("hard_denial" | "failed_tool") => self.hard_denials += 1,
                    _ => {}
                }
                None
            }
            _ => None,
        }
    }
    fn request(&mut self, request: Request) -> Frame {
        let params = request
            .params
            .as_ref()
            .cloned()
            .unwrap_or_else(|| json!({}));
        let success = |result: Value| {
            Frame::Success(Success {
                jsonrpc: "2.0".into(),
                id: request.id.clone(),
                result,
            })
        };
        let error = |code, message: &str| {
            Frame::Failure(Failure {
                jsonrpc: "2.0".into(),
                id: request.id.clone(),
                error: RpcError {
                    code,
                    message: message.into(),
                    data: None,
                },
            })
        };
        match request.method.as_str() {
            "initialize" => {
                if params["protocolVersion"] == 1 {
                    success(json!({"protocolVersion":1,"evidenceClass":"fake_only"}))
                } else {
                    error(-32602, "unsupported protocol version")
                }
            }
            "session/prompt" => {
                self.prompts += 1;
                self.active = Some((
                    params["generation"].as_u64().unwrap(),
                    params["turnId"].as_str().unwrap().into(),
                ));
                success(json!({"state":"running"}))
            }
            "_session/steering" => {
                if params["idleBehavior"] != "promptRequired" {
                    return error(-32602, "strict idle behavior required");
                }
                let addressed = (
                    params["generation"].as_u64().unwrap(),
                    params["turnId"].as_str().unwrap().to_owned(),
                );
                if self.active.as_ref() == Some(&addressed) {
                    self.injections += 1;
                    success(json!({"state":"injected"}))
                } else {
                    success(json!({"state":"promptRequired"}))
                }
            }
            "session/cancel" => {
                if self.wedged_cancel {
                    success(json!({"submission":"submitted","effect":"unknown"}))
                } else if self.active.take().is_some() {
                    success(json!({"submission":"submitted","effect":"confirmed"}))
                } else {
                    success(json!({"submission":"not_attempted","effect":"already_ended"}))
                }
            }
            "session/request_permission" => {
                self.pending_requests.push(format!("{:?}", request.id));
                success(json!({"state":"pending"}))
            }
            _ => error(-32601, "method not supported by deterministic fixture"),
        }
    }
}
