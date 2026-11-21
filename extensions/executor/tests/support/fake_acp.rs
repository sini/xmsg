use serde_json::{json, Value};
use xmsg_executor::{
    framing::{Failure, Frame, Notification, Request, RequestId, RpcError, Success},
    protocol::ContentEnvelope,
};

#[derive(Default)]
pub struct FakePeer {
    pub prompts: usize,
    pub injections: usize,
    pub child_observations: usize,
    pub failed_tools: usize,
    pub pending_requests: Vec<RequestId>,
    pub content: Vec<ContentEnvelope>,
    pub active_prompt: Option<RequestId>,
    pub wedged_cancel: bool,
}
impl FakePeer {
    pub fn content(&mut self, delivery: ContentEnvelope) {
        self.content.push(delivery);
    }
    pub fn client_frame(&mut self, frame: Frame) -> Option<Frame> {
        match frame {
            Frame::Request(request) => self.request(request),
            Frame::Notification(note) if note.method == "session/cancel" => {
                if note.params.as_ref().and_then(|p| p["sessionId"].as_str())
                    != Some("fake-session")
                {
                    return None;
                }
                let id = if self.wedged_cancel {
                    self.active_prompt.clone()
                } else {
                    self.active_prompt.take()
                };
                id.map(|id| {
                    Frame::Success(Success {
                        jsonrpc: "2.0".into(),
                        id,
                        result: json!({"stopReason":"cancelled"}),
                    })
                })
            }
            Frame::Success(response) => {
                if let Some(index) = self
                    .pending_requests
                    .iter()
                    .position(|id| *id == response.id)
                {
                    let outcome = &response.result["outcome"];
                    assert!(
                        outcome["outcome"] == "cancelled"
                            || outcome["outcome"] == "selected"
                                && outcome["optionId"] == "allow-once"
                    );
                    self.pending_requests.remove(index);
                }
                None
            }
            _ => None,
        }
    }
    pub fn agent_update(&mut self, update: Value) -> Frame {
        match update["sessionUpdate"].as_str() {
            Some("session_message") => self.child_observations += 1,
            Some("tool_call_update") if update["status"] == "failed" => self.failed_tools += 1,
            _ => {}
        }
        Frame::Notification(Notification {
            jsonrpc: "2.0".into(),
            method: "session/update".into(),
            params: Some(json!({"sessionId":"fake-session","update":update})),
        })
    }
    pub fn permission_request(&mut self, id: RequestId) -> Frame {
        self.pending_requests.push(id.clone());
        Frame::Request(Request {
            jsonrpc: "2.0".into(),
            id,
            method: "session/request_permission".into(),
            params: Some(
                json!({"sessionId":"fake-session","toolCall":{"toolCallId":"tool-1","status":"pending","title":"harmless fixture"},"options":[{"optionId":"allow-once","name":"Allow once","kind":"allow_once"}]}),
            ),
        })
    }
    fn request(&mut self, request: Request) -> Option<Frame> {
        let params = request
            .params
            .as_ref()
            .cloned()
            .unwrap_or_else(|| json!({}));
        let success = |result: Value| {
            Some(Frame::Success(Success {
                jsonrpc: "2.0".into(),
                id: request.id.clone(),
                result,
            }))
        };
        let error = |code, message: &str| {
            Some(Frame::Failure(Failure {
                jsonrpc: "2.0".into(),
                id: request.id.clone(),
                error: RpcError {
                    code,
                    message: message.into(),
                    data: None,
                },
            }))
        };
        match request.method.as_str() {
            "initialize" => {
                if params["protocolVersion"] == 1 {
                    success(
                        json!({"protocolVersion":1,"agentCapabilities":{},"_meta":{"steering":{"supported":true}}}),
                    )
                } else {
                    error(-32602, "unsupported protocol version")
                }
            }
            "session/prompt" => {
                if params["sessionId"] != "fake-session" || !params["prompt"].is_array() {
                    return error(-32602, "invalid prompt");
                }
                if self.active_prompt.is_some() {
                    return error(-32000, "prompt already active");
                }
                self.prompts += 1;
                self.active_prompt = Some(request.id);
                None
            }
            "_session/steering" => {
                if params["sessionId"] != "fake-session"
                    || !params["prompt"].is_array()
                    || params["_meta"]["steering"]["idleBehavior"] != "promptRequired"
                {
                    return error(-32602, "strict steering fixture parameters required");
                }
                if self.active_prompt.is_some() {
                    self.injections += 1;
                    success(json!({"outcome":"injected"}))
                } else {
                    success(json!({"outcome":"promptRequired","reason":"noRunningTurn"}))
                }
            }
            _ => error(-32601, "method not supported by deterministic fixture"),
        }
    }
}
