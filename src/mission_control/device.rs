use super::*;
use std::collections::VecDeque;

pub(super) const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";

#[derive(Default)]
pub(super) struct Devices {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    entries: HashMap<[u8; 32], Entry>,
    issued: VecDeque<i64>,
    attempts: HashMap<String, VecDeque<i64>>,
}

struct Entry {
    code: String,
    issued_at: i64,
    expires: i64,
    interval: i64,
    next_poll: i64,
    source: String,
    agent: String,
    checked: Option<String>,
    decision: Decision,
}

enum Decision {
    Pending,
    Denied,
    Approved(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Begin {
    client_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Poll {
    client_id: String,
    grant_type: String,
    device_code: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Review,
    Approve,
    Deny,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    action: Action,
    user_code: String,
    csrf: String,
}

fn json(status: StatusCode, value: serde_json::Value) -> WebResponse {
    response(status, "application/json", value.to_string())
}

fn oauth_error(status: StatusCode, code: &str) -> WebResponse {
    json(status, serde_json::json!({"error": code}))
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn user_code() -> Result<String, Error> {
    let mut code = String::new();
    while code.len() < 8 {
        for byte in random::<8>()? {
            if byte < 240 {
                code.push(ALPHABET[usize::from(byte % 20)] as char);
                if code.len() == 8 {
                    break;
                }
            }
        }
    }
    Ok(code)
}

impl State {
    fn prune(&mut self, now: i64) {
        self.entries
            .retain(|_, entry| entry.expires.saturating_add(600) > now);
        self.issued
            .retain(|issued| now.saturating_sub(*issued) < 60);
        self.attempts.retain(|_, timestamps| {
            timestamps.retain(|attempt| now.saturating_sub(*attempt) < 600);
            !timestamps.is_empty()
        });
    }
}

impl Issuer {
    pub(super) async fn device_authorization(&self, request: Request<Incoming>) -> WebResponse {
        let source = request
            .extensions()
            .get::<std::net::SocketAddr>()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".into());
        let agent = request
            .headers()
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("unknown")
            .chars()
            .take(256)
            .collect();
        let Some(payload): Option<Begin> = form(request).await else {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        if payload.client_id != self.config.native_client_id {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_client");
        }
        self.begin_device(now_epoch_secs(), source, agent)
            .unwrap_or_else(|_| unavailable())
    }

    pub(super) fn begin_device(
        &self,
        now: i64,
        source: String,
        agent: String,
    ) -> Result<WebResponse, Error> {
        let mut state = self.devices.state.lock().map_err(|_| Error::Unavailable)?;
        state.prune(now);
        let live = state
            .entries
            .values()
            .filter(|entry| entry.expires > now)
            .count();
        if live >= self.config.device_codes_live
            || state.issued.len() >= self.config.device_authorizations_per_min
        {
            return Ok(oauth_error(StatusCode::TOO_MANY_REQUESTS, "slow_down"));
        }
        let device_code = opaque()?;
        let hash = digest(&device_code);
        if state.entries.contains_key(&hash) {
            return Err(Error::Unavailable);
        }
        let code = loop {
            let candidate = user_code()?;
            if !state
                .entries
                .values()
                .any(|entry| entry.expires > now && entry.code == candidate)
            {
                break candidate;
            }
        };
        let interval = self.config.device_poll_secs as i64;
        state.entries.insert(
            hash,
            Entry {
                code: code.clone(),
                issued_at: now,
                expires: now.saturating_add(self.config.device_code_ttl_secs as i64),
                interval,
                next_poll: now.saturating_add(interval),
                source,
                agent,
                checked: None,
                decision: Decision::Pending,
            },
        );
        state.issued.push_back(now);
        Ok(json(
            StatusCode::OK,
            serde_json::json!({
                "device_code": device_code, "user_code": code,
                "verification_uri": format!("{}/device", self.config.public_origin),
                "expires_in": self.config.device_code_ttl_secs,
                "interval": self.config.device_poll_secs,
            }),
        ))
    }

    pub(super) async fn device_token(&self, request: Request<Incoming>) -> WebResponse {
        let Some(payload): Option<Poll> = form(request).await else {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        if payload.grant_type != DEVICE_GRANT
            || payload.device_code.len() != 64
            || !payload
                .device_code
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
        }
        if payload.client_id != self.config.native_client_id {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_client");
        }
        self.poll_device(&payload.device_code, now_epoch_secs())
            .unwrap_or_else(|_| unavailable())
    }

    pub(super) fn poll_device(&self, device_code: &str, now: i64) -> Result<WebResponse, Error> {
        let mut state = self.devices.state.lock().map_err(|_| Error::Unavailable)?;
        state.prune(now);
        let hash = digest(device_code);
        let Some(entry) = state.entries.get_mut(&hash) else {
            return Ok(oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"));
        };
        if entry.expires <= now {
            return Ok(oauth_error(StatusCode::BAD_REQUEST, "expired_token"));
        }
        if now < entry.next_poll {
            entry.interval = entry.interval.saturating_add(5);
            entry.next_poll = now.saturating_add(entry.interval);
            return Ok(oauth_error(StatusCode::BAD_REQUEST, "slow_down"));
        }
        entry.next_poll = now.saturating_add(entry.interval);
        match &entry.decision {
            Decision::Pending => Ok(oauth_error(
                StatusCode::BAD_REQUEST,
                "authorization_pending",
            )),
            Decision::Denied => Ok(oauth_error(StatusCode::BAD_REQUEST, "access_denied")),
            Decision::Approved(parent) => {
                let issued = self
                    .authority
                    .issue_native(parent)
                    .map_err(|_| Error::Unavailable)?;
                state.entries.remove(&hash);
                Ok(json(
                    StatusCode::OK,
                    serde_json::json!({
                        "access_token": issued.handle, "token_type": "Bearer",
                        "expires_in": issued.record.absolute_expires_at.saturating_sub(now),
                    }),
                ))
            }
        }
    }

    pub(super) async fn device_page(&self, headers: &header::HeaderMap) -> WebResponse {
        let Some((handle, _)) = self.browser(headers).await else {
            return redirect("/login");
        };
        response(StatusCode::OK, "text/html; charset=utf-8", format!(
            "<!doctype html><title>Connect a device</title><h1>Connect a device</h1>\
             <form method=\"post\" action=\"/device\"><label>Device code <input name=\"user_code\" required maxlength=\"8\"></label>\
             <input type=\"hidden\" name=\"csrf\" value=\"{}\"><button name=\"action\" value=\"review\">Review</button></form>",
             csrf(&handle)
        ))
    }

    pub(super) async fn device_approval(&self, request: Request<Incoming>) -> WebResponse {
        if !self.exact_origin(request.headers()) {
            return forbidden();
        }
        let Some((handle, record)) = self.browser(request.headers()).await else {
            return denied();
        };
        let Some(payload): Option<Approval> = form(request).await else {
            return forbidden();
        };
        if !self.synchronizer(&handle, &payload.csrf) {
            return forbidden();
        }
        self.review_device(&record.record_id, payload, now_epoch_secs())
            .unwrap_or_else(|_| unavailable())
    }

    fn review_device(
        &self,
        record: &str,
        payload: Approval,
        now: i64,
    ) -> Result<WebResponse, Error> {
        let mut state = self.devices.state.lock().map_err(|_| Error::Unavailable)?;
        state.prune(now);
        if state
            .attempts
            .get(record)
            .is_some_and(|attempts| attempts.len() >= self.config.device_code_attempts_per_session)
        {
            return Ok(forbidden());
        }
        let code = payload.user_code.to_ascii_uppercase();
        let entry = state.entries.values_mut().find(|entry| {
            entry.code == code && entry.expires > now && matches!(entry.decision, Decision::Pending)
        });
        let Some(entry) = entry else {
            state
                .attempts
                .entry(record.to_owned())
                .or_default()
                .push_back(now);
            return Ok(forbidden());
        };
        match payload.action {
            Action::Review => {
                entry.checked = Some(record.to_owned());
                Ok(response(StatusCode::OK, "text/html; charset=utf-8", format!(
                    "<!doctype html><title>Review device</title><h1>Review device</h1>\
                    <dl><dt>Client</dt><dd>{}</dd><dt>Requested at (Unix seconds)</dt><dd>{}</dd>\
                    <dt>Source</dt><dd>{}</dd><dt>User agent</dt><dd>{}</dd></dl>\
                    <form method=\"post\" action=\"/device\"><input type=\"hidden\" name=\"user_code\" value=\"{}\">\
                    <input type=\"hidden\" name=\"csrf\" value=\"{}\">\
                    <button name=\"action\" value=\"approve\">Approve</button><button name=\"action\" value=\"deny\">Deny</button></form>",
                    escape(&self.config.native_client_id), entry.issued_at, escape(&entry.source),
                    escape(&entry.agent), entry.code, escape(&payload.csrf)
                )))
            }
            Action::Approve | Action::Deny if entry.checked.as_deref() == Some(record) => {
                let approved = matches!(payload.action, Action::Approve);
                entry.decision = if approved {
                    Decision::Approved(record.to_owned())
                } else {
                    Decision::Denied
                };
                Ok(response(
                    StatusCode::OK,
                    "text/plain; charset=utf-8",
                    if approved {
                        "Device approved\n"
                    } else {
                        "Device denied\n"
                    },
                ))
            }
            _ => Ok(forbidden()),
        }
    }
}
