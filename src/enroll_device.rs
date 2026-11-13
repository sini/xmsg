use super::*;
use crate::enroll_ca::{DeviceProjection, VerifiedClaims};
use std::sync::{OnceLock, Weak};

static LOCAL_SERVICES: OnceLock<Mutex<HashMap<usize, Weak<Service>>>> = OnceLock::new();

pub(super) struct AwaitingApproval {
    pub(super) claims: VerifiedClaims,
    pub(super) projection: DeviceProjection,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovalRequest {
    pub user: String,
    pub host: String,
    pub spki_sha256: String,
}

#[derive(Serialize)]
pub(crate) struct PendingDevice {
    request_id: String,
    user: String,
    issuer: String,
    subject: String,
    host: String,
    node_name: String,
    spki_sha256: String,
    provider: String,
    expires_in: u64,
}

pub(super) fn request_id() -> Result<String, Failure> {
    use base64::Engine;
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes)
        .map_err(|_| Failure(StatusCode::SERVICE_UNAVAILABLE, "random_unavailable"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn names(service: &Service) -> Vec<String> {
    let peers = service.fed.current_peers();
    peers
        .iter()
        .map(|(_, peer)| {
            peers
                .canonical_name(&peer.name)
                .unwrap_or(&peer.name)
                .to_owned()
        })
        .collect()
}

fn remaining(session: &Session, clock: &dyn Clock) -> u64 {
    let wall = session
        .expires
        .load(Ordering::Acquire)
        .saturating_sub(clock.now())
        .max(0) as u64;
    session
        .deadline
        .lock()
        .unwrap()
        .map(|limit| {
            let left = limit.saturating_duration_since(clock.monotonic_now());
            wall.min(
                left.as_secs()
                    .saturating_add(u64::from(left.subsec_nanos() != 0)),
            )
        })
        .unwrap_or(wall)
}

fn fail(session: &Session, reason: &'static str) {
    let mut phase = session.phase.lock().unwrap();
    if matches!(*phase, Phase::Preparing | Phase::DevicePolling) {
        *phase = Phase::Complete(Err(SessionFailure::reason(reason)));
        session.device_active.store(false, Ordering::Release);
        session.notify.notify_waiters();
    }
}

fn valid_verification_uri(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && reqwest::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
        })
}

pub(super) async fn start(
    service: Arc<Service>,
    session: Arc<Session>,
    handle: String,
    provider: Arc<enroll_oidc::Provider>,
) -> Result<Response, Failure> {
    let pending = provider.begin_device().await.map_err(oidc_failure)?;
    let code = pending.user_code();
    if code.is_empty()
        || code.len() > 128
        || !code.bytes().all(|b| (0x20..=0x7e).contains(&b))
        || !valid_verification_uri(pending.verification_uri())
        || pending
            .verification_uri_complete()
            .is_some_and(|uri| !valid_verification_uri(uri))
    {
        return Err(Failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "invalid_device_response",
        ));
    }
    let deadline = pending.deadline();
    if deadline <= service.clock.monotonic_now() || session.cancelled.load(Ordering::Acquire) {
        return Err(Failure(StatusCode::GONE, "expired"));
    }
    *session.deadline.lock().unwrap() = Some(deadline);
    let left = deadline.saturating_duration_since(service.clock.monotonic_now());
    let seconds = left
        .as_secs()
        .saturating_add(u64::from(left.subsec_nanos() != 0))
        .min(300);
    session.expires.store(
        service.clock.now().saturating_add(seconds as i64),
        Ordering::Release,
    );
    let response = serde_json::json!({
        "session":handle,"expires_in":seconds,"request_id":session.request_id,
        "provider":session.provider,
        "user_code":code,"verification_uri":pending.verification_uri(),
        "verification_uri_complete":pending.verification_uri_complete(),
        "interval":pending.interval().as_secs(),
    });
    {
        let mut phase = session.phase.lock().unwrap();
        if !matches!(*phase, Phase::Preparing) || session.cancelled.load(Ordering::Acquire) {
            return Err(Failure(StatusCode::CONFLICT, "invalid_session_state"));
        }
        *phase = Phase::DevicePolling;
    }
    let weak = Arc::downgrade(&service);
    let clock = service.clock.clone();
    tokio::spawn(async move {
        let cancelled = session.cancel.notified();
        tokio::pin!(cancelled);
        cancelled.as_mut().enable();
        if session.cancelled.load(Ordering::Acquire) {
            return;
        }
        let wall_now = || clock.now();
        let result = tokio::select! {
            biased;
            _ = cancelled => return,
            _ = tokio::time::sleep_until(deadline) => {
                fail(&session, "expired");
                return;
            }
            result = provider.poll_device(pending, &wall_now) => result,
        };
        let Some(service) = weak.upgrade() else {
            return;
        };
        if session.expired(service.clock.as_ref()) || session.cancelled.load(Ordering::Acquire) {
            fail(&session, "expired");
            return;
        }
        let claims = match result {
            Ok(claims) => claims,
            Err(error) => {
                fail(&session, oidc_reason(error));
                return;
            }
        };
        let projection =
            match service
                .ca
                .project_device(&claims, &session.csr, &session.host, &names(&service))
            {
                Ok(projection) => projection,
                Err(error) => {
                    fail(&session, error.code());
                    return;
                }
            };
        let mut phase = session.phase.lock().unwrap();
        if matches!(*phase, Phase::DevicePolling) && !session.cancelled.load(Ordering::Acquire) {
            *phase = Phase::AwaitingApproval(AwaitingApproval { claims, projection });
            session.notify.notify_waiters();
        }
    });
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

impl Service {
    pub fn register_local_approval(self: &Arc<Self>) -> Result<(), &'static str> {
        let mut services = LOCAL_SERVICES
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap();
        services.retain(|_, service| service.strong_count() != 0);
        let key = Arc::as_ptr(&self.fed) as usize;
        if services
            .get(&key)
            .and_then(Weak::upgrade)
            .is_some_and(|old| !Arc::ptr_eq(&old, self))
        {
            return Err("another enrollment authority is registered for this node");
        }
        services.insert(key, Arc::downgrade(self));
        self.local_approval.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn local_for_fed(fed: &Arc<crate::fed::FedState>) -> Option<Arc<Self>> {
        let service = LOCAL_SERVICES
            .get()?
            .lock()
            .unwrap()
            .get(&(Arc::as_ptr(fed) as usize))?
            .upgrade()?;
        Arc::ptr_eq(&service.fed, fed).then_some(service)
    }

    fn device_session(&self, request: &str) -> Result<Arc<Session>, Failure> {
        let mut sessions = self.sessions.lock().unwrap();
        self.prune(&mut sessions);
        sessions
            .values()
            .find(|session| session.request_id.as_deref() == Some(request))
            .cloned()
            .ok_or(Failure(StatusCode::GONE, "gone"))
    }

    pub(crate) fn pending_device_requests(&self) -> Vec<PendingDevice> {
        let sessions = {
            let mut sessions = self.sessions.lock().unwrap();
            self.prune(&mut sessions);
            sessions
                .values()
                .filter(|s| s.request_id.is_some())
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut result = Vec::new();
        for session in sessions {
            let phase = session.phase.lock().unwrap();
            let Phase::AwaitingApproval(approval) = &*phase else {
                continue;
            };
            if session.expired(self.clock.as_ref()) {
                continue;
            }
            let p = &approval.projection;
            result.push(PendingDevice {
                request_id: session.request_id.clone().unwrap(),
                user: p.user().into(),
                issuer: p.issuer().into(),
                subject: p.sub().into(),
                host: p.host().into(),
                node_name: p.node_name().into(),
                spki_sha256: p.spki_sha256().into(),
                provider: session.provider.clone(),
                expires_in: remaining(&session, self.clock.as_ref()),
            });
        }
        result.sort_by(|a, b| a.request_id.cmp(&b.request_id));
        result
    }

    pub(crate) fn approve_device(
        &self,
        request: &str,
        body: ApprovalRequest,
    ) -> Result<serde_json::Value, Failure> {
        let session = self.device_session(request)?;
        let mut phase = session.phase.lock().unwrap();
        let Phase::AwaitingApproval(approval) = &*phase else {
            return Err(Failure(StatusCode::CONFLICT, "invalid_session_state"));
        };
        let p = &approval.projection;
        if body.user != p.user() || body.host != p.host() || body.spki_sha256 != p.spki_sha256() {
            return Err(Failure(StatusCode::FORBIDDEN, "approval_mismatch"));
        }
        let result = self.ca.issue_device_approved(
            &approval.claims,
            &session.csr,
            &session.host,
            &names(self),
            p,
            self.clock.now(),
            || !session.expired(self.clock.as_ref()) && !session.cancelled.load(Ordering::Acquire),
        );
        let response = result
            .as_ref()
            .map(|_| serde_json::json!({"status":"approved"}))
            .map_err(|error| core_failure_code(error.code()));
        *phase = Phase::Complete(result.map_err(|error| SessionFailure::reason(error.code())));
        session.device_active.store(false, Ordering::Release);
        session.notify.notify_waiters();
        response
    }

    pub(crate) fn deny_device(&self, request: &str) -> Result<serde_json::Value, Failure> {
        let session = self.device_session(request)?;
        let mut phase = session.phase.lock().unwrap();
        if !matches!(
            *phase,
            Phase::Preparing | Phase::DevicePolling | Phase::AwaitingApproval(_)
        ) {
            return Err(Failure(StatusCode::CONFLICT, "invalid_session_state"));
        }
        session.cancel();
        *phase = Phase::Complete(Err(SessionFailure::reason("access_denied")));
        session.notify.notify_waiters();
        Ok(serde_json::json!({"status":"denied"}))
    }
}
