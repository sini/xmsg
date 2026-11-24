use super::*;
use crate::enroll_oidc::signed_fixture::Fixture;
use serde_json::{json, Value};
use std::time::Duration;
use tempfile::TempDir;

fn config(issuer: &str) -> Config {
    serde_json::from_value(json!({
        "public_origin": "https://collector.example",
        "issuer": issuer,
        "client_id": "web-client",
        "redirect_uri": "https://collector.example/login/callback",
        "allowlist": ["alice@example.org"],
        "native_client_id": "tui-client",
    }))
    .unwrap()
}

fn token_key() -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &[3; 32]).unwrap())
}

async fn issuer(oidc: &Fixture, directory: &TempDir, refresh: bool) -> Arc<Issuer> {
    issuer_with_config(oidc, directory, refresh, config(&oidc.issuer())).await
}

async fn issuer_with_config(
    oidc: &Fixture,
    directory: &TempDir,
    refresh: bool,
    config: Config,
) -> Arc<Issuer> {
    let provider = Provider::discover_with_client(
        config.oidc(),
        &config.public_origin,
        refresh,
        oidc.http_client(),
    )
    .await
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let authority = Authority::open(
        directory.path(),
        config.authority_config(vec!["fixture.node".to_owned()]),
    )
    .unwrap();
    Issuer::start(
        Prepared {
            config,
            provider,
            key: refresh.then(token_key),
        },
        authority,
    )
}

pub(crate) async fn transport_fixture(
    oidc: &Fixture,
    directory: &TempDir,
) -> (Arc<Issuer>, authority::Issued) {
    transport_with_lease(oidc, directory, 900).await
}

pub(crate) async fn transport_with_lease(
    oidc: &Fixture,
    directory: &TempDir,
    lease_secs: u64,
) -> (Arc<Issuer>, authority::Issued) {
    transport_with_settings(oidc, directory, lease_secs, None, None).await
}

pub(crate) async fn transport_with_slo(
    oidc: &Fixture,
    directory: &TempDir,
    revocation_slo_ms: u64,
) -> (Arc<Issuer>, authority::Issued) {
    transport_with_settings(oidc, directory, 900, Some(revocation_slo_ms), None).await
}

pub(crate) async fn transport_with_handshake_timeout(
    oidc: &Fixture,
    directory: &TempDir,
    handshake_timeout_ms: u64,
) -> (Arc<Issuer>, authority::Issued) {
    transport_with_settings(oidc, directory, 900, None, Some(handshake_timeout_ms)).await
}

async fn transport_with_settings(
    oidc: &Fixture,
    directory: &TempDir,
    lease_secs: u64,
    revocation_slo_ms: Option<u64>,
    handshake_timeout_ms: Option<u64>,
) -> (Arc<Issuer>, authority::Issued) {
    let mut settings = config(&oidc.issuer());
    settings.session_limits.lease_max_secs = lease_secs;
    if let Some(slo) = revocation_slo_ms {
        settings.revocation_slo_ms = slo;
    }
    if let Some(handshake) = handshake_timeout_ms {
        settings.handshake_timeout_ms = handshake;
    }
    let issuer = issuer_with_config(oidc, directory, false, settings).await;
    let browser = issuer
        .authority
        .login("alice@example.org", &oidc.issuer(), "transport-owner", None)
        .unwrap();
    let machine = issuer
        .authority
        .mint_machine(
            &browser.record.principal,
            "transport-reader",
            vec![authority::Scope::Fleet],
            None,
            60,
        )
        .unwrap();
    (issuer, machine)
}

pub(crate) fn transport_owner_records(
    issuer: &Issuer,
    upstream: &str,
) -> (authority::Issued, authority::Issued, authority::Issued) {
    let browser = issuer
        .authority
        .login("alice@example.org", upstream, "transport-owner", None)
        .unwrap();
    let native = issuer
        .authority
        .issue_native(&browser.record.record_id)
        .unwrap();
    let delegated = issuer
        .authority
        .mint_delegated(
            &browser.record.principal,
            authority::DelegatedGrant {
                holder: "synthetic-transport-holder".into(),
                verbs: vec!["send".into()],
                targets: vec![authority::Target {
                    node: "fixture.node".into(),
                    endpoint: "worker@fixture.node".into(),
                }],
                presenter: None,
                expires_at: now_epoch_secs() + 60,
                rate: 1,
                read_scope: Some(vec![authority::Scope::Attention]),
                confirm_verbs: Vec::new(),
            },
        )
        .unwrap();
    (browser, native, delegated)
}

pub(crate) fn scoped_transport_machine(issuer: &Issuer, owner: &str) -> authority::Issued {
    issuer
        .authority
        .mint_machine(
            owner,
            "fixture-scope",
            vec![authority::Scope::Node {
                node: "fixture.node".into(),
            }],
            None,
            3,
        )
        .unwrap()
}

pub(crate) fn synthetic_transport_record(issuer: &Issuer, handle: &str) {
    issuer.authority.allow_synthetic_for_test(handle);
}

pub(crate) struct WatchdogAbortGuard(
    tokio::task::JoinHandle<std::result::Result<(), super::authority::AuthorityError>>,
);

impl Drop for WatchdogAbortGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) fn delay_abort_for_test(issuer: &Issuer, delay: std::time::Duration) {
    issuer.authority.delay_abort_for_test(delay);
}

pub(crate) fn authority_cutoff(issuer: &Issuer) -> std::time::Duration {
    issuer.authority.cutoff()
}

pub(crate) async fn suppress_and_revoke_scoped(
    issuer: &Arc<Issuer>,
    directory: &TempDir,
    record_id: &str,
) -> (std::time::Instant, WatchdogAbortGuard) {
    let listener = admin::bind(directory.path(), &issuer.authority).unwrap();
    let admin = tokio::spawn(admin::serve(listener, issuer.authority.clone()));
    let tick = issuer.authority.watchdog_tick_for_test();
    let watchdog = tokio::spawn(issuer.authority.clone().watchdog());
    issuer.authority.suppress_push_for_test();
    tokio::time::timeout(Duration::from_secs(5), tick.notified())
        .await
        .unwrap();
    admin::revoke_fixture(directory.path(), record_id).await;
    let (audit_row, at) = issuer.authority.last_revoke_for_test();
    assert!(audit_row > 0);
    assert!(issuer
        .authority
        .audit_records()
        .unwrap()
        .iter()
        .any(|row| { row.action == "revoke" && row.record_id.as_deref() == Some(record_id) }));
    admin.abort();
    (at, WatchdogAbortGuard(watchdog))
}

pub(crate) async fn suppress_and_revoke(
    issuer: &Arc<Issuer>,
    directory: &TempDir,
    record_id: &str,
) -> std::time::Instant {
    let (at, guard) = suppress_and_revoke_scoped(issuer, directory, record_id).await;
    let watchdog = guard;
    tokio::spawn(async move {
        let _guard = watchdog;
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    at
}

pub(crate) fn admission_reads(issuer: &Issuer) -> u64 {
    issuer.authority.admission_reads()
}

pub(crate) fn set_expired(issuer: &Issuer, record: &authority::Record, absolute: bool) {
    issuer
        .authority
        .edit_fixture_record(&record.record_id, |stored| {
            if absolute {
                stored.absolute_expires_at = 0;
            } else {
                stored.idle_expires_at = 0;
            }
        });
}

pub(crate) fn clear_machine_scope(issuer: &Issuer, record: &authority::Record) {
    issuer
        .authority
        .edit_fixture_record(&record.record_id, |stored| {
            if let authority::Grants::Machine { scope, .. } = &mut stored.grants {
                scope.clear();
            } else {
                panic!("fixture requires a machine record");
            }
        });
}

pub(crate) fn set_entitlement(issuer: &Issuer, value: bool) {
    issuer.authority.fixture_entitlement(value);
}

pub(crate) fn fail_store(issuer: &Issuer) {
    issuer.authority.fail_fixture_store();
}

pub(crate) async fn upstream_fixture_tokens(issuer: &Issuer, provider: &Fixture) -> Vec<String> {
    let _ = login(issuer, provider).await;
    let tokens = provider.secret_values();
    assert!(!tokens.is_empty());
    tokens
}

pub(crate) fn start_watchdog(issuer: &Issuer) -> tokio::task::JoinHandle<()> {
    let authority = issuer.authority.clone();
    tokio::spawn(async move {
        authority.watchdog().await.unwrap();
    })
}

pub(crate) fn without_push(issuer: &Issuer) {
    issuer.authority.suppress_push_for_test();
}

pub(crate) fn arm_projection(
    issuer: &Issuer,
    snapshot: bool,
) -> Arc<super::writer::ProjectionGate> {
    issuer.authority.arm_projection_gate(snapshot)
}

pub(crate) fn last_handoff(issuer: &Issuer) -> Option<std::time::Instant> {
    issuer.authority.last_handoff_for_test()
}

fn set_cookie_header(response: &WebResponse, name: &str) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|line| line.split_once('=').is_some_and(|(key, _)| key == name))
        .unwrap()
        .to_owned()
}

fn request_cookie(response: &WebResponse, name: &str) -> header::HeaderMap {
    let cookie = set_cookie_header(response, name);
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::COOKIE,
        cookie.split(';').next().unwrap().parse().unwrap(),
    );
    headers
}

async fn login(issuer: &Issuer, oidc: &Fixture) -> WebResponse {
    let begin = issuer.begin().unwrap();
    let headers = request_cookie(&begin, FLOW_COOKIE);
    let (code, state) = oidc.authorize(begin.headers()[header::LOCATION].to_str().unwrap());
    issuer
        .callback(Some(&format!("code={code}&state={state}")), &headers)
        .await
}

#[tokio::test]
async fn flow_cookie_and_callback_are_bound_single_use_and_expiring() {
    let oidc = Fixture::new_at(now_epoch_secs()).await;
    let directory = tempfile::tempdir().unwrap();
    let issuer = issuer(&oidc, &directory, false).await;
    let begin = issuer.begin().unwrap();
    let flow_header = set_cookie_header(&begin, FLOW_COOKIE);
    assert!(flow_header.starts_with("__Host-mc_flow="));
    assert!(flow_header.contains("; Secure; HttpOnly; Path=/; SameSite=Lax;"));
    let headers = request_cookie(&begin, FLOW_COOKIE);
    let (code, state) = oidc.authorize(begin.headers()[header::LOCATION].to_str().unwrap());
    let callback = format!("code={code}&state={state}");
    let wrong = issuer
        .callback(Some(&format!("code={code}&state=wrong")), &headers)
        .await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert!(set_cookie_header(&wrong, FLOW_COOKIE).ends_with("Max-Age=0"));
    assert_eq!(
        issuer.callback(Some(&callback), &headers).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let begin = issuer.begin().unwrap();
    let headers = request_cookie(&begin, FLOW_COOKIE);
    let (code, state) = oidc.authorize(begin.headers()[header::LOCATION].to_str().unwrap());
    let callback = format!("code={code}&state={state}");
    assert_eq!(
        issuer
            .callback(Some(&callback), &header::HeaderMap::new())
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        issuer.callback(Some(&callback), &headers).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let begin = issuer.begin().unwrap();
    let headers = request_cookie(&begin, FLOW_COOKIE);
    let (code, state) = oidc.authorize(begin.headers()[header::LOCATION].to_str().unwrap());
    issuer
        .flows
        .lock()
        .unwrap()
        .get_mut(&digest(&state))
        .unwrap()
        .expires = now_epoch_secs();
    assert_eq!(
        issuer
            .callback(Some(&format!("code={code}&state={state}")), &headers)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let accepted = login(&issuer, &oidc).await;
    assert_eq!(accepted.status(), StatusCode::OK);
    let session = set_cookie_header(&accepted, SESSION_COOKIE);
    assert!(session.starts_with("__Host-mc_session="));
    assert!(session.contains("; Secure; HttpOnly; Path=/; SameSite=Strict;"));
    assert_eq!(issuer.authority.list().unwrap().len(), 1);
}

struct TestServer {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn local_server(issuer: Arc<Issuer>) -> TestServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, addr) = accepted.unwrap();
                    let issuer = issuer.clone();
                    connections.spawn(async move {
                        let service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
                            request.extensions_mut().insert(addr);
                            let issuer = issuer.clone();
                            async move { Ok::<_, std::convert::Infallible>(issuer.handle(request).await) }
                        });
                        hyper::server::conn::http1::Builder::new()
                            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                            .await.unwrap();
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    TestServer { url, task }
}

async fn body_json(response: WebResponse) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn device_origin_csrf_rate_and_single_issue() {
    let oidc = Fixture::new_at(now_epoch_secs()).await;
    let directory = tempfile::tempdir().unwrap();
    let issuer = issuer(&oidc, &directory, false).await;
    let session_response = login(&issuer, &oidc).await;
    let headers = request_cookie(&session_response, SESSION_COOKIE);
    let handle = cookie(&headers, SESSION_COOKIE).unwrap();
    let csrf = csrf(handle);
    let server = local_server(issuer.clone()).await;
    let client = reqwest::Client::new();
    let now = now_epoch_secs();
    let pending = body_json(
        issuer
            .begin_device(now, "fixture".into(), "<test>".into())
            .unwrap(),
    )
    .await;
    assert_eq!(
        pending["verification_uri"],
        "https://collector.example/device"
    );
    assert!(pending.get("verification_uri_complete").is_none());
    let device = pending["device_code"].as_str().unwrap();
    let user = pending["user_code"].as_str().unwrap();
    assert_eq!(
        body_json(issuer.poll_device(device, now).unwrap()).await["error"],
        "slow_down"
    );
    assert_eq!(
        body_json(issuer.poll_device(device, now + 6).unwrap()).await["error"],
        "slow_down"
    );
    assert_eq!(
        body_json(issuer.poll_device(device, now + 21).unwrap()).await["error"],
        "authorization_pending"
    );

    let wrong = client
        .post(format!("{}/oauth/token", server.url))
        .form(&[
            ("client_id", "wrong"),
            ("device_code", device),
            ("grant_type", device::DEVICE_GRANT),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        wrong.json::<Value>().await.unwrap()["error"],
        "invalid_client"
    );
    let malformed = client
        .post(format!("{}/oauth/token", server.url))
        .form(&[("client_id", "tui-client")])
        .send()
        .await
        .unwrap();
    assert_eq!(
        malformed.json::<Value>().await.unwrap()["error"],
        "invalid_request"
    );

    let approval = |action, origin, code, supplied| {
        client
            .post(format!("{}/device", server.url))
            .headers(headers.clone())
            .header(header::ORIGIN, origin)
            .form(&[("action", action), ("user_code", code), ("csrf", supplied)])
    };
    assert_eq!(
        approval("review", "https://other.example", user, &csrf)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        approval("review", "https://collector.example", user, "wrong")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let review = approval("review", "https://collector.example", user, &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(review.status(), 200);
    assert!(review.text().await.unwrap().contains("&lt;test&gt;"));
    assert_eq!(
        approval("approve", "https://collector.example", user, &csrf)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let issued = issuer.poll_device(device, now + 40).unwrap();
    assert_eq!(issued.headers()[header::CACHE_CONTROL], "no-store");
    let issued = body_json(issued).await;
    let native = issued["access_token"].as_str().unwrap();
    assert_eq!(
        issuer.admit(native, Carrier::Bearer).await.unwrap().class,
        Class::Native
    );
    assert_eq!(
        body_json(issuer.poll_device(device, now + 60).unwrap()).await["error"],
        "invalid_grant"
    );

    let expired = body_json(issuer.begin_device(now, "".into(), "".into()).unwrap()).await;
    assert_eq!(
        body_json(
            issuer
                .poll_device(expired["device_code"].as_str().unwrap(), now + 600)
                .unwrap()
        )
        .await["error"],
        "expired_token"
    );
    let denied_code = body_json(issuer.begin_device(now, "".into(), "".into()).unwrap()).await;
    let denied_user = denied_code["user_code"].as_str().unwrap();
    assert_eq!(
        approval("review", "https://collector.example", denied_user, &csrf)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        approval("deny", "https://collector.example", denied_user, &csrf)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        body_json(
            issuer
                .poll_device(denied_code["device_code"].as_str().unwrap(), now + 5)
                .unwrap()
        )
        .await["error"],
        "access_denied"
    );

    let own = now_epoch_secs();
    let valid = body_json(issuer.begin_device(own, "".into(), "".into()).unwrap()).await;
    for _ in 0..5 {
        assert_eq!(
            approval("review", "https://collector.example", "11111111", &csrf)
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
    }
    assert_eq!(
        approval(
            "review",
            "https://collector.example",
            valid["user_code"].as_str().unwrap(),
            &csrf
        )
        .send()
        .await
        .unwrap()
        .status(),
        403
    );
    for _ in 0..8 {
        issuer.begin_device(now, "".into(), "".into()).unwrap();
    }
    assert_eq!(
        issuer
            .begin_device(now, "".into(), "".into())
            .unwrap()
            .status(),
        429
    );
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn capture_transport_trace(
) -> (impl FnOnce() -> Vec<u8>, tracing::subscriber::DefaultGuard) {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer({
            let capture = capture.clone();
            move || capture.clone()
        })
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    (move || capture.0.lock().unwrap().clone(), guard)
}

pub(crate) fn transport_files(directory: &TempDir) -> Vec<Vec<u8>> {
    state_files(directory)
}

#[tokio::test]
async fn upstream_refresh_is_encrypted_rotates_and_rechecks_entitlement() {
    use crate::mission_control::authority::Scope;

    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer({
            let capture = capture.clone();
            move || capture.clone()
        })
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let oidc = Fixture::new_at(now_epoch_secs()).await;
    oidc.set_discovery_claim(
        "scopes_supported",
        json!(["openid", "email", "offline_access"]),
    );
    let directory = tempfile::tempdir().unwrap();
    let issuer = issuer(&oidc, &directory, true).await;

    let begin = issuer.begin().unwrap();
    let location = begin.headers()[header::LOCATION].to_str().unwrap();
    assert!(url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .any(|(name, value)| {
            name == "scope"
                && value
                    .split_whitespace()
                    .any(|scope| scope == "offline_access")
        }));
    let flow_headers = request_cookie(&begin, FLOW_COOKIE);
    let (code, state) = oidc.authorize(location);
    let accepted = issuer
        .callback(Some(&format!("code={code}&state={state}")), &flow_headers)
        .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    let issued_files = state_files(&directory);
    let headers = request_cookie(&accepted, SESSION_COOKIE);
    let handle = cookie(&headers, SESSION_COOKIE).unwrap();
    let browser = issuer.admit(handle, Carrier::Cookie).await.unwrap();
    let owner = &browser.principal;
    let refresh = issuer.authority.refresh(owner).unwrap().unwrap();
    let when = refresh.checked_at + issuer.config.upstream_revalidate_secs as i64 + 1;
    let native = issuer.authority.issue_native(&browser.record_id).unwrap();
    let machine = issuer
        .authority
        .mint_machine(owner, "fixture", vec![Scope::Fleet], None, 1)
        .unwrap();

    oidc.queue_refresh_reply(503, json!({"error":"server_error"}));
    assert!(issuer.admit_at(handle, Carrier::Cookie, when).await.is_ok());
    assert_eq!(oidc.refresh_requests(), 1);
    assert_eq!(
        issuer.authority.refresh(owner).unwrap().unwrap().encrypted,
        refresh.encrypted
    );

    let rotated = "fixture-rotated-refresh-canary-for-mission-control";
    oidc.queue_refresh_reply(200, json!({
        "access_token":"fixture-rotated-access-canary-for-mission-control", "token_type":"Bearer", "refresh_token":rotated
    }));
    assert!(issuer.admit_at(handle, Carrier::Cookie, when).await.is_ok());
    assert_eq!(oidc.refresh_requests(), 2);
    let current = issuer.authority.refresh(owner).unwrap().unwrap();
    assert_ne!(current.encrypted, refresh.encrypted);
    assert!(decrypt(issuer.key.as_ref().unwrap(), &current.encrypted)
        .is_ok_and(|value| value == rotated));

    oidc.queue_refresh_reply(400, json!({"error":"invalid_grant"}));
    assert!(issuer
        .admit_at(handle, Carrier::Cookie, when)
        .await
        .is_err());
    assert_eq!(oidc.refresh_requests(), 3);
    for issued in [&native, &machine] {
        assert!(issuer
            .authority
            .admit(&issued.handle, Carrier::Bearer)
            .is_err());
    }

    let response_headers = format!("{:?}", accepted.headers()).into_bytes();
    let response_body = accepted.into_body().collect().await.unwrap().to_bytes();
    let logs = capture.0.lock().unwrap().clone();
    let mut examined = vec![
        response_headers,
        response_body.to_vec(),
        logs,
        refresh.encrypted,
        current.encrypted,
    ];
    examined.extend(issued_files);
    examined.extend(state_files(&directory));
    let mut forbidden = oidc.secret_values();
    forbidden.push(rotated.into());
    assert!(!forbidden.is_empty());
    for canary in forbidden.into_iter().filter(|value| !value.is_empty()) {
        assert!(
            !examined.iter().any(|bytes| bytes
                .windows(canary.len())
                .any(|window| window == canary.as_bytes())),
            "upstream secret escaped the issuer"
        );
    }
}

fn state_files(directory: &TempDir) -> Vec<Vec<u8>> {
    std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|file| file.file_type().unwrap().is_file())
        .map(|file| std::fs::read(file.path()).unwrap())
        .collect()
}

async fn send_to_issuer(
    issuer: &Arc<Issuer>,
    hub: Option<&upstream::ReadHub>,
    method: Method,
    uri: &str,
    headers: Vec<(&str, &str)>,
    body: &[u8],
) -> (StatusCode, hyper::header::HeaderMap, String) {
    let (client_io, server_io) = tokio::io::duplex(65536);
    let issuer_srv = issuer.clone();
    let hub_ptr = hub.map(|h| h as *const upstream::ReadHub as usize);
    let srv = tokio::spawn(async move {
        let io = hyper_util::rt::TokioIo::new(server_io);
        let service = hyper::service::service_fn(move |req| {
            let issuer = issuer_srv.clone();
            async move {
                let hub_ref = hub_ptr.map(|p| unsafe { &*(p as *const upstream::ReadHub) });
                Ok::<_, std::convert::Infallible>(issuer.handle_with_hub(req, hub_ref).await)
            }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .await;
    });
    let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(client_io))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut req = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    let req = req.body(Full::new(Bytes::copy_from_slice(body))).unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    drop(sender);
    let _ = srv.await;
    (status, resp_headers, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn callback_bridge_and_root_fetch_metadata_shells() {
    let oidc = Fixture::new_at(now_epoch_secs()).await;
    let directory = tempfile::tempdir().unwrap();
    let issuer = issuer(&oidc, &directory, false).await;
    let hub = upstream::ReadHub::new(&issuer.config().session_limits).unwrap();

    // 1. finish_login returns 200 bridge (never 303 /) with canonical CSP and no credentials
    let cb = login(&issuer, &oidc).await;
    assert_eq!(cb.status(), StatusCode::OK);
    assert_eq!(cb.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(cb.headers()["x-content-type-options"], "nosniff");
    assert_eq!(cb.headers()["referrer-policy"], "no-referrer");
    let csp = cb.headers()["content-security-policy"].to_str().unwrap();
    assert!(!csp.contains("unsafe-inline"), "CSP must not allow unsafe-inline: {csp}");
    assert_eq!(
        csp,
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-src 'none'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; require-trusted-types-for 'script'"
    );
    let session_cookie = set_cookie_header(&cb, SESSION_COOKIE);
    assert!(session_cookie.contains("SameSite=Strict"));
    let cb_body = String::from_utf8_lossy(&cb.into_body().collect().await.unwrap().to_bytes()).into_owned();
    assert!(cb_body.contains("<meta http-equiv=\"refresh\" content=\"0;url=/\">"));
    assert!(cb_body.contains("<a href=\"/\">Continue</a>"));
    assert!(!cb_body.contains("alice@example.org"));

    // 2. GET / with no cookie NEVER 303s to /login regardless of Sec-Fetch-Site, and omits logout form/bundle
    for sfs in [None, Some("same-origin"), Some("none"), Some("cross-site")] {
        let hdrs = sfs.map(|v| vec![("sec-fetch-site", v)]).unwrap_or_default();
        let (status, _, body) = send_to_issuer(&issuer, Some(&hub), Method::GET, "/", hdrs, b"").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("<a class=\"mc-btn\" href=\"/login\">Sign in</a>"));
        assert!(!body.contains("action=\"/logout\""));
        assert!(!body.contains(assets::JS_PATH));
    }

    // 3. GET / with valid cookie + cross-site / same-site / missing Sec-Fetch-Site gets 200 no-data shell
    let cookie_val = session_cookie.split(';').next().unwrap();
    for hdrs in [
        vec![("cookie", cookie_val), ("sec-fetch-site", "cross-site")],
        vec![("cookie", cookie_val), ("sec-fetch-site", "same-site")],
        vec![("cookie", cookie_val)],
    ] {
        let (status, _, body) = send_to_issuer(&issuer, Some(&hub), Method::GET, "/", hdrs, b"").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("<a class=\"mc-btn\" href=\"/\">Open Mission Control</a>"));
        assert!(!body.contains("action=\"/logout\""));
        assert!(!body.contains("mc-ssr"));
        assert!(!body.contains(assets::JS_PATH));
    }

    // 4. GET / with valid cookie + Sec-Fetch-Site: same-origin renders authenticated shell + SSR + bundle
    let (status, _, body) = send_to_issuer(
        &issuer,
        Some(&hub),
        Method::GET,
        "/",
        vec![("cookie", cookie_val), ("sec-fetch-site", "same-origin")],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("action=\"/logout\""));
    assert!(body.contains("href=\"/device\""));
    assert!(body.contains("id=\"mc-ssr\""));
    assert!(body.contains(assets::JS_PATH));

    // 5. POST /logout returns 303 Location: /, Max-Age=0, and revokes the record
    let csrf_val = body.split("name=\"csrf\" value=\"").nth(1).unwrap().split('"').next().unwrap();
    let form_body = format!("csrf={csrf_val}");
    let (out_status, out_hdrs, _) = send_to_issuer(
        &issuer,
        Some(&hub),
        Method::POST,
        "/logout",
        vec![
            ("cookie", cookie_val),
            ("origin", "https://collector.example"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        form_body.as_bytes(),
    )
    .await;
    assert_eq!(out_status, StatusCode::SEE_OTHER);
    assert_eq!(out_hdrs[header::LOCATION], "/");
    let cleared = out_hdrs.get_all(header::SET_COOKIE).iter().map(|v| v.to_str().unwrap()).collect::<Vec<_>>().join(";");
    assert!(cleared.contains("Max-Age=0"));
    assert_eq!(issuer.authority.list().unwrap().iter().filter(|r| r.revoked).count(), 1);
}

#[tokio::test]
async fn populated_ssr_escaping_assets_and_fetch_metadata_edges() {
    use crate::observe_export::{EndpointDescriptor, EndpointKind, Harness, RegistrationState};
    let oidc = Fixture::new_at(now_epoch_secs()).await;
    let directory = tempfile::tempdir().unwrap();
    let issuer = issuer(&oidc, &directory, false).await;
    issuer.authority.set_node_masked("fixture.node", true).unwrap();

    let hub = upstream::ReadHub::new(&issuer.config().session_limits).unwrap();
    hub.seed_nodes_for_test(vec![
        protocol::Node {
            node: "node-a".to_owned(),
            status: protocol::Status::Healthy,
            delivery: protocol::Delivery::Delayed,
            last_success_at: Some(1000),
            last_source_at: Some(1000),
            via_hub: None,
            history_hidden: false,
            last_activity_at: None,
            activity_authority: Some(protocol::ActivityAuthority::Disabled),
            endpoints: vec![protocol::Endpoint {
                descriptor: EndpointDescriptor {
                    id: "bad<id>\"@node-a".to_owned(),
                    node: "node-a".to_owned(),
                    kind: EndpointKind::Instance,
                    harness: Harness::Declared("<img src=x onerror='1'>".to_owned()),
                    state: RegistrationState::Registered,
                    source_at: Some(1),
                    label: Some("<script>alert(\"xss\")</script><a href=\"https://evil\">".to_owned()),
                    context: None,
                    activity: None,
                },
                activity: None,
                activity_stale: None,
            }],
            endpoints_truncated: false,
            exchanges: Vec::new(),
            source_gaps: Vec::new(),
        },
        protocol::Node {
            node: "fixture.node".to_owned(),
            status: protocol::Status::Healthy,
            delivery: protocol::Delivery::Delayed,
            last_success_at: Some(1000),
            last_source_at: Some(1000),
            via_hub: None,
            history_hidden: false,
            last_activity_at: None,
            activity_authority: Some(protocol::ActivityAuthority::Disabled),
            endpoints: vec![protocol::Endpoint {
                descriptor: EndpointDescriptor {
                    id: "secret-agent@node-masked".to_owned(),
                    node: "fixture.node".to_owned(),
                    kind: EndpointKind::Instance,
                    harness: Harness::Claude,
                    state: RegistrationState::Registered,
                    source_at: Some(1),
                    label: Some("secret-label".to_owned()),
                    context: None,
                    activity: None,
                },
                activity: None,
                activity_stale: None,
            }],
            endpoints_truncated: false,
            exchanges: Vec::new(),
            source_gaps: Vec::new(),
        },
    ]);

    let cb = login(&issuer, &oidc).await;
    let session_cookie = set_cookie_header(&cb, SESSION_COOKIE);
    let cookie_val = session_cookie.split(';').next().unwrap();

    // m01: duplicate Sec-Fetch-Site must return the static no-data shell
    let (dup_status, _, dup_body) = send_to_issuer(
        &issuer,
        Some(&hub),
        Method::GET,
        "/",
        vec![
            ("cookie", cookie_val),
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-site", "same-origin"),
        ],
        b"",
    )
    .await;
    assert_eq!(dup_status, StatusCode::OK);
    assert!(dup_body.contains("Open Mission Control"));
    assert!(!dup_body.contains("node-a"));
    assert!(!dup_body.contains(assets::JS_PATH));

    // m02: unknown Sec-Fetch-Site value must return the static no-data shell
    let (bogus_status, _, bogus_body) = send_to_issuer(
        &issuer,
        Some(&hub),
        Method::GET,
        "/",
        vec![("cookie", cookie_val), ("sec-fetch-site", "bogus")],
        b"",
    )
    .await;
    assert_eq!(bogus_status, StatusCode::OK);
    assert!(bogus_body.contains("Open Mission Control"));
    assert!(!bogus_body.contains("node-a"));

    // m03 & m06: populated SSR with same-origin escapes hostile label/id/harness and hides masked endpoints
    let (ssr_status, _, ssr_body) = send_to_issuer(
        &issuer,
        Some(&hub),
        Method::GET,
        "/",
        vec![("cookie", cookie_val), ("sec-fetch-site", "same-origin")],
        b"",
    )
    .await;
    assert_eq!(ssr_status, StatusCode::OK);
    assert!(ssr_body.contains("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;&lt;a href=&quot;https://evil&quot;&gt;"));
    assert!(ssr_body.contains("bad&lt;id&gt;&quot;@node-a"));
    assert!(ssr_body.contains("&lt;img src=x onerror=&#39;1&#39;&gt;"));
    assert!(!ssr_body.contains("<script>alert"));
    assert!(!ssr_body.contains("<a href=\"https://evil\">"));
    assert!(!ssr_body.contains("<img src=x"));
    assert!(ssr_body.contains("History masked by node policy."));
    assert!(!ssr_body.contains("secret-agent"));
    assert!(!ssr_body.contains("secret-label"));

    // m05: JS & CSS assets served with canonical MIME + nosniff; unknown asset path 404
    let (js_status, js_hdrs, js_body) = send_to_issuer(&issuer, Some(&hub), Method::GET, assets::JS_PATH, vec![], b"").await;
    assert_eq!(js_status, StatusCode::OK);
    assert_eq!(js_hdrs[header::CONTENT_TYPE], "application/javascript; charset=utf-8");
    assert_eq!(js_hdrs["x-content-type-options"], "nosniff");
    assert_eq!(js_body.as_bytes(), assets::JS_BYTES);

    let (css_status, css_hdrs, css_body) = send_to_issuer(&issuer, Some(&hub), Method::GET, assets::CSS_PATH, vec![], b"").await;
    assert_eq!(css_status, StatusCode::OK);
    assert_eq!(css_hdrs[header::CONTENT_TYPE], "text/css; charset=utf-8");
    assert_eq!(css_hdrs["x-content-type-options"], "nosniff");
    assert_eq!(css_body.as_bytes(), assets::CSS_BYTES);

    let (miss_status, _, _) = send_to_issuer(&issuer, Some(&hub), Method::GET, "/assets/nonexistent.js", vec![], b"").await;
    assert_eq!(miss_status, StatusCode::NOT_FOUND);
}
