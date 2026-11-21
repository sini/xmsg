use super::*;
use crate::enroll_oidc::signed_fixture::Fixture;
use serde_json::{json, Value};
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
    let config = config(&oidc.issuer());
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
    let authority = Authority::open(directory.path(), config.authority_config(vec![])).unwrap();
    Issuer::start(
        Prepared {
            config,
            provider,
            key: refresh.then(token_key),
        },
        authority,
    )
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
    assert_eq!(accepted.status(), StatusCode::SEE_OTHER);
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
    assert_eq!(accepted.status(), StatusCode::SEE_OTHER);
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
