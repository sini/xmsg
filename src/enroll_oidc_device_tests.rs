use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

struct Clock {
    start: tokio::time::Instant,
    elapsed: AtomicU64,
    sleeps: Mutex<Vec<u64>>,
}
impl Clock {
    fn new() -> Self {
        Self {
            start: tokio::time::Instant::now(),
            elapsed: AtomicU64::new(0),
            sleeps: Mutex::new(vec![]),
        }
    }
    fn now(&self) -> tokio::time::Instant {
        self.start + Duration::from_secs(self.elapsed.load(Ordering::SeqCst))
    }
    async fn sleep(&self, duration: Duration) {
        self.sleeps.lock().unwrap().push(duration.as_secs());
        self.elapsed.fetch_add(duration.as_secs(), Ordering::SeqCst);
    }
}
async fn provider(fixture: &Fixture) -> Provider {
    let mut config = fixture.config(false);
    config.device.enabled = true;
    config.clients.insert(
        Flow::Device,
        crate::enroll_ca::ClientConfig {
            client_id: "device-client".into(),
            client_secret_file: None,
        },
    );
    Provider::discover_with_client("fixture", &config, true, fixture.http_client())
        .await
        .unwrap()
}
async fn poll(
    provider: &Provider,
    pending: PendingDeviceAuthorization,
    clock: &Clock,
) -> Result<VerifiedClaims, Error> {
    provider
        .poll_device_inner(pending, &|| NOW, &|| clock.now(), |duration| {
            clock.sleep(duration)
        })
        .await
}

#[tokio::test]
async fn device_signed_https_success_and_one_shot_binding() {
    let fixture = Fixture::new().await;
    let provider = provider(&fixture).await;
    let clock = Clock::new();
    let pending = provider
        .begin_device_with_clock(&|| clock.now())
        .await
        .unwrap();
    assert!(pending.user_code().starts_with("TEST-"));
    assert!(pending.verification_uri().starts_with("https://127.0.0.1:"));
    assert_eq!(pending.deadline(), clock.start + Duration::from_secs(300));
    let details = pending.details.clone();
    let claims = poll(&provider, pending, &clock).await.unwrap();
    assert_eq!(claims.sub, "fixture-sub");
    assert_eq!(claims.email.as_deref(), Some("alice@example.org"));
    assert!(claims.email_verified);
    assert_eq!(claims.hd.as_deref(), Some("example.org"));
    assert_eq!(claims.groups.len(), 2);
    assert_eq!(*clock.sleeps.lock().unwrap(), vec![5]);
    let forms = fixture.shared.lock().unwrap().forms.clone();
    assert_eq!(forms[0]["client_id"], "device-client");
    assert_eq!(forms[0]["scope"], "openid email groups");
    assert_eq!(
        forms[1]["grant_type"],
        "urn:ietf:params:oauth:grant-type:device_code"
    );
    assert_eq!(forms[1]["client_id"], "device-client");
    assert!(!forms[1].contains_key("code"));
    assert!(!forms[1].contains_key("code_verifier"));
    let client = provider.device_client(
        provider.metadata.read().unwrap().clone(),
        "paste-client",
        None,
    );
    let result = client
        .exchange_device_access_token(&details)
        .unwrap()
        .request_async(
            &fixture.http,
            tokio::time::sleep,
            Some(Duration::from_secs(1)),
        )
        .await;
    assert!(
        result.is_err(),
        "used device code unexpectedly reused across clients"
    );
}

async fn claim_case(arm: &str) -> Result<VerifiedClaims, Error> {
    let fixture = Fixture::new().await;
    {
        let mut shared = fixture.shared.lock().unwrap();
        match arm {
            "aud" => {
                shared
                    .mode
                    .overrides
                    .insert("aud".into(), json!("paste-client"));
            }
            "azp" => {
                shared
                    .mode
                    .overrides
                    .insert("aud".into(), json!(["device-client", "other"]));
                shared
                    .mode
                    .overrides
                    .insert("azp".into(), json!("paste-client"));
            }
            "iss" => {
                shared
                    .mode
                    .overrides
                    .insert("iss".into(), json!("https://other.example"));
            }
            "exp" => {
                shared.mode.overrides.insert("exp".into(), json!(NOW));
            }
            "iat" => {
                shared.mode.overrides.insert("iat".into(), json!(NOW + 301));
            }
            "nonce" => {
                shared
                    .mode
                    .overrides
                    .insert("nonce".into(), json!("unsolicited"));
            }
            "signature" => shared.mode.bad_signature = true,
            "unknown_kid" => shared.mode.kid = "unavailable".into(),
            "rotated" => shared.mode.kid = "rotated".into(),
            "none" => shared.mode.alg = "none".into(),
            "hs" => shared.mode.alg = "HS256".into(),
            "multi_aud" => {
                shared
                    .mode
                    .overrides
                    .insert("aud".into(), json!(["device-client", "other"]));
                shared
                    .mode
                    .overrides
                    .insert("azp".into(), json!("device-client"));
            }
            "es256" => {
                shared.mode.alg = "ES256".into();
                shared.mode.kid = "ec".into();
            }
            "email_false" => {
                shared
                    .mode
                    .overrides
                    .insert("email_verified".into(), json!(false));
            }
            "email_string" => {
                shared
                    .mode
                    .overrides
                    .insert("email_verified".into(), json!("true"));
            }
            "missing_token" => shared.device_no_token = true,
            "bare_google" => {
                shared
                    .mode
                    .overrides
                    .insert("iss".into(), json!("accounts.google.com"));
            }
            _ => panic!("unknown test arm"),
        }
    }
    let provider = provider(&fixture).await;
    let clock = Clock::new();
    let pending = provider
        .begin_device_with_clock(&|| clock.now())
        .await
        .unwrap();
    let result = poll(&provider, pending, &clock).await;
    if arm == "unknown_kid" {
        assert_eq!(
            fixture.shared.lock().unwrap().jwks_requests,
            2,
            "unknown key refresh must happen exactly once"
        );
    }
    result
}
macro_rules! refusal {
    ($name:ident, $arm:literal, $error:pat) => {
        #[tokio::test]
        async fn $name() {
            assert!(
                matches!(claim_case($arm).await, Err($error)),
                concat!("device ", $arm, " refusal failed")
            );
        }
    };
}
refusal!(device_aud_refused, "aud", Error::Audience);
refusal!(device_azp_refused, "azp", Error::Audience);
refusal!(device_issuer_refused, "iss", Error::Issuer);
refusal!(device_expired_refused, "exp", Error::Expired);
refusal!(device_future_iat_refused, "iat", Error::IssuedAt);
refusal!(device_nonce_refused, "nonce", Error::Nonce);
refusal!(device_bad_signature_refused, "signature", Error::Signature);
refusal!(device_unknown_kid_refused, "unknown_kid", Error::Signature);
refusal!(device_hs_refused, "hs", Error::Signature);
refusal!(device_unsigned_refused, "none", Error::Signature);
refusal!(
    device_missing_id_token_refused,
    "missing_token",
    Error::Token
);
refusal!(
    device_bare_google_refused,
    "bare_google",
    Error::UnsupportedIssuer
);
#[tokio::test]
async fn device_es256_and_email_projection() {
    assert!(
        claim_case("es256").await.is_ok(),
        "device ES256 positive control failed"
    );
    assert!(
        claim_case("email_string").await.unwrap().email_verified,
        "string boolean rejected"
    );
    let claims = claim_case("email_false").await.unwrap();
    assert!(!claims.email_verified);
    assert!(
        claims.email.is_none(),
        "unverified email escaped projection"
    );
}

#[tokio::test]
async fn device_disabled_and_unsupported_metadata_make_no_device_request() {
    for arm in [
        "disabled",
        "no_client",
        "no_endpoint",
        "http_endpoint",
        "no_grant",
        "unadvertised_grants",
    ] {
        let fixture = Fixture::new().await;
        let mut config = fixture.config(false);
        config.device.enabled = arm != "disabled";
        if arm != "no_client" {
            config.clients.insert(
                Flow::Device,
                crate::enroll_ca::ClientConfig {
                    client_id: "device-client".into(),
                    client_secret_file: None,
                },
            );
        }
        match arm {
            "no_endpoint" => {
                fixture
                    .shared
                    .lock()
                    .unwrap()
                    .discovery_overrides
                    .insert("device_authorization_endpoint".into(), Value::Null);
            }
            "http_endpoint" => {
                fixture.shared.lock().unwrap().discovery_overrides.insert(
                    "device_authorization_endpoint".into(),
                    json!("http://fixture.example/device"),
                );
            }
            "no_grant" => {
                fixture.shared.lock().unwrap().discovery_overrides.insert(
                    "grant_types_supported".into(),
                    json!(["authorization_code"]),
                );
            }
            "unadvertised_grants" => {
                fixture
                    .shared
                    .lock()
                    .unwrap()
                    .discovery_overrides
                    .insert("grant_types_supported".into(), Value::Null);
            }
            _ => (),
        }
        let provider =
            Provider::discover_with_client("fixture", &config, true, fixture.http_client())
                .await
                .unwrap();
        let result = provider.begin_device().await;
        if arm == "unadvertised_grants" {
            assert!(result.is_ok(), "absent grant list refused");
        } else {
            assert!(
                matches!(
                    result,
                    Err(Error::DeviceDisabled | Error::DeviceUnsupported)
                ),
                "device capability guard failed: {arm}"
            );
            assert!(!fixture.request_paths().contains(&"/device".into()));
            assert!(!fixture.request_paths().contains(&"/token".into()));
        }
    }
}

#[tokio::test]
async fn device_pending_and_403_slowdown_are_persistent() {
    let fixture = Fixture::new().await;
    fixture.shared.lock().unwrap().device_errors.extend([
        (428, json!({"error":"authorization_pending"})),
        (403, json!({"error":"slow_down"})),
        (403, json!({"error":"slow_down"})),
        (428, json!({"error":"authorization_pending"})),
    ]);
    let provider = provider(&fixture).await;
    let clock = Clock::new();
    let pending = provider
        .begin_device_with_clock(&|| clock.now())
        .await
        .unwrap();
    assert!(poll(&provider, pending, &clock).await.is_ok());
    assert_eq!(
        *clock.sleeps.lock().unwrap(),
        vec![5, 5, 10, 15, 15],
        "pending/slow_down polling intervals changed"
    );
}

#[tokio::test]
async fn device_small_interval_uses_five_second_floor_and_slowdown() {
    let fixture = Fixture::new().await;
    fixture.shared.lock().unwrap().device_reply["interval"] = json!(1);
    fixture
        .shared
        .lock()
        .unwrap()
        .device_errors
        .push_back((403, json!({"error":"slow_down"})));
    let provider = provider(&fixture).await;
    let clock = Clock::new();
    let pending = provider
        .begin_device_with_clock(&|| clock.now())
        .await
        .unwrap();
    assert!(poll(&provider, pending, &clock).await.is_ok());
    assert_eq!(
        *clock.sleeps.lock().unwrap(),
        vec![5, 10],
        "small interval bypassed five-second floor"
    );
}

#[tokio::test]
async fn device_terminal_denial_expiry_and_unsupported_do_not_retry() {
    for (error, expected) in [
        ("access_denied", "denied"),
        ("expired_token", "expired"),
        ("unsupported_grant_type", "unsupported"),
    ] {
        let fixture = Fixture::new().await;
        fixture.shared.lock().unwrap().device_errors.extend([
            (403, json!({"error":error})),
            (428, json!({"error":"authorization_pending"})),
        ]);
        let provider = provider(&fixture).await;
        let clock = Clock::new();
        let pending = provider
            .begin_device_with_clock(&|| clock.now())
            .await
            .unwrap();
        let result = poll(&provider, pending, &clock).await;
        assert!(
            match expected {
                "denied" => matches!(result, Err(Error::Denied)),
                "expired" => matches!(result, Err(Error::Expired)),
                _ => matches!(result, Err(Error::DeviceUnsupported)),
            },
            "terminal device error classification failed"
        );
        assert_eq!(
            fixture
                .request_paths()
                .iter()
                .filter(|path| path.as_str() == "/token")
                .count(),
            1,
            "terminal provider error retried"
        );
    }
}

#[tokio::test]
async fn device_exact_deadline_and_late_response_refused() {
    for late_response in [false, true] {
        let fixture = Fixture::new().await;
        let provider = provider(&fixture).await;
        let clock = Arc::new(Clock::new());
        let pending = provider
            .begin_device_with_clock(&|| clock.now())
            .await
            .unwrap();
        if late_response {
            let clock = clock.clone();
            fixture.shared.lock().unwrap().mode.after_token = Some(Arc::new(move || {
                clock.elapsed.store(300, Ordering::SeqCst);
            }));
            // The issued code captures its own mode, as a real one-shot provider would.
            let mut shared = fixture.shared.lock().unwrap();
            let hook = shared.mode.after_token.clone();
            for mode in shared.codes.values_mut() {
                mode.after_token = hook.clone();
            }
        } else {
            clock.elapsed.store(295, Ordering::SeqCst);
        }
        let result = poll(&provider, pending, &clock).await;
        assert!(
            matches!(result, Err(Error::Expired)),
            "deadline equality or late signed response authorized"
        );
        let count = fixture
            .request_paths()
            .iter()
            .filter(|path| path.as_str() == "/token")
            .count();
        assert_eq!(
            count,
            usize::from(late_response),
            "expired code made an extra HTTP attempt"
        );
    }
}

#[tokio::test]
async fn device_invalid_expiry_and_unusable_interval_refused() {
    for (expiry, interval) in [(0, 5), (5, 5), (300, 300), (u64::MAX, u64::MAX)] {
        let fixture = Fixture::new().await;
        fixture.shared.lock().unwrap().device_reply =
            json!({"expires_in":expiry,"interval":interval});
        let provider = provider(&fixture).await;
        assert!(
            matches!(provider.begin_device().await, Err(Error::Expired)),
            "unusable device timing accepted"
        );
        assert!(!fixture.request_paths().contains(&"/token".into()));
    }
}

#[tokio::test]
async fn device_slowdown_above_ten_survives_transport_error() {
    let fixture = Fixture::new().await;
    fixture.shared.lock().unwrap().device_errors.extend([
        (403, json!({"error":"slow_down"})),
        (403, json!({"error":"slow_down"})),
        (0, json!({})),
        (428, json!({"error":"authorization_pending"})),
    ]);
    let provider = provider(&fixture).await;
    let clock = Clock::new();
    let pending = provider
        .begin_device_with_clock(&|| clock.now())
        .await
        .unwrap();
    assert!(poll(&provider, pending, &clock).await.is_ok());
    assert_eq!(
        *clock.sleeps.lock().unwrap(),
        vec![5, 10, 15, 30, 30],
        "transport backoff shrank live slow_down floor"
    );
}

#[tokio::test]
async fn device_code_http_latency_counts_against_original_deadline() {
    for elapsed in [250, 300] {
        let fixture = Fixture::new().await;
        let clock = Arc::new(Clock::new());
        let advanced = clock.clone();
        fixture.shared.lock().unwrap().after_device = Some(Arc::new(move || {
            advanced.elapsed.store(elapsed, Ordering::SeqCst);
        }));
        let provider = provider(&fixture).await;
        let result = provider.begin_device_with_clock(&|| clock.now()).await;
        if elapsed == 300 {
            assert!(
                matches!(result, Err(Error::Expired)),
                "late code response renewed deadline"
            );
        } else {
            assert_eq!(
                result.unwrap().deadline(),
                clock.start + Duration::from_secs(300),
                "code request latency excluded from deadline"
            );
        }
        assert!(!fixture.request_paths().contains(&"/token".into()));
    }
}

#[tokio::test]
async fn device_cancel_and_outer_deadline_stop_initial_wait() {
    let fixture = Fixture::new().await;
    let provider = Arc::new(provider(&fixture).await);
    let mut pending = provider.begin_device().await.unwrap();
    pending.deadline = tokio::time::Instant::now() + Duration::from_millis(10);
    let started = tokio::time::Instant::now();
    assert!(
        matches!(
            provider.poll_device(pending, &|| NOW).await,
            Err(Error::Expired)
        ),
        "outer deadline did not stop initial wait"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "outer deadline waited for polling interval"
    );
    let pending = provider.begin_device().await.unwrap();
    let worker = provider.clone();
    let task = tokio::spawn(async move { worker.poll_device(pending, &|| NOW).await });
    tokio::task::yield_now().await;
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(
        !fixture.request_paths().contains(&"/token".into()),
        "cancelled poller made a token request"
    );
}

#[tokio::test]
async fn device_frozen_client_binding_refuses_other_provider() {
    let fixture = Fixture::new().await;
    let provider = provider(&fixture).await;
    let pending = provider.begin_device().await.unwrap();
    let mut config = fixture.config(false);
    config.device.enabled = true;
    config.clients.insert(
        Flow::Device,
        crate::enroll_ca::ClientConfig {
            client_id: "other-device-client".into(),
            client_secret_file: None,
        },
    );
    let other = Provider::discover_with_client("fixture", &config, true, fixture.http_client())
        .await
        .unwrap();
    assert!(
        matches!(
            other.poll_device(pending, &|| NOW).await,
            Err(Error::Configuration)
        ),
        "device session changed frozen client"
    );
    assert!(!fixture.request_paths().contains(&"/token".into()));
}

#[tokio::test]
async fn device_google_uses_body_auth_for_code_and_poll() {
    let fixture = Fixture::new().await;
    let mut config = fixture.config(true);
    config.device.enabled = true;
    let mut device = config.clients[&Flow::Loopback].clone();
    device.client_id = "device-client".into();
    config.clients.insert(Flow::Device, device);
    let mut provider =
        Provider::discover_with_client("fixture", &config, false, fixture.http_client())
            .await
            .unwrap();
    provider.issuer = "https://accounts.google.com".into();
    let clock = Clock::new();
    let pending = provider
        .begin_device_with_clock(&|| clock.now())
        .await
        .unwrap();
    let _ = poll(&provider, pending, &clock).await;
    let shared = fixture.shared.lock().unwrap();
    assert_eq!(shared.forms.len(), 2);
    for form in &shared.forms {
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some("device-client"),
            "Google request did not use device body client ID"
        );
        assert_eq!(
            form.get("client_secret"),
            Some(&shared.secret),
            "Google client secret omitted from request body"
        );
    }
}

#[tokio::test]
async fn device_rotated_key_and_matching_multi_audience_accepted() {
    assert!(
        claim_case("rotated").await.is_ok(),
        "device rotated key not refreshed"
    );
    assert!(
        claim_case("multi_aud").await.is_ok(),
        "matching device multi-aud azp rejected"
    );
}

#[tokio::test]
async fn device_verification_wall_clock_sampled_after_http() {
    use std::sync::atomic::AtomicI64;
    let fixture = Fixture::new().await;
    let current = Arc::new(AtomicI64::new(NOW));
    let advanced = current.clone();
    fixture.shared.lock().unwrap().mode.after_token = Some(Arc::new(move || {
        advanced.store(NOW + 3600, Ordering::SeqCst);
    }));
    let provider = provider(&fixture).await;
    let clock = Clock::new();
    let pending = provider
        .begin_device_with_clock(&|| clock.now())
        .await
        .unwrap();
    assert!(
        matches!(
            provider
                .poll_device_inner(
                    pending,
                    &|| current.load(Ordering::SeqCst),
                    &|| clock.now(),
                    |duration| clock.sleep(duration)
                )
                .await,
            Err(Error::Expired)
        ),
        "device verification clock sampled before token HTTP"
    );
}

#[tokio::test]
async fn disabled_device_registration_does_not_read_secret_or_require_endpoint() {
    let fixture = Fixture::new().await;
    let mut config = fixture.config(false);
    config.clients.insert(
        Flow::Device,
        crate::enroll_ca::ClientConfig {
            client_id: "device-client".into(),
            client_secret_file: Some(fixture.files.path().join("deliberately-missing")),
        },
    );
    fixture
        .shared
        .lock()
        .unwrap()
        .discovery_overrides
        .insert("device_authorization_endpoint".into(), Value::Null);
    let provider = Provider::discover_with_client("fixture", &config, true, fixture.http_client())
        .await
        .expect("disabled device registration broke browser discovery");
    assert!(
        provider
            .begin(Flow::Loopback, "http://127.0.0.1:18551/cb")
            .is_ok(),
        "disabled device registration broke browser begin"
    );
    assert!(
        matches!(provider.begin_device().await, Err(Error::DeviceDisabled)),
        "disabled device must be classified before metadata"
    );
    assert!(!fixture.request_paths().contains(&"/device".into()));
}

#[tokio::test]
async fn fixture_unique_user_codes_need_one_shot_authorization() {
    let fixture = Fixture::new().await;
    fixture.require_device_authorization();
    let config = fixture.device_config(false);
    let provider = Provider::discover_with_client("fixture", &config, true, fixture.http_client())
        .await
        .unwrap();
    let first = provider.begin_device().await.unwrap();
    let second = provider.begin_device().await.unwrap();
    assert_ne!(
        first.user_code(),
        second.user_code(),
        "fixture reused user code"
    );
    assert!(!fixture.authorize_device("unknown-user-code"));
    assert!(fixture.authorize_device(first.user_code()));
    assert!(
        !fixture.authorize_device(first.user_code()),
        "fixture user code approval reused"
    );
    let clock = Clock::new();
    assert!(poll(&provider, first, &clock).await.is_ok());
    assert_eq!(fixture.device_requests(), 2);
    assert_eq!(fixture.device_polls(), 1);
}

#[tokio::test]
async fn device_poll_deadline_guard_stops_before_extra_http() {
    let fixture = Fixture::new().await;
    fixture.shared.lock().unwrap().device_reply["expires_in"] = json!(20);
    fixture
        .shared
        .lock()
        .unwrap()
        .device_errors
        .extend((0..4).map(|_| (428, json!({"error":"authorization_pending"}))));
    let provider = provider(&fixture).await;
    let clock = Clock::new();
    let pending = provider
        .begin_device_with_clock(&|| clock.now())
        .await
        .unwrap();
    assert!(
        matches!(poll(&provider, pending, &clock).await, Err(Error::Expired)),
        "polling continued after deadline"
    );
    assert_eq!(fixture.device_polls(), 3, "request sent at exact expiry");
}

#[tokio::test]
async fn device_provider_lifetime_is_capped_and_larger_interval_honored() {
    let fixture = Fixture::new().await;
    fixture.shared.lock().unwrap().device_reply = json!({"expires_in":600,"interval":12});
    let provider = provider(&fixture).await;
    let clock = Clock::new();
    let pending = provider
        .begin_device_with_clock(&|| clock.now())
        .await
        .unwrap();
    assert_eq!(
        pending.deadline(),
        clock.start + Duration::from_secs(300),
        "provider lifetime exceeded CA cap"
    );
    assert_eq!(pending.interval(), Duration::from_secs(12));
    assert!(poll(&provider, pending, &clock).await.is_ok());
    assert_eq!(
        *clock.sleeps.lock().unwrap(),
        vec![12],
        "larger provider interval ignored"
    );
}

#[tokio::test]
async fn device_jwks_refresh_checks_deadline_before_and_after_http() {
    for expire_before_fetch in [true, false] {
        use std::sync::atomic::AtomicBool;
        let fixture = Fixture::new().await;
        fixture.shared.lock().unwrap().mode.kid = "rotated".into();
        let clock = Arc::new(Clock::new());
        let token_returned = Arc::new(AtomicBool::new(false));
        let after_token_reads = AtomicU64::new(0);
        if expire_before_fetch {
            let returned = token_returned.clone();
            fixture.shared.lock().unwrap().mode.after_token = Some(Arc::new(move || {
                returned.store(true, Ordering::SeqCst);
            }));
        } else {
            let advanced = clock.clone();
            fixture.shared.lock().unwrap().mode.after_refresh = Some(Arc::new(move || {
                advanced.elapsed.store(300, Ordering::SeqCst);
            }));
        }
        let provider = provider(&fixture).await;
        let monotonic = || {
            if token_returned.load(Ordering::SeqCst) {
                let reads = after_token_reads.fetch_add(1, Ordering::SeqCst);
                clock.start + Duration::from_secs(if reads < 2 { 299 } else { 300 })
            } else {
                clock.now()
            }
        };
        let pending = provider.begin_device_with_clock(&monotonic).await.unwrap();
        let result = provider
            .poll_device_inner(pending, &|| NOW, &monotonic, |duration| {
                clock.sleep(duration)
            })
            .await;
        assert!(
            matches!(result, Err(Error::Expired)),
            "JWKS fetch crossed device deadline"
        );
        assert_eq!(
            fixture.shared.lock().unwrap().jwks_requests,
            if expire_before_fetch { 1 } else { 2 },
            "JWKS HTTP sent after device deadline"
        );
    }
}

#[tokio::test]
async fn device_authorization_endpoint_refusal_is_terminal_unsupported() {
    let fixture = Fixture::new().await;
    fixture.shared.lock().unwrap().device_reply =
        json!({"error":"unsupported_grant_type","__status":400});
    let provider = provider(&fixture).await;
    assert!(
        matches!(provider.begin_device().await, Err(Error::DeviceUnsupported)),
        "device endpoint refusal lost unsupported classification"
    );
    assert_eq!(fixture.device_requests(), 1);
    assert_eq!(
        fixture.device_polls(),
        0,
        "refused device endpoint was polled"
    );
}
