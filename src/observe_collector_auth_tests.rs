use super::*;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

#[derive(Clone)]
struct Reply {
    status: u16,
    body: Vec<u8>,
    delay: Duration,
    chunked: bool,
}
impl Reply {
    fn claims(value: Value) -> Self {
        Self {
            status: 200,
            body: serde_json::to_vec(&value).unwrap(),
            delay: Duration::ZERO,
            chunked: false,
        }
    }
}
struct Idp {
    config: AuthConfig,
    reply: Arc<Mutex<Reply>>,
    calls: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    task: JoinHandle<()>,
    _files: TempDir,
}
impl Drop for Idp {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn claims() -> Value {
    json!({"active":true,"iss":"https://owner.example","sub":"owner","aud":"collector","client_id":"hosted","exp":2000})
}
impl Idp {
    async fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
                ),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let files = tempfile::tempdir().unwrap();
        let ca = files.path().join("provider.pem");
        std::fs::write(&ca, cert.cert.pem()).unwrap();
        let reply = Arc::new(Mutex::new(Reply::claims(claims())));
        let calls = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (responses, count, ledger) = (reply.clone(), calls.clone(), requests.clone());
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (acceptor, responses, count, ledger) = (
                    acceptor.clone(),
                    responses.clone(),
                    count.clone(),
                    ledger.clone(),
                );
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut bytes = Vec::new();
                    loop {
                        let mut chunk = [0; 1024];
                        let Ok(n) = stream.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&chunk[..n]);
                        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                            let len = head
                                .lines()
                                .find_map(|line| line.strip_prefix("content-length: "))
                                .unwrap_or("0")
                                .trim()
                                .parse::<usize>()
                                .unwrap();
                            if bytes.len() >= end + 4 + len {
                                break;
                            }
                        }
                    }
                    count.fetch_add(1, Ordering::SeqCst);
                    ledger.lock().unwrap().push(bytes);
                    let response = responses.lock().unwrap().clone();
                    tokio::time::sleep(response.delay).await;
                    let framing = if response.chunked {
                        "Transfer-Encoding: chunked".to_owned()
                    } else {
                        format!("Content-Length: {}", response.body.len())
                    };
                    let headers = format!("HTTP/1.1 {} Fixture\r\n{}\r\nLocation: /redirected\r\nConnection: close\r\n\r\n", response.status, framing);
                    if stream.write_all(headers.as_bytes()).await.is_err() {
                        return;
                    }
                    if response.chunked {
                        for chunk in response.body.chunks(8192) {
                            if stream
                                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                                .await
                                .is_err()
                            {
                                return;
                            }
                            if stream.write_all(chunk).await.is_err() {
                                return;
                            }
                            if stream.write_all(b"\r\n").await.is_err() {
                                return;
                            }
                        }
                        let _ = stream.write_all(b"0\r\n\r\n").await;
                    } else {
                        let _ = stream.write_all(&response.body).await;
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            config: AuthConfig {
                issuer: "https://owner.example".to_owned(),
                introspection_url: format!("https://localhost:{port}/introspect"),
                subjects: vec!["owner".to_owned()],
                audience: "collector".to_owned(),
                hosted_client: "hosted".to_owned(),
                lookup_client: None,
                lookup_secret_file: None,
                provider_ca: Some(ca),
            },
            reply,
            calls,
            requests,
            task,
            _files: files,
        }
    }
    fn verifier(&self) -> Verifier {
        Verifier::new(self.config.clone(), Arc::new(|| 1000)).unwrap()
    }
    fn set(&self, value: Value) {
        *self.reply.lock().unwrap() = Reply::claims(value);
    }
}
fn headers() -> axum::http::HeaderMap {
    let mut h = axum::http::HeaderMap::new();
    h.insert("authorization", "Bearer fixture-token".parse().unwrap());
    h
}
async fn is_denied(idp: &Idp, value: Value) -> bool {
    idp.set(value);
    idp.verifier().authorize(&headers()).await.is_err()
}

#[tokio::test]
async fn owner_claims() {
    let idp = Idp::new().await;
    let owner = idp.verifier().authorize(&headers()).await.unwrap();
    assert_eq!(owner.subject, "owner");
    assert_eq!(owner.expires_at, 2000);
    for mode in 0..3 {
        let mut c = claims();
        c.as_object_mut().unwrap().remove("client_id");
        if mode != 1 {
            c["client_id"] = json!("hosted");
        }
        if mode != 0 {
            c["azp"] = json!("hosted");
        }
        c["aud"] = json!(["collector"]);
        idp.set(c);
        assert!(idp.verifier().authorize(&headers()).await.is_ok());
    }
    let mut c = claims();
    c["nbf"] = json!(1000);
    idp.set(c);
    assert!(idp.verifier().authorize(&headers()).await.is_ok());
}

macro_rules! denied_claim {
    ($name:ident, $field:literal, $value:expr, $message:literal) => {
        #[tokio::test]
        async fn $name() {
            let idp = Idp::new().await;
            assert!(idp.verifier().authorize(&headers()).await.is_ok());
            let mut c = claims();
            c[$field] = $value;
            assert!(is_denied(&idp, c).await, $message);
        }
    };
}
denied_claim!(
    inactive,
    "active",
    json!(false),
    "inactive owner must refuse"
);
denied_claim!(
    active_type,
    "active",
    json!("true"),
    "nonboolean active must refuse"
);
denied_claim!(
    issuer,
    "iss",
    json!("https://foreign.example"),
    "foreign issuer must refuse"
);
denied_claim!(
    subject,
    "sub",
    json!("stranger"),
    "nonowner subject must refuse"
);
denied_claim!(
    audience,
    "aud",
    json!("other"),
    "foreign audience must refuse"
);
denied_claim!(
    audience_multiple,
    "aud",
    json!(["collector", "collector"]),
    "multiple audiences must refuse"
);
denied_claim!(
    client,
    "client_id",
    json!("other"),
    "foreign client must refuse"
);
denied_claim!(
    client_type,
    "client_id",
    json!(null),
    "null client must refuse"
);
denied_claim!(expired, "exp", json!(1000), "expired owner must refuse");
denied_claim!(expiry_type, "exp", json!("2000"), "bad expiry must refuse");
denied_claim!(
    not_before,
    "nbf",
    json!(1001),
    "future not-before must refuse"
);
denied_claim!(
    not_before_type,
    "nbf",
    json!(null),
    "bad not-before must refuse"
);

#[tokio::test]
async fn conflicting_client() {
    let idp = Idp::new().await;
    assert!(idp.verifier().authorize(&headers()).await.is_ok());
    let mut c = claims();
    c["azp"] = json!("other");
    assert!(is_denied(&idp, c).await, "conflicting clients must refuse");
}
#[tokio::test]
async fn missing_claims() {
    let idp = Idp::new().await;
    for field in ["active", "iss", "sub", "aud", "client_id", "exp"] {
        let mut c = claims();
        c.as_object_mut().unwrap().remove(field);
        assert!(
            is_denied(&idp, c).await,
            "missing required claim must refuse"
        );
    }
    for field in ["active", "iss", "sub", "aud", "client_id", "exp", "nbf"] {
        for bad in [Value::Null, json!(false), json!({}), json!([])] {
            let mut c = claims();
            c[field] = bad;
            assert!(is_denied(&idp, c).await, "malformed claim must refuse");
        }
    }
    for bad in [
        json!(-1),
        json!(1.5),
        serde_json::from_str("18446744073709551616").unwrap(),
    ] {
        let mut c = claims();
        c["exp"] = bad;
        assert!(is_denied(&idp, c).await, "non-u64 expiry must refuse");
    }
}
#[tokio::test]
async fn missing_client() {
    let idp = Idp::new().await;
    assert!(idp.verifier().authorize(&headers()).await.is_ok());
    let mut c = claims();
    c.as_object_mut().unwrap().remove("client_id");
    assert!(is_denied(&idp, c).await, "missing client must refuse");
}
#[tokio::test]
async fn revalidation() {
    let idp = Idp::new().await;
    let verifier = idp.verifier();
    assert!(verifier.authorize(&headers()).await.is_ok());
    let mut c = claims();
    c["active"] = json!(false);
    idp.set(c);
    assert!(
        verifier.authorize(&headers()).await.is_err(),
        "every request must revalidate activity"
    );
    assert_eq!(idp.calls.load(Ordering::SeqCst), 2);
    idp.reply.lock().unwrap().status = 503;
    assert_eq!(
        verifier
            .authorize(&headers())
            .await
            .err()
            .unwrap()
            .status_code(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
}
#[tokio::test]
async fn bearer_syntax() {
    let idp = Idp::new().await;
    let v = idp.verifier();
    let mut forged = axum::http::HeaderMap::new();
    forged.insert("x-auth-request-user", "owner".parse().unwrap());
    forged.insert("x-forwarded-user", "owner".parse().unwrap());
    assert!(
        v.authorize(&forged).await.is_err(),
        "identity headers must not authorize"
    );
    for raw in [
        "",
        "Basic foo",
        "Bearer",
        "Bearer ",
        "Bearer foo bar",
        "Bearer foo ",
        "Bearer\tfoo",
        "Bearer foo\tbar",
        "Bearer =foo",
        "Bearer foo=bar",
        "Bearer foo,bar",
    ] {
        let mut h = headers();
        h.insert("authorization", raw.parse().unwrap());
        assert!(
            v.authorize(&h).await.is_err(),
            "malformed bearer must refuse"
        );
    }
    let mut h = headers();
    h.append("authorization", "Bearer second".parse().unwrap());
    assert!(
        v.authorize(&h).await.is_err(),
        "duplicate authorization must refuse"
    );
    assert_eq!(idp.calls.load(Ordering::SeqCst), 0);
    let mut h = headers();
    h.insert("authorization", "bEaReR abc-._~+/==".parse().unwrap());
    assert!(v.authorize(&h).await.is_ok());
    h.insert("authorization", "Bearer  fixture-token".parse().unwrap());
    assert!(
        v.authorize(&h).await.is_ok(),
        "ASCII separator spaces must be accepted"
    );
}
#[tokio::test]
async fn bearer_bound() {
    let idp = Idp::new().await;
    let v = idp.verifier();
    let mut h = headers();
    h.insert(
        "authorization",
        format!("Bearer {}", "x".repeat(8192)).parse().unwrap(),
    );
    assert!(v.authorize(&h).await.is_ok());
    h.insert(
        "authorization",
        format!("Bearer {}", "x".repeat(8193)).parse().unwrap(),
    );
    assert!(
        v.authorize(&h).await.is_err(),
        "oversized bearer must refuse"
    );
}
#[tokio::test]
async fn header_bound() {
    let idp = Idp::new().await;
    let v = idp.verifier();
    let mut h = headers();
    let used = h
        .iter()
        .map(|(k, v)| k.as_str().len() + v.as_bytes().len() + 4)
        .sum::<usize>()
        + 2
        + "x-fill".len()
        + 4;
    h.insert("x-fill", "x".repeat(16384 - used).parse().unwrap());
    assert!(v.authorize(&h).await.is_ok());
    h.insert("x-fill", "x".repeat(16385 - used).parse().unwrap());
    assert!(
        v.authorize(&h).await.is_err(),
        "oversized headers must refuse"
    );
}
#[tokio::test]
async fn response_bound() {
    let idp = Idp::new().await;
    let v = idp.verifier();
    let mut body = serde_json::to_vec(&claims()).unwrap();
    body.resize(65536, b' ');
    {
        let mut r = idp.reply.lock().unwrap();
        r.body = body.clone();
        r.chunked = true;
    }
    assert!(v.authorize(&headers()).await.is_ok());
    body.push(b' ');
    idp.reply.lock().unwrap().body = body;
    assert!(
        v.authorize(&headers()).await.is_err(),
        "oversized streamed provider response must refuse"
    );
}
#[tokio::test]
async fn provider_status() {
    let idp = Idp::new().await;
    let v = idp.verifier();
    assert!(v.authorize(&headers()).await.is_ok());
    idp.reply.lock().unwrap().status = 201;
    assert!(
        v.authorize(&headers()).await.is_err(),
        "non-200 provider must refuse"
    );
}
#[tokio::test]
async fn redirect() {
    let idp = Idp::new().await;
    let v = idp.verifier();
    assert!(v.authorize(&headers()).await.is_ok());
    idp.reply.lock().unwrap().status = 302;
    assert!(v.authorize(&headers()).await.is_err());
    assert_eq!(
        idp.calls.load(Ordering::SeqCst),
        2,
        "provider redirects must not be followed"
    );
}
#[tokio::test]
async fn provider_timeout() {
    let idp = Idp::new().await;
    let v = idp.verifier();
    assert!(v.authorize(&headers()).await.is_ok());
    idp.reply.lock().unwrap().delay = Duration::from_millis(2300);
    let started = std::time::Instant::now();
    let result = v.authorize(&headers()).await;
    assert!(result.is_err(), "slow provider must refuse");
    assert!(
        started.elapsed() < Duration::from_millis(2250),
        "provider must have a whole two-second budget"
    );
}
#[tokio::test]
async fn configuration_and_privacy() {
    let idp = Idp::new().await;
    let mut c = idp.config.clone();
    c.introspection_url = "http://localhost/introspect".into();
    assert!(Verifier::new(c, Arc::new(|| 1000)).is_err());
    let mut c = idp.config.clone();
    c.provider_ca = None;
    assert!(Verifier::new(c, Arc::new(|| 1000))
        .unwrap()
        .authorize(&headers())
        .await
        .is_err());
    let mut c = idp.config.clone();
    c.lookup_client = Some("lookup".into());
    assert!(Verifier::new(c.clone(), Arc::new(|| 1000)).is_err());
    let secret = idp._files.path().join("secret");
    std::fs::write(&secret, "fixture-secret\n").unwrap();
    c.lookup_secret_file = Some(secret.clone());
    let v = Verifier::new(c.clone(), Arc::new(|| 1000)).unwrap();
    std::fs::remove_file(&secret).unwrap();
    assert!(v.authorize(&headers()).await.is_ok());
    let req = idp.requests.lock().unwrap().last().unwrap().clone();
    let req = String::from_utf8(req).unwrap();
    assert!(req.starts_with("POST /introspect HTTP/1.1\r\n"));
    assert!(req.contains("token=fixture-token"));
    assert!(req.to_ascii_lowercase().contains("authorization: basic "));
    assert!(!req.contains("Bearer fixture-token"));
    std::fs::write(&secret, vec![b'x'; 8193]).unwrap();
    assert!(
        Verifier::new(c, Arc::new(|| 1000)).is_err(),
        "oversized mounted secret must refuse"
    );
    idp.reply.lock().unwrap().body = b"provider-private-error".to_vec();
    let error = idp.verifier().authorize(&headers()).await.err().unwrap();
    assert_eq!(error.to_string(), "identity provider unavailable");
    assert!(!format!("{error:?}").contains("private"));
}

macro_rules! absent_claim {
    ($name:ident, $field:literal, $message:literal) => {
        #[tokio::test]
        async fn $name() {
            let idp = Idp::new().await;
            assert!(idp.verifier().authorize(&headers()).await.is_ok());
            let mut c = claims();
            c.as_object_mut().unwrap().remove($field);
            assert!(is_denied(&idp, c).await, $message);
        }
    };
}
absent_claim!(missing_issuer, "iss", "missing issuer must refuse");
absent_claim!(missing_subject, "sub", "missing subject must refuse");
absent_claim!(missing_expiry, "exp", "missing expiry must refuse");

#[tokio::test]
async fn identity_header_fallback() {
    let idp = Idp::new().await;
    let mut h = axum::http::HeaderMap::new();
    h.insert("x-auth-request-user", "owner".parse().unwrap());
    assert!(
        idp.verifier().authorize(&h).await.is_err(),
        "identity headers must not authorize"
    );
    assert_eq!(idp.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn verified_tls() {
    let idp = Idp::new().await;
    assert!(idp.verifier().authorize(&headers()).await.is_ok());
    let mut config = idp.config.clone();
    config.provider_ca = None;
    assert!(
        Verifier::new(config, Arc::new(|| 1000))
            .unwrap()
            .authorize(&headers())
            .await
            .is_err(),
        "untrusted provider TLS must refuse"
    );
}
#[tokio::test]
async fn https_configuration() {
    let idp = Idp::new().await;
    assert!(Verifier::new(idp.config.clone(), Arc::new(|| 1000)).is_ok());
    let mut config = idp.config.clone();
    config.introspection_url = "http://localhost/introspect".to_owned();
    assert!(
        Verifier::new(config, Arc::new(|| 1000)).is_err(),
        "plaintext provider configuration must refuse"
    );
}

#[tokio::test]
async fn audience_array() {
    let idp = Idp::new().await;
    let mut c = claims();
    c["aud"] = json!(["collector"]);
    idp.set(c.clone());
    assert!(idp.verifier().authorize(&headers()).await.is_ok());
    c["aud"] = json!(["other"]);
    assert!(
        is_denied(&idp, c).await,
        "foreign singleton audience must refuse"
    );
}
#[tokio::test]
async fn audience_array_type() {
    let idp = Idp::new().await;
    let mut c = claims();
    c["aud"] = json!(["collector"]);
    idp.set(c.clone());
    assert!(idp.verifier().authorize(&headers()).await.is_ok());
    c["aud"] = json!([null]);
    assert!(
        is_denied(&idp, c).await,
        "nonstring singleton audience must refuse"
    );
}
#[tokio::test]
async fn malformed_azp() {
    let idp = Idp::new().await;
    for bad in [Value::Null, json!(false), json!(1), json!([]), json!({})] {
        let mut c = claims();
        c["azp"] = bad.clone();
        assert!(
            is_denied(&idp, c.clone()).await,
            "malformed additional client binding must refuse"
        );
        c.as_object_mut().unwrap().remove("client_id");
        assert!(
            is_denied(&idp, c).await,
            "malformed sole client binding must refuse"
        );
    }
}
