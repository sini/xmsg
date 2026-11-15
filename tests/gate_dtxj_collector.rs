use http_body_util::Full;
use hyper::body::Bytes;
use serde_json::json;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use xmsg::observe_export::*;

const LABEL: &str = "</text><image href=\"https://attacker.invalid/collect\"/><script>probe</script><img src=\"https://attacker.invalid/html\">&\"'";
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Server(JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
type FixtureReply = Arc<dyn Fn(&str) -> Vec<u8> + Send + Sync>;
async fn serve(
    acceptor: tokio_rustls::TlsAcceptor,
    reply: FixtureReply,
    ledger: Arc<Mutex<Vec<String>>>,
) -> (std::net::SocketAddr, Server) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted=listener.accept()=> {
                    let (tcp,_)=accepted.unwrap();
                    let (acceptor,reply,ledger)=(acceptor.clone(),reply.clone(),ledger.clone());
                    tasks.spawn(async move {
                        let Ok(tls)=acceptor.accept(tcp).await else{return};
                        let service=hyper::service::service_fn(move |request:hyper::Request<hyper::body::Incoming>| {
                            let resource=request.uri().to_string();
                            ledger.lock().unwrap().push(format!("{} {}",request.method(),resource));
                            let bytes=reply(&resource);
                            async move { Ok::<_,Infallible>(hyper::Response::new(Full::new(Bytes::from(bytes)))) }
                        });
                        let _=hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tls),service).await;
                    });
                }
                Some(_)=tasks.join_next(),if !tasks.is_empty()=>{}
            }
        }
    });
    (address, Server(task))
}
fn files_under(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut result = BTreeMap::new();
    fn visit(root: &Path, current: &Path, result: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(current).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                visit(root, &entry.path(), result);
            } else {
                result.insert(
                    entry
                        .path()
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .into(),
                    std::fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    visit(root, root, &mut result);
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn collector_cli_is_passive_and_owner_view_is_bounded() {
    cli_fixture(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operations_example_ca_and_lookup_fields_start_the_real_cli() {
    cli_fixture(true).await;
}

async fn cli_fixture(ca_mode: bool) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let files = tempfile::tempdir().unwrap();
    let canaries = [
        format!("synthetic-body-{}", ulid::Ulid::new()),
        format!("/synthetic/path/{}", ulid::Ulid::new()),
        format!("SYNTHETIC_ENV={}", ulid::Ulid::new()),
        format!("synthetic-bearer-{}", ulid::Ulid::new()),
    ];
    let scan = |bytes: &[u8]| {
        canaries
            .iter()
            .map(|canary| {
                bytes
                    .windows(canary.len())
                    .filter(|window| *window == canary.as_bytes())
                    .count()
            })
            .sum::<usize>()
    };
    let planted = canaries.join("\n");
    assert_eq!(
        scan(planted.as_bytes()),
        4,
        "fresh leak scanner positive control did not fire"
    );
    let mut metadata_matches = 0usize;
    let untouched = files.path().join("untouched");
    std::fs::create_dir_all(untouched.join("harness")).unwrap();
    for name in [
        "primary.db",
        "enroll-ca",
        "registration.sock",
        "harness/session.json",
    ] {
        let index = if name == "primary.db" {
            0
        } else if name == "enroll-ca" {
            1
        } else {
            2
        };
        std::fs::write(untouched.join(name), canaries[index].as_bytes()).unwrap();
    }
    let before = files_under(&untouched);
    let server = if ca_mode {
        let mut ca = rcgen::CertificateParams::default();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate().unwrap();
        std::fs::write(
            files.path().join("node-ca.pem"),
            ca.self_signed(&ca_key).unwrap().pem(),
        )
        .unwrap();
        let mut leaf = rcgen::CertificateParams::default();
        leaf.subject_alt_names = vec![rcgen::SanType::URI(
            "spiffe://xmsg/host/node/user/owner".try_into().unwrap(),
        )];
        leaf.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = leaf
            .signed_by(&key, &rcgen::Issuer::from_params(&ca, &ca_key))
            .unwrap();
        rcgen::CertifiedKey {
            cert,
            signing_key: key,
        }
    } else {
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap()
    };
    let client = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server_pin = xmsg::fed::spki_sha256_from_der(server.cert.der()).unwrap();
    let client_pin = xmsg::fed::spki_sha256_from_der(client.cert.der()).unwrap();
    let node = if ca_mode {
        "owner.node".to_owned()
    } else {
        xmsg::node::node_name_from_pin(&server_pin).unwrap()
    };
    let client_node = xmsg::node::node_name_from_pin(&client_pin).unwrap();
    let peers=Arc::new(xmsg::fed::PeersMap::load_from_json(&json!({client_node.clone():{"address":"127.0.0.1:1","pin":client_pin,"allow":["observe"]}}).to_string()).unwrap());
    let acceptor = xmsg::fed::make_tls_acceptor(
        &[server.cert.der().clone()],
        &server.signing_key.serialize_der(),
        peers,
    )
    .unwrap();
    let scope = Scope::new(&node, &client_node, None, !ca_mode).unwrap();
    let now = xmsg::storage::now_epoch_secs();
    let endpoint = format!("fixture@{node}");
    let snapshot = ExportSnapshot {
        v: 1,
        node: node.clone(),
        scope: scope.fingerprint().into(),
        observed_at: now,
        endpoints: vec![EndpointDescriptor {
            id: endpoint.clone(),
            node: node.clone(),
            kind: EndpointKind::Service,
            harness: Harness::Unknown,
            state: RegistrationState::Registered,
            source_at: Some(now),
            label: (!ca_mode).then(|| LABEL.into()),
        }],
        truncated: false,
        available: SnapshotAvailability::Partial,
    };
    let page = ExportPage {
        v: 1,
        node: node.clone(),
        epoch: "fixture-epoch".into(),
        scope: scope.fingerprint().into(),
        events: vec![ExportEvent {
            sequence: 1,
            source_at: Some(now),
            observed_at: now,
            persisted_at: now,
            kind: EventKind::MessageRecorded,
            from: Some(endpoint.clone()),
            to: Some(endpoint.clone()),
            message_id: Some("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()),
            reply_id: None,
            thread_id: None,
            outcome: Some(Outcome::Queued),
            reason: None,
            available: Availability::NotRecorded,
        }],
        next: 1,
        has_more: false,
        gaps: vec![ExportGap {
            reason: Reason::QueueLoss,
            unknown_loss: true,
        }],
        available: true,
    };
    let source_ledger = Arc::new(Mutex::new(Vec::new()));
    let (source_addr, _source) = serve(
        acceptor,
        Arc::new(move |resource| {
            if resource.starts_with("/fed/v2/observe/snapshot?") {
                serde_json::to_vec(&snapshot).unwrap()
            } else if resource.starts_with("/fed/v2/observe/events?") {
                let mut current = page.clone();
                if resource.contains("after=1") {
                    current.events.clear();
                }
                serde_json::to_vec(&current).unwrap()
            } else {
                panic!("collector accessed a consuming bus path");
            }
        }),
        source_ledger.clone(),
    )
    .await;
    let provider = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![provider.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(provider.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
    let provider_ledger = Arc::new(Mutex::new(Vec::new()));
    let (provider_addr,_provider)=serve(tokio_rustls::TlsAcceptor::from(Arc::new(provider_tls)),Arc::new(move |_|json!({"active":true,"iss":"https://owner.invalid","sub":"fixture-owner","aud":"collector","client_id":"hosted","exp":now+3600}).to_string().into_bytes()),provider_ledger.clone()).await;
    std::fs::write(files.path().join("client.pem"), client.cert.pem()).unwrap();
    std::fs::write(
        files.path().join("client.key"),
        client.signing_key.serialize_pem(),
    )
    .unwrap();
    std::fs::write(files.path().join("provider.pem"), provider.cert.pem()).unwrap();
    std::fs::write(
        files.path().join("lookup-secret"),
        "synthetic-lookup-fixture",
    )
    .unwrap();
    let source = if ca_mode {
        json!({"node":node,"address":source_addr.to_string(),"ca":"node-ca.pem","identity":"spiffe://xmsg/host/node/user/owner","labels":false})
    } else {
        json!({"node":node,"address":source_addr.to_string(),"pin":server_pin,"labels":true})
    };
    let config = json!({"client_cert":"client.pem","client_key":"client.key","auth":{"issuer":"https://owner.invalid","introspection_url":format!("https://localhost:{}/introspect",provider_addr.port()),"subjects":["fixture-owner"],"audience":"collector","hosted_client":"hosted","lookup_client":"observer-lookup","lookup_secret_file":"lookup-secret","provider_ca":"provider.pem"},"sources":[source,{"node":"outbound.leaf","outbound_only":true}]});
    let config_file = files.path().join("collector.json");
    std::fs::write(&config_file, config.to_string()).unwrap();
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let mut child = Process(
        Command::new(env!("CARGO_BIN_EXE_xmsg"))
            .args(["observe-collector", "--config"])
            .arg(&config_file)
            .arg("--state-dir")
            .arg(files.path().join("collector-state"))
            .arg("--listen")
            .arg(address.to_string())
            .current_dir(&untouched)
            .env("HOME", &untouched)
            .env("XDG_RUNTIME_DIR", &untouched)
            .env("XDG_STATE_HOME", &untouched)
            .env("XMSG_DB_PATH", untouched.join("primary.db"))
            .env("XMSG_ENROLL_CA_DIR", untouched.join("enroll-ca"))
            .env("CODEX_HOME", untouched.join("harness"))
            .env("XMSG_COLLECTOR_FIXTURE_LEAK", &canaries[2])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let url = format!("http://{address}");
    let index = usize::from(node.as_str() > "outbound.leaf");
    let deadline = Instant::now() + Duration::from_secs(12);
    let html = loop {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "collector CLI exited during isolated startup"
        );
        if let Ok(reply) = client
            .get(format!("{url}/?node={index}"))
            .bearer_auth(&canaries[3])
            .send()
            .await
        {
            let headers = reply.headers().clone();
            let html = reply.text().await.unwrap();
            metadata_matches += scan(html.as_bytes());
            if html.contains("sequence 1") {
                assert_eq!(headers["cache-control"], "no-store");
                assert_eq!(headers["x-content-type-options"], "nosniff");
                if let Some(output) =
                    std::env::var_os("XMSG_COLLECTOR_BROWSER_FIXTURE_DIR").filter(|_| !ca_mode)
                {
                    let output = std::path::PathBuf::from(output);
                    std::fs::create_dir_all(&output).unwrap();
                    std::fs::write(output.join("page.html"), &html).unwrap();
                    std::fs::write(output.join("headers.json"),json!({"content-security-policy":headers["content-security-policy"].to_str().unwrap(),"cache-control":"no-store","x-content-type-options":"nosniff"}).to_string()).unwrap();
                    std::fs::write(
                        output.join("expect.json"),
                        json!({"label":LABEL,"endpoint":endpoint,"events":1,"endpoints":1})
                            .to_string(),
                    )
                    .unwrap();
                }
                break html;
            }
        }
        assert!(
            Instant::now() < deadline,
            "collector CLI failed to persist and present exporter backfill"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    if !ca_mode {
        if let (Some(python), Some(chromium)) = (
            std::env::var_os("XMSG_COLLECTOR_BROWSER_PYTHON"),
            std::env::var_os("XMSG_COLLECTOR_BROWSER_CHROMIUM"),
        ) {
            let output = files.path().join("browser-fixture");
            std::fs::create_dir_all(&output).unwrap();
            std::fs::write(output.join("page.html"), &html).unwrap();
            std::fs::write(output.join("headers.json"),json!({"content-security-policy":xmsg::observe_collector_web::content_security_policy(),"cache-control":"no-store","x-content-type-options":"nosniff"}).to_string()).unwrap();
            std::fs::write(
                output.join("expect.json"),
                json!({"label":LABEL,"endpoint":endpoint,"events":1,"endpoints":1}).to_string(),
            )
            .unwrap();
            let browser = Command::new(python)
                .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dtxj_collector_browser.py"))
                .arg("--fixture-dir")
                .arg(&output)
                .arg("--chromium")
                .arg(chromium)
                .output()
                .unwrap();
            eprintln!("{}", String::from_utf8_lossy(&browser.stdout));
            if !browser.status.success() {
                eprintln!("{}", String::from_utf8_lossy(&browser.stderr));
            }
            assert!(
                browser.status.success(),
                "collector browser DOM/network gate failed"
            );
        }
    }
    assert!(html.contains("unsupported: outbound-only source"));
    if !ca_mode {
        assert!(html.contains("&lt;image"));
    }
    assert_eq!(
        scan(html.as_bytes()),
        0,
        "browser HTML leaked a synthetic canary"
    );
    assert_eq!(
        client
            .get(format!("{url}/?node={index}"))
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "direct backend exposed owner metadata"
    );
    assert_eq!(
        client
            .get(format!("{url}/health"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "available\n"
    );
    let ledger = source_ledger.lock().unwrap();
    assert!(
        ledger
            .iter()
            .any(|r| r.starts_with("GET /fed/v2/observe/snapshot?")),
        "snapshot positive ledger missing"
    );
    assert!(
        ledger.iter().any(|r| r.contains(&format!(
            "/events?v=1&after=0&limit=200&labels={}",
            !ca_mode
        ))),
        "collector started at tail rather than explicit backfill"
    );
    assert!(
        ledger.iter().all(|r| r.starts_with("GET /fed/v2/observe/")),
        "collector invoked a non-observation bus route"
    );
    assert!(
        !provider_ledger.lock().unwrap().is_empty(),
        "owner introspection positive ledger missing"
    );
    assert!(
        files_under(&untouched) == before,
        "collector initialized or changed primary/harness/enrollment state"
    );
    assert_eq!(
        metadata_matches, 0,
        "collector metadata response leaked a synthetic canary"
    );
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let mut diagnostics = Vec::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut diagnostics)
        .unwrap();
    assert_eq!(
        scan(&diagnostics),
        0,
        "collector diagnostics leaked a synthetic canary"
    );
    for bytes in files_under(&files.path().join("collector-state")).values() {
        assert_eq!(
            scan(bytes),
            0,
            "collector database leaked a synthetic canary"
        );
    }
    println!("fresh synthetic canaries generated=4; planted positive matches=4; unexpected metadata/DB/diagnostic matches=0");
    println!(
        "collector CLI ledger: exporter calls={}, owner lookups={}, untouched files={}",
        ledger.len(),
        provider_ledger.lock().unwrap().len(),
        before.len()
    );
}
