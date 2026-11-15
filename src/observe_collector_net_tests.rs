use super::*;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fixture {
    _directory: tempfile::TempDir,
    config_file: PathBuf,
    config: serde_json::Value,
    task: tokio::task::JoinHandle<()>,
    requests: Arc<AtomicUsize>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = tempfile::tempdir().unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_pin = crate::fed::spki_sha256_from_der(server.cert.der()).unwrap();
        let client_pin = crate::fed::spki_sha256_from_der(client.cert.der()).unwrap();
        let server_name = crate::node::node_name_from_pin(&server_pin).unwrap();
        let client_name = crate::node::node_name_from_pin(&client_pin).unwrap();
        std::fs::write(directory.path().join("client.pem"), client.cert.pem()).unwrap();
        std::fs::write(
            directory.path().join("client.key"),
            client.signing_key.serialize_pem(),
        )
        .unwrap();
        let peer_json = json!({client_name.clone():{"address":"127.0.0.1:1","pin":client_pin,"allow":["observe"]}});
        let peers = Arc::new(PeersMap::load_from_json(&peer_json.to_string()).unwrap());
        let acceptor = crate::fed::make_tls_acceptor(
            &[server.cert.der().clone()],
            &server.signing_key.serialize_der(),
            peers,
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = requests.clone();
        let scope =
            crate::observe_export::Scope::new(&server_name, &client_name, None, false).unwrap();
        let snapshot = crate::observe_export::project_snapshot(
            &scope,
            Vec::new(),
            crate::storage::now_epoch_secs(),
            true,
        )
        .unwrap();
        let body = serde_json::to_vec(&snapshot).unwrap();
        let task = tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let observed = observed.clone();
                let body = body.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let service = hyper::service::service_fn(
                        move |request: hyper::Request<hyper::body::Incoming>| {
                            let body = body.clone();
                            observed.fetch_add(1, Ordering::SeqCst);
                            async move {
                                assert!(request.uri().path().starts_with("/fed/v2/observe/"));
                                Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                    http_body_util::Full::new(Bytes::from(body)),
                                ))
                            }
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        let config = json!({"client_cert":"client.pem","client_key":"client.key","auth":{
            "issuer":"https://idp.invalid/issuer","introspection_url":"https://idp.invalid/introspect","subjects":["owner"],"audience":"collector","hosted_client":"browser"
        },"sources":[{"node":server_name,"address":address.to_string(),"pin":server_pin}]});
        Self {
            config_file: directory.path().join("config.json"),
            _directory: directory,
            config,
            task,
            requests,
        }
    }
    fn load(&self) -> Result<Config, Error> {
        std::fs::write(&self.config_file, self.config.to_string()).unwrap();
        Config::load(&self.config_file)
    }
}

#[tokio::test]
async fn configured_pin_collects_without_any_bus_state_and_enforces_spacing() {
    let fixture = Fixture::new().await;
    let config = fixture.load().unwrap();
    let client = Client::new(&config).unwrap();
    let snapshot = client.snapshot(0).await.unwrap();
    assert_eq!(snapshot.node, config.sources[0].node);
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 1);
    assert!(
        matches!(client.snapshot(0).await, Err(Error::Pending)),
        "minimum node spacing bypassed"
    );
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn outbound_only_inventory_never_opens_a_connection() {
    let mut fixture = Fixture::new().await;
    fixture.config["sources"][0]["outbound_only"] = json!(true);
    let config = fixture.load().unwrap();
    let client = Client::new(&config).unwrap();
    assert!(
        matches!(client.snapshot(0).await, Err(Error::Unsupported)),
        "outbound leaf became directly observable"
    );
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn inventory_is_bounded_literal_and_unique() {
    let mut fixture = Fixture::new().await;
    assert!(fixture.load().is_ok());
    let entry = fixture.config["sources"][0].clone();
    fixture.config["sources"] = json!([entry.clone(), entry.clone()]);
    assert!(fixture.load().is_err(), "duplicate inventory node accepted");
    fixture.config["sources"] = json!(vec![entry.clone(); 65]);
    assert!(fixture.load().is_err(), "oversized inventory accepted");
    fixture.config["sources"] = json!([{"node":"owner.collector","address":"127.0.0.1:1","ca":"ca.pem","identity":"spiffe://xmsg/host/*/user/owner"}]);
    assert!(
        fixture.load().is_err(),
        "wildcard collector trust identity accepted"
    );
    fixture.config["sources"][0]["identity"] = json!("spiffe://xmsg/host/other/user/owner");
    assert!(
        fixture.load().is_err(),
        "foreign inventory identity accepted"
    );
    fixture.config["sources"] = json!([entry]);
    fixture.config["browser_address"] = json!("127.0.0.1:9");
    assert!(
        fixture.load().is_err(),
        "unrecognized configuration authority accepted"
    );
}
