use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xmsg::observe_collector_net::{Client, Config, Error};
use xmsg::observe_export::ExportPage;

pub fn event(sequence: i64, kind: Value) -> Value {
    json!({"sequence":sequence,"observed_at":1700000000,"persisted_at":1700000000,
        "kind":kind,"available":"not_recorded"})
}

pub fn page(events: Vec<Value>) -> Value {
    json!({"v":2,"node":"placeholder","epoch":"fixture-epoch","scope":"a".repeat(64),
        "next":events.len(),"events":events,"has_more":false,"gaps":[],"available":true})
}

pub async fn receive(mut page: Value) -> Result<ExportPage, Error> {
    receive_raw(move |node| {
        page["node"] = json!(node);
        page.to_string()
    })
    .await
}

pub async fn receive_raw(body: impl FnOnce(&str) -> String) -> Result<ExportPage, Error> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let directory = tempfile::tempdir().unwrap();
    let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let client = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server_pin = xmsg::fed::spki_sha256_from_der(server.cert.der()).unwrap();
    let client_pin = xmsg::fed::spki_sha256_from_der(client.cert.der()).unwrap();
    let server_name = xmsg::node::node_name_from_pin(&server_pin).unwrap();
    let client_name = xmsg::node::node_name_from_pin(&client_pin).unwrap();
    std::fs::write(directory.path().join("client.pem"), client.cert.pem()).unwrap();
    std::fs::write(
        directory.path().join("client.key"),
        client.signing_key.serialize_pem(),
    )
    .unwrap();
    let peers = xmsg::fed::PeersMap::load_from_json(
        &json!({client_name:{
        "address":"127.0.0.1:1","pin":client_pin,"allow":["observe"]}})
        .to_string(),
    )
    .unwrap();
    let acceptor = xmsg::fed::make_tls_acceptor(
        &[server.cert.der().clone()],
        &server.signing_key.serialize_der(),
        Arc::new(peers),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let body = body(&server_name);
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let mut buf = [0; 1024];
            let size = tls.read(&mut buf).await.unwrap();
            assert!(size > 0, "client closed before request");
            request.extend_from_slice(&buf[..size]);
            assert!(request.len() < 8192);
        }
        assert!(request.starts_with(b"GET /fed/v2/observe/events?"));
        tls.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        tls.shutdown().await.unwrap();
    });
    let config_file = directory.path().join("config.json");
    std::fs::write(&config_file, json!({"client_cert":"client.pem","client_key":"client.key",
        "auth":{"issuer":"https://idp.invalid/issuer","introspection_url":"https://idp.invalid/introspect",
        "subjects":["owner"],"audience":"collector","hosted_client":"browser"},
        "sources":[{"node":server_name,"address":address.to_string(),"pin":server_pin}]}).to_string()).unwrap();
    let client = Client::new(&Config::load(&config_file).unwrap()).unwrap();
    let result = client.events(0, None, None, 0).await;
    tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    result
}
