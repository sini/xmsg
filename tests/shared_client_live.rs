use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use xmsg::client::{ClientOptions, ListQuery, RegisteredService, RegistrationExpectation};

struct Node(Child);
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn exercise(binary: &Path) {
    assert!(binary.is_file(), "required real-xmsg binary missing");
    let temp = tempfile::tempdir().unwrap();
    let run = temp.path().join("run");
    let sessions = temp.path().join("sessions");
    for dir in [&run, &sessions] {
        fs::create_dir(dir).unwrap();
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let options = ClientOptions {
        register_socket: run.join("register.sock"),
        agent_socket: run.join("agent.sock"),
        max_frame_bytes: 400_000,
        operation_timeout: Duration::from_secs(5),
    };
    let executable = std::env::current_exe().unwrap();
    let child = Command::new(binary)
        .env("HOME", temp.path())
        .env("XDG_RUNTIME_DIR", &run)
        .env_remove("XMSG_HOST_LABEL")
        .arg("serve")
        .arg("--db-path")
        .arg(temp.path().join("node.db"))
        .arg("--sessions-dir")
        .arg(sessions)
        .arg("--http-sock")
        .arg(run.join("http.sock"))
        .arg("--register-sock")
        .arg(&options.register_socket)
        .arg("--agent-sock")
        .arg(&options.agent_socket)
        .arg("--svc-exe")
        .arg(format!("bridge={}", executable.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut node = Node(child);
    let deadline = Instant::now() + Duration::from_secs(30);
    while !options.agent_socket.exists() || !options.register_socket.exists() {
        assert!(Instant::now() < deadline, "real-xmsg readiness deadline");
        assert!(
            node.0.try_wait().unwrap().is_none(),
            "real-xmsg exited during startup"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let expected = RegistrationExpectation {
        service: "bridge".into(),
        node: xmsg::node::local_node_name(),
        daemon_uid: unsafe { libc::geteuid() },
    };
    let mut client = RegisteredService::register(options, expected)
        .await
        .unwrap();
    let address = client.address().unwrap().to_owned();
    let listed = client.list(ListQuery::default()).await.unwrap();
    assert!(listed
        .recipients
        .iter()
        .any(|r| r.address == address && r.kind == "service"));
    let sent = client
        .send(&address, "bounded live body", Some("durable-key"))
        .await
        .unwrap();
    let repeat = client
        .send(&address, "bounded live body", Some("durable-key"))
        .await
        .unwrap();
    assert_eq!(sent.message_id, repeat.message_id);
    let delivery = client.poll(1).await.unwrap().unwrap();
    assert_eq!(delivery.message_id(), sent.message_id);
    assert_eq!(delivery.origin().service.as_deref(), Some("bridge"));
    assert_eq!(delivery.origin().node, client.node().unwrap());
    assert_eq!(delivery.text(), "bounded live body");
    client.ack(delivery.message_id()).await.unwrap();
    assert!(
        client.poll(0).await.unwrap().is_none(),
        "ACK must remove the service item"
    );
    let reply = client
        .reply(&sent.message_id, "live reply", Some("reply-key"))
        .await
        .unwrap();
    assert!(reply.pushed_message_id.is_some());
    let pushed = client.poll(1).await.unwrap().unwrap();
    assert_eq!(pushed.in_reply_to(), Some(sent.message_id.as_str()));
    assert_eq!(pushed.text(), "live reply");
    client.ack(pushed.message_id()).await.unwrap();
}

#[tokio::test]
#[ignore = "shared-client compat CI explicitly runs verified baseline and candidate binaries"]
async fn pinned_and_candidate_service_contract() {
    let baseline = PathBuf::from(
        std::env::var_os("XMSG_SHARED_BASELINE_BIN").expect("required baseline binary unset"),
    );
    let pin = include_str!("../ci/xmsg-pin.toml");
    let revision = pin.lines().find_map(|line| line.strip_prefix("revision = "))
        .expect("baseline revision missing").trim_matches('"');
    let version = Command::new(&baseline).arg("--version").output().expect("baseline executable missing");
    assert!(version.status.success());
    assert_eq!(String::from_utf8(version.stdout).unwrap().trim(), format!("xmsg 0.1.0+{revision}"), "baseline binary provenance mismatch");
    exercise(&baseline).await;
    exercise(Path::new(env!("CARGO_BIN_EXE_xmsg"))).await;
    println!("shared-client: verified baseline and candidate service contract completed");
}
