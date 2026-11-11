use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use xmsg::client::{ClientError, ClientOptions, ListQuery, RegisteredService};

struct Node(Child);
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn socket_listening(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

async fn wait_for_daemon_sockets(
    node: &mut Node,
    register_socket: &Path,
    agent_socket: &Path,
    label: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !socket_listening(agent_socket) || !socket_listening(register_socket) {
        assert!(Instant::now() < deadline, "{label}");
        assert!(
            node.0.try_wait().unwrap().is_none(),
            "real-xmsg exited during startup"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn bind_without_listen_race_control() {
    let temp = tempfile::tempdir().unwrap();
    let sock_path = temp.path().join("unlistening.sock");
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0, "socket() failed");

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = sock_path.as_os_str().as_bytes();
    assert!(bytes.len() < addr.sun_path.len());
    for (dst, &src) in addr.sun_path.iter_mut().zip(bytes.iter()) {
        *dst = src as libc::c_char;
    }
    let bind_rc = unsafe {
        libc::bind(
            fd,
            (&raw const addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    assert_eq!(bind_rc, 0, "bind() failed");

    // Forced-race control: after bind() and before listen(), .exists() is true while
    // UnixStream::connect fails with ConnectionRefused, so socket_listening() is false.
    assert!(
        sock_path.exists(),
        "bound AF_UNIX path must exist on disk before listen()"
    );
    let err = std::os::unix::net::UnixStream::connect(&sock_path)
        .expect_err("connect before listen() must fail");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused,
        "connect between bind() and listen() must produce ConnectionRefused, got {err:?}"
    );
    assert!(
        !socket_listening(&sock_path),
        "socket_listening must be false between bind() and listen()"
    );

    let waiter_path = sock_path.clone();
    let waiter = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket_listening(&waiter_path) {
            assert!(Instant::now() < deadline, "waiter timed out before listen()");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !waiter.is_finished(),
        "waiter must not complete before listen() is called"
    );

    let listen_rc = unsafe { libc::listen(fd, 8) };
    assert_eq!(listen_rc, 0, "listen() failed");
    waiter.await.unwrap();
    assert!(socket_listening(&sock_path));
    unsafe {
        libc::close(fd);
    }
}

async fn exercise(binary: &Path, expects_effective_limits: bool) {
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
        service: "bridge".into(),
        expected_node: Some(xmsg::node::local_node_name()),
        daemon_uid: xmsg::client::current_uid(),
    };
    let executable = std::env::current_exe().unwrap();
    let mut command = Command::new(binary);
    let child = command
        .env_clear()
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
    wait_for_daemon_sockets(
        &mut node,
        &options.register_socket,
        &options.agent_socket,
        "real-xmsg readiness deadline",
    )
    .await;
    let mut client = RegisteredService::register(options.clone()).await.unwrap();
    if expects_effective_limits {
        assert_eq!(client.reply_ttl_secs(), Some(604_800));
        assert_eq!(client.idempotency_ttl_secs(), Some(86_400));
        assert_eq!(client.svc_queue_cap(), Some(100));
        assert_eq!(client.max_body_bytes(), Some(65_536));
        let reg = client.registration().unwrap();
        assert_eq!(reg.reply_ttl_secs, Some(604_800));
        assert_eq!(reg.idempotency_ttl_secs, Some(86_400));
        assert_eq!(reg.svc_queue_cap, Some(100));
        assert_eq!(reg.max_body_bytes, Some(65_536));
    } else {
        assert_eq!(client.reply_ttl_secs(), None);
        assert_eq!(client.idempotency_ttl_secs(), None);
        assert_eq!(client.svc_queue_cap(), None);
        assert_eq!(client.max_body_bytes(), None);
        let reg = client.registration().unwrap();
        assert_eq!(reg.reply_ttl_secs, None);
        assert_eq!(reg.idempotency_ttl_secs, None);
        assert_eq!(reg.svc_queue_cap, None);
        assert_eq!(reg.max_body_bytes, None);
    }
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
    let snapshot = client.agent_client();
    client.health().unwrap();
    node.0.kill().unwrap();
    node.0.wait().unwrap();
    assert!(
        matches!(client.health(), Err(ClientError::Disconnected)),
        "real daemon EOF"
    );
    assert!(matches!(
        snapshot.send(&address, "old snapshot", None).await,
        Err(ClientError::Disconnected)
    ));
    for socket in [
        &options.register_socket,
        &options.agent_socket,
        &run.join("http.sock"),
    ] {
        if socket.exists() {
            fs::remove_file(socket).unwrap();
        }
    }
    node.0 = command.spawn().unwrap();
    wait_for_daemon_sockets(
        &mut node,
        &options.register_socket,
        &options.agent_socket,
        "restarted daemon readiness",
    )
    .await;
    let mut recovered = RegisteredService::register(options).await.unwrap();
    let sent = recovered
        .send(&address, "after restart", None)
        .await
        .unwrap();
    let delivered = recovered.poll(1).await.unwrap().unwrap();
    assert_eq!(delivered.message_id(), sent.message_id);
    assert_eq!(delivered.origin().service.as_deref(), Some("bridge"));
    recovered.ack(delivered.message_id()).await.unwrap();
}

#[tokio::test]
#[ignore = "shared-client compat CI explicitly runs verified baseline and candidate binaries"]
async fn pinned_and_candidate_service_contract() {
    if let Ok(live_svc) = std::env::var("XMSG_LIVE_SVC_CHILD") {
        let register_socket =
            PathBuf::from(std::env::var_os("XMSG_LIVE_REG_SOCK").expect("XMSG_LIVE_REG_SOCK"));
        let agent_socket =
            PathBuf::from(std::env::var_os("XMSG_LIVE_AGENT_SOCK").expect("XMSG_LIVE_AGENT_SOCK"));
        exercise_single_live_service(&live_svc, register_socket, agent_socket).await;
        return;
    }
    let baseline = PathBuf::from(
        std::env::var_os("XMSG_SHARED_BASELINE_BIN").expect("required baseline binary unset"),
    );
    let pin = include_str!("../ci/xmsg-pin.toml");
    let revision = pin
        .lines()
        .find_map(|line| line.strip_prefix("revision = "))
        .expect("baseline revision missing")
        .trim_matches('"');
    let version = Command::new(&baseline)
        .arg("--version")
        .output()
        .expect("baseline executable missing");
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        format!("xmsg 0.1.0+{revision}"),
        "baseline binary provenance mismatch"
    );
    exercise(&baseline, false).await;
    let candidate = Path::new(env!("CARGO_BIN_EXE_xmsg"));
    exercise(candidate, true).await;
    exercise_candidate_service_name_validation(candidate).await;
    exercise_candidate_effective_limits(candidate).await;
    println!("shared-client: verified baseline and candidate service contract completed");
}

async fn exercise_candidate_service_name_validation(binary: &Path) {
    assert!(binary.is_file(), "required candidate xmsg binary missing");
    let temp = tempfile::tempdir().unwrap();
    let run = temp.path().join("run");
    let sessions = temp.path().join("sessions");
    for dir in [&run, &sessions] {
        fs::create_dir(dir).unwrap();
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let long_name = "a".repeat(33);
    let refused_names = [
        "gateway/child",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/child",
        "550e8400-e29b-41d4-a716-446655440000",
        "550e8400-e29b-41d4-a716-446655440000~2",
        "xmsg",
        "worker.dot",
        "worker:colon",
        "worker~tilde",
        "worker·dot",
        "bad space",
        long_name.as_str(),
    ];
    let executable = std::env::current_exe().unwrap();
    let register_socket = run.join("register.sock");
    let agent_socket = run.join("agent.sock");
    let live_mesh_services = [
        "matrix-xmsg",
        "genie",
        "genie-guard",
        "genie-expert-trusted",
        "genie-expert-public",
        "gateway",
    ];
    let mut cmd = Command::new(binary);
    cmd.env_clear()
        .env("HOME", temp.path())
        .env("XDG_RUNTIME_DIR", &run)
        .env_remove("XMSG_HOST_LABEL")
        .arg("serve")
        .arg("--db-path")
        .arg(temp.path().join("node.db"))
        .arg("--sessions-dir")
        .arg(&sessions)
        .arg("--http-sock")
        .arg(run.join("http.sock"))
        .arg("--register-sock")
        .arg(&register_socket)
        .arg("--agent-sock")
        .arg(&agent_socket)
        .arg("--svc-exe")
        .arg(format!("gateway-child={}", executable.display()));
    for live_svc in live_mesh_services {
        cmd.arg("--svc-exe")
            .arg(format!("{live_svc}={}", executable.display()));
    }
    for bad in refused_names {
        cmd.arg("--svc-exe")
            .arg(format!("{bad}={}", executable.display()));
    }
    let child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut node = Node(child);
    wait_for_daemon_sockets(
        &mut node,
        &register_socket,
        &agent_socket,
        "real-xmsg readiness deadline",
    )
    .await;

    for bad in refused_names {
        assert!(
            xmsg::fed::check_origin(&xmsg::storage::Origin::service(bad, "test-node")).is_err(),
            "check_origin must refuse invalid service name {bad:?}"
        );
        let options = ClientOptions {
            register_socket: register_socket.clone(),
            agent_socket: agent_socket.clone(),
            max_frame_bytes: 400_000,
            operation_timeout: Duration::from_secs(5),
            service: bad.to_owned(),
            expected_node: Some(xmsg::node::local_node_name()),
            daemon_uid: xmsg::client::current_uid(),
        };
        let err = match RegisteredService::register(options).await {
            Ok(_) => panic!("register.sock must refuse invalid service name {bad:?}"),
            Err(err) => err,
        };
        assert!(
            matches!(
                &err,
                ClientError::Refused { code } if code == "bad_request"
            ),
            "invalid service name {bad:?} must be refused with bad_request, got: {err:?}"
        );
    }

    // Positive control for every service name live in the mesh today: each registers from its
    // own OS process (one process holds one svc identity), self-sends (exercising check_origin
    // on surface::deliver), and passes check_origin.
    for live_svc in live_mesh_services {
        assert!(
            xmsg::fed::check_origin(&xmsg::storage::Origin::service(live_svc, "test-node")).is_ok(),
            "live mesh service {live_svc:?} must pass check_origin"
        );
        let out = Command::new(&executable)
            .env("XMSG_LIVE_SVC_CHILD", live_svc)
            .env("XMSG_LIVE_REG_SOCK", &register_socket)
            .env("XMSG_LIVE_AGENT_SOCK", &agent_socket)
            .arg("pinned_and_candidate_service_contract")
            .arg("--exact")
            .arg("--ignored")
            .arg("--nocapture")
            .output()
            .expect("spawn per-service positive-control child");
        assert!(
            out.status.success(),
            "live mesh service {live_svc:?} child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // Positive control: a valid name registers in this process, lists, and self-sends.
    let valid_options = ClientOptions {
        register_socket: register_socket.clone(),
        agent_socket: agent_socket.clone(),
        max_frame_bytes: 400_000,
        operation_timeout: Duration::from_secs(5),
        service: "gateway-child".to_owned(),
        expected_node: Some(xmsg::node::local_node_name()),
        daemon_uid: xmsg::client::current_uid(),
    };
    let mut client = RegisteredService::register(valid_options.clone())
        .await
        .unwrap();
    let address = client.address().unwrap().to_owned();
    let listed = client.list(ListQuery::default()).await.unwrap();
    assert!(listed
        .recipients
        .iter()
        .any(|r| r.address == address && r.kind == "service"));

    // Producer invariant (XR4): a second, different service name from the same live process is
    // refused with `process_already_registered`, and the first registration's sends continue to
    // be stamped with the first service name.
    let second_name_opts = ClientOptions {
        register_socket: register_socket.clone(),
        agent_socket: agent_socket.clone(),
        max_frame_bytes: 400_000,
        operation_timeout: Duration::from_secs(5),
        service: "genie".to_owned(),
        expected_node: Some(xmsg::node::local_node_name()),
        daemon_uid: xmsg::client::current_uid(),
    };
    let dup_err = match RegisteredService::register(second_name_opts.clone()).await {
        Ok(_) => panic!("register.sock must refuse second service name from the same process"),
        Err(err) => err,
    };
    assert!(
        matches!(
            &dup_err,
            ClientError::Refused { code } if code == "process_already_registered"
        ),
        "second service name from same process must be refused with process_already_registered, got: {dup_err:?}"
    );

    let sent = client
        .send(&address, "positive control self-send", Some("xr4-key"))
        .await
        .unwrap();
    let delivery = client.poll(1).await.unwrap().unwrap();
    assert_eq!(delivery.message_id(), sent.message_id);
    assert_eq!(delivery.origin().service.as_deref(), Some("gateway-child"));
    assert_eq!(delivery.text(), "positive control self-send");
    client.ack(delivery.message_id()).await.unwrap();

    // Re-registering the SAME service name from the same process remains permitted:
    // connection 1 (`client`) registers `"gateway-child"`, connection 2 (`reregistered`)
    // re-registers `"gateway-child"`, connection 1 is closed and its server-side EOF runs,
    // and `"gateway-child"` remains registered while connection 2's sends remain stamped
    // with `"gateway-child"`.
    let mut reregistered = RegisteredService::register(valid_options).await.unwrap();
    drop(client);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let listed_after_eof = reregistered.list(ListQuery::default()).await.unwrap();
    assert!(
        listed_after_eof
            .recipients
            .iter()
            .any(|r| r.address == address && r.kind == "service"),
        "closing superseded connection 1 must not remove connection 2's registration for {address}"
    );
    let sent2 = reregistered
        .send(&address, "reregistered self-send", None)
        .await
        .unwrap();
    let delivery2 = reregistered.poll(1).await.unwrap().unwrap();
    assert_eq!(delivery2.message_id(), sent2.message_id);
    assert_eq!(delivery2.origin().service.as_deref(), Some("gateway-child"));
    reregistered.ack(delivery2.message_id()).await.unwrap();
}

async fn exercise_single_live_service(
    live_svc: &str,
    register_socket: PathBuf,
    agent_socket: PathBuf,
) {
    assert!(
        xmsg::fed::check_origin(&xmsg::storage::Origin::service(live_svc, "test-node")).is_ok(),
        "live mesh service {live_svc:?} must pass check_origin"
    );
    let live_opts = ClientOptions {
        register_socket,
        agent_socket,
        max_frame_bytes: 400_000,
        operation_timeout: Duration::from_secs(5),
        service: live_svc.to_owned(),
        expected_node: Some(xmsg::node::local_node_name()),
        daemon_uid: xmsg::client::current_uid(),
    };
    let mut client = RegisteredService::register(live_opts).await.unwrap();
    let address = client.address().unwrap().to_owned();
    let sent = client
        .send(&address, "mesh positive control", None)
        .await
        .unwrap();
    let delivery = client.poll(1).await.unwrap().unwrap();
    assert_eq!(delivery.message_id(), sent.message_id);
    assert_eq!(delivery.origin().service.as_deref(), Some(live_svc));
    client.ack(delivery.message_id()).await.unwrap();
}

async fn exercise_candidate_effective_limits(binary: &Path) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    #[derive(serde::Deserialize)]
    struct Pin4f4a4dfRegistration {
        status: String,
        address: String,
        node: String,
    }

    type CapMatrixCase<'a> = (
        &'a [(&'a str, &'a str)],
        &'a [&'a str],
        u64,
        u64,
        usize,
        usize,
    );
    let cases: &[CapMatrixCase<'_>] = &[
        // Positive control: defaults (reply_ttl=604800, idempotency_ttl=86400, svc_queue_cap=100, max_body_bytes=65536)
        (&[], &[], 604_800, 86_400, 100, 65_536),
        // Cell 1: non-default --reply-ttl vs default idempotency_ttl, svc_queue_cap & max_body_bytes
        (&[], &["--reply-ttl", "3600"], 3_600, 86_400, 100, 65_536),
        // Cell 2: non-default --idempotency-ttl (and env XMSG_IDEMPOTENCY_TTL) vs default reply_ttl, svc_queue_cap & max_body_bytes
        (
            &[("XMSG_IDEMPOTENCY_TTL", "7200")],
            &[],
            604_800,
            7_200,
            100,
            65_536,
        ),
        // Cell 3: non-default --svc-queue-cap vs default reply_ttl, idempotency_ttl & max_body_bytes
        (&[], &["--svc-queue-cap", "3"], 604_800, 86_400, 3, 65_536),
        // Cell 4: non-default --max-body 4096 vs default reply_ttl, idempotency_ttl & svc_queue_cap
        (&[], &["--max-body", "4096"], 604_800, 86_400, 100, 4_096),
        // Cell 5: all four non-default simultaneously
        (
            &[],
            &[
                "--reply-ttl",
                "1800",
                "--idempotency-ttl",
                "900",
                "--svc-queue-cap",
                "2",
                "--max-body",
                "4096",
            ],
            1_800,
            900,
            2,
            4_096,
        ),
    ];

    let executable = std::env::current_exe().unwrap();
    for &(envs, extra_args, exp_reply_ttl, exp_idem_ttl, exp_queue_cap, exp_max_body) in cases {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("run");
        let sessions = temp.path().join("sessions");
        for dir in [&run, &sessions] {
            fs::create_dir(dir).unwrap();
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let register_socket = run.join("register.sock");
        let agent_socket = run.join("agent.sock");
        let mut cmd = Command::new(binary);
        cmd.env_clear()
            .env("HOME", temp.path())
            .env("XDG_RUNTIME_DIR", &run)
            .env_remove("XMSG_HOST_LABEL");
        for &(k, v) in envs {
            cmd.env(k, v);
        }
        cmd.arg("serve")
            .arg("--db-path")
            .arg(temp.path().join("node.db"))
            .arg("--sessions-dir")
            .arg(&sessions)
            .arg("--http-sock")
            .arg(run.join("http.sock"))
            .arg("--register-sock")
            .arg(&register_socket)
            .arg("--agent-sock")
            .arg(&agent_socket)
            .arg("--svc-exe")
            .arg(format!("gateway={}", executable.display()))
            .args(extra_args);
        let child = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut node = Node(child);
        wait_for_daemon_sockets(
            &mut node,
            &register_socket,
            &agent_socket,
            "real-xmsg readiness deadline",
        )
        .await;

        // First: verify 4f4a4df's client shape (status, address, node only) decodes the
        // new daemon's registration frame and ignores the additive XR5 fields.
        {
            let mut raw_stream = UnixStream::connect(&register_socket).await.unwrap();
            raw_stream
                .write_all(b"{\"harness\":\"svc\",\"name\":\"gateway\",\"cwd\":\"/\"}\n")
                .await
                .unwrap();
            raw_stream.flush().await.unwrap();
            let mut reader = BufReader::new(&mut raw_stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let legacy: Pin4f4a4dfRegistration = serde_json::from_str(&line).unwrap();
            assert_eq!(legacy.status, "ok");
            assert_eq!(legacy.node, xmsg::node::local_node_name());
            assert_eq!(legacy.address, format!("gateway@{}", legacy.node));
        }

        // Second: register via the current xmsg::client::RegisteredService and assert
        // all four effective values match.
        let options = ClientOptions {
            register_socket: register_socket.clone(),
            agent_socket: agent_socket.clone(),
            max_frame_bytes: 400_000,
            operation_timeout: Duration::from_secs(5),
            service: "gateway".to_owned(),
            expected_node: Some(xmsg::node::local_node_name()),
            daemon_uid: xmsg::client::current_uid(),
        };
        let mut client = RegisteredService::register(options).await.unwrap();
        assert_eq!(client.reply_ttl_secs(), Some(exp_reply_ttl));
        assert_eq!(client.idempotency_ttl_secs(), Some(exp_idem_ttl));
        assert_eq!(client.svc_queue_cap(), Some(exp_queue_cap));
        assert_eq!(client.max_body_bytes(), Some(exp_max_body));
        let reg = client.registration().unwrap();
        assert_eq!(reg.reply_ttl_secs, Some(exp_reply_ttl));
        assert_eq!(reg.idempotency_ttl_secs, Some(exp_idem_ttl));
        assert_eq!(reg.svc_queue_cap, Some(exp_queue_cap));
        assert_eq!(reg.max_body_bytes, Some(exp_max_body));

        // When a non-default --max-body bound is in force, prove that a send at exactly
        // the reported bound is accepted and a send (and reply) at bound + 1 is refused
        // with the existing `payload_too_large` error.
        if exp_max_body == 4_096 {
            let address = client.address().unwrap().to_owned();
            let reported_bound = client.max_body_bytes().unwrap();
            assert_eq!(reported_bound, 4_096);
            let exact_body = "x".repeat(reported_bound);
            let exact_sent = client
                .send(&address, &exact_body, None)
                .await
                .expect("send at exact max_body_bytes bound must be accepted");
            assert_eq!(exact_sent.outcome, "queued");
            let delivered = client.poll(1).await.unwrap().unwrap();
            assert_eq!(delivered.message_id(), exact_sent.message_id);
            assert_eq!(delivered.text().len(), reported_bound);
            client.ack(delivered.message_id()).await.unwrap();

            let over_body = "x".repeat(reported_bound + 1);
            let send_err = client
                .send(&address, &over_body, None)
                .await
                .expect_err("send at max_body_bytes + 1 must be refused");
            assert!(
                matches!(
                    &send_err,
                    ClientError::Refused { code } if code == "payload_too_large"
                ),
                "expected payload_too_large at bound + 1 on send, got {send_err:?}"
            );
            let reply_err = client
                .reply(&exact_sent.message_id, &over_body, None)
                .await
                .expect_err("reply at max_body_bytes + 1 must be refused");
            assert!(
                matches!(
                    &reply_err,
                    ClientError::Refused { code } if code == "payload_too_large"
                ),
                "expected payload_too_large at bound + 1 on reply, got {reply_err:?}"
            );
        }

        // When a small non-default queue cap is in force, prove the daemon actually enforces
        // that effective queue cap on service deliveries.
        if exp_queue_cap <= 3 {
            let address = client.address().unwrap().to_owned();
            for i in 0..exp_queue_cap {
                let sent = client
                    .send(&address, &format!("cap-{i}"), None)
                    .await
                    .unwrap();
                assert_eq!(sent.outcome, "queued");
            }
            let overflow = client
                .send(&address, "cap-overflow", None)
                .await
                .expect_err("send beyond effective svc_queue_cap must be refused");
            assert!(
                matches!(
                    &overflow,
                    ClientError::Refused { code } if code == "service_unavailable"
                ),
                "expected service_unavailable when svc_queue_cap={exp_queue_cap} is reached, got {overflow:?}"
            );
            let first = client.poll(1).await.unwrap().unwrap();
            client.ack(first.message_id()).await.unwrap();
            let after_ack = client.send(&address, "cap-after-ack", None).await.unwrap();
            assert_eq!(after_ack.outcome, "queued");
        }
    }
}
