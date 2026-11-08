use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use xmsg::client::{
    validate_service_name, ClientError, ClientOptions, ListQuery, RegisteredService,
};

fn fixture() -> (TempDir, ClientOptions, UnixListener, UnixListener) {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let options = ClientOptions {
        register_socket: temp.path().join("register.sock"),
        agent_socket: temp.path().join("agent.sock"),
        max_frame_bytes: 4096,
        operation_timeout: Duration::from_secs(2),
        service: "bridge".into(),
        expected_node: Some("fixture".into()),
        daemon_uid: xmsg::client::current_uid(),
    };
    let register = UnixListener::bind(&options.register_socket).unwrap();
    let agent = UnixListener::bind(&options.agent_socket).unwrap();
    (temp, options, register, agent)
}

async fn request(stream: &mut BufReader<UnixStream>, response: Value) -> Value {
    let mut line = String::new();
    stream.read_line(&mut line).await.unwrap();
    let request: Value = serde_json::from_str(&line).unwrap();
    stream
        .get_mut()
        .write_all(format!("{response}\n").as_bytes())
        .await
        .unwrap();
    request
}

fn registration() -> Value {
    json!({"status":"ok","address":"bridge@fixture","node":"fixture"})
}

#[tokio::test]
async fn registration_health_preserves_pending_frames_and_detects_shutdown() {
    for close in [false, true] {
        for partial in [false, true] {
            let (_temp, options, register, _agent) = fixture();
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let (write_tx, write_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let mut stream = BufReader::new(register.accept().await.unwrap().0);
                request(&mut stream, registration()).await;
                write_rx.await.unwrap();
                let frame = format!(
                    "{}\n",
                    delivery(json!({"service":"sender","node":"fixture"}))
                );
                let split = if partial {
                    frame.len() / 2
                } else {
                    frame.len()
                };
                stream
                    .get_mut()
                    .write_all(&frame.as_bytes()[..split])
                    .await
                    .unwrap();
                if close {
                    stream.get_mut().shutdown().await.unwrap();
                }
                ready_tx.send(()).unwrap();
                release_rx.await.unwrap();
                if !close && partial {
                    stream
                        .get_mut()
                        .write_all(&frame.as_bytes()[split..])
                        .await
                        .unwrap();
                }
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                assert_eq!(
                    serde_json::from_str::<Value>(&line).unwrap()["action"],
                    "poll"
                );
            });
            let mut client = RegisteredService::register(options).await.unwrap();
            let snapshot = client.agent_client();
            write_tx.send(()).unwrap();
            ready_rx.await.unwrap();
            for _ in 0..3 {
                assert_eq!(
                    snapshot.health().is_ok(),
                    !close,
                    "pending-data shutdown detection"
                );
                assert_eq!(client.health().is_ok(), !close);
            }
            release_tx.send(()).unwrap();
            if close && partial {
                assert!(matches!(client.poll(0).await, Err(ClientError::Protocol)));
            } else {
                let frame = client.poll(0).await.unwrap().unwrap();
                assert_eq!(frame.message_id(), "msg", "health must preserve the frame");
                assert_eq!(frame.text(), "body");
            }
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn registration_health_is_idle_and_snapshots_die_with_owner() {
    let (_temp, options, register, _agent) = fixture();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut stream = BufReader::new(register.accept().await.unwrap().0);
        request(&mut stream, registration()).await;
        ready_tx.send(()).unwrap();
        let mut extra = String::new();
        assert_eq!(
            stream.read_line(&mut extra).await.unwrap(),
            0,
            "health emits no frame"
        );
    });
    let client = RegisteredService::register(options).await.unwrap();
    let snapshot = client.agent_client();
    ready_rx.await.unwrap();
    for _ in 0..100 {
        client.health().unwrap();
        snapshot.health().unwrap();
    }
    drop(client);
    assert!(matches!(snapshot.health(), Err(ClientError::Disconnected)));
    server.await.unwrap();
}

#[tokio::test]
async fn registration_health_detects_idle_eof_and_half_close() {
    for half_close in [false, true] {
        let (_temp, options, register, _agent) = fixture();
        let (close_tx, close_rx) = tokio::sync::oneshot::channel();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut stream = BufReader::new(register.accept().await.unwrap().0);
            request(&mut stream, registration()).await;
            close_rx.await.unwrap();
            if half_close {
                stream.get_mut().shutdown().await.unwrap();
                closed_tx.send(Some(stream)).unwrap();
            } else {
                drop(stream);
                closed_tx.send(None).unwrap();
            }
        });
        let client = RegisteredService::register(options).await.unwrap();
        let snapshot = client.agent_client();
        client.health().unwrap();
        snapshot.health().unwrap();
        close_tx.send(()).unwrap();
        let _held_half = closed_rx.await.unwrap();
        assert!(
            matches!(client.health(), Err(ClientError::Disconnected)),
            "idle EOF invalidates registration"
        );
        assert!(matches!(snapshot.health(), Err(ClientError::Disconnected)));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn registration_health_distinguishes_refusal_from_disconnect_after_request() {
    for close in [false, true] {
        for accepted in [false, true] {
            let (_temp, options, register, agent) = fixture();
            let (registration_tx, registration_rx) = tokio::sync::oneshot::channel();
            let registrar = tokio::spawn(async move {
                let mut stream = BufReader::new(register.accept().await.unwrap().0);
                request(&mut stream, registration()).await;
                registration_tx.send(stream).unwrap();
            });
            let server = tokio::spawn(async move {
                let mut registration = registration_rx.await.unwrap();
                let mut stream = BufReader::new(agent.accept().await.unwrap().0);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                assert_eq!(
                    serde_json::from_str::<Value>(&line).unwrap()["action"],
                    "send"
                );
                if close {
                    registration.get_mut().shutdown().await.unwrap();
                }
                let response = if accepted {
                    json!({"status":"ok","message_id":"accepted","address":"target@fixture","outcome":"pending"})
                } else {
                    json!({"status":"error","error":"denied"})
                };
                stream
                    .get_mut()
                    .write_all(format!("{response}\n").as_bytes())
                    .await
                    .unwrap();
                let mut eof = String::new();
                stream.read_line(&mut eof).await.unwrap();
                registration
            });
            let client = RegisteredService::register(options).await.unwrap();
            let result = client.send("target@fixture", "body", None).await;
            if accepted {
                assert_eq!(
                    result.unwrap().message_id,
                    "accepted",
                    "accepted receipt survives EOF"
                );
            } else if close {
                assert!(
                    matches!(result, Err(ClientError::Disconnected)),
                    "causal EOF is not denial"
                );
            } else {
                assert!(matches!(result, Err(ClientError::Refused { code }) if code == "denied"));
            }
            drop(server.await.unwrap());
            registrar.await.unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_health_can_race_a_split_response_reader() {
    let (_temp, options, register, _agent) = fixture();
    let (split_tx, split_rx) = tokio::sync::oneshot::channel();
    let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut stream = BufReader::new(register.accept().await.unwrap().0);
        request(&mut stream, registration()).await;
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        let frame = format!(
            "{}\n",
            delivery(json!({"service":"sender","node":"fixture"}))
        );
        let split = frame.len() / 2;
        stream
            .get_mut()
            .write_all(&frame.as_bytes()[..split])
            .await
            .unwrap();
        split_tx.send(()).unwrap();
        finish_rx.await.unwrap();
        stream
            .get_mut()
            .write_all(&frame.as_bytes()[split..])
            .await
            .unwrap();
        release_rx.await.unwrap();
    });
    let mut client = RegisteredService::register(options).await.unwrap();
    let snapshot = client.agent_client();
    let reader = tokio::spawn(async move {
        let delivered = client.poll(0).await.unwrap().unwrap();
        assert_eq!(delivered.message_id(), "msg");
        assert_eq!(delivered.text(), "body");
        client
    });
    split_rx.await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    let probe_snapshot = snapshot.clone();
    let probe = tokio::time::timeout(
        Duration::from_millis(500),
        tokio::task::spawn_blocking(move || {
            for _ in 0..100 {
                probe_snapshot.health().unwrap();
            }
        }),
    )
    .await;
    if probe.is_err() {
        reader.abort();
        server.abort();
        let _ = reader.await;
        let _ = server.await;
        panic!("health lock held across I/O");
    }
    probe.unwrap().unwrap();
    finish_tx.send(()).unwrap();
    let client = reader.await.unwrap();
    snapshot.health().unwrap();
    drop(client);
    assert!(matches!(snapshot.health(), Err(ClientError::Disconnected)));
    release_tx.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn registration_health_probe_io_error_does_not_mask_agent_error() {
    let (_temp, options, register, agent) = fixture();
    let (write_probe_tx, write_probe_rx) = tokio::sync::oneshot::channel();
    let (reg_ready_tx, reg_ready_rx) = tokio::sync::oneshot::channel();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let registrar = tokio::spawn(async move {
        let mut stream = BufReader::new(register.accept().await.unwrap().0);
        request(&mut stream, registration()).await;
        write_probe_rx.await.unwrap();
        stream.get_mut().write_all(b"XF8PROBE").await.unwrap();
        reg_ready_tx.send(()).unwrap();
        done_rx.await.unwrap();
    });
    let client = RegisteredService::register(options).await.unwrap();
    write_probe_tx.send(()).unwrap();
    reg_ready_rx.await.unwrap();

    let reg_fd = (3..512)
        .find(|&fd| {
            let mut buf = [0_u8; 8];
            let n = unsafe {
                libc::recv(
                    fd,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    libc::MSG_PEEK | libc::MSG_DONTWAIT,
                )
            };
            n == 8 && &buf == b"XF8PROBE"
        })
        .expect("locate client registration socket fd via MSG_PEEK");

    let mut pipe_fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
    let saved_fd = unsafe { libc::dup(reg_fd) };
    assert!(saved_fd >= 0);

    let server = tokio::spawn(async move {
        let mut stream = BufReader::new(agent.accept().await.unwrap().0);
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        // After pre-flight health() succeeded, swap reg_fd onto the pipe write end so the
        // post-failure health() probe returns Err(ClientError::Io(_)) instead of Ok or Disconnected.
        assert_eq!(unsafe { libc::dup2(pipe_fds[1], reg_fd) }, reg_fd);
        stream
            .get_mut()
            .write_all(b"{\"status\":\"error\",\"error\":\"denied\"}\n")
            .await
            .unwrap();
    });

    let result = client.send("target@fixture", "body", None).await;
    assert_eq!(unsafe { libc::dup2(saved_fd, reg_fd) }, reg_fd);
    unsafe {
        libc::close(saved_fd);
        libc::close(pipe_fds[0]);
        libc::close(pipe_fds[1]);
    }
    assert!(
        matches!(result, Err(ClientError::Refused { ref code }) if code == "denied"),
        "post-failure health I/O error must not mask original agent error, got: {result:?}"
    );
    server.await.unwrap();
    done_tx.send(()).unwrap();
    registrar.await.unwrap();
}

#[tokio::test]
async fn registration_health_rechecks_after_an_agent_timeout() {
    for close in [false, true] {
        let (_temp, mut options, register, agent) = fixture();
        options.operation_timeout = Duration::from_millis(100);
        let (registration_tx, registration_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let registrar = tokio::spawn(async move {
            let mut stream = BufReader::new(register.accept().await.unwrap().0);
            request(&mut stream, registration()).await;
            registration_tx.send(stream).unwrap();
        });
        let server = tokio::spawn(async move {
            let mut registration = registration_rx.await.unwrap();
            let mut stream = BufReader::new(agent.accept().await.unwrap().0);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            if close {
                registration.get_mut().shutdown().await.unwrap();
            }
            release_rx.await.unwrap();
            (registration, stream)
        });
        let client = RegisteredService::register(options).await.unwrap();
        let result = client.send("target@fixture", "body", None).await;
        if close {
            assert!(
                matches!(result, Err(ClientError::Disconnected)),
                "timeout after registration EOF is disconnected"
            );
        } else {
            assert!(matches!(result, Err(ClientError::Timeout)));
        }
        release_tx.send(()).unwrap();
        drop(server.await.unwrap());
        registrar.await.unwrap();
    }
}
fn delivery(origin: Value) -> Value {
    let missing = origin == json!("missing");
    let mut value = json!({"action":"deliver","messageId":"msg","fromName":"display · sender@fixture","text":"body","envelope":"rendered","origin":origin,"inReplyTo":"parent"});
    if missing {
        value.as_object_mut().unwrap().remove("origin");
    }
    value
}

#[tokio::test]
async fn socket_specific_exact_frame_keys() {
    let (_temp, options, register, agent) = fixture();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let svc = tokio::spawn(async move {
        let mut stream = BufReader::new(register.accept().await.unwrap().0);
        let registration = request(&mut stream, registration()).await;
        let poll = request(
            &mut stream,
            delivery(json!({"service":"sender","node":"fixture"})),
        )
        .await;
        let ack = request(&mut stream, json!({"status":"ok"})).await;
        release_rx.await.unwrap();
        (registration, poll, ack)
    });
    let calls = tokio::spawn(async move {
        let mut frames = vec![];
        for response in [
            json!({"status":"ok","message_id":"sent","address":"receiver@fixture","outcome":"pending"}),
            json!({"status":"ok","reply":{"seq":1,"messageId":"msg","createdAt":1,"replierSessionId":"bridge","text":"reply","pushOutcome":"queued","pushedMessageId":"reply-id"}}),
            json!({"status":"ok","recipients":[],"nodes":[]}),
        ] {
            let mut stream = BufReader::new(agent.accept().await.unwrap().0);
            frames.push(request(&mut stream, response).await);
        }
        frames
    });
    let mut client = RegisteredService::register(options).await.unwrap();
    let delivered = client.poll(0).await.unwrap().unwrap();
    assert_eq!(delivered.message_id(), "msg");
    assert_eq!(delivered.from_name(), "display · sender@fixture");
    assert_eq!(delivered.origin().service.as_deref(), Some("sender"));
    assert_eq!(delivered.in_reply_to(), Some("parent"));
    client.ack("msg").await.unwrap();
    assert_eq!(
        client
            .send("receiver@fixture", "send", Some("key"))
            .await
            .unwrap()
            .outcome,
        "pending"
    );
    assert_eq!(
        client
            .reply("msg", "reply", Some("reply-key"))
            .await
            .unwrap()
            .pushed_message_id
            .as_deref(),
        Some("reply-id")
    );
    assert!(client
        .list(ListQuery::default())
        .await
        .unwrap()
        .recipients
        .is_empty());
    release_tx.send(()).unwrap();
    let (reg, poll, ack) = svc.await.unwrap();
    assert_eq!(reg, json!({"harness":"svc","name":"bridge","cwd":"/"}));
    assert_eq!(poll, json!({"action":"poll","waitSecs":0}));
    assert_eq!(ack, json!({"action":"ack","messageId":"msg"}));
    let frames = calls.await.unwrap();
    assert_eq!(
        frames[0],
        json!({"action":"send","schema_version":2,"to":"receiver@fixture","text":"send","idempotency_key":"key"})
    );
    assert_eq!(
        frames[1],
        json!({"action":"reply","schema_version":2,"message_id":"msg","text":"reply","idempotency_key":"reply-key"})
    );
    assert_eq!(frames[2], json!({"action":"list","schema_version":2}));
}

#[tokio::test]
async fn missing_or_wrong_registration_identity_is_refused() {
    for response in [
        json!({"status":"ok","node":"fixture"}),
        json!({"status":"ok","node":"foreign","address":"bridge@foreign"}),
        json!({"status":"ok","node":"fixture","address":"impostor@fixture"}),
    ] {
        let (_temp, options, register, _agent) = fixture();
        let server = tokio::spawn(async move {
            request(
                &mut BufReader::new(register.accept().await.unwrap().0),
                response,
            )
            .await;
        });
        assert!(RegisteredService::register(options).await.is_err());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn registration_deadline_is_a_client_error() {
    let (_temp, mut options, register, _agent) = fixture();
    options.operation_timeout = Duration::from_millis(20);
    let server = tokio::spawn(async move {
        let _stream = register.accept().await.unwrap().0;
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let result = tokio::time::timeout(
        Duration::from_millis(250),
        RegisteredService::register(options),
    )
    .await;
    assert!(matches!(result, Ok(Err(ClientError::Timeout))));
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn oversized_and_unterminated_frames_are_refused() {
    for response in [
        vec![b' '; 4097],
        b"{\"status\":\"ok\"}".to_vec(),
        vec![0xff, b'\n'],
    ] {
        let (_temp, options, register, _agent) = fixture();
        let server = tokio::spawn(async move {
            let mut stream = BufReader::new(register.accept().await.unwrap().0);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            stream.get_mut().write_all(&response).await.unwrap();
            if response.len() > 4096 {
                std::future::pending::<()>().await;
            }
        });
        assert!(matches!(
            RegisteredService::register(options).await,
            Err(ClientError::Protocol)
        ));
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn delivery_requires_origin_and_preserves_all_origin_kinds() {
    for origin in [
        json!({"node":"fixture","id":"instance"}),
        json!({"node":"fixture","service":"svc"}),
        json!({"node":"fixture","label":"unattested"}),
        Value::Null,
        json!("missing"),
        json!({"node":""}),
        json!({"node":"fixture","id":"one","service":"two"}),
    ] {
        let valid = origin.get("node").and_then(Value::as_str) == Some("fixture")
            && !(origin.get("id").is_some() && origin.get("service").is_some());
        let (_temp, options, register, _agent) = fixture();
        let server = tokio::spawn(async move {
            let mut stream = BufReader::new(register.accept().await.unwrap().0);
            request(&mut stream, registration()).await;
            request(&mut stream, delivery(origin)).await;
        });
        let mut client = RegisteredService::register(options).await.unwrap();
        assert_eq!(client.poll(0).await.is_ok(), valid);
        if !valid {
            assert!(client.node().is_none());
        }
        server.await.unwrap();
    }
}

#[tokio::test]
async fn timeout_or_cancellation_discards_registration() {
    let (_temp, options, register, _agent) = fixture();
    let server = tokio::spawn(async move {
        let mut stream = BufReader::new(register.accept().await.unwrap().0);
        request(&mut stream, registration()).await;
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let mut client = RegisteredService::register(options).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.poll(0))
            .await
            .is_err()
    );
    assert!(client.address().is_none());
    assert!(client.node().is_none());
    assert!(matches!(
        client.ack("msg").await,
        Err(ClientError::Disconnected)
    ));
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn wrong_uid_and_public_directory_are_refused() {
    let (temp, mut options, _register, _agent) = fixture();
    options.daemon_uid = options.daemon_uid.wrapping_add(1);
    assert!(matches!(
        RegisteredService::register(options.clone()).await,
        Err(ClientError::Peer)
    ));
    options.daemon_uid = xmsg::client::current_uid();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        RegisteredService::register(options).await,
        Err(ClientError::Peer)
    ));
}

#[tokio::test]
async fn long_poll_does_not_block_agent_and_handle_expires_with_registration() {
    let (_temp, options, register, agent_listener) = fixture();
    let (polled_tx, polled_rx) = tokio::sync::oneshot::channel();
    let (sent_tx, sent_rx) = tokio::sync::oneshot::channel();
    let service = tokio::spawn(async move {
        let mut stream = BufReader::new(register.accept().await.unwrap().0);
        request(&mut stream, registration()).await;
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        polled_tx.send(()).unwrap();
        sent_rx.await.unwrap();
        stream
            .get_mut()
            .write_all(b"{\"action\":\"timeout\"}\n")
            .await
            .unwrap();
    });
    let sender = tokio::spawn(async move {
        let mut stream = BufReader::new(agent_listener.accept().await.unwrap().0);
        request(&mut stream, json!({"status":"ok","message_id":"sent","address":"receiver@fixture","outcome":"queued"})).await;
        sent_tx.send(()).unwrap();
    });
    let mut client = RegisteredService::register(options).await.unwrap();
    let agent = client.agent_client();
    let (poll, sent) = tokio::join!(client.poll(1), async {
        polled_rx.await.unwrap();
        agent.send("receiver@fixture", "body", Some("key")).await
    });
    assert!(poll.unwrap().is_none());
    assert_eq!(sent.unwrap().message_id, "sent");
    drop(client);
    assert!(matches!(
        agent.send("receiver@fixture", "body", Some("key")).await,
        Err(ClientError::Disconnected)
    ));
    service.await.unwrap();
    sender.await.unwrap();
}

#[tokio::test]
async fn agent_deadline_is_unknown_not_a_confirmed_refusal() {
    let (_temp, mut options, register, agent_listener) = fixture();
    options.operation_timeout = Duration::from_secs(1);
    let registration_server = tokio::spawn(async move {
        let mut stream = BufReader::new(register.accept().await.unwrap().0);
        request(&mut stream, registration()).await;
        std::future::pending::<()>().await;
    });
    let stalled = tokio::spawn(async move {
        let _stream = agent_listener.accept().await.unwrap().0;
        std::future::pending::<()>().await;
    });
    let client = RegisteredService::register(options).await.unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        client.send("target@fixture", "body", Some("key")),
    )
    .await;
    assert!(matches!(result, Ok(Err(ClientError::Timeout))));
    stalled.abort();
    registration_server.abort();
    let _ = stalled.await;
    let _ = registration_server.await;
}

#[tokio::test]
async fn registration_identity_modes() {
    for pin in [None, Some("fixture")] {
        for (node, wrong_uid, accepted) in [
            ("fixture", false, true),
            ("reported", false, pin.is_none()),
            ("", false, false),
            ("fixture", true, false),
        ] {
            let (_temp, mut options, register, _agent) = fixture();
            options.expected_node = pin.map(str::to_owned);
            if wrong_uid {
                options.daemon_uid = options.daemon_uid.wrapping_add(1);
            }
            let response = json!({"status":"ok","node":node,"address":format!("bridge@{node}")});
            let server = tokio::spawn(async move {
                request(
                    &mut BufReader::new(register.accept().await.unwrap().0),
                    response,
                )
                .await;
            });
            let result = RegisteredService::register(options).await;
            if accepted {
                let client = result.unwrap();
                assert_eq!(client.node(), Some(node));
                assert_eq!(client.address(), Some(format!("bridge@{node}").as_str()));
            } else {
                assert!(matches!(result, Err(ClientError::Peer)));
            }
            server.abort();
            let _ = server.await;
        }
    }
}

#[tokio::test]
async fn service_deadlines_expire_and_drop_registration() {
    for (ack, wait_secs) in [(false, 0), (false, 1), (true, 0)] {
        let (_temp, mut options, register, _agent) = fixture();
        options.operation_timeout = Duration::from_secs(1);
        let server = tokio::spawn(async move {
            let mut stream = BufReader::new(register.accept().await.unwrap().0);
            request(&mut stream, registration()).await;
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            std::future::pending::<()>().await;
        });
        let mut client = RegisteredService::register(options).await.unwrap();
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(wait_secs + 4), async {
            if ack {
                client.ack("message").await
            } else {
                client.poll(wait_secs).await.map(|_| ())
            }
        })
        .await;
        assert!(matches!(result, Ok(Err(ClientError::Timeout))));
        assert!(started.elapsed() >= Duration::from_secs(wait_secs));
        assert!(client.address().is_none());
        assert!(client.node().is_none());
        server.abort();
        let _ = server.await;
    }
}

#[test]
fn exported_service_name_validator_matches_mesh_and_refusals() {
    for live in [
        "matrix-xmsg",
        "genie",
        "genie-guard",
        "genie-expert-trusted",
        "genie-expert-public",
        "gateway",
        "bridge",
        &"a".repeat(32),
    ] {
        assert!(
            validate_service_name(live).is_ok(),
            "live/valid service {live:?} must pass validate_service_name"
        );
    }
    for bad in [
        "",
        "xmsg",
        "gateway/child",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/child",
        "550e8400-e29b-41d4-a716-446655440000",
        "550e8400-e29b-41d4-a716-446655440000~2",
        "worker@host",
        "worker·daemon",
        "worker~2",
        "worker.daemon",
        "svc:worker",
        "bad space",
        "bad\nnewline",
        &"a".repeat(33),
    ] {
        assert!(
            validate_service_name(bad).is_err(),
            "invalid service {bad:?} must be refused by validate_service_name"
        );
    }
}

#[tokio::test]
async fn registration_exposes_effective_limits_and_absent_baseline_fields() {
    // 1. Pre-XR5 baseline daemon response (fields absent -> None)
    {
        let (_temp, options, register, _agent) = fixture();
        let server = tokio::spawn(async move {
            let mut stream = BufReader::new(register.accept().await.unwrap().0);
            request(&mut stream, registration()).await;
            std::future::pending::<()>().await;
        });
        let client = RegisteredService::register(options).await.unwrap();
        assert_eq!(client.reply_ttl_secs(), None);
        assert_eq!(client.idempotency_ttl_secs(), None);
        assert_eq!(client.svc_queue_cap(), None);
        assert_eq!(client.max_body_bytes(), None);
        let reg = client.registration().unwrap();
        assert_eq!(reg.reply_ttl_secs, None);
        assert_eq!(reg.idempotency_ttl_secs, None);
        assert_eq!(reg.svc_queue_cap, None);
        assert_eq!(reg.max_body_bytes, None);
        server.abort();
        let _ = server.await;
    }

    // 2. Older XR5 daemon response that omits max_body_bytes (max_body_bytes -> None)
    {
        let (_temp, options, register, _agent) = fixture();
        let server = tokio::spawn(async move {
            let mut stream = BufReader::new(register.accept().await.unwrap().0);
            request(
                &mut stream,
                json!({
                    "status": "ok",
                    "address": "bridge@fixture",
                    "node": "fixture",
                    "reply_ttl_secs": 3600,
                    "idempotency_ttl_secs": 1800,
                    "svc_queue_cap": 42
                }),
            )
            .await;
            std::future::pending::<()>().await;
        });
        let client = RegisteredService::register(options).await.unwrap();
        assert_eq!(client.reply_ttl_secs(), Some(3600));
        assert_eq!(client.idempotency_ttl_secs(), Some(1800));
        assert_eq!(client.svc_queue_cap(), Some(42));
        assert_eq!(client.max_body_bytes(), None);
        let reg = client.registration().unwrap();
        assert_eq!(reg.reply_ttl_secs, Some(3600));
        assert_eq!(reg.idempotency_ttl_secs, Some(1800));
        assert_eq!(reg.svc_queue_cap, Some(42));
        assert_eq!(reg.max_body_bytes, None);
        server.abort();
        let _ = server.await;
    }

    // 3. Current daemon response (all four effective limits populated -> Some(...))
    {
        let (_temp, options, register, _agent) = fixture();
        let server = tokio::spawn(async move {
            let mut stream = BufReader::new(register.accept().await.unwrap().0);
            request(
                &mut stream,
                json!({
                    "status": "ok",
                    "address": "bridge@fixture",
                    "node": "fixture",
                    "reply_ttl_secs": 3600,
                    "idempotency_ttl_secs": 1800,
                    "svc_queue_cap": 42,
                    "max_body_bytes": 4096
                }),
            )
            .await;
            std::future::pending::<()>().await;
        });
        let client = RegisteredService::register(options).await.unwrap();
        assert_eq!(client.reply_ttl_secs(), Some(3600));
        assert_eq!(client.idempotency_ttl_secs(), Some(1800));
        assert_eq!(client.svc_queue_cap(), Some(42));
        assert_eq!(client.max_body_bytes(), Some(4096));
        let reg = client.registration().unwrap();
        assert_eq!(reg.reply_ttl_secs, Some(3600));
        assert_eq!(reg.idempotency_ttl_secs, Some(1800));
        assert_eq!(reg.svc_queue_cap, Some(42));
        assert_eq!(reg.max_body_bytes, Some(4096));
        server.abort();
        let _ = server.await;
    }
}
