//! XB2 gate: input validation across all six XA4 findings (F1–F6).
//!
//! Rule: validate where a value enters and re-check at the use site, using the shared
//! helpers (`is_uuid_shaped`, `check_origin`, `validate_subagent_id`,
//! `validate_session_file_entry`, `validate_messaging_socket_path`,
//! `read_initial_register_line`).

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::broadcast;

use xmsg::agy::{AgyConfig, AgyCredentials, AgySessionInfo};
use xmsg::fed::{
    generate_self_signed_ed25519, normalize_pin, run_fed_listener, run_outbound_peer_pull_loop,
    FedInboxMessage, FedState, PeersMap, RateLimiter,
};
use xmsg::handoff::Transfer;
use xmsg::http::{AppState, ResolvedTarget};
use xmsg::registry::{Session, SessionFileEntry};
use xmsg::storage::{self, MessageRecord, Origin, PeerMailboxMessage, QueuedMessage};

const VALID_UUID_1: &str = "0199cecf-0001-7000-8000-000000000001";
const VALID_UUID_2: &str = "0199cecf-0002-7000-8000-000000000002";

fn make_test_state(tmp: &std::path::Path) -> Arc<AppState> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));
    let (notify_tx, _) = broadcast::channel(16);
    let (pi_tx, _) = broadcast::channel(16);
    let (svc_tx, _) = broadcast::channel(16);
    let proc_root = tmp.join("proc");
    let presence_dir = tmp.join("presence");
    let brain_dir = tmp.join("brain");
    fs::create_dir_all(&proc_root).unwrap();
    let my_pid = std::process::id();
    let pid_dir = proc_root.join(my_pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();
    // Populate a synthetic Linux-style `<proc_root>/<pid>/stat` on every platform
    // (`src/process.rs:3-4`: synthetic `proc_root != LIVE_PROC_ROOT` is always read as a
    // Linux-style procfs tree, including on macOS where `/proc` does not exist).
    let my_proc_start =
        xmsg::process::starttime(std::path::Path::new(xmsg::process::LIVE_PROC_ROOT), my_pid)
            .unwrap_or_else(|_| "100".to_string());
    let stat_content =
        format!("{my_pid} (xmsg) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {my_proc_start} 0 0\n");
    fs::write(pid_dir.join("stat"), stat_content).unwrap();
    fs::create_dir_all(&presence_dir).unwrap();
    fs::create_dir_all(&brain_dir).unwrap();

    Arc::new(AppState {
        sessions_dirs: vec![tmp.join("sessions")],
        agy_config: AgyConfig {
            presence_dir,
            brain_dir,
            proc_locks_path: tmp.join("locks"),
            proc_root,
            agy_bin: "agy".to_string(),
            trusted_agy_exes: Vec::new(),
        },
        agy_store: Arc::new(RwLock::new(HashMap::new())),
        pi_store: Arc::new(RwLock::new(HashMap::new())),
        pi_notify_tx: pi_tx,
        svc_store: Arc::new(RwLock::new(HashMap::new())),
        svc_notify_tx: svc_tx,
        node_name: "sini.leaf".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(0),
        db,
        notify_tx,
        reply_ttl: Duration::from_secs(60),
        idempotency_ttl: Duration::from_secs(60),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(16)),
        fed_state: None,
    })
}

/// F1: `is_uuid_shaped` on `conversation_id` for every `register.sock` action, including
/// `check`, before any path join or store insert.
#[tokio::test]
async fn f1_register_sock_conversation_id_requires_uuid() {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let sock_path = tmp.path().join("register.sock");
    let state = make_test_state(tmp.path());

    // Even if a file exists at `tmp/traversal.pb` outside `presence/`, a `../traversal`
    // conversation_id must be refused before any path join.
    fs::write(tmp.path().join("traversal.pb"), b"secret").unwrap();
    assert!(
        !xmsg::agy::is_conversation_proc_watched(&state.agy_config, "../traversal"),
        "non-UUID conversation_id must be refused before joining .pb path"
    );

    let creds = AgyCredentials {
        ls_address: "127.0.0.1:1".to_string(),
        csrf_token: "tok".to_string(),
        is_stale: false,
    };
    state.agy_store.write().unwrap().insert(
        VALID_UUID_1.to_string(),
        AgySessionInfo::new_with_credentials(
            VALID_UUID_1.to_string(),
            std::process::id(),
            "100".to_string(),
            creds.clone(),
        ),
    );
    // Poison entry with non-UUID key to prove `run_register_server` check action refuses it
    // before consulting `store`.
    state.agy_store.write().unwrap().insert(
        "../traversal".to_string(),
        AgySessionInfo::new_with_credentials(
            "../traversal".to_string(),
            std::process::id(),
            "100".to_string(),
            creds,
        ),
    );

    let srv_sock = sock_path.clone();
    let srv_state = state.clone();
    let my_uid = unsafe { libc::geteuid() };
    let srv_handle = tokio::spawn(async move {
        let _ = xmsg::agy::run_register_server(srv_sock, srv_state, my_uid, HashMap::new()).await;
    });

    for _ in 0..50 {
        if std::os::unix::net::UnixStream::connect(&sock_path).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // 1. Valid UUID on `check` action passes.
    {
        let mut s = UnixStream::connect(&sock_path).await.unwrap();
        let req = serde_json::json!({
            "action": "check",
            "conversation_id": VALID_UUID_1,
        });
        s.write_all(format!("{req}\n").as_bytes()).await.unwrap();
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).await.unwrap();
        let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(resp["status"], "ok", "valid UUID check should pass: {resp}");
    }

    // 2. Malformed `conversation_id` on `check` action is refused with error.
    {
        let mut s = UnixStream::connect(&sock_path).await.unwrap();
        let req = serde_json::json!({
            "action": "check",
            "conversation_id": "../traversal",
        });
        s.write_all(format!("{req}\n").as_bytes()).await.unwrap();
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).await.unwrap();
        let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(
            resp["status"], "error",
            "malformed conversation_id on check must be refused: {resp}"
        );
    }

    // 3. Malformed `conversation_id` on registration request is refused before path join / store.
    {
        let mut s = UnixStream::connect(&sock_path).await.unwrap();
        let req = serde_json::json!({
            "conversation_id": "../traversal",
            "ls_address": "127.0.0.1:1234",
            "csrf_token": "tok",
        });
        s.write_all(format!("{req}\n").as_bytes()).await.unwrap();
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).await.unwrap();
        let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(
            resp["status"], "error",
            "malformed conversation_id on register must be refused: {resp}"
        );
    }

    srv_handle.abort();
}

/// F2: `transcript_path` and `agent_id` are confined to the expected session directory
/// (no `..`), read only as a regular file through `symlink_metadata`, with a size cap.
#[test]
fn f2_read_meta_json_confines_path_symlink_and_size() {
    let tmp = tempdir().unwrap();
    let session_dir = tmp.path().join("project").join(VALID_UUID_1);
    let subagents_dir = session_dir.join("subagents");
    fs::create_dir_all(&subagents_dir).unwrap();

    let valid_transcript = session_dir.with_extension("jsonl");
    // Valid `.meta.json` inside `<stem>/subagents/agent-<agent_id>.meta.json` passes.
    let valid_meta = subagents_dir.join("agent-good.meta.json");
    fs::write(
        &valid_meta,
        r#"{"name":"bounded-worker","agentType":"research"}"#,
    )
    .unwrap();
    let (name, atype) =
        xmsg::agent::read_meta_json_fields(valid_transcript.to_str().unwrap(), "good");
    assert_eq!(name.as_deref(), Some("bounded-worker"));
    assert_eq!(atype.as_deref(), Some("research"));

    // Malformed 1: `..` traversal in `transcript_path` refused.
    let outside_meta = tmp.path().join("agent-outside.meta.json");
    fs::write(&outside_meta, r#"{"name":"leaked","agentType":"leaked"}"#).unwrap();
    let traversal_transcript = subagents_dir.join("..").join("..").join("outside.jsonl");
    let (name, atype) =
        xmsg::agent::read_meta_json_fields(traversal_transcript.to_str().unwrap(), "outside");
    assert!(
        name.is_none() && atype.is_none(),
        "transcript_path with '..' must be refused"
    );

    // Malformed 2: `..` or `/` in `agent_id` refused.
    let (name, atype) =
        xmsg::agent::read_meta_json_fields(valid_transcript.to_str().unwrap(), "../outside");
    assert!(
        name.is_none() && atype.is_none(),
        "agent_id with '..' or '/' must be refused"
    );

    // Malformed 3: symlink `.meta.json` inside `subagents_dir` refused via `symlink_metadata`.
    let symlink_meta = subagents_dir.join("agent-symlink.meta.json");
    std::os::unix::fs::symlink(&outside_meta, &symlink_meta).unwrap();
    let (name, atype) =
        xmsg::agent::read_meta_json_fields(valid_transcript.to_str().unwrap(), "symlink");
    assert!(
        name.is_none() && atype.is_none(),
        "symlink .meta.json must be refused by symlink_metadata"
    );

    // Valid 2: `transcript_path` accessed through a symlinked parent directory (such as macOS
    // `/var/folders/...` -> `/private/var/folders/...`) passes when both `expected_session_dir`
    // and the candidate `meta.json` resolve under the same canonical session directory.
    let symlink_root = tmp.path().join("var-folders-link");
    std::os::unix::fs::symlink(tmp.path().join("project"), &symlink_root).unwrap();
    let symlinked_transcript = symlink_root.join(format!("{VALID_UUID_1}.jsonl"));
    let (name, atype) =
        xmsg::agent::read_meta_json_fields(symlinked_transcript.to_str().unwrap(), "good");
    assert_eq!(name.as_deref(), Some("bounded-worker"));
    assert_eq!(atype.as_deref(), Some("research"));

    // Malformed 3b: intermediate `subagents` directory replaced by a symlink pointing outside
    // `expected_session_dir` is refused by canonical prefix check.
    let escape_session_dir = tmp.path().join("project").join(VALID_UUID_2);
    fs::create_dir_all(&escape_session_dir).unwrap();
    std::os::unix::fs::symlink(tmp.path(), escape_session_dir.join("subagents")).unwrap();
    let escape_transcript = escape_session_dir.with_extension("jsonl");
    let (name, atype) =
        xmsg::agent::read_meta_json_fields(escape_transcript.to_str().unwrap(), "outside");
    assert!(
        name.is_none() && atype.is_none(),
        "intermediate symlinked subagents/ directory pointing outside session dir must be refused"
    );

    // Malformed 4: oversized `.meta.json` (> 65536 bytes) refused by size cap.
    let huge_meta = subagents_dir.join("agent-huge.meta.json");
    let huge_payload = format!(r#"{{"name":"{}","agentType":"huge"}}"#, "x".repeat(70_000));
    fs::write(&huge_meta, huge_payload).unwrap();
    let (name, atype) =
        xmsg::agent::read_meta_json_fields(valid_transcript.to_str().unwrap(), "huge");
    assert!(
        name.is_none() && atype.is_none(),
        "oversized .meta.json must be refused by size cap"
    );
}

/// F3: `SessionFileEntry` requires a UUID-shaped `session_id`, and `messaging_socket_path`
/// is constrained to the expected directory, never `xmsg`'s own `agent.sock` or `register.sock`.
#[tokio::test]
async fn f3_session_file_entry_requires_uuid_and_safe_socket_path() {
    let tmp = tempdir().unwrap();
    let valid_sock = tmp.path().join("claude-valid.sock");

    let valid_entry = SessionFileEntry {
        pid: std::process::id(),
        session_id: VALID_UUID_1.to_string(),
        name: Some("valid".to_string()),
        cwd: "/tmp".to_string(),
        status: "idle".to_string(),
        kind: "interactive".to_string(),
        entrypoint: None,
        version: None,
        started_at: 1,
        updated_at: 1,
        proc_start: "100".to_string(),
        messaging_socket_path: valid_sock.to_string_lossy().to_string(),
    };
    assert!(
        xmsg::registry::validate_session_file_entry(&valid_entry),
        "valid UUID session_id and tmp socket path must pass"
    );

    // Malformed 1: non-UUID session_id refused.
    let bad_id_entry = SessionFileEntry {
        session_id: "not-a-uuid".to_string(),
        ..valid_entry.clone()
    };
    assert!(
        !xmsg::registry::validate_session_file_entry(&bad_id_entry),
        "non-UUID session_id must be refused"
    );

    // Malformed 2: xmsg's own `agent.sock`, `register.sock` and `http.sock` refused.
    // Bind a real `UnixListener` at each reserved path so that without the use-site check in
    // `inbox::deliver_to_socket`, `UnixStream::connect` + write would succeed (`Ok(())`).
    let valid_sock_listener = UnixListener::bind(&valid_sock).unwrap();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = valid_sock_listener.accept().await {
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf).await;
        }
    });
    assert!(
        xmsg::inbox::deliver_to_socket(&valid_sock, "{}\n")
            .await
            .is_ok(),
        "valid session socket must pass deliver_to_socket use site"
    );

    for reserved in ["agent.sock", "register.sock", "http.sock"] {
        let reserved_sock = tmp.path().join(reserved);
        let reserved_listener = UnixListener::bind(&reserved_sock).unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = reserved_listener.accept().await {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
            }
        });
        let bad_sock_entry = SessionFileEntry {
            messaging_socket_path: reserved_sock.to_string_lossy().to_string(),
            ..valid_entry.clone()
        };
        assert!(
            !xmsg::registry::validate_session_file_entry(&bad_sock_entry),
            "reserved xmsg socket {reserved} must be refused at entry"
        );
        let err = xmsg::inbox::deliver_to_socket(&reserved_sock, "{}\n")
            .await
            .expect_err("reserved xmsg socket must be refused at deliver_to_socket use site");
        assert!(
            err.to_string().contains("invalid messaging socket path"),
            "deliver_to_socket error must come from socket path validation, got: {err}"
        );
    }

    // Malformed 3: socket path outside expected directory or containing `..` refused.
    for bad_path in [
        "/etc/claude.sock",
        "/private/etc/claude.sock",
        "/tmp/../etc/claude.sock",
        "relative.sock",
    ] {
        let bad_sock_entry = SessionFileEntry {
            messaging_socket_path: bad_path.to_string(),
            ..valid_entry.clone()
        };
        assert!(
            !xmsg::registry::validate_session_file_entry(&bad_sock_entry),
            "unsafe socket path {bad_path} must be refused"
        );
    }
    // Symlinked parent directory pointing to `/etc` refused via canonical parent check.
    let etc_link = tmp.path().join("etc-link");
    std::os::unix::fs::symlink("/etc", &etc_link).unwrap();
    let etc_link_sock = SessionFileEntry {
        messaging_socket_path: etc_link.join("claude.sock").to_string_lossy().to_string(),
        ..valid_entry.clone()
    };
    assert!(
        !xmsg::registry::validate_session_file_entry(&etc_link_sock),
        "socket path under symlink to /etc must be refused"
    );
}

/// F4: `handle_subagent_frame` uses the same `agent_id` validation as `plugin.rs`, through
/// the shared function `claim::validate_subagent_id`.
#[tokio::test]
async fn f4_subagent_frame_shares_agent_id_validation() {
    let tmp = tempdir().unwrap();
    let state = make_test_state(tmp.path());
    let parent = Session {
        session_id: VALID_UUID_1.to_string(),
        name: None,
        pid: std::process::id(),
        cwd: "/tmp".to_string(),
        status: "idle".to_string(),
        kind: "interactive".to_string(),
        entrypoint: None,
        version: None,
        started_at: 1,
        updated_at: 1,
        harness: "claude".to_string(),
        registered: Some(true),
    };

    // Valid `agent_id` passes both the shared helper and `handle_subagent_frame`.
    assert_eq!(
        xmsg::claim::validate_subagent_id("agent-valid_01").unwrap(),
        "agent-valid_01"
    );
    let res = xmsg::agent::handle_subagent_frame(
        &state,
        &parent,
        "start",
        "agent-valid_01",
        Some("worker"),
        Some("research"),
        None,
        None,
        None,
        None,
    )
    .await;
    assert!(
        res.is_ok(),
        "valid agent_id must pass handle_subagent_frame"
    );

    // Malformed `agent_id`s (empty, '/', '@', whitespace, control char, > 128 bytes) are
    // refused before touching the database.
    let long_id = "a".repeat(129);
    for bad_id in [
        "",
        "   ",
        "sub/child",
        "sub@node",
        "sub id",
        "sub\nid",
        &long_id,
    ] {
        assert!(
            xmsg::claim::validate_subagent_id(bad_id).is_err(),
            "validate_subagent_id must refuse {bad_id:?}"
        );
        let res = xmsg::agent::handle_subagent_frame(
            &state, &parent, "start", bad_id, None, None, None, None, None, None,
        )
        .await;
        assert!(
            res.is_err(),
            "handle_subagent_frame must refuse malformed agent_id {bad_id:?}"
        );
    }
}

/// F5: `check_origin` and the control-character validation apply on the hub pull path
/// (`run_outbound_peer_pull_loop`) and in `handoff::step`, the same as on the direct path,
/// and the use-site re-checks (`surface::deliver`, `inbox::encode_transport_line`,
/// `storage::insert_handed_over`) refuse malformed inputs even when called directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f5_hub_pull_and_handoff_step_enforce_check_origin_and_control_chars() {
    // 1. Valid pulled message passes `validate_pulled_message`.
    let valid_pulled = FedInboxMessage {
        id: "01M6DNYSJF6YTHXYEAGY6GNX06".to_string(),
        origin: Origin::instance(VALID_UUID_1, "sini.hub", Some("worker")),
        body: "hello".to_string(),
        to: Some(VALID_UUID_2.to_string()),
    };
    assert!(
        xmsg::fed::validate_pulled_message(&valid_pulled).is_ok(),
        "valid pulled message must pass"
    );

    // Malformed pulled messages (both service and id set, bad origin id with '@' or control
    // char, bad service name, origin node with control char, or message id with control char)
    // are refused.
    let bad_pulled_cases = vec![
        FedInboxMessage {
            origin: Origin {
                service: Some("svc".to_string()),
                id: Some(VALID_UUID_1.to_string()),
                label: None,
                node: "sini.hub".to_string(),
            },
            ..valid_pulled.clone()
        },
        FedInboxMessage {
            origin: Origin::instance("bad@id", "sini.hub", None),
            ..valid_pulled.clone()
        },
        FedInboxMessage {
            origin: Origin::instance("bad\nid", "sini.hub", None),
            ..valid_pulled.clone()
        },
        FedInboxMessage {
            origin: Origin::service("bad/service", "sini.hub"),
            ..valid_pulled.clone()
        },
        FedInboxMessage {
            origin: Origin::instance(VALID_UUID_1, "sini.hub\nevil", None),
            ..valid_pulled.clone()
        },
        FedInboxMessage {
            id: "msg\nid".to_string(),
            ..valid_pulled.clone()
        },
    ];
    for bad in &bad_pulled_cases {
        assert!(
            xmsg::fed::validate_pulled_message(bad).is_err(),
            "malformed pulled message must be refused: {bad:?}"
        );
    }

    // 1b. Drive `run_outbound_peer_pull_loop` end-to-end against a real mTLS hub listener:
    // - A pulled `FedInboxMessage` with an invalid `origin` (both `service` and `id` set) is
    //   refused at `src/fed.rs:4655`, acked from the hub mailbox, and NEVER stored in
    //   `messages` (`storage::get_message` returns `None`) or delivered to the target socket.
    // - A pulled `FedInboxMessage` with a valid `origin` in the same pull loop passes, is
    //   stored in `messages` (`outcome == "delivered"`), and is delivered to the target socket.
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let (hub_cert_der, hub_key_der, hub_pin) = generate_self_signed_ed25519("hub").unwrap();
    let (leaf_cert_der, leaf_key_der, leaf_pin) = generate_self_signed_ed25519("leaf").unwrap();

    let hub_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub_port = hub_listener.local_addr().unwrap().port();

    let hub_peers_path = tmp.path().join("hub-peers.json");
    fs::write(
        &hub_peers_path,
        serde_json::json!({
            "leaf": {
                "address": "127.0.0.1:0",
                "pin": normalize_pin(&leaf_pin),
                "leaf": true,
                "allow": ["send", "reply", "inbox"]
            }
        })
        .to_string(),
    )
    .unwrap();
    let hub_peers = Arc::new(PeersMap::load_from_file_for(&hub_peers_path, None).unwrap());

    let hub_state = make_test_state(&tmp.path().join("hub"));
    let bad_pull_id = "01M6DNYSJF6YTHXYEAGY6GNX01";
    let good_pull_id = "01M6DNYSJF6YTHXYEAGY6GNX02";
    {
        let hub_db = hub_state.db.lock().unwrap();
        // Invalid origin: both `service` and `id` set.
        storage::insert_peer_mailbox(
            &hub_db,
            &PeerMailboxMessage {
                id: bad_pull_id.to_string(),
                peer: "leaf".to_string(),
                target_ref: VALID_UUID_2.to_string(),
                created_at: 10,
                from_name: "spoof".to_string(),
                bytes: 16,
                body: "poisoned message".to_string(),
                envelope: "{}".to_string(),
                origin: Origin {
                    service: Some("svc".to_string()),
                    id: Some(VALID_UUID_1.to_string()),
                    label: None,
                    node: "sini.hub".to_string(),
                },
            },
        )
        .unwrap();
        // Valid origin: instance on `sini.hub`.
        storage::insert_peer_mailbox(
            &hub_db,
            &PeerMailboxMessage {
                id: good_pull_id.to_string(),
                peer: "leaf".to_string(),
                target_ref: VALID_UUID_2.to_string(),
                created_at: 20,
                from_name: format!("worker · {VALID_UUID_1}@sini.hub"),
                bytes: 13,
                body: "clean message".to_string(),
                envelope: "{}".to_string(),
                origin: Origin::instance(VALID_UUID_1, "sini.hub", Some("worker")),
            },
        )
        .unwrap();
    }

    let hub_fed_state = Arc::new(FedState {
        node_name: "sini.hub".to_string(),
        peers: (hub_peers).into(),
        cert_der: hub_cert_der.clone(),
        cert_chain_der: vec![hub_cert_der],
        key_der: hub_key_der,
        rate_limiter: Arc::new(RateLimiter::new(60, 100)),
        db: hub_state.db.clone(),
        sessions_dirs: hub_state.sessions_dirs.clone(),
        agy_config: hub_state.agy_config.clone(),
        agy_store: hub_state.agy_store.clone(),
        pi_store: hub_state.pi_store.clone(),
        pi_notify_tx: hub_state.pi_notify_tx.clone(),
        svc_store: hub_state.svc_store.clone(),
        svc_notify_tx: hub_state.svc_notify_tx.clone(),
        notify_tx: hub_state.notify_tx.clone(),
        max_body: 65_536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: Duration::from_secs(3600),
        list_queries: Default::default(),
    });
    let hub_srv = tokio::spawn(run_fed_listener(hub_listener, hub_fed_state.clone()));

    let leaf_dir = tmp.path().join("leaf");
    let leaf_state = make_test_state(&leaf_dir);
    let leaf_sessions_dir = &leaf_state.sessions_dirs[0];
    fs::create_dir_all(leaf_sessions_dir).unwrap();
    fs::set_permissions(leaf_sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    // Register a live local Claude session `VALID_UUID_2` on the leaf so pulled messages
    // targeting `VALID_UUID_2` resolve locally.
    let target_sock = leaf_dir.join("claude-target.sock");
    let target_listener = UnixListener::bind(&target_sock).unwrap();
    let delivered_lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let delivered_clone = delivered_lines.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = target_listener.accept().await {
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf).await;
            if let Ok(s) = String::from_utf8(buf) {
                delivered_clone.lock().unwrap().push(s);
            }
        }
    });

    let my_pid = std::process::id();
    let my_proc_start = xmsg::process::starttime(&leaf_state.agy_config.proc_root, my_pid)
        .unwrap_or_else(|_| "1000".to_string());
    let session_json = serde_json::json!({
        "pid": my_pid,
        "sessionId": VALID_UUID_2,
        "name": "target",
        "cwd": "/tmp",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": my_proc_start,
        "messagingSocketPath": target_sock.to_string_lossy()
    });
    fs::write(
        leaf_sessions_dir.join(format!("{my_pid}-{VALID_UUID_2}.json")),
        session_json.to_string(),
    )
    .unwrap();

    let leaf_peers_path = tmp.path().join("leaf-peers.json");
    fs::write(
        &leaf_peers_path,
        serde_json::json!({
            "hub": {
                "address": format!("127.0.0.1:{hub_port}"),
                "pin": normalize_pin(&hub_pin),
                "dial": "outbound",
                "allow": ["send", "reply", "inbox"]
            }
        })
        .to_string(),
    )
    .unwrap();
    let leaf_peers = Arc::new(PeersMap::load_from_file_for(&leaf_peers_path, None).unwrap());

    let leaf_fed_state = Arc::new(FedState {
        node_name: "sini.leaf".to_string(),
        peers: (leaf_peers).into(),
        cert_der: leaf_cert_der.clone(),
        cert_chain_der: vec![leaf_cert_der],
        key_der: leaf_key_der,
        rate_limiter: Arc::new(RateLimiter::new(60, 100)),
        db: leaf_state.db.clone(),
        sessions_dirs: leaf_state.sessions_dirs.clone(),
        agy_config: leaf_state.agy_config.clone(),
        agy_store: leaf_state.agy_store.clone(),
        pi_store: leaf_state.pi_store.clone(),
        pi_notify_tx: leaf_state.pi_notify_tx.clone(),
        svc_store: leaf_state.svc_store.clone(),
        svc_notify_tx: leaf_state.svc_notify_tx.clone(),
        notify_tx: leaf_state.notify_tx.clone(),
        max_body: 65_536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: Duration::from_secs(3600),
        list_queries: Default::default(),
    });

    let pull_handle = tokio::spawn(run_outbound_peer_pull_loop(
        leaf_fed_state.clone(),
        "hub".to_string(),
    ));

    // Wait for both mailbox items to be pulled and acked from the hub.
    let mut mailbox_drained = false;
    for _ in 0..100 {
        let remaining = {
            let hub_db = hub_state.db.lock().unwrap();
            storage::count_peer_mailbox_messages(&hub_db, "leaf").unwrap()
        };
        if remaining == 0 {
            mailbox_drained = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    pull_handle.abort();
    hub_srv.abort();
    assert!(
        mailbox_drained,
        "run_outbound_peer_pull_loop must drain and ack both hub mailbox items"
    );

    {
        let leaf_db = leaf_state.db.lock().unwrap();
        assert!(
            storage::get_message(&leaf_db, bad_pull_id)
                .unwrap()
                .is_none(),
            "invalid-origin pulled message must be refused at entry and NEVER stored in messages"
        );
        let good_rec = storage::get_message(&leaf_db, good_pull_id)
            .unwrap()
            .expect("valid pulled message must be stored in messages");
        assert_eq!(good_rec.outcome, "delivered");
    }
    let lines = delivered_lines.lock().unwrap().clone();
    assert_eq!(
        lines.len(),
        1,
        "only the valid pulled message may be delivered to the target socket, got: {lines:?}"
    );
    assert!(
        lines[0].contains("clean message") && !lines[0].contains("poisoned message"),
        "target socket must receive only the valid pulled message, got: {}",
        lines[0]
    );

    // 2. Valid handoff Transfer passes `validate_handoff_transfer` and `insert_handed_over`.
    let valid_qmsg = QueuedMessage {
        id: "01M6DNYSJF6YTHXYEAGY6GNX06".to_string(),
        instance_id: VALID_UUID_2.to_string(),
        created_at: 10,
        expires_at: 100,
        from_name: format!("worker · {VALID_UUID_1}@sini.hub"),
        body: "queued hello".to_string(),
    };
    let valid_rec = MessageRecord {
        id: "01M6DNYSJF6YTHXYEAGY6GNX06".to_string(),
        created_at: 10,
        session_id: VALID_UUID_2.to_string(),
        from_name: format!("worker · {VALID_UUID_1}@sini.hub"),
        bytes: 12,
        outcome: "queued".to_string(),
        recipient_harness: "claude".to_string(),
        return_harness: Some("fed".to_string()),
        return_session_id: Some(VALID_UUID_1.to_string()),
        thread_id: "01M6DNYSJF6YTHXYEAGY6GNX06".to_string(),
        return_host: Some("sini.hub".to_string()),
    };
    let valid_transfer = Transfer {
        messages: vec![valid_qmsg.clone()],
        records: vec![valid_rec.clone()],
    };
    assert!(
        xmsg::fed::validate_handoff_transfer(&valid_transfer, "sini.hub").is_ok(),
        "valid handoff transfer must pass"
    );

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&conn).unwrap();
    assert!(
        storage::insert_handed_over(&conn, &valid_qmsg).is_ok(),
        "valid QueuedMessage must pass insert_handed_over use-site check"
    );

    // Malformed handoff Transfers (control char in from_name, unparseable/spoofed from_name,
    // control char in message id, or invalid return_session_id) are refused before DB write.
    let bad_transfers = vec![
        Transfer {
            messages: vec![QueuedMessage {
                from_name: "evil\nline · id@sini.hub".to_string(),
                ..valid_qmsg.clone()
            }],
            records: vec![],
        },
        Transfer {
            messages: vec![QueuedMessage {
                from_name: "spoof@extra · id@sini.hub".to_string(),
                ..valid_qmsg.clone()
            }],
            records: vec![],
        },
        Transfer {
            messages: vec![QueuedMessage {
                id: "bad\nid".to_string(),
                ..valid_qmsg.clone()
            }],
            records: vec![],
        },
        Transfer {
            messages: vec![valid_qmsg.clone()],
            records: vec![MessageRecord {
                return_session_id: Some("bad@return".to_string()),
                ..valid_rec.clone()
            }],
        },
    ];
    for bad in &bad_transfers {
        assert!(
            xmsg::fed::validate_handoff_transfer(bad, "sini.hub").is_err(),
            "malformed handoff transfer must be refused: {bad:?}"
        );
    }
    assert!(
        storage::insert_handed_over(
            &conn,
            &QueuedMessage {
                from_name: "evil\nline · id@sini.hub".to_string(),
                ..valid_qmsg.clone()
            }
        )
        .is_err(),
        "insert_handed_over use site must refuse control chars in from_name"
    );
    assert!(
        storage::insert_handed_over(
            &conn,
            &QueuedMessage {
                from_name: "spoof@extra · id@sini.hub".to_string(),
                ..valid_qmsg
            }
        )
        .is_err(),
        "insert_handed_over use site must refuse unparseable/spoofed origin in from_name"
    );

    // 3. Direct use-site check on `inbox::encode_transport_line` (without entry check):
    assert!(
        xmsg::inbox::encode_transport_line(&format!("worker · {VALID_UUID_1}@sini.hub"), "hello")
            .is_ok(),
        "valid from_name must pass encode_transport_line"
    );
    assert!(
        xmsg::inbox::encode_transport_line("evil\nfrom · id@sini.hub", "hello").is_err(),
        "encode_transport_line use site must refuse control chars in from_name"
    );

    // 4. Direct use-site check on `surface::deliver` (without entry check):
    let parked_target = ResolvedTarget::Parked {
        session: Session {
            session_id: VALID_UUID_2.to_string(),
            name: Some("target".to_string()),
            pid: my_pid,
            cwd: "/tmp".to_string(),
            status: "parked".to_string(),
            kind: "interactive".to_string(),
            entrypoint: None,
            version: None,
            started_at: 1,
            updated_at: 1,
            harness: "claude".to_string(),
            registered: Some(true),
        },
        expires_at: 9_999_999_999,
    };
    let valid_origin = Origin::instance(VALID_UUID_1, "sini.hub", Some("worker"));
    let invalid_origin = Origin {
        service: Some("svc".to_string()),
        id: Some(VALID_UUID_1.to_string()),
        label: None,
        node: "sini.hub".to_string(),
    };
    assert!(
        xmsg::surface::deliver(
            &leaf_state.local(),
            &parked_target,
            &format!("worker · {VALID_UUID_1}@sini.hub"),
            "01M6DNYSJF6YTHXYEAGY6GNX90",
            "hello",
            invalid_origin,
        )
        .await
        .is_err(),
        "surface::deliver use site must refuse invalid Origin"
    );
    assert!(
        xmsg::surface::deliver(
            &leaf_state.local(),
            &parked_target,
            "evil\nfrom · id@sini.hub",
            "01M6DNYSJF6YTHXYEAGY6GNX91",
            "hello",
            valid_origin.clone(),
        )
        .await
        .is_err(),
        "surface::deliver use site must refuse control chars in from_name"
    );
    assert!(
        xmsg::surface::deliver(
            &leaf_state.local(),
            &parked_target,
            &format!("worker · {VALID_UUID_1}@sini.hub"),
            "bad\nid",
            "hello",
            valid_origin.clone(),
        )
        .await
        .is_err(),
        "surface::deliver use site must refuse control chars in message_id"
    );
    assert!(
        xmsg::surface::deliver(
            &leaf_state.local(),
            &parked_target,
            &format!("worker · {VALID_UUID_1}@sini.hub"),
            "01M6DNYSJF6YTHXYEAGY6GNX92",
            "hello",
            valid_origin,
        )
        .await
        .is_ok(),
        "surface::deliver use site must accept valid Origin, from_name, and message_id"
    );
}

/// F6: a byte cap and a timeout on `read_line` in `run_leaf_register_server`.
#[tokio::test]
async fn f6_run_leaf_register_server_enforces_byte_cap_and_timeout() {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let sock_path = tmp.path().join("leaf-register.sock");
    let state = make_test_state(tmp.path());

    let my_uid = unsafe { libc::geteuid() };
    let srv_sock = sock_path.clone();
    let srv_state = state.clone();
    let srv_handle = tokio::spawn(async move {
        let _ = xmsg::svc::run_leaf_register_server(
            srv_sock,
            srv_state,
            my_uid,
            "svc:matrix".to_string(),
        )
        .await;
    });

    for _ in 0..50 {
        if std::os::unix::net::UnixStream::connect(&sock_path).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // 1. Valid registration frame within byte cap and timeout succeeds.
    let mut valid_conn = UnixStream::connect(&sock_path).await.unwrap();
    valid_conn
        .write_all(b"{\"name\":\"matrix\"}\n")
        .await
        .unwrap();
    let mut resp_line = String::new();
    BufReader::new(&mut valid_conn)
        .read_line(&mut resp_line)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_str(&resp_line).unwrap();
    assert_eq!(
        resp["status"], "ok",
        "valid leaf register must succeed: {resp}"
    );
    drop(valid_conn);

    // 2. Oversized registration frame (> 65536 bytes) is refused by byte cap.
    let mut huge_conn = UnixStream::connect(&sock_path).await.unwrap();
    let huge_frame = format!("{{\"name\":\"{}\"}}\n", "m".repeat(70_000));
    let _ = huge_conn.write_all(huge_frame.as_bytes()).await;
    let mut err_line = String::new();
    BufReader::new(&mut huge_conn)
        .read_line(&mut err_line)
        .await
        .unwrap();
    let err_resp: serde_json::Value = serde_json::from_str(&err_line).unwrap();
    assert_eq!(err_resp["status"], "error");
    assert!(
        err_resp["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("maximum allowed size"),
        "oversized frame must be refused by byte cap: {err_resp}"
    );

    // 3. Stalled client with no newline is cut off by timeout in `read_initial_register_line`.
    let (client_stream, server_stream) = UnixStream::pair().unwrap();
    let (srv_r, mut srv_w) = server_stream.into_split();
    let mut buf_reader = BufReader::new(srv_r);
    let mut client_stream = client_stream;
    client_stream
        .write_all(b"{\"name\":\"stalled")
        .await
        .unwrap();
    let res = xmsg::svc::read_initial_register_line(
        &mut buf_reader,
        &mut srv_w,
        xmsg::svc::REGISTER_INITIAL_MAX_BYTES,
        Duration::from_millis(50),
    )
    .await;
    assert!(
        res.is_none(),
        "stalled initial registration line without newline must time out"
    );

    srv_handle.abort();
}
