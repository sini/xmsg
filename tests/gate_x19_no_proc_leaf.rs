//! No-`/proc` portability and `pidfd` `fdinfo` state tests:
//! - Oracle 1: Leaf `svc` registration, `list`, `send`, `poll`, `ack`, and `reply` succeed when
//!   ALL `/proc` paths (`proc_root`, `proc_locks`, and `/proc/self/fdinfo/<pidfd>`) are unavailable.
//! - Oracle 2: A readable `fdinfo` reporting `Pid: -1` (and malformed or missing `Pid:` lines)
//!   remains `Dead` and is refused on leaf registration.
//! - Oracle 3: Non-leaf session tracing (`svc` exe attestation, `agent.sock`, and caller session
//!   resolution) remains unchanged and fails closed when `/proc` is unavailable.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixStream};

use xmsg::agent::{current_uid, resolve_caller_session_peer, run_agent_server};
use xmsg::agy::{new_agy_store, run_register_server, AgyConfig};
use xmsg::client::{ClientError, ClientOptions, ListQuery, RegisteredService};
use xmsg::fed::{
    generate_self_signed_ed25519, run_fed_listener, FedState, PeerConfig, PeersMap, RateLimiter,
};
use xmsg::http::AppState;
use xmsg::pi::new_pi_store;
use xmsg::process;
use xmsg::storage;
use xmsg::svc::{new_svc_store, run_leaf_inbox_task, run_leaf_register_server};

struct FdinfoResetGuard;

impl Drop for FdinfoResetGuard {
    fn drop(&mut self) {
        process::set_force_pidfd_fdinfo_file_for_test(None);
    }
}

struct HubFixture {
    name: String,
    fed_addr: std::net::SocketAddr,
    reg_sock: PathBuf,
    agent_sock: PathBuf,
    _temp: TempDir,
}

struct LeafFixture {
    reg_sock: PathBuf,
    agent_sock: PathBuf,
    _temp: TempDir,
}

fn write_fake_stat(proc_root: &Path, pid: u32, ppid: u32, starttime: &str) {
    let dir = proc_root.join(pid.to_string());
    fs::create_dir_all(&dir).unwrap();
    let mut fields = vec!["0"; 50];
    fields[0] = "S";
    let ppid_s = ppid.to_string();
    fields[1] = &ppid_s;
    fields[19] = starttime;
    let stat = format!("{pid} (test) {}", fields.join(" "));
    fs::write(dir.join("stat"), stat).unwrap();
}

async fn start_hub_with_svc_receiver(
    name: &str,
    peers: Vec<PeerConfig>,
    creds: (Vec<u8>, Vec<u8>, String),
    svc_name: &str,
) -> HubFixture {
    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let sock_dir = temp.path().join("xmsg");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let reg_sock = sock_dir.join("register.sock");
    let agent_sock = sock_dir.join("agent.sock");

    let sessions_dir = temp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let proc_root = temp.path().join("hub-proc");
    fs::create_dir_all(&proc_root).unwrap();
    let my_pid = std::process::id();
    write_fake_stat(&proc_root, my_pid, 1, "9001");
    let cur_exe = std::env::current_exe().unwrap();
    std::os::unix::fs::symlink(&cur_exe, proc_root.join(my_pid.to_string()).join("exe")).unwrap();

    let presence_dir = temp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    let proc_locks = temp.path().join("proc_locks");
    fs::write(&proc_locks, "").unwrap();

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root: proc_root.clone(),
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
        brain_dir: PathBuf::new(),
    };

    let agy_store = new_agy_store();
    let pi_store = new_pi_store();
    let svc_store = new_svc_store();
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (notify_tx, _) = tokio::sync::broadcast::channel(16);

    let mut peers_map = PeersMap::empty();
    for p in peers {
        peers_map.insert(p).unwrap();
    }
    let peers_arc = Arc::new(peers_map);

    let db_path = temp.path().join("hub.db");
    let db = Arc::new(Mutex::new(rusqlite::Connection::open(&db_path).unwrap()));
    storage::init_db(&db.lock().unwrap()).unwrap();

    let (cert_der, key_der, _pin) = creds;

    let fed_state = Arc::new(FedState {
        node_name: name.to_string(),
        peers: peers_arc.into(),
        cert_der,
        cert_chain_der: Vec::new(),
        key_der,
        rate_limiter: Arc::new(RateLimiter::new(60, 100)),
        db: db.clone(),
        sessions_dirs: vec![sessions_dir.clone()],
        agy_config: agy_config.clone(),
        agy_store: agy_store.clone(),
        pi_store: pi_store.clone(),
        pi_notify_tx: pi_notify_tx.clone(),
        svc_store: svc_store.clone(),
        svc_notify_tx: svc_notify_tx.clone(),
        notify_tx: notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: Duration::from_secs(7 * 24 * 3600),
        list_queries: Default::default(),
    });

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fed_addr = tcp_listener.local_addr().unwrap();
    let fs_clone = fed_state.clone();
    tokio::spawn(async move {
        let _ = run_fed_listener(tcp_listener, fs_clone).await;
    });

    let app_state = Arc::new(AppState {
        max_attachment_bytes: 8 * 1024 * 1024,
        sessions_dirs: vec![sessions_dir],
        agy_config,
        agy_store,
        pi_store,
        pi_notify_tx,
        svc_store,
        svc_notify_tx,
        node_name: name.to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db,
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(3600),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: Some(fed_state),
    });

    let uid = current_uid();
    let a_sock = agent_sock.clone();
    let a_state = app_state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server(a_sock, a_state, uid).await;
    });

    let mut trusted = HashMap::new();
    trusted.insert(svc_name.to_string(), cur_exe);
    let r_sock = reg_sock.clone();
    tokio::spawn(async move {
        let _ = run_register_server(r_sock, app_state, uid, trusted).await;
    });

    for _ in 0..500 {
        if std::os::unix::net::UnixStream::connect(&reg_sock).is_ok()
            && std::os::unix::net::UnixStream::connect(&agent_sock).is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    HubFixture {
        name: name.to_string(),
        fed_addr,
        reg_sock,
        agent_sock,
        _temp: temp,
    }
}

async fn start_leaf_with_unavailable_proc(
    name: &str,
    peers: Vec<PeerConfig>,
    creds: (Vec<u8>, Vec<u8>, String),
    leaf_principal: &str,
    unavailable_proc_root: &Path,
) -> LeafFixture {
    assert!(
        !unavailable_proc_root.exists(),
        "unavailable proc_root must not exist"
    );

    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let sock_dir = temp.path().join("xmsg");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let reg_sock = sock_dir.join("register.sock");
    let agent_sock = sock_dir.join("agent.sock");

    let sessions_dir = temp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let presence_dir = temp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: unavailable_proc_root.join("locks"),
        proc_root: unavailable_proc_root.to_path_buf(),
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
        brain_dir: PathBuf::new(),
    };

    let agy_store = new_agy_store();
    let pi_store = new_pi_store();
    let svc_store = new_svc_store();
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (notify_tx, _) = tokio::sync::broadcast::channel(16);

    let mut peers_map = PeersMap::empty();
    for p in peers {
        peers_map.insert(p).unwrap();
    }
    let peers_arc = Arc::new(peers_map);

    let db_path = temp.path().join("leaf.db");
    let db = Arc::new(Mutex::new(rusqlite::Connection::open(&db_path).unwrap()));
    storage::init_db(&db.lock().unwrap()).unwrap();

    let (cert_der, key_der, _pin) = creds;
    let fed_state = Arc::new(FedState {
        node_name: name.to_string(),
        peers: (peers_arc.clone()).into(),
        cert_der,
        cert_chain_der: Vec::new(),
        key_der,
        rate_limiter: Arc::new(RateLimiter::new(60, 100)),
        db: db.clone(),
        sessions_dirs: vec![sessions_dir.clone()],
        agy_config: agy_config.clone(),
        agy_store: agy_store.clone(),
        pi_store: pi_store.clone(),
        pi_notify_tx: pi_notify_tx.clone(),
        svc_store: svc_store.clone(),
        svc_notify_tx: svc_notify_tx.clone(),
        notify_tx: notify_tx.clone(),
        max_body: 65536,
        is_leaf: true,
        leaf_principal: Some(leaf_principal.to_string()),
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: Duration::from_secs(7 * 24 * 3600),
        list_queries: Default::default(),
    });

    let app_state = Arc::new(AppState {
        max_attachment_bytes: 8 * 1024 * 1024,
        sessions_dirs: vec![sessions_dir],
        agy_config,
        agy_store,
        pi_store,
        pi_notify_tx,
        svc_store,
        svc_notify_tx: svc_notify_tx.clone(),
        node_name: name.to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(3600),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: Some(fed_state.clone()),
    });

    let uid = current_uid();
    let a_sock = agent_sock.clone();
    let a_state = app_state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server(a_sock, a_state, uid).await;
    });

    let r_sock = reg_sock.clone();
    let r_p = leaf_principal.to_string();
    tokio::spawn(async move {
        let _ = run_leaf_register_server(r_sock, app_state, uid, r_p).await;
    });

    for peer_name in peers_arc.keys() {
        let fs_c = fed_state.clone();
        let peer_c = peer_name.clone();
        let p_c = leaf_principal.to_string();
        let db_c = db.clone();
        let notify_c = svc_notify_tx.clone();
        tokio::spawn(async move {
            run_leaf_inbox_task(fs_c, peer_c, p_c, db_c, notify_c).await;
        });
    }

    for _ in 0..500 {
        if std::os::unix::net::UnixStream::connect(&reg_sock).is_ok()
            && std::os::unix::net::UnixStream::connect(&agent_sock).is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    LeafFixture {
        reg_sock,
        agent_sock,
        _temp: temp,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leaf_svc_without_proc_and_pidfd_dead_controls() {
    let _reset = FdinfoResetGuard;
    let root_tmp = tempdir().unwrap();
    fs::set_permissions(root_tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let unavailable_proc = root_tmp.path().join("nonexistent-proc-root");
    assert!(!unavailable_proc.exists());

    let creds_hub = generate_self_signed_ed25519("hub").unwrap();
    let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();

    let hub = start_hub_with_svc_receiver(
        "hub",
        vec![PeerConfig {
            name: "leaf".to_string(),
            address: "127.0.0.1:54321".to_string(),
            pin: Some(creds_leaf.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
            from: None,
            leaf: true,
            principals: Vec::new(),
            targets: Some(vec!["gateway".to_string(), "receiver".to_string()]),
            dial: None,
        }],
        creds_hub.clone(),
        "receiver",
    )
    .await;

    let leaf = start_leaf_with_unavailable_proc(
        "leaf",
        vec![PeerConfig {
            name: "hub".to_string(),
            address: hub.fed_addr.to_string(),
            pin: Some(creds_hub.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_leaf,
        "svc:gateway",
        &unavailable_proc,
    )
    .await;

    // Hub `receiver` registers on the hub node first (where `/proc` exists).
    let mut receiver = RegisteredService::register(ClientOptions {
        register_socket: hub.reg_sock.clone(),
        agent_socket: hub.agent_sock.clone(),
        max_frame_bytes: 65536,
        operation_timeout: Duration::from_secs(5),
        service: "receiver".to_string(),
        expected_node: Some(hub.name.clone()),
        daemon_uid: current_uid(),
    })
    .await
    .expect("hub receiver with valid hub-proc metadata should register");
    let receiver_agent = receiver.agent_client();

    // Redirect pidfd fdinfo reads to the nonexistent `/proc` root as well: ALL `/proc` is now absent.
    process::set_force_pidfd_fdinfo_file_for_test(Some(unavailable_proc.join("self/fdinfo/99")));

    // =========================================================================
    // Oracle 1: Leaf `svc` registration + list + send + poll + ack + reply
    // succeed when ALL `/proc` paths (proc_root, proc_locks, fdinfo) are absent.
    // =========================================================================
    let leaf_opts = ClientOptions {
        register_socket: leaf.reg_sock.clone(),
        agent_socket: leaf.agent_sock.clone(),
        max_frame_bytes: 65536,
        operation_timeout: Duration::from_secs(5),
        service: "gateway".to_string(),
        expected_node: Some("leaf".to_string()),
        daemon_uid: current_uid(),
    };

    let mut leaf_svc = RegisteredService::register(leaf_opts.clone())
        .await
        .expect("Oracle 1: leaf registration must succeed when /proc and fdinfo are unavailable");
    assert_eq!(leaf_svc.address(), Some("gateway@leaf"));
    assert!(
        process::peerpidfd_fallback_warned_for_test(),
        "Oracle 1: unreadable fdinfo must take the Unpinned fallback and trip warn-once"
    );

    let leaf_agent = leaf_svc.agent_client();
    let listed = leaf_agent
        .list(ListQuery {
            name: Some("receiver".to_string()),
            node: Some("hub".to_string()),
            ..Default::default()
        })
        .await
        .expect("Oracle 1: leaf list without /proc must succeed");
    assert!(
        listed
            .recipients
            .iter()
            .any(|r| r.address == "receiver@hub"),
        "Expected receiver@hub in leaf list: {listed:?}"
    );

    let sent1 = leaf_agent
        .send(
            "receiver@hub",
            "leaf request without /proc",
            Some("no-proc-send-1"),
        )
        .await
        .expect("Oracle 1: leaf send without /proc must succeed");
    let sent2 = leaf_agent
        .send(
            "receiver@hub",
            "leaf request without /proc",
            Some("no-proc-send-1"),
        )
        .await
        .expect("Oracle 1: deduplicated leaf send without /proc must succeed");
    assert_eq!(sent1.message_id, sent2.message_id);

    let hub_delivery = receiver
        .poll(5)
        .await
        .unwrap()
        .expect("hub receiver must receive leaf message");
    assert_eq!(hub_delivery.message_id(), sent1.message_id);
    assert_eq!(hub_delivery.text(), "leaf request without /proc");
    assert_eq!(hub_delivery.from_name(), "gateway@leaf");
    assert_eq!(hub_delivery.origin().service.as_deref(), Some("gateway"));
    receiver.ack(hub_delivery.message_id()).await.unwrap();

    let question = receiver_agent
        .send("gateway@leaf", "hub question", Some("hub-q-1"))
        .await
        .expect("hub send to gateway@leaf must succeed");
    let leaf_delivery = leaf_svc
        .poll(5)
        .await
        .unwrap()
        .expect("leaf must receive hub question without /proc");
    assert_eq!(leaf_delivery.message_id(), question.message_id);
    assert_eq!(leaf_delivery.text(), "hub question");
    leaf_svc.ack(leaf_delivery.message_id()).await.unwrap();

    let rep1 = leaf_agent
        .reply(
            &question.message_id,
            "leaf answer without /proc",
            Some("no-proc-reply-1"),
        )
        .await
        .expect("Oracle 1: leaf reply without /proc must succeed");
    let rep2 = leaf_agent
        .reply(
            &question.message_id,
            "leaf answer without /proc",
            Some("no-proc-reply-1"),
        )
        .await
        .expect("Oracle 1: deduplicated leaf reply without /proc must succeed");
    assert_eq!(rep1.seq, rep2.seq);
    assert_eq!(rep1.pushed_message_id, rep2.pushed_message_id);

    let hub_answer = receiver
        .poll(5)
        .await
        .unwrap()
        .expect("hub receiver must receive leaf reply");
    assert_eq!(hub_answer.text(), "leaf answer without /proc");
    assert_eq!(hub_answer.in_reply_to(), Some(question.message_id.as_str()));
    assert_eq!(hub_answer.from_name(), "gateway@leaf");
    assert_eq!(hub_answer.origin().service.as_deref(), Some("gateway"));
    receiver.ack(hub_answer.message_id()).await.unwrap();

    drop(leaf_svc);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // =========================================================================
    // Oracle 2: Readable fdinfo with `Pid: -1`, malformed `Pid:`, or missing
    // `Pid:` line remains `Dead` and is refused on leaf registration.
    // =========================================================================
    let fdinfo_cases = [
        (
            "pid_minus_one",
            "pos:\t0\nflags:\t02000002\nmnt_id:\t15\nPid:\t-1\n",
        ),
        (
            "malformed_pid",
            "pos:\t0\nflags:\t02000002\nPid:\tnot_an_integer\n",
        ),
        (
            "missing_pid_line",
            "pos:\t0\nflags:\t02000002\nmnt_id:\t15\n",
        ),
    ];
    for (case_name, contents) in fdinfo_cases {
        let fdinfo_file = root_tmp.path().join(format!("fdinfo-{case_name}"));
        fs::write(&fdinfo_file, contents).unwrap();
        process::set_force_pidfd_fdinfo_file_for_test(Some(fdinfo_file));

        let res = RegisteredService::register(leaf_opts.clone()).await;
        assert!(
            matches!(res, Err(ClientError::Refused { ref code }) if code == "not_found"),
            "Oracle 2 ({case_name}): readable fdinfo must remain Dead and refuse leaf registration, got: {:?}",
            res.err()
        );
    }

    // =========================================================================
    // Oracle 3: Non-leaf session tracing is unchanged and fails closed when
    // `/proc` is unavailable (`proc_root` and `fdinfo` both absent).
    // =========================================================================
    process::set_force_pidfd_fdinfo_file_for_test(Some(unavailable_proc.join("self/fdinfo/99")));

    let nonleaf_sock_dir = root_tmp.path().join("nonleaf-xmsg");
    fs::create_dir_all(&nonleaf_sock_dir).unwrap();
    fs::set_permissions(&nonleaf_sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let nonleaf_reg_sock = nonleaf_sock_dir.join("register.sock");
    let nonleaf_agent_sock = nonleaf_sock_dir.join("agent.sock");

    let nonleaf_sessions = root_tmp.path().join("nonleaf-sessions");
    fs::create_dir_all(&nonleaf_sessions).unwrap();
    fs::set_permissions(&nonleaf_sessions, fs::Permissions::from_mode(0o700)).unwrap();
    let nonleaf_presence = root_tmp.path().join("nonleaf-presence");
    fs::create_dir_all(&nonleaf_presence).unwrap();

    let nonleaf_agy_cfg = AgyConfig {
        presence_dir: nonleaf_presence,
        proc_locks_path: unavailable_proc.join("locks"),
        proc_root: unavailable_proc.clone(),
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
        brain_dir: PathBuf::new(),
    };
    let nonleaf_db = Arc::new(Mutex::new(rusqlite::Connection::open_in_memory().unwrap()));
    storage::init_db(&nonleaf_db.lock().unwrap()).unwrap();
    let (pi_tx, _) = tokio::sync::broadcast::channel(16);
    let (svc_tx, _) = tokio::sync::broadcast::channel(16);
    let (ntx, _) = tokio::sync::broadcast::channel(16);

    let nonleaf_state = Arc::new(AppState {
        max_attachment_bytes: 8 * 1024 * 1024,
        sessions_dirs: vec![nonleaf_sessions.clone()],
        agy_config: nonleaf_agy_cfg.clone(),
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx: pi_tx,
        svc_store: new_svc_store(),
        svc_notify_tx: svc_tx,
        node_name: "nonleaf".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: nonleaf_db.clone(),
        notify_tx: ntx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(3600),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: None,
    });
    assert!(!nonleaf_state.is_leaf());

    let uid = current_uid();
    let mut nonleaf_trusted = HashMap::new();
    nonleaf_trusted.insert("worker".to_string(), std::env::current_exe().unwrap());
    let nl_reg = nonleaf_reg_sock.clone();
    let nl_st1 = nonleaf_state.clone();
    tokio::spawn(async move {
        let _ = run_register_server(nl_reg, nl_st1, uid, nonleaf_trusted).await;
    });
    let nl_agent = nonleaf_agent_sock.clone();
    let nl_st2 = nonleaf_state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server(nl_agent, nl_st2, uid).await;
    });
    for _ in 0..500 {
        if std::os::unix::net::UnixStream::connect(&nonleaf_reg_sock).is_ok()
            && std::os::unix::net::UnixStream::connect(&nonleaf_agent_sock).is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // 3a. Non-leaf svc executable attestation refuses when /proc is unavailable
    let nonleaf_reg_res = RegisteredService::register(ClientOptions {
        register_socket: nonleaf_reg_sock,
        agent_socket: nonleaf_agent_sock.clone(),
        max_frame_bytes: 65536,
        operation_timeout: Duration::from_secs(3),
        service: "worker".to_string(),
        expected_node: Some("nonleaf".to_string()),
        daemon_uid: uid,
    })
    .await;
    assert!(
        matches!(nonleaf_reg_res, Err(ClientError::Refused { ref code }) if code == "not_found"),
        "Oracle 3: non-leaf svc registration must fail closed without /proc, got: {:?}",
        nonleaf_reg_res.err()
    );

    // 3b. Non-leaf agent.sock refuses connection when /proc is unavailable.
    // Exercise both scheduling orders: immediate write after connect and forced-race write
    // after the server has already accepted, failed caller session resolution, and closed
    // its socket half (`BrokenPipe` on write, `0` bytes read).
    for delay_ms in [0_u64, 25_u64] {
        let stream = UnixStream::connect(&nonleaf_agent_sock).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        if delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        let _ = writer.write_all(b"{\"action\":\"list\"}\n").await;
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line))
            .await
            .unwrap()
            .unwrap_or(0);
        assert_eq!(
            n, 0,
            "Oracle 3 (delay_ms={delay_ms}): non-leaf agent.sock must reject caller without /proc: {line}"
        );
    }

    // 3c. Non-leaf caller session resolution refuses when /proc is unavailable
    let (pair_a, _pair_b) = UnixStream::pair().unwrap();
    let unpinned_peer = process::peer_cred(&pair_a).unwrap();
    let db_guard = nonleaf_db.lock().unwrap();
    let resolved = resolve_caller_session_peer(
        &unavailable_proc,
        &nonleaf_state.sessions_dirs[..],
        &nonleaf_agy_cfg,
        &nonleaf_state.agy_store,
        &nonleaf_state.pi_store,
        &nonleaf_state.svc_store,
        Some(&*db_guard),
        &unpinned_peer,
    );
    assert!(
        resolved.is_err(),
        "Oracle 3: non-leaf session tracing must fail without /proc"
    );
}
