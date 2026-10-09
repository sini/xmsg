use std::fs;
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use xmsg::http::{bind_ucred_unix_listener, build_router, http_get_unix, AppState};
use xmsg::mcp::{run_mcp_loop, McpConfig};

fn test_app_state() -> Arc<AppState> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let (notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);

    Arc::new(AppState {
        sessions_dirs: vec![PathBuf::from("/tmp/nonexistent-sessions")],
        agy_config: xmsg::agy::AgyConfig {
            presence_dir: PathBuf::from("/tmp/nonexistent-presence"),
            proc_locks_path: PathBuf::from("/tmp/nonexistent-proc-locks"),
            proc_root: PathBuf::from(xmsg::process::LIVE_PROC_ROOT),
            agy_bin: "agy".to_string(),
            trusted_agy_exes: Vec::new(),
        },
        agy_store: xmsg::agy::new_agy_store(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx,
        host_label: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: Arc::new(std::sync::Mutex::new(conn)),
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
    })
}

async fn call_mcp_single(config: &McpConfig, req: serde_json::Value) -> Option<serde_json::Value> {
    let config = config.clone();
    tokio::task::spawn_blocking(move || {
        let mut req_bytes = serde_json::to_vec(&req).unwrap();
        req_bytes.push(b'\n');
        let reader = Cursor::new(req_bytes);
        let mut writer = Vec::new();
        run_mcp_loop(&config, reader, &mut writer).unwrap();
        let out_str = String::from_utf8(writer).unwrap();
        let trimmed = out_str.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(serde_json::from_str(trimmed).unwrap())
        }
    })
    .await
    .unwrap()
}

/// Oracle 1: Injected expected_uid != caller's real UID refuses connection via the peer-cred check.
/// Positive control: matching UID connects and receives 200 OK.
/// Negative control (Oracle 1): listener.expected_uid = my_uid + 1000. Real kernel peer-cred
/// comparison (peer_uid == expected_uid) refuses connection.
/// Mutant 1: skip the peer UID comparison check => connection accepted => RED.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_1_foreign_uid_refused() {
    let temp_dir = tempdir().expect("tempdir");
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let sock_path = temp_dir.path().join("http.sock");
    let my_uid = xmsg::agent::current_uid();

    // Positive control: expected_uid == my_uid (real peer cred) -> 200 OK
    {
        let listener =
            bind_ucred_unix_listener(&sock_path, my_uid, None).expect("bind ucred listener");
        let app = build_router(test_app_state());
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let (status, body) =
            http_get_unix(&sock_path, "/healthz").expect("matching UID must succeed");
        assert_eq!(status, axum::http::StatusCode::OK);
        assert!(body.contains("\"status\":\"ok\""));

        server_handle.abort();
        let _ = server_handle.await;
        let _ = fs::remove_file(&sock_path);
    }

    // Negative control (Oracle 1): inject expected_uid != my_uid on listener.
    // Filesystem permissions pass (owned by my_uid), but peer-cred comparison refuses!
    {
        let mut listener =
            bind_ucred_unix_listener(&sock_path, my_uid, None).expect("bind ucred listener");
        listener.expected_uid = my_uid + 1000; // Injected expected UID seam

        let app = build_router(test_app_state());
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let res = http_get_unix(&sock_path, "/healthz");
        assert!(
            res.is_err(),
            "Connection from different UID must be refused by peer-cred comparison check, got: {:?}",
            res
        );

        server_handle.abort();
        let _ = server_handle.await;
    }
}

/// Oracle 1A: Socket file permissions must be strictly mode 0600.
/// Mutant 1A: bind with mode 0666 => stat assertion fails => RED.
#[tokio::test]
async fn test_oracle_1a_socket_mode_0600() {
    let temp_dir = tempdir().expect("tempdir");
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let sock_path = temp_dir.path().join("http.sock");
    let my_uid = xmsg::agent::current_uid();

    let _listener = bind_ucred_unix_listener(&sock_path, my_uid, None).expect("bind listener");
    let meta = fs::metadata(&sock_path).expect("socket metadata");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "Socket permissions must be strictly 0600; got: {:o}",
        mode
    );
}

/// Oracle 1B: Socket directory permissions must be strictly mode 0700 via ensure_secure_socket_dir.
/// Insecure directory modes (0755, 0777) are refused fail-closed.
/// Mutant 1B: skip mode check in ensure_secure_socket_dir => RED.
#[test]
fn test_oracle_1b_dir_mode_0700() {
    let temp_dir = tempdir().expect("tempdir");
    let my_uid = xmsg::agent::current_uid();

    // Permissive mode 0755 must be rejected
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let res_755 = xmsg::agent::ensure_secure_socket_dir(temp_dir.path(), my_uid);
    assert!(
        res_755.is_err(),
        "ensure_secure_socket_dir must reject 0755 directory"
    );

    // Permissive mode 0777 must be rejected
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
    let res_777 = xmsg::agent::ensure_secure_socket_dir(temp_dir.path(), my_uid);
    assert!(
        res_777.is_err(),
        "ensure_secure_socket_dir must reject 0777 directory"
    );

    // Secure mode 0700 must be accepted
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let res_700 = xmsg::agent::ensure_secure_socket_dir(temp_dir.path(), my_uid);
    assert!(
        res_700.is_ok(),
        "ensure_secure_socket_dir must accept 0700 directory"
    );
}

/// Oracle 2: No flag => no TCP listener bound (assert by probing old port 127.0.0.1:7787).
/// Mutant 2: keep default TCP bind => 127.0.0.1:7787 is bound => RED.
#[tokio::test]
async fn test_oracle_2_no_flag_no_tcp_bound() {
    let bin = env!("CARGO_BIN_EXE_xmsg");

    // Sub-oracle 2A: CLI help shows --listen has NO default value
    let help_output = Command::new(bin)
        .args(["serve", "--help"])
        .output()
        .expect("run xmsg serve --help");
    let help_str = String::from_utf8_lossy(&help_output.stdout);
    assert!(
        !help_str.contains("[default: 127.0.0.1:7787]"),
        "xmsg serve --help must NOT list a default value for --listen; got: {}",
        help_str
    );

    // Sub-oracle 2B: Run server with NO --listen flag; probe old port 127.0.0.1:7787.
    // Must NOT be bound by this server process.
    let temp_dir = tempdir().expect("tempdir");
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let http_sock = temp_dir.path().join("http.sock");
    let reg_sock = temp_dir.path().join("reg.sock");
    let agent_sock = temp_dir.path().join("agent.sock");
    let db_path = temp_dir.path().join("db.sqlite");

    let unshare_check = Command::new("unshare").args(["-r", "-n", "true"]).output();
    let has_unshare = unshare_check.map(|o| o.status.success()).unwrap_or(false);

    let script = format!(
        r#"
ip link set lo up 2>/dev/null || true
"{bin}" serve \
    --http-sock "{}" \
    --register-sock "{}" \
    --agent-sock "{}" \
    --db-path "{}" &
SERVER_PID=$!

for i in $(seq 1 50); do
    if [ -S "{}" ]; then break; fi
    sleep 0.05
done

python3 -c "import socket, sys
s = socket.socket()
s.settimeout(0.5)
res = s.connect_ex(('127.0.0.1', 7787))
sys.exit(0 if res != 0 else 1) # Exit 0 if REFUSED (not bound), Exit 1 if connected (bound)
"
PROBE_RES=$?

kill -9 $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
exit $PROBE_RES
"#,
        http_sock.display(),
        reg_sock.display(),
        agent_sock.display(),
        db_path.display(),
        http_sock.display(),
    );

    let output = if has_unshare {
        Command::new("unshare")
            .args(["-r", "-n", "sh", "-c", &script])
            .output()
            .expect("execute in unshare netns")
    } else {
        Command::new("sh")
            .args(["-c", &script])
            .output()
            .expect("execute in shell")
    };

    assert_eq!(
        output.status.code(),
        Some(0),
        "No TCP listener must be bound on 127.0.0.1:7787 when --listen is omitted. Stdout: {}, Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Oracle 3: With --reply-only, MCP tools/list = [reply]. Calling send is rejected.
/// Positive control: default mode exposes [list, send, reply].
/// Mutant 3: also expose send in reply-only mode => RED.
#[tokio::test]
async fn test_oracle_3_reply_only_mcp() {
    let bin = env!("CARGO_BIN_EXE_xmsg");

    // Sub-oracle 3A: CLI help shows --reply-only flag
    let help_output = Command::new(bin)
        .args(["mcp", "--help"])
        .output()
        .expect("run xmsg mcp --help");
    let help_str = String::from_utf8_lossy(&help_output.stdout);
    assert!(
        help_str.contains("--reply-only"),
        "xmsg mcp --help must describe --reply-only; got: {}",
        help_str
    );

    // Sub-oracle 3B: MCP protocol in reply-only mode exposes ONLY reply tool
    let mut config = McpConfig::new(
        vec![PathBuf::from("/tmp/nonexistent-sessions")],
        "http://127.0.0.1:7787".to_string(),
    );
    config.reply_only = true;

    // 1. tools/list
    let list_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list"
    });
    let list_resp = call_mcp_single(&config, list_req)
        .await
        .expect("response to tools/list");
    let tools = list_resp["result"]["tools"]
        .as_array()
        .expect("tools array in result");

    assert_eq!(
        tools.len(),
        1,
        "With --reply-only, exactly 1 tool must be listed; got: {:?}",
        tools
    );
    assert_eq!(tools[0]["name"], "reply");
    assert!(
        !tools.iter().any(|t| t["name"] == "send"),
        "send tool must NOT be exposed in reply-only mode"
    );
    assert!(
        !tools.iter().any(|t| t["name"] == "list"),
        "list tool must NOT be exposed in reply-only mode"
    );

    // 2. Calling send in reply-only mode must fail
    let send_call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "send",
            "arguments": {
                "ref": "someone",
                "text": "hello"
            }
        }
    });
    let send_resp = call_mcp_single(&config, send_call)
        .await
        .expect("response to send call");
    assert!(
        send_resp.get("error").is_some() || send_resp["result"]["isError"] == true,
        "Calling send in reply-only mode must return error; got: {:?}",
        send_resp
    );

    // 3. Positive control: with reply_only = false, all 3 tools are listed
    let mut default_config = McpConfig::new(
        vec![PathBuf::from("/tmp/nonexistent-sessions")],
        "http://127.0.0.1:7787".to_string(),
    );
    default_config.reply_only = false;
    let normal_list_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/list"
    });
    let normal_list_resp = call_mcp_single(&default_config, normal_list_req)
        .await
        .expect("response to normal tools/list");
    let normal_tools = normal_list_resp["result"]["tools"]
        .as_array()
        .expect("normal tools array");
    let names: Vec<&str> = normal_tools
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["list", "send", "reply"]);
}
