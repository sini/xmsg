use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::time::timeout;

use super::authority::{Authority, Record};
use super::command::{self, CommandDouble, ExactCommandAuthorityFixture};
use super::command_store::{self as store, Reservation, State};
use super::command_wire::{CommandRequest, PreparedRequest};
use super::{Config, Issuer, Prepared, Provider};
use crate::enroll_oidc::signed_fixture::Fixture;

const ENTRY: &str = "mission_control::command_crash_tests::sc14_abrupt_restart";
const STATE_ROOT: &str = "XMSG_TEST_COMMAND_CRASH_ROOT";
const IPC_ADDRESS: &str = "XMSG_TEST_COMMAND_CRASH_IPC";
const OIDC_ISSUER: &str = "XMSG_TEST_COMMAND_CRASH_ISSUER";
const CERTIFICATE_FILE: &str = "oidc-fixture.der";
const CASE: &str = "XMSG_TEST_COMMAND_CRASH_CASE";
const REQUEST_ID: &str = "00000000000000000000000000000001";
const TIMEOUT: Duration = Duration::from_secs(10);

fn target() -> Value {
    json!({
        "node": "fixture.node",
        "endpoint": "claude-1@fixture.node",
        "state_epoch": "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
        "incarnation": 3,
        "selector": {"kind": "execution", "session_id": "exec-alpha", "generation": 7}
    })
}

async fn open(
    root: &Path,
    issuer_url: &str,
    client: reqwest::Client,
) -> (
    Arc<Issuer>,
    Arc<ExactCommandAuthorityFixture>,
    Arc<CommandDouble>,
) {
    let config: Config = serde_json::from_value(json!({
        "public_origin": "https://collector.example",
        "issuer": issuer_url,
        "client_id": "web-client",
        "redirect_uri": "https://collector.example/login/callback",
        "allowlist": ["alice@example.org"],
        "native_client_id": "tui-client",
    }))
    .unwrap();
    let provider =
        Provider::discover_with_client(config.oidc(), &config.public_origin, false, client)
            .await
            .unwrap();
    let authority =
        Authority::open(root, config.authority_config(vec!["fixture.node".into()])).unwrap();
    let fixture = Arc::new(ExactCommandAuthorityFixture::default());
    let double = Arc::new(CommandDouble::default());
    let issuer = Issuer::start_with_command_double_for_test(
        Prepared {
            config,
            provider,
            key: None,
        },
        authority,
        fixture.clone(),
        double.clone(),
    );
    issuer.recover_commands().unwrap();
    (issuer, fixture, double)
}

async fn child(role: &str) {
    let root = std::path::PathBuf::from(std::env::var_os(STATE_ROOT).unwrap());
    let address = std::env::var(IPC_ADDRESS).unwrap();
    let mut ipc = BufReader::new(TcpStream::connect(address).await.unwrap());
    ipc.get_mut().write_all(b"started\n").await.unwrap();
    let mut ready = String::new();
    ipc.read_line(&mut ready).await.unwrap();
    assert_eq!(ready, "hold\n");
    ipc.get_mut().write_all(b"waiting\n").await.unwrap();
    ready.clear();
    ipc.read_line(&mut ready).await.unwrap();
    assert_eq!(ready, "continue\n");

    let issuer_url = std::env::var(OIDC_ISSUER).unwrap();
    let certificate = std::fs::read(root.join(CERTIFICATE_FILE)).unwrap();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .add_root_certificate(reqwest::Certificate::from_der(&certificate).unwrap())
        .build()
        .unwrap();
    let (issuer, fixture, double) = open(&root, &issuer_url, client).await;
    let (_, native, _) = super::tests::transport_owner_records(&issuer, &issuer_url);
    fixture.grant(&native.record.principal, target());
    fixture.abandon.store(role == "reserved", Ordering::SeqCst);
    let at = command::now_ms();
    fixture.freeze_clock(at);
    let request: PreparedRequest = serde_json::from_value(json!({
        "request_id": REQUEST_ID, "requested_at": at, "verb": "send", "target": target(),
        "params": {"text": "Crash recovery fixture."}
    }))
    .unwrap();
    let prepared = issuer
        .command(
            &native.record,
            "http",
            CommandRequest::Prepare { id: None, request },
        )
        .unwrap();
    let commit_request = || CommandRequest::Commit {
        id: None,
        request_id: REQUEST_ID.into(),
        intent: prepared.body["intent"].as_str().unwrap().into(),
        digest: prepared.body["digest"].as_str().unwrap().into(),
    };
    let commit = issuer
        .command(&native.record, "http", commit_request())
        .unwrap();
    assert_eq!(commit.body["outcome"], "effect_unknown");

    if role == "submitting" {
        timeout(TIMEOUT, double.submitted.acquire())
            .await
            .expect("double did not observe the submitted command")
            .unwrap()
            .forget();
    }

    for recovered in [
        issuer.command(
            &native.record,
            "http",
            CommandRequest::Lookup {
                id: None,
                request_id: REQUEST_ID.into(),
            },
        ),
        issuer.command(&native.record, "http", commit_request()),
    ] {
        let recovered = recovered.unwrap();
        assert_eq!(recovered.body["outcome"], "effect_unknown");
        assert_eq!(recovered.body["receipt_id"], commit.body["receipt_id"]);
        assert_eq!(recovered.body["lookup"], true);
    }

    // The parent owns this IPC listener and retains the count across the crash.
    let observed = double.requests.lock().unwrap().len();
    let marker = json!({
        "principal": native.record.principal,
        "receipt_id": commit.body["receipt_id"],
        "submitted": observed,
    });
    ipc.get_mut()
        .write_all(format!("{marker}\n").as_bytes())
        .await
        .unwrap();
    std::future::pending::<()>().await;
}

fn load(root: &Path, principal: &str) -> Reservation {
    let conn = rusqlite::Connection::open(root.join("authority.sqlite")).unwrap();
    store::reservation(&conn, principal, REQUEST_ID)
        .unwrap()
        .expect("reservation is durable before the crash")
}

async fn crash_and_recover(
    oidc: &Fixture,
    role: &str,
    before: State,
    after: State,
    submitted: u64,
) {
    let directory = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let ipc = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer_url = oidc.issuer();
    std::fs::write(
        directory.path().join(CERTIFICATE_FILE),
        oidc.certificate_der(),
    )
    .unwrap();
    let diagnostic = tempfile::tempfile().unwrap();
    let child_output = diagnostic.try_clone().unwrap();
    let mut process = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", ENTRY, "--nocapture"])
        .env(CASE, role)
        .env(STATE_ROOT, directory.path())
        .env(IPC_ADDRESS, ipc.local_addr().unwrap().to_string())
        .env(OIDC_ISSUER, &issuer_url)
        .stdin(Stdio::null())
        .stdout(child_output)
        .stderr(diagnostic.try_clone().unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stream = BufReader::new(
        wait_for_child(&mut process, &diagnostic, ipc.accept())
            .await
            .0,
    );
    let mut first = String::new();
    wait_for_child(&mut process, &diagnostic, stream.read_line(&mut first)).await;
    assert_eq!(first, "started\n");

    // Force the startup ordering: hold the child before opening authority state.
    stream.get_mut().write_all(b"hold\n").await.unwrap();
    let mut waiting = String::new();
    wait_for_child(&mut process, &diagnostic, stream.read_line(&mut waiting)).await;
    assert_eq!(waiting, "waiting\n");
    assert!(
        !directory.path().join("authority.sqlite").exists(),
        "authority state opened before parent released the child"
    );
    stream.get_mut().write_all(b"continue\n").await.unwrap();

    let mut contents = String::new();
    wait_for_child(&mut process, &diagnostic, stream.read_line(&mut contents)).await;
    let marker: Value = serde_json::from_str(&contents).unwrap();
    assert_eq!(marker["submitted"], submitted);
    let principal = marker["principal"].as_str().unwrap();
    let original = load(directory.path(), principal);
    assert_eq!(original.state, before);
    assert_eq!(marker["receipt_id"], original.receipt_id);
    assert!(process.try_wait().unwrap().is_none());
    timeout(TIMEOUT, process.kill()).await.unwrap().unwrap();

    let (issuer, fixture, double) = open(directory.path(), &issuer_url, oidc.http_client()).await;
    fixture.grant(principal, target());
    let recovered = load(directory.path(), principal);
    assert_eq!(recovered.state, after);
    assert_eq!(recovered.receipt_id, original.receipt_id);
    assert_eq!(
        recovered.code.as_deref(),
        (role == "reserved").then_some("interrupted")
    );
    let record: Record = {
        let state = issuer.authority.locked().unwrap();
        let encoded: String = state
            .conn
            .query_row(
                "SELECT record FROM records WHERE id = ?",
                [&recovered.record_id],
                |row| row.get(0),
            )
            .unwrap();
        serde_json::from_str(&encoded).unwrap()
    };
    let receipt = issuer
        .command(
            &record,
            "http",
            CommandRequest::Lookup {
                id: None,
                request_id: REQUEST_ID.into(),
            },
        )
        .unwrap();
    assert_eq!(receipt.body["receipt_id"], original.receipt_id);
    assert_eq!(
        receipt.body["outcome"],
        if role == "reserved" {
            "refused"
        } else {
            "effect_unknown"
        }
    );
    assert_eq!(receipt.body["lookup"], true);
    assert_no_redrive(&double, "first").await;
    drop(issuer);

    let (_issuer, _, second_double) = open(directory.path(), &issuer_url, oidc.http_client()).await;
    assert_eq!(load(directory.path(), principal), recovered);
    assert_no_redrive(&second_double, "second").await;
}

async fn wait_for_child<T>(
    process: &mut tokio::process::Child,
    diagnostics: &std::fs::File,
    operation: impl std::future::Future<Output = std::io::Result<T>>,
) -> T {
    let result = timeout(TIMEOUT, async {
        tokio::select! {
            biased;
            status = process.wait() => Err(std::io::Error::other(format!("crash child exited early: {status:?}"))),
            result = operation => result,
        }
    }).await;
    match result {
        Ok(Ok(value)) => value,
        other => {
            use std::io::{Read, Seek};
            let _ = process.kill().await;
            let mut file = diagnostics.try_clone().unwrap();
            file.rewind().unwrap();
            let mut output = String::new();
            file.read_to_string(&mut output).unwrap();
            let description = match other {
                Ok(Err(error)) => error.to_string(),
                Err(error) => error.to_string(),
                Ok(Ok(_)) => unreachable!(),
            };
            panic!("child did not reach crash marker: {description}\n{output}");
        }
    }
}

async fn assert_no_redrive(double: &CommandDouble, restart: &str) {
    assert!(
        timeout(Duration::from_millis(100), double.submitted.acquire())
            .await
            .is_err(),
        "{restart} restart redrove a command"
    );
    assert!(double.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn sc14_abrupt_restart() {
    if let Ok(role) = std::env::var(CASE) {
        child(&role).await;
        return;
    }
    let oidc = Fixture::new_at(crate::storage::now_epoch_secs()).await;
    crash_and_recover(&oidc, "reserved", State::Reserved, State::Refused, 0).await;
    crash_and_recover(
        &oidc,
        "submitting",
        State::Submitting,
        State::EffectUnknown,
        1,
    )
    .await;
}
