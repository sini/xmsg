use super::*;
use std::sync::atomic::AtomicU64;

struct DeadlineClock {
    wall: AtomicI64,
    origin: tokio::time::Instant,
    elapsed: AtomicU64,
}
impl Clock for DeadlineClock {
    fn now(&self) -> i64 {
        self.wall.load(Ordering::SeqCst)
    }
    fn monotonic_now(&self) -> tokio::time::Instant {
        self.origin + Duration::from_secs(self.elapsed.load(Ordering::SeqCst))
    }
}
async fn controlled() -> (Harness, Arc<DeadlineClock>) {
    let mut h = enabled().await;
    let clock = Arc::new(DeadlineClock {
        wall: AtomicI64::new(h.clock.now()),
        origin: tokio::time::Instant::now(),
        elapsed: AtomicU64::new(0),
    });
    h.service = Arc::new(Service::with_oidc_http(
        h.service.ca.clone(),
        h.service.fed.clone(),
        clock.clone(),
        h.service.hub_entry.clone(),
        h.service.ca_identity.clone(),
        h.idp.http_client(),
    ));
    h.service.register_local_approval().unwrap();
    (h, clock)
}
fn session(h: &Harness, created: &Value) -> Arc<Session> {
    h.service
        .sessions
        .lock()
        .unwrap()
        .get(created["session"].as_str().unwrap())
        .unwrap()
        .clone()
}
async fn awaiting(h: &Harness) -> (Value, Value) {
    let (status, created, _) = start(h, "remote", 1).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "device positive control refused"
    );
    let state = authorized(h, &created).await;
    assert_eq!(
        state["status"], "awaiting_approval",
        "provider authorization bypassed approval wait"
    );
    assert_eq!(
        effects(h),
        [0, 0, 0],
        "provider authorization wrote without local approval"
    );
    let views = serde_json::to_value(h.service.pending_device_requests()).unwrap();
    (created, views[0].clone())
}
fn wait_for_approval_lock(s: &Session) {
    let until = std::time::Instant::now() + Duration::from_secs(10);
    while s.phase.try_lock().is_ok() {
        assert!(
            std::time::Instant::now() < until,
            "approval lock barrier timed out"
        );
        std::thread::yield_now();
    }
}
fn bounded_result<T>(rx: std::sync::mpsc::Receiver<T>) -> T {
    rx.recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|_| panic!("device worker barrier timed out"))
}

fn thread_finished(worker: &std::thread::JoinHandle<()>) -> bool {
    let limit = std::time::Instant::now() + Duration::from_secs(10);
    while !worker.is_finished() && std::time::Instant::now() < limit {
        std::thread::yield_now();
    }
    worker.is_finished()
}
fn join_worker(worker: std::thread::JoinHandle<()>) {
    assert!(
        thread_finished(&worker),
        "device worker completion timed out"
    );
    worker.join().unwrap();
}

#[tokio::test]
async fn enabled_device_requires_local_registration_before_provider_work() {
    let mut h = enabled().await;
    h.service = Arc::new(Service::with_oidc_http(
        h.service.ca.clone(),
        h.service.fed.clone(),
        h.clock.clone(),
        h.service.hub_entry.clone(),
        h.service.ca_identity.clone(),
        h.idp.http_client(),
    ));
    let before = h.idp.request_paths();
    let (status, response, _) = start(&h, "remote", 1).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "device started without local approval facility"
    );
    assert_eq!(response["error"]["reason"], "device_unsupported");
    assert_eq!(
        h.idp.request_paths(),
        before,
        "unavailable local approval contacted provider"
    );
    assert_eq!(effects(&h), [0, 0, 0]);
    h.service.register_local_approval().unwrap();
    assert_eq!(start(&h, "remote", 1).await.0, StatusCode::CREATED);
}

#[tokio::test]
async fn device_global_cap_keeps_older_requests_and_deny_releases_permit() {
    let h = enabled().await;
    let mut requests = Vec::new();
    for ip in 1..=8 {
        let (status, request, _) = start(&h, "remote", ip).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "device cap positive control refused"
        );
        requests.push(request);
    }
    let before = h.idp.request_paths();
    let (status, refused, _) = start(&h, "remote", 9).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "ninth device reservation admitted"
    );
    assert_eq!(refused["error"]["reason"], "device_pending_full");
    assert_eq!(
        h.idp.request_paths(),
        before,
        "global device cap contacted provider"
    );
    assert_eq!(
        h.service.sessions.lock().unwrap().len(),
        8,
        "device cap evicted older request"
    );
    let old = session(&h, &requests[0]);
    assert!(h
        .service
        .deny_device(requests[0]["request_id"].as_str().unwrap())
        .is_ok());
    assert!(
        !old.device_active.load(Ordering::Acquire),
        "deny retained active device permit"
    );
    assert!(
        old.cancelled.load(Ordering::Acquire),
        "deny failed to cancel provider task"
    );
    h.clock.0.fetch_add(2, Ordering::SeqCst);
    assert_eq!(
        start(&h, "remote", 9).await.0,
        StatusCode::CREATED,
        "denial did not release global device permit"
    );
    let sessions = h.service.sessions.lock().unwrap();
    assert_eq!(sessions.len(), 9, "denial evicted common pending record");
    for request in requests {
        assert!(
            sessions.contains_key(request["session"].as_str().unwrap()),
            "old request evicted by device admission"
        );
    }
}

#[tokio::test]
async fn device_ip_cap_precedes_provider_and_deny_releases_same_ip() {
    let h = enabled().await;
    let (status, first, _) = start(&h, "remote", 1).await;
    assert_eq!(status, StatusCode::CREATED);
    let before = h.idp.request_paths();
    let (status, refused, _) = start(&h, "second", 1).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "second same-IP device admitted"
    );
    assert_eq!(refused["error"]["reason"], "device_pending_per_ip");
    assert_eq!(
        h.idp.request_paths(),
        before,
        "IP device cap contacted provider"
    );
    assert!(h
        .service
        .deny_device(first["request_id"].as_str().unwrap())
        .is_ok());
    assert_eq!(
        start(&h, "second", 1).await.0,
        StatusCode::CREATED,
        "denial did not release same-IP permit"
    );
    assert_eq!(h.service.sessions.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn device_subcaps_preserve_common_four_and_sixty_four_limits() {
    let h = enabled().await;
    for _ in 0..4 {
        assert_eq!(h.start("browser", 1).await.0, StatusCode::CREATED);
    }
    let before = h.idp.request_paths();
    let (status, response, _) = start(&h, "remote", 1).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response["error"]["reason"], "pending_per_ip",
        "device changed common four-per-IP cap"
    );
    assert_eq!(h.idp.request_paths(), before);
    for ip in 2..=61 {
        h.clock.0.fetch_add(2, Ordering::SeqCst);
        assert_eq!(h.start("browser", ip).await.0, StatusCode::CREATED);
    }
    h.clock.0.fetch_add(2, Ordering::SeqCst);
    let before = h.idp.request_paths();
    let (status, response, _) = start(&h, "remote", 62).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response["error"]["reason"], "pending_full",
        "device changed common 64-record cap"
    );
    assert_eq!(h.idp.request_paths(), before);
    assert_eq!(h.service.sessions.lock().unwrap().len(), 64);
}

#[tokio::test]
async fn exact_monotonic_expiry_refuses_with_valid_wall_clock() {
    let (h, clock) = controlled().await;
    let (created, view) = awaiting(&h).await;
    let s = session(&h, &created);
    let now = clock.monotonic_now();
    *s.deadline.lock().unwrap() = Some(now);
    assert!(clock.now() < s.expires.load(Ordering::Acquire));
    assert!(
        h.service
            .approve_device(created["request_id"].as_str().unwrap(), approval(&view))
            .is_err(),
        "monotonic equality permitted issuance"
    );
    assert_eq!(effects(&h), [0, 0, 0]);
}

#[tokio::test]
async fn real_approval_rechecks_deadline_after_sql_mutex_wait() {
    let (h, clock) = controlled().await;
    let (created, view) = awaiting(&h).await;
    let s = session(&h, &created);
    let locked = h.db.lock().unwrap();
    let service = h.service.clone();
    let id = created["request_id"].as_str().unwrap().to_owned();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        tx.send(service.approve_device(&id, approval(&view)))
            .unwrap();
    });
    wait_for_approval_lock(&s);
    clock.elapsed.store(1000, Ordering::SeqCst);
    drop(locked);
    let result = bounded_result(rx);
    join_worker(worker);
    assert!(
        matches!(result, Err(Failure(_, "approval_expired"))),
        "SQL wait deadline did not refuse actual approval"
    );
    assert_eq!(
        effects(&h),
        [0, 0, 0],
        "expired actual approval wrote authority state"
    );
}

#[tokio::test]
async fn changed_policy_cannot_remap_protocol_approval() {
    let h = enabled().await;
    let (created, view) = awaiting(&h).await;
    let mut policy = (*h.service.ca.policy()).clone();
    policy.issue_per_hour += 1;
    std::fs::write(
        h._directory.path().join("policy.json"),
        serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    let result = h
        .service
        .approve_device(created["request_id"].as_str().unwrap(), approval(&view));
    assert!(
        matches!(result, Err(Failure(_, "approval_mismatch"))),
        "protocol reused approval across policy revision"
    );
    assert_eq!(effects(&h), [0, 0, 0]);
}

#[tokio::test]
async fn approval_owns_phase_until_complete_then_deny_replay_and_collect_refuse() {
    let h = enabled().await;
    let (created, view) = awaiting(&h).await;
    let s = session(&h, &created);
    let locked = h.db.lock().unwrap();
    let id = created["request_id"].as_str().unwrap().to_owned();
    let service = h.service.clone();
    let request = approval(&view);
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        tx.send(service.approve_device(&id, request)).unwrap();
    });
    wait_for_approval_lock(&s);
    let service = h.service.clone();
    let id = created["request_id"].as_str().unwrap().to_owned();
    let (dtx, drx) = std::sync::mpsc::channel();
    let (entered, queued) = std::sync::mpsc::channel();
    let deny = std::thread::spawn(move || {
        entered.send(()).unwrap();
        dtx.send(service.deny_device(&id)).unwrap();
    });
    bounded_result(queued);
    drop(locked);
    assert!(bounded_result(rx).is_ok(), "approved SQL winner refused");
    assert!(
        bounded_result(drx).is_err(),
        "late denial overwrote completed issuance"
    );
    join_worker(worker);
    join_worker(deny);
    assert!(
        h.service
            .approve_device(created["request_id"].as_str().unwrap(), approval(&view))
            .is_err(),
        "protocol approval replay issued again"
    );
    assert_eq!(
        effects(&h),
        [1, 1, 1],
        "approval race wrote more than one result"
    );
    let (status, issued) = h
        .request(
            "GET",
            "/enroll/v1/sessions?wait=0",
            Value::Null,
            Some(created["session"].as_str().unwrap()),
            1,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        issued["cert_chain_pem"].is_string(),
        "late deny destroyed collectable certificate"
    );
    assert_eq!(
        h.request(
            "GET",
            "/enroll/v1/sessions?wait=0",
            Value::Null,
            Some(created["session"].as_str().unwrap()),
            1
        )
        .await
        .0,
        StatusCode::GONE,
        "protocol collect replay succeeded"
    );
}

#[tokio::test]
async fn denial_wins_before_approval_without_authority_effects() {
    let h = enabled().await;
    let (created, view) = awaiting(&h).await;
    let id = created["request_id"].as_str().unwrap();
    assert!(h.service.deny_device(id).is_ok());
    assert!(
        h.service.approve_device(id, approval(&view)).is_err(),
        "denied request later issued"
    );
    assert_eq!(effects(&h), [0, 0, 0]);
}

#[tokio::test]
async fn service_drop_cancels_pending_and_restart_has_no_approval() {
    let h = enabled().await;
    let (status, created, _) = start(&h, "remote", 1).await;
    assert_eq!(status, StatusCode::CREATED);
    let s = session(&h, &created);
    tokio::task::yield_now().await;
    let before = h.idp.request_paths();
    let ca = h.service.ca.clone();
    let fed = h.service.fed.clone();
    let entry = h.service.hub_entry.clone();
    let identity = h.service.ca_identity.clone();
    let Harness {
        service,
        idp,
        db,
        clock,
        _directory,
    } = h;
    let weak = Arc::downgrade(&service);
    drop(service);
    assert!(
        weak.upgrade().is_none(),
        "poller retained authority service after drop"
    );
    assert!(
        s.cancelled.load(Ordering::Acquire),
        "service drop did not cancel device session"
    );
    assert!(
        !s.device_active.load(Ordering::Acquire),
        "service drop retained device permit"
    );
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        idp.request_paths(),
        before,
        "service drop left provider polling active"
    );
    let restarted = Arc::new(Service::with_oidc_http(
        ca,
        fed,
        clock,
        entry,
        identity,
        idp.http_client(),
    ));
    restarted.register_local_approval().unwrap();
    assert!(restarted.pending_device_requests().is_empty());
    assert!(
        restarted
            .deny_device(created["request_id"].as_str().unwrap())
            .is_err(),
        "restart retained pending approval"
    );
    let database = db.lock().unwrap();
    for table in ["enroll_bindings", "enroll_rates", "enroll_certs"] {
        assert_eq!(
            database
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0,
            "restart persisted pending authority effects"
        );
    }
}

#[tokio::test]
#[ignore = "isolated trace subscriber invoked by device_trace_and_every_sqlite_column_exclude_secrets"]
async fn device_secret_census_child() {
    let output = TraceBytes(Arc::new(Mutex::new(Vec::new())));
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .without_time()
            .with_ansi(false)
            .with_writer(output.clone())
            .finish(),
    )
    .unwrap();
    tracing::debug!(public_control = "device-invariant-trace-positive-control");
    let h = enabled().await;
    let mut secrets = h.idp.secret_values();
    let (created, view) = awaiting(&h).await;
    secrets.extend(h.idp.secret_values());
    assert!(
        secrets
            .iter()
            .any(|value| value.starts_with("fixture-device-")),
        "raw device-code census positive control missing"
    );
    secrets.push(created["request_id"].as_str().unwrap().to_owned());
    secrets.push(created["session"].as_str().unwrap().to_owned());
    secrets.push(created["user_code"].as_str().unwrap().to_owned());
    assert!(h
        .service
        .approve_device(created["request_id"].as_str().unwrap(), approval(&view))
        .is_ok());
    assert_eq!(effects(&h), [1, 1, 1]);
    let trace = output.0.lock().unwrap().clone();
    assert!(
        trace
            .windows(b"device-invariant-trace-positive-control".len())
            .any(|v| v == b"device-invariant-trace-positive-control"),
        "device trace positive control missing"
    );
    let database = every_database_column(&h.db.lock().unwrap());
    assert!(!database.is_empty());
    for secret in secrets {
        assert!(!secret.is_empty());
        assert!(
            !trace.windows(secret.len()).any(|v| v == secret.as_bytes()),
            "device trace leaked transient secret"
        );
        assert!(
            !database
                .iter()
                .any(|bytes| bytes.windows(secret.len()).any(|v| v == secret.as_bytes())),
            "device SQLite column stored transient secret"
        );
    }
    println!("device-invariant-secret-census:complete");
}
#[test]
fn device_trace_and_every_sqlite_column_exclude_secrets() {
    use std::process::{Command, Stdio};
    let name = format!(
        "{}::device_secret_census_child",
        module_path!().split_once("::").unwrap().1
    );
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--ignored", "--nocapture"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("device census child timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let result = child.wait_with_output().unwrap();
    let diagnostic = String::from_utf8_lossy(&result.stdout).into_owned()
        + &String::from_utf8_lossy(&result.stderr);
    let reason = if diagnostic.contains("device trace leaked transient secret") {
        "device trace leaked transient secret"
    } else if diagnostic.contains("device SQLite column stored transient secret") {
        "device SQLite column stored transient secret"
    } else {
        "unclassified child failure"
    };
    assert!(
        result.status.success(),
        "device secret census child failed: {reason}"
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("device-invariant-secret-census:complete"),
        "device census completion missing"
    );
}

#[tokio::test]
async fn completed_device_approval_cannot_issue_twice() {
    let h = enabled().await;
    let (created, view) = awaiting(&h).await;
    let id = created["request_id"].as_str().unwrap();
    assert!(h.service.approve_device(id, approval(&view)).is_ok());
    assert!(
        h.service.approve_device(id, approval(&view)).is_err(),
        "completed approval replay issued another certificate"
    );
    assert_eq!(effects(&h), [1, 1, 1]);
}

fn collect_on_thread(service: Arc<Service>, handle: String) -> (StatusCode, Value) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let request = Request::builder()
                .uri("/enroll/v1/sessions?wait=0")
                .header("xmsg-enroll-session", handle)
                .body(Body::empty())
                .unwrap();
            let response = router(service).oneshot(request).await.unwrap();
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 131072).await.unwrap();
            (status, serde_json::from_slice(&bytes).unwrap())
        })
}
#[tokio::test]
async fn queued_collectors_behind_approval_have_one_certificate_result() {
    let h = enabled().await;
    let (created, view) = awaiting(&h).await;
    let s = session(&h, &created);
    let locked = h.db.lock().unwrap();
    let service = h.service.clone();
    let id = created["request_id"].as_str().unwrap().to_owned();
    let (tx, rx) = std::sync::mpsc::channel();
    let approve = std::thread::spawn(move || {
        tx.send(service.approve_device(&id, approval(&view)))
            .unwrap();
    });
    wait_for_approval_lock(&s);
    assert_eq!(
        Arc::strong_count(&s),
        3,
        "collector owner baseline control failed"
    );
    let mut collectors = Vec::new();
    for _ in 0..2 {
        let service = h.service.clone();
        let handle = created["session"].as_str().unwrap().to_owned();
        let (entered, queued) = std::sync::mpsc::channel();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            entered.send(()).unwrap();
            tx.send(collect_on_thread(service, handle)).unwrap();
        });
        bounded_result(queued);
        collectors.push((worker, rx));
    }
    let limit = std::time::Instant::now() + Duration::from_secs(10);
    while Arc::strong_count(&s) != 5 {
        assert!(
            std::time::Instant::now() < limit,
            "collectors did not clone session before SQL release"
        );
        std::thread::yield_now();
    }
    drop(locked);
    assert!(
        bounded_result(rx).is_ok(),
        "approval lost to queued collector"
    );
    join_worker(approve);
    let mut certificates = 0;
    let mut gone = 0;
    for (worker, rx) in collectors {
        let (status, result) = bounded_result(rx);
        join_worker(worker);
        if status == StatusCode::OK && result["cert_chain_pem"].is_string() {
            certificates += 1;
        }
        if status == StatusCode::GONE {
            gone += 1;
        }
    }
    assert_eq!(
        certificates, 1,
        "queued collectors received duplicate or missing certificate result"
    );
    assert_eq!(gone, 1, "queued collect loser was not terminal");
    assert_eq!(effects(&h), [1, 1, 1]);
}

#[tokio::test]
async fn restart_loses_verified_awaiting_approval_without_authority_writes() {
    let h = enabled().await;
    let (created, view) = awaiting(&h).await;
    assert_eq!(h.service.pending_device_requests().len(), 1);
    let ca = h.service.ca.clone();
    let fed = h.service.fed.clone();
    let entry = h.service.hub_entry.clone();
    let identity = h.service.ca_identity.clone();
    let Harness {
        service,
        idp,
        db,
        clock,
        _directory,
    } = h;
    drop(service);
    let restarted = Arc::new(Service::with_oidc_http(
        ca,
        fed,
        clock,
        entry,
        identity,
        idp.http_client(),
    ));
    restarted.register_local_approval().unwrap();
    assert!(
        restarted.pending_device_requests().is_empty(),
        "restart recovered transient verified approval"
    );
    assert!(
        restarted
            .approve_device(created["request_id"].as_str().unwrap(), approval(&view))
            .is_err(),
        "restart accepted old verified approval"
    );
    let db = db.lock().unwrap();
    for table in ["enroll_bindings", "enroll_rates", "enroll_certs"] {
        assert_eq!(
            db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0,
            "restart wrote pending verified authority state"
        );
    }
}

#[tokio::test]
async fn terminal_projection_denial_releases_device_permit_without_eviction() {
    let h = enabled().await;
    let (status, created, _) = start(&h, "remote", 1).await;
    assert_eq!(status, StatusCode::CREATED);
    let s = session(&h, &created);
    let mut policy = (*h.service.ca.policy()).clone();
    policy.deny.users.push("alice".into());
    std::fs::write(
        h._directory.path().join("policy.json"),
        serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    assert!(h
        .idp
        .authorize_device(created["user_code"].as_str().unwrap()));
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if matches!(&*s.phase.lock().unwrap(), Phase::Complete(Err(error)) if error.reason == "denied") { break; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await.unwrap();
    assert!(
        !s.device_active.load(Ordering::Acquire),
        "terminal failure retained active device permit"
    );
    assert_eq!(effects(&h), [0, 0, 0]);
    assert_eq!(
        start(&h, "remote", 1).await.0,
        StatusCode::CREATED,
        "terminal failure did not release source-IP permit"
    );
    assert_eq!(
        h.service.sessions.lock().unwrap().len(),
        2,
        "terminal failure evicted common pending record"
    );
}

fn every_database_column(connection: &rusqlite::Connection) -> Vec<Vec<u8>> {
    let mut schemas = connection
        .prepare("PRAGMA database_list")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    if !schemas.iter().any(|name| name == "temp") {
        schemas.push("temp".into());
    }
    let mut values = Vec::new();
    for schema in schemas {
        let schema = schema.replace('"', "\"\"");
        let mut names = connection
            .prepare(&format!(
                "SELECT name FROM \"{schema}\".sqlite_schema WHERE type='table'"
            ))
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        names.push("sqlite_schema".into());
        for name in names {
            let mut statement = connection
                .prepare(&format!(
                    "SELECT * FROM \"{schema}\".\"{}\"",
                    name.replace('"', "\"\"")
                ))
                .unwrap();
            let columns = statement.column_count();
            let mut rows = statement.query([]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                for column in 0..columns {
                    use rusqlite::types::ValueRef;
                    match row.get_ref(column).unwrap() {
                        ValueRef::Text(value) | ValueRef::Blob(value) => {
                            values.push(value.to_vec())
                        }
                        ValueRef::Integer(value) => values.push(value.to_string().into_bytes()),
                        ValueRef::Real(value) => values.push(value.to_string().into_bytes()),
                        ValueRef::Null => {}
                    }
                }
            }
        }
    }
    values
}

struct PolicyFifo {
    path: PathBuf,
    bytes: Vec<u8>,
    release: Option<std::sync::mpsc::Sender<()>>,
    done: std::sync::mpsc::Receiver<Result<(), ()>>,
    worker: Option<std::thread::JoinHandle<()>>,
    restored: bool,
}
impl PolicyFifo {
    fn new(path: PathBuf) -> (Self, std::sync::mpsc::Receiver<()>) {
        use std::io::Write;
        use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(name.as_ptr(), 0o600) },
            0,
            "private policy FIFO creation failed"
        );
        let (release, released) = std::sync::mpsc::channel();
        let (arrived, reader) = std::sync::mpsc::channel();
        let (finished, done) = std::sync::mpsc::channel();
        let file_path = path.clone();
        let policy = bytes.clone();
        let worker = std::thread::spawn(move || {
            let result = (|| -> Result<(), ()> {
                let limit = std::time::Instant::now() + Duration::from_secs(30);
                let mut file = loop {
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .custom_flags(libc::O_NONBLOCK)
                        .open(&file_path)
                    {
                        Ok(file) => break file,
                        Err(error)
                            if error.raw_os_error() == Some(libc::ENXIO)
                                && std::time::Instant::now() < limit =>
                        {
                            std::thread::sleep(Duration::from_millis(1))
                        }
                        Err(_) => return Err(()),
                    }
                };
                arrived.send(()).map_err(|_| ())?;
                released
                    .recv_timeout(Duration::from_secs(30))
                    .map_err(|_| ())?;
                file.write_all(&policy).map_err(|_| ())?;
                Ok(())
            })();
            let _ = finished.send(result);
        });
        (
            Self {
                path,
                bytes,
                release: Some(release),
                done,
                worker: Some(worker),
                restored: false,
            },
            reader,
        )
    }
    fn restore(&mut self) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::remove_file(&self.path)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.path)?;
        file.write_all(&self.bytes)?;
        self.restored = true;
        Ok(())
    }
    fn finish(&mut self) {
        self.release
            .take()
            .unwrap()
            .send(())
            .expect("policy FIFO release failed");
        let result = self
            .done
            .recv_timeout(Duration::from_secs(30))
            .expect("policy FIFO writer timed out");
        join_worker(self.worker.take().unwrap());
        self.restore().expect("policy FIFO restoration failed");
        assert!(result.is_ok(), "policy FIFO writer failed");
    }
}
impl Drop for PolicyFifo {
    fn drop(&mut self) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        if self.restored {
            return;
        }
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        let mut keeper = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&self.path)
            .ok();
        if let Some(file) = &mut keeper {
            let _ = file.write_all(&self.bytes);
        }
        if self.done.recv_timeout(Duration::from_secs(35)).is_ok() {
            if let Some(worker) = self.worker.take() {
                if thread_finished(&worker) {
                    let _ = worker.join();
                }
            }
        }
        drop(keeper);
        let _ = self.restore();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn denied_device_cannot_be_resurrected_by_verified_claim_publication() {
    let h = enabled().await;
    let (status, created, _) = start(&h, "remote", 1).await;
    assert_eq!(status, StatusCode::CREATED);
    let s = session(&h, &created);
    let (mut policy, reader) = PolicyFifo::new(h._directory.path().join("policy.json"));
    assert!(h
        .idp
        .authorize_device(created["user_code"].as_str().unwrap()));
    reader
        .recv_timeout(Duration::from_secs(30))
        .expect("verified policy-reader handshake timed out");
    assert_eq!(
        Arc::strong_count(&s),
        3,
        "poll producer owner baseline control failed"
    );
    assert!(h
        .service
        .deny_device(created["request_id"].as_str().unwrap())
        .is_ok());
    policy.finish();
    assert!(
        std::fs::read(&policy.path).unwrap() == policy.bytes,
        "policy FIFO restoration changed policy"
    );
    tokio::time::timeout(Duration::from_secs(30), async {
        while Arc::strong_count(&s) != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("known poll producer completion timed out");
    assert!(
        !h.service.ca.reload_status().degraded,
        "policy FIFO did not deliver valid policy"
    );
    let (status, result) = h
        .request(
            "GET",
            "/enroll/v1/sessions?wait=0",
            Value::Null,
            Some(created["session"].as_str().unwrap()),
            1,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        result["error"]["reason"], "access_denied",
        "denied device request was resurrected by late publication"
    );
    assert_eq!(
        effects(&h),
        [0, 0, 0],
        "late publication wrote authority state"
    );
}

#[tokio::test]
async fn approved_completion_releases_device_permit_before_certificate_collection() {
    let h = enabled().await;
    let (created, view) = awaiting(&h).await;
    assert!(h
        .service
        .approve_device(created["request_id"].as_str().unwrap(), approval(&view))
        .is_ok());
    let first = session(&h, &created);
    assert!(
        matches!(*first.phase.lock().unwrap(), Phase::Complete(Ok(_))),
        "issued certificate was not awaiting collection"
    );
    assert_eq!(effects(&h), [1, 1, 1]);
    let (status, replacement, _) = start(&h, "replacement", 1).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "approved completion did not release source-IP permit before collect"
    );
    assert_eq!(
        h.service.sessions.lock().unwrap().len(),
        2,
        "permit release evicted uncollected certificate record"
    );
    assert!(matches!(
        *first.phase.lock().unwrap(),
        Phase::Complete(Ok(_))
    ));
    assert!(h
        .service
        .deny_device(replacement["request_id"].as_str().unwrap())
        .is_ok());
    assert_eq!(
        effects(&h),
        [1, 1, 1],
        "unapproved replacement wrote authority state"
    );
    let (status, result) = h
        .request(
            "GET",
            "/enroll/v1/sessions?wait=0",
            Value::Null,
            Some(created["session"].as_str().unwrap()),
            1,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(result["cert_chain_pem"].is_string());
}
