use super::*;
use std::sync::{atomic::AtomicUsize, Condvar};

struct DiscoveryState {
    entered: AtomicUsize,
    timed_out: AtomicBool,
    released: Mutex<bool>,
    changed: Condvar,
    arrived: Notify,
}
struct DiscoveryGate(Arc<DiscoveryState>);
impl DiscoveryGate {
    fn install(h: &Harness) -> Self {
        let state = Arc::new(DiscoveryState {
            entered: AtomicUsize::new(0),
            timed_out: AtomicBool::new(false),
            released: Mutex::new(false),
            changed: Condvar::new(),
            arrived: Notify::new(),
        });
        let callback = state.clone();
        h.idp.set_before_discovery_hook(Some(Arc::new(move || {
            callback.entered.fetch_add(1, Ordering::SeqCst);
            callback.arrived.notify_waiters();
            let released = callback.released.lock().unwrap();
            let (released, elapsed) = callback
                .changed
                .wait_timeout_while(released, Duration::from_secs(4), |released| !*released)
                .unwrap();
            if elapsed.timed_out() && !*released {
                callback.timed_out.store(true, Ordering::SeqCst);
            }
        })));
        Self(state)
    }
    fn release(&self) {
        *self
            .0
            .released
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = true;
        self.0.changed.notify_all();
    }
    async fn arrived(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let notified = self.0.arrived.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.0.entered.load(Ordering::SeqCst) >= count {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("discovery arrival barrier timed out");
    }
}
impl Drop for DiscoveryGate {
    fn drop(&mut self) {
        self.release();
    }
}
struct StartTask(tokio::task::JoinHandle<()>);
impl StartTask {
    async fn finish(mut self) {
        tokio::time::timeout(Duration::from_secs(3), &mut self.0)
            .await
            .expect("reservation contender completion timed out")
            .expect("reservation contender panicked");
    }
}
impl Drop for StartTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn contend(
    h: Arc<Harness>,
    ips: [u8; 2],
    initial: usize,
    cap_reason: &str,
) -> ((usize, usize), usize) {
    let mut tasks = Vec::new();
    let gate = DiscoveryGate::install(&h);
    let first = Arc::new(tokio::sync::Barrier::new(3));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    for (number, ip) in ips.into_iter().enumerate() {
        let h = h.clone();
        let first = first.clone();
        let tx = tx.clone();
        tasks.push(StartTask(tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(3), first.wait())
                .await
                .expect("reservation start barrier timed out");
            let (status, response, _) = start(&h, &format!("contender-{number}"), ip).await;
            assert!(
                tx.send((status, response)).is_ok(),
                "reservation result receiver disappeared"
            );
        })));
    }
    drop(tx);
    tokio::time::timeout(Duration::from_secs(3), first.wait())
        .await
        .expect("reservation controller start barrier timed out");
    let mut results = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let notified = gate.0.arrived.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if gate.0.entered.load(Ordering::SeqCst) >= 2 {
                return;
            }
            tokio::select! {
                _ = &mut notified => {},
                result = rx.recv() => {
                    results.push(result.expect("both reservation contenders disappeared"));
                    return;
                },
            }
        }
    })
    .await
    .expect("reservation check/discovery interleaving timed out");
    gate.arrived(1).await;
    let held_arrivals = gate.0.entered.load(Ordering::SeqCst);
    gate.release();
    while results.len() != 2 {
        results.push(
            tokio::time::timeout(Duration::from_secs(3), rx.recv())
                .await
                .expect("reservation response timed out")
                .expect("reservation response producer disappeared"),
        );
    }
    for task in tasks.drain(..) {
        task.finish().await;
    }
    h.idp.set_before_discovery_hook(None);
    assert!(
        !gate.0.timed_out.load(Ordering::SeqCst),
        "discovery gate timed out instead of forcing interleaving"
    );
    assert!(
        results.iter().all(|(status, _)| matches!(
            *status,
            StatusCode::CREATED | StatusCode::TOO_MANY_REQUESTS
        )),
        "reservation provider failed before admission outcome"
    );
    for (status, response) in &results {
        if *status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(
                response["error"]["reason"], cap_reason,
                "reservation refusal was not the targeted active cap"
            );
        }
    }
    let created = results
        .iter()
        .filter(|(status, _)| *status == StatusCode::CREATED)
        .count();
    let refused = results
        .iter()
        .filter(|(status, _)| *status == StatusCode::TOO_MANY_REQUESTS)
        .count();
    assert_eq!(
        held_arrivals, created,
        "discovery handshake did not account for admitted contenders"
    );
    let requests = {
        let sessions = h.service.sessions.lock().unwrap();
        assert_eq!(
            sessions.len(),
            initial + created,
            "reservation replies did not match retained records"
        );
        assert_eq!(
            sessions
                .values()
                .filter(|s| s.device_active.load(Ordering::Acquire))
                .count(),
            initial + created
        );
        assert!(
            sessions.len() <= 64,
            "common 64-record cap interfered with device race"
        );
        for session in sessions.values() {
            assert!(
                sessions
                    .values()
                    .filter(|other| other.ip == session.ip)
                    .count()
                    <= 4,
                "common four-record IP cap interfered with device race"
            );
        }
        sessions
            .values()
            .map(|session| session.request_id.clone().unwrap())
            .collect::<Vec<_>>()
    };
    for request in requests {
        assert!(
            h.service.deny_device(&request).is_ok(),
            "reservation cleanup denial failed"
        );
    }
    assert_eq!(
        effects(&h),
        [0, 0, 0],
        "unauthorized reservation race wrote authority state"
    );
    assert!(
        h.service
            .sessions
            .lock()
            .unwrap()
            .values()
            .all(|s| !s.device_active.load(Ordering::Acquire)),
        "reservation cleanup retained active permit"
    );
    ((created, refused), held_arrivals)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_same_ip_reservations_admit_exactly_one() {
    let h = Arc::new(enabled().await);
    let (outcomes, _) = contend(h, [1, 1], 0, "device_pending_per_ip").await;
    assert_eq!(
        outcomes,
        (1, 1),
        "concurrent same-IP reservation leaked the single active slot"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_global_reservations_admit_only_the_eighth() {
    let h = Arc::new(enabled().await);
    for ip in 1..=7 {
        let (status, _, _) = start(&h, "existing", ip).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "seven-active global reservation control failed"
        );
    }
    assert_eq!(
        h.service
            .sessions
            .lock()
            .unwrap()
            .values()
            .filter(|s| s.device_active.load(Ordering::Acquire))
            .count(),
        7
    );
    let (outcomes, _) = contend(h, [8, 9], 7, "device_pending_full").await;
    assert_eq!(
        outcomes,
        (1, 1),
        "concurrent global reservation leaked the eighth active slot"
    );
}
