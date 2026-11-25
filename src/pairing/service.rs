//! Pairing service controls, startup-cancel retry, monotonic intent timers, and diagnostics (§5.2–§5.4).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use rusqlite::Connection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::Serialize;
use tokio::sync::Notify;
use tokio_rustls::TlsConnector;

use super::auth::{DeviceId, GrantId};
use super::budgets::{
    PairingBudgets, PairingError, MAX_INBOUND_STARTS_PER_MIN, MAX_OUTBOUND_STARTS_PER_MIN,
    OUTBOUND_PROBE_TIMEOUT,
};
use super::ceremony::{
    build_pairing_client_config, ed25519_device_id_from_cert, ed25519_keypair_from_der,
    execute_initiator_exchange, execute_responder_exchange, export_pairing_keying_material,
    spki_der_from_cert, unix_now_u32, InitiatorInputs, LiveCeremonySlots, ResponderInputs,
    PAIRING_ALPN,
};
use super::codec::{
    ExposurePolicy, Offer, PairingProfile, ReceiptVerificationContext, SpkiDeviceId,
    MAX_CEREMONY_WINDOW_SECS,
};
use super::store::{
    self, IntentRequest, StoreError, VerifiedReceipts, MAX_MANUAL_GRANTS, MAX_PENDING_INTENTS,
};
use crate::fed::{CredentialReloader, FedState};

/// Process-wide registry mapping each `FedState` (by its DB `Arc`) to its `PairingRuntime`,
/// avoiding structural churn across `FedState` literals in existing tests.
pub struct PairingRuntime {
    pub service: Arc<PairingService>,
    reloader: Mutex<Option<Weak<CredentialReloader>>>,
    #[cfg(any(test, feature = "test-hooks"))]
    before_permit_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(any(test, feature = "test-hooks"))]
    test_now: Mutex<Option<i64>>,
}

impl Default for PairingRuntime {
    fn default() -> Self {
        Self {
            service: Arc::new(PairingService::new()),
            reloader: Mutex::new(None),
            #[cfg(any(test, feature = "test-hooks"))]
            before_permit_hook: Mutex::new(None),
            #[cfg(any(test, feature = "test-hooks"))]
            test_now: Mutex::new(None),
        }
    }
}

#[cfg(any(test, feature = "test-hooks"))]
pub fn set_before_permit_hook(
    fs: &FedState,
    hook: Option<Arc<dyn Fn() + Send + Sync>>,
) {
    *pairing_runtime(fs).before_permit_hook.lock().unwrap() = hook;
}

#[cfg(any(test, feature = "test-hooks"))]
pub(crate) fn run_before_permit_hook(fs: &FedState) {
    let hook = pairing_runtime(fs).before_permit_hook.lock().unwrap().clone();
    if let Some(h) = hook {
        h();
    }
}

#[cfg(any(test, feature = "test-hooks"))]
pub fn set_test_now_override(fs: &FedState, now: Option<i64>) {
    *pairing_runtime(fs).test_now.lock().unwrap() = now;
}

#[cfg(any(test, feature = "test-hooks"))]
pub(crate) fn test_now_override(fs: &FedState) -> Option<i64> {
    *pairing_runtime(fs).test_now.lock().unwrap()
}

pub fn pairing_runtime(fs: &FedState) -> Arc<PairingRuntime> {
    type Registry = Vec<(Weak<Mutex<Connection>>, Arc<PairingRuntime>)>;
    static RUNTIMES: OnceLock<Mutex<Registry>> = OnceLock::new();
    let mut reg = RUNTIMES.get_or_init(Mutex::default).lock().unwrap();
    reg.retain(|(db, _)| db.strong_count() > 0);
    if let Some((_, rt)) = reg.iter().find(|(db, _)| db.ptr_eq(&Arc::downgrade(&fs.db))) {
        return rt.clone();
    }
    let rt = Arc::new(PairingRuntime::default());
    reg.push((Arc::downgrade(&fs.db), rt.clone()));
    rt
}

pub fn set_fed_listen(fs: &FedState, enabled: bool) {
    pairing_runtime(fs).service.set_fed_listen(enabled);
}

pub fn attach_reloader(fs: &FedState, reloader: &Arc<CredentialReloader>) {
    let rt = pairing_runtime(fs);
    *rt.reloader.lock().unwrap() = Some(Arc::downgrade(reloader));
}

pub(crate) fn reloader_for(fs: &FedState) -> Option<Arc<CredentialReloader>> {
    pairing_runtime(fs)
        .reloader
        .lock()
        .unwrap()
        .as_ref()
        .and_then(Weak::upgrade)
}

impl FedState {
    pub fn own_cert_der(&self) -> Option<Vec<u8>> {
        let guard = self.dynamic_tls.read().unwrap_or_else(|e| e.into_inner());
        if let Some(ref tls) = *guard {
            if !tls.cert_der.is_empty() {
                return Some(tls.cert_der.clone());
            }
        }
        if !self.cert_der.is_empty() {
            Some(self.cert_der.clone())
        } else {
            None
        }
    }

    pub fn own_key_der(&self) -> Option<PrivateKeyDer<'static>> {
        let guard = self.dynamic_tls.read().unwrap_or_else(|e| e.into_inner());
        if let Some(ref tls) = *guard {
            if !tls.key_der.is_empty() {
                return PrivateKeyDer::try_from(tls.key_der.clone()).ok();
            }
        }
        if !self.key_der.is_empty() {
            PrivateKeyDer::try_from(self.key_der.clone()).ok()
        } else {
            None
        }
    }

    pub fn open_mdns_announce_window(&self) {
        let _ = crate::discovery::trigger_announce(self);
    }

    pub fn close_mdns_announce_window(&self) {
        let _ = crate::discovery::close_announce(self);
    }

    pub async fn publish_pairing_update(&self, committed_rev: u64) -> Result<u64, PairingError> {
        let Some(reloader) = reloader_for(self) else {
            return Ok(self.current_peers().authority_revision);
        };
        let res = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::task::spawn_blocking(move || {
                let pub_res = reloader.publish_store();
                (pub_res, reloader.installed_revision())
            }),
        )
        .await;
        match res {
            Ok(Ok((Ok(_), installed))) if installed >= committed_rev => Ok(installed),
            Ok(Ok((Ok(_), installed))) => Err(PairingError::ReloadFailed {
                committed_revision: committed_rev,
                installed_revision: installed,
                error: "installed revision remained behind committed revision".to_string(),
            }),
            Ok(Ok((Err(e), installed))) => Err(PairingError::ReloadFailed {
                committed_revision: committed_rev,
                installed_revision: installed,
                error: e.to_string(),
            }),
            Ok(Err(e)) => Err(PairingError::ReloadFailed {
                committed_revision: committed_rev,
                installed_revision: self.current_peers().authority_revision,
                error: e.to_string(),
            }),
            Err(_) => {
                let installed = self.current_peers().authority_revision;
                Err(PairingError::ReloadFailed {
                    committed_revision: committed_rev,
                    installed_revision: installed,
                    error: "publication wait timed out after 10s".to_string(),
                })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentRole {
    Responder,
    Initiator,
}

#[derive(Clone, Debug)]
pub struct LiveIntent {
    pub intent_id: [u8; 16],
    pub grant_id: GrantId,
    pub peer_id: DeviceId,
    pub role: IntentRole,
    pub exposure: ExposurePolicy,
    pub grant_not_after: Option<i64>,
    pub deadline: tokio::time::Instant,
    pub start_mono_secs: u64,
    pub cancel_notify: Arc<Notify>,
    pub completion: Arc<Mutex<Option<Result<ActivationSummary, PairingError>>>>,
    pub done_notify: Arc<Notify>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActivationSummary {
    pub grant_id: String,
    pub peer_id: String,
    pub committed_revision: u64,
    pub installed_revision: u64,
    pub committed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct MutationOutcome {
    pub committed: bool,
    pub committed_revision: u64,
    pub installed_revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub struct PairingService {
    pub budgets: PairingBudgets,
    pub ceremony_slots: LiveCeremonySlots,
    startup_cancel_done: AtomicBool,
    fed_listen_enabled: AtomicBool,
    startup_cancel_error: Mutex<Option<String>>,
    live_intents: Mutex<HashMap<[u8; 16], LiveIntent>>,
    mono_epoch: Instant,
    #[cfg(any(test, feature = "test-hooks"))]
    pub test_inject_startup_cancel_fail: AtomicBool,
}

impl Default for PairingService {
    fn default() -> Self {
        Self::new()
    }
}

impl PairingService {
    pub fn new() -> Self {
        Self {
            budgets: PairingBudgets::default(),
            ceremony_slots: LiveCeremonySlots::default(),
            startup_cancel_done: AtomicBool::new(false),
            fed_listen_enabled: AtomicBool::new(false),
            startup_cancel_error: Mutex::new(None),
            live_intents: Mutex::new(HashMap::new()),
            mono_epoch: Instant::now(),
            #[cfg(any(test, feature = "test-hooks"))]
            test_inject_startup_cancel_fail: AtomicBool::new(false),
        }
    }

    pub fn set_fed_listen(&self, enabled: bool) {
        self.fed_listen_enabled.store(enabled, Ordering::SeqCst);
    }

    pub fn has_fed_listen(&self) -> bool {
        self.fed_listen_enabled.load(Ordering::SeqCst)
    }

    pub fn mono_secs(&self) -> u64 {
        self.mono_epoch.elapsed().as_secs()
    }

    pub fn is_startup_cancel_done(&self) -> bool {
        self.startup_cancel_done.load(Ordering::SeqCst)
    }

    pub fn startup_cancel_error(&self) -> Option<String> {
        self.startup_cancel_error.lock().unwrap().clone()
    }

    /// Cancels every open intent in the store before the pairing listener opens (§5.3).
    /// Only sets `startup_cancel_done` AFTER the store transaction commits (carry-in N1).
    pub fn attempt_startup_cancel(&self, fed: &FedState) -> Result<usize, PairingError> {
        #[cfg(any(test, feature = "test-hooks"))]
        if self.test_inject_startup_cancel_fail.load(Ordering::SeqCst) {
            let msg = "injected startup-cancel transaction failure".to_string();
            *self.startup_cancel_error.lock().unwrap() = Some(msg.clone());
            self.startup_cancel_done.store(false, Ordering::SeqCst);
            return Err(PairingError::StartupCancelFailed(msg));
        }

        let res = {
            let db = fed.db.lock().unwrap_or_else(|e| e.into_inner());
            store::cancel_open_intents(&db)
        };
        match res {
            Ok(n) => {
                *self.startup_cancel_error.lock().unwrap() = None;
                self.startup_cancel_done.store(true, Ordering::SeqCst);
                Ok(n)
            }
            Err(e) => {
                let msg = e.to_string();
                *self.startup_cancel_error.lock().unwrap() = Some(msg.clone());
                self.startup_cancel_done.store(false, Ordering::SeqCst);
                Err(PairingError::StartupCancelFailed(msg))
            }
        }
    }

    pub fn has_live_responder_intent(&self) -> bool {
        if !self.is_startup_cancel_done() {
            return false;
        }
        let now = tokio::time::Instant::now();
        let guard = self.live_intents.lock().unwrap();
        guard
            .values()
            .any(|i| i.role == IntentRole::Responder && i.deadline > now)
    }

    pub fn has_live_responder_intent_for(&self, peer_id: &DeviceId) -> bool {
        if !self.is_startup_cancel_done() {
            return false;
        }
        let now = tokio::time::Instant::now();
        let guard = self.live_intents.lock().unwrap();
        guard
            .values()
            .any(|i| i.role == IntentRole::Responder && &i.peer_id == peer_id && i.deadline > now)
    }

    pub fn find_live_responder_intent(&self, peer_id: &DeviceId) -> Option<LiveIntent> {
        let now = tokio::time::Instant::now();
        let guard = self.live_intents.lock().unwrap();
        guard
            .values()
            .find(|i| i.role == IntentRole::Responder && &i.peer_id == peer_id && i.deadline > now)
            .cloned()
    }

    /// Own canonical `xmsg-spki1:...` device ID, or `pairing.key_algorithm` on a P-256 node (§5.2).
    pub fn own_device_id(&self, fed: &FedState) -> Result<SpkiDeviceId, PairingError> {
        let cert_der = fed.own_cert_der().ok_or_else(|| {
            PairingError::KeyAlgorithm("no federation certificate configured".into())
        })?;
        ed25519_device_id_from_cert(&cert_der)
    }

    fn map_store_error(err: StoreError) -> PairingError {
        match err {
            StoreError::PendingFull => PairingError::IntentsFull(err.to_string()),
            StoreError::GrantsFull => PairingError::GrantsFull(err.to_string()),
            StoreError::Blocked => PairingError::PeerRefused(err.to_string()),
            StoreError::WouldRestore(reasons) => {
                PairingError::UnblockWouldRestore(reasons.join("; "))
            }
            StoreError::IntentUnavailable => PairingError::Expired(err.to_string()),
            StoreError::Removed => PairingError::NotFound(err.to_string()),
            other => PairingError::Internal(other.to_string()),
        }
    }

    /// Creates or reconfirms a responder (`accept`) or initiator (`start`) intent.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_intent(
        self: &Arc<Self>,
        fed: &Arc<FedState>,
        peer_id_str: &str,
        role: IntentRole,
        profile: PairingProfile,
        targets: Vec<String>,
        principals: Vec<String>,
        grant_not_after: Option<i64>,
    ) -> Result<(LiveIntent, bool), PairingError> {
        // Carry-in N2: retry startup cancel at the start of every accept/start.
        if !self.is_startup_cancel_done() {
            self.attempt_startup_cancel(fed)?;
        }
        let own_id = self.own_device_id(fed)?;
        let peer_id = SpkiDeviceId::parse_device_id_string(peer_id_str)
            .map_err(|e| PairingError::InvalidDeviceId(e.to_string()))?;
        if peer_id == own_id {
            return Err(PairingError::InvalidDeviceId(
                "cannot pair with own device ID".into(),
            ));
        }

        let target_selectors = match profile {
            PairingProfile::Contact => {
                if targets.is_empty() {
                    return Err(PairingError::TargetsRequired(
                        "contact profile requires at least one --target".into(),
                    ));
                }
                let mut sorted = targets;
                sorted.sort();
                sorted.dedup();
                sorted
            }
            PairingProfile::OwnerDevice => {
                if targets.is_empty() {
                    vec!["*".to_owned()]
                } else {
                    let mut sorted = targets;
                    sorted.sort();
                    sorted.dedup();
                    sorted
                }
            }
        };
        let principal_selectors = if principals.is_empty() {
            vec!["*".to_owned()]
        } else {
            let mut sorted = principals;
            sorted.sort();
            sorted.dedup();
            sorted
        };
        let exposure = ExposurePolicy {
            profile,
            target_selectors,
            principal_selectors,
            max_body_bytes: fed.max_body.min(u32::MAX as usize) as u32,
            max_attachment_bytes: fed.max_attachment_bytes.min(u32::MAX as usize) as u32,
            rate_burst: 10,
            rate_per_minute: 60,
        };
        exposure
            .validate()
            .map_err(|e| PairingError::Internal(e.to_string()))?;

        // Check reconfirmation vs conflict against live intents (Q2-5a).
        {
            let guard = self.live_intents.lock().unwrap();
            if let Some(existing) = guard
                .values()
                .find(|i| i.peer_id == peer_id.0 && i.deadline > tokio::time::Instant::now())
            {
                if existing.role == role
                    && existing.exposure == exposure
                    && existing.grant_not_after == grant_not_after
                {
                    return Ok((existing.clone(), true));
                }
                return Err(PairingError::IntentExists(
                    "pending intent already exists for peer with different parameters or role"
                        .into(),
                ));
            }
        }

        let now_utc = unix_now_u32() as i64;
        let req = IntentRequest {
            peer: peer_id.0,
            exposure: exposure.clone(),
            grant_not_after,
            revision: 1,
            expires_at: now_utc + i64::from(MAX_CEREMONY_WINDOW_SECS),
            replaces: None,
        };
        let fed_db = fed.clone();
        let reserved = tokio::task::spawn_blocking(move || {
            let db = fed_db.db.lock().unwrap_or_else(|e| e.into_inner());
            store::reserve_intent(&db, &req, now_utc)
        })
        .await
        .map_err(|e| PairingError::Internal(e.to_string()))?
        .map_err(Self::map_store_error)?;

        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(u64::from(MAX_CEREMONY_WINDOW_SECS));
        let intent = LiveIntent {
            intent_id: reserved.intent_id,
            grant_id: reserved.grant_id,
            peer_id: peer_id.0,
            role,
            exposure,
            grant_not_after,
            deadline,
            start_mono_secs: self.mono_secs(),
            cancel_notify: Arc::new(Notify::new()),
            completion: Arc::new(Mutex::new(None)),
            done_notify: Arc::new(Notify::new()),
        };

        {
            let mut guard = self.live_intents.lock().unwrap();
            guard.insert(intent.intent_id, intent.clone());
        }

        if role == IntentRole::Responder {
            fed.open_mdns_announce_window();
        }

        // §5.3: per-intent monotonic daemon timer cancels transactionally at 120s.
        let svc = self.clone();
        let fed_timer = fed.clone();
        let intent_id = intent.intent_id;
        let cancel_notify = intent.cancel_notify.clone();
        let done_notify = intent.done_notify.clone();
        let completion = intent.completion.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    svc.finish_intent_timeout(&fed_timer, intent_id).await;
                    let mut c = completion.lock().unwrap();
                    if c.is_none() {
                        *c = Some(Err(PairingError::Expired("intent expired after 120s".into())));
                    }
                    done_notify.notify_waiters();
                }
                _ = cancel_notify.notified() => {}
            }
        });

        Ok((intent, false))
    }

    async fn finish_intent_timeout(&self, fed: &Arc<FedState>, intent_id: [u8; 16]) {
        loop {
            let fed_c = fed.clone();
            let res = tokio::task::spawn_blocking(move || {
                let db = fed_c.db.lock().unwrap_or_else(|e| e.into_inner());
                store::cancel_intent_by_id(&db, &intent_id)
            })
            .await;
            match res {
                Ok(Ok(_)) => break,
                _ => tokio::time::sleep(Duration::from_millis(250)).await,
            }
        }
        self.remove_live_intent(fed, &intent_id);
    }

    fn remove_live_intent(&self, fed: &FedState, intent_id: &[u8; 16]) {
        let was_responder = {
            let mut guard = self.live_intents.lock().unwrap();
            let removed = guard.remove(intent_id);
            if let Some(ref item) = removed {
                item.cancel_notify.notify_waiters();
            }
            let any_responder_left = guard.values().any(|i| i.role == IntentRole::Responder);
            removed.is_some_and(|r| r.role == IntentRole::Responder) && !any_responder_left
        };
        if was_responder {
            fed.close_mdns_announce_window();
        }
    }

    pub async fn cancel_intent(
        &self,
        fed: &Arc<FedState>,
        target: &str,
    ) -> Result<usize, PairingError> {
        let count = if let Ok(peer) = SpkiDeviceId::parse_device_id_string(target) {
            let fed_c = fed.clone();
            let peer_id = peer.0;
            let ids = tokio::task::spawn_blocking(move || {
                let db = fed_c.db.lock().unwrap_or_else(|e| e.into_inner());
                store::cancel_open_intents_for_peer(&db, &peer_id)
            })
            .await
            .map_err(|e| PairingError::Internal(e.to_string()))?
            .map_err(Self::map_store_error)?;
            for id in &ids {
                self.finish_cancelled_live_intent(fed, id, "cancelled by operator");
            }
            ids.len()
        } else {
            let raw = hex::decode(target)
                .map_err(|_| PairingError::InvalidDeviceId("invalid intent or peer ID".into()))?;
            let intent_id: [u8; 16] = raw
                .try_into()
                .map_err(|_| PairingError::InvalidDeviceId("invalid intent ID length".into()))?;
            let fed_c = fed.clone();
            let cancelled = tokio::task::spawn_blocking(move || {
                let db = fed_c.db.lock().unwrap_or_else(|e| e.into_inner());
                store::cancel_intent_by_id(&db, &intent_id)
            })
            .await
            .map_err(|e| PairingError::Internal(e.to_string()))?
            .map_err(Self::map_store_error)?;
            if cancelled {
                self.finish_cancelled_live_intent(fed, &intent_id, "cancelled by operator");
                1
            } else {
                0
            }
        };
        if count == 0 {
            return Err(PairingError::NotFound("no matching open intent".into()));
        }
        Ok(count)
    }

    fn finish_cancelled_live_intent(&self, fed: &FedState, intent_id: &[u8; 16], msg: &str) {
        let completion_info = {
            let guard = self.live_intents.lock().unwrap();
            guard
                .get(intent_id)
                .map(|i| (i.completion.clone(), i.done_notify.clone()))
        };
        if let Some((completion, done_notify)) = completion_info {
            let mut c = completion.lock().unwrap();
            if c.is_none() {
                *c = Some(Err(PairingError::Expired(msg.to_string())));
            }
            done_notify.notify_waiters();
        }
        self.remove_live_intent(fed, intent_id);
    }

    pub async fn run_initiator_and_wait(
        self: &Arc<Self>,
        fed: &Arc<FedState>,
        intent: LiveIntent,
        addresses: Vec<SocketAddr>,
    ) -> Result<ActivationSummary, PairingError> {
        let Some(_out_permit) = self.budgets.outbound.try_acquire() else {
            self.budgets.record_refusal("pairing.attempt_budget");
            let _ = self
                .cancel_intent(fed, &hex::encode(intent.intent_id))
                .await;
            return Err(PairingError::AttemptBudget(
                "outbound pairing attempt budget exhausted".into(),
            ));
        };

        let cert_der = fed
            .own_cert_der()
            .ok_or_else(|| PairingError::KeyAlgorithm("no certificate".into()))?;
        let key_der = fed
            .own_key_der()
            .ok_or_else(|| PairingError::KeyAlgorithm("no private key".into()))?;
        let own_id = ed25519_device_id_from_cert(&cert_der)?.0;
        let own_spki = spki_der_from_cert(&cert_der)
            .map_err(|e| PairingError::KeyAlgorithm(e.to_string()))?;
        let signing_key = ed25519_keypair_from_der(key_der.secret_der(), &cert_der)?;

        let deny_peers = Some(fed.current_peers());
        let (client_cfg, key_alg_flag) = build_pairing_client_config(
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::try_from(key_der.secret_der().to_vec())
                .map_err(|e| PairingError::Internal(e.to_string()))?,
            intent.peer_id,
            deny_peers,
        )?;
        let connector = TlsConnector::from(client_cfg);

        let mut last_err = PairingError::Unreachable("no candidate addresses".into());
        for addr in addresses {
            let tcp = match tokio::time::timeout(
                OUTBOUND_PROBE_TIMEOUT,
                tokio::net::TcpStream::connect(addr),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    last_err = PairingError::Unreachable(format!("{addr}: {e}"));
                    continue;
                }
                Err(_) => {
                    last_err = PairingError::Unreachable(format!("{addr}: connect timed out"));
                    continue;
                }
            };
            let dns = ServerName::try_from("xmsg-pair.local")
                .map_err(|e| PairingError::Internal(e.to_string()))?;
            let mut tls = match tokio::time::timeout(
                OUTBOUND_PROBE_TIMEOUT,
                connector.connect(dns, tcp),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    if key_alg_flag.load(Ordering::SeqCst) {
                        self.budgets.record_refusal("pairing.key_algorithm");
                        let _ = self
                            .cancel_intent(fed, &hex::encode(intent.intent_id))
                            .await;
                        return Err(PairingError::KeyAlgorithm(
                            "remote pinned SPKI is not Ed25519".into(),
                        ));
                    }
                    last_err = PairingError::PeerRefused(format!("TLS handshake failed: {e}"));
                    continue;
                }
                Err(_) => {
                    last_err = PairingError::Unreachable(format!("{addr}: TLS probe timed out"));
                    continue;
                }
            };

            // Q2-4b: require negotiated xmsg-pair/1 ALPN before HelloI.
            if tls.get_ref().1.alpn_protocol() != Some(PAIRING_ALPN) {
                self.budgets.record_refusal("pairing.peer_unsupported");
                let _ = self
                    .cancel_intent(fed, &hex::encode(intent.intent_id))
                    .await;
                return Err(PairingError::PeerUnsupported(
                    "peer did not negotiate xmsg-pair/1".into(),
                ));
            }

            let peer_cert_der = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .ok_or_else(|| PairingError::PeerRefused("missing peer certificate".into()))?;
            let peer_spki = spki_der_from_cert(peer_cert_der.as_ref())
                .map_err(|e| PairingError::KeyAlgorithm(e.to_string()))?;
            let exporter = export_pairing_keying_material(tls.get_ref().1)?;

            let exp_sha = intent
                .exposure
                .sha256()
                .map_err(|e| PairingError::Internal(e.to_string()))?;
            let offer_i = Offer {
                profile: intent.exposure.profile,
                grant_not_after: intent.grant_not_after.map(|v| v as u32),
                exposure_policy_sha256: exp_sha,
            };
            let now_utc = unix_now_u32();
            let inputs = InitiatorInputs {
                own_id,
                peer_id: intent.peer_id,
                own_spki: &own_spki,
                peer_spki: &peer_spki,
                offer_i,
                policy_i: 1,
                intent_id: intent.intent_id,
                grant_id: intent.grant_id,
                signing_key: &signing_key,
                exporter,
                deadline: intent.deadline,
                start_mono_secs: intent.start_mono_secs,
                now_utc,
            };

            let fed_cap = fed.clone();
            let res = execute_initiator_exchange(&mut tls, inputs, |iid, now| {
                let db = fed_cap.db.lock().unwrap_or_else(|e| e.into_inner());
                store::reserve_capacity(&db, &iid, now).map_err(Self::map_store_error)
            })
            .await;

            match res {
                Ok(artifacts) => {
                    let txn_id = artifacts
                        .transcript
                        .transaction_id()
                        .map_err(|e| PairingError::Internal(e.to_string()))?;
                    let ctx = ReceiptVerificationContext {
                        id_i: artifacts.transcript.id_i,
                        id_r: artifacts.transcript.id_r,
                        spki_i: &own_spki,
                        spki_r: &peer_spki,
                        offer_i: artifacts.transcript.offer_i,
                        offer_r: artifacts.transcript.offer_r,
                        created_utc: artifacts.transcript.created_utc,
                        ceremony_expires_utc: artifacts.transcript.ceremony_expires_utc,
                        exporter,
                        transaction_id: txn_id,
                        now_utc,
                        current_policy_i: artifacts.transcript.policy_i,
                        current_policy_r: artifacts.transcript.policy_r,
                        blocked: false,
                        revoked: false,
                        bilateral: true,
                    };
                    let verified = VerifiedReceipts::verify(
                        &artifacts.receipt_i,
                        &artifacts.receipt_r,
                        &ctx,
                    )
                    .map_err(Self::map_store_error)?;
                    let fed_act = fed.clone();
                    let intent_id = intent.intent_id;
                    let now_i64 = i64::from(now_utc);
                    let (_, committed_rev) = tokio::task::spawn_blocking(move || {
                        let db = fed_act.db.lock().unwrap_or_else(|e| e.into_inner());
                        store::activate(&db, &own_id, &intent_id, &verified, now_i64)
                    })
                    .await
                    .map_err(|e| PairingError::Internal(e.to_string()))?
                    .map_err(Self::map_store_error)?;

                    self.remove_live_intent(fed, &intent.intent_id);
                    let installed_rev = fed.publish_pairing_update(committed_rev).await?;
                    return Ok(ActivationSummary {
                        grant_id: hex::encode(intent.grant_id),
                        peer_id: SpkiDeviceId(intent.peer_id).to_device_id_string(),
                        committed_revision: committed_rev,
                        installed_revision: installed_rev,
                        committed: true,
                    });
                }
                Err(e) => {
                    self.budgets.record_refusal(e.code());
                    // §5.3: initiator cancels its intent at once on refusal/pre-ReceiptR close.
                    let _ = self
                        .cancel_intent(fed, &hex::encode(intent.intent_id))
                        .await;
                    return Err(e);
                }
            }
        }

        self.budgets.record_refusal(last_err.code());
        let _ = self
            .cancel_intent(fed, &hex::encode(intent.intent_id))
            .await;
        Err(last_err)
    }

    pub async fn handle_inbound_pairing_stream(
        self: &Arc<Self>,
        fed: &Arc<FedState>,
        mut tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    ) {
        let peer_cert_der = match tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .cloned()
        {
            Some(c) => c,
            None => return,
        };
        let peer_id = match ed25519_device_id_from_cert(peer_cert_der.as_ref()) {
            Ok(id) => id.0,
            Err(_) => {
                self.budgets.record_refusal("pairing.key_algorithm");
                return;
            }
        };
        let Some(intent) = self.find_live_responder_intent(&peer_id) else {
            self.budgets.record_refusal("pairing.no_intent");
            return;
        };
        // Q2-5e: 1 live ceremony per intent, taken ONLY after mutual authentication.
        let Some(_ceremony_guard) = self.ceremony_slots.try_acquire(intent.intent_id) else {
            self.budgets.record_refusal("pairing.ceremony_busy");
            return;
        };

        let cert_der = match fed.own_cert_der() {
            Some(c) => c,
            None => return,
        };
        let key_der = match fed.own_key_der() {
            Some(k) => k,
            None => return,
        };
        let own_id = match ed25519_device_id_from_cert(&cert_der) {
            Ok(id) => id.0,
            Err(_) => return,
        };
        let own_spki = match spki_der_from_cert(&cert_der) {
            Ok(s) => s,
            Err(_) => return,
        };
        let peer_spki = match spki_der_from_cert(peer_cert_der.as_ref()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let signing_key = match ed25519_keypair_from_der(key_der.secret_der(), &cert_der) {
            Ok(k) => k,
            Err(_) => return,
        };
        let exporter = match export_pairing_keying_material(tls.get_ref().1) {
            Ok(e) => e,
            Err(_) => return,
        };
        let exp_sha = match intent.exposure.sha256() {
            Ok(s) => s,
            Err(_) => return,
        };
        let offer_r = Offer {
            profile: intent.exposure.profile,
            grant_not_after: intent.grant_not_after.map(|v| v as u32),
            exposure_policy_sha256: exp_sha,
        };
        let now_utc = unix_now_u32();
        let inputs = ResponderInputs {
            own_id,
            peer_id,
            own_spki: &own_spki,
            peer_spki: &peer_spki,
            offer_r,
            policy_r: 1,
            intent_id: intent.intent_id,
            grant_id: intent.grant_id,
            signing_key: &signing_key,
            exporter,
            deadline: intent.deadline,
            start_mono_secs: intent.start_mono_secs,
            now_utc,
        };

        let fed_cap = fed.clone();
        let fed_act = fed.clone();
        let mut committed_rev_out: Option<u64> = None;
        let res = execute_responder_exchange(
            &mut tls,
            inputs,
            |iid, now| {
                let db = fed_cap.db.lock().unwrap_or_else(|e| e.into_inner());
                store::reserve_capacity(&db, &iid, now).map_err(Self::map_store_error)
            },
            |artifacts| {
                let txn_id = artifacts
                    .transcript
                    .transaction_id()
                    .map_err(|e| PairingError::Internal(e.to_string()))?;
                let ctx = ReceiptVerificationContext {
                    id_i: artifacts.transcript.id_i,
                    id_r: artifacts.transcript.id_r,
                    spki_i: &peer_spki,
                    spki_r: &own_spki,
                    offer_i: artifacts.transcript.offer_i,
                    offer_r: artifacts.transcript.offer_r,
                    created_utc: artifacts.transcript.created_utc,
                    ceremony_expires_utc: artifacts.transcript.ceremony_expires_utc,
                    exporter,
                    transaction_id: txn_id,
                    now_utc,
                    current_policy_i: artifacts.transcript.policy_i,
                    current_policy_r: artifacts.transcript.policy_r,
                    blocked: false,
                    revoked: false,
                    bilateral: true,
                };
                let verified = VerifiedReceipts::verify(
                    &artifacts.receipt_r,
                    &artifacts.receipt_i,
                    &ctx,
                )
                .map_err(Self::map_store_error)?;
                let db = fed_act.db.lock().unwrap_or_else(|e| e.into_inner());
                let (_, rev) = store::activate(
                    &db,
                    &own_id,
                    &intent.intent_id,
                    &verified,
                    i64::from(now_utc),
                )
                .map_err(Self::map_store_error)?;
                committed_rev_out = Some(rev);
                Ok(())
            },
        )
        .await;

        match res {
            Ok(_) => {
                let committed_rev = committed_rev_out.unwrap_or(0);
                self.remove_live_intent(fed, &intent.intent_id);
                let pub_res = fed.publish_pairing_update(committed_rev).await;
                let outcome = match pub_res {
                    Ok(installed_rev) => Ok(ActivationSummary {
                        grant_id: hex::encode(intent.grant_id),
                        peer_id: SpkiDeviceId(intent.peer_id).to_device_id_string(),
                        committed_revision: committed_rev,
                        installed_revision: installed_rev,
                        committed: true,
                    }),
                    Err(e) => Err(e),
                };
                *intent.completion.lock().unwrap() = Some(outcome);
                intent.done_notify.notify_waiters();
            }
            Err(e) => {
                self.budgets.record_refusal(e.code());
            }
        }
    }

    pub async fn wait_for_responder(
        &self,
        intent: &LiveIntent,
    ) -> Result<ActivationSummary, PairingError> {
        loop {
            if let Some(res) = intent.completion.lock().unwrap().clone() {
                return res;
            }
            intent.done_notify.notified().await;
        }
    }

    pub async fn remove_grant(
        &self,
        fed: &Arc<FedState>,
        grant_id_hex: &str,
    ) -> Result<serde_json::Value, PairingError> {
        let raw = hex::decode(grant_id_hex)
            .map_err(|_| PairingError::InvalidDeviceId("invalid grant ID hex".into()))?;
        let grant_id: GrantId = raw
            .try_into()
            .map_err(|_| PairingError::InvalidDeviceId("grant ID must be 16 bytes".into()))?;

        // Check if grant belongs to legacy_unilateral -> refuse pairing.legacy_config_owned (§5.2).
        let fed_check = fed.clone();
        let legacy_name = tokio::task::spawn_blocking(move || {
            let db = fed_check.db.lock().unwrap_or_else(|e| e.into_inner());
            let grants = store::list_grants_summary(&db).map_err(Self::map_store_error)?;
            if let Some(g) = grants.into_iter().find(|g| g.grant_id == grant_id) {
                if g.provenance == "legacy_unilateral" {
                    return Ok::<Option<String>, PairingError>(Some(
                        SpkiDeviceId(g.peer_id).to_device_id_string(),
                    ));
                }
            }
            Ok(None)
        })
        .await
        .map_err(|e| PairingError::Internal(e.to_string()))??;
        if let Some(peer) = legacy_name {
            return Err(PairingError::LegacyConfigOwned(format!(
                "legacy_unilateral grant for {peer} is owned by peers config"
            )));
        }

        let now = unix_now_u32() as i64;
        let revocations = store::revocations_for_db(&fed.db);
        let fed_rm = fed.clone();
        let (committed_rev, remaining) = tokio::task::spawn_blocking(move || {
            let db = fed_rm.db.lock().unwrap_or_else(|e| e.into_inner());
            let rev = store::remove_with_marks(&db, &grant_id, now, Some(&revocations))
                .map_err(Self::map_store_error)?;
            let grants = store::list_grants_summary(&db).map_err(Self::map_store_error)?;
            Ok::<(u64, Vec<store::StoredGrantSummary>), PairingError>((rev, grants))
        })
        .await
        .map_err(|e| PairingError::Internal(e.to_string()))??;

        let installed_rev = fed.publish_pairing_update(committed_rev).await?;
        let remaining_json: Vec<serde_json::Value> = remaining
            .into_iter()
            .map(|g| {
                serde_json::json!({
                    "grant_id": hex::encode(g.grant_id),
                    "peer_id": SpkiDeviceId(g.peer_id).to_device_id_string(),
                    "provenance": g.provenance,
                    "profile": g.profile,
                    "active": g.active,
                })
            })
            .collect();
        Ok(serde_json::json!({
            "committed": true,
            "committed_revision": committed_rev,
            "installed_revision": installed_rev,
            "remaining_grants": remaining_json,
        }))
    }

    pub async fn block_device(
        &self,
        fed: &Arc<FedState>,
        peer_id_str: &str,
    ) -> Result<MutationOutcome, PairingError> {
        let peer_id = SpkiDeviceId::parse_device_id_string(peer_id_str)
            .map_err(|e| PairingError::InvalidDeviceId(e.to_string()))?;
        let now = unix_now_u32() as i64;
        let revocations = store::revocations_for_db(&fed.db);
        let fed_blk = fed.clone();
        let pid = peer_id.0;
        let committed_rev = tokio::task::spawn_blocking(move || {
            let db = fed_blk.db.lock().unwrap_or_else(|e| e.into_inner());
            store::block_device_with_marks(&db, &pid, now, Some(&revocations))
        })
        .await
        .map_err(|e| PairingError::Internal(e.to_string()))?
        .map_err(Self::map_store_error)?;

        // Cancel any live in-memory intents for the blocked device.
        let matching_ids: Vec<[u8; 16]> = {
            let guard = self.live_intents.lock().unwrap();
            guard
                .values()
                .filter(|i| i.peer_id == peer_id.0)
                .map(|i| i.intent_id)
                .collect()
        };
        for id in matching_ids {
            self.finish_cancelled_live_intent(fed, &id, "device blocked");
        }

        let installed_rev = fed.publish_pairing_update(committed_rev).await?;
        Ok(MutationOutcome {
            committed: true,
            committed_revision: committed_rev,
            installed_revision: installed_rev,
            error: None,
        })
    }

    pub async fn unblock_device(
        &self,
        fed: &Arc<FedState>,
        peer_id_str: &str,
    ) -> Result<MutationOutcome, PairingError> {
        let peer_id = SpkiDeviceId::parse_device_id_string(peer_id_str)
            .map_err(|e| PairingError::InvalidDeviceId(e.to_string()))?;
        let Some(reloader) = reloader_for(fed) else {
            return Err(PairingError::Internal(
                "no credential reloader attached for unblock proof".into(),
            ));
        };
        let pid = peer_id.0;
        let committed_rev = tokio::task::spawn_blocking(move || reloader.unblock_device(&pid))
            .await
            .map_err(|e| PairingError::Internal(e.to_string()))?
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("unblock would restore") {
                    PairingError::UnblockWouldRestore(msg)
                } else {
                    PairingError::Internal(msg)
                }
            })?;
        let installed_rev = fed.current_peers().authority_revision;
        if installed_rev < committed_rev {
            return Err(PairingError::ReloadFailed {
                committed_revision: committed_rev,
                installed_revision: installed_rev,
                error: "installed revision remained behind committed revision".to_string(),
            });
        }
        Ok(MutationOutcome {
            committed: true,
            committed_revision: committed_rev,
            installed_revision: installed_rev,
            error: None,
        })
    }

    pub async fn list_state(&self, fed: &Arc<FedState>) -> Result<serde_json::Value, PairingError> {
        let fed_db = fed.clone();
        let (committed_rev, grants, blocks, slots_used) = tokio::task::spawn_blocking(move || {
            let db = fed_db.db.lock().unwrap_or_else(|e| e.into_inner());
            let rev = store::authority_revision(&db).map_err(Self::map_store_error)?;
            let grants = store::list_grants_summary(&db).map_err(Self::map_store_error)?;
            let blocks = store::list_blocks(&db).map_err(Self::map_store_error)?;
            let slots = store::count_slots_used(&db).map_err(Self::map_store_error)?;
            Ok::<_, PairingError>((rev, grants, blocks, slots))
        })
        .await
        .map_err(|e| PairingError::Internal(e.to_string()))??;

        let installed_rev = fed.current_peers().authority_revision;
        let now_inst = tokio::time::Instant::now();
        let intents_json: Vec<serde_json::Value> = {
            let guard = self.live_intents.lock().unwrap();
            guard
                .values()
                .filter(|i| i.deadline > now_inst)
                .map(|i| {
                    serde_json::json!({
                        "intent_id": hex::encode(i.intent_id),
                        "grant_id": hex::encode(i.grant_id),
                        "peer_id": SpkiDeviceId(i.peer_id).to_device_id_string(),
                        "role": i.role,
                        "profile": i.exposure.profile.as_str(),
                        "targets": i.exposure.target_selectors,
                        "seconds_left": i.deadline.saturating_duration_since(now_inst).as_secs(),
                    })
                })
                .collect()
        };
        let grants_json: Vec<serde_json::Value> = grants
            .into_iter()
            .map(|g| {
                let targets = g
                    .exposure
                    .as_deref()
                    .and_then(|raw| ExposurePolicy::decode_cbor(raw).ok())
                    .map(|e| e.target_selectors)
                    .unwrap_or_default();
                serde_json::json!({
                    "grant_id": hex::encode(g.grant_id),
                    "peer_id": SpkiDeviceId(g.peer_id).to_device_id_string(),
                    "provenance": g.provenance,
                    "profile": g.profile,
                    "grant_not_after": g.not_after,
                    "targets": targets,
                    "has_reverse_receipt": g.has_reverse_receipt,
                    "active": g.active,
                })
            })
            .collect();
        let blocks_json: Vec<serde_json::Value> = blocks
            .into_iter()
            .map(|(pid, blocked_at)| {
                serde_json::json!({
                    "peer_id": SpkiDeviceId(pid).to_device_id_string(),
                    "blocked_at": blocked_at,
                })
            })
            .collect();

        Ok(serde_json::json!({
            "committed_revision": committed_rev,
            "installed_revision": installed_rev,
            "slots_used": slots_used,
            "slots_cap": MAX_MANUAL_GRANTS,
            "grants": grants_json,
            "intents": intents_json,
            "blocks": blocks_json,
        }))
    }

    pub async fn diagnostics(
        &self,
        fed: &Arc<FedState>,
        has_fed_listen: bool,
    ) -> Result<serde_json::Value, PairingError> {
        let now = unix_now_u32() as i64;
        let fed_db = fed.clone();
        let (committed_rev, grants, slots_used, expired_holding_slots) =
            tokio::task::spawn_blocking(move || {
                let db = fed_db.db.lock().unwrap_or_else(|e| e.into_inner());
                let rev = store::authority_revision(&db).map_err(Self::map_store_error)?;
                let grants = store::list_grants_summary(&db).map_err(Self::map_store_error)?;
                let slots = store::count_slots_used(&db).map_err(Self::map_store_error)?;
                let expired = store::count_expired_grants_holding_slots(&db, now)
                    .map_err(Self::map_store_error)?;
                Ok::<_, PairingError>((rev, grants, slots, expired))
            })
            .await
            .map_err(|e| PairingError::Internal(e.to_string()))??;

        let installed_rev = fed.current_peers().authority_revision;
        let device_id = match self.own_device_id(fed) {
            Ok(id) => serde_json::json!({
                "status": "info",
                "device_id": id.to_device_id_string(),
            }),
            Err(e) => serde_json::json!({
                "status": "warn",
                "code": "pairing.key_algorithm",
                "message": e.to_string(),
            }),
        };
        let listener = if has_fed_listen && !fed.is_leaf {
            serde_json::json!({ "status": "info", "mode": "responder_available" })
        } else {
            serde_json::json!({ "status": "info", "mode": "initiator_only" })
        };
        let manual_count = grants
            .iter()
            .filter(|g| g.provenance == "manual_authenticated_oob")
            .count();
        let receive_path = if (!has_fed_listen || fed.is_leaf) && manual_count > 0 {
            serde_json::json!({
                "status": "warn",
                "code": "pairing.receive_path",
                "manual_grants": manual_count,
                "message": "initiator-only node has no inbound receive path for manual grants",
            })
        } else {
            serde_json::json!({ "status": "pass" })
        };
        let startup = if self.is_startup_cancel_done() {
            serde_json::json!({ "status": "pass" })
        } else {
            serde_json::json!({
                "status": "warn",
                "code": "pairing.startup_cancel_failed",
                "error": self.startup_cancel_error(),
            })
        };
        let authority = if installed_rev == committed_rev {
            serde_json::json!({
                "status": "pass",
                "committed_revision": committed_rev,
                "installed_revision": installed_rev,
            })
        } else {
            serde_json::json!({
                "status": "warn",
                "code": "pairing.reload_failed",
                "committed_revision": committed_rev,
                "installed_revision": installed_rev,
            })
        };

        let peers_map = fed.current_peers();
        let manual_peers: std::collections::HashSet<DeviceId> = grants
            .iter()
            .filter(|g| g.provenance == "manual_authenticated_oob")
            .map(|g| g.peer_id)
            .collect();
        let mut coexistence_warnings = Vec::new();
        for g in &grants {
            if g.provenance == "legacy_unilateral" && manual_peers.contains(&g.peer_id) {
                coexistence_warnings.push(SpkiDeviceId(g.peer_id).to_device_id_string());
            }
        }
        let literal_wildcard_entries: Vec<String> = peers_map
            .peers_by_name
            .iter()
            .filter(|(_, p)| {
                p.targets
                    .as_ref()
                    .is_some_and(|t| t.iter().any(|s| s == "*"))
            })
            .map(|(name, _)| name.clone())
            .collect();

        let (resp_count, init_count) = {
            let now_inst = tokio::time::Instant::now();
            let guard = self.live_intents.lock().unwrap();
            let mut r = 0usize;
            let mut i = 0usize;
            for item in guard.values().filter(|x| x.deadline > now_inst) {
                match item.role {
                    IntentRole::Responder => r += 1,
                    IntentRole::Initiator => i += 1,
                }
            }
            (r, i)
        };

        let expired_grants: Vec<serde_json::Value> = grants
            .iter()
            .filter(|g| {
                g.provenance == "manual_authenticated_oob"
                    && g.not_after.is_some_and(|e| e <= now)
            })
            .map(|g| {
                serde_json::json!({
                    "grant_id": hex::encode(g.grant_id),
                    "peer_id": SpkiDeviceId(g.peer_id).to_device_id_string(),
                    "not_after": g.not_after,
                })
            })
            .collect();

        Ok(serde_json::json!({
            "pairing.device_id": device_id,
            "pairing.listener": listener,
            "pairing.receive_path": receive_path,
            "pairing.startup": startup,
            "pairing.authority": authority,
            "pairing.grants": {
                "status": "info",
                "slots_used": slots_used,
                "slots_cap": MAX_MANUAL_GRANTS,
                "manual_grants": manual_count,
                "expired_grants_holding_slots": expired_holding_slots,
                "expired_grants": expired_grants,
            },
            "pairing.legacy": {
                "status": if coexistence_warnings.is_empty() && literal_wildcard_entries.is_empty() { "notice" } else { "warn" },
                "coexistence_peers": coexistence_warnings,
                "literal_wildcard_entries": literal_wildcard_entries,
            },
            "pairing.intents": {
                "status": "info",
                "responder_pending": resp_count,
                "initiator_pending": init_count,
                "pending_cap": MAX_PENDING_INTENTS,
                "inbound_remaining": self.budgets.inbound.remaining(),
                "inbound_cap_per_min": MAX_INBOUND_STARTS_PER_MIN,
                "outbound_remaining": self.budgets.outbound.remaining(),
                "outbound_cap_per_min": MAX_OUTBOUND_STARTS_PER_MIN,
            },
            "pairing.refused": {
                "status": "info",
                "counts_by_code": self.budgets.refusal_snapshot(),
            },
        }))
    }
}
