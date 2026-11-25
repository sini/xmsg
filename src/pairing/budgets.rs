//! Separate inbound and outbound pairing attempt budgets and typed refusal counters (§5.3).

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use thiserror::Error;

/// Maximum inbound pairing handshakes started per 60s window while a responder intent is live.
pub const MAX_INBOUND_STARTS_PER_MIN: usize = 16;
/// Maximum concurrent inbound pairing handshakes.
pub const MAX_INBOUND_CONCURRENT: usize = 4;
/// Inbound handshake completion deadline.
pub const INBOUND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum outbound pairing dials started per 60s window.
pub const MAX_OUTBOUND_STARTS_PER_MIN: usize = 16;
/// Maximum concurrent outbound pairing probes.
pub const MAX_OUTBOUND_CONCURRENT: usize = 4;
/// Outbound probe timeout.
pub const OUTBOUND_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

const WINDOW: Duration = Duration::from_secs(60);

/// Typed pairing error codes surfaced on the Unix API, CLI, and doctor diagnostics.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PairingError {
    #[error("pairing.key_algorithm: {0}")]
    KeyAlgorithm(String),
    #[error("pairing.peer_unsupported: {0}")]
    PeerUnsupported(String),
    #[error("pairing.intent_exists: {0}")]
    IntentExists(String),
    #[error("pairing.intents_full: {0}")]
    IntentsFull(String),
    #[error("pairing.attempt_budget: {0}")]
    AttemptBudget(String),
    #[error("pairing.unreachable: {0}")]
    Unreachable(String),
    #[error("pairing.ceremony_busy: {0}")]
    CeremonyBusy(String),
    #[error("pairing.frame_too_large: {0}")]
    FrameTooLarge(String),
    #[error("pairing.clock: {0}")]
    Clock(String),
    #[error("pairing.grants_full: {0}")]
    GrantsFull(String),
    #[error("pairing.peer_refused: {0}")]
    PeerRefused(String),
    #[error("pairing.expired: {0}")]
    Expired(String),
    #[error("pairing.startup_cancel_failed: {0}")]
    StartupCancelFailed(String),
    #[error("pairing.caller_indeterminate: {0}")]
    CallerIndeterminate(String),
    #[error("pairing.legacy_config_owned: {0}")]
    LegacyConfigOwned(String),
    #[error("pairing.unblock_would_restore: {0}")]
    UnblockWouldRestore(String),
    #[error("pairing.reload_failed: committed={committed_revision} installed={installed_revision} error={error}")]
    ReloadFailed {
        committed_revision: u64,
        installed_revision: u64,
        error: String,
    },
    #[error("pairing.targets_required: {0}")]
    TargetsRequired(String),
    #[error("pairing.invalid_device_id: {0}")]
    InvalidDeviceId(String),
    #[error("pairing.not_found: {0}")]
    NotFound(String),
    #[error("pairing.internal: {0}")]
    Internal(String),
}

impl PairingError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::KeyAlgorithm(_) => "pairing.key_algorithm",
            Self::PeerUnsupported(_) => "pairing.peer_unsupported",
            Self::IntentExists(_) => "pairing.intent_exists",
            Self::IntentsFull(_) => "pairing.intents_full",
            Self::AttemptBudget(_) => "pairing.attempt_budget",
            Self::Unreachable(_) => "pairing.unreachable",
            Self::CeremonyBusy(_) => "pairing.ceremony_busy",
            Self::FrameTooLarge(_) => "pairing.frame_too_large",
            Self::Clock(_) => "pairing.clock",
            Self::GrantsFull(_) => "pairing.grants_full",
            Self::PeerRefused(_) => "pairing.peer_refused",
            Self::Expired(_) => "pairing.expired",
            Self::StartupCancelFailed(_) => "pairing.startup_cancel_failed",
            Self::CallerIndeterminate(_) => "pairing.caller_indeterminate",
            Self::LegacyConfigOwned(_) => "pairing.legacy_config_owned",
            Self::UnblockWouldRestore(_) => "pairing.unblock_would_restore",
            Self::ReloadFailed { .. } => "pairing.reload_failed",
            Self::TargetsRequired(_) => "pairing.targets_required",
            Self::InvalidDeviceId(_) => "pairing.invalid_device_id",
            Self::NotFound(_) => "pairing.not_found",
            Self::Internal(_) => "pairing.internal",
        }
    }
}

#[derive(Debug)]
struct LimiterState {
    starts: VecDeque<Instant>,
    active: usize,
    max_per_min: usize,
    max_concurrent: usize,
}

impl LimiterState {
    fn new(max_per_min: usize, max_concurrent: usize) -> Self {
        Self {
            starts: VecDeque::new(),
            active: 0,
            max_per_min,
            max_concurrent,
        }
    }

    fn prune(&mut self, now: Instant) {
        while let Some(&front) = self.starts.front() {
            if now.saturating_duration_since(front) >= WINDOW {
                self.starts.pop_front();
            } else {
                break;
            }
        }
    }

    fn try_acquire(&mut self, now: Instant) -> bool {
        self.prune(now);
        if self.active >= self.max_concurrent || self.starts.len() >= self.max_per_min {
            return false;
        }
        // Starts are never refunded on failure (Q2-5d).
        self.starts.push_back(now);
        self.active += 1;
        true
    }

    fn remaining(&mut self, now: Instant) -> usize {
        self.prune(now);
        self.max_per_min.saturating_sub(self.starts.len())
    }
}

/// Independent sliding-window + concurrency limiter (never shared between inbound and outbound).
#[derive(Clone, Debug)]
pub struct AttemptLimiter {
    inner: Arc<Mutex<LimiterState>>,
}

impl AttemptLimiter {
    pub fn new(max_per_min: usize, max_concurrent: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(LimiterState::new(max_per_min, max_concurrent))),
        }
    }

    pub fn try_acquire(&self) -> Option<AttemptPermit> {
        let mut guard = self.inner.lock().unwrap();
        if guard.try_acquire(Instant::now()) {
            Some(AttemptPermit {
                inner: self.inner.clone(),
            })
        } else {
            None
        }
    }

    pub fn remaining(&self) -> usize {
        self.inner.lock().unwrap().remaining(Instant::now())
    }

    pub fn active(&self) -> usize {
        self.inner.lock().unwrap().active
    }
}

/// RAII concurrency slot; dropping releases concurrency only, never the 60s start count.
pub struct AttemptPermit {
    inner: Arc<Mutex<LimiterState>>,
}

impl Drop for AttemptPermit {
    fn drop(&mut self) {
        let mut guard = self.inner.lock().unwrap();
        guard.active = guard.active.saturating_sub(1);
    }
}

/// Separate inbound and outbound pairing budgets plus code-only refusal counters (§5.2, §5.3).
#[derive(Clone, Debug)]
pub struct PairingBudgets {
    pub inbound: AttemptLimiter,
    pub outbound: AttemptLimiter,
    refusals: Arc<Mutex<BTreeMap<String, u64>>>,
}

impl Default for PairingBudgets {
    fn default() -> Self {
        Self {
            inbound: AttemptLimiter::new(MAX_INBOUND_STARTS_PER_MIN, MAX_INBOUND_CONCURRENT),
            outbound: AttemptLimiter::new(MAX_OUTBOUND_STARTS_PER_MIN, MAX_OUTBOUND_CONCURRENT),
            refusals: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl PairingBudgets {
    /// Increments a code-only refusal counter. Never records peer IDs (Q2-13e).
    pub fn record_refusal(&self, code: &str) {
        let mut guard = self.refusals.lock().unwrap();
        *guard.entry(code.to_string()).or_insert(0) += 1;
    }

    pub fn refusal_snapshot(&self) -> BTreeMap<String, u64> {
        self.refusals.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_exhaustion_leaves_outbound_budget_intact() {
        let budgets = PairingBudgets::default();
        for _ in 0..MAX_INBOUND_STARTS_PER_MIN {
            let permit = budgets.inbound.try_acquire().expect("inbound slot");
            drop(permit);
        }
        assert!(budgets.inbound.try_acquire().is_none());
        assert_eq!(budgets.outbound.remaining(), MAX_OUTBOUND_STARTS_PER_MIN);
        assert!(budgets.outbound.try_acquire().is_some());
    }

    #[test]
    fn failed_outbound_attempts_never_refund_60s_budget() {
        let budgets = PairingBudgets::default();
        for _ in 0..MAX_OUTBOUND_STARTS_PER_MIN {
            let permit = budgets.outbound.try_acquire().expect("outbound slot");
            drop(permit);
        }
        assert!(budgets.outbound.try_acquire().is_none());
        assert_eq!(budgets.outbound.remaining(), 0);
    }

    #[test]
    fn refusal_counters_record_codes_without_peer_ids() {
        let budgets = PairingBudgets::default();
        budgets.record_refusal("pairing.no_intent");
        budgets.record_refusal("pairing.no_intent");
        budgets.record_refusal("pairing.key_algorithm");
        let snap = budgets.refusal_snapshot();
        assert_eq!(snap.get("pairing.no_intent"), Some(&2));
        assert_eq!(snap.get("pairing.key_algorithm"), Some(&1));
    }
}
