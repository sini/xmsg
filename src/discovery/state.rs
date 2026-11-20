use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{Notify, Semaphore};

use super::{Candidate, CandidateTable, SharedCandidates, MAX_TTL_SECS, MDNS_CAP};
use crate::fed::PeersMap;

#[derive(Clone, Debug)]
pub(crate) struct Presence {
    pub uri: String,
    pub rule: String,
    pub policy: Arc<PeersMap>,
    pub candidate: Candidate,
    pub verified_at: Instant,
    pub expires_at: Instant,
    pub not_after: i64,
}

#[derive(Clone)]
struct Negative {
    policy: Arc<PeersMap>,
    expires_at: Instant,
}

struct LastAttempt {
    policy: Arc<PeersMap>,
    addr: SocketAddr,
}

#[derive(Default)]
struct Tables {
    presence: HashMap<String, Presence>,
    negative: HashMap<(SocketAddr, String), Negative>,
    last_attempt: HashMap<String, LastAttempt>,
}

pub struct State {
    pub candidates: SharedCandidates,
    pub changed: Arc<Notify>,
    pub probes: Arc<Semaphore>,
    tables: Mutex<Tables>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            candidates: Arc::new(std::sync::RwLock::new(CandidateTable::new())),
            changed: Arc::new(Notify::new()),
            probes: Arc::new(Semaphore::new(4)),
            tables: Mutex::new(Tables::default()),
        }
    }
}

impl State {
    pub(crate) fn identity_uris(
        &self,
        policy: &Arc<PeersMap>,
        now: Instant,
        wall_now: i64,
    ) -> Vec<String> {
        let active = self.active_addresses(now);
        let mut tables = self
            .tables
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        prune(&mut tables, policy, &active, now, wall_now);
        tables.presence.keys().cloned().collect()
    }

    pub(crate) fn order_untried(
        &self,
        policy: &Arc<PeersMap>,
        rule: &str,
        candidates: &mut [Candidate],
    ) {
        let tables = self
            .tables
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(last) = tables
            .last_attempt
            .get(rule)
            .filter(|last| Arc::ptr_eq(&last.policy, policy))
        {
            if let Some(index) = candidates
                .iter()
                .position(|candidate| candidate.addr == last.addr)
            {
                if !candidates.is_empty() {
                    let len = candidates.len();
                    candidates.rotate_left((index + 1) % len);
                }
            }
        }
    }

    pub(crate) fn attempted(
        &self,
        policy: &Arc<PeersMap>,
        rule: &str,
        addr: SocketAddr,
        now: Instant,
    ) {
        let active = self.active_addresses(now);
        let mut tables = self
            .tables
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        prune_attempts(&mut tables, policy, &active);
        if active.contains(&addr) && configured_exact_rule(policy, rule) {
            tables.last_attempt.insert(
                rule.to_owned(),
                LastAttempt {
                    policy: policy.clone(),
                    addr,
                },
            );
        }
    }

    fn active_addresses(&self, now: Instant) -> HashSet<SocketAddr> {
        self.candidates
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .snapshot(now)
            .into_iter()
            .map(|candidate| candidate.addr)
            .collect()
    }

    // Only a completed, exact-rule TLS proof may supply this record.
    pub(crate) fn record_verified(
        &self,
        mut presence: Presence,
        current_policy: &Arc<PeersMap>,
        now: Instant,
        wall_now: i64,
    ) -> bool {
        if presence.uri.is_empty()
            || !Arc::ptr_eq(&presence.policy, current_policy)
            || presence.verified_at > now
            || presence.not_after <= wall_now
        {
            return false;
        }
        let Some(certificate_remaining) = presence.not_after.checked_sub(wall_now) else {
            return false;
        };
        let Ok(certificate_remaining) = u64::try_from(certificate_remaining) else {
            return false;
        };
        let Some(certificate_expiry) = now.checked_add(Duration::from_secs(certificate_remaining))
        else {
            return false;
        };
        let Some(proof_expiry) = presence
            .verified_at
            .checked_add(Duration::from_secs(MAX_TTL_SECS))
        else {
            return false;
        };
        presence.expires_at = presence
            .expires_at
            .min(presence.candidate.expires_at)
            .min(proof_expiry)
            .min(certificate_expiry);
        let active = self.active_addresses(now);
        if presence.expires_at <= now || !active.contains(&presence.candidate.addr) {
            return false;
        }
        let mut tables = self
            .tables
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        prune(&mut tables, current_policy, &active, now, wall_now);
        if tables.presence.len() >= MDNS_CAP && !tables.presence.contains_key(&presence.uri) {
            let oldest = tables
                .presence
                .iter()
                .min_by_key(|(_, row)| row.verified_at)
                .map(|(uri, _)| uri.clone());
            if let Some(oldest) = oldest {
                tables.presence.remove(&oldest);
            }
        }
        tables.presence.insert(presence.uri.clone(), presence);
        true
    }

    pub(crate) fn lookup(
        &self,
        uri: &str,
        rule: &str,
        policy: &Arc<PeersMap>,
        now: Instant,
        wall_now: i64,
    ) -> Option<Presence> {
        let active = self.active_addresses(now);
        let mut tables = self
            .tables
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        prune(&mut tables, policy, &active, now, wall_now);
        tables
            .presence
            .get(uri)
            .filter(|row| row.rule == rule)
            .cloned()
    }

    pub(crate) fn evict(&self, uri: &str) {
        self.tables
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .presence
            .remove(uri);
    }

    pub(crate) fn negative(
        &self,
        addr: SocketAddr,
        rule: &str,
        policy: &Arc<PeersMap>,
        expires_at: Instant,
        now: Instant,
    ) {
        let active = self.active_addresses(now);
        if expires_at <= now || !active.contains(&addr) {
            return;
        }
        let mut tables = self
            .tables
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        tables.negative.retain(|(addr, _), row| {
            row.expires_at > now && active.contains(addr) && Arc::ptr_eq(&row.policy, policy)
        });
        let key = (addr, rule.to_owned());
        if let Some(row) = tables.negative.get_mut(&key) {
            row.expires_at = row.expires_at.min(expires_at);
            return;
        }
        if tables.negative.len() >= MDNS_CAP {
            let earliest = tables
                .negative
                .iter()
                .min_by_key(|(_, row)| row.expires_at)
                .map(|(key, _)| key.clone());
            if let Some(earliest) = earliest {
                tables.negative.remove(&earliest);
            }
        }
        tables.negative.insert(
            key,
            Negative {
                policy: policy.clone(),
                expires_at,
            },
        );
    }

    pub(crate) fn is_negative(
        &self,
        addr: SocketAddr,
        rule: &str,
        policy: &Arc<PeersMap>,
        now: Instant,
    ) -> bool {
        let active = self.active_addresses(now);
        let mut tables = self
            .tables
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        tables.negative.retain(|(addr, _), row| {
            row.expires_at > now && active.contains(addr) && Arc::ptr_eq(&row.policy, policy)
        });
        tables.negative.contains_key(&(addr, rule.to_owned()))
    }
}

fn configured_exact_rule(policy: &PeersMap, rule: &str) -> bool {
    policy.get(rule).is_some_and(|peer| {
        peer.name == rule
            && peer.pin.is_none()
            && peer.ca.is_some()
            && peer
                .identities
                .as_deref()
                .is_some_and(|ids| matches!(ids, [uri] if !uri.contains('*')))
    })
}

fn prune_attempts(tables: &mut Tables, policy: &Arc<PeersMap>, active: &HashSet<SocketAddr>) {
    tables.last_attempt.retain(|rule, last| {
        Arc::ptr_eq(&last.policy, policy)
            && active.contains(&last.addr)
            && configured_exact_rule(policy, rule)
    });
}

fn prune(
    tables: &mut Tables,
    policy: &Arc<PeersMap>,
    active: &HashSet<SocketAddr>,
    now: Instant,
    wall_now: i64,
) {
    prune_attempts(tables, policy, active);
    tables.presence.retain(|_, row| {
        row.expires_at > now
            && row.not_after > wall_now
            && active.contains(&row.candidate.addr)
            && Arc::ptr_eq(&row.policy, policy)
    });
    tables.negative.retain(|(addr, _), row| {
        row.expires_at > now && active.contains(addr) && Arc::ptr_eq(&row.policy, policy)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::Source;

    fn candidate(state: &State, now: Instant, ttl: u64) -> Candidate {
        let candidate = Candidate {
            addr: "192.0.2.1:7788".parse().unwrap(),
            source: Source::Mdns,
            hint: Some("untrusted hint".into()),
            root_fp: None,
            seen_at: now,
            expires_at: now + Duration::from_secs(ttl),
        };
        assert!(state
            .candidates
            .write()
            .unwrap()
            .upsert(candidate.clone(), now));
        candidate
    }

    fn presence(candidate: Candidate, policy: &Arc<PeersMap>, now: Instant) -> Presence {
        Presence {
            uri: "spiffe://test/node/owner/device".into(),
            rule: "exact rule".into(),
            policy: policy.clone(),
            candidate,
            verified_at: now,
            expires_at: now + Duration::from_secs(3600),
            not_after: 10_000,
        }
    }

    fn rules(count: usize) -> Arc<PeersMap> {
        let mut policy = PeersMap::empty();
        for index in 0..count {
            policy
                .insert(crate::fed::PeerConfig {
                    name: format!("rule{index}"),
                    ca: Some("component.pem".into()),
                    identities: Some(vec![format!("spiffe://test/host/h{index}/user/owner")]),
                    ..Default::default()
                })
                .unwrap();
        }
        Arc::new(policy)
    }

    #[test]
    fn expired_certificate_proof_cannot_publish_presence() {
        let state = State::default();
        let now = Instant::now();
        let policy = Arc::new(PeersMap::empty());
        let mut row = presence(candidate(&state, now, 60), &policy, now);
        row.uri = "spiffe://test/host/device/user/owner".into();
        let uri = row.uri.clone();
        let rule = row.rule.clone();
        assert!(state.record_verified(row.clone(), &policy, now, 100));
        assert!(state.lookup(&uri, &rule, &policy, now, 100).is_some());
        state.evict(&uri);

        row.not_after = 99;
        assert!(
            !state.record_verified(row, &policy, now, 100),
            "expired certificate proof published presence"
        );
        assert!(state.lookup(&uri, &rule, &policy, now, 100).is_none());
    }

    #[test]
    fn cancelled_probe_retains_next_candidate_across_sends() {
        let state = State::default();
        let now = Instant::now();
        let policy = rules(65);
        let first = candidate(&state, now, 60);
        let mut second = first.clone();
        second.addr = "192.0.2.2:7788".parse().unwrap();
        assert!(state
            .candidates
            .write()
            .unwrap()
            .upsert(second.clone(), now));
        let mut candidates = vec![first.clone(), second.clone()];
        state.attempted(&policy, "rule0", first.addr, now);
        for index in 1..65 {
            state.attempted(&policy, &format!("rule{index}"), first.addr, now);
        }
        state.order_untried(&policy, "rule0", &mut candidates);
        assert_eq!(
            candidates[0].addr, second.addr,
            "other configured rules erased cancelled-probe continuation"
        );
        assert_eq!(state.tables.lock().unwrap().last_attempt.len(), 65);
        state.attempted(&policy, "rule0", second.addr, now);
        state.order_untried(&policy, "rule0", &mut candidates);
        assert_eq!(candidates[0].addr, first.addr);
        let current = rules(1);
        candidates = vec![second.clone(), first.clone()];
        state.order_untried(&current, "rule0", &mut candidates);
        assert_eq!(
            candidates[0].addr, second.addr,
            "old generation reordered current candidates"
        );
        state.attempted(&current, "rule0", first.addr, now);
        assert_eq!(state.tables.lock().unwrap().last_attempt.len(), 1);
        state.attempted(&current, "unconfigured", first.addr, now);
        assert_eq!(
            state.tables.lock().unwrap().last_attempt.len(),
            1,
            "unconfigured rule grew cursor history"
        );
        state
            .candidates
            .write()
            .unwrap()
            .clear_source(super::super::Source::Mdns);
        state.attempted(&current, "rule0", first.addr, now);
        assert!(
            state.tables.lock().unwrap().last_attempt.is_empty(),
            "removed candidates retained cursors"
        );
    }

    #[test]
    fn verified_presence_is_identity_keyed_and_capped_by_proof_source_and_certificate() {
        let state = State::default();
        let now = Instant::now();
        let policy = Arc::new(PeersMap::empty());
        let row = presence(candidate(&state, now, 900), &policy, now);
        let uri = row.uri.clone();
        assert!(state.record_verified(row, &policy, now, 100));
        let stored = state.lookup(&uri, "exact rule", &policy, now, 100).unwrap();
        assert_eq!(stored.expires_at, now + Duration::from_secs(600));
        assert!(state
            .lookup("untrusted hint", "exact rule", &policy, now, 100)
            .is_none());
        assert!(state
            .lookup(&uri, "other rule", &policy, now, 100)
            .is_none());
        assert!(state
            .lookup(
                &uri,
                "exact rule",
                &policy,
                now + Duration::from_secs(600),
                700
            )
            .is_none());

        let mut row = presence(candidate(&state, now, 20), &policy, now);
        row.not_after = 110;
        assert!(state.record_verified(row, &policy, now, 100));
        assert_eq!(
            state
                .lookup(&uri, "exact rule", &policy, now, 100)
                .unwrap()
                .expires_at,
            now + Duration::from_secs(10)
        );
        assert!(state
            .lookup(&uri, "exact rule", &policy, now, 110)
            .is_none());

        let row = presence(candidate(&state, now, 20), &policy, now);
        assert!(state.record_verified(row, &policy, now, 100));
        assert_eq!(
            state
                .lookup(&uri, "exact rule", &policy, now, 100)
                .unwrap()
                .expires_at,
            now + Duration::from_secs(20)
        );
        state.evict(&uri);
        assert!(state
            .lookup(&uri, "exact rule", &policy, now, 100)
            .is_none());
    }

    #[test]
    fn policy_generation_rejects_late_proofs_and_invalidates_old_presence() {
        let state = State::default();
        let now = Instant::now();
        let old = Arc::new(PeersMap::empty());
        let current = Arc::new(PeersMap::empty());
        let row = presence(candidate(&state, now, 60), &old, now);
        let uri = row.uri.clone();
        assert!(!state.record_verified(row.clone(), &current, now, 100));
        assert!(state.record_verified(row, &old, now, 100));
        assert!(state
            .lookup(&uri, "exact rule", &current, now, 100)
            .is_none());
    }

    #[test]
    fn candidate_refresh_cannot_extend_a_verified_presence_and_source_removal_evicts() {
        let state = State::default();
        let now = Instant::now();
        let policy = Arc::new(PeersMap::empty());
        let candidate = candidate(&state, now, 20);
        let row = presence(candidate.clone(), &policy, now);
        let uri = row.uri.clone();
        assert!(state.record_verified(row, &policy, now, 100));
        let mut refreshed = candidate.clone();
        refreshed.expires_at = now + Duration::from_secs(100);
        assert!(state.candidates.write().unwrap().upsert(refreshed, now));
        assert!(state
            .lookup(
                &uri,
                "exact rule",
                &policy,
                now + Duration::from_secs(20),
                120
            )
            .is_none());
        assert!(state.record_verified(
            presence(candidate.clone(), &policy, now),
            &policy,
            now,
            100
        ));
        state.candidates.write().unwrap().clear_source(Source::Mdns);
        assert!(state
            .lookup(&uri, "exact rule", &policy, now, 100)
            .is_none());
    }

    #[test]
    fn negatives_expire_without_refresh_extension_and_follow_source_and_policy() {
        let state = State::default();
        let now = Instant::now();
        let policy = Arc::new(PeersMap::empty());
        let candidate = candidate(&state, now, 120);
        state.negative(
            candidate.addr,
            "rule",
            &policy,
            now + Duration::from_secs(20),
            now,
        );
        state.negative(
            candidate.addr,
            "rule",
            &policy,
            now + Duration::from_secs(100),
            now,
        );
        assert!(state.is_negative(candidate.addr, "rule", &policy, now));
        assert!(!state.is_negative(candidate.addr, "other rule", &policy, now));
        assert!(!state.is_negative(
            candidate.addr,
            "rule",
            &policy,
            now + Duration::from_secs(20)
        ));
        state.negative(candidate.addr, "rule", &policy, candidate.expires_at, now);
        assert!(!state.is_negative(candidate.addr, "rule", &Arc::new(PeersMap::empty()), now));
        state.negative(candidate.addr, "rule", &policy, candidate.expires_at, now);
        state.candidates.write().unwrap().clear_source(Source::Mdns);
        assert!(!state.is_negative(candidate.addr, "rule", &policy, now));
    }

    #[test]
    fn negative_history_is_bounded_even_with_many_rules_and_expired_addresses() {
        let state = State::default();
        let now = Instant::now();
        let policy = Arc::new(PeersMap::empty());
        let candidate = candidate(&state, now, 120);
        for index in 0..1000 {
            state.negative(
                candidate.addr,
                &format!("rule {index}"),
                &policy,
                candidate.expires_at,
                now,
            );
        }
        assert_eq!(state.tables.lock().unwrap().negative.len(), MDNS_CAP);
        assert!(!state.is_negative("192.0.2.2:7788".parse().unwrap(), "rule", &policy, now));
        assert!(state.tables.lock().unwrap().negative.len() <= MDNS_CAP);
        state.candidates.write().unwrap().clear_source(Source::Mdns);
        assert!(!state.is_negative(candidate.addr, "rule", &policy, now));
        assert!(state.tables.lock().unwrap().negative.is_empty());
    }
}
