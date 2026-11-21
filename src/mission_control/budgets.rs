use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::admission::Refusal;
use super::authority::{Grants, Record};
use super::limits::ReadLimits;

#[derive(Default)]
pub(super) struct Budgets(Mutex<Counts>);

#[derive(Default)]
struct Bucket {
    live: usize,
    attempts: VecDeque<Instant>,
}

#[derive(Default)]
struct Counts {
    connections: usize,
    principals: HashMap<String, Bucket>,
    records: HashMap<String, Bucket>,
}

pub(super) struct Slot {
    counts: Arc<Budgets>,
    key: String,
    mode: Mode,
}

#[derive(Clone, Copy)]
pub(super) enum Mode {
    Upgrade,
    Stream,
    Snapshot,
}

const WINDOW: Duration = Duration::from_secs(60);

impl Budgets {
    pub(super) fn take(
        self: &Arc<Self>,
        record: &Record,
        mode: Mode,
        limits: &ReadLimits,
    ) -> Result<Slot, Refusal> {
        let mut counts = self.0.lock().map_err(|_| Refusal::UNAVAILABLE)?;
        let now = Instant::now();
        let relevant = |bucket: &mut Bucket| {
            while bucket
                .attempts
                .front()
                .is_some_and(|at| now.saturating_duration_since(*at) >= WINDOW)
            {
                bucket.attempts.pop_front();
            }
            bucket.live != 0 || !bucket.attempts.is_empty()
        };
        counts.principals.retain(|_, value| relevant(value));
        counts.records.retain(|_, value| relevant(value));
        if matches!(mode, Mode::Upgrade) && counts.connections >= limits.connections_global {
            return Err(Refusal::RATE_LIMIT);
        }
        let key = if matches!(mode, Mode::Upgrade) {
            &record.principal
        } else {
            &record.record_id
        };
        let bucket = if matches!(mode, Mode::Upgrade) {
            counts.principals.entry(key.clone()).or_default()
        } else {
            counts.records.entry(key.clone()).or_default()
        };
        match mode {
            Mode::Upgrade
                if bucket.live >= limits.connections_per_principal
                    || bucket.attempts.len() >= limits.upgrades_per_principal_per_min =>
            {
                return Err(Refusal::RATE_LIMIT)
            }
            Mode::Stream if bucket.live >= limits.streams_per_token => {
                return Err(Refusal::RATE_LIMIT)
            }
            Mode::Snapshot | Mode::Stream
                if bucket.attempts.len()
                    >= http_rate(record, limits.http_requests_per_token_per_min) =>
            {
                return Err(Refusal::RATE_LIMIT);
            }
            _ => {}
        }
        if !matches!(mode, Mode::Snapshot) {
            bucket.live += 1;
        }
        bucket.attempts.push_back(now);
        if matches!(mode, Mode::Upgrade) {
            counts.connections += 1;
        }
        Ok(Slot {
            counts: Arc::clone(self),
            key: key.clone(),
            mode,
        })
    }
}

fn http_rate(record: &Record, maximum: usize) -> usize {
    match &record.grants {
        Grants::Machine { rate, .. } => (*rate as usize).min(maximum),
        _ => maximum,
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let Ok(mut counts) = self.counts.0.lock() else {
            return;
        };
        let bucket = match self.mode {
            Mode::Upgrade => {
                counts.connections = counts.connections.saturating_sub(1);
                counts.principals.get_mut(&self.key)
            }
            Mode::Stream => counts.records.get_mut(&self.key),
            Mode::Snapshot => None,
        };
        if let Some(bucket) = bucket {
            bucket.live = bucket.live.saturating_sub(1);
        }
    }
}
