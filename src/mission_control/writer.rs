use std::io;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use super::admission::Refusal;
use super::authority::{Live, Record};
use super::hub::Sequenced;
use super::upstream::ReadHub;
use super::Issuer;

pub(super) struct SessionWriter {
    pub live: std::sync::Arc<Live>,
    pub lease_at: i64,
    pub limits: super::limits::ReadLimits,
}

impl SessionWriter {
    pub(super) fn register(
        issuer: &Issuer,
        record: &Record,
        abort: TcpStream,
        maximum_lease: Duration,
    ) -> Result<Self, Refusal> {
        let wall = crate::storage::now_epoch_secs();
        let lease_at = record
            .absolute_expires_at
            .min(record.idle_expires_at)
            .min(wall.saturating_add(maximum_lease.as_secs() as i64));
        let lease = Instant::now()
            .checked_add(maximum_lease)
            .ok_or(Refusal::UNAVAILABLE)?;
        Ok(Self {
            live: std::sync::Arc::new(issuer.authority.register(record, lease, abort)?),
            lease_at: lease_at.saturating_mul(1000),
            limits: issuer.config.session_limits.clone(),
        })
    }

    pub(super) fn handoff<'a, T>(
        &self,
        nodes: impl IntoIterator<Item = &'a str>,
        source: Option<(&ReadHub, &Sequenced)>,
        write: impl FnOnce() -> T,
    ) -> io::Result<T> {
        self.live
            .authorize_payload(
                nodes,
                || source.is_none_or(|(hub, sequence)| hub.current(sequence)),
                write,
            )
            .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "session write fenced"))
    }
}
