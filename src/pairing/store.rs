//! The durable pairing authority: OOB intents, grants, removed-grant tombstones and device
//! blocks, in the node's primary database. Reservation, activation, removal and legacy import
//! each run in one `BEGIN IMMEDIATE` transaction, so removal and activation serialize: once
//! `remove` commits, no activation can recreate that grant.

use std::collections::HashSet;

use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

use super::auth::{
    device_id_from_pin, Authority, DeviceId, Grant, GrantId, LegacyPredicates, ManualEvidence,
    PROVENANCE_LEGACY, PROVENANCE_MANUAL,
};
use super::codec::{
    parse_and_verify_receipt, ExposurePolicy, PairingProfile, Receipt, ReceiptVerificationContext,
    MAX_CEREMONY_WINDOW_SECS,
};
use crate::fed::PeersMap;

/// Pending local intents retained at once.
pub const MAX_PENDING_INTENTS: usize = 32;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS pairing_intents (
    intent_id BLOB PRIMARY KEY CHECK (length(intent_id) = 16),
    grant_id BLOB NOT NULL UNIQUE CHECK (length(grant_id) = 16),
    peer_id BLOB NOT NULL CHECK (length(peer_id) = 32),
    profile TEXT NOT NULL,
    exposure BLOB NOT NULL,
    grant_not_after INTEGER,
    revision INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    replaces BLOB,
    state TEXT NOT NULL CHECK (state IN ('open', 'consumed', 'cancelled')),
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pairing_grants (
    grant_id BLOB PRIMARY KEY CHECK (length(grant_id) = 16),
    issuer BLOB NOT NULL CHECK (length(issuer) = 32),
    subject BLOB NOT NULL CHECK (length(subject) = 32),
    provenance TEXT NOT NULL CHECK (provenance IN ('manual_authenticated_oob', 'legacy_unilateral')),
    profile TEXT,
    exposure BLOB,
    legacy_predicates TEXT,
    not_after INTEGER,
    origin_intent_id BLOB,
    transaction_id BLOB,
    exporter BLOB,
    receipt_local BLOB,
    receipt_remote BLOB,
    ceremony_created INTEGER,
    ceremony_expires INTEGER,
    activated_at INTEGER NOT NULL,
    active INTEGER NOT NULL,
    CHECK ((provenance = 'manual_authenticated_oob') = (profile IS NOT NULL AND exposure IS NOT NULL
        AND receipt_local IS NOT NULL AND receipt_remote IS NOT NULL AND legacy_predicates IS NULL)),
    CHECK ((provenance = 'legacy_unilateral') = (legacy_predicates IS NOT NULL AND profile IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_pairing_grants_subject ON pairing_grants(subject);
CREATE TABLE IF NOT EXISTS pairing_removed_grants (
    grant_id BLOB PRIMARY KEY CHECK (length(grant_id) = 16),
    removed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pairing_device_blocks (
    device_id BLOB PRIMARY KEY CHECK (length(device_id) = 32),
    blocked_at INTEGER NOT NULL
);
";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("pairing store: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("device is blocked")]
    Blocked,
    #[error("grant was removed")]
    Removed,
    #[error("intent is consumed, cancelled, expired or unknown")]
    IntentUnavailable,
    #[error("activation does not match the reserved intent: {0}")]
    Binding(&'static str),
    #[error("receipt rejected: {0}")]
    Receipt(#[from] super::codec::CodecError),
    #[error("pending intent limit reached")]
    PendingFull,
    #[error("invalid intent: {0}")]
    Invalid(&'static str),
}

/// A local OOB intent: the expected peer ID and directional profile, fixed before dialing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentRequest {
    pub peer: DeviceId,
    pub exposure: ExposurePolicy,
    pub grant_not_after: Option<i64>,
    pub revision: u32,
    pub expires_at: i64,
    /// The legacy grant an explicit replace-legacy action retires on activation.
    pub replaces: Option<GrantId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Intent {
    pub intent_id: [u8; 16],
    pub grant_id: GrantId,
}

/// Both receipts, each verified against the live ceremony's context.
pub struct VerifiedReceipts {
    local: Receipt,
    remote: Receipt,
    local_bytes: Vec<u8>,
    remote_bytes: Vec<u8>,
    exporter: [u8; 32],
    created: u32,
}

impl VerifiedReceipts {
    pub fn verify(
        local: &[u8],
        remote: &[u8],
        ctx: &ReceiptVerificationContext<'_>,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            local: parse_and_verify_receipt(local, ctx)?,
            remote: parse_and_verify_receipt(remote, ctx)?,
            local_bytes: local.to_vec(),
            remote_bytes: remote.to_vec(),
            exporter: ctx.exporter,
            created: ctx.created_utc,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activated {
    New,
    /// An identical record was already active; nothing changed.
    AlreadyActive,
}

fn random<const N: usize>() -> Result<[u8; N], StoreError> {
    let mut out = [0u8; N];
    SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| StoreError::Invalid("system random source failed"))?;
    Ok(out)
}

fn immediate(conn: &Connection) -> Result<Transaction<'_>, StoreError> {
    Ok(Transaction::new_unchecked(
        conn,
        TransactionBehavior::Immediate,
    )?)
}

fn blocked_in(tx: &Connection, device: &DeviceId) -> Result<bool, StoreError> {
    Ok(tx
        .query_row(
            "SELECT 1 FROM pairing_device_blocks WHERE device_id = ?1",
            [&device[..]],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn removed_in(tx: &Connection, grant: &GrantId) -> Result<bool, StoreError> {
    Ok(tx
        .query_row(
            "SELECT 1 FROM pairing_removed_grants WHERE grant_id = ?1",
            [&grant[..]],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// A fresh grant ID that no intent, grant or tombstone has ever held.
fn fresh_grant_id(tx: &Connection) -> Result<GrantId, StoreError> {
    loop {
        let id: GrantId = random()?;
        let used: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pairing_intents WHERE grant_id = ?1)
                 OR EXISTS(SELECT 1 FROM pairing_grants WHERE grant_id = ?1)
                 OR EXISTS(SELECT 1 FROM pairing_removed_grants WHERE grant_id = ?1)",
            [&id[..]],
            |r| r.get(0),
        )?;
        if !used {
            return Ok(id);
        }
    }
}

/// Persists an OOB intent and durably reserves its one grant ID.
pub fn reserve_intent(
    conn: &Connection,
    req: &IntentRequest,
    now: i64,
) -> Result<Intent, StoreError> {
    req.exposure
        .validate()
        .map_err(|_| StoreError::Invalid("exposure policy"))?;
    if req.expires_at <= now || req.expires_at - now > i64::from(MAX_CEREMONY_WINDOW_SECS) {
        return Err(StoreError::Invalid("intent lifetime must be 1..=120 s"));
    }
    if req.grant_not_after.is_some_and(|end| end <= now) {
        return Err(StoreError::Invalid("grant expiry is in the past"));
    }
    let tx = immediate(conn)?;
    if blocked_in(&tx, &req.peer)? {
        return Err(StoreError::Blocked);
    }
    let pending: Vec<Vec<u8>> = tx
        .prepare("SELECT peer_id FROM pairing_intents WHERE state = 'open' AND expires_at > ?1")?
        .query_map([now], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    if pending.iter().any(|peer| peer[..] == req.peer[..]) {
        return Err(StoreError::Invalid(
            "a pending intent for this device exists",
        ));
    }
    if pending.len() >= MAX_PENDING_INTENTS {
        return Err(StoreError::PendingFull);
    }
    if let Some(legacy) = &req.replaces {
        let subject: Option<Vec<u8>> = tx
            .query_row(
                "SELECT subject FROM pairing_grants
                 WHERE grant_id = ?1 AND provenance = 'legacy_unilateral' AND active = 1",
                [&legacy[..]],
                |r| r.get(0),
            )
            .optional()?;
        if subject.as_deref() != Some(&req.peer[..]) || removed_in(&tx, legacy)? {
            return Err(StoreError::Invalid(
                "replaced grant is not this device's active legacy grant",
            ));
        }
    }
    let intent = Intent {
        intent_id: random()?,
        grant_id: fresh_grant_id(&tx)?,
    };
    let exposure = req
        .exposure
        .encode_cbor()
        .map_err(|_| StoreError::Invalid("exposure policy"))?;
    tx.execute(
        "INSERT INTO pairing_intents (intent_id, grant_id, peer_id, profile, exposure,
             grant_not_after, revision, expires_at, replaces, state, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'open', ?10)",
        params![
            &intent.intent_id[..],
            &intent.grant_id[..],
            &req.peer[..],
            req.exposure.profile.as_str(),
            exposure,
            req.grant_not_after,
            req.revision,
            req.expires_at,
            req.replaces.as_ref().map(|id| id.to_vec()),
            now
        ],
    )?;
    tx.commit()?;
    Ok(intent)
}

struct IntentRow {
    grant_id: Vec<u8>,
    peer_id: Vec<u8>,
    exposure: Vec<u8>,
    grant_not_after: Option<i64>,
    revision: u32,
    expires_at: i64,
    replaces: Option<Vec<u8>>,
    state: String,
}

/// Activates the locally issued grant of `intent` from both verified receipts.
pub fn activate(
    conn: &Connection,
    issuer: &DeviceId,
    intent_id: &[u8; 16],
    receipts: &VerifiedReceipts,
    now: i64,
) -> Result<Activated, StoreError> {
    let tx = immediate(conn)?;
    let row = tx
        .query_row(
            "SELECT grant_id, peer_id, exposure, grant_not_after, revision, expires_at,
                    replaces, state
             FROM pairing_intents WHERE intent_id = ?1",
            [&intent_id[..]],
            |r| {
                Ok(IntentRow {
                    grant_id: r.get(0)?,
                    peer_id: r.get(1)?,
                    exposure: r.get(2)?,
                    grant_not_after: r.get(3)?,
                    revision: r.get(4)?,
                    expires_at: r.get(5)?,
                    replaces: r.get(6)?,
                    state: r.get(7)?,
                })
            },
        )
        .optional()?
        .ok_or(StoreError::IntentUnavailable)?;
    let grant_id: GrantId = row
        .grant_id
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Binding("grant_id"))?;
    let peer: DeviceId = row
        .peer_id
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Binding("peer"))?;
    if removed_in(&tx, &grant_id)? {
        return Err(StoreError::Removed);
    }
    if blocked_in(&tx, &peer)? {
        return Err(StoreError::Blocked);
    }
    let exposure =
        ExposurePolicy::decode_cbor(&row.exposure).map_err(|_| StoreError::Binding("exposure"))?;
    let exposure_sha256 = exposure
        .sha256()
        .map_err(|_| StoreError::Binding("exposure"))?;
    let (local, remote) = (&receipts.local, &receipts.remote);
    let expected_not_after = row.grant_not_after.map(u32::try_from).transpose();
    let checks: [(bool, &'static str); 10] = [
        (local.signer_id == *issuer, "local signer"),
        (local.subject_id == peer, "local subject"),
        (remote.signer_id == peer, "remote signer"),
        (remote.subject_id == *issuer, "remote subject"),
        (local.signer_role != remote.signer_role, "roles"),
        (local.transaction_id == remote.transaction_id, "transaction"),
        (local.grant_id == grant_id, "grant_id"),
        (local.profile == exposure.profile, "profile"),
        (
            local.exposure_policy_sha256 == exposure_sha256,
            "exposure digest",
        ),
        (
            local.policy_revision == row.revision
                && expected_not_after.ok() == Some(local.grant_not_after),
            "revision or grant expiry",
        ),
    ];
    if let Some((_, what)) = checks.iter().find(|(ok, _)| !ok) {
        return Err(StoreError::Binding(what));
    }
    let created = i64::from(receipts.created);
    let expires = i64::from(local.ceremony_expires_utc);
    if now < created || now > expires {
        return Err(StoreError::Binding("outside the ceremony window"));
    }
    if row.grant_not_after.is_some_and(|end| end <= now) {
        return Err(StoreError::Binding("grant expiry passed"));
    }
    let evidence = ManualEvidence {
        transaction_id: local.transaction_id,
        exporter: receipts.exporter,
        receipt_local: receipts.local_bytes.clone(),
        receipt_remote: receipts.remote_bytes.clone(),
        ceremony_created: created,
        ceremony_expires: expires,
        activated_at: now,
    };
    if let Some(existing) = load_grant(&tx, &grant_id)? {
        // Only an identical repeat of the same ceremony is accepted, and it changes nothing.
        let same = existing.active
            && existing.issuer == *issuer
            && existing.subject == peer
            && existing.not_after == row.grant_not_after
            && matches!(&existing.authority, Authority::Manual { profile, exposure: stored, evidence: old }
                if *profile == exposure.profile && *stored == exposure
                    && old.transaction_id == evidence.transaction_id
                    && old.receipt_local == evidence.receipt_local
                    && old.receipt_remote == evidence.receipt_remote);
        return if same {
            Ok(Activated::AlreadyActive)
        } else {
            Err(StoreError::Binding(
                "a different record holds this grant_id",
            ))
        };
    }
    if row.state != "open" || row.expires_at <= now {
        return Err(StoreError::IntentUnavailable);
    }
    if let Some(legacy) = &row.replaces {
        let retired = tx.execute(
            "UPDATE pairing_grants SET active = 0
             WHERE grant_id = ?1 AND provenance = 'legacy_unilateral' AND active = 1
               AND subject = ?2",
            params![legacy, &peer[..]],
        )?;
        if retired != 1 {
            return Err(StoreError::Binding("replaced legacy grant is gone"));
        }
        tx.execute(
            "INSERT OR IGNORE INTO pairing_removed_grants (grant_id, removed_at) VALUES (?1, ?2)",
            params![legacy, now],
        )?;
    }
    tx.execute(
        "INSERT INTO pairing_grants (grant_id, issuer, subject, provenance, profile, exposure,
             not_after, origin_intent_id, transaction_id, exporter, receipt_local, receipt_remote,
             ceremony_created, ceremony_expires, activated_at, active)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 1)",
        params![
            &grant_id[..],
            &issuer[..],
            &peer[..],
            PROVENANCE_MANUAL,
            exposure.profile.as_str(),
            row.exposure,
            row.grant_not_after,
            &intent_id[..],
            &evidence.transaction_id[..],
            &evidence.exporter[..],
            evidence.receipt_local,
            evidence.receipt_remote,
            created,
            expires,
            now
        ],
    )?;
    tx.execute(
        "UPDATE pairing_intents SET state = 'consumed' WHERE intent_id = ?1",
        [&intent_id[..]],
    )?;
    tx.commit()?;
    Ok(Activated::New)
}

/// Removes one grant (active or only reserved): tombstones its ID, consumes the intent that
/// reserved it, and cancels any replacement intent depending on it. True when anything changed.
pub fn remove(conn: &Connection, grant_id: &GrantId, now: i64) -> Result<bool, StoreError> {
    let tx = immediate(conn)?;
    let mut changed = tx.execute(
        "UPDATE pairing_grants SET active = 0 WHERE grant_id = ?1 AND active = 1",
        [&grant_id[..]],
    )?;
    changed += tx.execute(
        "UPDATE pairing_intents SET state = 'consumed' WHERE grant_id = ?1 AND state = 'open'",
        [&grant_id[..]],
    )?;
    changed += tx.execute(
        "UPDATE pairing_intents SET state = 'cancelled' WHERE replaces = ?1 AND state = 'open'",
        [&grant_id[..]],
    )?;
    changed += tx.execute(
        "INSERT OR IGNORE INTO pairing_removed_grants (grant_id, removed_at) VALUES (?1, ?2)",
        params![&grant_id[..], now],
    )?;
    tx.commit()?;
    Ok(changed > 0)
}

/// A durable full-ID block, above every grant and legacy rule. It also cancels the device's
/// open intents; its grants stay recorded but no longer authorize.
pub fn block_device(conn: &Connection, device: &DeviceId, now: i64) -> Result<(), StoreError> {
    let tx = immediate(conn)?;
    tx.execute(
        "INSERT OR IGNORE INTO pairing_device_blocks (device_id, blocked_at) VALUES (?1, ?2)",
        params![&device[..], now],
    )?;
    tx.execute(
        "UPDATE pairing_intents SET state = 'cancelled' WHERE peer_id = ?1 AND state = 'open'",
        [&device[..]],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn unblock_device(conn: &Connection, device: &DeviceId) -> Result<bool, StoreError> {
    Ok(conn.execute(
        "DELETE FROM pairing_device_blocks WHERE device_id = ?1",
        [&device[..]],
    )? > 0)
}

pub fn blocked_devices(conn: &Connection) -> Result<HashSet<DeviceId>, StoreError> {
    ids(conn, "SELECT device_id FROM pairing_device_blocks")
}

pub fn removed_grants(conn: &Connection) -> Result<HashSet<GrantId>, StoreError> {
    ids(conn, "SELECT grant_id FROM pairing_removed_grants")
}

fn ids<const N: usize>(conn: &Connection, sql: &str) -> Result<HashSet<[u8; N]>, StoreError> {
    let rows: Vec<Vec<u8>> = conn
        .prepare(sql)?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(rows
        .into_iter()
        .filter_map(|row| row.try_into().ok())
        .collect())
}

const GRANT_COLUMNS: &str = "grant_id, issuer, subject, provenance, profile, exposure,
    legacy_predicates, not_after, transaction_id, exporter, receipt_local, receipt_remote,
    ceremony_created, ceremony_expires, activated_at, active";

fn grant_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Option<Grant>> {
    fn fixed<const N: usize>(v: Option<Vec<u8>>) -> Option<[u8; N]> {
        v?.try_into().ok()
    }
    let provenance: String = r.get(3)?;
    let authority = if provenance == PROVENANCE_MANUAL {
        let profile = r.get::<_, String>(4)?;
        let exposure = r.get::<_, Vec<u8>>(5)?;
        let (Ok(profile), Ok(exposure), Some(transaction_id), Some(exporter)) = (
            PairingProfile::parse(&profile),
            ExposurePolicy::decode_cbor(&exposure),
            fixed(r.get(8)?),
            fixed(r.get(9)?),
        ) else {
            return Ok(None);
        };
        Authority::Manual {
            profile,
            exposure,
            evidence: ManualEvidence {
                transaction_id,
                exporter,
                receipt_local: r.get(10)?,
                receipt_remote: r.get(11)?,
                ceremony_created: r.get(12)?,
                ceremony_expires: r.get(13)?,
                activated_at: r.get(14)?,
            },
        }
    } else if provenance == PROVENANCE_LEGACY {
        let Ok(predicates) = serde_json::from_str(&r.get::<_, String>(6)?) else {
            return Ok(None);
        };
        Authority::Legacy { predicates }
    } else {
        return Ok(None);
    };
    let (Some(grant_id), Some(issuer), Some(subject)) =
        (fixed(r.get(0)?), fixed(r.get(1)?), fixed(r.get(2)?))
    else {
        return Ok(None);
    };
    Ok(Some(Grant {
        grant_id,
        issuer,
        subject,
        not_after: r.get(7)?,
        active: r.get(15)?,
        authority,
    }))
}

fn load_grant(conn: &Connection, grant_id: &GrantId) -> Result<Option<Grant>, StoreError> {
    Ok(conn
        .query_row(
            &format!("SELECT {GRANT_COLUMNS} FROM pairing_grants WHERE grant_id = ?1"),
            [&grant_id[..]],
            grant_from_row,
        )
        .optional()?
        .flatten())
}

/// Every active grant this node issued to `subject`. An unreadable row authorizes nothing.
pub fn grants_for(
    conn: &Connection,
    issuer: &DeviceId,
    subject: &DeviceId,
) -> Result<Vec<Grant>, StoreError> {
    let rows = conn
        .prepare(&format!(
            "SELECT {GRANT_COLUMNS} FROM pairing_grants
             WHERE issuer = ?1 AND subject = ?2 AND active = 1 ORDER BY activated_at, grant_id"
        ))?
        .query_map(params![&issuer[..], &subject[..]], grant_from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows.into_iter().flatten().collect())
}

/// Imports each pinned peers-file entry as a `legacy_unilateral` grant with its exact
/// predicates. An entry already recorded with the same predicates, active or removed, is not
/// imported again, so a removal survives reloads; a changed entry is a new explicit record.
/// Returns the number of grants created.
pub fn import_legacy(
    conn: &Connection,
    issuer: &DeviceId,
    config: &PeersMap,
    now: i64,
) -> Result<usize, StoreError> {
    let tx = immediate(conn)?;
    let mut created = 0;
    let mut peers: Vec<_> = config.values().filter(|p| p.pin.is_some()).collect();
    peers.sort_by(|a, b| a.name.cmp(&b.name));
    for peer in peers {
        let Some(subject) = peer.pin.as_deref().and_then(device_id_from_pin) else {
            continue;
        };
        let predicates = LegacyPredicates::from_peer(peer).to_json();
        let known: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pairing_grants WHERE provenance = 'legacy_unilateral'
                 AND issuer = ?1 AND subject = ?2 AND legacy_predicates = ?3)",
            params![&issuer[..], &subject[..], predicates],
            |r| r.get(0),
        )?;
        if known {
            continue;
        }
        let grant_id = fresh_grant_id(&tx)?;
        tx.execute(
            "INSERT INTO pairing_grants (grant_id, issuer, subject, provenance, legacy_predicates,
                 activated_at, active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
            params![
                &grant_id[..],
                &issuer[..],
                &subject[..],
                PROVENANCE_LEGACY,
                predicates,
                now
            ],
        )?;
        created += 1;
    }
    tx.commit()?;
    Ok(created)
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
