//! The durable pairing authority: OOB intents, grants, removed-grant tombstones and device
//! blocks, in the node's primary database. Reservation, activation, removal and legacy import
//! each run in one `BEGIN IMMEDIATE` transaction, so removal and activation serialize: once
//! `remove` commits, no activation can recreate that grant.
//!
//! Every transaction that changes authority increments one monotonic `authority_revision`
//! inside that transaction and returns it. A policy generation records the revision of the
//! store snapshot it was built from, so a publication can refuse an older snapshot.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, Weak};

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
/// Manual grant slots: manual grants not removed (blocked and expired included) plus the
/// capacity reservations of open intents.
pub const MAX_MANUAL_GRANTS: i64 = 1024;

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
    state TEXT NOT NULL CHECK (state IN ('open', 'consumed', 'cancelled', 'refused_cap')),
    cap_reserved INTEGER NOT NULL DEFAULT 0,
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
CREATE TABLE IF NOT EXISTS pairing_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    authority_revision INTEGER NOT NULL
);
INSERT OR IGNORE INTO pairing_meta (singleton, authority_revision) VALUES (1, 0);
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
    #[error("manual grant capacity reached")]
    GrantsFull,
    #[error("intent holds no capacity reservation")]
    NoReservation,
    #[error("unblock would restore authority: {}", .0.join("; "))]
    WouldRestore(Vec<String>),
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

/// Increments the authority revision inside the caller's transaction and returns it.
fn bump(tx: &Connection) -> Result<u64, StoreError> {
    Ok(tx.query_row(
        "UPDATE pairing_meta SET authority_revision = authority_revision + 1
         WHERE singleton = 1 RETURNING authority_revision",
        [],
        |r| r.get::<_, i64>(0),
    )? as u64)
}

/// The committed authority revision.
pub fn authority_revision(conn: &Connection) -> Result<u64, StoreError> {
    Ok(conn.query_row(
        "SELECT authority_revision FROM pairing_meta WHERE singleton = 1",
        [],
        |r| r.get::<_, i64>(0),
    )? as u64)
}

/// Slots in use: manual grants not removed plus reservations of open intents, optionally
/// excluding one intent. No clock term: only a terminal transaction releases a slot.
fn slots_used(tx: &Connection, except: Option<&[u8; 16]>) -> Result<i64, StoreError> {
    Ok(tx.query_row(
        "SELECT (SELECT COUNT(*) FROM pairing_grants g WHERE g.provenance = 'manual_authenticated_oob'
                    AND NOT EXISTS (SELECT 1 FROM pairing_removed_grants r WHERE r.grant_id = g.grant_id))
              + (SELECT COUNT(*) FROM pairing_intents WHERE state = 'open' AND cap_reserved = 1
                    AND intent_id IS NOT ?1)",
        [except.map(|id| id.to_vec())],
        |r| r.get(0),
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
    // Convenience only; reserve_capacity enforces the cap.
    if slots_used(&tx, None)? >= MAX_MANUAL_GRANTS {
        return Err(StoreError::GrantsFull);
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
    cap_reserved: bool,
}

/// Reserves one manual grant slot for an open intent, before this side signs its receipt.
/// At the cap the intent becomes `refused_cap`, a terminal state, and `GrantsFull` returns.
/// A repeat on an intent that already holds its reservation is a no-op.
pub fn reserve_capacity(
    conn: &Connection,
    intent_id: &[u8; 16],
    now: i64,
) -> Result<(), StoreError> {
    let tx = immediate(conn)?;
    let row: Option<(String, i64, bool)> = tx
        .query_row(
            "SELECT state, expires_at, cap_reserved FROM pairing_intents WHERE intent_id = ?1",
            [&intent_id[..]],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((state, expires_at, reserved)) = row else {
        return Err(StoreError::IntentUnavailable);
    };
    if state != "open" || expires_at <= now {
        return Err(StoreError::IntentUnavailable);
    }
    if reserved {
        return Ok(());
    }
    if slots_used(&tx, Some(intent_id))? + 1 > MAX_MANUAL_GRANTS {
        tx.execute(
            "UPDATE pairing_intents SET state = 'refused_cap' WHERE intent_id = ?1",
            [&intent_id[..]],
        )?;
        tx.commit()?;
        return Err(StoreError::GrantsFull);
    }
    tx.execute(
        "UPDATE pairing_intents SET cap_reserved = 1 WHERE intent_id = ?1",
        [&intent_id[..]],
    )?;
    tx.commit()?;
    Ok(())
}

/// Startup: every open intent and its reservation ends, since no ceremony survives a restart.
pub fn cancel_open_intents(conn: &Connection) -> Result<usize, StoreError> {
    let tx = immediate(conn)?;
    let n = tx.execute(
        "UPDATE pairing_intents SET state = 'cancelled' WHERE state = 'open'",
        [],
    )?;
    tx.commit()?;
    Ok(n)
}

/// Activates the locally issued grant of `intent` from both verified receipts, and returns
/// the authority revision it committed (the current one for an identical repeat).
pub fn activate(
    conn: &Connection,
    issuer: &DeviceId,
    intent_id: &[u8; 16],
    receipts: &VerifiedReceipts,
    now: i64,
) -> Result<(Activated, u64), StoreError> {
    let tx = immediate(conn)?;
    let row = tx
        .query_row(
            "SELECT grant_id, peer_id, exposure, grant_not_after, revision, expires_at,
                    replaces, state, cap_reserved
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
                    cap_reserved: r.get(8)?,
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
            Ok((Activated::AlreadyActive, authority_revision(&tx)?))
        } else {
            Err(StoreError::Binding(
                "a different record holds this grant_id",
            ))
        };
    }
    if row.state != "open" || row.expires_at <= now {
        return Err(StoreError::IntentUnavailable);
    }
    if !row.cap_reserved {
        return Err(StoreError::NoReservation);
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
    let revision = bump(&tx)?;
    tx.commit()?;
    Ok((Activated::New, revision))
}

/// Removes one grant (active or only reserved): tombstones its ID, consumes the intent that
/// reserved it, and cancels any replacement intent depending on it. Returns the committed
/// authority revision; a repeat commits a new revision with no other change.
pub fn remove(conn: &Connection, grant_id: &GrantId, now: i64) -> Result<u64, StoreError> {
    remove_with_marks(conn, grant_id, now, None)
}

/// Removes one grant while recording an in-memory revocation mark before `COMMIT` (§5.4 item 4).
pub fn remove_with_marks(
    conn: &Connection,
    grant_id: &GrantId,
    now: i64,
    revocations: Option<&RevocationRegistry>,
) -> Result<u64, StoreError> {
    let tx = immediate(conn)?;
    let subject: Option<DeviceId> = tx
        .query_row(
            "SELECT subject FROM pairing_grants WHERE grant_id = ?1",
            [&grant_id[..]],
            |r| {
                let bytes: Vec<u8> = r.get(0)?;
                Ok(bytes.try_into().ok())
            },
        )
        .optional()?
        .flatten();
    tx.execute(
        "UPDATE pairing_grants SET active = 0 WHERE grant_id = ?1 AND active = 1",
        [&grant_id[..]],
    )?;
    tx.execute(
        "UPDATE pairing_intents SET state = 'consumed' WHERE grant_id = ?1 AND state = 'open'",
        [&grant_id[..]],
    )?;
    tx.execute(
        "UPDATE pairing_intents SET state = 'cancelled' WHERE replaces = ?1 AND state = 'open'",
        [&grant_id[..]],
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO pairing_removed_grants (grant_id, removed_at) VALUES (?1, ?2)",
        params![&grant_id[..], now],
    )?;
    let revision = bump(&tx)?;
    let mark_scope = MarkScope::Grant {
        device: subject,
        grant_id: *grant_id,
    };
    if let Some(reg) = revocations {
        reg.insert_mark(mark_scope.clone(), revision);
        #[cfg(any(test, feature = "test-hooks"))]
        if let Some(cb) = reg
            .before_commit_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
        {
            cb();
        }
    }
    #[cfg(any(test, feature = "test-hooks"))]
    let abort_precommit = revocations.is_some_and(|r| {
        r.inject_precommit_abort
            .swap(false, std::sync::atomic::Ordering::SeqCst)
    });
    #[cfg(not(any(test, feature = "test-hooks")))]
    let abort_precommit = false;
    let commit_res = if abort_precommit {
        drop(tx);
        Err(StoreError::Invalid("injected pre-commit abort"))
    } else {
        tx.commit().map_err(StoreError::from)
    };
    #[cfg(any(test, feature = "test-hooks"))]
    let commit_res = if commit_res.is_ok()
        && revocations.is_some_and(|r| {
            r.inject_commit_io_error
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        }) {
        Err(StoreError::Invalid("injected post-write COMMIT I/O error"))
    } else {
        commit_res
    };
    match commit_res {
        Ok(()) => Ok(revision),
        Err(err) => {
            if let Some(reg) = revocations {
                #[cfg(any(test, feature = "test-hooks"))]
                let read_res = if reg
                    .inject_rev_read_error
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    Err(StoreError::Invalid("injected revision read-back error"))
                } else {
                    authority_revision(conn)
                };
                #[cfg(not(any(test, feature = "test-hooks")))]
                let read_res = authority_revision(conn);
                match read_res {
                    Ok(r) if r >= revision => return Ok(revision),
                    Ok(_) => reg.drop_mark(&mark_scope, revision),
                    Err(_) => {
                        // Ambiguous COMMIT and read-back failed: keep the mark fail-closed.
                    }
                }
            }
            Err(err)
        }
    }
}

/// A durable full-ID block, above every grant and legacy rule. It also cancels the device's
/// open intents; its grants stay recorded but no longer authorize.
pub fn block_device(conn: &Connection, device: &DeviceId, now: i64) -> Result<u64, StoreError> {
    block_device_with_marks(conn, device, now, None)
}

/// Blocks `device` while recording an in-memory revocation mark before `COMMIT` (§5.4 item 4).
pub fn block_device_with_marks(
    conn: &Connection,
    device: &DeviceId,
    now: i64,
    revocations: Option<&RevocationRegistry>,
) -> Result<u64, StoreError> {
    let tx = immediate(conn)?;
    tx.execute(
        "INSERT OR IGNORE INTO pairing_device_blocks (device_id, blocked_at) VALUES (?1, ?2)",
        params![&device[..], now],
    )?;
    tx.execute(
        "UPDATE pairing_intents SET state = 'cancelled' WHERE peer_id = ?1 AND state = 'open'",
        [&device[..]],
    )?;
    let revision = bump(&tx)?;
    let mark_scope = MarkScope::Device(*device);
    if let Some(reg) = revocations {
        reg.insert_mark(mark_scope.clone(), revision);
        #[cfg(any(test, feature = "test-hooks"))]
        if let Some(cb) = reg
            .before_commit_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
        {
            cb();
        }
    }
    #[cfg(any(test, feature = "test-hooks"))]
    let abort_precommit = revocations.is_some_and(|r| {
        r.inject_precommit_abort
            .swap(false, std::sync::atomic::Ordering::SeqCst)
    });
    #[cfg(not(any(test, feature = "test-hooks")))]
    let abort_precommit = false;
    let commit_res = if abort_precommit {
        drop(tx);
        Err(StoreError::Invalid("injected pre-commit abort"))
    } else {
        tx.commit().map_err(StoreError::from)
    };
    #[cfg(any(test, feature = "test-hooks"))]
    let commit_res = if commit_res.is_ok()
        && revocations.is_some_and(|r| {
            r.inject_commit_io_error
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        }) {
        Err(StoreError::Invalid("injected post-write COMMIT I/O error"))
    } else {
        commit_res
    };
    match commit_res {
        Ok(()) => Ok(revision),
        Err(err) => {
            if let Some(reg) = revocations {
                #[cfg(any(test, feature = "test-hooks"))]
                let read_res = if reg
                    .inject_rev_read_error
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    Err(StoreError::Invalid("injected revision read-back error"))
                } else {
                    authority_revision(conn)
                };
                #[cfg(not(any(test, feature = "test-hooks")))]
                let read_res = authority_revision(conn);
                match read_res {
                    Ok(r) if r >= revision => return Ok(revision),
                    Ok(_) => reg.drop_mark(&mark_scope, revision),
                    Err(_) => {
                        // Ambiguous COMMIT and read-back failed: keep the mark fail-closed.
                    }
                }
            }
            Err(err)
        }
    }
}

/// Lifts a block only when lifting it provably restores nothing (the interim rule while
/// restoration is unspecified). `installed_file_policy` is the parsed peers file of the
/// installed generation, before any store merge; the caller holds the publication mutex.
/// Refuses with every reason and changes nothing; otherwise returns the committed revision.
pub fn unblock_device(
    conn: &Connection,
    device: &DeviceId,
    installed_file_policy: &PeersMap,
) -> Result<u64, StoreError> {
    let tx = immediate(conn)?;
    let mut reasons = Vec::new();
    let unremoved_manual: i64 = tx.query_row(
        "SELECT COUNT(*) FROM pairing_grants g WHERE g.subject = ?1
             AND g.provenance = 'manual_authenticated_oob'
             AND NOT EXISTS (SELECT 1 FROM pairing_removed_grants r WHERE r.grant_id = g.grant_id)",
        [&device[..]],
        |r| r.get(0),
    )?;
    if unremoved_manual > 0 {
        reasons.push(format!("{unremoved_manual} manual grant(s) not removed"));
    }
    // The peers file's own deny dominates every file-derived right for this device.
    let hex_id = hex::encode(device);
    if !installed_file_policy.deny.spkis.contains(&hex_id) {
        let mut pins: Vec<&str> = installed_file_policy
            .values()
            .filter(|p| p.pin.as_deref().and_then(device_id_from_pin) == Some(*device))
            .map(|p| p.name.as_str())
            .collect();
        pins.sort();
        for name in pins {
            reasons.push(format!("peers-file pin entry '{name}'"));
        }
        if !installed_file_policy.ca_peers().is_empty() || installed_file_policy.hub.is_some() {
            reasons.push("a CA entry or CA-anchored hub pattern may admit this key".into());
        }
    }
    if !reasons.is_empty() {
        return Err(StoreError::WouldRestore(reasons));
    }
    tx.execute(
        "DELETE FROM pairing_device_blocks WHERE device_id = ?1",
        [&device[..]],
    )?;
    let revision = bump(&tx)?;
    tx.commit()?;
    Ok(revision)
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
/// Returns the number of grants created and the authority revision, which moves only when
/// something was created.
pub fn import_legacy(
    conn: &Connection,
    issuer: &DeviceId,
    config: &PeersMap,
    now: i64,
) -> Result<(usize, u64), StoreError> {
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
    let revision = if created > 0 {
        bump(&tx)?
    } else {
        authority_revision(&tx)?
    };
    tx.commit()?;
    Ok((created, revision))
}

/// Records a freshly parsed peers file's pins as legacy grants (a file rebuild only).
pub fn import_file_policy(
    conn: &Connection,
    own_cert_der: &[u8],
    peers: &mut PeersMap,
    now: i64,
) -> Result<u64, StoreError> {
    let issuer = crate::fed::spki_sha256_from_der(own_cert_der)
        .ok()
        .as_deref()
        .and_then(device_id_from_pin)
        .ok_or(StoreError::Invalid("own certificate SPKI"))?;
    peers.own_device_id = Some(issuer);
    Ok(import_legacy(conn, &issuer, peers, now)?.1)
}

/// Shared token carried by every `PeersMap` clone of one installed generation (§5.4 item 5).
#[derive(Debug, Default)]
pub struct GenerationToken {
    pub revision: u64,
}

impl GenerationToken {
    pub fn new(revision: u64) -> Self {
        Self { revision }
    }
}

/// Scope of an in-memory revocation mark (§5.4 item 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MarkScope {
    Device(DeviceId),
    Grant {
        device: Option<DeviceId>,
        grant_id: GrantId,
    },
}

#[derive(Clone, Debug)]
struct RevocationMark {
    scope: MarkScope,
    revision: u64,
}

#[derive(Default)]
struct RevocationInner {
    marks: Vec<RevocationMark>,
    tokens: Vec<Weak<GenerationToken>>,
}

/// In-memory revocation marks and weak generation tokens for §5.4 permit-time fencing and GC.
#[derive(Default)]
pub struct RevocationRegistry {
    inner: Mutex<RevocationInner>,
    #[cfg(any(test, feature = "test-hooks"))]
    pub inject_commit_io_error: std::sync::atomic::AtomicBool,
    #[cfg(any(test, feature = "test-hooks"))]
    pub inject_precommit_abort: std::sync::atomic::AtomicBool,
    #[cfg(any(test, feature = "test-hooks"))]
    pub inject_rev_read_error: std::sync::atomic::AtomicBool,
    #[cfg(any(test, feature = "test-hooks"))]
    pub before_commit_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl RevocationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_mark(&self, scope: MarkScope, revision: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.marks.push(RevocationMark { scope, revision });
    }

    pub fn drop_mark(&self, scope: &MarkScope, revision: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = inner
            .marks
            .iter()
            .position(|m| m.revision == revision && &m.scope == scope)
        {
            inner.marks.remove(pos);
        }
    }

    pub fn register_token(&self, token: &Arc<GenerationToken>) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.tokens.retain(|w| w.strong_count() > 0);
        inner.tokens.push(Arc::downgrade(token));
    }

    /// Returns `true` if any active mark covering `device` or `grant_id` has `mark.revision > gen_rev`.
    pub fn has_blocking_mark(
        &self,
        device: &DeviceId,
        grant_id: Option<&GrantId>,
        gen_rev: u64,
    ) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.marks.iter().any(|m| {
            m.revision > gen_rev
                && match &m.scope {
                    MarkScope::Device(d) => d == device,
                    MarkScope::Grant {
                        device: d,
                        grant_id: gid,
                    } => grant_id == Some(gid) && d.is_none_or(|dev| dev == *device),
                }
        })
    }

    /// Retires marks at `M` once `installed_revision >= M` and every token with `revision < M`
    /// is dead (§5.4 item 5).
    pub fn gc(&self, installed_revision: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut min_live_rev: Option<u64> = None;
        inner.tokens.retain(|w| {
            if let Some(tok) = w.upgrade() {
                min_live_rev = Some(min_live_rev.map_or(tok.revision, |m| m.min(tok.revision)));
                true
            } else {
                false
            }
        });
        inner.marks.retain(|m| {
            if installed_revision < m.revision {
                return true;
            }
            min_live_rev.is_some_and(|min_r| min_r < m.revision)
        });
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn mark_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .marks
            .len()
    }
}

/// Returns the process-wide `RevocationRegistry` bound to `db` (keyed by `Weak<Mutex<Connection>>`).
pub fn revocations_for_db(db: &Arc<Mutex<Connection>>) -> Arc<RevocationRegistry> {
    type RevocationEntry = (Weak<Mutex<Connection>>, Arc<RevocationRegistry>);
    static REGISTRY: std::sync::OnceLock<Mutex<Vec<RevocationEntry>>> = std::sync::OnceLock::new();
    let map = REGISTRY.get_or_init(|| Mutex::new(Vec::new()));
    let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
    guard.retain(|(w, _)| w.strong_count() > 0);
    if let Some((_, reg)) = guard.iter().find(|(w, _)| w.as_ptr() == Arc::as_ptr(db)) {
        return reg.clone();
    }
    let reg = Arc::new(RevocationRegistry::new());
    guard.push((Arc::downgrade(db), reg.clone()));
    reg
}

/// Merges one store snapshot, read in a single read transaction, into a policy generation:
/// every durable device block joins its `deny.spkis`, active manual grants and removed tombstones
/// are loaded into the generation, and the generation records the snapshot's revision.
pub fn merge_snapshot(conn: &Connection, peers: &mut PeersMap) -> Result<u64, StoreError> {
    let tx = conn.unchecked_transaction()?;
    let revision = authority_revision(&tx)?;
    let blocked_set = blocked_devices(&tx)?;
    let removed_set = removed_grants(&tx)?;
    let manual_grants: Vec<Grant> = tx
        .prepare(&format!(
            "SELECT {GRANT_COLUMNS} FROM pairing_grants
             WHERE provenance = 'manual_authenticated_oob' AND active = 1
             ORDER BY activated_at, grant_id"
        ))?
        .query_map([], grant_from_row)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
    tx.commit()?;
    let mut blocked: Vec<String> = blocked_set.iter().map(hex::encode).collect();
    blocked.sort();
    for pin in blocked {
        if !peers.deny.spkis.contains(&pin) {
            peers.deny.spkis.push(pin);
        }
    }
    peers.manual_blocked = blocked_set;
    peers.manual_removed = removed_set;
    peers.manual_grants = manual_grants;
    peers.authority_revision = revision;
    Ok(revision)
}

/// A file rebuild's store step: legacy import, then one snapshot merge.
pub fn apply_to_policy(
    conn: &Connection,
    own_cert_der: &[u8],
    peers: &mut PeersMap,
    now: i64,
) -> Result<u64, StoreError> {
    import_file_policy(conn, own_cert_der, peers, now)?;
    merge_snapshot(conn, peers)
}

/// The `pairing` health field: the committed store revision against the installed one. A
/// store that cannot be read is reported, and the installed generation stays in effect.
pub fn health(fed: Option<&crate::fed::FedState>) -> serde_json::Value {
    let Some(fs) = fed else {
        return serde_json::Value::Null;
    };
    let installed = fs.current_peers().authority_revision;
    let committed = authority_revision(&fs.db.lock().unwrap_or_else(|e| e.into_inner()));
    match committed {
        Ok(committed) => serde_json::json!({
            "committed_revision": committed,
            "installed_revision": installed,
        }),
        Err(e) => serde_json::json!({
            "committed_revision": null,
            "installed_revision": installed,
            "error": e.to_string(),
        }),
    }
}

/// Cancels a single open intent by intent ID or peer ID, releasing any capacity reservation.
pub fn cancel_intent_by_id(conn: &Connection, intent_id: &[u8; 16]) -> Result<bool, StoreError> {
    let tx = immediate(conn)?;
    let n = tx.execute(
        "UPDATE pairing_intents SET state = 'cancelled' WHERE intent_id = ?1 AND state = 'open'",
        [&intent_id[..]],
    )?;
    tx.commit()?;
    Ok(n > 0)
}

/// Cancels all open intents for `peer`, releasing any capacity reservations.
pub fn cancel_open_intents_for_peer(
    conn: &Connection,
    peer: &DeviceId,
) -> Result<Vec<[u8; 16]>, StoreError> {
    let tx = immediate(conn)?;
    let mut stmt = tx.prepare(
        "SELECT intent_id FROM pairing_intents WHERE peer_id = ?1 AND state = 'open'",
    )?;
    let ids: Vec<[u8; 16]> = stmt
        .query_map([&peer[..]], |r| {
            let v: Vec<u8> = r.get(0)?;
            Ok(v.try_into().unwrap_or([0u8; 16]))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);
    if !ids.is_empty() {
        tx.execute(
            "UPDATE pairing_intents SET state = 'cancelled' WHERE peer_id = ?1 AND state = 'open'",
            [&peer[..]],
        )?;
    }
    tx.commit()?;
    Ok(ids)
}

#[derive(Clone, Debug)]
pub struct StoredGrantSummary {
    pub grant_id: GrantId,
    pub peer_id: DeviceId,
    pub provenance: String,
    pub profile: Option<String>,
    pub not_after: Option<i64>,
    pub exposure: Option<Vec<u8>>,
    pub has_reverse_receipt: bool,
    pub active: bool,
}

pub fn list_grants_summary(conn: &Connection) -> Result<Vec<StoredGrantSummary>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT g.grant_id, g.subject, g.provenance, g.profile, g.not_after, g.exposure,
                (g.receipt_remote IS NOT NULL), g.active
         FROM pairing_grants g
         WHERE NOT EXISTS (SELECT 1 FROM pairing_removed_grants r WHERE r.grant_id = g.grant_id)
         ORDER BY g.activated_at ASC, g.grant_id ASC",
    )?;
    let rows = stmt
        .query_map([], |r| {
            let gid: Vec<u8> = r.get(0)?;
            let pid: Vec<u8> = r.get(1)?;
            Ok(StoredGrantSummary {
                grant_id: gid.try_into().unwrap_or([0u8; 16]),
                peer_id: pid.try_into().unwrap_or([0u8; 32]),
                provenance: r.get(2)?,
                profile: r.get(3)?,
                not_after: r.get(4)?,
                exposure: r.get(5)?,
                has_reverse_receipt: r.get::<_, i64>(6)? != 0,
                active: r.get::<_, i64>(7)? != 0,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn list_blocks(conn: &Connection) -> Result<Vec<(DeviceId, i64)>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT device_id, blocked_at FROM pairing_device_blocks ORDER BY blocked_at ASC",
    )?;
    let rows = stmt
        .query_map([], |r| {
            let pid: Vec<u8> = r.get(0)?;
            Ok((pid.try_into().unwrap_or([0u8; 32]), r.get(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn count_slots_used(conn: &Connection) -> Result<i64, StoreError> {
    slots_used(conn, None)
}

pub fn count_expired_grants_holding_slots(conn: &Connection, now: i64) -> Result<i64, StoreError> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM pairing_grants g
         WHERE g.provenance = 'manual_authenticated_oob'
           AND NOT EXISTS (SELECT 1 FROM pairing_removed_grants r WHERE r.grant_id = g.grant_id)
           AND g.not_after IS NOT NULL AND g.not_after <= ?1",
        [now],
        |r| r.get(0),
    )?)
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
