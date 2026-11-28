use rusqlite::{
    params,
    types::{FromSql, FromSqlError, FromSqlResult, ValueRef},
    Connection, OptionalExtension, Result, Row,
};

const MAINTENANCE_BATCH: i64 = 256;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS command_intents (
    hash BLOB PRIMARY KEY NOT NULL CHECK(length(hash) = 32),
    principal TEXT NOT NULL,
    record_id TEXT NOT NULL,
    transport TEXT NOT NULL,
    request_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed INTEGER NOT NULL CHECK(consumed IN (0, 1))
);
CREATE INDEX IF NOT EXISTS command_intents_unused_expiry
    ON command_intents(expires_at, record_id) WHERE consumed = 0;
CREATE INDEX IF NOT EXISTS command_intents_consumed_request
    ON command_intents(principal, request_id) WHERE consumed = 1;
CREATE TABLE IF NOT EXISTS command_reservations (
    principal TEXT NOT NULL,
    record_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    receipt_id TEXT NOT NULL UNIQUE,
    requested_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN (
        'reserved', 'held', 'submitting', 'admitted', 'refused', 'effect_unknown'
    )),
    code TEXT,
    at INTEGER NOT NULL,
    held_at INTEGER,
    pending_hold INTEGER NOT NULL CHECK(pending_hold IN (0, 1)),
    PRIMARY KEY (principal, request_id),
    CHECK((state = 'refused') = (code IS NOT NULL)),
    CHECK((state = 'held') = (held_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS command_reservations_state_record
    ON command_reservations(state, record_id);
CREATE INDEX IF NOT EXISTS command_reservations_final_retention
    ON command_reservations(at, requested_at)
    WHERE state IN ('admitted', 'refused', 'effect_unknown');
CREATE TRIGGER IF NOT EXISTS command_reservations_purge_consumed
AFTER DELETE ON command_reservations
BEGIN
    DELETE FROM command_intents
    WHERE consumed = 1 AND principal = OLD.principal AND request_id = OLD.request_id;
END;
";

pub(super) fn migrate(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction()?;
    tx.execute_batch(SCHEMA)?;
    tx.commit()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum State {
    Reserved,
    Held,
    Submitting,
    Admitted,
    Refused,
    EffectUnknown,
}

impl State {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Held => "held",
            Self::Submitting => "submitting",
            Self::Admitted => "admitted",
            Self::Refused => "refused",
            Self::EffectUnknown => "effect_unknown",
        }
    }
}

impl FromSql for State {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Ok(match value.as_str()? {
            "reserved" => Self::Reserved,
            "held" => Self::Held,
            "submitting" => Self::Submitting,
            "admitted" => Self::Admitted,
            "refused" => Self::Refused,
            "effect_unknown" => Self::EffectUnknown,
            _ => return Err(FromSqlError::InvalidType),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Intent {
    pub hash: [u8; 32],
    pub principal: String,
    pub record_id: String,
    pub transport: String,
    pub request_id: String,
    pub request_json: String,
    pub digest: String,
    pub expires_at: i64,
    pub consumed: bool,
}

pub(super) fn insert_intent(conn: &Connection, intent: &Intent) -> Result<()> {
    conn.execute(
        "INSERT INTO command_intents
         (hash, principal, record_id, transport, request_id, request_json, digest, expires_at, consumed)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            &intent.hash[..],
            intent.principal,
            intent.record_id,
            intent.transport,
            intent.request_id,
            intent.request_json,
            intent.digest,
            intent.expires_at,
            intent.consumed,
        ],
    )?;
    Ok(())
}

pub(super) fn intent(conn: &Connection, hash: &[u8; 32]) -> Result<Option<Intent>> {
    conn.query_row(
        "SELECT principal, record_id, transport, request_id, request_json, digest, expires_at, consumed
         FROM command_intents WHERE hash = ?",
        [&hash[..]],
        |row| {
            Ok(Intent {
                hash: *hash,
                principal: row.get(0)?,
                record_id: row.get(1)?,
                transport: row.get(2)?,
                request_id: row.get(3)?,
                request_json: row.get(4)?,
                digest: row.get(5)?,
                expires_at: row.get(6)?,
                consumed: row.get(7)?,
            })
        },
    )
    .optional()
}

pub(super) fn consume_intent(conn: &Connection, hash: &[u8; 32]) -> Result<bool> {
    Ok(conn.execute(
        "UPDATE command_intents SET consumed = 1 WHERE hash = ? AND consumed = 0",
        [&hash[..]],
    )? == 1)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Reservation {
    pub principal: String,
    pub record_id: String,
    pub request_id: String,
    pub request_json: String,
    pub digest: String,
    pub receipt_id: String,
    pub requested_at: i64,
    pub state: State,
    pub code: Option<String>,
    pub at: i64,
    pub held_at: Option<i64>,
    pub pending_hold: bool,
}

pub(super) fn insert_reservation(conn: &Connection, row: &Reservation) -> Result<bool> {
    Ok(conn.execute(
        "INSERT INTO command_reservations
         (principal, record_id, request_id, request_json, digest, receipt_id, requested_at,
          state, code, at, held_at, pending_hold)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(principal, request_id) DO NOTHING",
        params![
            row.principal,
            row.record_id,
            row.request_id,
            row.request_json,
            row.digest,
            row.receipt_id,
            row.requested_at,
            row.state.as_str(),
            row.code,
            row.at,
            row.held_at,
            row.pending_hold,
        ],
    )? == 1)
}

fn reservation_row(row: &Row<'_>) -> Result<Reservation> {
    Ok(Reservation {
        principal: row.get(0)?,
        record_id: row.get(1)?,
        request_id: row.get(2)?,
        request_json: row.get(3)?,
        digest: row.get(4)?,
        receipt_id: row.get(5)?,
        requested_at: row.get(6)?,
        state: row.get(7)?,
        code: row.get(8)?,
        at: row.get(9)?,
        held_at: row.get(10)?,
        pending_hold: row.get(11)?,
    })
}

pub(super) fn reservation(
    conn: &Connection,
    principal: &str,
    request_id: &str,
) -> Result<Option<Reservation>> {
    conn.query_row(
        "SELECT principal, record_id, request_id, request_json, digest, receipt_id, requested_at,
                state, code, at, held_at, pending_hold
         FROM command_reservations WHERE principal = ? AND request_id = ?",
        params![principal, request_id],
        reservation_row,
    )
    .optional()
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Transition<'a> {
    pub from: State,
    pub to: State,
    pub code: Option<&'a str>,
    pub now: i64,
    pub held_at: Option<i64>,
}

pub(super) fn transition(
    conn: &Connection,
    principal: &str,
    request_id: &str,
    change: Transition<'_>,
) -> Result<bool> {
    use State::*;
    match (change.from, change.to) {
        (Reserved, Held | Submitting | Refused)
        | (Held, Submitting | Refused)
        | (Submitting, Admitted | Refused | EffectUnknown) => {}
        _ => return Ok(false),
    }
    Ok(conn.execute(
        "UPDATE command_reservations
         SET state = ?, code = ?, at = ?, held_at = ?, pending_hold = 0
         WHERE principal = ? AND request_id = ? AND state = ?",
        params![
            change.to.as_str(),
            change.code,
            change.now,
            change.held_at,
            principal,
            request_id,
            change.from.as_str(),
        ],
    )? == 1)
}

fn count(row: &Row<'_>) -> Result<usize> {
    let value: i64 = row.get(0)?;
    usize::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

pub(super) fn count_reserved(conn: &Connection, record_id: Option<&str>) -> Result<usize> {
    conn.query_row(
        "SELECT count(*) FROM command_reservations
         WHERE state = 'reserved' AND (?1 IS NULL OR record_id = ?1)",
        [record_id],
        count,
    )
}

pub(super) fn count_holds(conn: &Connection, record_id: Option<&str>) -> Result<usize> {
    conn.query_row(
        "SELECT count(*) FROM command_reservations
         WHERE (state = 'held' OR (state = 'reserved' AND pending_hold = 1))
           AND (?1 IS NULL OR record_id = ?1)",
        [record_id],
        count,
    )
}

pub(super) fn count_unused_intents(conn: &Connection, record_id: Option<&str>) -> Result<usize> {
    conn.query_row(
        "SELECT count(*) FROM command_intents
         WHERE consumed = 0 AND (?1 IS NULL OR record_id = ?1)",
        [record_id],
        count,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Recovery {
    pub reserved: usize,
    pub submitting: usize,
}

pub(super) fn recover(conn: &mut Connection, now: i64) -> Result<Recovery> {
    let tx = conn.transaction()?;
    let reserved = tx.execute(
        "UPDATE command_reservations
         SET state = 'refused', code = 'interrupted', at = ?, pending_hold = 0
         WHERE state = 'reserved'",
        [now],
    )?;
    let submitting = tx.execute(
        "UPDATE command_reservations SET state = 'effect_unknown', at = ? WHERE state = 'submitting'",
        [now],
    )?;
    tx.commit()?;
    Ok(Recovery {
        reserved,
        submitting,
    })
}

pub(super) fn held_candidates(conn: &Connection, after: i64) -> Result<Vec<(i64, Reservation)>> {
    let mut statement = conn.prepare(
        "SELECT rowid, principal, record_id, request_id, request_json, digest, receipt_id,
         requested_at, state, code, at, held_at, pending_hold
         FROM command_reservations WHERE rowid > ? AND state = 'held' ORDER BY rowid LIMIT 256",
    )?;
    let mut rows = statement.query([after])?;
    let mut held = Vec::new();
    while let Some(row) = rows.next()? {
        held.push((
            row.get(0)?,
            Reservation {
                principal: row.get(1)?,
                record_id: row.get(2)?,
                request_id: row.get(3)?,
                request_json: row.get(4)?,
                digest: row.get(5)?,
                receipt_id: row.get(6)?,
                requested_at: row.get(7)?,
                state: row.get(8)?,
                code: row.get(9)?,
                at: row.get(10)?,
                held_at: row.get(11)?,
                pending_hold: row.get(12)?,
            },
        ));
    }
    Ok(held)
}

pub(super) fn compact(conn: &Connection, cutoff: i64, now: i64) -> Result<usize> {
    conn.execute(
        "DELETE FROM command_intents WHERE rowid IN (
             SELECT rowid FROM command_intents WHERE consumed = 0 AND expires_at <= ?
             ORDER BY expires_at LIMIT ?
         )",
        params![now, MAINTENANCE_BATCH],
    )?;
    conn.execute(
        "DELETE FROM command_reservations WHERE rowid IN (
             SELECT rowid FROM command_reservations
             WHERE state IN ('admitted', 'refused', 'effect_unknown')
               AND requested_at < ?1 AND at < ?1
             ORDER BY at LIMIT ?2
         )",
        params![cutoff, MAINTENANCE_BATCH],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        conn
    }

    fn row(principal: &str, id: &str, state: State) -> Reservation {
        Reservation {
            principal: principal.into(),
            record_id: "record".into(),
            request_id: id.into(),
            request_json: "{}".into(),
            digest: "digest".into(),
            receipt_id: format!("r_{principal}_{id}"),
            requested_at: 100,
            state,
            code: None,
            at: 110,
            held_at: (state == State::Held).then_some(110),
            pending_hold: false,
        }
    }

    fn binding(principal: &str, hash_byte: u8, expires_at: i64) -> Intent {
        Intent {
            hash: [hash_byte; 32],
            principal: principal.into(),
            record_id: "record".into(),
            transport: "http".into(),
            request_id: "one".into(),
            request_json: "{}".into(),
            digest: "digest".into(),
            expires_at,
            consumed: false,
        }
    }

    #[test]
    fn migration_preserves_other_tables_and_reservations_are_principal_scoped() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE existing(id INTEGER); INSERT INTO existing VALUES (42);")
            .unwrap();
        migrate(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(
            conn.query_row("SELECT id FROM existing", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            42
        );
        let a = row("a", "one", State::Reserved);
        assert!(insert_reservation(&conn, &a).unwrap());
        assert!(!insert_reservation(&conn, &a).unwrap());
        let b = row("b", "one", State::Reserved);
        assert!(insert_reservation(&conn, &b).unwrap());
        assert_eq!(reservation(&conn, "a", "one").unwrap(), Some(a));
        assert_eq!(reservation(&conn, "b", "one").unwrap(), Some(b));
    }

    #[test]
    fn compaction_keeps_live_rows_and_respects_both_final_timestamps() {
        let conn = open();
        for (principal, state) in [
            ("old_final", State::Admitted),
            ("reserved", State::Reserved),
            ("held", State::Held),
            ("submitting", State::Submitting),
            ("recent_decision", State::Admitted),
            ("recent_request", State::Admitted),
        ] {
            let mut entry = row(principal, "one", state);
            match principal {
                "recent_decision" => entry.at = 150,
                "recent_request" => entry.requested_at = 150,
                _ => {}
            }
            assert!(insert_reservation(&conn, &entry).unwrap());
        }
        let retained = binding("old_final", 1, 115);
        let unconsumed = binding("old_final", 2, 300);
        let expired = binding("other", 3, 120);
        let live = binding("held", 4, 115);
        for entry in [&retained, &unconsumed, &expired, &live] {
            insert_intent(&conn, entry).unwrap();
        }
        assert!(consume_intent(&conn, &retained.hash).unwrap());
        assert!(!consume_intent(&conn, &retained.hash).unwrap());
        assert!(consume_intent(&conn, &live.hash).unwrap());
        assert_eq!(count_unused_intents(&conn, Some("record")).unwrap(), 2);
        assert_eq!(compact(&conn, 150, 200).unwrap(), 1);
        assert_eq!(count_unused_intents(&conn, Some("record")).unwrap(), 1);
        assert!(reservation(&conn, "old_final", "one").unwrap().is_none());
        for principal in [
            "reserved",
            "held",
            "submitting",
            "recent_decision",
            "recent_request",
        ] {
            assert!(reservation(&conn, principal, "one").unwrap().is_some());
        }
        assert!(intent(&conn, &retained.hash).unwrap().is_none());
        assert!(intent(&conn, &expired.hash).unwrap().is_none());
        assert_eq!(intent(&conn, &unconsumed.hash).unwrap(), Some(unconsumed));
        assert!(intent(&conn, &live.hash).unwrap().unwrap().consumed);
    }

    #[test]
    fn startup_releases_charges_once_and_keeps_receipt_identity() {
        let mut conn = open();
        let mut abandoned = row("a", "one", State::Reserved);
        abandoned.pending_hold = true;
        let submitting = row("a", "two", State::Submitting);
        let held = row("a", "three", State::Held);
        for entry in [&abandoned, &submitting, &held] {
            assert!(insert_reservation(&conn, entry).unwrap());
        }
        assert_eq!(count_reserved(&conn, Some("record")).unwrap(), 1);
        assert_eq!(count_reserved(&conn, Some("other")).unwrap(), 0);
        assert_eq!(count_holds(&conn, None).unwrap(), 2);
        assert_eq!(
            recover(&mut conn, 200).unwrap(),
            Recovery {
                reserved: 1,
                submitting: 1,
            }
        );
        assert_eq!(
            recover(&mut conn, 201).unwrap(),
            Recovery {
                reserved: 0,
                submitting: 0,
            }
        );
        assert_eq!(count_reserved(&conn, None).unwrap(), 0);
        assert_eq!(count_holds(&conn, None).unwrap(), 1);
        let refused = reservation(&conn, "a", "one").unwrap().unwrap();
        assert_eq!(refused.receipt_id, abandoned.receipt_id);
        assert_eq!(
            (refused.state, refused.code.as_deref(), refused.at),
            (State::Refused, Some("interrupted"), 200)
        );
        let unknown = reservation(&conn, "a", "two").unwrap().unwrap();
        assert_eq!(unknown.receipt_id, submitting.receipt_id);
        assert_eq!((unknown.state, unknown.at), (State::EffectUnknown, 200));
        assert_eq!(reservation(&conn, "a", "three").unwrap(), Some(held));
        assert!(!transition(
            &conn,
            "a",
            "two",
            Transition {
                from: State::Submitting,
                to: State::Admitted,
                code: None,
                now: 210,
                held_at: None,
            },
        )
        .unwrap());
    }
}
