use rusqlite::{types::Value, Connection};
use std::sync::{Arc, Barrier};
use std::time::Duration;
use xmsg::storage::{self, Origin, PeerMailboxInsert, PeerMailboxLimits, PeerMailboxMessage};

fn database() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    storage::init_db(&db).unwrap();
    db
}

fn message(id: &str, peer: &str) -> PeerMailboxMessage {
    PeerMailboxMessage {
        id: id.into(),
        peer: peer.into(),
        target_ref: "worker".into(),
        created_at: storage::now_epoch_secs(),
        from_name: "sender".into(),
        bytes: 0,
        body: "雪".into(),
        envelope: "untrusted envelope".into(),
        origin: Origin {
            id: None,
            service: Some("sender".into()),
            node: "upstream".into(),
            label: Some("é".into()),
        },
    }
}

fn stored_size(msg: &PeerMailboxMessage) -> u64 {
    let origin = serde_json::to_string(&msg.origin).unwrap();
    [
        &msg.id,
        &msg.peer,
        &msg.target_ref,
        &msg.from_name,
        &msg.body,
        &msg.envelope,
        &origin,
    ]
    .into_iter()
    .map(|value| value.len() as u64)
    .sum::<u64>()
        + 16
}

fn snapshot(db: &Connection) -> Vec<Vec<Value>> {
    let mut statement = db
        .prepare("SELECT * FROM peer_mailbox ORDER BY id")
        .unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| (0..columns).map(|index| row.get(index)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn row_cap_preserves_earlier_rows_and_is_independent_per_leaf() {
    let db = database();
    let limits = PeerMailboxLimits {
        max_rows: 2,
        max_bytes: u64::MAX / 2,
    };
    for id in ["a1", "a2"] {
        assert_eq!(
            storage::insert_peer_mailbox_with_limits(&db, &message(id, "leaf-a"), limits).unwrap(),
            PeerMailboxInsert::Inserted
        );
    }
    let before = snapshot(&db);
    assert_eq!(
        storage::insert_peer_mailbox_with_limits(&db, &message("a3", "leaf-a"), limits).unwrap(),
        PeerMailboxInsert::Full,
        "N+1 mailbox row bypassed the per-leaf cap"
    );
    assert_eq!(
        snapshot(&db),
        before,
        "capacity refusal changed earlier rows"
    );
    assert_eq!(
        storage::insert_peer_mailbox_with_limits(&db, &message("a1", "leaf-a"), limits).unwrap(),
        PeerMailboxInsert::Duplicate,
        "duplicate at full capacity was refused"
    );
    assert_eq!(snapshot(&db), before, "duplicate rewrote the original row");
    assert_eq!(
        storage::insert_peer_mailbox_with_limits(&db, &message("b1", "leaf-b"), limits).unwrap(),
        PeerMailboxInsert::Inserted,
        "another leaf inherited the full leaf's budget"
    );
}

#[test]
fn byte_cap_counts_utf8_envelope_origin_and_metadata_at_the_exact_boundary() {
    let db = database();
    let first = message("01", "leaf");
    let mut second = message("02", "leaf");
    second.envelope = "é雪".repeat(80);
    second.bytes = 0;
    let total = stored_size(&first) + stored_size(&second);
    let below = PeerMailboxLimits {
        max_rows: 10,
        max_bytes: total - 1,
    };
    assert_eq!(
        storage::insert_peer_mailbox_with_limits(&db, &first, below).unwrap(),
        PeerMailboxInsert::Inserted
    );
    let before = snapshot(&db);
    assert_eq!(
        storage::insert_peer_mailbox_with_limits(&db, &second, below).unwrap(),
        PeerMailboxInsert::Full,
        "stored UTF-8 envelope/metadata bytes bypassed the mailbox cap"
    );
    assert_eq!(snapshot(&db), before);
    let exact = PeerMailboxLimits {
        max_bytes: total,
        ..below
    };
    assert_eq!(
        storage::insert_peer_mailbox_with_limits(&db, &second, exact).unwrap(),
        PeerMailboxInsert::Inserted,
        "exact byte boundary was refused"
    );
    assert_eq!(
        storage::count_peer_mailbox_messages(&db, "leaf").unwrap(),
        2
    );
}

#[test]
fn ack_and_ttl_purge_release_capacity_without_evicting_earlier_rows() {
    let db = database();
    let mut expired = message("old", "leaf");
    expired.created_at = storage::now_epoch_secs() - 100;
    let next = message("new", "leaf");
    let limits = PeerMailboxLimits {
        max_rows: 1,
        max_bytes: stored_size(&expired).max(stored_size(&next)),
    };
    assert_eq!(
        storage::insert_peer_mailbox_with_limits(&db, &expired, limits).unwrap(),
        PeerMailboxInsert::Inserted
    );
    assert_eq!(
        storage::insert_peer_mailbox_with_limits(&db, &next, limits).unwrap(),
        PeerMailboxInsert::Full,
        "full mailbox admitted a new row before explicit ACK or TTL purge"
    );
    assert_eq!(
        storage::get_next_peer_mailbox_message(&db, "leaf")
            .unwrap()
            .unwrap()
            .id,
        "old"
    );
    assert_eq!(storage::purge_peer_mailbox(&db, 1).unwrap(), 1);
    assert_eq!(
        storage::insert_peer_mailbox_with_limits(&db, &next, limits).unwrap(),
        PeerMailboxInsert::Inserted,
        "TTL purge did not release the byte/row budget"
    );
    assert!(!storage::delete_peer_mailbox_message(&db, "other-leaf", "new").unwrap());
    assert!(storage::delete_peer_mailbox_message(&db, "leaf", "new").unwrap());
    assert_eq!(
        storage::insert_peer_mailbox_with_limits(&db, &message("ack", "leaf"), limits).unwrap(),
        PeerMailboxInsert::Inserted,
        "ACK did not release the byte/row budget"
    );
}

#[test]
fn concurrent_connections_cannot_overshoot_one_leaf_slot() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("mailbox.db");
    let db = Connection::open(&file).unwrap();
    storage::init_db(&db).unwrap();
    db.pragma_update(None, "journal_mode", "WAL").unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|index| {
            let file = file.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let db = Connection::open(file).unwrap();
                db.busy_timeout(Duration::from_secs(5)).unwrap();
                barrier.wait();
                storage::insert_peer_mailbox_with_limits(
                    &db,
                    &message(&format!("row-{index}"), "leaf"),
                    PeerMailboxLimits {
                        max_rows: 1,
                        max_bytes: 4096,
                    },
                )
                .unwrap()
            })
        })
        .collect();
    let outcomes: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == PeerMailboxInsert::Inserted)
            .count(),
        1,
        "concurrent mailbox inserts overshot the row budget"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == PeerMailboxInsert::Full)
            .count(),
        7
    );
    assert_eq!(
        storage::count_peer_mailbox_messages(&db, "leaf").unwrap(),
        1
    );
}
