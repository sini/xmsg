use rusqlite::Connection;
use xmsg::storage::{
    self, ack_pi_message, get_next_pending_pi_message, insert_pi_message, now_epoch_secs,
    purge_pi_messages, PiPendingMessage,
};

#[test]
fn test_pi_pending_messages_fifo_and_ack() {
    let conn = Connection::open_in_memory().unwrap();
    storage::init_db(&conn).unwrap();

    let msg1 = PiPendingMessage {
        id: "m1".to_string(),
        session_id: "pi-sess-1".to_string(),
        created_at: 100,
        from_name: "sender-a".to_string(),
        bytes: 11,
        text: "hello 1".to_string(),
        envelope: "env 1".to_string(),
        delivered_at: None,
    };

    let msg2 = PiPendingMessage {
        id: "m2".to_string(),
        session_id: "pi-sess-1".to_string(),
        created_at: 200,
        from_name: "sender-b".to_string(),
        bytes: 11,
        text: "hello 2".to_string(),
        envelope: "env 2".to_string(),
        delivered_at: None,
    };

    insert_pi_message(&conn, &msg1).unwrap();
    insert_pi_message(&conn, &msg2).unwrap();

    // First retrieval must return msg1 (FIFO order)
    let fetched1 = get_next_pending_pi_message(&conn, "pi-sess-1").unwrap();
    assert_eq!(fetched1.as_ref().map(|m| m.id.as_str()), Some("m1"));

    // Ack msg1
    ack_pi_message(&conn, "m1").unwrap();

    // Second retrieval must return msg2
    let fetched2 = get_next_pending_pi_message(&conn, "pi-sess-1").unwrap();
    assert_eq!(fetched2.as_ref().map(|m| m.id.as_str()), Some("m2"));

    // Ack msg2
    ack_pi_message(&conn, "m2").unwrap();

    // Third retrieval must return None
    let fetched3 = get_next_pending_pi_message(&conn, "pi-sess-1").unwrap();
    assert!(fetched3.is_none());
}

#[test]
fn test_pi_pending_messages_session_isolation() {
    let conn = Connection::open_in_memory().unwrap();
    storage::init_db(&conn).unwrap();

    let msg_a = PiPendingMessage {
        id: "ma".to_string(),
        session_id: "sess-a".to_string(),
        created_at: 100,
        from_name: "sender".to_string(),
        bytes: 5,
        text: "for a".to_string(),
        envelope: "env a".to_string(),
        delivered_at: None,
    };

    let msg_b = PiPendingMessage {
        id: "mb".to_string(),
        session_id: "sess-b".to_string(),
        created_at: 100,
        from_name: "sender".to_string(),
        bytes: 5,
        text: "for b".to_string(),
        envelope: "env b".to_string(),
        delivered_at: None,
    };

    insert_pi_message(&conn, &msg_a).unwrap();
    insert_pi_message(&conn, &msg_b).unwrap();

    let fetched_a = get_next_pending_pi_message(&conn, "sess-a").unwrap();
    assert_eq!(fetched_a.as_ref().map(|m| m.id.as_str()), Some("ma"));

    let fetched_b = get_next_pending_pi_message(&conn, "sess-b").unwrap();
    assert_eq!(fetched_b.as_ref().map(|m| m.id.as_str()), Some("mb"));

    let fetched_c = get_next_pending_pi_message(&conn, "sess-c").unwrap();
    assert!(fetched_c.is_none());
}

#[test]
fn test_pi_queue_ttl_purge() {
    let conn = Connection::open_in_memory().unwrap();
    storage::init_db(&conn).unwrap();

    let now = now_epoch_secs();
    let old_msg = PiPendingMessage {
        id: "old".to_string(),
        session_id: "sess-1".to_string(),
        created_at: now - 10000,
        from_name: "sender".to_string(),
        bytes: 3,
        text: "old".to_string(),
        envelope: "old".to_string(),
        delivered_at: None,
    };

    let fresh_msg = PiPendingMessage {
        id: "fresh".to_string(),
        session_id: "sess-1".to_string(),
        created_at: now - 10,
        from_name: "sender".to_string(),
        bytes: 5,
        text: "fresh".to_string(),
        envelope: "fresh".to_string(),
        delivered_at: None,
    };

    insert_pi_message(&conn, &old_msg).unwrap();
    insert_pi_message(&conn, &fresh_msg).unwrap();

    let purged = purge_pi_messages(&conn, 3600).unwrap();
    assert_eq!(purged, 1);

    let next = get_next_pending_pi_message(&conn, "sess-1").unwrap();
    assert_eq!(next.as_ref().map(|m| m.id.as_str()), Some("fresh"));
}
