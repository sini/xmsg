use crate::fed::FedState;
use crate::observe_export::{EndpointKind, Harness, RegistrationState, SnapshotRecord};
use crate::session_context::{project, Surface};

const SOURCE_ROWS: usize = 201;

fn harness(reg: &crate::harnesses::HarnessRegistry, value: &str) -> Harness {
    match value {
        "claude" => Harness::Claude,
        "codex" => Harness::Codex,
        "agy" => Harness::Agy,
        "pi" => Harness::Pi,
        "opencode" => Harness::Opencode,
        "hermes" => Harness::Hermes,
        other if reg.is_declared(other) => Harness::Declared(other.to_string()),
        _ => Harness::Unknown,
    }
}

fn label(value: &str) -> String {
    value.chars().take(256).collect()
}

pub(crate) fn collect(state: &std::sync::Arc<FedState>) -> (Vec<SnapshotRecord>, bool) {
    let harnesses = crate::harnesses::for_db(&state.db);
    let mut records = Vec::new();
    // A cached catalog cannot enumerate filesystem-only registrations.
    let mut partial = true;
    let database = state.db.try_lock().ok().and_then(|connection| {
        connection
            .path()
            .filter(|name| !name.is_empty())
            .map(std::path::PathBuf::from)
    });
    let connection = database.and_then(|database| {
        let connection = rusqlite::Connection::open_with_flags(
            database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .ok()?;
        connection
            .busy_timeout(std::time::Duration::from_millis(25))
            .ok()?;
        Some(connection)
    });
    if let Some(connection) = connection.as_ref() {
        for (sql, kind, registration) in [
            (
                "SELECT substr(id,1,513),substr(harness,1,33),last_live,NULL FROM instance_seen ORDER BY id LIMIT 201",
                EndpointKind::Instance,
                RegistrationState::Seen,
            ),
            (
                "SELECT substr(root_id,1,513),'codex',registered_at,substr(label,1,257) FROM codex_roots ORDER BY root_id LIMIT 201",
                EndpointKind::Instance,
                RegistrationState::Seen,
            ),
        ] {
            let result = (|| -> rusqlite::Result<()> {
                let mut statement = connection.prepare(sql)?;
                let mut rows = statement.query([])?;
                while let Some(row) = rows.next()? {
                    let id: String = row.get(0)?;
                    let source: String = row.get(1)?;
                    let context = project(connection, &id, &source, Surface::Observe);
                    let activity = crate::activity::runtime_snapshot_state(&state.db, &id);
                    records.push(SnapshotRecord {
                        id,
                        kind,
                        harness: harness(&harnesses, &source),
                        state: registration,
                        source_at: row.get(2)?,
                        label: row.get(3)?,
                        context,
                        activity,
                    });
                }
                Ok(())
            })();
            partial |= result.is_err();
        }
    }
    if let Ok(store) = state.svc_store.try_read() {
        for value in store.values().take(SOURCE_ROWS) {
            records.push(SnapshotRecord {
                id: value.name.clone(),
                kind: EndpointKind::Service,
                harness: Harness::Unknown,
                state: RegistrationState::Registered,
                source_at: Some(value.registered_at),
                label: Some(label(&value.name)),
                context: None,
                activity: None,
            });
        }
    }
    if let Ok(store) = state.agy_store.try_read() {
        for value in store.values().take(SOURCE_ROWS) {
            records.push(SnapshotRecord {
                id: value.conversation_id.clone(),
                kind: EndpointKind::Instance,
                harness: Harness::Agy,
                state: RegistrationState::Registered,
                source_at: Some(value.registered_at),
                label: value.label.as_deref().map(label),
                context: connection
                    .as_ref()
                    .and_then(|db| project(db, &value.conversation_id, "agy", Surface::Observe)),
                activity: crate::activity::runtime_snapshot_state(
                    &state.db,
                    &value.conversation_id,
                ),
            });
        }
    }
    if let Ok(store) = state.pi_store.try_read() {
        for value in store.values().take(SOURCE_ROWS) {
            records.push(SnapshotRecord {
                id: value.session_id.clone(),
                kind: EndpointKind::Instance,
                harness: Harness::Pi,
                state: RegistrationState::Registered,
                source_at: Some(value.registered_at),
                label: value.name.as_deref().map(label),
                context: connection
                    .as_ref()
                    .and_then(|db| project(db, &value.session_id, "pi", Surface::Observe)),
                activity: crate::activity::runtime_snapshot_state(&state.db, &value.session_id),
            });
        }
    }
    #[cfg(any(test, feature = "test-hooks"))]
    crate::observe_fed::test_hooks::controls(state)
        .snapshot_candidates
        .store(records.len(), std::sync::atomic::Ordering::SeqCst);
    (records, partial)
}
