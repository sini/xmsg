use crate::fed::FedState;
use crate::observe_export::{EndpointKind, Harness, RegistrationState, SnapshotRecord};

const SOURCE_ROWS: usize = 201;

fn harness(value: &str) -> Harness {
    match value {
        "claude" => Harness::Claude,
        "codex" => Harness::Codex,
        "agy" => Harness::Agy,
        "pi" => Harness::Pi,
        "opencode" => Harness::Opencode,
        "hermes" => Harness::Hermes,
        _ => Harness::Unknown,
    }
}

fn label(value: &str) -> String {
    value.chars().take(256).collect()
}

pub(crate) fn collect(state: &FedState) -> (Vec<SnapshotRecord>, bool) {
    let mut records = Vec::new();
    // A cached catalog cannot enumerate filesystem-only registrations.
    let mut partial = true;
    if let Ok(connection) = state.db.try_lock() {
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
            (
                "SELECT substr(address,1,513),substr(harness,1,33),registered_at,substr(session,1,257) FROM temp.plugin_sessions ORDER BY address LIMIT 201",
                EndpointKind::Instance,
                RegistrationState::Registered,
            ),
        ] {
            let result = (|| -> rusqlite::Result<()> {
                let mut statement = connection.prepare(sql)?;
                let mut rows = statement.query([])?;
                while let Some(row) = rows.next()? {
                    records.push(SnapshotRecord {
                        id: row.get(0)?,
                        kind,
                        harness: harness(&row.get::<_, String>(1)?),
                        state: registration,
                        source_at: row.get(2)?,
                        label: row.get(3)?,
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
            });
        }
    }
    (records, partial)
}
