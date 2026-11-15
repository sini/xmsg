use std::collections::BTreeMap;

use serde::Serialize;

use crate::client::wire::{NodeStatus, Recipient};
use crate::error::AppError;
use crate::http::AppState;
use crate::surface::ListQuery;

const MAX_ROWS: usize = 1000;

#[derive(Debug, Serialize)]
pub(crate) struct Snapshot {
    read_only: bool,
    partial: bool,
    truncated: bool,
    recipients: Vec<Recipient>,
    nodes: Vec<NodeStatus>,
}

struct Catalog<'a> {
    node: &'a str,
    user: String,
    query: &'a ListQuery,
    rows: BTreeMap<(String, String), Recipient>,
    truncated: bool,
}

impl Catalog<'_> {
    fn add(&mut self, mut row: Recipient) {
        if row.address.is_empty() || row.address.len() > 512 {
            return;
        }
        if self
            .query
            .kind
            .as_ref()
            .is_some_and(|kind| *kind != row.kind)
            || self.query.name.as_ref().is_some_and(|name| {
                row.label.as_ref() != Some(name) && !(row.kind == "service" && row.address == *name)
            })
        {
            return;
        }
        row.label = row.label.as_deref().and_then(crate::inbox::clean_label);
        row.label = row.label.map(|label| label.chars().take(256).collect());
        row.address = format!("{}@{}", row.address, self.node);
        row.node = self.node.to_owned();
        row.user.clone_from(&self.user);
        let key = (row.address.clone(), row.kind.clone());
        match self.rows.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(row);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let existing = entry.get_mut();
                let seen = existing.last_seen.max(row.last_seen);
                let prefer_new = (row.status == "registered" && existing.status != "registered")
                    || (row.status == existing.status
                        && (row.registered_at, row.last_seen, &row.harness, &row.label)
                            > (
                                existing.registered_at,
                                existing.last_seen,
                                &existing.harness,
                                &existing.label,
                            ));
                if prefer_new {
                    *existing = row;
                }
                existing.last_seen = seen;
            }
        }
        if self.rows.len() > MAX_ROWS {
            self.truncated = true;
            self.rows.pop_last();
        }
    }
}

fn row(
    id: String,
    kind: &str,
    harness: String,
    label: Option<String>,
    registered_at: Option<i64>,
    last_seen: Option<i64>,
) -> Recipient {
    Recipient {
        address: id,
        kind: kind.to_owned(),
        harness: Some(harness),
        label,
        status: if registered_at.is_some() {
            "registered"
        } else {
            "seen"
        }
        .to_owned(),
        node: String::new(),
        user: String::new(),
        registered_at,
        last_seen,
    }
}

pub(crate) fn collect(state: &AppState, query: &ListQuery) -> Result<Snapshot, AppError> {
    if query.host.is_some()
        || query
            .node
            .as_deref()
            .is_some_and(|node| node != "local" && node != state.node_name)
    {
        return Err(AppError::BadRequest(
            "read-only snapshots are local-only; use xmsg list for a live remote listing (which can reconcile and deliver queued work), or the fleet view when deployed".into(),
        ));
    }
    if query.status.is_some() || query.within.is_some() {
        return Err(AppError::BadRequest(
            "read-only snapshots report registered / last seen, partial; status and within filters require a live listing".into(),
        ));
    }
    if query
        .kind
        .as_deref()
        .is_some_and(|kind| !matches!(kind, "service" | "instance" | "subagent"))
    {
        return Err(AppError::BadRequest(
            "kind must be service, instance or subagent".into(),
        ));
    }
    let mut catalog = Catalog {
        node: &state.node_name,
        user: state.fed_state.as_ref().map_or_else(
            || crate::node::own_user(None),
            |fed| crate::fed::own_user(fed),
        ),
        query,
        rows: BTreeMap::new(),
        truncated: false,
    };
    {
        let db = state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        for sql in [
            "SELECT substr(id,1,513) || CASE WHEN suffix>1 THEN '~'||suffix ELSE '' END, 'instance', 'claude', NULL, CASE WHEN released=0 THEN created_at END, NULL FROM instance_claims ORDER BY 1,created_at DESC LIMIT ?1",
            "SELECT substr(id,1,513), 'instance', substr(harness,1,32), NULL, NULL, last_live FROM instance_seen ORDER BY id LIMIT ?1",
            "SELECT substr(root_id,1,513), 'instance', 'codex', substr(label,1,257), CASE WHEN active=1 AND revoked=0 THEN registered_at END, NULL FROM codex_roots ORDER BY root_id LIMIT ?1",
            "SELECT substr(address,1,513), 'instance', substr(harness,1,32), substr(session,1,257), registered_at, NULL FROM plugin_sessions ORDER BY address LIMIT ?1",
            "SELECT substr(parent||'/'||COALESCE(name,agent_id),1,513), 'subagent', COALESCE((SELECT substr(harness,1,32) FROM instance_seen WHERE id=parent),'unknown'), substr(name,1,257), NULL, NULLIF(MAX(last_active,COALESCE(stopped_at,0)),0) FROM subagents ORDER BY parent,agent_id LIMIT ?1",
        ] {
            let mut statement = db.prepare(sql).map_err(|e| AppError::Internal(e.to_string()))?;
            let records = statement.query_map([(MAX_ROWS + 1) as i64], |record| {
                Ok(row(record.get(0)?, &record.get::<_, String>(1)?, record.get(2)?, record.get(3)?, record.get(4)?, record.get(5)?))
            }).map_err(|e| AppError::Internal(e.to_string()))?;
            let mut count = 0;
            for record in records {
                catalog.add(record.map_err(|e| AppError::Internal(e.to_string()))?);
                count += 1;
            }
            catalog.truncated |= count > MAX_ROWS;
        }
    }
    {
        let store = state
            .agy_store
            .read()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        for info in store.values() {
            let id = if info.session_key.is_empty() {
                &info.conversation_id
            } else {
                &info.session_key
            };
            catalog.add(row(
                id.clone(),
                "instance",
                "agy".into(),
                info.label.clone(),
                Some(info.registered_at),
                None,
            ));
        }
    }
    {
        let store = state
            .pi_store
            .read()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        for info in store.values() {
            catalog.add(row(
                info.session_id.clone(),
                "instance",
                "pi".into(),
                info.name.clone(),
                Some(info.registered_at),
                None,
            ));
        }
    }
    {
        let store = state
            .svc_store
            .read()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        for info in store.values() {
            catalog.add(row(
                info.session_id.clone(),
                "service",
                "svc".into(),
                None,
                Some(info.registered_at),
                None,
            ));
        }
    }
    Ok(Snapshot {
        read_only: true,
        partial: true,
        truncated: catalog.truncated,
        recipients: catalog.rows.into_values().collect(),
        nodes: vec![NodeStatus::ok(&state.node_name)],
    })
}
