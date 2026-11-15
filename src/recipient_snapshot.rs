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
    recipients: Vec<SnapshotRecipient>,
    nodes: Vec<NodeStatus>,
}

#[derive(Debug, Serialize)]
struct SnapshotRecipient {
    #[serde(flatten)]
    recipient: Recipient,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_liveness: Option<ProcessLiveness>,
}

#[derive(Debug, Serialize)]
struct ProcessLiveness {
    state: &'static str,
    reason: &'static str,
}

#[derive(Clone)]
enum Identity {
    Process {
        pid: u32,
        start: String,
        claude: bool,
    },
    Service(crate::svc::SvcSessionInfo),
    Missing,
}

struct Candidate {
    recipient: Recipient,
    identity: Identity,
}

fn observe_process(proc_root: &std::path::Path, identity: &Identity) -> ProcessLiveness {
    use crate::process::StartTimeProbe;
    let (state, reason) = match identity {
        Identity::Missing => ("unknown", "missing_identity"),
        Identity::Service(info) => crate::svc::observe_svc_process(proc_root, info),
        Identity::Process { pid, start, .. } if *pid == 0 || start.is_empty() || start == "0" => {
            ("unknown", "missing_identity")
        }
        Identity::Process { pid, start, claude } => {
            match crate::process::probe_starttime(proc_root, *pid) {
                Ok(StartTimeProbe::Known(current)) => {
                    let matches = if *claude {
                        crate::process::claude_start_token_matches(proc_root, &current, start)
                    } else {
                        current == *start
                    };
                    if matches {
                        ("live", "identity_match")
                    } else {
                        ("gone", "identity_mismatch")
                    }
                }
                Ok(StartTimeProbe::Gone) => ("gone", "identity_gone"),
                Ok(StartTimeProbe::Unavailable) => ("unknown", "backend_unavailable"),
                Err(_) => ("unknown", "probe_error"),
            }
        }
    };
    ProcessLiveness { state, reason }
}

struct Catalog<'a> {
    node: &'a str,
    user: String,
    query: &'a ListQuery,
    rows: BTreeMap<(String, String), Candidate>,
    truncated: bool,
}

impl Catalog<'_> {
    fn add(&mut self, mut row: Recipient, identity: Identity) {
        if row.address.is_empty() || row.address.len() > 512 {
            return;
        }
        row.label = row.label.as_deref().and_then(crate::inbox::clean_label);
        row.label = row.label.map(|label| label.chars().take(256).collect());
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
        row.address = format!("{}@{}", row.address, self.node);
        row.node = self.node.to_owned();
        row.user.clone_from(&self.user);
        let key = (row.address.clone(), row.kind.clone());
        match self.rows.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Candidate {
                    recipient: row,
                    identity,
                });
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let candidate = entry.get_mut();
                let existing = &mut candidate.recipient;
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
                    candidate.identity = identity;
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

pub(crate) fn collect(
    state: &AppState,
    query: &ListQuery,
    liveness: bool,
) -> Result<Snapshot, AppError> {
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
            "SELECT substr(id,1,513) || CASE WHEN suffix>1 THEN '~'||suffix ELSE '' END, 'instance', 'claude', NULL, CASE WHEN released=0 THEN created_at END, NULL, pid, proc_start FROM instance_claims ORDER BY 1,created_at DESC LIMIT ?1",
            "SELECT substr(id,1,513), 'instance', substr(harness,1,32), NULL, NULL, last_live, NULL, NULL FROM instance_seen ORDER BY id LIMIT ?1",
            "SELECT substr(root_id,1,513), 'instance', 'codex', substr(label,1,257), CASE WHEN active=1 AND revoked=0 THEN registered_at END, NULL, owner_pid, owner_starttime FROM codex_roots ORDER BY root_id LIMIT ?1",
            "SELECT substr(s.address,1,513), 'instance', substr(s.harness,1,32), substr(s.session,1,257), s.registered_at, NULL, p.pid, p.starttime FROM plugin_sessions s LEFT JOIN plugin_procs p ON s.conn=p.conn ORDER BY s.address LIMIT ?1",
            "SELECT substr(parent||'/'||COALESCE(name,agent_id),1,513), 'subagent', COALESCE((SELECT substr(harness,1,32) FROM instance_seen WHERE id=parent),'unknown'), substr(name,1,257), NULL, NULLIF(MAX(last_active,COALESCE(stopped_at,0)),0), NULL, NULL FROM subagents ORDER BY parent,agent_id LIMIT ?1",
        ] {
            let mut statement = db.prepare(sql).map_err(|e| AppError::Internal(e.to_string()))?;
            let records = statement.query_map([(MAX_ROWS + 1) as i64], |record| {
                let row = row(record.get(0)?, &record.get::<_, String>(1)?, record.get(2)?, record.get(3)?, record.get(4)?, record.get(5)?);
                let pid = record.get::<_, Option<i64>>(6)?.and_then(|pid| u32::try_from(pid).ok());
                let start: Option<String> = record.get(7)?;
                let identity = match (row.registered_at, pid, start) {
                    (Some(_), Some(pid), Some(start)) => Identity::Process { pid, start, claude: row.harness.as_deref() == Some("claude") },
                    _ => Identity::Missing,
                };
                Ok((row, identity))
            }).map_err(|e| AppError::Internal(e.to_string()))?;
            let mut count = 0;
            for record in records {
                let (row, identity) = record.map_err(|e| AppError::Internal(e.to_string()))?;
                catalog.add(row, identity);
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
            catalog.add(
                row(
                    id.clone(),
                    "instance",
                    "agy".into(),
                    info.label.clone(),
                    Some(info.registered_at),
                    None,
                ),
                Identity::Process {
                    pid: info.pid,
                    start: info.starttime.clone(),
                    claude: false,
                },
            );
        }
    }
    {
        let store = state
            .pi_store
            .read()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        for info in store.values() {
            catalog.add(
                row(
                    info.session_id.clone(),
                    "instance",
                    "pi".into(),
                    info.name.clone(),
                    Some(info.registered_at),
                    None,
                ),
                Identity::Process {
                    pid: info.pid,
                    start: info.starttime.clone(),
                    claude: false,
                },
            );
        }
    }
    {
        let store = state
            .svc_store
            .read()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        for info in store.values() {
            catalog.add(
                row(
                    info.session_id.clone(),
                    "service",
                    "svc".into(),
                    None,
                    Some(info.registered_at),
                    None,
                ),
                Identity::Service(info.clone()),
            );
        }
    }
    Ok(Snapshot {
        read_only: true,
        partial: true,
        truncated: catalog.truncated,
        recipients: catalog
            .rows
            .into_values()
            .map(|candidate| SnapshotRecipient {
                process_liveness: liveness
                    .then(|| observe_process(&state.agy_config.proc_root, &candidate.identity)),
                recipient: candidate.recipient,
            })
            .collect(),
        nodes: vec![NodeStatus::ok(&state.node_name)],
    })
}
