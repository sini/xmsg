use crate::{
    client::wire::{NodeStatus, Recipient},
    error::AppError,
    http::AppState,
    surface::Local,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EnvironmentKind {
    Zellij,
    Tmux,
    Herdr,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub kind: EnvironmentKind,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

impl Environment {
    fn sanitized(&self) -> Self {
        let reference = self.reference.as_ref().map(|s| {
            let mut out = String::new();
            for c in s.chars().filter(|c| !c.is_control()) {
                if out.len() + c.len_utf8() > 64 {
                    break;
                }
                out.push(c);
            }
            out
        });
        Self {
            kind: self.kind.clone(),
            reference,
        }
    }
}

pub fn own_environment() -> Environment {
    for (key, kind) in [
        ("ZELLIJ_SESSION_NAME", EnvironmentKind::Zellij),
        ("TMUX_PANE", EnvironmentKind::Tmux),
        ("HERDR_PANE_ID", EnvironmentKind::Herdr),
    ] {
        if let Ok(reference) = std::env::var(key) {
            return Environment {
                kind,
                reference: Some(reference),
            }
            .sanitized();
        }
    }
    Environment {
        kind: EnvironmentKind::None,
        reference: None,
    }
}

pub fn record(
    conn: &rusqlite::Connection,
    address: &str,
    harness: &str,
    native_id: &str,
    env: Option<&Environment>,
) -> rusqlite::Result<()> {
    let env =
        env.map(|env| serde_json::to_string(&env.sanitized()).expect("environment serializes"));
    conn.execute("INSERT INTO locator_metadata(address,harness,native_id,env) VALUES (?1,?2,?3,?4) ON CONFLICT(address) DO UPDATE SET harness=excluded.harness,native_id=excluded.native_id,env=excluded.env", params![address,harness,native_id,env])?;
    Ok(())
}

pub fn update_native(
    conn: &rusqlite::Connection,
    address: &str,
    native_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE locator_metadata SET native_id=?2 WHERE address=?1",
        params![address, native_id],
    )?;
    Ok(())
}

pub fn forget(conn: &rusqlite::Connection, address: &str) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM locator_metadata WHERE address=?1", [address])?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Locator {
    pub recipient: Recipient,
    pub native_id: Option<String>,
    pub resume: Option<Vec<String>>,
    pub reason: String,
    pub env: Option<Environment>,
    pub cwd: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Located {
    pub locators: Vec<Locator>,
    pub nodes: Vec<NodeStatus>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub address: Option<String>,
    pub label: Option<String>,
    #[serde(default)]
    pub detail: bool,
}

pub fn inert(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

pub fn valid_native_id(harness: &str, id: &str) -> bool {
    if id.is_empty() || id.len() > 256 || id.starts_with('-') {
        return false;
    }
    match harness {
        "claude" | "codex" | "agy" => crate::claim::is_uuid_shaped(id),
        "pi" => {
            id.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && id.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        }
        "opencode" | "hermes" => {
            id.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
        }
        _ => false,
    }
}

fn fail(e: impl std::fmt::Display) -> AppError {
    AppError::Internal(e.to_string())
}

struct LocalCatalog {
    recipients: Vec<Recipient>,
    current_cwds: BTreeMap<(String, String), String>,
}

pub(crate) fn local_entries(local: &Local<'_>, user: &str) -> Result<Vec<Recipient>, AppError> {
    Ok(local_catalog(local, user, false)?.recipients)
}

fn local_catalog(local: &Local<'_>, user: &str, detail: bool) -> Result<LocalCatalog, AppError> {
    if !crate::codex::runtime_initialized(local.db) {
        return Err(AppError::ServiceUnavailable(
            "locator runtime is not initialized".into(),
        ));
    }
    let mut rows: BTreeMap<(String, String), Recipient> = BTreeMap::new();
    let mut current_cwds = BTreeMap::new();
    let mut add = |mut row: Recipient| {
        row.address = format!("{}@{}", row.address, local.node_name);
        row.node = local.node_name.into();
        row.user = user.into();
        let key = (row.address.clone(), row.kind.clone());
        match rows.entry(key) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(row);
            }
            std::collections::btree_map::Entry::Occupied(mut e) => {
                if row.registered_at.is_some() || e.get().registered_at.is_none() {
                    e.insert(row);
                }
            }
        }
    };
    {
        let db = local.db.lock().map_err(fail)?;
        for sql in [
            "SELECT id || CASE WHEN suffix>1 THEN '~'||suffix ELSE '' END,'instance','claude',NULL,CASE WHEN released=0 THEN created_at END,NULL,CASE WHEN released=0 THEN 'registered' WHEN suffix>1 THEN 'closed' ELSE 'seen' END FROM instance_claims ORDER BY created_at",
            "SELECT id,'instance',harness,NULL,NULL,last_live,'seen' FROM instance_seen ORDER BY id",
            "SELECT root_id,'instance','codex',label,CASE WHEN active=1 AND revoked=0 THEN registered_at END,NULL,CASE WHEN active=1 AND revoked=0 THEN 'registered' ELSE 'seen' END FROM codex_roots ORDER BY root_id",
            "SELECT address,'instance',harness,session,registered_at,NULL,'registered' FROM plugin_sessions ORDER BY address",
            "SELECT parent||'/'||COALESCE(name,agent_id),'subagent',COALESCE((SELECT harness FROM instance_seen WHERE id=parent),'unknown'),name,NULL,NULLIF(MAX(last_active,COALESCE(stopped_at,0)),0),'seen' FROM subagents ORDER BY parent,agent_id",
        ] {
            let mut stmt = db.prepare(sql).map_err(fail)?;
            let results = stmt.query_map([], |r| {
                let registered_at: Option<i64> = r.get(4)?;
                Ok(Recipient { address: r.get(0)?, kind: r.get(1)?, harness: Some(r.get(2)?), label: r.get(3)?, status: r.get(6)?, node: String::new(), user: String::new(), registered_at, last_seen: r.get(5)?, context: None })
            }).map_err(fail)?;
            for row in results { add(row.map_err(fail)?); }
        }
        if detail {
            let mut stmt = db
                .prepare("SELECT root_id,cwd FROM codex_roots WHERE cwd IS NOT NULL AND cwd<>''")
                .map_err(fail)?;
            let records = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(fail)?;
            for record in records {
                let (id, cwd) = record.map_err(fail)?;
                current_cwds.insert((format!("{id}@{}", local.node_name), "codex".into()), cwd);
            }
        }
    }
    let row = |id: String, harness: &str, kind: &str, label: Option<String>, time: i64| Recipient {
        address: id,
        kind: kind.into(),
        harness: Some(harness.into()),
        label,
        status: "registered".into(),
        node: String::new(),
        user: String::new(),
        registered_at: Some(time),
        last_seen: None,
        context: None,
    };
    for (key, info) in local.agy_store.read().map_err(fail)?.iter() {
        add(row(
            key.clone(),
            "agy",
            "instance",
            info.label.clone(),
            info.registered_at,
        ));
    }
    for (key, info) in local.pi_store.read().map_err(fail)?.iter() {
        if detail && !info.cwd.is_empty() {
            current_cwds.insert(
                (format!("{key}@{}", local.node_name), "pi".into()),
                info.cwd.clone(),
            );
        }
        add(row(
            key.clone(),
            "pi",
            "instance",
            info.name.clone(),
            info.registered_at,
        ));
    }
    for info in local.svc_store.read().map_err(fail)?.values() {
        add(row(
            info.session_id.clone(),
            "svc",
            "service",
            None,
            info.registered_at,
        ));
    }
    let entries = crate::registry::read_session_entries(local.sessions_dirs);
    let db = local.db.lock().map_err(fail)?;
    for entry in entries {
        if !crate::registry::validate_session_file_entry(&entry) {
            continue;
        }
        for claim in crate::claim::get_all_claims_for_id(&db, &entry.session_id).map_err(fail)? {
            if claim.pid == entry.pid && claim.proc_start == entry.proc_start {
                if let Some(row) = rows.get_mut(&(
                    format!("{}@{}", claim.address(), local.node_name),
                    "instance".into(),
                )) {
                    if row.harness.as_deref() == Some("claude") {
                        row.label = entry.name.clone();
                        if detail && !entry.cwd.is_empty() {
                            current_cwds
                                .insert((row.address.clone(), "claude".into()), entry.cwd.clone());
                        }
                    }
                }
            }
        }
    }
    Ok(LocalCatalog {
        recipients: rows.into_values().collect(),
        current_cwds,
    })
}

fn project(recipient: Recipient) -> Locator {
    let reason = if matches!(
        recipient.status.as_str(),
        "live" | "registered" | "seen" | "unknown"
    ) {
        "live"
    } else {
        "unproven"
    };
    Locator {
        recipient,
        native_id: None,
        resume: None,
        reason: reason.into(),
        env: None,
        cwd: None,
    }
}

pub async fn locate(state: &AppState, query: &Query) -> Result<Located, AppError> {
    if query.address.is_some() == query.label.is_some() {
        return Err(AppError::BadRequest(
            "provide exactly one of address or label".into(),
        ));
    }
    let (address, node) = match query.address.as_deref() {
        Some(address) => match address.rsplit_once('@') {
            Some((id, node)) if !id.is_empty() && !node.is_empty() && !id.contains('@') => {
                (Some(id), Some(node))
            }
            Some(_) => return Err(AppError::BadRequest("malformed address".into())),
            None => (Some(address), Some(state.node_name.as_str())),
        },
        None => (None, None),
    };
    let mut recipients = Vec::new();
    let mut nodes = Vec::new();
    let mut current_cwds = BTreeMap::new();
    if node.is_none_or(|n| n == state.node_name || n == "local") {
        let user = state
            .fed_state
            .as_ref()
            .map_or_else(|| crate::node::own_user(None), |f| crate::fed::own_user(f));
        let catalog = local_catalog(&state.local(), &user, query.detail)?;
        current_cwds = catalog.current_cwds;
        recipients.extend(catalog.recipients);
        nodes.push(NodeStatus::ok(&state.node_name));
    }
    if let Some(fs) = &state.fed_state {
        let current_peers = fs.current_peers();
        let peers: Vec<String> = match node {
            Some(name) if current_peers.contains_name(name) => {
                vec![current_peers.key_for(name).unwrap_or(name).to_owned()]
            }
            None => current_peers.keys().cloned().collect(),
            _ => Vec::new(),
        };
        let mut requests = tokio::task::JoinSet::new();
        for key in peers {
            let fs = fs.clone();
            requests.spawn(async move {
                let result = crate::fed::list_peer_read_only(&fs, &key).await;
                (key, result)
            });
        }
        while let Some(answer) = requests.join_next().await {
            let (key, (entries, status)) = answer.map_err(fail)?;
            recipients.extend(entries.into_iter().map(|e| Recipient {
                address: format!("{}@{key}", e.id),
                node: key.clone(),
                kind: e.kind,
                harness: e.harness,
                label: e.label,
                status: e.status,
                user: e.user,
                registered_at: e.registered_at,
                last_seen: e.last_seen,
                context: e.context,
            }));
            nodes.push(status);
        }
    }
    if nodes.is_empty() {
        nodes.push(NodeStatus::failed(
            node.unwrap_or("unknown"),
            "unreachable",
            "not a node in the local view".into(),
        ));
    }
    recipients.retain(|r| {
        address.is_none_or(|id| r.address.rsplit_once('@').is_some_and(|(raw, _)| raw == id))
            && query
                .label
                .as_deref()
                .is_none_or(|l| r.label.as_deref() == Some(l))
    });
    recipients.sort_by(|a, b| a.address.cmp(&b.address).then_with(|| a.kind.cmp(&b.kind)));
    let db = state.db.lock().map_err(fail)?;
    let mut locators = Vec::new();
    for recipient in recipients {
        let mut item = project(recipient);
        if item.recipient.node == state.node_name {
            item.cwd = current_cwds
                .get(&(
                    item.recipient.address.clone(),
                    item.recipient.harness.clone().unwrap_or_default(),
                ))
                .cloned();
            let address = item
                .recipient
                .address
                .rsplit_once('@')
                .map(|(id, _)| id)
                .unwrap_or("");
            if item.recipient.status == "registered" && item.recipient.kind != "service" {
                item.recipient.context = crate::session_context::project(
                    &db,
                    address,
                    item.recipient.harness.as_deref().unwrap_or_default(),
                    crate::session_context::Surface::Local,
                );
            }
            let metadata: Option<(String, String, Option<String>)> = db
                .query_row(
                    "SELECT harness,native_id,env FROM locator_metadata WHERE address=?1",
                    [address],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()
                .map_err(fail)?;
            if let Some((harness, id, env)) = metadata
                .filter(|(harness, _, _)| item.recipient.harness.as_deref() == Some(harness))
            {
                if valid_native_id(&harness, &id) {
                    item.native_id = Some(id);
                }
                item.env = env
                    .and_then(|raw| serde_json::from_str::<Environment>(&raw).ok())
                    .map(|e| e.sanitized());
                if !query.detail {
                    if let Some(env) = &mut item.env {
                        env.reference = None;
                    }
                }
            }
        } else {
            item.recipient.context = crate::session_context::mask_remote(
                &db,
                item.recipient.context.take(),
                crate::session_context::Surface::Local,
            );
        }
        locators.push(item);
    }
    nodes.sort_by(|a, b| a.node.cmp(&b.node));
    Ok(Located { locators, nodes })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{
        sync::{atomic::AtomicU64, Arc, Mutex},
        time::Duration,
    };
    const UUID: &str = "11111111-1111-4111-8111-111111111111";

    pub(crate) fn fixture() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        let db = rusqlite::Connection::open_in_memory().unwrap();
        crate::storage::init_db(&db).unwrap();
        let state = AppState {
            sessions_dirs: vec![dir.path().join("sessions")],
            agy_config: crate::agy::AgyConfig::default(),
            agy_store: crate::agy::new_agy_store(),
            pi_store: crate::pi::new_pi_store(),
            pi_notify_tx: tokio::sync::broadcast::channel(16).0,
            svc_store: crate::svc::new_svc_store(),
            svc_notify_tx: tokio::sync::broadcast::channel(16).0,
            node_name: "local.example".into(),
            max_body: 65536,
            max_attachment_bytes: 65536,
            request_counter: AtomicU64::new(0),
            db: Arc::new(Mutex::new(db)),
            notify_tx: tokio::sync::broadcast::channel(16).0,
            reply_ttl: Duration::from_secs(3600),
            idempotency_ttl: Duration::from_secs(3600),
            long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(16)),
            fed_state: None,
        };
        crate::codex::init_for_state(&state, crate::codex::CodexConfig::default());
        (dir, state)
    }
    fn seed(state: &AppState, address: &str, harness: &str, native: &str, label: &str) {
        if harness == "pi" {
            state.pi_store.write().unwrap().insert(
                address.into(),
                crate::pi::PiSessionInfo {
                    session_id: address.into(),
                    name: Some(label.into()),
                    pid: 0,
                    starttime: "unknown".into(),
                    cwd: "/private/work".into(),
                    registered_at: 1,
                },
            );
        }
        let db = state.db.lock().unwrap();
        db.execute(
            "INSERT INTO instance_seen(id,harness,last_live) VALUES (?1,?2,1)",
            params![address, harness],
        )
        .unwrap();
        db.execute("INSERT INTO plugin_sessions(address,conn,harness,session,registered_at,pid) VALUES (?1,?1,?2,?3,1,0)",params![address,harness,label]).unwrap();
        record(
            &db,
            address,
            harness,
            native,
            Some(&Environment {
                kind: EnvironmentKind::Tmux,
                reference: Some("%3".into()),
            }),
        )
        .unwrap();
    }
    async fn one(state: &AppState, address: &str, detail: bool) -> Locator {
        locate(
            state,
            &Query {
                address: Some(address.into()),
                label: None,
                detail,
            },
        )
        .await
        .unwrap()
        .locators
        .remove(0)
    }

    #[tokio::test]
    async fn native_id_is_recorded_not_derived_from_suffixed_address() {
        let (_dir, state) = fixture();
        seed(&state, &format!("{UUID}~2"), "claude", UUID, "fork");
        let item = one(&state, &format!("{UUID}~2"), false).await;
        assert_eq!(
            item.native_id.as_deref(),
            Some(UUID),
            "stored native ID changed to public address"
        );
        assert_eq!(item.resume, None);
        assert_eq!(
            item.reason, "live",
            "live locator lost location-only reason"
        );
    }
    #[tokio::test]
    async fn unknown_harness_never_falls_back_to_claude() {
        let (_dir, state) = fixture();
        seed(&state, "opaque-address", "future", UUID, "unknown");
        let item = one(&state, "opaque-address", false).await;
        assert_eq!(
            item.native_id, None,
            "unknown harness gained a native mapping"
        );
        assert_eq!(item.resume, None);
        assert_eq!(item.recipient.harness.as_deref(), Some("future"));
        assert_eq!(
            project(Recipient {
                status: "closed".into(),
                ..item.recipient
            })
            .reason,
            "unproven"
        );
    }
    #[test]
    fn native_ids_refuse_option_and_shell_shapes() {
        for harness in ["claude", "codex", "agy", "pi", "opencode", "hermes"] {
            for id in ["-x", "--exec=payload", "a;b"] {
                assert!(!valid_native_id(harness, id), "{harness} accepted {id}");
            }
        }
        assert!(valid_native_id("pi", "project-session_3"));
        assert!(valid_native_id("hermes", "20261120_123456_abcd"));
        assert!(valid_native_id("opencode", "ses_ephemeral_2x"));
    }
    #[tokio::test]
    async fn detail_and_environment_unknown_none_are_distinct() {
        let (_dir, state) = fixture();
        seed(&state, "a", "pi", "session-1", "label");
        let plain = one(&state, "a", false).await;
        assert_eq!(plain.env.as_ref().unwrap().kind, EnvironmentKind::Tmux);
        assert_eq!(
            plain.env.unwrap().reference,
            None,
            "detail escaped request gate"
        );
        assert_eq!(plain.cwd, None, "detail escaped request gate");
        let detail = one(&state, "a", true).await;
        assert_eq!(detail.env.unwrap().reference.as_deref(), Some("%3"));
        assert_eq!(detail.cwd.as_deref(), Some("/private/work"));
        {
            let db = state.db.lock().unwrap();
            db.execute("UPDATE locator_metadata SET env=NULL WHERE address='a'", [])
                .unwrap();
        }
        assert_eq!(
            one(&state, "a", true).await.env,
            None,
            "unknown environment became explicit none"
        );
        {
            let db = state.db.lock().unwrap();
            record(
                &db,
                "a",
                "pi",
                "session-1",
                Some(&Environment {
                    kind: EnvironmentKind::None,
                    reference: None,
                }),
            )
            .unwrap();
        }
        assert_eq!(
            one(&state, "a", true).await.env.unwrap().kind,
            EnvironmentKind::None
        );
    }
    #[tokio::test]
    async fn current_pi_cwd_updates_disappears_and_does_not_need_native_metadata() {
        let (_dir, state) = fixture();
        seed(&state, "pi-address", "pi", "native-1", "pi");
        assert_eq!(
            one(&state, "pi-address", true).await.cwd.as_deref(),
            Some("/private/work"),
            "current Pi cwd source was discarded"
        );
        state
            .pi_store
            .write()
            .unwrap()
            .get_mut("pi-address")
            .unwrap()
            .cwd = "/current/pi".into();
        forget(&state.db.lock().unwrap(), "pi-address").unwrap();
        let item = one(&state, "pi-address", true).await;
        assert_eq!(item.cwd.as_deref(), Some("/current/pi"));
        assert_eq!(item.native_id, None);
        assert_eq!(item.env, None);
        state.pi_store.write().unwrap().remove("pi-address");
        assert_eq!(
            one(&state, "pi-address", true).await.cwd,
            None,
            "detached Pi cwd was retained"
        );
    }
    #[tokio::test]
    async fn current_codex_cwd_updates_and_disappears_without_locator_metadata() {
        let (_dir, state) = fixture();
        {
            let db = state.db.lock().unwrap();
            db.execute(
                "INSERT INTO instance_seen(id,harness,last_live) VALUES (?1,'codex',1)",
                [UUID],
            )
            .unwrap();
            db.execute("INSERT INTO codex_roots(root_id,codex_home,owner_pid,owner_starttime,generation,label,cwd,registered_at,active) VALUES (?1,'/fixture',0,'unknown',1,'code','/codex/first',1,0)",[UUID]).unwrap();
        }
        assert_eq!(
            one(&state, UUID, true).await.cwd.as_deref(),
            Some("/codex/first")
        );
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE codex_roots SET cwd='/codex/current' WHERE root_id=?1",
                [UUID],
            )
            .unwrap();
        assert_eq!(
            one(&state, UUID, true).await.cwd.as_deref(),
            Some("/codex/current")
        );
        state
            .db
            .lock()
            .unwrap()
            .execute("DELETE FROM codex_roots WHERE root_id=?1", [UUID])
            .unwrap();
        assert_eq!(one(&state, UUID, true).await.cwd, None);
    }
    #[tokio::test]
    async fn current_claude_cwd_uses_matched_file_and_disappears_without_retention() {
        let (dir, state) = fixture();
        std::fs::create_dir(&state.sessions_dirs[0]).unwrap();
        let socket = dir.path().join("inbox.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let file = state.sessions_dirs[0].join("fixture.json");
        let write = |cwd: &str| {
            std::fs::write(&file,serde_json::json!({"pid":1234,"sessionId":UUID,"name":"claude","cwd":cwd,"status":"idle","kind":"interactive","startedAt":1,"updatedAt":1,"procStart":"42","messagingSocketPath":socket}).to_string()).unwrap()
        };
        state.db.lock().unwrap().execute("INSERT INTO instance_claims(id,pid,proc_start,suffix,released,created_at) VALUES (?1,1234,'42',2,0,1)",[UUID]).unwrap();
        let address = format!("{UUID}~2");
        write("/claude/first");
        assert_eq!(
            one(&state, &address, true).await.cwd.as_deref(),
            Some("/claude/first")
        );
        write("/claude/current");
        assert_eq!(
            one(&state, &address, true).await.cwd.as_deref(),
            Some("/claude/current")
        );
        std::fs::remove_file(file).unwrap();
        assert_eq!(one(&state, &address, true).await.cwd, None);
    }
    #[tokio::test]
    async fn agy_native_conversation_is_not_its_registered_address() {
        let (_dir, state) = fixture();
        state.agy_store.write().unwrap().insert(
            "registered-alias".into(),
            crate::agy::AgySessionInfo::new(UUID.into(), 0, "unknown".into(), None),
        );
        record(
            &state.db.lock().unwrap(),
            "registered-alias",
            "agy",
            UUID,
            None,
        )
        .unwrap();
        let item = one(&state, "registered-alias", false).await;
        assert_eq!(item.recipient.address, "registered-alias@local.example");
        assert_eq!(item.native_id.as_deref(), Some(UUID));
    }
    #[tokio::test]
    async fn metadata_for_a_different_harness_is_not_reused() {
        let (_dir, state) = fixture();
        seed(&state, "a", "pi", "session-1", "label");
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE locator_metadata SET harness='codex' WHERE address='a'",
                [],
            )
            .unwrap();
        let item = one(&state, "a", true).await;
        assert_eq!((item.native_id, item.env), (None, None));
        assert_eq!(
            item.cwd.as_deref(),
            Some("/private/work"),
            "current registry cwd must not depend on stale native metadata"
        );
    }
    #[tokio::test]
    async fn label_lookup_is_complete_beyond_list_and_snapshot_caps_and_read_only() {
        let (_dir, state) = fixture();
        for i in 0..1105 {
            seed(
                &state,
                &format!("instance-{i:04}"),
                "pi",
                &format!("native-{i}"),
                "shared",
            );
        }
        let before = state.db.lock().unwrap().total_changes();
        let result = locate(
            &state,
            &Query {
                address: None,
                label: Some("shared".into()),
                detail: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            result.locators.len(),
            1105,
            "locator discarded disambiguation matches"
        );
        assert!(result.locators.iter().all(|item| item.resume.is_none()));
        assert_eq!(state.db.lock().unwrap().total_changes(), before);
        let missing = locate(
            &state,
            &Query {
                address: Some("id@absent.example".into()),
                label: None,
                detail: false,
            },
        )
        .await
        .unwrap();
        assert!(missing.locators.is_empty());
        assert_eq!(
            missing.nodes[0].status, "unreachable",
            "node failure became no-match"
        );
        let empty = locate(
            &state,
            &Query {
                address: None,
                label: Some("absent".into()),
                detail: false,
            },
        )
        .await
        .unwrap();
        assert!(empty.locators.is_empty());
        assert_eq!(empty.nodes[0].status, "ok");
    }
    #[test]
    fn peer_metadata_is_rejected_and_recipient_shape_is_unchanged() {
        let peer = serde_json::json!({"id":"x","kind":"instance","status":"live","user":"owner","resume":"bad","reach":"bad"});
        assert!(
            serde_json::from_value::<crate::fed::FedListEntry>(peer).is_err(),
            "peer locator extras were accepted"
        );
        let row = Recipient {
            address: "id@node".into(),
            kind: "instance".into(),
            harness: None,
            label: None,
            status: "live".into(),
            node: "node".into(),
            user: "u".into(),
            registered_at: None,
            last_seen: None,
            context: None,
        };
        assert_eq!(
            serde_json::to_value(&row).unwrap(),
            serde_json::json!({"address":"id@node","kind":"instance","status":"live","node":"node","user":"u"})
        );
        assert!(
            serde_json::from_value::<Recipient>(serde_json::to_value(project(row)).unwrap())
                .is_err()
        );
    }
    #[tokio::test]
    async fn cold_runtime_is_refused_without_initialization_or_writes() {
        let (_dir, state) = fixture();
        let replacement = std::sync::Arc::new(std::sync::Mutex::new(
            rusqlite::Connection::open_in_memory().unwrap(),
        ));
        crate::storage::init_db(&replacement.lock().unwrap()).unwrap();
        let cold = AppState {
            db: replacement,
            ..state
        };
        let before = cold.db.lock().unwrap().total_changes();
        assert!(matches!(
            locate(
                &cold,
                &Query {
                    address: Some("id".into()),
                    label: None,
                    detail: false
                }
            )
            .await,
            Err(AppError::ServiceUnavailable(_))
        ));
        assert!(!crate::codex::runtime_initialized(&cold.db));
        assert_eq!(cold.db.lock().unwrap().total_changes(), before);
    }
    #[tokio::test]
    async fn locate_route_is_absent_from_tcp_router() {
        use tower::ServiceExt;
        let (_dir, state) = fixture();
        let response = crate::http::build_router(Arc::new(state))
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/locate?address=id")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }
    #[test]
    fn environment_reference_is_typed_sanitized_and_byte_bounded() {
        let env = Environment {
            kind: EnvironmentKind::Tmux,
            reference: Some(format!("%3\u{1b}[2J{}", "界".repeat(40))),
        }
        .sanitized();
        let reference = env.reference.unwrap();
        assert!(!reference.contains('\u{1b}'));
        assert!(reference.len() <= 64);
        assert!(reference.starts_with("%3[2J"));
        assert!(serde_json::from_value::<Environment>(
            serde_json::json!({"kind":"shell","ref":"evil"})
        )
        .is_err());
    }
    #[test]
    fn display_escapes_terminal_controls_without_truncation() {
        assert_eq!(
            inert("a\u{1b}[2J\n"),
            "a\\u{1b}[2J\\n",
            "terminal controls were not escaped"
        );
        assert_eq!(inert(&"x".repeat(200)), "x".repeat(200));
    }
}
