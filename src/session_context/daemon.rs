use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension};

use super::{ContextFields, SessionContext};
use crate::{error::AppError, registry::Session, storage};

const TTL: i64 = 900;

pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS session_context (
        id TEXT NOT NULL,
        harness TEXT NOT NULL,
        display_id TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        fields TEXT NOT NULL,
        generation INTEGER NOT NULL,
        PRIMARY KEY (id, harness)
    );
    CREATE INDEX IF NOT EXISTS session_context_display ON session_context(display_id, harness);
    CREATE TABLE IF NOT EXISTS session_context_policy (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        enabled INTEGER NOT NULL,
        generation INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS session_context_mask (
        surface TEXT NOT NULL,
        field TEXT NOT NULL,
        PRIMARY KEY (surface, field)
    );
    CREATE TABLE IF NOT EXISTS session_tag (
        id TEXT NOT NULL,
        harness TEXT NOT NULL,
        reg TEXT NOT NULL,
        tag TEXT NOT NULL,
        added_at INTEGER NOT NULL,
        PRIMARY KEY (id, harness, reg, tag)
    );
    INSERT OR IGNORE INTO session_context_policy VALUES (1, 1, 0);
";

#[derive(Clone, Copy)]
pub enum Surface {
    Local,
    Federation,
    Observe,
}

impl Surface {
    fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Federation => "federation",
            Self::Observe => "observe",
        }
    }
}

fn db_error(error: impl std::fmt::Display) -> AppError {
    AppError::Internal(error.to_string())
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    context_tags: Option<Tags>,
    #[serde(default)]
    context_mask: std::collections::BTreeMap<String, Vec<String>>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Tags {
    enabled: Option<bool>,
}

impl Config {
    pub fn apply(
        &self,
        db: &Connection,
        disabled: bool,
        cli_masks: &[String],
    ) -> Result<(), AppError> {
        let enabled = !disabled
            && self
                .context_tags
                .as_ref()
                .and_then(|tags| tags.enabled)
                .unwrap_or(true);
        let masks: Vec<String> = self
            .context_mask
            .iter()
            .flat_map(|(surface, fields)| {
                fields.iter().map(move |field| format!("{surface}:{field}"))
            })
            .chain(cli_masks.iter().cloned())
            .collect();
        initialize(db, enabled, &masks)
    }
}

pub(super) fn initialize(db: &Connection, enabled: bool, masks: &[String]) -> Result<(), AppError> {
    let tx = db.unchecked_transaction().map_err(db_error)?;
    tx.execute_batch(SCHEMA).map_err(db_error)?;
    tx.execute("DELETE FROM session_context_mask", [])
        .map_err(db_error)?;
    if !enabled {
        tx.execute("DELETE FROM session_context", [])
            .map_err(db_error)?;
    }
    tx.execute(
        "UPDATE session_context_policy SET enabled=?1 WHERE singleton=1",
        [enabled],
    )
    .map_err(db_error)?;
    for mask in masks {
        let (surface, field) = mask
            .split_once(':')
            .filter(|(surface, field)| {
                matches!(*surface, "local" | "federation" | "observe")
                    && matches!(*field, "*" | "repo" | "branch" | "worktree" | "task" | "pr")
            })
            .ok_or_else(|| {
                AppError::BadRequest("invalid context mask, expected surface:field".into())
            })?;
        tx.execute(
            "INSERT OR IGNORE INTO session_context_mask VALUES (?1, ?2)",
            [surface, field],
        )
        .map_err(db_error)?;
    }
    tx.commit().map_err(db_error)
}

fn raw_path(value: &str) -> bool {
    value.split_whitespace().any(|part| {
        let part = part.trim_start_matches(['"', '\'', '(', '[', '{', '=']);
        matches!(part.as_bytes(), [letter, b':', b'/' | b'\\', ..] if letter.is_ascii_alphabetic())
            || ["/", "\\", "~/", "./", "../", "~\\", ".\\", "..\\"]
                .iter()
                .any(|prefix| part.starts_with(prefix))
    })
}

fn unsafe_text(value: &str) -> bool {
    value.chars().any(|ch| {
        ch.is_control()
            || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    })
}

fn repo_slug(value: &str) -> bool {
    let valid_component = |component: &str| {
        !matches!(component, "" | "." | "..")
            && component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    };
    let mut parts = value.split('/');
    matches!((parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(host), Some(owner), Some(repo), None) if host.contains('.') && [host, owner, repo].into_iter().all(valid_component))
        || value.strip_prefix("id:").is_some_and(valid_component)
}

impl ContextFields {
    fn all(&self) -> [(&'static str, &Option<String>, usize); 5] {
        [
            ("repo", &self.repo, 128),
            ("branch", &self.branch, 128),
            ("worktree", &self.worktree, 64),
            ("task", &self.task, 160),
            ("pr", &self.pr, 32),
        ]
    }

    pub(super) fn validate(&self) -> Result<(), AppError> {
        for (field, value, cap) in self.all() {
            let Some(value) = value else { continue };
            if value.trim().is_empty()
                || value.len() > cap
                || raw_path(value)
                || unsafe_text(value)
                || (field == "worktree"
                    && (value.contains(['/', '\\']) || matches!(value.as_str(), "." | "..")))
                || (field == "repo" && !repo_slug(value))
            {
                return Err(AppError::BadRequest(format!(
                    "invalid context field {field}"
                )));
            }
        }
        Ok(())
    }

    fn mask(&mut self, field: &str) {
        match field {
            "repo" => self.repo = None,
            "branch" => self.branch = None,
            "worktree" => self.worktree = None,
            "task" => self.task = None,
            "pr" => self.pr = None,
            "*" => *self = Self::default(),
            _ => {}
        }
    }
}

impl SessionContext {
    pub(super) fn validate_size(&self) -> Result<(), AppError> {
        let bytes = serde_json::to_vec(self).map_err(db_error)?;
        if bytes.len() > 512 {
            return Err(AppError::BadRequest(
                "encoded context exceeds 512 bytes".into(),
            ));
        }
        Ok(())
    }

    pub fn is_valid(&self) -> bool {
        self.fields.validate().is_ok() && self.validate_size().is_ok()
    }
}

pub(super) fn write(
    db: &Connection,
    id: &str,
    harness: &str,
    fields: ContextFields,
    now: i64,
) -> Result<(), AppError> {
    let tx = db.unchecked_transaction().map_err(db_error)?;
    let generation: Option<i64> = tx
        .query_row(
            "UPDATE session_context_policy SET generation=generation+1 WHERE singleton=1 AND enabled RETURNING generation",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?;
    let generation =
        generation.ok_or_else(|| AppError::Denied("session context tags are disabled".into()))?;
    fields.validate()?;
    let context = SessionContext {
        fields,
        updated_at: now,
        generation: u64::try_from(generation).map_err(db_error)?,
        stale: false,
    };
    context.validate_size()?;
    let display_id = match id.split_once('/') {
        Some((parent, child)) => storage::get_subagent(&tx, parent, child)
            .map_err(db_error)?
            .and_then(|binding| binding.name)
            .map_or_else(|| id.to_owned(), |name| format!("{parent}/{name}")),
        None => id.to_owned(),
    };
    prune(&tx, now).map_err(db_error)?;
    tx.execute(
        "INSERT OR REPLACE INTO session_context (id, harness, display_id, updated_at, fields, generation) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, harness, display_id, now, serde_json::to_string(&context.fields).map_err(db_error)?, generation],
    )
    .map_err(db_error)?;
    tx.commit().map_err(db_error)
}

pub fn reset(db: &Connection) -> rusqlite::Result<()> {
    db.execute("DELETE FROM session_context", [])?;
    Ok(())
}

pub fn prune(db: &Connection, now: i64) -> rusqlite::Result<()> {
    db.execute(
        "DELETE FROM session_context WHERE updated_at <= ?1",
        [now.saturating_sub(TTL * 2)],
    )?;
    Ok(())
}

pub fn end(db: &Connection, id: &str, harness: &str) -> rusqlite::Result<()> {
    db.execute(
        "DELETE FROM session_context WHERE harness=?2 AND (id=?1 OR substr(id, 1, length(?1)+1)=?1 || '/')",
        [id, harness],
    )?;
    db.execute(
        "DELETE FROM session_tag WHERE harness=?2 AND id=?1",
        [id, harness],
    )?;
    Ok(())
}

pub fn update(
    db: &Arc<Mutex<Connection>>,
    caller: &Session,
    fields: ContextFields,
) -> Result<(), AppError> {
    let db = db.lock().map_err(db_error)?;
    update_locked(&db, caller, fields)
}

pub fn update_locked(
    db: &Connection,
    caller: &Session,
    fields: ContextFields,
) -> Result<(), AppError> {
    write(
        db,
        &caller.session_id,
        &caller.harness,
        fields,
        storage::now_epoch_secs(),
    )
}

pub fn clear(db: &Arc<Mutex<Connection>>, caller: &Session) -> Result<(), AppError> {
    let db = db.lock().map_err(db_error)?;
    clear_locked(&db, caller)
}

pub fn clear_locked(db: &Connection, caller: &Session) -> Result<(), AppError> {
    db.execute(
        "DELETE FROM session_context WHERE id=?1 AND harness=?2",
        [&caller.session_id, &caller.harness],
    )
    .map_err(db_error)?;
    Ok(())
}

pub fn project(
    db: &Connection,
    id: &str,
    harness: &str,
    surface: Surface,
) -> Option<SessionContext> {
    project_at(db, id, harness, surface, storage::now_epoch_secs())
}

pub(super) fn project_at(
    db: &Connection,
    id: &str,
    harness: &str,
    surface: Surface,
    now: i64,
) -> Option<SessionContext> {
    let (fields, updated_at, generation): (String, i64, i64) = db.query_row(
        "SELECT fields, updated_at, session_context.generation FROM session_context, session_context_policy
         WHERE (id=?1 OR display_id=?1) AND harness=?2 AND enabled AND updated_at>?3 ORDER BY (id=?1) DESC LIMIT 1",
        params![id, harness, now.saturating_sub(TTL * 2)],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ).ok()?;
    let context = SessionContext {
        fields: serde_json::from_str(&fields).ok()?,
        updated_at,
        generation: u64::try_from(generation).ok()?,
        stale: now.saturating_sub(updated_at) >= TTL,
    };
    mask_remote(db, Some(context), surface)
}

pub fn mask_remote(
    db: &Connection,
    context: Option<SessionContext>,
    surface: Surface,
) -> Option<SessionContext> {
    let mut context = context?;
    if !db
        .query_row(
            "SELECT enabled FROM session_context_policy WHERE singleton=1",
            [],
            |row| row.get::<_, bool>(0),
        )
        .ok()?
        || !context.is_valid()
    {
        return None;
    }
    let mut masks = db
        .prepare_cached("SELECT field FROM session_context_mask WHERE surface=?1")
        .ok()?;
    for field in masks
        .query_map([surface.name()], |row| row.get::<_, String>(0))
        .ok()?
    {
        context.fields.mask(&field.ok()?);
    }
    (context.fields != ContextFields::default()).then_some(context)
}

pub const MAX_TAGS_PER_REG: usize = 8;

/// Validates a session tag against `^[a-z0-9][a-z0-9._-]{0,63}$` (1..=64 ASCII bytes).
pub fn validate_tag(tag: &str) -> Result<(), AppError> {
    let bytes = tag.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return Err(AppError::BadRequest(
            "tag must be 1 to 64 bytes matching ^[a-z0-9][a-z0-9._-]{0,63}$".into(),
        ));
    }
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(AppError::BadRequest(
            "tag must start with [a-z0-9] and match ^[a-z0-9][a-z0-9._-]{0,63}$".into(),
        ));
    }
    if !bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(AppError::BadRequest(
            "tag must match ^[a-z0-9][a-z0-9._-]{0,63}$".into(),
        ));
    }
    Ok(())
}

/// Reads all tag rows grouped by `(id, harness, reg)`, sorted ascending per key.
pub fn live_tags(
    db: &Connection,
) -> rusqlite::Result<std::collections::HashMap<(String, String, String), Vec<String>>> {
    let mut stmt = db.prepare("SELECT id, harness, reg, tag FROM session_tag ORDER BY tag ASC")?;
    let mut rows = stmt.query([])?;
    let mut out: std::collections::HashMap<(String, String, String), Vec<String>> =
        std::collections::HashMap::new();
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let harness: String = row.get(1)?;
        let reg: String = row.get(2)?;
        let tag: String = row.get(3)?;
        out.entry((id, harness, reg)).or_default().push(tag);
    }
    Ok(out)
}

fn current_tags_for_reg(
    db: &Connection,
    id: &str,
    harness: &str,
    reg: &str,
) -> Result<Vec<String>, AppError> {
    let mut stmt = db
        .prepare(
            "SELECT tag FROM session_tag WHERE id=?1 AND harness=?2 AND reg=?3 ORDER BY tag ASC",
        )
        .map_err(db_error)?;
    let rows = stmt
        .query_map(params![id, harness, reg], |r| r.get::<_, String>(0))
        .map_err(db_error)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(db_error)?);
    }
    Ok(out)
}

fn sweep_non_current_for_caller(
    db: &Connection,
    id: &str,
    harness: &str,
    reg: &str,
) -> Result<(), AppError> {
    db.execute(
        "DELETE FROM session_tag WHERE id=?1 AND harness=?2 AND reg!=?3",
        params![id, harness, reg],
    )
    .map_err(db_error)?;
    Ok(())
}

/// Adds `tag` to `(id, harness, reg)` under the caller's held `db` lock (I1, I3, 8-tag cap).
pub fn add_tag_with_check(
    db: &Connection,
    id: &str,
    harness: &str,
    reg: &str,
    tag: &str,
    now: i64,
    is_current: impl FnOnce() -> Result<bool, AppError>,
) -> Result<Vec<String>, AppError> {
    validate_tag(tag)?;
    sweep_non_current_for_caller(db, id, harness, reg)?;
    if !is_current()? {
        return Err(AppError::Denied("registration changed".into()));
    }
    let exists: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM session_tag WHERE id=?1 AND harness=?2 AND reg=?3 AND tag=?4)",
            params![id, harness, reg, tag],
            |r| r.get(0),
        )
        .map_err(db_error)?;
    if !exists {
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM session_tag WHERE id=?1 AND harness=?2 AND reg=?3",
                params![id, harness, reg],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        if count >= MAX_TAGS_PER_REG as i64 {
            return Err(AppError::BadRequest(format!(
                "at most {MAX_TAGS_PER_REG} tags per registration"
            )));
        }
        db.execute(
            "INSERT INTO session_tag (id, harness, reg, tag, added_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, harness, reg, tag, now],
        )
        .map_err(db_error)?;
    }
    current_tags_for_reg(db, id, harness, reg)
}

/// Removes `tag` from `(id, harness, reg)` under the caller's held `db` lock (I1, I3).
pub fn remove_tag_with_check(
    db: &Connection,
    id: &str,
    harness: &str,
    reg: &str,
    tag: &str,
    is_current: impl FnOnce() -> Result<bool, AppError>,
) -> Result<Vec<String>, AppError> {
    validate_tag(tag)?;
    sweep_non_current_for_caller(db, id, harness, reg)?;
    if !is_current()? {
        return Err(AppError::Denied("registration changed".into()));
    }
    db.execute(
        "DELETE FROM session_tag WHERE id=?1 AND harness=?2 AND reg=?3 AND tag=?4",
        params![id, harness, reg, tag],
    )
    .map_err(db_error)?;
    current_tags_for_reg(db, id, harness, reg)
}

/// I4: startup sweep before listeners accept and before `codex::init_for_db` marks roots inactive.
pub fn sweep_startup_tags(db: &Connection, proc_root: &std::path::Path) -> rusqlite::Result<()> {
    db.execute("DELETE FROM session_tag WHERE reg LIKE 'mint:%'", [])?;

    let mut claude_live_regs = std::collections::HashSet::new();
    {
        let mut stmt = db.prepare(
            "SELECT pid, proc_start, created_at FROM instance_claims WHERE released = 0",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let pid: i64 = row.get(0)?;
            let proc_start: String = row.get(1)?;
            let created_at: i64 = row.get(2)?;
            if pid > 0 {
                if let Ok(pid_u32) = u32::try_from(pid) {
                    if crate::registry::is_pid_live_in(proc_root, pid_u32, &proc_start) {
                        claude_live_regs.insert(format!("claude:{pid}:{proc_start}:{created_at}"));
                    }
                }
            }
        }
    }
    {
        let mut stmt =
            db.prepare("SELECT DISTINCT reg FROM session_tag WHERE reg LIKE 'claude:%'")?;
        let regs: Vec<String> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for reg in regs {
            if !claude_live_regs.contains(&reg) {
                db.execute("DELETE FROM session_tag WHERE reg = ?1", [&reg])?;
            }
        }
    }

    let mut codex_live_regs = std::collections::HashSet::new();
    {
        let mut stmt = db.prepare("SELECT generation FROM codex_roots WHERE revoked = 0")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let gen: i64 = row.get(0)?;
            codex_live_regs.insert(format!("codex:{gen}"));
        }
    }
    {
        let mut stmt =
            db.prepare("SELECT DISTINCT reg FROM session_tag WHERE reg LIKE 'codex:%'")?;
        let regs: Vec<String> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for reg in regs {
            if !codex_live_regs.contains(&reg) {
                db.execute("DELETE FROM session_tag WHERE reg = ?1", [&reg])?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tag_tests {
    use super::*;

    fn test_db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        storage::init_db(&db).unwrap();
        db
    }

    #[test]
    fn u1_live_tags_excludes_foreign_reg() {
        let db = test_db();
        db.execute(
            "INSERT INTO session_tag (id, harness, reg, tag, added_at) VALUES ('s1', 'claude', 'claude:1:10:100', 't1', 100)",
            [],
        )
        .unwrap();
        let all = live_tags(&db).unwrap();
        assert!(!all.contains_key(&("s1".into(), "claude".into(), "claude:1:10:200".into())));
        assert_eq!(
            all.get(&("s1".into(), "claude".into(), "claude:1:10:100".into()))
                .map(Vec::as_slice),
            Some(&["t1".to_string()][..])
        );
    }

    #[test]
    fn u2_sweep_startup_tags_deletes_stale_and_keeps_live_claude() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path();
        let my_pid = std::process::id();
        // Synthetic proc_root with /proc/<pid>/stat for live pid.
        let pid_dir = proc_root.join(my_pid.to_string());
        std::fs::create_dir_all(&pid_dir).unwrap();
        std::fs::write(
            pid_dir.join("stat"),
            format!("{my_pid} (xmsg) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0"),
        )
        .unwrap();
        assert!(crate::registry::is_pid_live_in(proc_root, my_pid, "12345"));

        let db = test_db();
        db.execute(
            "INSERT INTO instance_claims (id, pid, proc_start, suffix, released, created_at) VALUES ('live-c', ?1, '12345', 1, 0, 500)",
            [my_pid as i64],
        ).unwrap();
        db.execute(
            "INSERT INTO instance_claims (id, pid, proc_start, suffix, released, created_at) VALUES ('dead-c', 9999999, '99', 1, 0, 500)",
            [],
        ).unwrap();
        db.execute(
            "INSERT INTO codex_roots (root_id, codex_home, rollout_dev, rollout_ino, label, cwd, generation, revoked, owner_pid, owner_starttime, registered_at, active, restart_pending) VALUES ('cx1', '/tmp/cx', 1, 1, 'cx', '/', 7, 0, 1, '1', 1, 1, 0)",
            [],
        ).unwrap();

        let live_claude = format!("claude:{my_pid}:12345:500");
        let dead_claude = "claude:9999999:99:500";
        let orphan_claude = "claude:8888888:88:500";
        let live_codex = "codex:7";
        let stale_codex = "codex:6";
        let mint_row = "mint:00000000-0000-4000-8000-000000000001";

        for (id, h, reg) in [
            ("live-c", "claude", live_claude.as_str()),
            ("dead-c", "claude", dead_claude),
            ("orphan-c", "claude", orphan_claude),
            ("cx1", "codex", live_codex),
            ("cx1", "codex", stale_codex),
            ("a1", "agy", mint_row),
        ] {
            db.execute(
                "INSERT INTO session_tag (id, harness, reg, tag, added_at) VALUES (?1, ?2, ?3, 't', 1)",
                params![id, h, reg],
            ).unwrap();
        }

        sweep_startup_tags(&db, proc_root).unwrap();

        let remaining = live_tags(&db).unwrap();
        assert!(remaining.contains_key(&("live-c".into(), "claude".into(), live_claude)));
        assert!(remaining.contains_key(&("cx1".into(), "codex".into(), live_codex.to_string())));
        assert_eq!(
            remaining.len(),
            2,
            "expected only live claude and current codex rows: {remaining:?}"
        );
    }

    #[test]
    fn u3_u4_u6_add_check_cap_and_write_sweep() {
        let db = test_db();
        // U4: 8 foreign-reg rows do not count toward cap for K.
        for i in 0..8 {
            db.execute(
                "INSERT INTO session_tag (id, harness, reg, tag, added_at) VALUES ('s1', 'claude', 'claude:1:1:1', ?1, 1)",
                [format!("old{i}")],
            ).unwrap();
        }
        // U3: replaced registration between trace and insert is denied.
        let err = add_tag_with_check(&db, "s1", "claude", "claude:2:2:2", "t0", 10, || Ok(false))
            .unwrap_err();
        assert!(matches!(err, AppError::Denied(_)));

        // U6: add under K sweeps old foreign-reg rows and allows 8 tags under K.
        for i in 0..8 {
            let tags = add_tag_with_check(
                &db,
                "s1",
                "claude",
                "claude:2:2:2",
                &format!("k{i}"),
                10,
                || Ok(true),
            )
            .unwrap();
            assert_eq!(tags.len(), i + 1);
        }
        let old_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM session_tag WHERE reg='claude:1:1:1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(old_count, 0);

        let err9 = add_tag_with_check(&db, "s1", "claude", "claude:2:2:2", "k8", 10, || Ok(true))
            .unwrap_err();
        assert!(matches!(err9, AppError::BadRequest(_)));
    }
}
