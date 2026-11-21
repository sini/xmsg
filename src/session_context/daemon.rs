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
