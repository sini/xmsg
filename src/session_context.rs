use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worktree: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pr: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionContext {
    #[serde(flatten)]
    pub fields: ContextFields,
    pub updated_at: i64,
    pub generation: u64,
    pub stale: bool,
}

#[cfg(feature = "daemon")]
mod daemon;

#[cfg(feature = "daemon")]
pub use daemon::*;
#[cfg(all(test, feature = "daemon"))]
use daemon::{initialize, project_at, write};

#[cfg(all(test, feature = "daemon"))]
mod tests {
    use super::*;

    fn fields() -> ContextFields {
        ContextFields {
            repo: Some("github.com/org/repo".into()),
            branch: Some("feature/context".into()),
            task: Some("42".into()),
            ..Default::default()
        }
    }

    #[test]
    fn rejects_raw_paths_and_inert_text_violations() {
        for task in [
            "/tmp/work",
            "~/repo",
            "./repo",
            "../repo",
            r"C:\repo",
            "text\x1b",
            "text\u{202e}",
        ] {
            assert!(
                ContextFields {
                    task: Some(task.into()),
                    ..fields()
                }
                .validate()
                .is_err(),
                "{task:?}"
            );
        }
        assert!(fields().validate().is_ok());
    }

    #[test]
    fn enforces_field_and_encoded_limits() {
        assert!(ContextFields {
            task: Some("t".repeat(161)),
            ..fields()
        }
        .validate()
        .is_err());
        let large = ContextFields {
            repo: Some(format!("github.com/org/{}", "r".repeat(110))),
            branch: Some("b".repeat(128)),
            worktree: Some("w".repeat(64)),
            task: Some("t".repeat(160)),
            pr: Some("p".repeat(32)),
        };
        assert!(SessionContext {
            fields: large,
            updated_at: 1,
            generation: 1,
            stale: false
        }
        .validate_size()
        .is_err());
    }

    #[test]
    fn stale_context_expires_and_masking_preserves_other_surfaces() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        initialize(&db, true, &["observe:*".into(), "federation:task".into()]).unwrap();
        write(&db, "session", "claude", fields(), 100).unwrap();
        let local = project_at(&db, "session", "claude", Surface::Local, 100).unwrap();
        assert_eq!(local.fields, fields());
        assert_eq!(local.updated_at, 100);
        assert!(!local.stale);
        assert!(
            project_at(&db, "session", "claude", Surface::Local, 1000)
                .unwrap()
                .stale
        );
        assert!(project_at(&db, "session", "claude", Surface::Local, 1900).is_none());
        assert!(project_at(&db, "session", "claude", Surface::Observe, 100).is_none());
        let fed = project_at(&db, "session", "claude", Surface::Federation, 100).unwrap();
        assert_eq!(fed.fields.repo, fields().repo);
        assert_eq!(fed.fields.task, None);
    }

    #[test]
    fn disabled_policy_refuses_writes_and_suppresses_publication() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        initialize(&db, false, &[]).unwrap();
        assert!(write(&db, "session", "claude", fields(), 100).is_err());
        assert!(project_at(&db, "session", "claude", Surface::Local, 100).is_none());
    }

    #[test]
    fn policy_reload_applies_masks_and_clears_when_disabled() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        Config::default().apply(&db, false, &[]).unwrap();
        write(&db, "session", "claude", fields(), 100).unwrap();
        assert!(project_at(&db, "session", "agy", Surface::Local, 100).is_none());
        let policy: Config = toml::from_str("[context_mask]\nlocal = ['task']").unwrap();
        policy.apply(&db, false, &[]).unwrap();
        let local = project_at(&db, "session", "claude", Surface::Local, 100).unwrap();
        assert!(local.fields.task.is_none());
        assert_eq!(local.fields.repo, fields().repo);
        let policy: Config = toml::from_str("[context_tags]\nenabled = false").unwrap();
        policy.apply(&db, false, &[]).unwrap();
        Config::default().apply(&db, false, &[]).unwrap();
        assert!(project_at(&db, "session", "claude", Surface::Local, 100).is_none());
    }
}
