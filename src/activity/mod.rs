pub mod hook;
pub mod model;
pub mod reconcile;
pub mod reducer;
pub mod store;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};

use rusqlite::{params, Connection, OptionalExtension};

pub use model::{
    ActivityDescriptor, ActivityFrame, ActivityHarness, ActivityReason, ActivityState,
    ActivityStatus, BackgroundPresence, BlockKind, OwnerProof, SnapshotActivity, WakePresence,
    ACTIVITY_JOURNAL_MAX_BYTES, ACTIVITY_JOURNAL_MAX_ROWS, ACTIVITY_PUBLISH_QUEUE_CAP,
    ACTIVITY_RATE_LIMIT_PER_SEC,
};
pub use reducer::{
    ActivityEngine, ActivityIngestQueue, ActivityTransition, BindingOutcome, OwnerResolver,
    ProofFlags,
};
pub use store::SCHEMA;

pub struct DbOwnerResolver {
    pub db: Arc<Mutex<Connection>>,
    pub sessions_dirs: Vec<PathBuf>,
}

impl DbOwnerResolver {
    fn resolve_codex(
        conn: &Connection,
        frame: &ActivityFrame,
    ) -> rusqlite::Result<Option<BindingOutcome>> {
        let mut stmt = conn.prepare(
            "SELECT root_id, owner_pid, owner_starttime, generation, active, revoked
             FROM codex_roots
             WHERE root_id = ?1",
        )?;
        let row: Option<(String, i64, String, i64, i64, i64)> = stmt
            .query_row(params![frame.session], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })
            .optional()?;
        let Some((root_id, pid, start_str, gen, active, revoked)) = row else {
            return Ok(None);
        };
        if active == 0 || revoked != 0 {
            return Ok(Some(BindingOutcome::StaleOwner));
        }
        let Some(owner) = frame.owner else {
            return Ok(Some(BindingOutcome::Unverified {
                identified_address: Some(root_id),
            }));
        };
        let expected_start = start_str.parse::<u64>().ok();
        if pid as u32 == owner.pid && expected_start == Some(owner.started_at) {
            if !crate::registry::is_pid_live(owner.pid, &start_str) {
                return Ok(Some(BindingOutcome::Unverified {
                    identified_address: Some(root_id),
                }));
            }
            Ok(Some(BindingOutcome::Verified {
                address: root_id,
                incarnation: gen.max(1) as u64,
                owner,
                has_pending_wake: false,
            }))
        } else {
            Ok(Some(BindingOutcome::StaleOwner))
        }
    }

    fn resolve_claude(&self, frame: &ActivityFrame) -> Option<BindingOutcome> {
        let sessions = crate::registry::read_session_entries(&self.sessions_dirs);
        let matching: Vec<_> = sessions
            .into_iter()
            .filter(|s| s.session_id == frame.session)
            .collect();
        if matching.is_empty() {
            return None;
        }
        if matching.len() > 1 {
            return Some(BindingOutcome::AmbiguousOwners {
                address: matching[0].session_id.clone(),
            });
        }
        let entry = &matching[0];
        let Some(owner) = frame.owner else {
            return Some(BindingOutcome::Unverified {
                identified_address: Some(entry.session_id.clone()),
            });
        };
        if entry.pid == owner.pid && entry.started_at == owner.started_at {
            if !crate::registry::is_pid_live(owner.pid, &owner.started_at.to_string()) {
                return Some(BindingOutcome::Unverified {
                    identified_address: Some(entry.session_id.clone()),
                });
            }
            Some(BindingOutcome::Verified {
                address: entry.session_id.clone(),
                incarnation: owner.started_at.max(1),
                owner,
                has_pending_wake: false,
            })
        } else {
            Some(BindingOutcome::StaleOwner)
        }
    }
}

impl OwnerResolver for DbOwnerResolver {
    fn resolve(&self, frame: &ActivityFrame) -> BindingOutcome {
        let Ok(conn) = self.db.lock() else {
            return BindingOutcome::RegistryUnavailable {
                identified_address: None,
            };
        };
        match frame.harness {
            ActivityHarness::Codex => match Self::resolve_codex(&conn, frame) {
                Ok(Some(outcome)) => outcome,
                Ok(None) => BindingOutcome::Unverified {
                    identified_address: None,
                },
                Err(_) => BindingOutcome::RegistryUnavailable {
                    identified_address: None,
                },
            },
            ActivityHarness::Claude => {
                self.resolve_claude(frame)
                    .unwrap_or(BindingOutcome::Unverified {
                        identified_address: None,
                    })
            }
            _ => {
                // In-process / agy bindings verify owner pid + start time when present.
                let Some(owner) = frame.owner else {
                    return BindingOutcome::Unverified {
                        identified_address: Some(frame.session.clone()),
                    };
                };
                if !crate::registry::is_pid_live(owner.pid, &owner.started_at.to_string()) {
                    return BindingOutcome::Unverified {
                        identified_address: Some(frame.session.clone()),
                    };
                }
                BindingOutcome::Verified {
                    address: frame.session.clone(),
                    incarnation: owner.started_at.max(1),
                    owner,
                    has_pending_wake: false,
                }
            }
        }
    }

    fn is_owner_live(&self, owner: OwnerProof) -> bool {
        crate::registry::is_pid_live(owner.pid, &owner.started_at.to_string())
    }
}

#[derive(Clone)]
pub struct ActivityRuntime {
    pub engine: Arc<Mutex<ActivityEngine>>,
    pub tx: tokio::sync::mpsc::Sender<ActivityFrame>,
}

static RUNTIMES: LazyLock<Mutex<HashMap<usize, ActivityRuntime>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn register_runtime(db: &Arc<Mutex<Connection>>, runtime: ActivityRuntime) {
    if let Ok(mut map) = RUNTIMES.lock() {
        map.insert(Arc::as_ptr(db) as usize, runtime);
    }
}

pub fn unregister_runtime(db: &Arc<Mutex<Connection>>) {
    if let Ok(mut map) = RUNTIMES.lock() {
        map.remove(&(Arc::as_ptr(db) as usize));
    }
}

pub fn runtime_for_db(db: &Arc<Mutex<Connection>>) -> Option<ActivityRuntime> {
    RUNTIMES
        .lock()
        .ok()
        .and_then(|map| map.get(&(Arc::as_ptr(db) as usize)).cloned())
}

pub fn runtime_snapshot_state(
    db: &Arc<Mutex<Connection>>,
    address: &str,
) -> Option<ActivityDescriptor> {
    let rt = runtime_for_db(db)?;
    let guard = rt.engine.lock().ok()?;
    guard.descriptor_for(address)
}

pub fn runtime_snapshot_activity(db: &Arc<Mutex<Connection>>) -> SnapshotActivity {
    let Some(rt) = runtime_for_db(db) else {
        return SnapshotActivity {
            status: ActivityStatus::Disabled,
            complete: true,
        };
    };
    rt.engine
        .lock()
        .map(|g| g.snapshot_activity())
        .unwrap_or(SnapshotActivity {
            status: ActivityStatus::Disabled,
            complete: false,
        })
}
