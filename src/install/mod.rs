//! Explicit, reversible per-user harness configuration.

mod claude;
pub mod claude_observe;
mod json_edit;
mod transaction;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("unsupported_layout")]
    Unsupported,
    #[error("unsafe_target")]
    Unsafe,
    #[error("invalid_json")]
    InvalidJson,
    #[error("configuration_conflict")]
    Conflict,
    #[error("target_changed")]
    Drift,
    #[error("adapter_busy")]
    Busy,
    #[error("writer_observed")]
    WriterObserved,
    #[error("recovery_pending")]
    Recovery,
    #[error("adapter_io")]
    Io,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Install,
    Uninstall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ManagedField {
    #[serde(rename = "mcpServers.xmsg")]
    Mcp,
    #[serde(rename = "hooks.PreToolUse")]
    PreToolUse,
    #[serde(rename = "hooks.PostToolUse")]
    PostToolUse,
    #[serde(rename = "hooks.SubagentStart")]
    SubagentStart,
    #[serde(rename = "hooks.SubagentStop")]
    SubagentStop,
    #[serde(rename = "skills.xmsg")]
    Skill,
    #[serde(rename = "ownership")]
    Ownership,
    #[serde(rename = "recovery")]
    Recovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Add,
    Remove,
    Replace,
    Reuse,
    Conflict,
    Recover,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Change {
    pub field: ManagedField,
    pub operation: Operation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub action: Action,
    pub status: &'static str,
    pub changes: Vec<Change>,
}

#[derive(Clone, Debug)]
pub struct Request {
    pub account_home: PathBuf,
    pub state_root: PathBuf,
    pub executable: PathBuf,
    pub config_dir: Option<PathBuf>,
    pub agent_socket: Option<PathBuf>,
    pub http_socket: Option<PathBuf>,
    pub uid: u32,
}

pub struct Plan {
    pub report: Report,
    request: Request,
    targets: Vec<TargetPlan>,
    ownership: Ownership,
    before_ownership: Option<String>,
    pending: bool,
    metadata_change: bool,
}
impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plan")
            .field("report", &self.report)
            .finish()
    }
}
impl Plan {
    pub fn render(&self, json: bool) -> String {
        if json {
            serde_json::to_string(&self.report).expect("fixed report serialization")
        } else {
            let mut out = format!("claude: {}\n", self.report.status);
            for change in &self.report.changes {
                out.push_str(&format!(
                    "{} {}\n",
                    serde_json::to_string(&change.field).unwrap(),
                    serde_json::to_string(&change.operation).unwrap()
                ));
            }
            out
        }
    }
    pub fn apply(self) -> Result<Report, Error> {
        transaction::apply(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum TargetKind {
    Mcp,
    Settings,
    Skill,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OwnedEntry {
    field: ManagedField,
    selector: String,
    value: serde_json::Value,
    hash: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Ownership {
    version: u32,
    set_id: String,
    targets: Vec<PathBuf>,
    active: bool,
    entries: Vec<OwnedEntry>,
    created_files: BTreeSet<TargetKind>,
    created_containers: BTreeSet<String>,
}
struct TargetPlan {
    path: PathBuf,
    before: Option<transaction::Snapshot>,
    after: Option<Vec<u8>>,
    mode: u32,
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn plan(request: &Request, action: Action) -> Result<Plan, Error> {
    claude::plan(request, action)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fresh_claude_preview_has_no_filesystem_effects() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let request = Request {
            account_home: home.clone(),
            state_root: home.join("state"),
            executable: "/verified/bin/xmsg".into(),
            config_dir: None,
            agent_socket: None,
            http_socket: None,
            uid: unsafe { libc::geteuid() },
        };
        let preview = plan(&request, Action::Install).unwrap();
        assert_eq!(preview.report.status, "preview");
        assert!(preview
            .report
            .changes
            .iter()
            .any(|c| c.field == ManagedField::Mcp));
        assert_eq!(
            std::fs::read_dir(home).unwrap().count(),
            0,
            "preview created adapter or transaction files"
        );
        let output = serde_json::to_string(&preview.report).unwrap();
        assert!(!output.contains("verified/bin"));
    }
    #[test]
    fn applied_claude_hooks_are_owned_and_removed_without_user_data_loss() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let request = Request {
            account_home: home.clone(),
            state_root: home.join("state"),
            executable: "/verified/bin/xmsg".into(),
            config_dir: None,
            agent_socket: None,
            http_socket: None,
            uid: unsafe { libc::geteuid() },
        };
        let report = plan(&request, Action::Install).unwrap().apply().unwrap();
        assert_eq!(report.status, "applied");
        let settings = std::fs::read(home.join(".claude/settings.json")).unwrap();
        assert!(String::from_utf8_lossy(&settings).contains("register claude --hook"));
        plan(&request, Action::Uninstall).unwrap().apply().unwrap();
        assert!(
            !home.join(".claude/settings.json").exists(),
            "written hook lost its ownership record and survived uninstall"
        );
        assert!(!home.join(".claude.json").exists());
        assert!(!home.join(".claude/skills/xmsg/SKILL.md").exists());
        assert!(
            request.state_root.exists(),
            "uninstall removed retained daemon state"
        );
    }
    fn fixture() -> (tempfile::TempDir, Request) {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let request = Request {
            account_home: home.clone(),
            state_root: home.join("state"),
            executable: "/verified/bin/xmsg".into(),
            config_dir: None,
            agent_socket: None,
            http_socket: None,
            uid: unsafe { libc::geteuid() },
        };
        (root, request)
    }
    fn inventory(root: &std::path::Path) -> Vec<String> {
        use std::os::unix::fs::MetadataExt;
        fn visit(root: &std::path::Path, current: &std::path::Path, out: &mut Vec<String>) {
            let meta = std::fs::symlink_metadata(current).unwrap();
            let bytes = if meta.is_file() {
                hash(&std::fs::read(current).unwrap())
            } else {
                String::new()
            };
            out.push(format!(
                "{:?}:{:?}:{}:{}:{}:{}:{}:{}:{}:{}",
                current.strip_prefix(root).unwrap(),
                meta.created().ok(),
                meta.mode(),
                meta.uid(),
                meta.ino(),
                meta.mtime(),
                meta.mtime_nsec(),
                meta.ctime(),
                meta.ctime_nsec(),
                bytes
            ));
            if meta.is_dir() {
                let mut entries = std::fs::read_dir(current)
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .collect::<Vec<_>>();
                entries.sort();
                for entry in entries {
                    visit(root, &entry, out);
                }
            }
        }
        let mut out = Vec::new();
        visit(root, root, &mut out);
        out
    }
    #[test]
    fn repeat_and_preview_leave_all_content_and_metadata_unchanged() {
        let (_root, request) = fixture();
        let before = inventory(&request.account_home);
        let preview = plan(&request, Action::Install).unwrap();
        let _ = preview.render(false);
        let _ = preview.render(true);
        assert_eq!(
            inventory(&request.account_home),
            before,
            "preview performed eager preparation"
        );
        preview.apply().unwrap();
        let installed = inventory(&request.account_home);
        let repeat = plan(&request, Action::Install).unwrap();
        assert_eq!(repeat.report.status, "no_op");
        repeat.apply().unwrap();
        assert_eq!(
            inventory(&request.account_home),
            installed,
            "repeat install changed backups or ownership metadata"
        );
        plan(&request, Action::Uninstall).unwrap().apply().unwrap();
        let removed = inventory(&request.account_home);
        plan(&request, Action::Uninstall).unwrap().apply().unwrap();
        assert_eq!(
            inventory(&request.account_home),
            removed,
            "repeat uninstall changed retained state"
        );
    }
    #[test]
    fn dirty_neighbors_keep_exact_syntax_order_and_permissions() {
        let (_root, request) = fixture();
        let mcp = request.account_home.join(".claude.json");
        let settings = request.account_home.join(".claude/settings.json");
        std::fs::create_dir(settings.parent().unwrap()).unwrap();
        let original=b"{\n  \"neighbor\" : {\"token\":\"SYNTHETIC_NEIGHBOR_CANARY\",\"n\":1.00e+2},\n  \"mcpServers\" : { \"other\" : { \"command\" : \"unrelated\" } }\n}\n";
        let user_settings=b"{ \"permissions\" : { \"allow\" : [\"Read\"] }, \"hooks\" : { \"SubagentStart\" : [{\"hooks\":[{\"type\":\"command\",\"command\":\"user-command\"}]}] } }\n";
        std::fs::write(&mcp, original).unwrap();
        std::fs::write(&settings, user_settings).unwrap();
        let preview = plan(&request, Action::Install).unwrap();
        for output in [preview.render(false), preview.render(true)] {
            assert!(
                !output.contains("SYNTHETIC_NEIGHBOR_CANARY"),
                "install report leaked neighboring value"
            );
            assert!(!output.contains("unrelated"));
        }
        preview.apply().unwrap();
        let installed = std::fs::read(&mcp).unwrap();
        assert!(
            installed
                .windows(b"\"token\":\"SYNTHETIC_NEIGHBOR_CANARY\",\"n\":1.00e+2".len())
                .any(|w| w == b"\"token\":\"SYNTHETIC_NEIGHBOR_CANARY\",\"n\":1.00e+2"),
            "whole-file replacement changed unowned syntax"
        );
        plan(&request, Action::Uninstall).unwrap().apply().unwrap();
        assert_eq!(
            std::fs::read(mcp).unwrap(),
            original,
            "uninstall rewrote unowned syntax or key order"
        );
        assert_eq!(
            std::fs::read(settings).unwrap(),
            user_settings,
            "installer changed unowned hook or permission entries"
        );
    }
    #[test]
    fn changed_after_plan_refuses_before_target_publication() {
        let (_root, request) = fixture();
        let target = request.account_home.join(".claude.json");
        std::fs::write(&target, b"{}").unwrap();
        let planned = plan(&request, Action::Install).unwrap();
        std::fs::write(&target, b"{\"changed\":true}").unwrap();
        assert_eq!(planned.apply().unwrap_err(), Error::Drift);
        assert_eq!(std::fs::read(target).unwrap(), b"{\"changed\":true}");
        assert!(!request.account_home.join(".claude/settings.json").exists());
    }
    #[test]
    fn edited_owned_entry_is_preserved_with_redacted_repeatable_conflict() {
        let (_root, request) = fixture();
        plan(&request, Action::Install).unwrap().apply().unwrap();
        let target = request.account_home.join(".claude.json");
        std::fs::write(&target,b"{\"neighbor\":\"SYNTHETIC_UNINSTALL_CANARY\",\"mcpServers\":{\"xmsg\":{\"command\":\"EDITED_SENTINEL\"}}}").unwrap();
        let removal = plan(&request, Action::Uninstall).unwrap();
        for report in [removal.render(false), removal.render(true)] {
            assert!(
                !report.contains("SYNTHETIC_UNINSTALL_CANARY"),
                "uninstall conflict report leaked neighboring value"
            );
            assert!(!report.contains("EDITED_SENTINEL"));
        }
        removal.apply().unwrap();
        assert!(
            String::from_utf8(std::fs::read(&target).unwrap())
                .unwrap()
                .contains("EDITED_SENTINEL"),
            "uninstall removed an edited owned entry"
        );
        let before = inventory(&request.account_home);
        plan(&request, Action::Uninstall).unwrap().apply().unwrap();
        assert_eq!(
            inventory(&request.account_home),
            before,
            "unchanged conflict rewrote backups or ownership metadata"
        );
    }
    #[test]
    fn identical_unowned_configuration_is_never_adopted() {
        let (_source_root, source) = fixture();
        plan(&source, Action::Install).unwrap().apply().unwrap();
        let (_root, request) = fixture();
        let relatives = [
            ".claude.json",
            ".claude/settings.json",
            ".claude/skills/xmsg/SKILL.md",
        ];
        for name in relatives {
            let target = request.account_home.join(name);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::copy(source.account_home.join(name), target).unwrap();
        }
        plan(&request, Action::Install).unwrap().apply().unwrap();
        let removal = plan(&request, Action::Uninstall).unwrap();
        assert!(
            removal.ownership.entries.is_empty(),
            "identical unowned entries were adopted"
        );
        removal.apply().unwrap();
        for name in relatives {
            assert_eq!(
                std::fs::read(request.account_home.join(name)).unwrap(),
                std::fs::read(source.account_home.join(name)).unwrap(),
                "uninstall removed identical unowned content"
            );
        }
    }
    #[test]
    fn all_state_roots_for_one_account_share_the_adapter_lock() {
        let (_root, first) = fixture();
        let mut second = first.clone();
        second.state_root = first.account_home.join("another-state");
        let held = transaction::lock(&first).unwrap();
        let outcome = plan(&second, Action::Install).unwrap().apply();
        assert!(
            !first.account_home.join(".claude.json").exists(),
            "competing state root published while the account adapter lock was held"
        );
        assert_eq!(outcome.unwrap_err(), Error::Busy);
        drop(held);
    }
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }
    fn crash_after_first_publish(request: &Request) {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "install::tests::install_crash_fixture",
                "--nocapture",
            ])
            .env("XMSG_INSTALL_FIXTURE_HOME", &request.account_home)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut child = ChildGuard(child);
        let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                std::time::Instant::now() < bound,
                "owned install crash fixture did not finish"
            );
            std::thread::yield_now();
        };
        assert_eq!(
            status.code(),
            Some(73),
            "fixture must exit after the first published file"
        );
    }
    #[test]
    #[ignore = "test-only owned crash process, executed and reaped by recovery oracles"]
    fn install_crash_fixture() {
        let home = PathBuf::from(std::env::var_os("XMSG_INSTALL_FIXTURE_HOME").unwrap());
        let request = Request {
            account_home: home.clone(),
            state_root: home.join("state"),
            executable: "/verified/bin/xmsg".into(),
            config_dir: None,
            agent_socket: None,
            http_socket: None,
            uid: unsafe { libc::geteuid() },
        };
        transaction::AFTER_PUBLICATION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|index| {
                if index == 0 {
                    unsafe { libc::_exit(73) }
                }
            }))
        });
        plan(&request, Action::Install).unwrap().apply().unwrap();
        panic!("crash barrier was not reached");
    }
    #[test]
    fn interrupted_apply_has_durable_intent_and_explicit_recovery() {
        let (_root, request) = fixture();
        std::fs::write(
            request.account_home.join(".claude.json"),
            b"{\"neighbor\":\"RETAINED_BEFORE\"}",
        )
        .unwrap();
        crash_after_first_publish(&request);
        assert!(
            String::from_utf8(std::fs::read(request.account_home.join(".claude.json")).unwrap())
                .unwrap()
                .contains("mcpServers"),
            "crash did not follow a real target publication"
        );
        assert!(
            !request.account_home.join(".claude/settings.json").exists(),
            "fixture did not stop after the first rename"
        );
        let before = inventory(&request.account_home);
        let recovery = plan(&request, Action::Install).unwrap();
        assert_eq!(
            recovery.report.status, "recovery_pending",
            "partial publication lacks durable recovery state"
        );
        assert_eq!(
            inventory(&request.account_home),
            before,
            "recovery preview wrote to disk"
        );
        recovery.apply().unwrap();
        assert!(
            std::fs::read_to_string(request.account_home.join(".claude.json"))
                .unwrap()
                .contains("RETAINED_BEFORE")
        );
        assert!(request.account_home.join(".claude/settings.json").exists());
        assert_eq!(
            plan(&request, Action::Install).unwrap().report.status,
            "no_op"
        );
    }
    #[test]
    fn interrupted_apply_preserves_changed_bytes_and_all_backups() {
        let (_root, request) = fixture();
        std::fs::write(
            request.account_home.join(".claude.json"),
            b"{\"before\":true}",
        )
        .unwrap();
        crash_after_first_publish(&request);
        let target = request.account_home.join(".claude.json");
        std::fs::write(&target, b"{\"concurrent\":\"CHANGED_DURING_RECOVERY\"}").unwrap();
        let before = inventory(&request.account_home);
        let result = plan(&request, Action::Install).unwrap().apply();
        assert_eq!(result.unwrap_err(), Error::Conflict);
        assert_eq!(
            inventory(&request.account_home),
            before,
            "recovery changed conflicting bytes or private backups"
        );
    }
    #[test]
    fn preview_refuses_duplicate_keys_symlinks_and_unsafe_coordinator() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let (_root, request) = fixture();
        let target = request.account_home.join(".claude.json");
        std::fs::write(&target, b"{\"mcpServers\":{},\"mcpServers\":{}}").unwrap();
        assert_eq!(
            plan(&request, Action::Install).unwrap_err(),
            Error::InvalidJson
        );
        std::fs::remove_file(&target).unwrap();
        let outside = request.account_home.join("other");
        std::fs::write(&outside, b"{}").unwrap();
        symlink(&outside, &target).unwrap();
        assert_eq!(plan(&request, Action::Install).unwrap_err(), Error::Unsafe);
        std::fs::remove_file(&target).unwrap();
        let coordinator = transaction::coordinator(&request);
        std::fs::create_dir_all(&coordinator).unwrap();
        std::fs::set_permissions(&coordinator, std::fs::Permissions::from_mode(0o755)).unwrap();
        let before = inventory(&request.account_home);
        assert_eq!(plan(&request, Action::Install).unwrap_err(), Error::Unsafe);
        assert_eq!(inventory(&request.account_home), before);
    }
    #[test]
    fn observed_managed_policy_conflict_refuses_without_target_changes() {
        let (_root, request) = fixture();
        let policy = request.account_home.join(".managed-policy-fixture");
        std::fs::create_dir(&policy).unwrap();
        std::fs::write(
            policy.join("managed-mcp.json"),
            b"{\"mcpServers\":{\"xmsg\":{\"command\":\"SYNTHETIC_POLICY_CANARY\"}}}",
        )
        .unwrap();
        let before = inventory(&request.account_home);
        assert_eq!(
            plan(&request, Action::Install).unwrap_err(),
            Error::Conflict
        );
        assert_eq!(inventory(&request.account_home), before);
    }
}
