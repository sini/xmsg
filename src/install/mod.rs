//! Explicit, reversible per-user harness configuration.

mod claude;
pub mod claude_observe;
mod json_edit;
mod transaction;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid_arguments")]
    Arguments,
    #[error("installation_resolution")]
    Resolution,
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
impl Report {
    pub fn render(&self, json: bool) -> String {
        if json {
            serde_json::to_string(self).expect("fixed report serialization")
        } else {
            let mut out = format!("claude: {}\n", self.status);
            for change in &self.changes {
                out.push_str(&format!(
                    "{} {}\n",
                    serde_json::to_string(&change.field).unwrap(),
                    serde_json::to_string(&change.operation).unwrap()
                ));
            }
            out
        }
    }
}

#[derive(clap::Subcommand, Debug)]
pub enum Adapter {
    Claude(Args),
}
#[derive(clap::Args, Debug)]
pub struct Args {
    /// Explicitly publish the planned adapter changes
    #[arg(long, conflicts_with = "dry_run")]
    pub apply: bool,
    /// Preview only; never create files or acquire a lock
    #[arg(long)]
    pub dry_run: bool,
    /// Print the allowlisted machine-readable plan or result
    #[arg(long)]
    pub json: bool,
    /// Database selecting the daemon's state root
    #[arg(long, env = "XMSG_DB_PATH", hide_env_values = true)]
    pub db_path: Option<PathBuf>,
    #[arg(long, env = "XMSG_AGENT_SOCK", hide_env_values = true)]
    pub agent_sock: Option<PathBuf>,
    #[arg(long, env = "XMSG_HTTP_SOCK", hide_env_values = true)]
    pub http_sock: Option<PathBuf>,
    #[arg(long, env = "XMSG_REGISTER_SOCK", hide_env_values = true)]
    pub register_sock: Option<PathBuf>,
    /// Preserve a compatible enrollment-state selection while planning roots
    #[arg(long)]
    pub enroll_state: Option<PathBuf>,
    #[arg(long, env = "XMSG_PEERS_FILE", hide_env_values = true)]
    pub peers_file: Option<PathBuf>,
}

#[doc(hidden)]
pub fn request_from_environment(
    args: &Args,
    env: &crate::install_paths::ResolveEnv<'_>,
    executable: PathBuf,
    config_dir: Option<PathBuf>,
) -> Result<Request, Error> {
    if args.apply && args.dry_run {
        return Err(Error::Arguments);
    }
    let input = crate::install_paths::ResolveRequest {
        db_path: args.db_path.clone(),
        agent_sock: args.agent_sock.clone(),
        http_sock: args.http_sock.clone(),
        register_sock: args.register_sock.clone(),
        enroll_state: args.enroll_state.clone(),
        peers_file: args.peers_file.clone(),
        ..Default::default()
    };
    Request::resolve(&input, env, executable, config_dir)
}

fn run_request(args: &Args, action: Action, request: Request) -> Result<(String, bool), Error> {
    let planned = plan(&request, action)?;
    if args.apply {
        let report = planned.apply()?;
        let success = report.status != "conflict";
        Ok((report.render(args.json), success))
    } else {
        let success = planned.report.status != "conflict";
        Ok((planned.render(args.json), success))
    }
}

pub fn run_with_environment(
    args: &Args,
    action: Action,
    env: &crate::install_paths::ResolveEnv<'_>,
    executable: PathBuf,
    config_dir: Option<PathBuf>,
) -> Result<(String, bool), Error> {
    run_request(
        args,
        action,
        request_from_environment(args, env, executable, config_dir)?,
    )
}

pub fn run_cli(adapter: Adapter, action: Action) -> bool {
    let Adapter::Claude(args) = adapter;
    let lookup = crate::install_paths::SystemHomeLookup;
    let env = crate::install_paths::ResolveEnv::from_process(&lookup);
    let request = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|_| Error::Unsafe)
        .and_then(|executable| {
            request_from_environment(
                &args,
                &env,
                executable,
                std::env::var_os("CLAUDE_CONFIG_DIR").map(PathBuf::from),
            )
        });
    run_cli_request(&args, action, request)
}

#[doc(hidden)]
pub fn run_cli_request(args: &Args, action: Action, request: Result<Request, Error>) -> bool {
    let result = request.and_then(|request| run_request(args, action, request));
    match result {
        Ok((output, success)) => {
            println!("{output}");
            success
        }
        Err(error) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({"action":action,"status":"refused","reason":error.to_string()})
                );
            } else {
                println!("claude: refused {error}");
            }
            false
        }
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    account_home: PathBuf,
    state_root: PathBuf,
    db_path: PathBuf,
    executable: PathBuf,
    config_dir: Option<PathBuf>,
    agent_socket: Option<PathBuf>,
    http_socket: Option<PathBuf>,
    command_environment: BTreeMap<&'static str, String>,
    uid: u32,
    resolution: Resolution,
    #[cfg(any(test, feature = "test-hooks"))]
    policy_roots: Option<Vec<PathBuf>>,
}

#[derive(Clone, Debug)]
struct Resolution {
    input: crate::install_paths::ResolveRequest,
    home: Option<std::ffi::OsString>,
    xdg_config_home: Option<std::ffi::OsString>,
    xdg_state_home: Option<std::ffi::OsString>,
    xdg_runtime_dir: Option<std::ffi::OsString>,
    darwin_user_temp_dir: Option<PathBuf>,
    system_tmp: PathBuf,
    platform: crate::install_paths::Platform,
}
impl Request {
    pub fn resolve(
        input: &crate::install_paths::ResolveRequest,
        env: &crate::install_paths::ResolveEnv<'_>,
        executable: PathBuf,
        config_dir: Option<PathBuf>,
    ) -> Result<Self, Error> {
        let account_home =
            crate::install_paths::resolve_account_home(env).map_err(|_| Error::Resolution)?;
        let roots =
            crate::install_paths::plan_install_roots(input, env).map_err(|_| Error::Resolution)?;
        if config_dir.is_some() {
            return Err(Error::Unsupported);
        }
        let mut command_environment = BTreeMap::new();
        for (name, raw) in [
            ("XDG_CONFIG_HOME", &env.xdg_config_home),
            ("XDG_STATE_HOME", &env.xdg_state_home),
            ("XDG_RUNTIME_DIR", &env.xdg_runtime_dir),
        ] {
            let value = raw
                .as_deref()
                .unwrap_or_default()
                .to_str()
                .ok_or(Error::Unsupported)?;
            if value.contains('\0') {
                return Err(Error::Unsupported);
            }
            command_environment.insert(name, value.to_string());
        }
        for p in [&executable, &roots.db_path]
            .into_iter()
            .chain(roots.agent_sock.iter())
            .chain(roots.http_sock.iter())
        {
            if !p.is_absolute() || p.to_str().is_none() {
                return Err(Error::Unsupported);
            }
        }
        Ok(Self {
            account_home,
            state_root: crate::install_paths::canonicalize_best_effort(&roots.state_root)
                .map_err(|_| Error::Resolution)?,
            db_path: roots.db_path,
            executable,
            config_dir,
            agent_socket: roots.agent_sock,
            http_socket: roots.http_sock,
            command_environment,
            uid: env.euid,
            resolution: Resolution {
                input: input.clone(),
                home: env.home.clone(),
                xdg_config_home: env.xdg_config_home.clone(),
                xdg_state_home: env.xdg_state_home.clone(),
                xdg_runtime_dir: env.xdg_runtime_dir.clone(),
                darwin_user_temp_dir: env.darwin_user_temp_dir.clone(),
                system_tmp: env.system_tmp.clone(),
                platform: env.platform,
            },
            #[cfg(any(test, feature = "test-hooks"))]
            policy_roots: None,
        })
    }
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn with_fixture_policy_roots(mut self, roots: Vec<PathBuf>) -> Self {
        self.policy_roots = Some(roots);
        self
    }
    fn prepare_roots(&self) -> Result<(), Error> {
        struct CapturedHome<'a>(&'a Request);
        impl crate::install_paths::HomeLookup for CapturedHome<'_> {
            fn account_home(&self, uid: u32) -> Option<PathBuf> {
                (uid == self.0.uid).then(|| self.0.account_home.clone())
            }
        }
        let lookup = CapturedHome(self);
        let selected = &self.resolution;
        let env = crate::install_paths::ResolveEnv {
            home: selected.home.clone(),
            xdg_config_home: selected.xdg_config_home.clone(),
            xdg_state_home: selected.xdg_state_home.clone(),
            xdg_runtime_dir: selected.xdg_runtime_dir.clone(),
            darwin_user_temp_dir: selected.darwin_user_temp_dir.clone(),
            system_tmp: selected.system_tmp.clone(),
            platform: selected.platform,
            euid: self.uid,
            home_lookup: &lookup,
        };
        let request = crate::install_paths::ResolveRequest {
            writable: true,
            ..selected.input.clone()
        };
        let resolved =
            crate::install_paths::resolve_install(&request, &env).map_err(|_| Error::Resolution)?;
        if crate::install_paths::canonicalize_best_effort(&resolved.state_root)
            .map_err(|_| Error::Resolution)?
            != crate::install_paths::canonicalize_best_effort(&self.state_root)
                .map_err(|_| Error::Resolution)?
            || resolved.db_path != self.db_path
        {
            return Err(Error::Drift);
        }
        Ok(())
    }
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
        self.report.render(json)
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

#[derive(Clone, Debug, Serialize)]
pub struct AdapterObservation {
    pub adapter: &'static str,
    pub coordinator: &'static str,
    pub writers: &'static str,
    pub managed_policy: &'static str,
    pub shadowing: &'static str,
    pub loaded_hooks: &'static str,
}
pub fn observe(request: &Request) -> AdapterObservation {
    let observation = claude_observe::inspect(request);
    let (writers, managed_policy) = observation
        .as_ref()
        .map(|o| (o.writers, o.managed_policy))
        .unwrap_or(("unknown", "unknown"));
    let coordinator = match std::fs::symlink_metadata(transaction::coordinator(request)) {
        Ok(metadata) => {
            use std::os::unix::fs::MetadataExt;
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == request.uid
                && metadata.mode() & 0o777 == 0o700
            {
                "present"
            } else {
                "unsafe"
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "absent",
        Err(_) => "unknown",
    };
    let adapter = if managed_policy == "conflict" {
        "policy_conflict"
    } else {
        match plan(request, Action::Uninstall) {
            Ok(removal) if removal.pending => "recovery_pending",
            Ok(removal)
                if removal
                    .report
                    .changes
                    .iter()
                    .any(|c| c.operation == Operation::Conflict) =>
            {
                "drift"
            }
            Ok(removal)
                if removal
                    .report
                    .changes
                    .iter()
                    .any(|c| c.operation == Operation::Remove) =>
            {
                "installed"
            }
            Ok(removal)
                if removal.before_ownership.is_some() && removal.report.status != "no_op" =>
            {
                "unowned"
            }
            Ok(_) => "not_installed",
            Err(Error::Unsafe) => "unsafe",
            Err(Error::InvalidJson) => "invalid",
            Err(Error::Unsupported) => "unsupported_layout",
            Err(Error::Conflict) => "conflict",
            Err(_) => "unknown",
        }
    };
    AdapterObservation {
        adapter,
        coordinator,
        writers,
        managed_policy,
        shadowing: if managed_policy == "conflict" {
            "observed"
        } else {
            "unknown"
        },
        loaded_hooks: "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request_for_home(home: &std::path::Path) -> Request {
        let lookup = crate::install_paths::FixtureHomeLookup(Some(home.to_path_buf()));
        let env = crate::install_paths::ResolveEnv {
            home: Some(home.as_os_str().to_owned()),
            xdg_config_home: None,
            xdg_state_home: None,
            xdg_runtime_dir: None,
            darwin_user_temp_dir: None,
            system_tmp: "/tmp".into(),
            platform: crate::install_paths::Platform::current(),
            euid: unsafe { libc::geteuid() },
            home_lookup: &lookup,
        };
        let input = crate::install_paths::ResolveRequest {
            db_path: Some(home.join("state/xmsg.db")),
            ..Default::default()
        };
        Request::resolve(&input, &env, "/verified/bin/xmsg".into(), None).unwrap()
    }
    #[test]
    fn fresh_claude_preview_has_no_filesystem_effects() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let request = request_for_home(&home);
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
        let request = request_for_home(&home);
        let report = plan(&request, Action::Install).unwrap().apply().unwrap();
        assert_eq!(report.status, "applied");
        let settings = std::fs::read(home.join(".claude/settings.json")).unwrap();
        assert!(String::from_utf8_lossy(&settings).contains("register claude --hook"));
        let retained = [
            ("xmsg.db", b"synthetic-database-sentinel".as_slice()),
            ("enroll/fed.key", b"synthetic-identity-sentinel".as_slice()),
            ("logs/daemon.log", b"synthetic-log-sentinel".as_slice()),
        ];
        for (relative, bytes) in retained {
            let file = request.state_root.join(relative);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, bytes).unwrap();
        }
        plan(&request, Action::Uninstall).unwrap().apply().unwrap();
        assert!(
            !home.join(".claude/settings.json").exists(),
            "written hook lost its ownership record and survived uninstall"
        );
        for (relative, bytes) in retained {
            assert_eq!(
                std::fs::read(request.state_root.join(relative)).unwrap(),
                bytes,
                "uninstall changed retained database, identity or logs"
            );
        }
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
        let request = request_for_home(&home);
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
        let repeat = plan(&request_for_home(&request.account_home), Action::Install).unwrap();
        assert_eq!(repeat.report.status, "no_op");
        repeat.apply().unwrap();
        assert_eq!(
            inventory(&request.account_home),
            installed,
            "repeat install changed backups or ownership metadata"
        );
        plan(&request_for_home(&request.account_home), Action::Uninstall)
            .unwrap()
            .apply()
            .unwrap();
        let removed = inventory(&request.account_home);
        plan(&request_for_home(&request.account_home), Action::Uninstall)
            .unwrap()
            .apply()
            .unwrap();
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
        let (_root, request) = fixture();
        let seeded = plan(&request, Action::Install)
            .unwrap()
            .targets
            .into_iter()
            .map(|target| (target.path, target.after.unwrap()))
            .collect::<Vec<_>>();
        for (target, bytes) in &seeded {
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(target, bytes).unwrap();
        }
        plan(&request, Action::Install).unwrap().apply().unwrap();
        let removal = plan(&request, Action::Uninstall).unwrap();
        assert!(
            removal.ownership.entries.is_empty(),
            "identical unowned entries were adopted"
        );
        removal.apply().unwrap();
        for (target, bytes) in seeded {
            assert_eq!(
                std::fs::read(target).unwrap(),
                bytes,
                "uninstall removed identical unowned content"
            );
        }
    }
    #[test]
    fn all_state_roots_for_one_account_share_the_adapter_lock() {
        let (_root, first) = fixture();
        let mut second = first.clone();
        second.state_root = first.account_home.join("another-state");
        second.db_path = second.state_root.join("xmsg.db");
        second.resolution.input.db_path = Some(second.db_path.clone());
        let held = transaction::lock(&first).unwrap();
        let outcome = plan(&second, Action::Install).unwrap().apply();
        assert!(
            !first.account_home.join(".claude.json").exists(),
            "competing state root published while the account adapter lock was held"
        );
        assert_eq!(outcome.unwrap_err(), Error::Busy);
        drop(held);
    }
    #[test]
    fn actual_inflight_apply_excludes_another_state_before_publication() {
        let (_root, first) = fixture();
        let mut second = first.clone();
        second.state_root = first.account_home.join("second-state");
        second.db_path = second.state_root.join("xmsg.db");
        second.resolution.input.db_path = Some(second.db_path.clone());
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let a = first.clone();
        let worker = std::thread::spawn(move || {
            transaction::BEFORE_PUBLICATION.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    ready_tx.send(()).unwrap();
                    let _ = release_rx.recv();
                }))
            });
            let result = plan(&a, Action::Install).unwrap().apply();
            transaction::BEFORE_PUBLICATION.with(|hook| *hook.borrow_mut() = None);
            result
        });
        let ready = ready_rx.recv_timeout(std::time::Duration::from_secs(10));
        if ready.is_err() {
            let _ = release_tx.send(());
            let _ = worker.join();
            panic!("first apply did not reach the durable pre-publication barrier");
        }
        let outcome = plan(&second, Action::Install).and_then(Plan::apply);
        let published = first.account_home.join(".claude/settings.json").exists();
        let created_second = second.state_root.exists();
        let _ = release_tx.send(());
        let completed = worker.join().unwrap();
        assert!(
            !published,
            "competing apply published while the first transaction held the account lock"
        );
        assert!(
            !created_second,
            "competing apply created a state transaction while the account lock was held"
        );
        assert_eq!(outcome.unwrap_err(), Error::Busy);
        assert_eq!(completed.unwrap().status, "applied");
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
        let request = request_for_home(&home);
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
    #[test]
    fn committed_transactions_retain_per_file_hashes_and_private_backups() {
        let (_root, request) = fixture();
        std::fs::write(
            request.account_home.join(".claude.json"),
            b"{\"neighbor\":\"RETAINED_TRANSACTION_BEFORE\"}",
        )
        .unwrap();
        let planned = plan(&request, Action::Install).unwrap();
        let key = planned.ownership.set_id.clone();
        planned.apply().unwrap();
        let root = transaction::area(&request, &key).join("backups");
        let attempts = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(attempts.len(), 1);
        let manifest = std::fs::read(attempts[0].join("manifest.json"));
        assert!(
            manifest.is_ok(),
            "committed transaction discarded per-file before/after hash record"
        );
        let record: serde_json::Value = serde_json::from_slice(&manifest.unwrap()).unwrap();
        assert_eq!(record["files"].as_array().unwrap().len(), 3);
        assert!(record["files"][0]["before"]["hash"].is_string());
        assert!(record["files"][0]["after_hash"].is_string());
        assert_eq!(
            std::fs::read(attempts[0].join("0.before")).unwrap(),
            b"{\"neighbor\":\"RETAINED_TRANSACTION_BEFORE\"}"
        );
        assert!(!transaction::area(&request, &key)
            .join("intent.json")
            .exists());
    }
    #[test]
    fn canonical_explicit_parent_and_shared_ancestors_keep_supported_paths() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let shared = root.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        let home = shared.join("home");
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let request = request_for_home(&home);
        let outcome = plan(&request, Action::Install).unwrap().apply();
        assert!(
            outcome.is_ok(),
            "installer rejected an arbitrary shared ancestor: {outcome:?}"
        );
        let alias = root.path().join("alias");
        symlink(&home, &alias).unwrap();
        let lookup = crate::install_paths::FixtureHomeLookup(Some(home.clone()));
        let env = crate::install_paths::ResolveEnv {
            home: Some(home.as_os_str().to_owned()),
            xdg_config_home: None,
            xdg_state_home: None,
            xdg_runtime_dir: None,
            darwin_user_temp_dir: None,
            system_tmp: "/tmp".into(),
            platform: crate::install_paths::Platform::current(),
            euid: unsafe { libc::geteuid() },
            home_lookup: &lookup,
        };
        let input = crate::install_paths::ResolveRequest {
            db_path: Some(alias.join("alias-state/xmsg.db")),
            ..Default::default()
        };
        let request = Request::resolve(&input, &env, "/verified/bin/xmsg".into(), None).unwrap();
        let outcome = plan(&request, Action::Install).unwrap().apply();
        assert!(
            outcome.is_ok(),
            "installer did not use the resolver's canonical explicit parent: {outcome:?}"
        );
        assert!(home.join("alias-state/install/claude").exists());
    }
    #[test]
    fn adapter_observation_is_readonly_while_owner_locks_are_held() {
        let (_root, request) = fixture();
        plan(&request, Action::Install).unwrap().apply().unwrap();
        let _state = crate::runtime_lock::StateLock::try_acquire(&request.state_root).unwrap();
        let _adapter = transaction::lock(&request).unwrap();
        let before = inventory(&request.account_home);
        let observed = observe(&request);
        assert_eq!(observed.adapter, "installed");
        assert_eq!(observed.coordinator, "present");
        assert_eq!(observed.loaded_hooks, "unknown");
        assert_eq!(observed.shadowing, "unknown");
        assert_eq!(
            inventory(&request.account_home),
            before,
            "adapter doctor observation wrote files or lock metadata"
        );
        let output = serde_json::to_string(&observed).unwrap();
        assert!(!output.contains(request.account_home.to_str().unwrap()));
    }
    #[test]
    fn captured_unset_xdg_values_keep_shared_resolver_semantics() {
        let (_root, request) = fixture();
        for name in ["XDG_STATE_HOME", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR"] {
            let captured = &request.command_environment[name];
            assert!(captured.is_empty());
            assert_eq!(
                crate::install_paths::validated_xdg(name, Some(std::ffi::OsStr::new(captured)))
                    .unwrap(),
                crate::install_paths::validated_xdg(name, None).unwrap(),
                "empty capture changed originally unset root semantics"
            );
        }
    }
    #[test]
    fn explicit_apply_refuses_an_observed_writer_even_when_unchanged() {
        let (_root, request) = fixture();
        plan(&request, Action::Install).unwrap().apply().unwrap();
        let unchanged = plan(&request, Action::Install).unwrap();
        assert_eq!(unchanged.report.status, "no_op");
        let sessions = request.account_home.join(".claude/sessions");
        std::fs::create_dir(&sessions).unwrap();
        let pid = std::process::id();
        let start =
            crate::process::starttime(std::path::Path::new(crate::process::LIVE_PROC_ROOT), pid)
                .unwrap();
        std::fs::write(
            sessions.join("writer.json"),
            serde_json::to_vec(&serde_json::json!({"pid":pid,"procStart":start})).unwrap(),
        )
        .unwrap();
        let before = inventory(&request.account_home);
        let result = unchanged.apply();
        assert_eq!(
            result.unwrap_err(),
            Error::WriterObserved,
            "no-op apply ignored a positively observed writer"
        );
        assert_eq!(inventory(&request.account_home), before);
    }
    #[test]
    fn explicit_apply_rechecks_policy_after_planning() {
        let (_root, request) = fixture();
        plan(&request, Action::Install).unwrap().apply().unwrap();
        let unchanged = plan(&request, Action::Install).unwrap();
        let policy = request.account_home.join(".managed-policy-fixture");
        std::fs::create_dir(&policy).unwrap();
        std::fs::write(
            policy.join("managed-mcp.json"),
            b"{\"mcpServers\":{\"xmsg\":{}}}",
        )
        .unwrap();
        let before = inventory(&request.account_home);
        assert_eq!(unchanged.apply().unwrap_err(), Error::Conflict);
        assert_eq!(inventory(&request.account_home), before);
    }
    #[test]
    fn native_file_modes_are_private_and_preserve_stricter_input() {
        use std::os::unix::fs::PermissionsExt;
        let (_root, request) = fixture();
        let mcp = request.account_home.join(".claude.json");
        std::fs::write(&mcp, b"{}").unwrap();
        std::fs::set_permissions(&mcp, std::fs::Permissions::from_mode(0o400)).unwrap();
        let planned = plan(&request, Action::Install).unwrap();
        let key = planned.ownership.set_id.clone();
        planned.apply().unwrap();
        assert_eq!(
            std::fs::metadata(&mcp).unwrap().permissions().mode() & 0o777,
            0o400,
            "installer widened a stricter input mode"
        );
        for file in [
            request.account_home.join(".claude/settings.json"),
            request.account_home.join(".claude/skills/xmsg/SKILL.md"),
            transaction::area(&request, &key).join("ownership.json"),
        ] {
            assert_eq!(
                std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600,
                "native private file creation did not preserve0600"
            );
        }
        plan(&request, Action::Uninstall).unwrap().apply().unwrap();
        assert_eq!(std::fs::read(&mcp).unwrap(), b"{}");
        assert_eq!(
            std::fs::metadata(mcp).unwrap().permissions().mode() & 0o777,
            0o400
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            std::mem::size_of::<libc::mode_t>(),
            std::mem::size_of::<libc::c_uint>()
        );
    }
}
