use crate::install_paths::{
    canonicalize_best_effort, check_legacy_components, resolve_install, resolve_optional_home,
    validate_private_dir, validate_socket_path, LegacyConflict, LegacyInventory, Platform,
    ResolveEnv, ResolveRequest, ResolvedInstall,
};
use crate::runtime_lock::{verify_runtime_dir_readonly, OwnerRecord};
use serde::Serialize;
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceOwner {
    HomebrewLaunchagent,
    SystemdUser,
    Foreground,
    Stopped,
    Unmanaged,
    Ambiguous,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagerEntry {
    pub kind: String,
    pub id: String,
    pub restarts: bool,
    pub targets_same_install: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallCheck {
    pub id: String,
    pub status: &'static str, // "info" | "pass" | "warn" | "fail"
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallDoctorReport {
    pub platform: Platform,
    pub target: String,
    pub executable_revision: &'static str,
    pub http_socket: Option<String>,
    pub agent_socket: Option<String>,
    pub register_socket: Option<String>,
    pub leaf_register_socket: Option<String>,
    pub endpoints_usable: bool,
    pub profile_state_root: Option<String>,
    pub profile_config_root: Option<String>,
    pub service_owner: ServiceOwner,
    pub competing_managers: Vec<ManagerEntry>,
    pub legacy_conflicts: Vec<LegacyConflict>,
    pub claude_adapter_status: &'static str,
    pub claude_coordinator_status: &'static str,
    pub checks: Vec<InstallCheck>,
}

#[derive(Debug, Clone, Default)]
pub struct ManagerScanRoots {
    pub launch_agents_dir: Option<PathBuf>,
    pub systemd_user_dir: Option<PathBuf>,
}

impl ManagerScanRoots {
    pub fn from_env(env: &ResolveEnv<'_>) -> Self {
        let Some(home) = resolve_optional_home(env) else {
            return Self::default();
        };
        let launch_agents_dir = if env.platform == Platform::MacOs {
            Some(home.join("Library/LaunchAgents"))
        } else {
            None
        };
        let systemd_user_dir = if env.platform == Platform::Linux {
            let cfg = env
                .xdg_config_home
                .as_deref()
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| home.join(".config"));
            Some(cfg.join("systemd/user"))
        } else {
            None
        };
        Self {
            launch_agents_dir,
            systemd_user_dir,
        }
    }
}

fn redact_path(path: &Path, account_home: Option<&Path>) -> String {
    if let Some(home) = account_home {
        if let Ok(rel) = path.strip_prefix(home) {
            return format!("~/{}", rel.display());
        }
    }
    path.display().to_string()
}

/// Strictly read-only installation check for `xmsg doctor`.
///
/// Guarantees:
/// - Never creates directories, files, sockets, or locks.
/// - Never attempts to acquire `serve.lock` or any endpoint lock (`M-S7b`).
/// - Exposes unredacted resolved endpoints (`http_socket`, `agent_socket`, `register_socket`,
///   `leaf_register_socket`) and sets `endpoints_usable = false` on any conflict/unsafe condition.
pub fn inspect_install(
    req: &ResolveRequest,
    env: &ResolveEnv<'_>,
    managers: &ManagerScanRoots,
) -> InstallDoctorReport {
    inspect_install_with_http_probe(req, env, managers, None)
}

pub fn inspect_install_with_http_probe(
    req: &ResolveRequest,
    env: &ResolveEnv<'_>,
    managers: &ManagerScanRoots,
    http_live_override: Option<bool>,
) -> InstallDoctorReport {
    let mut ro_req = req.clone();
    ro_req.writable = false;
    ro_req.enforce_legacy_guard = false;

    let account_home = resolve_optional_home(env);
    let target = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
    let executable_revision = option_env!("XMSG_BUILD_REVISION").unwrap_or("unknown");

    let mut checks = Vec::new();
    let adapter = std::env::current_exe()
        .ok()
        .and_then(|executable| {
            crate::install::Request::resolve(
                &ro_req,
                env,
                executable,
                std::env::var_os("CLAUDE_CONFIG_DIR").map(PathBuf::from),
            )
            .ok()
        })
        .map(|request| crate::install::observe(&request));
    let (claude_adapter_status, claude_coordinator_status) = adapter
        .as_ref()
        .map(|a| (a.adapter, a.coordinator))
        .unwrap_or(("unknown", "unknown"));
    if let Some(adapter) = &adapter {
        checks.push(InstallCheck{id:"install.claude_adapter".into(),status:if matches!(adapter.adapter,"unsafe"|"invalid"|"drift"|"conflict"|"policy_conflict"|"recovery_pending"){"warn"}else{"info"},message:format!("standalone Claude adapter {}; coordinator {}; writers {}; shadowing {}; loaded hooks {}",adapter.adapter,adapter.coordinator,adapter.writers,adapter.shadowing,adapter.loaded_hooks),hint:Some("Quiesce all Claude configuration writers before explicit adapter apply; loaded hooks and unobserved policy remain unverified.")});
    }

    let resolved = match resolve_install(&ro_req, env) {
        Ok(r) => r,
        Err(err) => {
            checks.push(InstallCheck {
                id: "install.resolve".into(),
                status: "fail",
                message: format!("installation resolution failed: {err}"),
                hint: Some("Check explicit flags, XDG_* roots, or authoritative account home."),
            });
            return InstallDoctorReport {
                platform: env.platform,
                target,
                executable_revision,
                http_socket: None,
                agent_socket: None,
                register_socket: None,
                leaf_register_socket: None,
                endpoints_usable: false,
                profile_state_root: None,
                profile_config_root: None,
                service_owner: ServiceOwner::Unknown,
                competing_managers: Vec::new(),
                legacy_conflicts: Vec::new(),
                claude_adapter_status,
                claude_coordinator_status,
                checks,
            };
        }
    };

    let mut usable = true;

    // Scan configured service managers read-only (never invokes mutating commands).
    let (detected_managers, inventory) = scan_service_managers(&resolved, managers);

    // Check legacy conflicts read-only (including prior service inventory when known).
    let legacy_conflicts = match check_legacy_components(&resolved, env, &inventory) {
        Ok(list) => list,
        Err(err) => {
            usable = false;
            checks.push(InstallCheck {
                id: "install.legacy_guard".into(),
                status: "fail",
                message: format!("inconclusive legacy state inspection: {err}"),
                hint: Some("Resolve ownership/symlink issues at legacy paths before starting."),
            });
            Vec::new()
        }
    };
    if !legacy_conflicts.is_empty() {
        usable = false;
        let summary = legacy_conflicts
            .iter()
            .map(|c| {
                format!(
                    "{} at {} (pin: {})",
                    c.component,
                    redact_path(&c.legacy_path, account_home.as_deref()),
                    c.compatible_pin
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        checks.push(InstallCheck {
            id: "install.legacy_guard".into(),
            status: "fail",
            message: format!("legacy default state would be bypassed: {summary}"),
            hint: Some("Pin compatible explicit flags/env or run a verified migration."),
        });
    } else {
        checks.push(InstallCheck {
            id: "install.legacy_guard".into(),
            status: "pass",
            message: "no bypassed legacy default state detected.".into(),
            hint: None,
        });
    }

    // Validate state root ownership/mode read-only (if present).
    if resolved.state_root.exists() {
        if let Err(err) = validate_private_dir(&resolved.state_root, env.euid) {
            usable = false;
            checks.push(InstallCheck {
                id: "install.state_root".into(),
                status: "fail",
                message: format!("state root ownership/permissions invalid: {err}"),
                hint: Some("Ensure the state root is owned by the service UID with mode 0700."),
            });
        } else {
            checks.push(InstallCheck {
                id: "install.state_root".into(),
                status: "pass",
                message: format!(
                    "state root {} is private and owned by UID {}.",
                    redact_path(&resolved.state_root, account_home.as_deref()),
                    env.euid
                ),
                hint: None,
            });
        }
    } else {
        checks.push(InstallCheck {
            id: "install.state_root".into(),
            status: "warn",
            message: format!(
                "state root {} does not exist yet (doctor does not create it).",
                redact_path(&resolved.state_root, account_home.as_deref())
            ),
            hint: None,
        });
    }

    // Validate managed runtime directory + identity.json read-only (if derived).
    if let (Some(ns_dir), Some(ns_id)) = (&resolved.runtime_namespace, &resolved.namespace_identity)
    {
        if ns_dir.exists() {
            if let Err(err) = verify_runtime_dir_readonly(ns_dir, ns_id, env.euid) {
                usable = false;
                checks.push(InstallCheck {
                    id: "install.runtime_namespace".into(),
                    status: "fail",
                    message: format!("managed runtime directory failed identity verification: {err}"),
                    hint: Some(
                        "Establish ownership offline before removing an unproven directory; doctor never repairs it.",
                    ),
                });
            } else {
                checks.push(InstallCheck {
                    id: "install.runtime_namespace".into(),
                    status: "pass",
                    message: "managed runtime directory and identity.json verified.".into(),
                    hint: None,
                });
            }
        }
    }

    // Validate socket byte budgets and live connect probe read-only.
    let mut any_live = false;
    for ep in resolved.enabled_endpoints() {
        if let Err(err) = validate_socket_path(&ep.path) {
            usable = false;
            checks.push(InstallCheck {
                id: format!("install.socket_budget.{}", ep.name),
                status: "fail",
                message: format!("socket path exceeds platform budget: {err}"),
                hint: Some("Use a shorter explicit socket path or standard runtime directory."),
            });
            continue;
        }
        if ep.name == "http" {
            if let Some(live) = http_live_override {
                if live {
                    any_live = true;
                }
                continue;
            }
        }
        if UnixStream::connect(&ep.path).is_ok() {
            any_live = true;
        }
    }

    // Read owner.json read-only (NEVER touch or flock serve.lock!).
    let owner_rec = OwnerRecord::load(&resolved.state_root).ok().flatten();

    // Classify service owner and detect competing managers (M-S7).
    let competing: Vec<ManagerEntry> = detected_managers
        .iter()
        .filter(|m| m.targets_same_install)
        .cloned()
        .collect();
    let service_owner = classify_service_owner(&resolved, owner_rec.as_ref(), any_live, &competing);

    if service_owner == ServiceOwner::Ambiguous {
        usable = false;
        let names = competing
            .iter()
            .map(|m| format!("{}({})", m.kind, m.id))
            .collect::<Vec<_>>()
            .join(", ");
        checks.push(InstallCheck {
            id: "install.service_owner".into(),
            status: "fail",
            message: format!(
                "competing service managers target the same xmsg installation: {names}"
            ),
            hint: Some("Stop and disable all but one service manager for this installation."),
        });
    } else {
        let status = match service_owner {
            ServiceOwner::HomebrewLaunchagent
            | ServiceOwner::SystemdUser
            | ServiceOwner::Foreground => "pass",
            ServiceOwner::Stopped => "warn",
            ServiceOwner::Unmanaged | ServiceOwner::Unknown => "info",
            ServiceOwner::Ambiguous => "fail",
        };
        checks.push(InstallCheck {
            id: "install.service_owner".into(),
            status,
            message: format!("service owner classified as {service_owner:?}."),
            hint: None,
        });
    }

    if account_home.is_none() {
        checks.push(InstallCheck {
            id: "install.home_observations".into(),
            status: "info",
            message:
                "account home unavailable: Claude adapter and coordinator observations are unknown."
                    .into(),
            hint: None,
        });
    }

    InstallDoctorReport {
        platform: env.platform,
        target,
        executable_revision,
        http_socket: resolved
            .http_sock
            .as_ref()
            .map(|e| e.path.to_string_lossy().into_owned()),
        agent_socket: resolved
            .agent_sock
            .as_ref()
            .map(|e| e.path.to_string_lossy().into_owned()),
        register_socket: resolved
            .register_sock
            .as_ref()
            .map(|e| e.path.to_string_lossy().into_owned()),
        leaf_register_socket: resolved
            .leaf_register_sock
            .as_ref()
            .map(|e| e.path.to_string_lossy().into_owned()),
        endpoints_usable: usable,
        profile_state_root: Some(redact_path(&resolved.state_root, account_home.as_deref())),
        profile_config_root: resolved
            .config_root
            .as_deref()
            .map(|p| redact_path(p, account_home.as_deref())),
        service_owner,
        competing_managers: competing,
        legacy_conflicts,
        claude_adapter_status,
        claude_coordinator_status,
        checks,
    }
}

fn classify_service_owner(
    resolved: &ResolvedInstall,
    owner_rec: Option<&OwnerRecord>,
    any_live: bool,
    competing: &[ManagerEntry],
) -> ServiceOwner {
    // Two or more distinct configured managers targeting the same state/sockets is ALWAYS a
    // conflict (ambiguous), even if one is stopped and configured to restart (M-S7).
    if competing.len() >= 2 {
        return ServiceOwner::Ambiguous;
    }

    if !any_live {
        return ServiceOwner::Stopped;
    }

    // Live socket answers: require trusted local owner.json + live PID + matching bound socket
    // inode to verify ownership (stale owner.json alone cannot identify a live owner).
    let Some(rec) = owner_rec else {
        return ServiceOwner::Unmanaged;
    };
    let pid_alive = rec.pid > 0 && unsafe { libc::kill(rec.pid as libc::pid_t, 0) == 0 };
    if !pid_alive {
        return ServiceOwner::Unknown;
    }

    // Verify at least one live resolved endpoint matches the recorded (dev, ino, uid).
    let mut inode_verified = false;
    for ep in resolved.enabled_endpoints() {
        if let Some(bound) = rec.endpoints.get(ep.name) {
            if let Ok(meta) = fs::symlink_metadata(&ep.path) {
                if meta.file_type().is_socket()
                    && meta.dev() == bound.dev
                    && meta.ino() == bound.ino
                    && meta.uid() == rec.uid
                {
                    inode_verified = true;
                    break;
                }
            }
        }
    }
    if !inode_verified {
        return ServiceOwner::Unknown;
    }

    match rec.manager_hint.as_deref() {
        Some("homebrew_launchagent") => ServiceOwner::HomebrewLaunchagent,
        Some("systemd_user") => ServiceOwner::SystemdUser,
        Some("foreground") => ServiceOwner::Foreground,
        _ => {
            if let Some(single) = competing.first() {
                match single.kind.as_str() {
                    "homebrew_launchagent" => ServiceOwner::HomebrewLaunchagent,
                    "systemd_user" => ServiceOwner::SystemdUser,
                    _ => ServiceOwner::Unknown,
                }
            } else {
                ServiceOwner::Unknown
            }
        }
    }
}

fn scan_service_managers(
    resolved: &ResolvedInstall,
    roots: &ManagerScanRoots,
) -> (Vec<ManagerEntry>, LegacyInventory) {
    let mut managers = Vec::new();
    let mut inventory = LegacyInventory::default();

    if let Some(dir) = &roots.launch_agents_dir {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("plist") {
                    continue;
                }
                let Ok(text) = fs::read_to_string(&path) else {
                    continue;
                };
                if !text.contains("xmsg") {
                    continue;
                }
                let id = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "launchagent".into());
                let kind = if id.contains("homebrew.mxcl.xmsg") {
                    "homebrew_launchagent"
                } else {
                    "launchagent"
                };
                let restarts = text.contains("KeepAlive") || text.contains("RunAtLoad");
                if let Some(h) = extract_plist_env_string(&text, "HOME") {
                    inventory.prior_homes.push(PathBuf::from(h));
                }
                if let Some(wd) = extract_plist_string_key(&text, "WorkingDirectory") {
                    inventory.prior_cwd = Some(PathBuf::from(wd));
                }
                managers.push(ManagerEntry {
                    kind: kind.into(),
                    id,
                    restarts,
                    targets_same_install: plist_command(&text).is_some_and(|(argv, db)| {
                        command_targets_install(&argv, db.as_deref(), resolved)
                    }),
                });
            }
        }
    }

    if let Some(dir) = &roots.systemd_user_dir {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("service") {
                    continue;
                }
                let Ok(text) = fs::read_to_string(&path) else {
                    continue;
                };
                if !text.contains("xmsg") {
                    continue;
                }
                let id = path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "systemd".into());
                let restarts = text.contains("Restart=always")
                    || text.contains("Restart=on-failure")
                    || text.contains("WantedBy=");
                for line in text.lines() {
                    let trimmed = line.trim();
                    if let Some(rest) = trimmed.strip_prefix("WorkingDirectory=") {
                        inventory.prior_cwd = Some(PathBuf::from(rest.trim()));
                    }
                    if let Some(rest) = trimmed.strip_prefix("Environment=") {
                        for tok in rest.split_whitespace() {
                            let tok = tok.trim_matches('"');
                            if let Some(h) = tok.strip_prefix("HOME=") {
                                inventory.prior_homes.push(PathBuf::from(h));
                            }
                        }
                    }
                }
                managers.push(ManagerEntry {
                    kind: "systemd_user".into(),
                    id,
                    restarts,
                    targets_same_install: systemd_commands(&text).is_some_and(|(commands, db)| {
                        commands
                            .iter()
                            .any(|argv| command_targets_install(argv, db.as_deref(), resolved))
                    }),
                });
            }
        }
    }

    managers.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.id.cmp(&b.id)));
    (managers, inventory)
}

fn command_targets_install(
    argv: &[String],
    env_db: Option<&str>,
    resolved: &ResolvedInstall,
) -> bool {
    // The CLI has no global value-taking options: an option value is never a subcommand.
    if argv
        .first()
        .is_none_or(|exe| Path::new(exe).file_name().is_none_or(|n| n != "xmsg"))
        || argv.get(1).is_none_or(|arg| arg != "serve")
    {
        return false;
    }
    let value = |name: &str| -> Result<Option<&str>, ()> {
        let mut found = None;
        let mut args = argv[2..].iter();
        while let Some(arg) = args.next() {
            let selected = if arg == name {
                Some(args.next().ok_or(())?.as_str())
            } else {
                arg.strip_prefix(&format!("{name}="))
            };
            if let Some(raw) = selected {
                if found.is_some() || raw.is_empty() || raw.starts_with('-') {
                    return Err(());
                }
                found = Some(raw);
            }
        }
        Ok(found)
    };
    let Ok(db) = value("--db-path") else {
        return false;
    };
    if let Some(raw) = db.or(env_db) {
        let candidate = Path::new(raw);
        return candidate.is_absolute()
            && matches!((canonicalize_best_effort(candidate), canonicalize_best_effort(&resolved.db_path)),
                (Ok(a), Ok(b)) if a == b);
    }
    // Socket pins do not move the default database to another installation.
    true
}

// Parse literal service argv, without interpreting shells, substitutions or specifiers.
fn service_words(input: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut started = false;
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        match c {
            '$' | '%' => return None,
            '\\' => {
                let next = chars.next()?;
                word.push(match next {
                    's' => ' ',
                    'n' => '\n',
                    't' => '\t',
                    '\\' | '\'' | '"' | ' ' => next,
                    _ => return None,
                });
                started = true;
            }
            '\'' | '"' if quote.is_none() => {
                quote = Some(c);
                started = true;
            }
            '\'' | '"' if quote == Some(c) => quote = None,
            c if c.is_whitespace() && quote.is_none() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            c => {
                word.push(c);
                started = true;
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    if started {
        words.push(word);
    }
    Some(words)
}

fn systemd_commands(text: &str) -> Option<(Vec<Vec<String>>, Option<String>)> {
    let logical = text.replace("\\\n", " ");
    let mut service = false;
    let mut commands = Vec::new();
    let mut db = None;
    for line in logical.lines().map(str::trim) {
        if line.starts_with('[') {
            service = line == "[Service]";
            continue;
        }
        if !service || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(value) = line.strip_prefix("ExecStart=") {
            if value.trim().is_empty() {
                commands.clear();
            } else {
                commands.push(service_words(value)?);
            }
        }
        if let Some(value) = line.strip_prefix("Environment=") {
            if value.trim().is_empty() {
                db = None;
            }
            for word in service_words(value)? {
                if let Some(value) = word.strip_prefix("XMSG_DB_PATH=") {
                    db = Some(value.into());
                }
            }
        }
    }
    Some((commands, db))
}

fn xml_string(input: &str) -> Option<String> {
    let mut result = String::new();
    let mut rest = input;
    while let Some(i) = rest.find('&') {
        result.push_str(&rest[..i]);
        let end = rest[i..].find(';')? + i;
        let entity = &rest[i + 1..end];
        result.push(match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => char::from_u32(if let Some(hex) = entity.strip_prefix("#x") {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                entity.strip_prefix('#')?.parse().ok()?
            })?,
        });
        rest = &rest[end + 1..];
    }
    result.push_str(rest);
    Some(result)
}

fn plist_command(text: &str) -> Option<(Vec<String>, Option<String>)> {
    let start = text.find("<key>ProgramArguments</key>")? + "<key>ProgramArguments</key>".len();
    let mut array = text[start..].trim_start().strip_prefix("<array>")?;
    let mut argv = Vec::new();
    loop {
        array = array.trim_start();
        if array.starts_with("</array>") {
            break;
        }
        array = array.strip_prefix("<string>")?;
        let end = array.find("</string>")?;
        argv.push(xml_string(&array[..end])?);
        array = &array[end + "</string>".len()..];
    }
    if let Some(program) = extract_plist_string_key(text, "Program") {
        *argv.first_mut()? = xml_string(&program)?;
    }
    let db = extract_plist_env_string(text, "XMSG_DB_PATH").and_then(|s| xml_string(&s));
    Some((argv, db))
}

fn extract_plist_string_key(xml: &str, key: &str) -> Option<String> {
    let needle = format!("<key>{key}</key>");
    let pos = xml.find(&needle)?;
    let rest = &xml[pos + needle.len()..];
    let s_start = rest.find("<string>")? + "<string>".len();
    let s_end = rest[s_start..].find("</string>")?;
    Some(rest[s_start..s_start + s_end].trim().to_string())
}

fn extract_plist_env_string(xml: &str, env_key: &str) -> Option<String> {
    let env_pos = xml.find("<key>EnvironmentVariables</key>")?;
    extract_plist_string_key(&xml[env_pos..], env_key)
}
