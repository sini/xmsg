//! Declared harness descriptors for plugin registration (`--harnesses-file`).
//!
//! Optional: when `--harnesses-file` is not configured, [`HarnessRegistry::disabled`] accepts no
//! dynamic plugin harnesses and `xmsg` remains a pure message transport bus.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};
use std::time::{Duration, Instant};

use regex::Regex;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use tokio::sync::watch;

use crate::http::AppState;

/// Built-in harness names that cannot be shadowed or overridden by `--harnesses-file`.
pub const BUILTIN_HARNESSES: &[&str] =
    &["claude", "codex", "agy", "pi", "opencode", "hermes", "svc"];

/// Default drain window for ordinary descriptor edits and removals (10 minutes).
pub const DEFAULT_DRAIN_WINDOW_SECS: u64 = 600;
/// Maximum configurable drain window (24 hours).
pub const MAX_DRAIN_WINDOW_SECS: u64 = 86_400;
/// Default `id_pattern` when a descriptor omits it.
pub const DEFAULT_ID_PATTERN: &str = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$";
const MAX_HARNESSES: usize = 128;
const MAX_ARGV_TOKENS: usize = 32;
const MAX_ENV_HINTS: usize = 32;
const MAX_REGEX_BYTES: usize = 1024;
const MAX_REGEX_COMPILED_SIZE: usize = 64 * 1024;

/// Returns whether `name` is valid on the wire (`[a-z0-9][a-z0-9_-]{0,31}`).
pub fn valid_wire_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=32).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

/// Returns whether `name` is a built-in harness or `"unknown"`.
pub fn is_reserved_name(name: &str) -> bool {
    name == "unknown" || BUILTIN_HARNESSES.contains(&name)
}

/// Returns whether `name` is a valid declared harness name (valid grammar and not reserved).
pub fn valid_declared_name(name: &str) -> bool {
    valid_wire_name(name) && !is_reserved_name(name)
}

/// Validates descriptor file metadata: regular file, owned by current UID or root (so NixOS
/// `/nix/store` 0444 files owned by root work), and not group- or world-writable.
pub fn validate_file_meta(
    is_file: bool,
    uid: u32,
    mode: u32,
    current_uid: u32,
) -> Result<(), String> {
    if !is_file {
        return Err("harnesses file must be a regular file".into());
    }
    if uid != current_uid && uid != 0 {
        return Err(format!(
            "harnesses file owned by uid {uid}, expected current uid {current_uid} or root (0)"
        ));
    }
    if mode & 0o022 != 0 {
        return Err(format!(
            "harnesses file mode {:04o} must not be group- or world-writable",
            mode & 0o7777
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn check_file_ownership(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("cannot stat harnesses file '{}': {e}", path.display()))?;
    let current_uid = unsafe { libc::geteuid() };
    validate_file_meta(meta.is_file(), meta.uid(), meta.mode(), current_uid)
}

#[cfg(not(unix))]
fn check_file_ownership(path: &Path) -> Result<(), String> {
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("cannot stat harnesses file '{}': {e}", path.display()))?;
    if !meta.is_file() {
        return Err("harnesses file must be a regular file".into());
    }
    Ok(())
}

/// Delivery mode for declared harnesses. V1 supports `"poll"` only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    Poll,
}

impl<'de> Deserialize<'de> for DeliveryMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        match raw.as_str() {
            "poll" => Ok(DeliveryMode::Poll),
            other => Err(de::Error::custom(format!(
                "unsupported delivery_mode '{other}': v1 declared harnesses only support \"poll\""
            ))),
        }
    }
}

/// One typed element of a local `resume_argv` recipe. Never a shell template string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgvToken {
    Literal(String),
    Id,
}

impl<'de> Deserialize<'de> for ArgvToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TokenVisitor;
        impl<'de> Visitor<'de> for TokenVisitor {
            type Value = ArgvToken;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a literal argv string or { \"var\": \"id\" }")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                if v.is_empty() {
                    return Err(E::custom("resume_argv literal must not be empty"));
                }
                if v.chars().any(char::is_control) {
                    return Err(E::custom(
                        "resume_argv literal must not contain control characters",
                    ));
                }
                Ok(ArgvToken::Literal(v.to_string()))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut var: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key != "var" {
                        return Err(de::Error::unknown_field(&key, &["var"]));
                    }
                    if var.is_some() {
                        return Err(de::Error::duplicate_field("var"));
                    }
                    var = Some(map.next_value()?);
                }
                match var.as_deref() {
                    Some("id") => Ok(ArgvToken::Id),
                    Some(other) => Err(de::Error::custom(format!(
                        "unsupported resume_argv variable '{other}': only \"id\" is allowed"
                    ))),
                    None => Err(de::Error::missing_field("var")),
                }
            }
        }
        deserializer.deserialize_any(TokenVisitor)
    }
}

/// Default-deny capability flags for a declared harness. Capabilities gate harness features only
/// and never grant authorization.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    #[serde(default)]
    pub attachments: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHarnessesFile {
    #[serde(default)]
    drain_window_secs: Option<u64>,
    #[serde(default)]
    revoked_harnesses: Vec<String>,
    #[serde(default)]
    harnesses: BTreeMap<String, RawDescriptor>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDescriptor {
    delivery_mode: DeliveryMode,
    #[serde(default)]
    resume_argv: Option<Vec<ArgvToken>>,
    #[serde(default)]
    id_pattern: Option<String>,
    #[serde(default)]
    env_hint_sources: Option<Vec<String>>,
    #[serde(default)]
    capabilities: Capabilities,
    #[serde(default)]
    revoked: bool,
}

/// Validated descriptor for one declared plugin harness.
#[derive(Debug, Clone)]
pub struct HarnessDescriptor {
    pub name: String,
    pub delivery_mode: DeliveryMode,
    pub resume_argv: Option<Vec<ArgvToken>>,
    pub id_pattern_src: String,
    id_regex: Regex,
    pub env_hint_sources: Option<Vec<String>>,
    pub capabilities: Capabilities,
}

impl PartialEq for HarnessDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.delivery_mode == other.delivery_mode
            && self.resume_argv == other.resume_argv
            && self.id_pattern_src == other.id_pattern_src
            && self.env_hint_sources == other.env_hint_sources
            && self.capabilities == other.capabilities
    }
}

impl Eq for HarnessDescriptor {}

impl HarnessDescriptor {
    /// Validates a native/resume identifier against leading-`-` refusal, length/control bounds,
    /// and the descriptor's compiled `id_pattern`.
    pub fn validate_id(&self, id: &str) -> bool {
        if id.is_empty()
            || id.len() > 256
            || id.starts_with('-')
            || id.chars().any(char::is_control)
        {
            return false;
        }
        self.id_regex.is_match(id)
    }

    /// Renders the typed `resume_argv` recipe for a validated native ID as inert display tokens.
    /// Returns `None` if no `resume_argv` is declared or `id` fails validation.
    pub fn render_resume(&self, id: &str) -> Option<Vec<String>> {
        let tokens = self.resume_argv.as_ref()?;
        if !self.validate_id(id) {
            return None;
        }
        Some(
            tokens
                .iter()
                .map(|t| match t {
                    ArgvToken::Literal(s) => s.clone(),
                    ArgvToken::Id => id.to_string(),
                })
                .collect(),
        )
    }

    /// Checks whether a reported locator environment is permitted by `env_hint_sources`.
    pub fn allows_env(&self, kind: &crate::locator::EnvironmentKind) -> bool {
        let Some(allowed) = &self.env_hint_sources else {
            return true;
        };
        let key = match kind {
            crate::locator::EnvironmentKind::Zellij => "ZELLIJ_SESSION_NAME",
            crate::locator::EnvironmentKind::Tmux => "TMUX_PANE",
            crate::locator::EnvironmentKind::Herdr => "HERDR_PANE_ID",
            crate::locator::EnvironmentKind::None => return true,
        };
        allowed.iter().any(|entry| entry == key)
    }
}

fn valid_env_var_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=64).contains(&bytes.len())
        && (bytes[0].is_ascii_uppercase() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

struct ParsedSnapshot {
    drain_window: Duration,
    harnesses: BTreeMap<String, Arc<HarnessDescriptor>>,
    config_revoked: HashSet<String>,
}

fn parse_harnesses_json(raw_json: &str) -> Result<ParsedSnapshot, String> {
    let raw: RawHarnessesFile =
        serde_json::from_str(raw_json).map_err(|e| format!("invalid harnesses config: {e}"))?;
    let drain_secs = raw.drain_window_secs.unwrap_or(DEFAULT_DRAIN_WINDOW_SECS);
    if drain_secs > MAX_DRAIN_WINDOW_SECS {
        return Err(format!(
            "drain_window_secs {drain_secs} exceeds maximum {MAX_DRAIN_WINDOW_SECS}"
        ));
    }
    if raw.harnesses.len() > MAX_HARNESSES {
        return Err(format!(
            "too many declared harnesses ({} > {MAX_HARNESSES})",
            raw.harnesses.len()
        ));
    }

    let mut config_revoked = HashSet::new();
    for name in raw.revoked_harnesses {
        if !valid_declared_name(&name) {
            return Err(format!(
                "invalid revoked_harnesses entry '{name}': must match [a-z0-9][a-z0-9_-]{{0,31}} and must not shadow a built-in or 'unknown'"
            ));
        }
        config_revoked.insert(name);
    }

    let mut harnesses = BTreeMap::new();
    for (name, desc) in raw.harnesses {
        if is_reserved_name(&name) {
            return Err(format!(
                "declared harness '{name}' cannot shadow a built-in harness or 'unknown'"
            ));
        }
        if !valid_wire_name(&name) {
            return Err(format!(
                "invalid harness name '{name}': must match [a-z0-9][a-z0-9_-]{{0,31}}"
            ));
        }
        if let Some(ref argv) = desc.resume_argv {
            if argv.is_empty() || argv.len() > MAX_ARGV_TOKENS {
                return Err(format!(
                    "harness '{name}': resume_argv must contain 1..={MAX_ARGV_TOKENS} elements"
                ));
            }
            match &argv[0] {
                ArgvToken::Literal(prog) if !prog.starts_with('-') && !prog.trim().is_empty() => {}
                ArgvToken::Literal(prog) => {
                    return Err(format!(
                        "harness '{name}': resume_argv program '{prog}' must not start with '-' or be whitespace"
                    ));
                }
                ArgvToken::Id => {
                    return Err(format!(
                        "harness '{name}': resume_argv[0] must be a literal program name, not {{ \"var\": \"id\" }}"
                    ));
                }
            }
        }
        let id_pattern_src = desc
            .id_pattern
            .unwrap_or_else(|| DEFAULT_ID_PATTERN.to_string());
        if id_pattern_src.len() > MAX_REGEX_BYTES {
            return Err(format!(
                "harness '{name}': id_pattern exceeds {MAX_REGEX_BYTES} bytes"
            ));
        }
        let id_regex = regex::RegexBuilder::new(&id_pattern_src)
            .size_limit(MAX_REGEX_COMPILED_SIZE)
            .build()
            .map_err(|e| format!("harness '{name}': invalid id_pattern regex: {e}"))?;
        if let Some(ref hints) = desc.env_hint_sources {
            if hints.len() > MAX_ENV_HINTS {
                return Err(format!(
                    "harness '{name}': env_hint_sources exceeds {MAX_ENV_HINTS} entries"
                ));
            }
            for env_name in hints {
                if !valid_env_var_name(env_name) {
                    return Err(format!(
                        "harness '{name}': invalid env_hint_sources entry '{env_name}'"
                    ));
                }
            }
        }
        if desc.revoked {
            config_revoked.insert(name.clone());
        }
        harnesses.insert(
            name.clone(),
            Arc::new(HarnessDescriptor {
                name,
                delivery_mode: desc.delivery_mode,
                resume_argv: desc.resume_argv,
                id_pattern_src,
                id_regex,
                env_hint_sources: desc.env_hint_sources,
                capabilities: desc.capabilities,
            }),
        );
    }

    Ok(ParsedSnapshot {
        drain_window: Duration::from_secs(drain_secs),
        harnesses,
        config_revoked,
    })
}

/// Pinned harness identity held by a live `register.sock` plugin connection.
#[derive(Debug, Clone)]
pub enum PinnedHarness {
    Builtin(&'static str),
    Declared {
        name: String,
        generation: u64,
        descriptor: Arc<HarnessDescriptor>,
    },
}

impl PinnedHarness {
    pub fn name(&self) -> &str {
        match self {
            PinnedHarness::Builtin(name) => name,
            PinnedHarness::Declared { name, .. } => name.as_str(),
        }
    }

    pub fn is_builtin(&self) -> bool {
        matches!(self, PinnedHarness::Builtin(_))
    }

    pub fn attachments_allowed(&self) -> bool {
        match self {
            PinnedHarness::Builtin(_) => true,
            PinnedHarness::Declared { descriptor, .. } => descriptor.capabilities.attachments,
        }
    }

    pub fn descriptor(&self) -> Option<&HarnessDescriptor> {
        match self {
            PinnedHarness::Builtin(_) => None,
            PinnedHarness::Declared { descriptor, .. } => Some(descriptor.as_ref()),
        }
    }
}

/// Live lifecycle status of a pinned connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Active,
    Draining(Instant),
    DrainExpired,
    Revoked,
}

/// Result of attempting to open a new `register.sock` plugin connection for `name`.
#[derive(Debug, Clone)]
pub enum ConnectDecision {
    Accepted(PinnedHarness),
    Revoked,
    Undeclared,
}

struct RegistryInner {
    path: Option<PathBuf>,
    drain_window: Duration,
    /// Active (non-revoked) descriptors by harness name, paired with their per-harness generation.
    active: BTreeMap<String, (u64, Arc<HarnessDescriptor>)>,
    /// Next generation number to assign per harness name (monotonic across removals/re-adds).
    next_gen: HashMap<String, u64>,
    /// Drain deadlines for superseded `(harness_name, generation)` pairs.
    drain_deadlines: HashMap<(String, u64), Instant>,
    /// Harnesses explicitly revoked in the current config snapshot.
    config_revoked: HashSet<String>,
    /// Harnesses explicitly revoked via CLI/admin endpoint (sticky until daemon restart).
    cli_revoked: HashSet<String>,
    version: u64,
}

/// Atomic, reloadable registry of declared plugin harnesses for one `xmsg` daemon instance.
pub struct HarnessRegistry {
    inner: RwLock<RegistryInner>,
    events_tx: watch::Sender<u64>,
}

impl HarnessRegistry {
    /// Disabled registry (used when `--harnesses-file` is omitted): accepts no dynamic harnesses.
    pub fn disabled() -> Arc<Self> {
        let (events_tx, _) = watch::channel(0);
        Arc::new(Self {
            inner: RwLock::new(RegistryInner {
                path: None,
                drain_window: Duration::from_secs(DEFAULT_DRAIN_WINDOW_SECS),
                active: BTreeMap::new(),
                next_gen: HashMap::new(),
                drain_deadlines: HashMap::new(),
                config_revoked: HashSet::new(),
                cli_revoked: HashSet::new(),
                version: 0,
            }),
            events_tx,
        })
    }

    /// Loads and validates a `--harnesses-file` from disk, enforcing ownership and mode checks.
    pub fn load_file(path: impl Into<PathBuf>) -> Result<Arc<Self>, String> {
        let path = path.into();
        check_file_ownership(&path)?;
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("failed to read harnesses file '{}': {e}", path.display()))?;
        let parsed = parse_harnesses_json(&content)?;
        let mut active = BTreeMap::new();
        let mut next_gen = HashMap::new();
        for (name, desc) in parsed.harnesses {
            if !parsed.config_revoked.contains(&name) {
                active.insert(name.clone(), (1, desc));
                next_gen.insert(name, 2);
            } else {
                next_gen.insert(name, 2);
            }
        }
        let (events_tx, _) = watch::channel(1);
        Ok(Arc::new(Self {
            inner: RwLock::new(RegistryInner {
                path: Some(path),
                drain_window: parsed.drain_window,
                active,
                next_gen,
                drain_deadlines: HashMap::new(),
                config_revoked: parsed.config_revoked,
                cli_revoked: HashSet::new(),
                version: 1,
            }),
            events_tx,
        }))
    }

    /// Loads from a JSON string directly (intended for tests without disk files).
    pub fn from_json(raw_json: &str) -> Result<Arc<Self>, String> {
        let parsed = parse_harnesses_json(raw_json)?;
        let mut active = BTreeMap::new();
        let mut next_gen = HashMap::new();
        for (name, desc) in parsed.harnesses {
            if !parsed.config_revoked.contains(&name) {
                active.insert(name.clone(), (1, desc));
                next_gen.insert(name, 2);
            } else {
                next_gen.insert(name, 2);
            }
        }
        let (events_tx, _) = watch::channel(1);
        Ok(Arc::new(Self {
            inner: RwLock::new(RegistryInner {
                path: None,
                drain_window: parsed.drain_window,
                active,
                next_gen,
                drain_deadlines: HashMap::new(),
                config_revoked: parsed.config_revoked,
                cli_revoked: HashSet::new(),
                version: 1,
            }),
            events_tx,
        }))
    }

    /// Whether `--harnesses-file` was configured on this registry.
    pub fn is_configured(&self) -> bool {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .path
            .is_some()
    }

    /// Configured drain window.
    pub fn drain_window(&self) -> Duration {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .drain_window
    }

    /// Subscribe to reload/revocation version changes.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.events_tx.subscribe()
    }

    /// Atomically reloads the configured `--harnesses-file`. On parse/validation error, the
    /// previous valid snapshot is retained unchanged.
    pub fn reload(&self) -> Result<(), String> {
        let path = {
            let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
            guard.path.clone()
        };
        let Some(path) = path else {
            return Ok(());
        };
        check_file_ownership(&path)?;
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("failed to read harnesses file '{}': {e}", path.display()))?;
        self.apply_json_at(&content, Instant::now())
    }

    /// Atomically replaces the snapshot from JSON at timestamp `now`.
    pub fn apply_json_at(&self, raw_json: &str, now: Instant) -> Result<(), String> {
        let parsed = parse_harnesses_json(raw_json)?;
        let new_version = {
            let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
            let drain_window = parsed.drain_window;
            guard.drain_window = drain_window;
            guard.config_revoked = parsed.config_revoked;

            let old_active = std::mem::take(&mut guard.active);
            let mut new_active = BTreeMap::new();

            // Check existing harnesses for edits, removals, or revocations.
            for (name, (old_gen, old_desc)) in old_active {
                let is_revoked =
                    guard.config_revoked.contains(&name) || guard.cli_revoked.contains(&name);
                if is_revoked {
                    guard.drain_deadlines.remove(&(name, old_gen));
                    continue;
                }
                match parsed.harnesses.get(&name) {
                    Some(new_desc) if *new_desc == old_desc => {
                        // Unchanged descriptor: preserve generation, no drain.
                        new_active.insert(name, (old_gen, old_desc));
                    }
                    Some(new_desc) => {
                        // Ordinary edit: old generation drains; new registrations use new gen immediately.
                        guard
                            .drain_deadlines
                            .entry((name.clone(), old_gen))
                            .or_insert(now + drain_window);
                        let gen = *guard.next_gen.get(&name).unwrap_or(&(old_gen + 1));
                        guard.next_gen.insert(name.clone(), gen + 1);
                        new_active.insert(name, (gen, new_desc.clone()));
                    }
                    None => {
                        // Ordinary removal: old generation drains; new registrations are refused.
                        guard
                            .drain_deadlines
                            .entry((name.clone(), old_gen))
                            .or_insert(now + drain_window);
                    }
                }
            }

            // Insert newly added (non-revoked) harnesses.
            for (name, desc) in parsed.harnesses {
                if new_active.contains_key(&name)
                    || guard.config_revoked.contains(&name)
                    || guard.cli_revoked.contains(&name)
                {
                    continue;
                }
                let gen = *guard.next_gen.get(&name).unwrap_or(&1);
                guard.next_gen.insert(name.clone(), gen + 1);
                new_active.insert(name, (gen, desc));
            }

            guard.active = new_active;
            guard.drain_deadlines.retain(|_, deadline| *deadline > now);
            guard.version += 1;
            guard.version
        };
        let _ = self.events_tx.send(new_version);
        Ok(())
    }

    /// Explicit security revocation (e.g. via CLI `xmsg harness revoke <name>`): immediately
    /// blocks active operations and new connections for `name` with zero drain delay.
    pub fn security_revoke(&self, name: &str) -> Result<(), String> {
        if !valid_declared_name(name) {
            return Err(format!(
                "invalid declared harness '{name}': cannot revoke built-in or malformed harness"
            ));
        }
        let new_version = {
            let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
            guard.cli_revoked.insert(name.to_string());
            guard.active.remove(name);
            guard.drain_deadlines.retain(|(h, _), _| h != name);
            guard.version += 1;
            guard.version
        };
        let _ = self.events_tx.send(new_version);
        Ok(())
    }

    /// Evaluates whether a new `register.sock` connection claiming `name` may connect.
    pub fn connect_decision(&self, name: &str) -> ConnectDecision {
        if let Some(builtin) = crate::plugin::harness(name) {
            return ConnectDecision::Accepted(PinnedHarness::Builtin(builtin));
        }
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        if guard.config_revoked.contains(name) || guard.cli_revoked.contains(name) {
            return ConnectDecision::Revoked;
        }
        if let Some((generation, descriptor)) = guard.active.get(name) {
            return ConnectDecision::Accepted(PinnedHarness::Declared {
                name: name.to_string(),
                generation: *generation,
                descriptor: descriptor.clone(),
            });
        }
        ConnectDecision::Undeclared
    }

    /// Returns whether `name` is currently an active (non-revoked) declared harness.
    pub fn is_declared(&self, name: &str) -> bool {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard.active.contains_key(name)
    }

    /// Returns the active descriptor for `name`, if declared and not revoked.
    pub fn get(&self, name: &str) -> Option<Arc<HarnessDescriptor>> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard.active.get(name).map(|(_, d)| d.clone())
    }

    /// Evaluates the current lifecycle state of an existing pinned connection.
    pub fn connection_state(&self, pinned: &PinnedHarness, now: Instant) -> ConnectionState {
        let PinnedHarness::Declared {
            name, generation, ..
        } = pinned
        else {
            return ConnectionState::Active;
        };
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        if guard.config_revoked.contains(name) || guard.cli_revoked.contains(name) {
            return ConnectionState::Revoked;
        }
        if let Some(&deadline) = guard.drain_deadlines.get(&(name.clone(), *generation)) {
            if now >= deadline {
                return ConnectionState::DrainExpired;
            }
            return ConnectionState::Draining(deadline);
        }
        if let Some((cur_gen, _)) = guard.active.get(name) {
            if cur_gen == generation {
                return ConnectionState::Active;
            }
        }
        // Fallback if generation was pruned after its drain deadline elapsed.
        ConnectionState::DrainExpired
    }
}

struct RegistrySlot {
    weak_db: Weak<Mutex<rusqlite::Connection>>,
    registry: Arc<HarnessRegistry>,
}

fn db_registry() -> &'static Mutex<HashMap<usize, RegistrySlot>> {
    static MAP: OnceLock<Mutex<HashMap<usize, RegistrySlot>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Attaches a [`HarnessRegistry`] to `db`, pruning dropped database entries.
pub fn init_for_db(
    db: &Arc<Mutex<rusqlite::Connection>>,
    registry: Arc<HarnessRegistry>,
) -> Arc<HarnessRegistry> {
    let key = Arc::as_ptr(db) as usize;
    let mut map = db_registry().lock().unwrap_or_else(|e| e.into_inner());
    map.retain(|_, slot| slot.weak_db.strong_count() > 0);
    map.insert(
        key,
        RegistrySlot {
            weak_db: Arc::downgrade(db),
            registry: registry.clone(),
        },
    );
    registry
}

/// Attaches a [`HarnessRegistry`] to `state.db`.
pub fn init_for_state(state: &AppState, registry: Arc<HarnessRegistry>) -> Arc<HarnessRegistry> {
    init_for_db(&state.db, registry)
}

/// Returns the [`HarnessRegistry`] attached to `db`, or a disabled registry if none was configured.
pub fn for_db(db: &Arc<Mutex<rusqlite::Connection>>) -> Arc<HarnessRegistry> {
    let key = Arc::as_ptr(db) as usize;
    let weak = Arc::downgrade(db);
    let map = db_registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(slot) = map.get(&key) {
        if Weak::ptr_eq(&slot.weak_db, &weak) {
            return slot.registry.clone();
        }
    }
    HarnessRegistry::disabled()
}

/// Returns the [`HarnessRegistry`] attached to `state.db`.
pub fn for_state(state: &AppState) -> Arc<HarnessRegistry> {
    for_db(&state.db)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_owned_0444_nix_store_file_is_accepted_and_writable_or_other_uid_refused() {
        // Root-owned 0444 (NixOS /nix/store) accepted for any current UID.
        assert!(validate_file_meta(true, 0, 0o100444, 1000).is_ok());
        // Owner-owned 0600 and 0644 accepted.
        assert!(validate_file_meta(true, 1000, 0o100600, 1000).is_ok());
        assert!(validate_file_meta(true, 1000, 0o100644, 1000).is_ok());
        // Group-writable or world-writable refused even if owned by root or current UID.
        assert!(validate_file_meta(true, 0, 0o100664, 1000).is_err());
        assert!(validate_file_meta(true, 1000, 0o100602, 1000).is_err());
        // Owned by another non-root UID refused.
        assert!(validate_file_meta(true, 2000, 0o100444, 1000).is_err());
        // Non-regular file refused.
        assert!(validate_file_meta(false, 0, 0o040555, 1000).is_err());
    }

    #[test]
    fn schema_validates_poll_only_non_shadowing_and_typed_argv() {
        let valid = r#"{
            "harnesses": {
                "cursor": {
                    "delivery_mode": "poll",
                    "resume_argv": ["cursor", "--resume", { "var": "id" }],
                    "id_pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
                    "env_hint_sources": ["ZELLIJ_SESSION_NAME", "TMUX_PANE", "HERDR_PANE_ID"]
                }
            }
        }"#;
        let reg = HarnessRegistry::from_json(valid).unwrap();
        assert_eq!(reg.drain_window(), Duration::from_secs(600));
        let desc = reg.get("cursor").unwrap();
        assert!(!desc.capabilities.attachments, "attachments default-deny");
        assert_eq!(
            desc.render_resume("ses_42"),
            Some(vec!["cursor".into(), "--resume".into(), "ses_42".into()])
        );
        assert_eq!(desc.render_resume("--exec=sh"), None);
        assert_eq!(desc.render_resume("-x"), None);

        // Non-poll delivery modes refused in v1.
        for bad_mode in ["push", "pull", "reclaim", "continues"] {
            let raw = format!(r#"{{"harnesses":{{"cursor":{{"delivery_mode":"{bad_mode}"}}}}}}"#);
            assert!(
                HarnessRegistry::from_json(&raw).is_err(),
                "mode {bad_mode} should fail"
            );
        }

        // Shadowing any built-in or "unknown" refused.
        for reserved in [
            "claude", "codex", "agy", "pi", "opencode", "hermes", "svc", "unknown",
        ] {
            let raw = format!(r#"{{"harnesses":{{"{reserved}":{{"delivery_mode":"poll"}}}}}}"#);
            assert!(
                HarnessRegistry::from_json(&raw).is_err(),
                "reserved name {reserved} should fail"
            );
        }

        // Raw shell string template for resume_argv refused.
        let shell_str = r#"{"harnesses":{"cursor":{"delivery_mode":"poll","resume_argv":"cursor --resume $id"}}}"#;
        assert!(HarnessRegistry::from_json(shell_str).is_err());

        // Unknown variable or variable as argv[0] refused.
        let bad_var = r#"{"harnesses":{"cursor":{"delivery_mode":"poll","resume_argv":["cursor",{"var":"cmd"}]}}}"#;
        assert!(HarnessRegistry::from_json(bad_var).is_err());
        let var_prog =
            r#"{"harnesses":{"cursor":{"delivery_mode":"poll","resume_argv":[{"var":"id"}]}}}"#;
        assert!(HarnessRegistry::from_json(var_prog).is_err());
    }

    #[test]
    fn drain_on_edit_or_removal_and_immediate_block_on_security_revocation() {
        let initial = r#"{
            "drain_window_secs": 10,
            "harnesses": {
                "cursor": { "delivery_mode": "poll", "capabilities": { "attachments": false } }
            }
        }"#;
        let reg = HarnessRegistry::from_json(initial).unwrap();
        let t0 = Instant::now();
        let ConnectDecision::Accepted(pinned_v1) = reg.connect_decision("cursor") else {
            panic!("cursor should be accepted");
        };
        assert_eq!(
            reg.connection_state(&pinned_v1, t0),
            ConnectionState::Active
        );

        // Ordinary edit: v1 drains for 10s, new connection gets v2 immediately.
        let edited = r#"{
            "drain_window_secs": 10,
            "harnesses": {
                "cursor": { "delivery_mode": "poll", "capabilities": { "attachments": true } }
            }
        }"#;
        reg.apply_json_at(edited, t0 + Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            reg.connection_state(&pinned_v1, t0 + Duration::from_secs(5)),
            ConnectionState::Draining(t0 + Duration::from_secs(11))
        );
        assert_eq!(
            reg.connection_state(&pinned_v1, t0 + Duration::from_secs(12)),
            ConnectionState::DrainExpired
        );
        let ConnectDecision::Accepted(pinned_v2) = reg.connect_decision("cursor") else {
            panic!("cursor v2 should be accepted");
        };
        assert!(pinned_v2.attachments_allowed());
        assert_eq!(
            reg.connection_state(&pinned_v2, t0 + Duration::from_secs(5)),
            ConnectionState::Active
        );

        // Explicit security revocation blocks v2 immediately with zero drain delay.
        reg.security_revoke("cursor").unwrap();
        assert_eq!(
            reg.connection_state(&pinned_v2, t0 + Duration::from_secs(5)),
            ConnectionState::Revoked
        );
        assert!(matches!(
            reg.connect_decision("cursor"),
            ConnectDecision::Revoked
        ));
    }
}
