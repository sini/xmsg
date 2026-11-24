use std::ffi::OsStr;

/// Every `XMSG_*` environment variable in `src/` that selects a socket, database,
/// node/principal identity, TLS credential, config file, or state/session/presence directory.
#[allow(dead_code)]
pub const XMSG_ENV_SCRUB_KEYS: &[&str] = &[
    "XMSG_ACTIVITY",
    "XMSG_ACTIVITY_CORRELATED",
    "XMSG_AGENT_SOCK",
    "XMSG_AGY_BRAIN_DIR",
    "XMSG_AGY_EXE",
    "XMSG_AGY_EXE_STRICT",
    "XMSG_AGY_LABEL",
    "XMSG_AGY_PRESENCE_DIR",
    "XMSG_BUILD_REVISION",
    "XMSG_CODEX_EXE",
    "XMSG_CODEX_EXE_STRICT",
    "XMSG_CODEX_HOME",
    "XMSG_CODEX_LABEL",
    "XMSG_CONTEXT_MASK",
    "XMSG_CONTEXT_TAGS_CONFIG",
    "XMSG_DB_PATH",
    "XMSG_EMBEDDED_REVISION",
    "XMSG_FED_CERT",
    "XMSG_FED_KEY",
    "XMSG_FED_LISTEN",
    "XMSG_FED_RELOAD_INTERVAL_SECS",
    "XMSG_HARNESSES_FILE",
    "XMSG_HOST_LABEL",
    "XMSG_HTTP_SOCK",
    "XMSG_IDEMPOTENCY_TTL",
    "XMSG_LEAF",
    "XMSG_LEAF_PRINCIPAL",
    "XMSG_LEAF_REGISTER_SOCK",
    "XMSG_LISTEN",
    "XMSG_MAX_ATTACHMENT_BYTES",
    "XMSG_MAX_BODY",
    "XMSG_NO_CONTEXT_TAGS",
    "XMSG_PEER_MAILBOX_MAX_BYTES",
    "XMSG_PEER_MAILBOX_MAX_ROWS",
    "XMSG_PEERS_FILE",
    "XMSG_REGISTER_SOCK",
    "XMSG_REPLY_ONLY",
    "XMSG_REPLY_TTL",
    "XMSG_SESSIONS_DIR",
    "XMSG_SESSIONS_DIRS",
    "XMSG_SVC_EXE",
    "XMSG_SVC_QUEUE_CAP",
    "XMSG_URL",
];

fn scrub_with(mut remove: impl FnMut(&OsStr)) {
    for key in XMSG_ENV_SCRUB_KEYS {
        remove(OsStr::new(key));
    }
    for (key, _) in std::env::vars_os() {
        if let Some(name) = key.to_str() {
            if name.starts_with("XMSG_") && !name.starts_with("XMSG_TEST_") {
                remove(&key);
            }
        }
    }
}

#[allow(dead_code)]
pub fn scrub_xmsg_env(cmd: &mut std::process::Command) {
    scrub_with(|k| {
        cmd.env_remove(k);
    });
}

#[allow(dead_code)]
pub fn scrub_xmsg_tokio_env(cmd: &mut tokio::process::Command) {
    scrub_with(|k| {
        cmd.env_remove(k);
    });
}

#[allow(dead_code)]
pub fn command<S: AsRef<OsStr>>(program: S) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    scrub_xmsg_env(&mut cmd);
    cmd
}

#[allow(dead_code)]
pub fn tokio_command<S: AsRef<OsStr>>(program: S) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(program);
    scrub_xmsg_tokio_env(&mut cmd);
    cmd
}
