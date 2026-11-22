use super::{Error, Request};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    pub writers: &'static str,
    pub managed_policy: &'static str,
    pub shadowing: &'static str,
    pub loaded_hooks: &'static str,
}

pub fn inspect(request: &Request) -> Result<Observation, Error> {
    let config = request
        .config_dir
        .clone()
        .unwrap_or_else(|| request.account_home.join(".claude"));
    let mut observed = false;
    if let Ok(entries) = std::fs::read_dir(config.join("sessions")) {
        for entry in entries {
            let entry = entry.map_err(|_| Error::Io)?;
            let Some(snapshot) = super::transaction::read(&entry.path(), request.uid)? else {
                continue;
            };
            let value: serde_json::Value =
                serde_json::from_slice(&snapshot.bytes).map_err(|_| Error::InvalidJson)?;
            let pid = value
                .get("pid")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok());
            let start = value.get("procStart").and_then(|v| v.as_str());
            if let (Some(pid), Some(start)) = (pid, start) {
                if let Ok(current) =
                    crate::process::starttime(Path::new(crate::process::LIVE_PROC_ROOT), pid)
                {
                    observed |= crate::process::claude_start_token_matches(
                        Path::new(crate::process::LIVE_PROC_ROOT),
                        &current,
                        start,
                    );
                }
            }
        }
    }
    let managed_policy = inspect_policy(request)?;
    Ok(Observation {
        writers: if observed { "observed" } else { "unknown" },
        managed_policy,
        shadowing: "unknown",
        loaded_hooks: "unknown",
    })
}

fn policy_roots(request: &Request) -> Vec<PathBuf> {
    #[cfg(any(test, feature = "test-hooks"))]
    if let Some(roots) = &request.policy_roots {
        return roots.clone();
    }
    #[cfg(test)]
    return vec![request.account_home.join(".managed-policy-fixture")];
    #[cfg(not(test))]
    let _ = request;
    #[cfg(all(not(test), target_os = "macos"))]
    return vec![PathBuf::from("/Library/Application Support/ClaudeCode")];
    #[cfg(all(not(test), not(target_os = "macos")))]
    return vec![PathBuf::from("/etc/claude-code")];
}

fn inspect_policy(request: &Request) -> Result<&'static str, Error> {
    for root in policy_roots(request) {
        let mut files = vec![
            root.join("managed-settings.json"),
            root.join("managed-mcp.json"),
        ];
        let fragments = root.join("managed-settings.d");
        match std::fs::read_dir(&fragments) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry.map_err(|_| Error::Unsafe)?;
                    if entry.path().extension().is_some_and(|e| e == "json") {
                        files.push(entry.path());
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Unsafe),
        }
        for file in files {
            use std::os::unix::fs::MetadataExt;
            let uid = match std::fs::symlink_metadata(&file) {
                Ok(metadata) => metadata.uid(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(Error::Unsafe),
            };
            if uid != 0 && uid != request.uid {
                return Err(Error::Unsafe);
            }
            let Some(snapshot) = super::transaction::read(&file, uid)? else {
                continue;
            };
            let doc = super::json_edit::Document::parse(&snapshot.bytes)
                .map_err(|_| Error::InvalidJson)?;
            let value = doc.value(&doc.root).map_err(|_| Error::InvalidJson)?;
            if !value.is_object() {
                return Err(Error::Unsupported);
            }
            let restricted = value
                .get("allowManagedMcpServersOnly")
                .and_then(|v| v.as_bool())
                == Some(true)
                || value.get("allowManagedHooksOnly").and_then(|v| v.as_bool()) == Some(true)
                || value.get("disableAllHooks").and_then(|v| v.as_bool()) == Some(true)
                || value
                    .get("mcpServers")
                    .and_then(|v| v.get("xmsg"))
                    .is_some();
            if restricted {
                return Ok("conflict");
            }
        }
    }
    Ok("unknown")
}
