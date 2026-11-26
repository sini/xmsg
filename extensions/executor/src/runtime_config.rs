use crate::{
    auth::ProvisionedCredentials,
    capability::builtin_pins,
    control::{ErrorCode, OwnerConfig},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAX_CONFIG: u64 = 1024 * 1024;
const MAX_PROGRAM: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedExecutable {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramConfig {
    pub pin_id: String,
    pub adapter: PinnedExecutable,
    pub native: PinnedExecutable,
    pub arguments: Vec<String>,
    pub native_mode: String,
    pub model: crate::protocol::Model,
    pub native_model_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceConfig {
    pub repo_id: String,
    pub repository: PathBuf,
    pub approved_root: PathBuf,
    pub base_revision: String,
    pub destination_selector: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePaths {
    pub journal: PathBuf,
    pub lifecycle_socket: PathBuf,
    pub owner_socket: PathBuf,
    pub human_socket: PathBuf,
    pub attribution_socket: PathBuf,
    pub runtime_root: PathBuf,
    pub owner_credential_file: PathBuf,
    pub human_credential_file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub version: u16,
    pub control: OwnerConfig,
    pub paths: ServicePaths,
    pub programs: Vec<ProgramConfig>,
    pub workspaces: Vec<WorkspaceConfig>,
    #[serde(default)]
    pub launch_environment: crate::launch_environment::LaunchEnvironment,
    #[serde(default)]
    pub bus: Option<crate::content::BusConfig>,
}

impl PinnedExecutable {
    pub fn verify(&self) -> Result<(), ErrorCode> {
        self.observe_verified().map(|_| ())
    }

    pub(crate) fn observe_verified(&self) -> Result<ExecutableArtifact, ErrorCode> {
        if self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ErrorCode::InvalidConfiguration);
        }
        let observed = ExecutableArtifact::observe(&self.path)?;
        if observed.sha256 != self.sha256 {
            return Err(ErrorCode::InvalidConfiguration);
        }
        Ok(observed)
    }
}

pub(crate) struct ExecutableArtifact {
    file: File,
    path: PathBuf,
    stamp: FileStamp,
    pub(crate) sha256: String,
}

impl ExecutableArtifact {
    pub(crate) fn observe(path: &Path) -> Result<Self, ErrorCode> {
        let mut file = regular_file(path)?;
        let before = file.metadata().map_err(invalid)?;
        if before.len() > MAX_PROGRAM || before.mode() & 0o111 == 0 || before.mode() & 0o022 != 0 {
            return Err(ErrorCode::InvalidConfiguration);
        }
        let mut hash = Sha256::new();
        let mut bounded = (&mut file).take(before.len() + 1);
        let mut copied = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let count = bounded.read(&mut buffer).map_err(invalid)?;
            if count == 0 {
                break;
            }
            copied += count as u64;
            hash.update(&buffer[..count]);
        }
        let after = file.metadata().map_err(invalid)?;
        if copied != before.len() || identity(&before) != identity(&after) {
            return Err(ErrorCode::InvalidConfiguration);
        }
        Ok(Self {
            file,
            path: path.to_owned(),
            stamp: identity(&after),
            sha256: hex::encode(hash.finalize()),
        })
    }

    pub(crate) fn unchanged(&self) -> Result<(), ErrorCode> {
        let held = self.file.metadata().map_err(invalid)?;
        let current = std::fs::symlink_metadata(&self.path).map_err(invalid)?;
        if !current.is_file() || identity(&held) != self.stamp || identity(&current) != self.stamp {
            return Err(ErrorCode::InvalidConfiguration);
        }
        Ok(())
    }
}

impl RuntimeConfig {
    pub(crate) fn program_for(
        &self,
        resolved: &crate::capability::ResolvedDispatch,
    ) -> Result<&ProgramConfig, ErrorCode> {
        self.programs
            .iter()
            .find(|p| p.pin_id == resolved.qualification.pin_id)
            .ok_or(ErrorCode::InvalidConfiguration)
    }

    /// Hashes owner launch settings; native effective inventory needs separate evidence.
    pub fn effective_digest(
        &self,
        resolved: &crate::capability::ResolvedDispatch,
    ) -> Result<String, ErrorCode> {
        let program = self.program_for(resolved)?;
        let workspace = self
            .workspaces
            .iter()
            .find(|w| {
                w.repo_id == resolved.workspace.repo_identity
                    && w.destination_selector == resolved.workspace.destination_selector
                    && w.base_revision == resolved.workspace.base_revision
            })
            .ok_or(ErrorCode::InvalidConfiguration)?;
        let bytes = serde_json::to_vec(&(
            &self.paths,
            &self.launch_environment,
            &self.bus,
            program,
            workspace,
            &resolved.harness,
            &resolved.model,
            &resolved.environment,
            &resolved.profile,
            &resolved.workspace,
            &resolved.budget,
        ))
        .map_err(invalid)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    pub fn validate(&self) -> Result<(), ErrorCode> {
        self.launch_environment.validate()?;
        if let Some(bus) = &self.bus {
            bus.validate().map_err(invalid)?;
        }
        self.control.validate()?;
        if self.version != 1 {
            return Err(ErrorCode::InvalidConfiguration);
        }
        let paths = [
            &self.paths.journal,
            &self.paths.lifecycle_socket,
            &self.paths.owner_socket,
            &self.paths.human_socket,
            &self.paths.attribution_socket,
            &self.paths.runtime_root,
            &self.paths.owner_credential_file,
            &self.paths.human_credential_file,
        ];
        let mut distinct = std::collections::HashSet::new();
        for path in paths {
            if !path.is_absolute() || !distinct.insert(path) {
                return Err(ErrorCode::InvalidConfiguration);
            }
        }
        let pins = builtin_pins().map_err(invalid)?;
        let mut programs = std::collections::HashSet::new();
        for p in &self.programs {
            if !programs.insert(&p.pin_id)
                || !pins.pins.iter().any(|pin| pin.pin.id == p.pin_id)
                || p.native_mode.is_empty()
                || p.native_mode.len() > 128
                || p.native_mode.chars().any(char::is_control)
                || p.native_model_id.is_empty()
                || p.native_model_id.len() > 128
                || p.native_model_id.chars().any(char::is_control)
                || p.model.provider.is_empty()
                || p.model.name.is_empty()
                || p.arguments.len() > 256
                || p.arguments.iter().any(|s| s.contains('\0'))
                || p.arguments.iter().map(String::len).sum::<usize>() > 16384
            {
                return Err(ErrorCode::InvalidConfiguration);
            }
            for executable in [&p.adapter, &p.native] {
                if !executable.path.is_absolute()
                    || executable.sha256.len() != 64
                    || !executable
                        .sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(ErrorCode::InvalidConfiguration);
                }
            }
        }
        let mut workspaces = std::collections::HashSet::new();
        for w in &self.workspaces {
            if w.repo_id.is_empty()
                || w.destination_selector.is_empty()
                || !w.repository.is_absolute()
                || !w.approved_root.is_absolute()
                || !matches!(w.base_revision.len(), 40 | 64)
                || !w.base_revision.bytes().all(|b| b.is_ascii_hexdigit())
                || !workspaces.insert((&w.repo_id, &w.destination_selector))
            {
                return Err(ErrorCode::InvalidConfiguration);
            }
        }
        for d in &self.control.defaults {
            let q = &d.resolved.qualification;
            let p = self
                .programs
                .iter()
                .find(|p| p.pin_id == q.pin_id)
                .ok_or(ErrorCode::InvalidConfiguration)?;
            let pin = &pins
                .pins
                .iter()
                .find(|pin| pin.pin.id == p.pin_id)
                .ok_or(ErrorCode::InvalidConfiguration)?
                .pin;
            if pin.harness != d.resolved.harness
                || pin.adapter_version != q.adapter_version
                || pin.runtime_version != q.runtime_version
                || pin.protocol_version != q.protocol_version
                || p.native_mode != q.native_mode
                || p.model != d.resolved.model
                || q.model != d.resolved.model
                || q.profile != d.resolved.profile.mode
                || q.review_mode != crate::capability::ReviewMode::HumanOnly
                || !self.workspaces.iter().any(|w| {
                    w.repo_id == d.resolved.workspace.repo_identity
                        && w.base_revision == d.resolved.workspace.base_revision
                        && w.destination_selector == d.resolved.workspace.destination_selector
                })
            {
                return Err(ErrorCode::InvalidConfiguration);
            }
        }
        Ok(())
    }

    pub fn read(path: &Path) -> Result<Self, ErrorCode> {
        let bytes = private_bytes(path, MAX_CONFIG)?;
        let config: Self =
            serde_json::from_slice(&bytes).map_err(|_| ErrorCode::InvalidConfiguration)?;
        config.validate()?;
        Ok(config)
    }

    pub fn credentials(&self) -> Result<ProvisionedCredentials, ErrorCode> {
        let owner = private_bytes(&self.paths.owner_credential_file, 128)?;
        let human = private_bytes(&self.paths.human_credential_file, 128)?;
        ProvisionedCredentials::from_bytes(&owner, &human)
    }
    pub(crate) fn human_proof(&self) -> Result<Vec<u8>, ErrorCode> {
        credential_proof(&self.paths.human_credential_file)
    }
    pub(crate) fn owner_proof(&self) -> Result<Vec<u8>, ErrorCode> {
        credential_proof(&self.paths.owner_credential_file)
    }
}

fn credential_proof(path: &Path) -> Result<Vec<u8>, ErrorCode> {
    let proof = private_bytes(path, 128)?;
    if !(32..=128).contains(&proof.len()) || proof.iter().any(|byte| matches!(byte, b'\r' | b'\n'))
    {
        return Err(ErrorCode::InvalidConfiguration);
    }
    Ok(proof)
}

fn private_bytes(path: &Path, limit: u64) -> Result<Vec<u8>, ErrorCode> {
    let mut file = regular_file(path)?;
    let before = file.metadata().map_err(invalid)?;
    if before.uid() != xmsg::client::current_uid()
        || before.mode() & 0o7777 != 0o600
        || before.len() > limit
    {
        return Err(ErrorCode::InvalidConfiguration);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(invalid)?;
    let after = file.metadata().map_err(invalid)?;
    if bytes.len() as u64 != before.len() || identity(&before) != identity(&after) {
        return Err(ErrorCode::InvalidConfiguration);
    }
    Ok(bytes)
}

fn invalid(_: impl std::fmt::Debug) -> ErrorCode {
    ErrorCode::InvalidConfiguration
}

fn regular_file(path: &Path) -> Result<File, ErrorCode> {
    if !path.is_absolute() {
        return Err(ErrorCode::InvalidConfiguration);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(invalid)?;
    if !file.metadata().map_err(invalid)?.is_file() {
        return Err(ErrorCode::InvalidConfiguration);
    }
    Ok(file)
}

type FileStamp = (u64, u64, u64, u32, u32, i64, i64, i64, i64);
fn identity(m: &std::fs::Metadata) -> FileStamp {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn artifact(root: &Path, name: &str) -> PinnedExecutable {
        let path = root.join(name);
        std::fs::write(&path, b"fixture program; never executed").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        PinnedExecutable {
            path,
            sha256: hex::encode(Sha256::digest(b"fixture program; never executed")),
        }
    }

    #[test]
    fn executable_pin_checks_actual_bytes_without_execution() {
        let root = tempfile::tempdir().unwrap();
        let program = artifact(root.path(), "adapter");
        assert_eq!(program.verify(), Ok(()));
        let held = program.observe_verified().unwrap();
        assert_eq!(held.unchanged(), Ok(()));
        std::fs::write(&program.path, b"changed").unwrap();
        assert_eq!(held.unchanged(), Err(ErrorCode::InvalidConfiguration));
        assert_eq!(program.verify(), Err(ErrorCode::InvalidConfiguration));
    }

    #[test]
    fn private_configuration_reads_refuse_permissions_symlink_and_oversize() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("private");
        std::fs::write(&path, b"bounded").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(private_bytes(&path, 7).unwrap(), b"bounded");
        assert!(private_bytes(&path, 6).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(private_bytes(&path, 7).is_err());
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(private_bytes(&link, 7).is_err());
    }

    #[test]
    fn configuration_is_strict_and_keeps_programs_owner_selected() {
        let root = tempfile::tempdir().unwrap();
        let path = |name: &str| root.path().join(name);
        let program = ProgramConfig {
            pin_id: "claude-acp-v1".into(),
            adapter: artifact(root.path(), "adapter"),
            native: artifact(root.path(), "native"),
            arguments: vec![],
            native_mode: "default".into(),
            model: crate::protocol::Model {
                provider: "fixture".into(),
                name: "no-model".into(),
            },
            native_model_id: "fixture-native-model".into(),
        };
        let mut config = RuntimeConfig {
            bus: None,
            version: 1,
            control: OwnerConfig {
                revision: 1,
                local_host: "local".into(),
                grants: vec![],
                profiles: vec![],
                defaults: vec![],
            },
            paths: ServicePaths {
                journal: path("journal"),
                lifecycle_socket: path("lifecycle"),
                owner_socket: path("owner"),
                human_socket: path("human"),
                attribution_socket: path("attribution"),
                runtime_root: path("runtime"),
                owner_credential_file: path("owner-proof"),
                human_credential_file: path("human-proof"),
            },
            programs: vec![program.clone()],
            workspaces: vec![],
            launch_environment: Default::default(),
        };
        assert_eq!(config.validate(), Ok(()));
        let mut old = serde_json::to_value(&config).unwrap();
        old.as_object_mut().unwrap().remove("bus");
        assert!(serde_json::from_value::<RuntimeConfig>(old)
            .unwrap()
            .bus
            .is_none());
        config.bus = Some(crate::content::BusConfig {
            node: "fixture".into(),
            register_socket: path("register"),
            agent_socket: path("agent"),
            auto_input: false,
        });
        assert_eq!(config.validate(), Ok(()));
        config.bus.as_mut().unwrap().agent_socket = PathBuf::from("relative");
        assert_eq!(config.validate(), Err(ErrorCode::InvalidConfiguration));
        config.bus = None;
        config.programs.push(program);
        assert_eq!(config.validate(), Err(ErrorCode::InvalidConfiguration));
        config.programs.pop();
        config.paths.owner_socket = config.paths.lifecycle_socket.clone();
        assert!(config.validate().is_err());
        let mut encoded = serde_json::to_value(&config).unwrap();
        encoded["enable_unqualified"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RuntimeConfig>(encoded).is_err());
    }
}
