use crate::protocol::{DigestRef, WorkspaceSpec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAX_GIT_OUTPUT: u64 = 1024 * 1024;
const MAX_REFERENCE: u64 = 1024 * 1024;
const MAX_REFERENCES: usize = 16;
const GIT_TIMEOUT: Duration = Duration::from_secs(30);
const OWNERSHIP_MARKER: &str = "xmsg-executor-workspace-owner";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WorkspaceError {
    #[error("invalid owner workspace binding")]
    InvalidBinding,
    #[error("workspace request is outside the owner binding")]
    OutsideBinding,
    #[error("repository configuration could execute external code or fetch")]
    UnsafeConfiguration,
    #[error("repository identity, HEAD or worktree inventory changed")]
    RepositoryChanged,
    #[error("workspace contains uncommitted work")]
    Dirty,
    #[error("workspace destination already exists or is unsafe")]
    Destination,
    #[error("context or patch reference is not owner-bound and digest verified")]
    Reference,
    #[error("Git operation failed or exceeded its bound")]
    Git,
    #[error("workspace ownership cannot be established")]
    Ownership,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    device: u64,
    inode: u64,
    uid: u32,
}
impl FileIdentity {
    fn of(meta: &fs::Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
            uid: meta.uid(),
        }
    }
}

#[derive(Debug, Clone)]
struct OwnerReference {
    file_path: PathBuf,
    digest: String,
}

#[derive(Debug, Clone)]
pub struct OwnerWorkspaceBinding {
    repo_id: String,
    repository: PathBuf,
    approved_root: PathBuf,
    base_revision: String,
    destination_selector: String,
    references: BTreeMap<String, OwnerReference>,
    search_path: OsString,
}
impl OwnerWorkspaceBinding {
    pub fn new(
        repo_id: impl Into<String>,
        repository: impl AsRef<Path>,
        approved_root: impl AsRef<Path>,
        base_revision: impl Into<String>,
        destination_selector: impl Into<String>,
    ) -> Result<Self, WorkspaceError> {
        let binding = Self {
            repo_id: repo_id.into(),
            repository: owner_directory(repository.as_ref())?,
            approved_root: owner_directory(approved_root.as_ref())?,
            base_revision: base_revision.into(),
            destination_selector: destination_selector.into(),
            references: BTreeMap::new(),
            search_path: std::env::var_os("PATH").ok_or(WorkspaceError::InvalidBinding)?,
        };
        if binding.repo_id.is_empty()
            || binding.destination_selector.is_empty()
            || !immutable_revision(&binding.base_revision)
            || binding.approved_root == binding.repository
        {
            return Err(WorkspaceError::InvalidBinding);
        }
        binding.snapshot()?;
        Ok(binding)
    }

    pub fn with_reference(
        mut self,
        name: impl Into<String>,
        file_path: impl AsRef<Path>,
        digest: impl Into<String>,
    ) -> Result<Self, WorkspaceError> {
        let name = name.into();
        let digest = digest.into();
        if name.is_empty()
            || !sha256_shape(&digest)
            || self.references.len() >= MAX_REFERENCES
            || self.references.contains_key(&name)
        {
            return Err(WorkspaceError::Reference);
        }
        let reference = OwnerReference {
            file_path: file_path
                .as_ref()
                .canonicalize()
                .map_err(|_| WorkspaceError::Reference)?,
            digest,
        };
        read_reference(&reference)?;
        self.references.insert(name, reference);
        Ok(self)
    }

    fn git(
        &self,
        root: &Path,
        args: &[&OsStr],
        input: Option<&[u8]>,
    ) -> Result<GitOutput, WorkspaceError> {
        safe_config(root)?;
        let mut git_dir = OsString::from("--git-dir=");
        git_dir.push(git_directory(root)?);
        let mut work_tree = OsString::from("--work-tree=");
        work_tree.push(root);
        let mut command = Command::new("git");
        command
            .env_clear()
            .env("PATH", &self.search_path)
            .env("LANG", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "false")
            .env("SSH_ASKPASS", "false")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .arg("--no-pager")
            .arg("-C")
            .arg(root)
            .arg(git_dir)
            .arg(work_tree)
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.attributesFile=/dev/null",
                "-c",
                "submodule.recurse=false",
                "-c",
                "gc.auto=0",
                "-c",
                "maintenance.auto=false",
                "-c",
                "credential.helper=",
                "-c",
                "protocol.allow=never",
            ])
            .args(args);
        bounded_command(command, input)
    }

    fn text(&self, root: &Path, args: &[&str]) -> Result<String, WorkspaceError> {
        let arguments: Vec<_> = args.iter().map(OsStr::new).collect();
        let output = self.git(root, &arguments, None)?;
        if !output.status.success() {
            return Err(WorkspaceError::Git);
        }
        String::from_utf8(output.stdout).map_err(|_| WorkspaceError::Git)
    }

    fn snapshot(&self) -> Result<RepositorySnapshot, WorkspaceError> {
        let repository = owner_directory(&self.repository)?;
        let git_dir = git_directory(&repository)?;
        let common_dir = common_directory(&git_dir)?;
        safe_config(&repository)?;
        let head = self.text(&repository, &["rev-parse", "--verify", "HEAD"])?;
        let base = self.text(
            &repository,
            &[
                "rev-parse",
                "--verify",
                &format!("{}^{{commit}}", self.base_revision),
            ],
        )?;
        if base.trim_end() != self.base_revision {
            return Err(WorkspaceError::OutsideBinding);
        }
        let status = self.text(
            &repository,
            &["status", "--porcelain=v1", "--untracked-files=all"],
        )?;
        if !status.is_empty() {
            return Err(WorkspaceError::Dirty);
        }
        let inventory = self.text(&repository, &["worktree", "list", "--porcelain", "-z"])?;
        Ok(RepositorySnapshot {
            repository: FileIdentity::of(
                &fs::metadata(repository).map_err(|_| WorkspaceError::Ownership)?,
            ),
            common_dir: FileIdentity::of(
                &fs::metadata(common_dir).map_err(|_| WorkspaceError::Ownership)?,
            ),
            approved_root: FileIdentity::of(
                &fs::metadata(&self.approved_root).map_err(|_| WorkspaceError::Ownership)?,
            ),
            head,
            inventory,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RepositorySnapshot {
    repository: FileIdentity,
    common_dir: FileIdentity,
    approved_root: FileIdentity,
    head: String,
    inventory: String,
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedContext {
    pub(crate) reference: String,
    pub(crate) sha256: String,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) struct WorkspacePlan {
    binding: OwnerWorkspaceBinding,
    snapshot: RepositorySnapshot,
    destination: PathBuf,
    contexts: Vec<VerifiedContext>,
    patch: Option<VerifiedContext>,
    ownership_marker: String,
}
impl WorkspacePlan {
    pub(crate) fn prepare(
        binding: &OwnerWorkspaceBinding,
        request: &WorkspaceSpec,
        execution_component: &str,
        ownership_nonce: &str,
    ) -> Result<Self, WorkspaceError> {
        if request.repo_identity != binding.repo_id
            || request.base_revision != binding.base_revision
            || request.destination_selector != binding.destination_selector
        {
            return Err(WorkspaceError::OutsideBinding);
        }
        if !safe_component(execution_component)
            || !safe_metadata_atom(ownership_nonce)
            || request.context_refs.len() > MAX_REFERENCES
        {
            return Err(WorkspaceError::Destination);
        }
        let destination = binding.approved_root.join(execution_component);
        if fs::symlink_metadata(&destination).is_ok() {
            return Err(WorkspaceError::Destination);
        }
        let mut names = BTreeSet::new();
        let mut contexts = Vec::new();
        for reference in &request.context_refs {
            if !names.insert(reference.reference.clone()) {
                return Err(WorkspaceError::Reference);
            }
            let bytes = verify_requested_reference(binding, reference)?;
            contexts.push(VerifiedContext {
                reference: reference.reference.clone(),
                sha256: reference.sha256.clone(),
                bytes,
            });
        }
        let patch = request
            .patch_ref
            .as_ref()
            .map(|reference| -> Result<VerifiedContext, WorkspaceError> {
                Ok(VerifiedContext {
                    reference: reference.reference.clone(),
                    sha256: reference.sha256.clone(),
                    bytes: verify_requested_reference(binding, reference)?,
                })
            })
            .transpose()?;
        Ok(Self {
            binding: binding.clone(),
            snapshot: binding.snapshot()?,
            destination,
            contexts,
            patch,
            ownership_marker: format!(
                "executor-workspace-v1\n{execution_component}\n{ownership_nonce}\n"
            ),
        })
    }

    pub(crate) fn revalidate(&self) -> Result<(), WorkspaceError> {
        if self.binding.snapshot()? != self.snapshot {
            return Err(WorkspaceError::RepositoryChanged);
        }
        if fs::symlink_metadata(&self.destination).is_ok() {
            return Err(WorkspaceError::Destination);
        }
        for context in &self.contexts {
            let owner = self
                .binding
                .references
                .get(&context.reference)
                .ok_or(WorkspaceError::Reference)?;
            if read_reference(owner)? != context.bytes {
                return Err(WorkspaceError::Reference);
            }
        }
        if let Some(patch) = &self.patch {
            let owner = self
                .binding
                .references
                .get(&patch.reference)
                .ok_or(WorkspaceError::Reference)?;
            if read_reference(owner)? != patch.bytes {
                return Err(WorkspaceError::Reference);
            }
        }
        Ok(())
    }

    pub(crate) fn destination(&self) -> &Path {
        &self.destination
    }

    pub(crate) fn create(self) -> Result<PreparedWorkspace, WorkspaceError> {
        self.revalidate()?;
        let output = self.binding.git(
            &self.binding.repository,
            &[
                OsStr::new("worktree"),
                OsStr::new("add"),
                OsStr::new("--detach"),
                OsStr::new("--"),
                self.destination.as_os_str(),
                OsStr::new(&self.binding.base_revision),
            ],
            None,
        )?;
        if !output.status.success() {
            return Err(WorkspaceError::Git);
        }
        let metadata_dir = git_directory(&self.destination)?;
        let mut marker = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(metadata_dir.join(OWNERSHIP_MARKER))
            .map_err(|_| WorkspaceError::Ownership)?;
        marker
            .write_all(self.ownership_marker.as_bytes())
            .map_err(|_| WorkspaceError::Ownership)?;
        marker.sync_all().map_err(|_| WorkspaceError::Ownership)?;
        fs::set_permissions(&self.destination, fs::Permissions::from_mode(0o700))
            .map_err(|_| WorkspaceError::Ownership)?;
        let identity = owner_directory(&self.destination)
            .and_then(|p| fs::metadata(p).map_err(|_| WorkspaceError::Ownership))?;
        let actual_head = self
            .binding
            .text(&self.destination, &["rev-parse", "--verify", "HEAD"])?;
        if actual_head.trim_end() != self.binding.base_revision {
            return Err(WorkspaceError::Ownership);
        }
        if let Some(patch) = &self.patch {
            for operation in ["--check", "--apply"] {
                let args: Vec<&OsStr> = if operation == "--check" {
                    vec![
                        OsStr::new("apply"),
                        OsStr::new("--check"),
                        OsStr::new("--whitespace=error-all"),
                        OsStr::new("-"),
                    ]
                } else {
                    vec![
                        OsStr::new("apply"),
                        OsStr::new("--whitespace=error-all"),
                        OsStr::new("-"),
                    ]
                };
                if !self
                    .binding
                    .git(&self.destination, &args, Some(&patch.bytes))?
                    .status
                    .success()
                {
                    return Err(WorkspaceError::Reference);
                }
            }
        }
        let identity = OwnedWorkspaceIdentity {
            destination: self.destination,
            directory: FileIdentity::of(&identity),
            base_revision: actual_head.trim_end().into(),
            repo_id: self.binding.repo_id.clone(),
            destination_selector: self.binding.destination_selector.clone(),
            repository: self.snapshot.repository,
            common_dir: self.snapshot.common_dir,
            approved_root: self.snapshot.approved_root,
            ownership_marker: self.ownership_marker,
        };
        Ok(PreparedWorkspace {
            binding: self.binding,
            identity,
            contexts: self.contexts,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedWorkspaceIdentity {
    destination: PathBuf,
    directory: FileIdentity,
    base_revision: String,
    repo_id: String,
    destination_selector: String,
    repository: FileIdentity,
    common_dir: FileIdentity,
    approved_root: FileIdentity,
    ownership_marker: String,
}
impl OwnedWorkspaceIdentity {
    pub fn path(&self) -> &Path {
        &self.destination
    }
}

pub(crate) struct PreparedWorkspace {
    binding: OwnerWorkspaceBinding,
    identity: OwnedWorkspaceIdentity,
    contexts: Vec<VerifiedContext>,
}
impl PreparedWorkspace {
    pub(crate) fn recover(
        binding: &OwnerWorkspaceBinding,
        identity: OwnedWorkspaceIdentity,
    ) -> Result<Self, WorkspaceError> {
        let prepared = Self {
            binding: binding.clone(),
            identity,
            contexts: Vec::new(),
        };
        prepared.verify_owned()?;
        Ok(prepared)
    }
    pub(crate) fn path(&self) -> &Path {
        self.identity.path()
    }
    pub(crate) fn identity(&self) -> &OwnedWorkspaceIdentity {
        &self.identity
    }
    pub(crate) fn contexts(&self) -> &[VerifiedContext] {
        &self.contexts
    }
    fn verify_owned(&self) -> Result<(), WorkspaceError> {
        let parent = self
            .identity
            .destination
            .parent()
            .ok_or(WorkspaceError::Ownership)?;
        if parent != self.binding.approved_root
            || self.identity.base_revision != self.binding.base_revision
            || self.identity.repo_id != self.binding.repo_id
            || self.identity.destination_selector != self.binding.destination_selector
        {
            return Err(WorkspaceError::Ownership);
        }
        let meta = fs::symlink_metadata(&self.identity.destination)
            .map_err(|_| WorkspaceError::Ownership)?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || FileIdentity::of(&meta) != self.identity.directory
        {
            return Err(WorkspaceError::Ownership);
        }
        if FileIdentity::of(
            &fs::metadata(&self.binding.repository).map_err(|_| WorkspaceError::Ownership)?,
        ) != self.identity.repository
            || FileIdentity::of(
                &fs::metadata(&self.binding.approved_root)
                    .map_err(|_| WorkspaceError::Ownership)?,
            ) != self.identity.approved_root
        {
            return Err(WorkspaceError::Ownership);
        }
        let metadata_dir = git_directory(&self.identity.destination)?;
        if read_small(&metadata_dir.join(OWNERSHIP_MARKER))?
            != self.identity.ownership_marker.as_bytes()
        {
            return Err(WorkspaceError::Ownership);
        }
        let common = common_directory(&metadata_dir)?;
        let owner_common = common_directory(&git_directory(&self.binding.repository)?)?;
        if common != owner_common
            || FileIdentity::of(&fs::metadata(&common).map_err(|_| WorkspaceError::Ownership)?)
                != self.identity.common_dir
        {
            return Err(WorkspaceError::Ownership);
        }
        if self
            .binding
            .text(
                &self.identity.destination,
                &["rev-parse", "--verify", "HEAD"],
            )?
            .trim_end()
            != self.identity.base_revision
        {
            return Err(WorkspaceError::Ownership);
        }
        Ok(())
    }
    pub(crate) fn cleanup(self) -> Result<(), WorkspaceError> {
        self.verify_owned()?;
        let result = self.binding.git(
            &self.binding.repository,
            &[
                OsStr::new("worktree"),
                OsStr::new("remove"),
                OsStr::new("--"),
                self.identity.destination.as_os_str(),
            ],
            None,
        )?;
        if !result.status.success() {
            let status = self.binding.text(
                &self.identity.destination,
                &["status", "--porcelain=v1", "--untracked-files=all"],
            )?;
            return Err(if status.is_empty() {
                WorkspaceError::Git
            } else {
                WorkspaceError::Dirty
            });
        }
        Ok(())
    }
}

fn verify_requested_reference(
    binding: &OwnerWorkspaceBinding,
    reference: &DigestRef,
) -> Result<Vec<u8>, WorkspaceError> {
    let owner = binding
        .references
        .get(&reference.reference)
        .ok_or(WorkspaceError::Reference)?;
    if reference.sha256 != owner.digest {
        return Err(WorkspaceError::Reference);
    }
    read_reference(owner)
}
fn read_reference(reference: &OwnerReference) -> Result<Vec<u8>, WorkspaceError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&reference.file_path)
        .map_err(|_| WorkspaceError::Reference)?;
    let meta = file.metadata().map_err(|_| WorkspaceError::Reference)?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.len() > MAX_REFERENCE {
        return Err(WorkspaceError::Reference);
    }
    let mut bytes = Vec::new();
    file.take(MAX_REFERENCE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| WorkspaceError::Reference)?;
    if bytes.len() as u64 > MAX_REFERENCE || hex::encode(Sha256::digest(&bytes)) != reference.digest
    {
        return Err(WorkspaceError::Reference);
    }
    Ok(bytes)
}
fn owner_directory(directory: &Path) -> Result<PathBuf, WorkspaceError> {
    let canonical = directory
        .canonicalize()
        .map_err(|_| WorkspaceError::InvalidBinding)?;
    let meta = fs::metadata(&canonical).map_err(|_| WorkspaceError::InvalidBinding)?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
        return Err(WorkspaceError::InvalidBinding);
    }
    Ok(canonical)
}
fn git_directory(root: &Path) -> Result<PathBuf, WorkspaceError> {
    let entry = root.join(".git");
    let meta = fs::symlink_metadata(&entry).map_err(|_| WorkspaceError::Ownership)?;
    if meta.file_type().is_symlink() {
        return Err(WorkspaceError::Ownership);
    }
    if meta.is_dir() {
        return owner_directory(&entry).map_err(|_| WorkspaceError::Ownership);
    }
    let bytes = read_small(&entry)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| WorkspaceError::Ownership)?;
    let target = text
        .strip_prefix("gitdir: ")
        .ok_or(WorkspaceError::Ownership)?
        .trim_end();
    let target = Path::new(target);
    root.join(target)
        .canonicalize()
        .map_err(|_| WorkspaceError::Ownership)
}
fn common_directory(git_dir: &Path) -> Result<PathBuf, WorkspaceError> {
    let common = git_dir.join("commondir");
    if !common.exists() {
        return Ok(git_dir.into());
    }
    let bytes = read_small(&common)?;
    let relative = std::str::from_utf8(&bytes)
        .map_err(|_| WorkspaceError::Ownership)?
        .trim_end();
    owner_directory(&git_dir.join(relative)).map_err(|_| WorkspaceError::Ownership)
}
fn read_small(file_path: &Path) -> Result<Vec<u8>, WorkspaceError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(file_path)
        .map_err(|_| WorkspaceError::Ownership)?;
    let meta = file.metadata().map_err(|_| WorkspaceError::Ownership)?;
    if !meta.is_file() || meta.len() > MAX_GIT_OUTPUT || meta.uid() != unsafe { libc::geteuid() } {
        return Err(WorkspaceError::Ownership);
    }
    let mut bytes = Vec::new();
    file.take(MAX_GIT_OUTPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| WorkspaceError::Ownership)?;
    if bytes.len() as u64 > MAX_GIT_OUTPUT {
        return Err(WorkspaceError::Ownership);
    }
    Ok(bytes)
}
fn safe_config(root: &Path) -> Result<(), WorkspaceError> {
    let git_dir = git_directory(root)?;
    let common = common_directory(&git_dir)?;
    for config in [common.join("config"), git_dir.join("config.worktree")] {
        if !config.exists() {
            continue;
        }
        let data = read_small(&config)?;
        let text = std::str::from_utf8(&data).map_err(|_| WorkspaceError::UnsafeConfiguration)?;
        for line in text.lines() {
            let line = line.trim().to_ascii_lowercase();
            if line.starts_with('[') {
                let section = line
                    .trim_start_matches('[')
                    .trim_start()
                    .split([' ', '\t', '.', '"', ']'])
                    .next()
                    .unwrap_or("");
                if matches!(section, "filter" | "include" | "includeif") || section.is_empty() {
                    return Err(WorkspaceError::UnsafeConfiguration);
                }
            } else if line.starts_with("promisor") || line.starts_with("partialclone") {
                return Err(WorkspaceError::UnsafeConfiguration);
            }
        }
    }
    Ok(())
}
fn immutable_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sha256_shape(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn safe_metadata_atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

struct GitOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
}
fn bounded_command(
    mut command: Command,
    input: Option<&[u8]>,
) -> Result<GitOutput, WorkspaceError> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| WorkspaceError::Git)?;
    let mut stdout = child.stdout.take().ok_or(WorkspaceError::Git)?;
    let mut stderr = child.stderr.take().ok_or(WorkspaceError::Git)?;
    let stdout_reader = thread::spawn(move || {
        let mut data = Vec::new();
        stdout
            .by_ref()
            .take(MAX_GIT_OUTPUT + 1)
            .read_to_end(&mut data)
            .map(|_| data)
    });
    let stderr_reader = thread::spawn(move || {
        let mut data = Vec::new();
        stderr
            .by_ref()
            .take(MAX_GIT_OUTPUT + 1)
            .read_to_end(&mut data)
            .map(|_| data)
    });
    let writer = child.stdin.take().map(|mut stdin| {
        let bytes = input.unwrap_or_default().to_vec();
        thread::spawn(move || stdin.write_all(&bytes))
    });
    let deadline = Instant::now() + GIT_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(WorkspaceError::Git);
            }
        }
    };
    let written = writer.map(|writer| writer.join());
    let stdout = stdout_reader.join();
    let stderr = stderr_reader.join();
    let status = status?;
    if let Some(written) = written {
        written
            .map_err(|_| WorkspaceError::Git)?
            .map_err(|_| WorkspaceError::Git)?;
    }
    let stdout = stdout
        .map_err(|_| WorkspaceError::Git)?
        .map_err(|_| WorkspaceError::Git)?;
    let stderr = stderr
        .map_err(|_| WorkspaceError::Git)?
        .map_err(|_| WorkspaceError::Git)?;
    if stdout.len() as u64 > MAX_GIT_OUTPUT || stderr.len() as u64 > MAX_GIT_OUTPUT {
        return Err(WorkspaceError::Git);
    }
    Ok(GitOutput { status, stdout })
}

#[cfg(test)]
#[path = "workspace_tests.rs"]
mod tests;
