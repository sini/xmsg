use super::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path},
};

#[derive(Clone)]
pub(super) struct Snapshot {
    pub bytes: Vec<u8>,
    pub fingerprint: Fingerprint,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fingerprint {
    hash: String,
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl Snapshot {
    pub fn mode(&self) -> u32 {
        self.fingerprint.mode
    }
}
fn cstring(value: &std::ffi::OsStr) -> Result<std::ffi::CString, Error> {
    std::ffi::CString::new(value.as_bytes()).map_err(|_| Error::Unsafe)
}
fn dir(path: &Path) -> std::io::Result<File> {
    if !path.is_absolute() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                let name = std::ffi::CString::new(name.as_bytes())
                    .map_err(|_| std::io::ErrorKind::InvalidInput)?;
                let fd = unsafe {
                    libc::openat(
                        current.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                current = unsafe { File::from_raw_fd(fd) };
            }
            _ => return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput)),
        }
    }
    Ok(current)
}
pub(super) fn read(path: &Path, uid: u32) -> Result<Option<Snapshot>, Error> {
    let parent = match dir(path.parent().ok_or(Error::Unsafe)?) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::Unsafe),
    };
    let name = cstring(path.file_name().ok_or(Error::Unsafe)?)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(Error::Unsafe)
        };
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata().map_err(|_| Error::Io)?;
    if !meta.is_file() || meta.uid() != uid || meta.mode() & 0o022 != 0 || meta.len() > 1024 * 1024
    {
        return Err(Error::Unsafe);
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Io)?;
    if bytes.len() > 1024 * 1024 {
        return Err(Error::Unsafe);
    }
    Ok(Some(Snapshot {
        fingerprint: Fingerprint {
            hash: hash(&bytes),
            dev: meta.dev(),
            ino: meta.ino(),
            uid: meta.uid(),
            mode: meta.mode() & 0o777,
            len: meta.len(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        },
        bytes,
    }))
}
pub(super) fn canonical(path: &Path) -> Result<PathBuf, Error> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
    {
        return Err(Error::Unsafe);
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(Error::Unsafe),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Unsafe),
        }
    }
    crate::install_paths::canonicalize_best_effort(path).map_err(|_| Error::Unsafe)
}
pub(super) fn coordinator(request: &Request) -> PathBuf {
    request
        .account_home
        .join(".local/state/xmsg/claude-coordinator")
}
pub(super) fn area(request: &Request, key: &str) -> PathBuf {
    coordinator(request).join("sets").join(key)
}
pub(super) fn load_ownership(
    request: &Request,
    key: &str,
) -> Result<Option<(Ownership, String)>, Error> {
    for root in [
        coordinator(request),
        coordinator(request).join("sets"),
        area(request, key),
    ] {
        match dir(&root) {
            Ok(directory) => {
                let meta = directory.metadata().map_err(|_| Error::Io)?;
                if meta.uid() != request.uid || meta.mode() & 0o777 != 0o700 {
                    return Err(Error::Unsafe);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Unsafe),
        }
    }
    let Some(snapshot) = read(&area(request, key).join("ownership.json"), request.uid)? else {
        return Ok(None);
    };
    if snapshot.mode() != 0o600 {
        return Err(Error::Unsafe);
    }
    super::json_edit::Document::parse(&snapshot.bytes).map_err(|_| Error::InvalidJson)?;
    let record: Ownership =
        serde_json::from_slice(&snapshot.bytes).map_err(|_| Error::InvalidJson)?;
    if record.version != 1 || record.set_id != key {
        return Err(Error::Conflict);
    }
    Ok(Some((record, hash(&snapshot.bytes))))
}
pub(super) fn pending(request: &Request, key: &str) -> Result<bool, Error> {
    Ok(read(&area(request, key).join("intent.json"), request.uid)?.is_some())
}

fn private_dir(path: &Path, uid: u32) -> Result<(), Error> {
    let meta = dir(path)
        .map_err(|_| Error::Unsafe)?
        .metadata()
        .map_err(|_| Error::Io)?;
    if meta.uid() != uid || meta.mode() & 0o777 != 0o700 {
        return Err(Error::Unsafe);
    }
    Ok(())
}
fn ensure(path: &Path, uid: u32, private: bool) -> Result<Vec<DirProof>, Error> {
    if !path.is_absolute() {
        return Err(Error::Unsafe);
    }
    let mut current = PathBuf::from("/");
    let mut made = Vec::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir) {
                continue;
            }
            return Err(Error::Unsafe);
        };
        let parent = dir(&current).map_err(|_| Error::Unsafe)?;
        let c = cstring(name)?;
        current.push(name);
        let created = unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o700) } == 0;
        if !created && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
            return Err(Error::Io);
        }
        let opened = dir(&current).map_err(|_| Error::Unsafe)?;
        let meta = opened.metadata().map_err(|_| Error::Io)?;
        if !meta.is_dir() || (created && (meta.uid() != uid || meta.mode() & 0o777 != 0o700)) {
            return Err(Error::Unsafe);
        }
        if created {
            parent.sync_all().map_err(|_| Error::Io)?;
            made.push(DirProof {
                path: current.clone(),
                dev: meta.dev(),
                ino: meta.ino(),
            });
        }
    }
    if private {
        private_dir(path, uid)?;
    } else {
        let meta = dir(path)
            .map_err(|_| Error::Unsafe)?
            .metadata()
            .map_err(|_| Error::Io)?;
        if meta.uid() != uid || meta.mode() & 0o022 != 0 {
            return Err(Error::Unsafe);
        }
    }
    Ok(made)
}
fn write_new(path: &Path, bytes: &[u8], mode: u32, uid: u32) -> Result<(), Error> {
    let parent = dir(path.parent().ok_or(Error::Unsafe)?).map_err(|_| Error::Unsafe)?;
    let name = cstring(path.file_name().ok_or(Error::Unsafe)?)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(Error::Io);
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata().map_err(|_| Error::Io)?;
    if !meta.is_file() || meta.uid() != uid {
        return Err(Error::Unsafe);
    }
    file.write_all(bytes).map_err(|_| Error::Io)?;
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(Error::Io);
    }
    file.sync_all().map_err(|_| Error::Io)?;
    parent.sync_all().map_err(|_| Error::Io)
}
fn rename(from: &Path, to: &Path) -> Result<(), Error> {
    if from.parent() != to.parent() {
        return Err(Error::Unsafe);
    }
    let parent = dir(to.parent().ok_or(Error::Unsafe)?).map_err(|_| Error::Unsafe)?;
    let a = cstring(from.file_name().ok_or(Error::Unsafe)?)?;
    let b = cstring(to.file_name().ok_or(Error::Unsafe)?)?;
    if unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            a.as_ptr(),
            parent.as_raw_fd(),
            b.as_ptr(),
        )
    } != 0
    {
        return Err(Error::Io);
    }
    parent.sync_all().map_err(|_| Error::Io)
}
fn unlink(path: &Path) -> Result<(), Error> {
    let parent = dir(path.parent().ok_or(Error::Unsafe)?).map_err(|_| Error::Unsafe)?;
    let name = cstring(path.file_name().ok_or(Error::Unsafe)?)?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(Error::Io);
    }
    parent.sync_all().map_err(|_| Error::Io)
}
fn atomic(path: &Path, bytes: &[u8], uid: u32) -> Result<(), Error> {
    let temp = path.with_file_name(format!(".xmsg-{}.tmp", ulid::Ulid::new()));
    write_new(&temp, bytes, 0o600, uid)?;
    rename(&temp, path)
}
pub(super) struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}
pub(super) fn lock(request: &Request) -> Result<Lock, Error> {
    let root = coordinator(request);
    ensure(&root, request.uid, true)?;
    let parent = dir(&root).map_err(|_| Error::Unsafe)?;
    let name = cstring(std::ffi::OsStr::new("adapter.lock"))?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(Error::Io);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata().map_err(|_| Error::Io)?;
    if !meta.is_file() || meta.uid() != request.uid || meta.mode() & 0o777 != 0o600 {
        return Err(Error::Unsafe);
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::Busy);
    }
    Ok(Lock(file))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirProof {
    path: PathBuf,
    dev: u64,
    ino: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentFile {
    path: PathBuf,
    before: Option<Fingerprint>,
    after: Option<Fingerprint>,
    after_hash: Option<String>,
    mode: u32,
    backup: Option<PathBuf>,
    staged: Option<PathBuf>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u32,
    transaction_id: String,
    set_id: String,
    targets: Vec<PathBuf>,
    before_ownership: Option<String>,
    after_ownership: String,
    files: Vec<IntentFile>,
    created_dirs: Vec<DirProof>,
}
fn save_intent(journal: &Path, intent: &Intent, uid: u32) -> Result<(), Error> {
    atomic(
        journal,
        &serde_json::to_vec(intent).map_err(|_| Error::Io)?,
        uid,
    )
}
fn match_state(current: Option<&Snapshot>, expected: Option<&Fingerprint>) -> bool {
    match (current, expected) {
        (None, None) => true,
        (Some(c), Some(e)) => {
            c.fingerprint.hash == e.hash
                && c.fingerprint.dev == e.dev
                && c.fingerprint.ino == e.ino
                && c.fingerprint.uid == e.uid
                && c.fingerprint.mode == e.mode
                && c.fingerprint.len == e.len
        }
        _ => false,
    }
}
fn overlap(plan: &Plan) -> Result<(), Error> {
    let sets = coordinator(&plan.request).join("sets");
    if !sets.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(&sets).map_err(|_| Error::Io)? {
        let entry = entry.map_err(|_| Error::Io)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(Error::Conflict)?;
        if name.len() != 64 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Conflict);
        }
        private_dir(&entry.path(), plan.request.uid)?;
        if name == plan.ownership.set_id {
            continue;
        }
        let record = load_ownership(&plan.request, name)?;
        let pending = pending(&plan.request, name)?;
        if record.as_ref().is_some_and(|(r, _)| !r.active) && !pending {
            continue;
        }
        let paths = if let Some((record, _)) = record {
            record.targets
        } else {
            let Some(snapshot) = read(&entry.path().join("targets.json"), plan.request.uid)? else {
                return Err(Error::Conflict);
            };
            serde_json::from_slice::<Vec<PathBuf>>(&snapshot.bytes)
                .map_err(|_| Error::InvalidJson)?
        };
        if paths.iter().any(|p| plan.ownership.targets.contains(p)) {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}
fn ownership_hash(request: &Request, key: &str) -> Result<Option<String>, Error> {
    Ok(read(&area(request, key).join("ownership.json"), request.uid)?.map(|s| hash(&s.bytes)))
}
fn verify_plan(plan: &Plan) -> Result<(), Error> {
    if ownership_hash(&plan.request, &plan.ownership.set_id)? != plan.before_ownership {
        return Err(Error::Drift);
    }
    for target in &plan.targets {
        let current = read(&target.path, plan.request.uid)?;
        if current.as_ref().map(|s| &s.fingerprint)
            != target.before.as_ref().map(|s| &s.fingerprint)
        {
            return Err(Error::Drift);
        }
    }
    Ok(())
}
fn recover(request: &Request, key: &str, expected_targets: &[PathBuf]) -> Result<(), Error> {
    let area = area(request, key);
    let journal = area.join("intent.json");
    let Some(snapshot) = read(&journal, request.uid)? else {
        return Ok(());
    };
    super::json_edit::Document::parse(&snapshot.bytes).map_err(|_| Error::InvalidJson)?;
    let intent: Intent = serde_json::from_slice(&snapshot.bytes).map_err(|_| Error::InvalidJson)?;
    if intent.version != 1
        || intent.set_id != key
        || intent.targets != expected_targets
        || hash(&serde_json::to_vec(&intent.targets).map_err(|_| Error::Conflict)?) != key
        || intent.transaction_id.len() != 26
        || !intent
            .transaction_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric())
    {
        return Err(Error::Conflict);
    }
    let mut unique = std::collections::BTreeSet::new();
    let backup_root = area.join("backups").join(&intent.transaction_id);
    for file in &intent.files {
        if !intent.targets.contains(&file.path) || !unique.insert(file.path.clone()) {
            return Err(Error::Conflict);
        }
        if let Some(backup) = &file.backup {
            if backup.parent() != Some(backup_root.as_path()) {
                return Err(Error::Conflict);
            }
        }
        if let Some(staged) = &file.staged {
            if staged.parent() != file.path.parent()
                || !staged
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(".xmsg-install-") && n.ends_with(".tmp"))
            {
                return Err(Error::Conflict);
            }
        }
    }
    for proof in &intent.created_dirs {
        if !intent.targets.iter().any(|target| {
            target
                .parent()
                .is_some_and(|parent| parent.starts_with(&proof.path))
        }) || !proof.path.starts_with(&request.account_home)
        {
            return Err(Error::Conflict);
        }
    }
    let ownership = ownership_hash(request, key)?;
    let currents = intent
        .files
        .iter()
        .map(|file| read(&file.path, request.uid))
        .collect::<Result<Vec<_>, _>>()?;
    let committed = ownership.as_deref() == Some(&intent.after_ownership);
    if committed {
        if intent
            .files
            .iter()
            .zip(&currents)
            .any(|(f, c)| !match_state(c.as_ref(), f.after.as_ref()))
        {
            return Err(Error::Conflict);
        }
    } else {
        if ownership != intent.before_ownership {
            return Err(Error::Conflict);
        }
        for (file, current) in intent.files.iter().zip(&currents) {
            if !match_state(current.as_ref(), file.before.as_ref())
                && !match_state(current.as_ref(), file.after.as_ref())
            {
                return Err(Error::Conflict);
            }
            if let Some(backup) = &file.backup {
                let data = read(backup, request.uid)?.ok_or(Error::Conflict)?;
                if file
                    .before
                    .as_ref()
                    .is_none_or(|before| hash(&data.bytes) != before.hash)
                {
                    return Err(Error::Conflict);
                }
            }
        }
        for (file, current) in intent.files.iter().zip(&currents) {
            if match_state(current.as_ref(), file.before.as_ref()) {
                continue;
            }
            if let Some(backup) = &file.backup {
                let data = read(backup, request.uid)?.ok_or(Error::Conflict)?;
                let temp = file
                    .path
                    .with_file_name(format!(".xmsg-recover-{}.tmp", ulid::Ulid::new()));
                write_new(
                    &temp,
                    &data.bytes,
                    file.before.as_ref().ok_or(Error::Conflict)?.mode,
                    request.uid,
                )?;
                rename(&temp, &file.path)?;
            } else if current.is_some() {
                unlink(&file.path)?;
            }
        }
    }
    for file in &intent.files {
        if let Some(staged) = &file.staged {
            if let Some(data) = read(staged, request.uid)? {
                if file.after_hash.as_ref() != Some(&hash(&data.bytes)) {
                    return Err(Error::Conflict);
                }
                unlink(staged)?;
            }
        }
    }
    if !committed {
        for proof in intent.created_dirs.iter().rev() {
            if let Ok(directory) = dir(&proof.path) {
                let m = directory.metadata().map_err(|_| Error::Io)?;
                if (m.dev(), m.ino(), m.uid()) != (proof.dev, proof.ino, request.uid) {
                    return Err(Error::Conflict);
                }
                match fs::remove_dir(&proof.path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
                    Err(_) => return Err(Error::Io),
                }
            }
        }
    }
    unlink(&journal)
}
#[cfg(test)]
type PublicationHook = Option<Box<dyn FnMut(usize)>>;
#[cfg(test)]
thread_local! {pub(super) static AFTER_PUBLICATION:std::cell::RefCell<PublicationHook>=const{std::cell::RefCell::new(None)};}
#[cfg(test)]
thread_local! {pub(super) static BEFORE_PUBLICATION:std::cell::RefCell<Option<Box<dyn FnMut()>>>=const{std::cell::RefCell::new(None)};}

pub(super) fn apply(mut plan: Plan) -> Result<Report, Error> {
    let observed = super::claude_observe::inspect(&plan.request)?;
    if observed.writers == "observed" {
        return Err(Error::WriterObserved);
    }
    if observed.managed_policy == "conflict" {
        return Err(Error::Conflict);
    }
    let file_changes = plan.targets.iter().any(|target| {
        target.before.as_ref().map(|s| s.bytes.as_slice()) != target.after.as_deref()
    });
    if !file_changes && !plan.metadata_change && !plan.pending {
        return Ok(plan.report);
    }
    let _lock = lock(&plan.request)?;
    overlap(&plan)?;
    if plan.pending {
        recover(
            &plan.request,
            &plan.ownership.set_id,
            &plan.ownership.targets,
        )?;
        plan = super::plan(&plan.request, plan.report.action)?;
        plan.report.changes.insert(
            0,
            Change {
                field: ManagedField::Recovery,
                operation: Operation::Recover,
            },
        );
    }
    verify_plan(&plan)?;
    if plan.report.status == "no_op" {
        if plan
            .report
            .changes
            .iter()
            .any(|c| c.operation == Operation::Recover)
        {
            plan.report.status = "recovered";
        }
        return Ok(plan.report);
    }
    plan.request.prepare_roots()?;
    let area = area(&plan.request, &plan.ownership.set_id);
    ensure(&area, plan.request.uid, true)?;
    let paths = serde_json::to_vec(&plan.ownership.targets).map_err(|_| Error::Io)?;
    let index = area.join("targets.json");
    if let Some(existing) = read(&index, plan.request.uid)? {
        if existing.bytes != paths {
            return Err(Error::Conflict);
        }
    } else {
        atomic(&index, &paths, plan.request.uid)?;
    }
    let ownership = serde_json::to_vec(&plan.ownership).map_err(|_| Error::Io)?;
    let transaction_id = ulid::Ulid::new().to_string();
    let tx = area.join("backups").join(&transaction_id);
    ensure(&tx, plan.request.uid, true)?;
    let mut intent = Intent {
        version: 1,
        transaction_id,
        set_id: plan.ownership.set_id.clone(),
        targets: plan.ownership.targets.clone(),
        before_ownership: plan.before_ownership.clone(),
        after_ownership: hash(&ownership),
        files: Vec::new(),
        created_dirs: Vec::new(),
    };
    for (index, target) in plan.targets.iter().enumerate() {
        if target.before.as_ref().map(|s| s.bytes.as_slice()) == target.after.as_deref() {
            continue;
        }
        let backup = if let Some(before) = &target.before {
            let backup_file = tx.join(format!("{index}.before"));
            write_new(&backup_file, &before.bytes, 0o600, plan.request.uid)?;
            Some(backup_file)
        } else {
            None
        };
        let staged = target.after.as_ref().map(|_| {
            target
                .path
                .with_file_name(format!(".xmsg-install-{}.tmp", ulid::Ulid::new()))
        });
        intent.files.push(IntentFile {
            path: target.path.clone(),
            before: target.before.as_ref().map(|s| s.fingerprint.clone()),
            after: None,
            after_hash: target.after.as_ref().map(|b| hash(b)),
            mode: target.mode,
            backup,
            staged,
        });
    }
    let journal = area.join("intent.json");
    save_intent(&journal, &intent, plan.request.uid)?;
    for file in &mut intent.files {
        intent.created_dirs.extend(ensure(
            file.path.parent().ok_or(Error::Unsafe)?,
            plan.request.uid,
            false,
        )?);
        if let Some(staged) = &file.staged {
            let target = plan
                .targets
                .iter()
                .find(|t| t.path == file.path)
                .ok_or(Error::Conflict)?;
            write_new(
                staged,
                target.after.as_ref().ok_or(Error::Conflict)?,
                file.mode,
                plan.request.uid,
            )?;
            file.after = Some(
                read(staged, plan.request.uid)?
                    .ok_or(Error::Conflict)?
                    .fingerprint,
            );
        }
    }
    save_intent(&journal, &intent, plan.request.uid)?;
    atomic(
        &tx.join("manifest.json"),
        &serde_json::to_vec(&intent).map_err(|_| Error::Io)?,
        plan.request.uid,
    )?;
    ensure(
        &plan.request.state_root.join("install/claude"),
        plan.request.uid,
        true,
    )?;
    let reference = plan
        .request
        .state_root
        .join("install/claude")
        .join(format!("{}.json", plan.ownership.set_id));
    let reference_data =
        serde_json::to_vec(&serde_json::json!({"version":1,"set_id":plan.ownership.set_id}))
            .map_err(|_| Error::Io)?;
    if read(&reference, plan.request.uid)?.is_none_or(|s| s.bytes != reference_data) {
        atomic(&reference, &reference_data, plan.request.uid)?;
    }
    #[cfg(test)]
    BEFORE_PUBLICATION.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook()
        }
    });
    for (index, file) in intent.files.iter().enumerate() {
        let current = read(&file.path, plan.request.uid)?;
        if current.as_ref().map(|s| &s.fingerprint) != file.before.as_ref() {
            return Err(Error::Drift);
        }
        if ownership_hash(&plan.request, &plan.ownership.set_id)? != plan.before_ownership {
            return Err(Error::Drift);
        }
        if let Some(staged) = &file.staged {
            rename(staged, &file.path)?;
        } else {
            unlink(&file.path)?;
        }
        #[cfg(test)]
        AFTER_PUBLICATION.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook(index)
            }
        });
        #[cfg(not(test))]
        let _ = index;
    }
    for file in &intent.files {
        if !match_state(
            read(&file.path, plan.request.uid)?.as_ref(),
            file.after.as_ref(),
        ) {
            return Err(Error::Drift);
        }
    }
    atomic(&area.join("ownership.json"), &ownership, plan.request.uid)?;
    unlink(&journal)?;
    plan.report.status = if plan
        .report
        .changes
        .iter()
        .any(|c| c.operation == Operation::Conflict)
    {
        "conflict"
    } else {
        "applied"
    };
    Ok(plan.report)
}
