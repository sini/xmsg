//! Shared executable-fixture writer for integration tests.
//!
//! Writes an executable fixture from a child process (this test binary re-exec'd on
//! [`writer_child`]), so the parent test process never holds a write descriptor on the file:
//! a sibling test thread's `fork` can never carry one into an `execve` window, avoiding `ETXTBSY`,
//! and no external `PATH` utilities are required.
#![allow(dead_code)]

#[allow(clippy::duplicate_mod)]
#[path = "../support/spawn.rs"]
mod spawn;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const WRITE_EXE_TARGET: &str = "XMSG_TEST_WRITE_EXE_TARGET";

/// Writes `contents` to `path` with mode `0755` from a re-exec'd child process and renames into
/// place, ensuring this process never opens a write descriptor on `path`.
pub fn write_exe(path: &Path, contents: impl AsRef<[u8]>) {
    use std::io::Write;
    let mut child = spawn::command(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "write_exe::writer_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(WRITE_EXE_TARGET, path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(contents.as_ref())
        .unwrap();
    assert!(
        child.wait().unwrap().success(),
        "write_exe {}",
        path.display()
    );
    let meta = fs::metadata(path).unwrap();
    assert!(
        meta.permissions().mode() & 0o111 != 0,
        "write_exe left {} non-executable",
        path.display()
    );
}

/// The writer half of [`write_exe`]; a fast no-op unless re-exec'd with [`WRITE_EXE_TARGET`] set.
#[test]
fn writer_child() {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let Some(target) = std::env::var_os(WRITE_EXE_TARGET) else {
        return;
    };
    let target = PathBuf::from(target);
    let mut tmp_os = target.as_os_str().to_os_string();
    tmp_os.push(format!(".write-exe-{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp_os);
    let mut body = Vec::new();
    std::io::stdin().read_to_end(&mut body).unwrap();
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .open(&tmp)
        .unwrap();
    std::io::Write::write_all(&mut f, &body).unwrap();
    f.sync_all().unwrap();
    drop(f);
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).unwrap();
    fs::rename(&tmp, &target).unwrap();
}
