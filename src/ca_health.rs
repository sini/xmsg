use rustls::pki_types::{pem::PemObject, CertificateDer};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_CERT: u64 = 1_048_576;

#[derive(Clone, Default)]
pub struct Config {
    pub enabled: Option<bool>,
    pub ca_dir: Option<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Check {
    pub id: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub source: String,
    pub enabled: Option<bool>,
    pub pending_approvals: Option<usize>,
    pub checks: Vec<Check>,
}

impl Report {
    fn new(source: &str, enabled: Option<bool>) -> Self {
        Self {
            source: source.into(),
            enabled,
            pending_approvals: None,
            checks: Vec::new(),
        }
    }
    fn add(&mut self, id: &str, status: &str, message: &str) {
        self.checks.push(Check {
            id: format!("ca.{id}"),
            status: status.into(),
            message: message.into(),
        });
    }
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|n| n.as_secs() as i64)
        .unwrap_or(0)
}

fn root(report: &mut Report, pem: &[u8], now: i64) {
    let parsed = (|| {
        if pem.len() as u64 > MAX_CERT {
            return None;
        }
        let der = CertificateDer::from_pem_slice(pem).ok()?;
        let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
        let before = cert.validity().not_before.timestamp();
        let after = cert.validity().not_after.timestamp();
        Some((before, after, cert.is_ca()))
    })();
    match parsed {
        Some((before, after, true)) if after > before => {
            let remaining = after.saturating_sub(now);
            let warning_window = (7 * 86400).min((after - before) / 3);
            let (status, reason) = if after <= now {
                ("fail", "CA root certificate has expired.")
            } else if before > now {
                ("fail", "CA root certificate is not yet valid.")
            } else if remaining <= warning_window {
                ("warn", "CA root certificate is near expiry.")
            } else {
                ("pass", "CA root certificate is within its validity period.")
            };
            report.add("root_expiry", status, reason);
        }
        _ => report.add(
            "root_expiry",
            "fail",
            "CA public root certificate is invalid or unavailable.",
        ),
    }
}

fn metadata_ok(metadata: &fs::Metadata, key: bool) -> bool {
    metadata.is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.len() <= MAX_CERT
        && metadata.mode() & if key { 0o077 } else { 0o022 } == 0
        && metadata.mode() & 0o400 != 0
}

fn signing_key(report: &mut Report, directory: &Path) {
    let key = directory.join("root.key");
    match fs::symlink_metadata(&key) {
        Ok(metadata) => {
            let kind = metadata.file_type();
            let kind = if kind.is_file() { "regular" } else if kind.is_symlink() { "symlink" }
                else if kind.is_dir() { "directory" } else if kind.is_fifo() { "fifo" }
                else if kind.is_socket() { "socket" } else { "other" };
            let valid = metadata_ok(&metadata, true);
            report.add("signing_key_metadata", if valid { "pass" } else { "warn" },
                &format!("Signing key metadata: present=true, type={kind}, mode={:04o}, owned_by_current_uid={}, owner_read_bit={}, size_bytes={}. Contents, validity, matching, actual readability and issuance are not tested.", metadata.mode() & 0o7777, metadata.uid() == unsafe { libc::geteuid() }, metadata.mode() & 0o400 != 0, metadata.len()));
        }
        Err(error) => report.add("signing_key_metadata", "warn", if error.kind() == std::io::ErrorKind::NotFound {
            "Signing key metadata: present=false. The daemon may retain its loaded signer; issuance is not tested."
        } else {
            "Signing key metadata: presence, type and permissions unknown because stat is unavailable; issuance is not tested."
        }),
    }
}

pub fn installed(directory: &Path, now: i64) -> Report {
    let mut report = Report::new("installed_not_loaded", None);
    let bytes = (|| -> std::io::Result<Vec<u8>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(directory.join("root.crt"))?;
        if !metadata_ok(&file.metadata()?, false) {
            return Err(std::io::Error::other("invalid public root metadata"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_CERT + 1).read_to_end(&mut bytes)?;
        Ok(bytes)
    })();
    match bytes {
        Ok(bytes) => root(&mut report, &bytes, now),
        Err(_) => report.add("root_expiry", "warn", "Installed public CA root is unavailable or has unacceptable file metadata; expiry is unknown."),
    }
    signing_key(&mut report, directory);
    report.add(
        "configuration",
        "warn",
        "Enabled state is unknown; installed files do not establish runtime configuration.",
    );
    report.add(
        "pending_approvals",
        "warn",
        "Pending device approval count is unknown without the running authority.",
    );
    report
}

pub fn live(config: &Config, service: Option<&Arc<crate::enroll::Service>>, now: i64) -> Report {
    let mut report = Report::new("runtime", config.enabled);
    report.add(
        "configuration",
        if config.enabled.is_some() {
            "pass"
        } else {
            "warn"
        },
        match config.enabled {
            Some(true) => "Enrollment is enabled in the daemon's parsed configuration.",
            Some(false) => "Enrollment is disabled in the daemon's parsed configuration.",
            None => "Enrollment enabled state is unknown.",
        },
    );
    if config.enabled == Some(false) {
        return report;
    }
    if let Some(service) = service {
        root(&mut report, service.ca.root_pem().as_bytes(), now);
        let degraded = service.ca.reload_status().degraded;
        report.add(
            "policy_reload",
            if degraded { "warn" } else { "pass" },
            if degraded {
                "Authority policy reload is degraded; the last accepted policy remains loaded."
            } else {
                "Authority policy reload is healthy."
            },
        );
        let count = service.pending_device_approval_count();
        report.pending_approvals = Some(count);
        report.add(
            "pending_approvals",
            if count == 0 { "pass" } else { "warn" },
            &format!("Pending device approvals: {count}."),
        );
    } else {
        report.add(
            "root_expiry",
            "warn",
            "Loaded CA root is unavailable; authority application health is unknown.",
        );
        report.add(
            "pending_approvals",
            "warn",
            "Pending device approval count is unknown without the running authority.",
        );
    }
    if let Some(directory) = &config.ca_dir {
        signing_key(&mut report, directory);
    } else {
        report.add(
            "signing_key_metadata",
            "warn",
            "Signing key metadata is unknown because no runtime CA directory is available.",
        );
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn certificate(before: i64, after: i64) -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.not_before = time::OffsetDateTime::from_unix_timestamp(before).unwrap();
        params.not_after = time::OffsetDateTime::from_unix_timestamp(after).unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn root_expiry_boundaries() {
        let pem = certificate(1_000_000, 1_900_000);
        for (now, expected) in [
            (1_100_000, "pass"),
            (1_600_000, "warn"),
            (1_900_000, "fail"),
            (999_999, "fail"),
        ] {
            let mut report = Report::new("fixture", None);
            root(&mut report, pem.as_bytes(), now);
            assert_eq!(
                report.checks[0].status, expected,
                "root expiry boundary {now}"
            );
        }
        let pem = certificate(1_000_000, 10_000_000);
        for (now, expected) in [(9_395_199, "pass"), (9_395_200, "warn")] {
            let mut report = Report::new("fixture", None);
            root(&mut report, pem.as_bytes(), now);
            assert_eq!(
                report.checks[0].status, expected,
                "seven-day warning boundary"
            );
        }
    }

    #[test]
    fn configuration_and_installed_metadata() {
        let disabled = live(
            &Config {
                enabled: Some(false),
                ca_dir: None,
            },
            None,
            0,
        );
        assert_eq!(disabled.enabled, Some(false));
        assert!(disabled.checks.iter().all(|c| c.status == "pass"));
        let unknown = live(&Config::default(), None, 0);
        assert_eq!(unknown.enabled, None);
        assert!(unknown.checks.iter().all(|c| c.status == "warn"));
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("root.crt"),
            certificate(1_000_000, 1_900_000),
        )
        .unwrap();
        let key = dir.path().join("root.key");
        fs::write(&key, b"SYNTHETIC-KEY-CANARY-NOT-A-CREDENTIAL").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let report = installed(dir.path(), 1_100_000);
        assert_eq!(report.source, "installed_not_loaded");
        assert_eq!(report.enabled, None);
        assert_eq!(report.pending_approvals, None);
        assert!(report.checks[..2].iter().all(|c| c.status == "pass"));
        assert!(report.checks[1]
            .message
            .contains("present=true, type=regular, mode=0600"));
        assert!(report.checks[1]
            .message
            .contains("owned_by_current_uid=true, owner_read_bit=true"));

        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(installed(dir.path(), 1_100_000).checks[1].status, "warn");
        fs::remove_file(&key).unwrap();
        std::os::unix::fs::symlink(dir.path().join("root.crt"), &key).unwrap();
        assert_eq!(installed(dir.path(), 1_100_000).checks[1].status, "warn");
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains("SYNTHETIC-KEY-CANARY"));
        fs::remove_file(&key).unwrap();
        let missing = installed(dir.path(), 1_100_000);
        assert_eq!(missing.checks[1].status, "warn");
        assert!(missing.checks[1].message.contains("present=false"));
        fs::remove_file(dir.path().join("root.crt")).unwrap();
        assert_eq!(installed(dir.path(), 1_100_000).checks[0].status, "warn");
    }

    #[test]
    fn key_probe_child() {
        if let Some(directory) = std::env::var_os("CA_HEALTH_FIXTURE_DIRECTORY") {
            let report = installed(Path::new(&directory), now());
            assert_eq!(report.checks[1].status, "warn");
        }
    }

    #[test]
    fn signing_key_fifo_is_never_opened() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("root.key");
        let name = std::ffi::CString::new(key.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let mut sentinel = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&key)
            .unwrap();
        let canary = b"SYNTHETIC-FIFO-CANARY";
        sentinel.write_all(canary).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ca_health::tests::key_probe_child",
                "--nocapture",
            ])
            .env("CA_HEALTH_FIXTURE_DIRECTORY", dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            status.is_some_and(|s| s.success()),
            "diagnostic opened or blocked on signing-key FIFO"
        );
        let mut remaining = [0u8; 128];
        let bytes = sentinel
            .read(&mut remaining)
            .expect("diagnostic consumed signing-key FIFO canary");
        assert_eq!(
            &remaining[..bytes],
            canary,
            "diagnostic consumed signing-key FIFO canary"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn signing_key_regular_file_is_never_opened() {
        use std::os::fd::{AsRawFd, FromRawFd};
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("root.key");
        fs::write(&key, b"SYNTHETIC-REGULAR-KEY-CANARY").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(fd >= 0);
        let mut watch = unsafe { fs::File::from_raw_fd(fd) };
        let name = std::ffi::CString::new(key.as_os_str().as_encoded_bytes()).unwrap();
        assert!(
            unsafe {
                libc::inotify_add_watch(
                    watch.as_raw_fd(),
                    name.as_ptr(),
                    libc::IN_OPEN | libc::IN_ACCESS,
                )
            } >= 0
        );
        let report = installed(dir.path(), now());
        assert_eq!(report.checks[1].status, "pass");
        let mut events = [0u8; 1024];
        let result = watch.read(&mut events);
        assert!(
            result.is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock),
            "diagnostic opened or accessed regular signing key"
        );
    }
}
