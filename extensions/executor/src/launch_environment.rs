use crate::control::ErrorCode;
use serde::{Deserialize, Serialize};
use std::{
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchEnvironment {
    #[serde(default)]
    pub search_path: Vec<PathBuf>,
    #[serde(default)]
    pub account_home: Option<PathBuf>,
}
impl LaunchEnvironment {
    pub fn validate(&self) -> Result<(), ErrorCode> {
        self.validate_paths()?;
        if let Some(home) = &self.account_home {
            validate_home(home, &passwd_home()?)?;
        }
        Ok(())
    }
    fn validate_paths(&self) -> Result<(), ErrorCode> {
        if self.search_path.len() > 32 {
            return Err(ErrorCode::InvalidConfiguration);
        }
        for dir in &self.search_path {
            if !dir.is_absolute() || !dir.is_dir() {
                return Err(ErrorCode::InvalidConfiguration);
            }
        }
        std::env::join_paths(&self.search_path).map_err(|_| ErrorCode::InvalidConfiguration)?;
        Ok(())
    }
    pub(crate) fn apply(&self, command: &mut Command) -> Result<(), ErrorCode> {
        command.env_clear().envs(self.snapshot()?);
        Ok(())
    }
    pub(crate) fn snapshot(
        &self,
    ) -> Result<Vec<(std::ffi::OsString, std::ffi::OsString)>, ErrorCode> {
        self.validate()?;
        let mut entries = vec![(
            std::ffi::OsString::from("PATH"),
            std::env::join_paths(&self.search_path).map_err(|_| ErrorCode::InvalidConfiguration)?,
        )];
        if let Some(home) = &self.account_home {
            entries.push((
                std::ffi::OsString::from("HOME"),
                home.canonicalize()
                    .map_err(|_| ErrorCode::InvalidConfiguration)?
                    .into_os_string(),
            ));
        }
        Ok(entries)
    }
}

fn validate_home(configured: &Path, actual: &Path) -> Result<(), ErrorCode> {
    if !configured.is_absolute() || !actual.is_absolute() {
        return Err(ErrorCode::InvalidConfiguration);
    }
    let configured = configured
        .canonicalize()
        .map_err(|_| ErrorCode::InvalidConfiguration)?;
    let actual = actual
        .canonicalize()
        .map_err(|_| ErrorCode::InvalidConfiguration)?;
    let metadata = std::fs::metadata(&configured).map_err(|_| ErrorCode::InvalidConfiguration)?;
    if configured != actual || !metadata.is_dir() || metadata.uid() != xmsg::client::current_uid() {
        return Err(ErrorCode::InvalidConfiguration);
    }
    Ok(())
}

fn passwd_home() -> Result<PathBuf, ErrorCode> {
    let uid = xmsg::client::current_uid();
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0u8; 65536];
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() || entry.pw_dir.is_null() || entry.pw_uid != uid {
        return Err(ErrorCode::InvalidConfiguration);
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }.to_bytes();
    if bytes.is_empty() {
        return Err(ErrorCode::InvalidConfiguration);
    }
    let home = PathBuf::from(std::ffi::OsStr::from_bytes(bytes));
    if !home.is_absolute() {
        return Err(ErrorCode::InvalidConfiguration);
    }
    Ok(home)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owned_alternate_home_is_refused_and_canonical_alias_is_allowed() {
        let real = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let alias = real.path().join("home-alias");
        std::os::unix::fs::symlink(real.path(), &alias).unwrap();
        assert_eq!(validate_home(&alias, real.path()), Ok(()));
        assert_eq!(
            validate_home(other.path(), real.path()),
            Err(ErrorCode::InvalidConfiguration)
        );
    }
    #[test]
    fn environment_is_fixed_and_has_no_arbitrary_provider_or_model_passthrough() {
        let root = tempfile::tempdir().unwrap();
        let mut command = Command::new("/fixture/not-run");
        command
            .env("CODEX_HOME", "untrusted")
            .env("OPENAI_API_KEY", "not-a-secret");
        let environment = LaunchEnvironment {
            search_path: vec![root.path().into()],
            account_home: None,
        };
        environment.apply(&mut command).unwrap();
        let keys: Vec<_> = command
            .get_envs()
            .filter_map(|(k, v)| v.map(|_| k.to_os_string()))
            .collect();
        assert_eq!(keys, vec![std::ffi::OsString::from("PATH")]);
        assert!(serde_json::from_value::<LaunchEnvironment>(
            serde_json::json!({"environment":{"HOME":"other"}})
        )
        .is_err());
        assert!(LaunchEnvironment {
            search_path: vec!["relative".into()],
            account_home: None
        }
        .validate()
        .is_err());
    }
}
