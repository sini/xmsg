use crate::{
    capability::ResolvedDispatch,
    control::ErrorCode,
    eligibility::{EffectFacts, Eligibility},
    runtime_config::{ExecutableArtifact, RuntimeConfig},
};
use std::sync::Arc;

struct ProgramArtifacts {
    pin_id: String,
    adapter: Option<ExecutableArtifact>,
    native: Option<ExecutableArtifact>,
}
fn observe_programs(configuration: &RuntimeConfig) -> Vec<ProgramArtifacts> {
    configuration
        .programs
        .iter()
        .map(|p| ProgramArtifacts {
            pin_id: p.pin_id.clone(),
            adapter: p.adapter.observe_verified().ok(),
            native: p.native.observe_verified().ok(),
        })
        .collect()
}

pub(crate) struct RuntimePolicy {
    pub(crate) configuration: RuntimeConfig,
    eligibility: Eligibility,
    executor: Arc<ExecutableArtifact>,
    programs: Vec<ProgramArtifacts>,
}

impl RuntimePolicy {
    pub(crate) fn reviewed(configuration: RuntimeConfig) -> Result<Self, ErrorCode> {
        configuration.validate()?;
        let eligibility = Eligibility::reviewed();
        let executor = Arc::new(ExecutableArtifact::observe(
            &std::env::current_exe().map_err(|_| ErrorCode::Storage)?,
        )?);
        let programs = if eligibility.is_empty() {
            vec![]
        } else {
            observe_programs(&configuration)
        };
        Ok(Self {
            configuration,
            eligibility,
            executor,
            programs,
        })
    }

    pub(crate) fn require(
        &self,
        resolved: &ResolvedDispatch,
        revision: u64,
        now: i64,
        emergency_disabled: bool,
    ) -> Result<(), ErrorCode> {
        self.require_at(resolved, revision, &|| Ok(now), emergency_disabled)
    }

    pub(crate) fn require_at(
        &self,
        resolved: &ResolvedDispatch,
        revision: u64,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
        emergency_disabled: bool,
    ) -> Result<(), ErrorCode> {
        if emergency_disabled {
            return Err(ErrorCode::ProfileDenied);
        }
        if self.eligibility.is_empty() {
            return Err(ErrorCode::NotSupported);
        }
        let program = self.configuration.program_for(resolved)?;
        if self.configuration.effective_digest(resolved)?
            != resolved.qualification.effective_config_digest
        {
            return Err(ErrorCode::InvalidConfiguration);
        }
        self.executor.unchanged()?;
        let observed = self
            .programs
            .iter()
            .find(|p| p.pin_id == program.pin_id)
            .ok_or(ErrorCode::InvalidConfiguration)?;
        let adapter = observed
            .adapter
            .as_ref()
            .ok_or(ErrorCode::InvalidConfiguration)?;
        let native = observed
            .native
            .as_ref()
            .ok_or(ErrorCode::InvalidConfiguration)?;
        adapter.unchanged()?;
        native.unchanged()?;
        if adapter.sha256 != program.adapter.sha256 || native.sha256 != program.native.sha256 {
            return Err(ErrorCode::InvalidConfiguration);
        }
        let (host, kernel) = runtime_envelope()?;
        let now = clock()?;
        self.eligibility.require(&EffectFacts {
            key: &resolved.qualification,
            adapter_sha256: &program.adapter.sha256,
            native_sha256: &program.native.sha256,
            executor_sha256: &self.executor.sha256,
            required_capabilities: &resolved.required_capabilities,
            host: &host,
            uid: xmsg::client::current_uid(),
            operating_system: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            kernel: &kernel,
            policy_revision: revision,
            now,
            emergency_disabled,
        })
    }

    #[cfg(test)]
    pub(crate) fn fixture(
        configuration: RuntimeConfig,
        records: Vec<crate::eligibility::AdapterQualification>,
        executor: Arc<ExecutableArtifact>,
    ) -> Self {
        let programs = observe_programs(&configuration);
        Self {
            configuration,
            eligibility: Eligibility::fixture(records),
            executor,
            programs,
        }
    }
}

pub(crate) fn runtime_envelope() -> Result<(String, String), ErrorCode> {
    let mut value: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut value) } != 0 {
        return Err(ErrorCode::AttestationUnavailable);
    }
    let host = unsafe { std::ffi::CStr::from_ptr(value.nodename.as_ptr()) }
        .to_str()
        .map_err(|_| ErrorCode::AttestationUnavailable)?
        .to_owned();
    let kernel = unsafe { std::ffi::CStr::from_ptr(value.release.as_ptr()) }
        .to_str()
        .map_err(|_| ErrorCode::AttestationUnavailable)?
        .to_owned();
    if host.is_empty() || kernel.is_empty() {
        return Err(ErrorCode::AttestationUnavailable);
    }
    Ok((host, kernel))
}
