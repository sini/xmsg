use crate::{
    capability::ResolvedDispatch,
    control::ErrorCode,
    eligibility::{EffectFacts, Eligibility},
    runtime_config::RuntimeConfig,
};

pub(crate) struct RuntimePolicy {
    pub(crate) configuration: RuntimeConfig,
    eligibility: Eligibility,
}

impl RuntimePolicy {
    pub(crate) fn reviewed(configuration: RuntimeConfig) -> Result<Self, ErrorCode> {
        configuration.validate()?;
        Ok(Self {
            configuration,
            eligibility: Eligibility::reviewed(),
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
        program.adapter.verify()?;
        program.native.verify()?;
        let (host, kernel) = runtime_envelope()?;
        let now = clock()?;
        self.eligibility.require(&EffectFacts {
            key: &resolved.qualification,
            adapter_sha256: &program.adapter.sha256,
            native_sha256: &program.native.sha256,
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
    ) -> Self {
        Self {
            configuration,
            eligibility: Eligibility::fixture(records),
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
