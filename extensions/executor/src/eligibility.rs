use crate::{capability::QualificationKey, control::ErrorCode};

#[derive(Clone)]
pub(crate) struct AdapterQualification {
    pub(crate) key: QualificationKey,
    pub(crate) adapter_sha256: String,
    pub(crate) native_sha256: String,
    pub(crate) operating_system: String,
    pub(crate) architecture: String,
    pub(crate) kernel: String,
    pub(crate) policy_revision: u64,
    pub(crate) expires_at: i64,
    pub(crate) revoked: bool,
}

pub(crate) struct Eligibility {
    records: Vec<AdapterQualification>,
}

pub(crate) struct EffectFacts<'a> {
    pub(crate) key: &'a QualificationKey,
    pub(crate) adapter_sha256: &'a str,
    pub(crate) native_sha256: &'a str,
    pub(crate) operating_system: &'a str,
    pub(crate) architecture: &'a str,
    pub(crate) kernel: &'a str,
    pub(crate) policy_revision: u64,
    pub(crate) now: i64,
    pub(crate) emergency_disabled: bool,
}

impl Eligibility {
    pub(crate) fn reviewed() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    pub(crate) fn require(&self, facts: &EffectFacts<'_>) -> Result<(), ErrorCode> {
        if facts.emergency_disabled {
            return Err(ErrorCode::ProfileDenied);
        }
        if self.records.iter().any(|r| {
            !r.revoked
                && r.expires_at > facts.now
                && r.key == *facts.key
                && r.adapter_sha256 == facts.adapter_sha256
                && r.native_sha256 == facts.native_sha256
                && r.operating_system == facts.operating_system
                && r.architecture == facts.architecture
                && r.kernel == facts.kernel
                && r.policy_revision == facts.policy_revision
        }) {
            Ok(())
        } else {
            Err(ErrorCode::NotSupported)
        }
    }

    #[cfg(test)]
    pub(crate) fn fixture(records: Vec<AdapterQualification>) -> Self {
        Self { records }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        capability::{ReviewMode, TrustProfile},
        protocol::Model,
    };

    #[test]
    fn eligibility_requires_exact_live_record_for_every_effect() {
        let key = QualificationKey {
            pin_id: "fixture".into(),
            adapter_version: "1".into(),
            runtime_version: "1".into(),
            protocol_version: 1,
            profile: TrustProfile::Safe,
            native_mode: "manual".into(),
            review_mode: ReviewMode::HumanOnly,
            protocol_schema: "schema".into(),
            model: Model {
                provider: "fixture".into(),
                name: "none".into(),
            },
            effective_config_digest: "config".into(),
        };
        let record = AdapterQualification {
            key: key.clone(),
            adapter_sha256: "adapter".into(),
            native_sha256: "native".into(),
            operating_system: "fixture-os".into(),
            architecture: "fixture-arch".into(),
            kernel: "fixture-kernel".into(),
            policy_revision: 1,
            expires_at: 20,
            revoked: false,
        };
        let mut facts = EffectFacts {
            key: &key,
            adapter_sha256: "adapter",
            native_sha256: "native",
            operating_system: "fixture-os",
            architecture: "fixture-arch",
            kernel: "fixture-kernel",
            policy_revision: 1,
            now: 10,
            emergency_disabled: false,
        };
        assert_eq!(
            Eligibility::reviewed().require(&facts),
            Err(ErrorCode::NotSupported)
        );
        let eligibility = Eligibility::fixture(vec![record.clone()]);
        assert_eq!(eligibility.require(&facts), Ok(()));
        facts.emergency_disabled = true;
        assert_eq!(eligibility.require(&facts), Err(ErrorCode::ProfileDenied));
        facts.emergency_disabled = false;
        facts.now = 20;
        assert!(eligibility.require(&facts).is_err());
        facts.now = 10;
        facts.policy_revision = 2;
        assert!(eligibility.require(&facts).is_err());
        facts.policy_revision = 1;
        facts.kernel = "changed-kernel";
        assert!(eligibility.require(&facts).is_err());
        facts.kernel = "fixture-kernel";
        let mut revoked = record;
        revoked.revoked = true;
        assert!(Eligibility::fixture(vec![revoked]).require(&facts).is_err());
    }
}
