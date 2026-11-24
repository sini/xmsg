use crate::{
    capability::{Capability, QualificationKey},
    control::ErrorCode,
};

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct AdapterQualification {
    pub(crate) key: QualificationKey,
    pub(crate) adapter_sha256: String,
    pub(crate) native_sha256: String,
    pub(crate) executor_sha256: String,
    pub(crate) capabilities: Vec<Capability>,
    pub(crate) host: String,
    pub(crate) uid: u32,
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
    pub(crate) executor_sha256: &'a str,
    pub(crate) required_capabilities: &'a [Capability],
    pub(crate) host: &'a str,
    pub(crate) uid: u32,
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

    pub(crate) fn is_empty(&self) -> bool {
        self.records.is_empty()
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
                && r.executor_sha256 == facts.executor_sha256
                && facts
                    .required_capabilities
                    .iter()
                    .all(|c| r.capabilities.contains(c))
                && r.host == facts.host
                && r.uid == facts.uid
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
    pub(crate) fn fixture_records(&self) -> Vec<AdapterQualification> {
        self.records.clone()
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
            executor_sha256: "executor".into(),
            capabilities: vec![],
            host: "fixture-host".into(),
            uid: 123,
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
            executor_sha256: "executor",
            required_capabilities: &[],
            host: "fixture-host",
            uid: 123,
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
        let required = [Capability::StrictSteer];
        facts.required_capabilities = &required;
        assert!(eligibility.require(&facts).is_err());
        facts.required_capabilities = &[];
        facts.host = "other-host";
        assert!(eligibility.require(&facts).is_err());
        facts.host = "fixture-host";
        facts.uid = 124;
        assert!(eligibility.require(&facts).is_err());
        facts.uid = 123;
        facts.adapter_sha256 = "changed-adapter";
        assert!(eligibility.require(&facts).is_err());
        facts.adapter_sha256 = "adapter";
        facts.native_sha256 = "changed-native";
        assert!(eligibility.require(&facts).is_err());
        facts.native_sha256 = "native";
        facts.executor_sha256 = "other-executor";
        assert!(eligibility.require(&facts).is_err());
        facts.executor_sha256 = "executor";
        facts.operating_system = "other-os";
        assert!(eligibility.require(&facts).is_err());
        facts.operating_system = "fixture-os";
        facts.architecture = "other-arch";
        assert!(eligibility.require(&facts).is_err());
        facts.architecture = "fixture-arch";
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
