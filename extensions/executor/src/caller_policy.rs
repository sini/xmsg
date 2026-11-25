use crate::auth::TrustedPrincipal;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MissingTrustProperty {
    ScopedCallerEvidence,
    ProtectedPolicyStore,
    ExactCallerQualification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScopeKind {
    Claude,
    Agy,
    Codex {
        root_generation: u64,
        child_generation: Option<u64>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct CallerScope {
    kind: ScopeKind,
    matched_pid: u32,
    matched_start: String,
    registration_digest: String,
    attestor_epoch: String,
    context_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedCallerContext {
    principal: String,
    peer_uid: u32,
    binding: crate::auth::CallBinding,
    scope: CallerScope,
}
impl TrustedCallerContext {
    pub(crate) fn from_attestation(
        principal: &TrustedPrincipal,
    ) -> Result<Self, MissingTrustProperty> {
        let stamp = principal
            .authority_stamp()
            .ok_or(MissingTrustProperty::ScopedCallerEvidence)?;
        let epoch = principal
            .attestor_epoch()
            .ok_or(MissingTrustProperty::ScopedCallerEvidence)?;
        let context_digest = principal
            .context_digest()
            .ok_or(MissingTrustProperty::ScopedCallerEvidence)?;
        let binding = principal.binding();
        checked_binding(principal.id(), binding)?;
        let scope = checked_scope(stamp, epoch, context_digest)?;
        Ok(Self {
            principal: principal.id().to_owned(),
            peer_uid: binding.peer.uid,
            binding: binding.clone(),
            scope,
        })
    }
    pub(crate) fn principal(&self) -> &str {
        &self.principal
    }
}

fn checked_binding(
    principal: &str,
    binding: &crate::auth::CallBinding,
) -> Result<(), MissingTrustProperty> {
    if !bounded_text(principal, 1024)
        || binding.call_nonce == 0
        || binding.peer.pid.is_none_or(|pid| pid == 0)
        || !hex_digest(&binding.input_digest, 64)
    {
        return Err(MissingTrustProperty::ScopedCallerEvidence);
    }
    Ok(())
}

fn checked_scope(
    stamp: &xmsg::client::caller_attribution::AuthorityStamp,
    epoch: &str,
    context_digest: &str,
) -> Result<CallerScope, MissingTrustProperty> {
    if stamp.matched_pid == 0
        || !bounded_text(&stamp.matched_start, 128)
        || !hex_digest(&stamp.registration_digest, 64)
        || !hex_digest(epoch, 32)
        || !hex_digest(context_digest, 64)
    {
        return Err(MissingTrustProperty::ScopedCallerEvidence);
    }
    let kind = match (
        stamp.source.as_str(),
        stamp.root_generation,
        stamp.child_generation,
    ) {
        ("claude", None, None) => ScopeKind::Claude,
        ("agy", None, None) => ScopeKind::Agy,
        ("codex", Some(root), child) if root > 0 && child.is_none_or(|child| child > 0) => {
            ScopeKind::Codex {
                root_generation: root,
                child_generation: child,
            }
        }
        _ => return Err(MissingTrustProperty::ScopedCallerEvidence),
    };
    Ok(CallerScope {
        kind,
        matched_pid: stamp.matched_pid,
        matched_start: stamp.matched_start.clone(),
        registration_digest: stamp.registration_digest.clone(),
        attestor_epoch: epoch.to_owned(),
        context_digest: context_digest.to_owned(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct CallerRuntimeFacts {
    pub(crate) host: String,
    pub(crate) uid: u32,
    pub(crate) operating_system: String,
    pub(crate) architecture: String,
    pub(crate) kernel: String,
    pub(crate) executor_sha256: String,
    pub(crate) caller_artifact_sha256: String,
    pub(crate) caller_configuration_sha256: String,
    pub(crate) caller_pin_id: String,
    pub(crate) caller_runtime_version: String,
    pub(crate) caller_mode: String,
    pub(crate) caller_protocol: String,
}
impl CallerRuntimeFacts {
    fn valid(&self) -> bool {
        bounded_text(&self.host, 256)
            && bounded_text(&self.operating_system, 64)
            && bounded_text(&self.architecture, 64)
            && bounded_text(&self.kernel, 256)
            && bounded_text(&self.caller_pin_id, 128)
            && bounded_text(&self.caller_runtime_version, 128)
            && bounded_text(&self.caller_mode, 64)
            && bounded_text(&self.caller_protocol, 128)
            && [
                &self.executor_sha256,
                &self.caller_artifact_sha256,
                &self.caller_configuration_sha256,
            ]
            .iter()
            .all(|value| hex_digest(value, 64))
    }
}
#[derive(Debug, Clone)]
struct CallerQualification {
    incarnation: Arc<()>,
    id: String,
    revision: u64,
    principal: String,
    scope: CallerScope,
    runtime: CallerRuntimeFacts,
    policy_revision: u64,
    expires_at: i64,
    revoked: bool,
}
impl CallerQualification {
    fn matches(
        &self,
        context: &TrustedCallerContext,
        runtime: &CallerRuntimeFacts,
        policy_revision: u64,
        now: i64,
    ) -> bool {
        bounded_text(&self.id, 128)
            && self.revision > 0
            && !self.revoked
            && self.expires_at > now
            && self.principal == context.principal
            && self.scope == context.scope
            && self.runtime == *runtime
            && self.policy_revision == policy_revision
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CallerRecordReference {
    provider: Arc<()>,
    context: TrustedCallerContext,
    record: CallerQualification,
}
impl CallerRecordReference {
    pub(crate) fn id(&self) -> &str {
        &self.record.id
    }
    pub(crate) fn revision(&self) -> u64 {
        self.record.revision
    }
    pub(crate) fn journal_receipt(&self) -> serde_json::Value {
        let (source, root_generation, child_generation) = match self.context.scope.kind {
            ScopeKind::Claude => ("claude", None, None),
            ScopeKind::Agy => ("agy", None, None),
            ScopeKind::Codex {
                root_generation,
                child_generation,
            } => ("codex", Some(root_generation), child_generation),
        };
        let scope = &self.context.scope;
        let binding = &self.context.binding;
        serde_json::json!({
            "record_id":self.record.id,"record_revision":self.record.revision,
            "policy_revision":self.record.policy_revision,"expires_at":self.record.expires_at,
            "runtime":self.record.runtime,
            "context":{"principal":self.context.principal,"peer_uid":self.context.peer_uid,
                "binding":{"peer_uid":binding.peer.uid,"peer_pid":binding.peer.pid,"call_nonce":binding.call_nonce,"input_digest":binding.input_digest},
                "scope":{"source":source,"matched_pid":scope.matched_pid,"matched_start":scope.matched_start,
                    "registration_digest":scope.registration_digest,"root_generation":root_generation,"child_generation":child_generation,
                    "attestor_epoch":scope.attestor_epoch,"context_digest":scope.context_digest}}
        })
    }
}

enum PolicyStoreEvidence {
    Unavailable,
    #[cfg(test)]
    TrustedFixture,
}
pub(crate) struct CallerEligibility {
    provider: Arc<()>,
    store: PolicyStoreEvidence,
    records: Vec<CallerQualification>,
}
impl CallerEligibility {
    pub(crate) fn reviewed() -> Self {
        Self {
            provider: Arc::new(()),
            store: PolicyStoreEvidence::Unavailable,
            records: vec![],
        }
    }
    pub(crate) fn require_protected_store(&self) -> Result<(), MissingTrustProperty> {
        self.protected()
    }
    fn protected(&self) -> Result<(), MissingTrustProperty> {
        match self.store {
            PolicyStoreEvidence::Unavailable => Err(MissingTrustProperty::ProtectedPolicyStore),
            #[cfg(test)]
            PolicyStoreEvidence::TrustedFixture => Ok(()),
        }
    }
    fn facts(
        &self,
        context: &TrustedCallerContext,
        runtime: &CallerRuntimeFacts,
        policy_revision: u64,
        now: i64,
    ) -> Result<(), MissingTrustProperty> {
        self.protected()?;
        if !runtime.valid() || runtime.uid != context.peer_uid || policy_revision == 0 || now <= 0 {
            return Err(MissingTrustProperty::ExactCallerQualification);
        }
        Ok(())
    }
    pub(crate) fn qualify(
        &self,
        context: &TrustedCallerContext,
        runtime: &CallerRuntimeFacts,
        policy_revision: u64,
        now: i64,
    ) -> Result<CallerRecordReference, MissingTrustProperty> {
        self.facts(context, runtime, policy_revision, now)?;
        let mut matching = self
            .records
            .iter()
            .filter(|record| record.matches(context, runtime, policy_revision, now));
        let record = matching
            .next()
            .ok_or(MissingTrustProperty::ExactCallerQualification)?;
        if matching.next().is_some()
            || self
                .records
                .iter()
                .filter(|other| other.id == record.id)
                .count()
                != 1
        {
            return Err(MissingTrustProperty::ExactCallerQualification);
        }
        Ok(CallerRecordReference {
            provider: self.provider.clone(),
            context: context.clone(),
            record: record.clone(),
        })
    }
    pub(crate) fn revalidate(
        &self,
        reference: &CallerRecordReference,
        context: &TrustedCallerContext,
        runtime: &CallerRuntimeFacts,
        policy_revision: u64,
        now: i64,
    ) -> Result<(), MissingTrustProperty> {
        self.facts(context, runtime, policy_revision, now)?;
        if context != &reference.context || !Arc::ptr_eq(&self.provider, &reference.provider) {
            return Err(MissingTrustProperty::ExactCallerQualification);
        }
        let mut same_id = self
            .records
            .iter()
            .filter(|record| record.id == reference.record.id);
        let current = same_id
            .next()
            .ok_or(MissingTrustProperty::ExactCallerQualification)?;
        if same_id.next().is_some()
            || !Arc::ptr_eq(&current.incarnation, &reference.record.incarnation)
            || current.revision != reference.record.revision
            || !current.matches(context, runtime, policy_revision, now)
            || current.principal != reference.record.principal
            || current.scope != reference.record.scope
            || current.runtime != reference.record.runtime
            || current.policy_revision != reference.record.policy_revision
            || current.expires_at != reference.record.expires_at
        {
            return Err(MissingTrustProperty::ExactCallerQualification);
        }
        Ok(())
    }
    #[cfg(test)]
    fn fixture(records: Vec<CallerQualification>) -> Self {
        Self {
            provider: Arc::new(()),
            store: PolicyStoreEvidence::TrustedFixture,
            records,
        }
    }
    #[cfg(test)]
    fn fixture_replace_record(&mut self, id: &str, mut replacement: CallerQualification) {
        replacement.incarnation = Arc::new(());
        *self.fixture_record_mut(id) = replacement;
    }
    #[cfg(test)]
    pub(crate) fn fixture_integration(
        principal: &str,
        runtime: CallerRuntimeFacts,
    ) -> Result<(Self, TrustedCallerContext, CallerRecordReference), MissingTrustProperty> {
        use sha2::{Digest, Sha256};
        if !bounded_text(principal, 1024) {
            return Err(MissingTrustProperty::ScopedCallerEvidence);
        }
        let stamp = xmsg::client::caller_attribution::AuthorityStamp {
            source: "claude".into(),
            matched_pid: 44,
            matched_start: "fixture-start".into(),
            registration_digest: hex::encode(Sha256::digest(principal.as_bytes())),
            root_generation: None,
            child_generation: None,
        };
        let context = TrustedCallerContext {
            principal: principal.into(),
            peer_uid: runtime.uid,
            binding: crate::auth::CallBinding {
                peer: crate::auth::PeerWitness {
                    uid: runtime.uid,
                    pid: Some(44),
                },
                call_nonce: 1,
                input_digest: "c".repeat(64),
            },
            scope: checked_scope(&stamp, &"a".repeat(32), &"b".repeat(64))?,
        };
        let record = CallerQualification {
            incarnation: Arc::new(()),
            id: "fixture-caller".into(),
            revision: 1,
            principal: principal.into(),
            scope: context.scope.clone(),
            runtime: runtime.clone(),
            policy_revision: 1,
            expires_at: i64::MAX,
            revoked: false,
        };
        let provider = Self::fixture(vec![record]);
        let reference = provider.qualify(&context, &runtime, 1, 1)?;
        provider.revalidate(&reference, &context, &runtime, 1, 1)?;
        Ok((provider, context, reference))
    }
    #[cfg(test)]
    pub(crate) fn fixture_policy_revision(
        &mut self,
        reference: &mut CallerRecordReference,
        revision: u64,
    ) -> Result<(), MissingTrustProperty> {
        self.protected()?;
        if revision == 0 || !Arc::ptr_eq(&self.provider, &reference.provider) {
            return Err(MissingTrustProperty::ExactCallerQualification);
        }
        let record = self
            .records
            .iter_mut()
            .find(|record| record.id == reference.record.id)
            .ok_or(MissingTrustProperty::ExactCallerQualification)?;
        if !Arc::ptr_eq(&record.incarnation, &reference.record.incarnation) {
            return Err(MissingTrustProperty::ExactCallerQualification);
        }
        record.policy_revision = revision;
        reference.record.policy_revision = revision;
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn fixture_revoke(
        &mut self,
        reference: &CallerRecordReference,
    ) -> Result<(), MissingTrustProperty> {
        if !Arc::ptr_eq(&self.provider, &reference.provider) {
            return Err(MissingTrustProperty::ExactCallerQualification);
        }
        let record = self
            .records
            .iter_mut()
            .find(|record| record.id == reference.record.id)
            .ok_or(MissingTrustProperty::ExactCallerQualification)?;
        record.revoked = true;
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn fixture_expiry_before_admission(
        &mut self,
        expires_at: i64,
    ) -> Result<(), MissingTrustProperty> {
        self.protected()?;
        if expires_at <= 0 {
            return Err(MissingTrustProperty::ExactCallerQualification);
        }
        for record in &mut self.records {
            record.expires_at = expires_at;
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn fixture_replace(
        &mut self,
        reference: &CallerRecordReference,
    ) -> Result<(), MissingTrustProperty> {
        if !Arc::ptr_eq(&self.provider, &reference.provider) {
            return Err(MissingTrustProperty::ExactCallerQualification);
        }
        let record = self
            .records
            .iter_mut()
            .find(|record| record.id == reference.record.id)
            .ok_or(MissingTrustProperty::ExactCallerQualification)?;
        record.incarnation = Arc::new(());
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn fixture_restore(
        &self,
        receipt: &serde_json::Value,
        expected_principal: &str,
        expected_input_digest: &str,
        runtime: &CallerRuntimeFacts,
        policy_revision: u64,
        now: i64,
    ) -> Result<(TrustedCallerContext, CallerRecordReference), MissingTrustProperty> {
        use serde_json::Value;
        self.require_protected_store()?;
        let missing = MissingTrustProperty::ExactCallerQualification;
        fn text(value: &Value) -> Option<&str> {
            value.as_str()
        }
        fn integer(value: &Value) -> Option<u64> {
            value.as_u64()
        }
        fn optional_integer(value: &Value) -> Option<Option<u64>> {
            if value.is_null() {
                Some(None)
            } else {
                value.as_u64().map(Some)
            }
        }
        let saved_context = receipt.get("context").ok_or(missing)?;
        let principal = text(&saved_context["principal"]).ok_or(missing)?;
        let saved_binding = saved_context.get("binding").ok_or(missing)?;
        if principal != expected_principal
            || text(&saved_binding["input_digest"]) != Some(expected_input_digest)
            || !hex_digest(expected_input_digest, 64)
            || receipt.get("runtime") != Some(&serde_json::to_value(runtime).map_err(|_| missing)?)
        {
            return Err(missing);
        }
        let uid = u32::try_from(integer(&saved_context["peer_uid"]).ok_or(missing)?)
            .map_err(|_| missing)?;
        let binding_uid = u32::try_from(integer(&saved_binding["peer_uid"]).ok_or(missing)?)
            .map_err(|_| missing)?;
        if uid != binding_uid {
            return Err(missing);
        }
        let binding = crate::auth::CallBinding {
            peer: crate::auth::PeerWitness {
                uid,
                pid: Some(
                    u32::try_from(integer(&saved_binding["peer_pid"]).ok_or(missing)?)
                        .map_err(|_| missing)?,
                ),
            },
            call_nonce: integer(&saved_binding["call_nonce"]).ok_or(missing)?,
            input_digest: text(&saved_binding["input_digest"]).ok_or(missing)?.into(),
        };
        checked_binding(principal, &binding)?;
        let saved_scope = saved_context.get("scope").ok_or(missing)?;
        let stamp = xmsg::client::caller_attribution::AuthorityStamp {
            source: text(&saved_scope["source"]).ok_or(missing)?.into(),
            matched_pid: u32::try_from(integer(&saved_scope["matched_pid"]).ok_or(missing)?)
                .map_err(|_| missing)?,
            matched_start: text(&saved_scope["matched_start"]).ok_or(missing)?.into(),
            registration_digest: text(&saved_scope["registration_digest"])
                .ok_or(missing)?
                .into(),
            root_generation: optional_integer(&saved_scope["root_generation"]).ok_or(missing)?,
            child_generation: optional_integer(&saved_scope["child_generation"]).ok_or(missing)?,
        };
        let scope = checked_scope(
            &stamp,
            text(&saved_scope["attestor_epoch"]).ok_or(missing)?,
            text(&saved_scope["context_digest"]).ok_or(missing)?,
        )?;
        let context = TrustedCallerContext {
            principal: principal.into(),
            peer_uid: uid,
            binding,
            scope,
        };
        let reference = self.qualify(&context, runtime, policy_revision, now)?;
        self.revalidate(&reference, &context, runtime, policy_revision, now)?;
        if reference.journal_receipt() != *receipt {
            return Err(missing);
        }
        Ok((context, reference))
    }
    #[cfg(test)]
    fn fixture_record_mut(&mut self, id: &str) -> &mut CallerQualification {
        self.records
            .iter_mut()
            .find(|record| record.id == id)
            .expect("fixture record exists")
    }
}
fn bounded_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn hex_digest(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[path = "caller_policy_tests.rs"]
mod tests;
