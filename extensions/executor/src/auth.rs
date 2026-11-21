use crate::protocol::{Target, Verb};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) mod daemon;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub principal: String,
    pub verb: Verb,
    pub target: GrantTarget,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantTarget {
    Team {
        team_id: String,
    },
    Session {
        session_id: String,
        generation: u64,
    },
    Turn {
        session_id: String,
        generation: u64,
        turn_id: String,
    },
}
impl GrantTarget {
    pub(crate) fn matches(&self, target: &Target) -> bool {
        match (self, target) {
            (Self::Team { team_id: a }, Target::Team { team_id: b }) => a == b,
            (
                Self::Session {
                    session_id: a,
                    generation: ga,
                },
                Target::Execution {
                    session_id: b,
                    generation: gb,
                },
            ) => a == b && ga == gb,
            (
                Self::Session {
                    session_id: a,
                    generation: ga,
                },
                Target::Turn {
                    session_id: b,
                    generation: gb,
                    ..
                },
            ) => a == b && ga == gb,
            (
                Self::Turn {
                    session_id: a,
                    generation: ga,
                    turn_id: ta,
                },
                Target::Turn {
                    session_id: b,
                    generation: gb,
                    turn_id: tb,
                },
            ) => a == b && ga == gb && ta == tb,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerWitness {
    pub(crate) uid: u32,
    pub(crate) pid: Option<u32>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallBinding {
    pub(crate) peer: PeerWitness,
    pub(crate) call_nonce: u64,
    pub(crate) input_digest: String,
}
#[derive(Debug, Clone)]
pub(crate) struct TrustedPrincipal {
    id: String,
    binding: CallBinding,
}
mod sealed {
    pub trait Sealed {}
}
pub(crate) trait HostAttestor: sealed::Sealed + Send + Sync {
    fn attest(&self, binding: &CallBinding) -> Result<TrustedPrincipal, crate::control::ErrorCode>;
}
pub(crate) struct Unavailable;
impl sealed::Sealed for Unavailable {}
impl HostAttestor for Unavailable {
    fn attest(&self, _: &CallBinding) -> Result<TrustedPrincipal, crate::control::ErrorCode> {
        Err(crate::control::ErrorCode::AttestationUnavailable)
    }
}

pub(crate) fn principal(
    attestor: &dyn HostAttestor,
    binding: &CallBinding,
    expected_uid: u32,
) -> Result<TrustedPrincipal, crate::control::ErrorCode> {
    if binding.peer.uid != expected_uid {
        return Err(crate::control::ErrorCode::PeerUid);
    }
    let principal = attestor.attest(binding)?;
    if principal.binding != *binding {
        return Err(crate::control::ErrorCode::AttestationBinding);
    }
    Ok(principal)
}
impl TrustedPrincipal {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
}

pub struct ProvisionedCredentials {
    owner: [u8; 32],
    human: [u8; 32],
}
impl std::fmt::Debug for ProvisionedCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProvisionedCredentials([redacted])")
    }
}
impl ProvisionedCredentials {
    pub fn from_bytes(owner: &[u8], human: &[u8]) -> Result<Self, crate::control::ErrorCode> {
        if !(32..=128).contains(&owner.len())
            || !(32..=128).contains(&human.len())
            || owner == human
            || owner
                .iter()
                .chain(human)
                .any(|b| matches!(b, b'\r' | b'\n'))
        {
            return Err(crate::control::ErrorCode::InvalidConfiguration);
        }
        Ok(Self {
            owner: Sha256::digest(owner).into(),
            human: Sha256::digest(human).into(),
        })
    }
    pub(crate) fn verify(&self, provided: &[u8], role: CredentialRole) -> bool {
        let candidate: [u8; 32] = Sha256::digest(provided).into();
        let expected = match role {
            CredentialRole::Owner => self.owner,
            CredentialRole::Human => self.human,
        };
        candidate
            .iter()
            .zip(expected)
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
    }
}
#[derive(Clone, Copy)]
pub(crate) enum CredentialRole {
    Owner,
    Human,
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    pub(crate) struct FakeAttestor {
        pub(crate) principal: String,
        pub(crate) wrong_binding: bool,
    }
    impl sealed::Sealed for FakeAttestor {}
    impl HostAttestor for FakeAttestor {
        fn attest(
            &self,
            binding: &CallBinding,
        ) -> Result<TrustedPrincipal, crate::control::ErrorCode> {
            let mut binding = binding.clone();
            if self.wrong_binding {
                binding.call_nonce = binding.call_nonce.wrapping_add(1);
            }
            Ok(TrustedPrincipal {
                id: self.principal.clone(),
                binding,
            })
        }
    }
}
