use super::{CallBinding, HostAttestor, TrustedPrincipal};
use crate::control::ErrorCode;
use sha2::{Digest, Sha256};
use std::{
    os::fd::{AsFd, OwnedFd},
    path::PathBuf,
    sync::Mutex,
    time::Instant,
};
use xmsg::client::caller_attribution::{self as wire, CallerContext, Query, Reply};

#[derive(Debug, Clone)]
pub struct DaemonAttributionConfig {
    pub query_socket: PathBuf,
    pub lifecycle_socket: PathBuf,
    pub expected_uid: u32,
}
impl DaemonAttributionConfig {
    pub(crate) fn validate(&self, uid: u32) -> Result<(), ErrorCode> {
        if self.expected_uid != uid
            || !self.query_socket.is_absolute()
            || !self.lifecycle_socket.is_absolute()
            || self.query_socket == self.lifecycle_socket
        {
            return Err(ErrorCode::InvalidConfiguration);
        }
        Ok(())
    }
}
pub(crate) struct ScopedDaemonAttestor {
    config: DaemonAttributionConfig,
    original: Mutex<Option<OwnedFd>>,
    epoch: String,
    context: Option<CallerContext>,
    deadline: Instant,
}
impl ScopedDaemonAttestor {
    pub(crate) fn new(
        config: DaemonAttributionConfig,
        original: OwnedFd,
        epoch: String,
        context: Option<CallerContext>,
        deadline: Instant,
    ) -> Result<Self, ErrorCode> {
        let context = context
            .map(CallerContext::normalize)
            .transpose()
            .map_err(|_| ErrorCode::AttestationBinding)?;
        Ok(Self {
            config,
            original: Mutex::new(Some(original)),
            epoch,
            context,
            deadline,
        })
    }
}
impl super::sealed::Sealed for ScopedDaemonAttestor {}
impl HostAttestor for ScopedDaemonAttestor {
    fn attest(&self, binding: &CallBinding) -> Result<TrustedPrincipal, ErrorCode> {
        let original = self
            .original
            .lock()
            .map_err(|_| ErrorCode::AttestationUnavailable)?
            .take()
            .ok_or(ErrorCode::AttestationBinding)?;
        if Instant::now() >= self.deadline {
            return Err(ErrorCode::DeadlineExpired);
        }
        let before = wire::private_socket(&self.config.query_socket, self.config.expected_uid)
            .map_err(|_| ErrorCode::AttestationUnavailable)?;
        wire::original_endpoint(original.as_fd(), &self.config.lifecycle_socket)
            .map_err(|_| ErrorCode::AttestationBinding)?;
        let query_stream = wire::connect(&self.config.query_socket, self.deadline)
            .map_err(|_| ErrorCode::AttestationUnavailable)?;
        if wire::socket_peer(query_stream.as_fd())
            .map_err(|_| ErrorCode::AttestationUnavailable)?
            .0
            != self.config.expected_uid
        {
            return Err(ErrorCode::PeerUid);
        }
        let mut hash = Sha256::new();
        hash.update(wire::CONTEXT_DOMAIN);
        hash.update(wire::context_bytes(&self.context).map_err(|_| ErrorCode::AttestationBinding)?);
        let context_digest = hex::encode(hash.finalize());
        let query = Query {
            v: wire::VERSION,
            runtime_epoch: self.epoch.clone(),
            call_nonce: binding.call_nonce,
            input_digest: binding.input_digest.clone(),
            context: self.context.clone(),
            context_digest: context_digest.clone(),
        };
        wire::send_query(&query_stream, original.as_fd(), &query, self.deadline)
            .map_err(|_| ErrorCode::AttestationUnavailable)?;
        let reply = wire::receive_reply(&query_stream, self.deadline)
            .map_err(|_| ErrorCode::AttestationUnavailable)?;
        if Instant::now() >= self.deadline {
            return Err(ErrorCode::DeadlineExpired);
        }
        if wire::private_socket(&self.config.query_socket, self.config.expected_uid).ok()
            != Some(before)
        {
            return Err(ErrorCode::AttestationUnavailable);
        }
        let Reply::Ok {
            v,
            runtime_epoch,
            call_nonce,
            input_digest,
            context_digest: returned_context,
            peer_uid,
            peer_pid,
            principal,
            authority_stamp,
        } = reply
        else {
            return Err(ErrorCode::AttestationUnavailable);
        };
        if v != wire::VERSION
            || runtime_epoch != self.epoch
            || call_nonce != binding.call_nonce
            || input_digest != binding.input_digest
            || returned_context != context_digest
            || peer_uid != binding.peer.uid
            || Some(peer_pid) != binding.peer.pid
        {
            return Err(ErrorCode::AttestationBinding);
        }
        if principal.is_empty() || principal.len() > 1024 || principal.chars().any(char::is_control)
        {
            return Err(ErrorCode::AttestationBinding);
        }
        Ok(TrustedPrincipal {
            id: principal,
            binding: binding.clone(),
            authority_stamp: Some(authority_stamp),
            attestor_epoch: Some(runtime_epoch),
            context_digest: Some(returned_context),
        })
    }
}
