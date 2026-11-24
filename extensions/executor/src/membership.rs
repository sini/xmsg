use serde::{Deserialize, Serialize};
use xmsg::client::{
    validate_service_name, AgentClient, AttachmentRef, ClientError, ClientOptions, Delivery,
    Origin, RegisteredService,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProxyBinding {
    session_id: String,
    generation: u64,
    service_id: [u8; 16],
    max_content_bytes: usize,
}
impl ProxyBinding {
    pub(crate) fn new(
        session_id: String,
        generation: u64,
        service_id: [u8; 16],
        max_content_bytes: usize,
    ) -> Result<Self, MembershipError> {
        if session_id.is_empty()
            || session_id.len() > 128
            || generation == 0
            || max_content_bytes == 0
            || max_content_bytes > crate::framing::MAX_FRAME_BYTES
        {
            return Err(MembershipError::InvalidBinding);
        }
        Ok(Self {
            session_id,
            generation,
            service_id,
            max_content_bytes,
        })
    }
    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn service_name(&self) -> String {
        const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut name = String::from("team_");
        let mut accumulator = 0u32;
        let mut bits = 0u32;
        for byte in self.service_id {
            accumulator = (accumulator << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                name.push(ALPHABET[((accumulator >> bits) & 31) as usize] as char);
            }
        }
        if bits > 0 {
            name.push(ALPHABET[((accumulator << (5 - bits)) & 31) as usize] as char);
        }
        name
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContentRecord {
    pub(crate) message_id: String,
    pub(crate) from_name: String,
    pub(crate) text: String,
    pub(crate) envelope: String,
    pub(crate) origin: Origin,
    pub(crate) attachments: Vec<AttachmentRef>,
    pub(crate) in_reply_to: Option<String>,
}
impl From<&Delivery> for ContentRecord {
    fn from(delivery: &Delivery) -> Self {
        Self {
            message_id: delivery.message_id().to_owned(),
            from_name: delivery.from_name().to_owned(),
            text: delivery.text().to_owned(),
            envelope: delivery.envelope().to_owned(),
            origin: delivery.origin().clone(),
            attachments: delivery.attachments().to_vec(),
            in_reply_to: delivery.in_reply_to().map(str::to_owned),
        }
    }
}
impl ContentRecord {
    fn validate(&self, binding: &ProxyBinding) -> Result<(), MembershipError> {
        if self.message_id.is_empty()
            || self.message_id.len() > 256
            || self.origin.node.is_empty()
            || self.origin.id.is_some() && self.origin.service.is_some()
        {
            return Err(MembershipError::InvalidContent);
        }
        let encoded = serde_json::to_vec(self).map_err(|_| MembershipError::InvalidContent)?;
        if encoded.len() > binding.max_content_bytes {
            return Err(MembershipError::ContentLimit);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommitOutcome {
    Inserted,
    Duplicate,
}

pub(crate) trait ContentStore {
    // Duplicate certifies an identical committed message and binding, never a changed payload.
    fn commit(
        &mut self,
        binding: &ProxyBinding,
        content: &ContentRecord,
    ) -> Result<CommitOutcome, MembershipError>;
    fn admit_outgoing(
        &mut self,
        _binding: &ProxyBinding,
        _operation: ContentOperation,
        _request_key: &str,
    ) -> Result<(), MembershipError> {
        Err(MembershipError::ManagedEffectDenied)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentOperation {
    List,
    Send,
    Reply,
}
impl ContentOperation {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Send => "send",
            Self::Reply => "reply",
        }
    }
}

pub(crate) struct SharedContentStore<S> {
    inner: std::sync::Arc<std::sync::Mutex<S>>,
}
impl<S> Clone for SharedContentStore<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
impl<S> SharedContentStore<S> {
    pub(crate) fn new(store: S) -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(store)),
        }
    }
    #[cfg(test)]
    pub(crate) fn fixture_with_mut<R>(&self, action: impl FnOnce(&mut S) -> R) -> R {
        action(&mut self.inner.lock().unwrap())
    }
}
impl<S: ContentStore> ContentStore for SharedContentStore<S> {
    fn commit(
        &mut self,
        binding: &ProxyBinding,
        content: &ContentRecord,
    ) -> Result<CommitOutcome, MembershipError> {
        self.inner
            .lock()
            .map_err(|_| MembershipError::Storage)?
            .commit(binding, content)
    }
    fn admit_outgoing(
        &mut self,
        binding: &ProxyBinding,
        operation: ContentOperation,
        key: &str,
    ) -> Result<(), MembershipError> {
        self.inner
            .lock()
            .map_err(|_| MembershipError::Storage)?
            .admit_outgoing(binding, operation, key)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum MembershipError {
    #[error("managed content effect denied")]
    ManagedEffectDenied,
    #[error("invalid bus proxy binding")]
    InvalidBinding,
    #[error("invalid bus content")]
    InvalidContent,
    #[error("bus content exceeds execution limit")]
    ContentLimit,
    #[error("content storage failed")]
    Storage,
    #[error("content belongs to a stale execution")]
    StaleGeneration,
    #[error("message identity was reused with different content")]
    MessageConflict,
    #[error("bus transport failed")]
    Transport(#[from] ClientError),
    #[error("bus acknowledgement failed after durable {stored:?}")]
    Acknowledgement {
        stored: CommitOutcome,
        #[source]
        source: ClientError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReceiveOutcome {
    Idle,
    Acknowledged {
        message_id: String,
        stored: CommitOutcome,
    },
}

pub(crate) struct ContentProxy {
    service: RegisteredService,
    binding: ProxyBinding,
    address: String,
}
impl ContentProxy {
    pub(crate) async fn register(
        mut options: ClientOptions,
        binding: ProxyBinding,
    ) -> Result<Self, MembershipError> {
        options.service = binding.service_name();
        validate_service_name(&options.service).map_err(|_| MembershipError::InvalidBinding)?;
        options.max_frame_bytes = options.max_frame_bytes.min(crate::framing::MAX_FRAME_BYTES);
        let service = RegisteredService::register(options).await?;
        let address = service
            .address()
            .ok_or(ClientError::Disconnected)?
            .to_owned();
        service.health()?;
        Ok(Self {
            service,
            binding,
            address,
        })
    }
    pub(crate) fn address(&self) -> &str {
        &self.address
    }
    pub(crate) fn binding(&self) -> &ProxyBinding {
        &self.binding
    }
    pub(crate) fn health(&self) -> Result<(), MembershipError> {
        self.service.health().map_err(MembershipError::from)
    }
    pub(crate) fn agent_client(&self) -> Result<AgentClient, MembershipError> {
        self.health()?;
        Ok(self.service.agent_client())
    }
    pub(crate) async fn receive_once(
        &mut self,
        store: &mut impl ContentStore,
        wait_secs: u64,
    ) -> Result<ReceiveOutcome, MembershipError> {
        receive_from(&mut self.service, &self.binding, store, wait_secs).await
    }
}

trait ContentConnection {
    fn health(&self) -> Result<(), ClientError>;
    async fn poll_content(&mut self, wait_secs: u64) -> Result<Option<ContentRecord>, ClientError>;
    async fn ack_content(&mut self, message_id: &str) -> Result<(), ClientError>;
}
impl ContentConnection for RegisteredService {
    fn health(&self) -> Result<(), ClientError> {
        RegisteredService::health(self)
    }
    async fn poll_content(&mut self, wait_secs: u64) -> Result<Option<ContentRecord>, ClientError> {
        RegisteredService::poll(self, wait_secs)
            .await
            .map(|delivery| delivery.as_ref().map(ContentRecord::from))
    }
    async fn ack_content(&mut self, message_id: &str) -> Result<(), ClientError> {
        RegisteredService::ack(self, message_id).await
    }
}

async fn receive_from(
    connection: &mut impl ContentConnection,
    binding: &ProxyBinding,
    store: &mut impl ContentStore,
    wait_secs: u64,
) -> Result<ReceiveOutcome, MembershipError> {
    if wait_secs > 60 {
        return Err(MembershipError::InvalidBinding);
    }
    connection.health()?;
    let Some(content) = connection.poll_content(wait_secs).await? else {
        return Ok(ReceiveOutcome::Idle);
    };
    content.validate(binding)?;
    let stored = store.commit(binding, &content)?;
    connection
        .ack_content(&content.message_id)
        .await
        .map_err(|source| MembershipError::Acknowledgement { stored, source })?;
    Ok(ReceiveOutcome::Acknowledged {
        message_id: content.message_id,
        stored,
    })
}

#[cfg(test)]
#[path = "membership_tests.rs"]
mod tests;
