use crate::error::AppError;
use crate::inbox::DeliveryResponse;
use crate::registry::{Session, SessionsQuery};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    Live,
    Gone,
    Stale,
}

pub trait HarnessAdapter: Send + Sync {
    fn harness_name(&self) -> &'static str;
    fn list(&self, query: &SessionsQuery) -> Vec<Session>;
    fn liveness(&self, session: &Session) -> Liveness;
    fn deliver(
        &self,
        session: &Session,
        from_name: &str,
        message_id: &str,
        body: &str,
    ) -> impl std::future::Future<Output = Result<DeliveryResponse, AppError>> + Send;
}
