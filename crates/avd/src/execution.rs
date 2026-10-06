//! Server-created connection authority. Public IDs are review context, never credentials.
use crate::BrokerError;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use uuid::Uuid;

#[derive(Clone)]
pub struct ExecutionSession(Arc<Identity>);
struct Identity {
    id: Uuid,
    live: AtomicBool,
    closed: tokio::sync::watch::Sender<bool>,
}
impl Default for ExecutionSession {
    fn default() -> Self {
        Self::new()
    }
}
impl ExecutionSession {
    /// Trusted in-process construction; this type cannot be deserialized from IPC.
    pub fn new() -> Self {
        Self(Arc::new(Identity {
            id: Uuid::new_v4(),
            live: AtomicBool::new(true),
            closed: tokio::sync::watch::channel(false).0,
        }))
    }
    pub fn id(&self) -> Uuid {
        self.0.id
    }
    pub(crate) fn is_live(&self) -> bool {
        self.0.live.load(Ordering::Acquire)
    }
    pub(crate) fn same_session(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(crate) fn authorize(&self, other: &Self) -> Result<(), BrokerError> {
        if self.same_session(other) && self.is_live() {
            Ok(())
        } else {
            Err(BrokerError::WrongExecutionSession)
        }
    }
    pub(crate) fn closure(&self) -> tokio::sync::watch::Receiver<bool> {
        self.0.closed.subscribe()
    }
    pub(crate) fn close(&self) {
        self.0.live.store(false, Ordering::Release);
        self.0.closed.send_replace(true);
    }
}
