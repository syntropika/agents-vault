//! Shared task supervision for platform-specific isolation engines.

use std::{future::Future, time::Duration};

use anyhow::{Result, anyhow};
use tokio::{sync::watch, task::JoinHandle};

pub(crate) enum TaskEvent {
    Exited(Result<i32>),
    Locked,
    Deadline,
    ProxyExited(String),
}

impl TaskEvent {
    pub(crate) fn into_result(self) -> Result<i32> {
        match self {
            Self::Exited(result) => result,
            Self::Locked => Err(anyhow!("broker session relocked")),
            Self::Deadline => Err(anyhow!(
                "fixture task reached its runtime or approval deadline"
            )),
            Self::ProxyExited(result) => Err(anyhow!("fixture proxy exited early: {result}")),
        }
    }
}

/// The caller owns the platform runner and must terminate it on any event
/// other than `Exited`. It also owns the proxy shutdown and transport relay.
pub(crate) async fn supervise_task<F, E>(
    task: F,
    shutdown: &mut watch::Receiver<bool>,
    lifetime: Duration,
    proxy_task: &mut JoinHandle<std::result::Result<(), E>>,
) -> (TaskEvent, bool)
where
    F: Future<Output = Result<i32>>,
    E: std::fmt::Debug + Send + 'static,
{
    tokio::select! {
        biased;
        result = task => (TaskEvent::Exited(result), false),
        _ = shutdown.changed() => (TaskEvent::Locked, false),
        _ = tokio::time::sleep(lifetime) => (TaskEvent::Deadline, false),
        result = proxy_task => (TaskEvent::ProxyExited(format!("{result:?}")), true),
    }
}
