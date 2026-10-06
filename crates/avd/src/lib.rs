//! Broker with immutable requests and separate agent and private administration IPC.

pub mod approval;
pub mod management;
pub mod mcp_approval;
mod operator_web;
pub mod service;
pub mod task_recipe;

use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use av_core::Vault;
use av_proxy::ProxyHub;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

mod execution;
pub use execution::ExecutionSession;
pub mod ipc;
mod isolation;
mod proxy_task;
pub mod session;
pub use proxy_task::ProxyPolicy;

use proxy_task::ProxyRuntime;

const MAX_PENDING_REQUESTS: usize = 1024;
const MAX_TRACKED_REQUESTS: usize = 4096;
const REQUEST_RETENTION_SECONDS: u64 = 300;
const MAX_TRACKED_TASKS: usize = 64;
const MAX_ACTIVE_HOST_TASKS: usize = 16;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Operation {
    pub connection: String,
    pub action: String,
    pub target: String,
    pub arguments: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestState {
    Pending,
    Approved { expires_at: u64, remaining: u32 },
    Denied,
    Exhausted,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Review {
    pub id: Uuid,
    pub operation: Operation,
    pub state: RequestState,
    pub execution_session: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_policy: Option<TaskPolicySnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskPolicySnapshot {
    pub host: String,
    pub command: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_version: Option<u64>,
    pub max_connects: u32,
    pub max_requests: u32,
    pub max_runtime_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrokerError {
    InvalidOperation,
    UnknownRequest,
    AlreadyDecided,
    InvalidGrant,
    NotApproved,
    Denied,
    Expired,
    QuotaExhausted,
    CapacityExceeded,
    StartFailed,
    WrongExecutionSession,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Running,
    Finished,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskStatus {
    pub task_id: Uuid,
    pub state: TaskState,
    pub exit_code: Option<i32>,
}

struct TrackedTask {
    status: TaskStatus,
    updated_at: u64,
}

struct Entry {
    owner: ExecutionSession,
    operation: Operation,
    state: RequestState,
    created_at: u64,
    updated_at: u64,
}

#[derive(Default)]
struct BrokerState {
    requests: HashMap<Uuid, Entry>,
    closed: bool,
}

/// The mutex makes grant consumption atomic within this broker process.
pub struct Broker {
    entries: Mutex<BrokerState>,
    proxy: Option<Arc<ProxyRuntime>>,
    host_proxy: tokio::sync::OnceCell<Arc<ProxyHub>>,
    tasks: Arc<Mutex<HashMap<Uuid, TrackedTask>>>,
    task_handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    host_cancel: Arc<Mutex<HashMap<Uuid, Option<tokio::sync::oneshot::Sender<i32>>>>>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl Default for Broker {
    fn default() -> Self {
        Self {
            entries: Mutex::new(BrokerState::default()),
            proxy: None,
            host_proxy: tokio::sync::OnceCell::new(),
            tasks: Arc::new(Mutex::new(HashMap::new())),
            task_handles: Mutex::new(Vec::new()),
            host_cancel: Arc::new(Mutex::new(HashMap::new())),
            shutdown: tokio::sync::watch::channel(false).0,
        }
    }
}

impl Broker {
    /// Bind the fixed host proxy when the broker unlocks. Without an active
    /// grant the listener remains reachable but rejects every connection.
    pub async fn start_host_proxy_listener(&self) -> Result<()> {
        if !self
            .proxy
            .as_ref()
            .is_some_and(|proxy| proxy.policy.host_client)
        {
            return Ok(());
        }
        self.host_proxy
            .get_or_try_init(|| async {
                ProxyHub::bind(proxy_task::HOST_PROXY_ADDR)
                    .await
                    .map(Arc::new)
            })
            .await
            .context("cannot bind fixed host proxy")?;
        Ok(())
    }

    /// Only trusted startup code should open the vault and construct this broker.
    pub fn from_vault(_vault: &Vault) -> Result<Self> {
        Ok(Self::default())
    }

    /// Load a single operator-owned synthetic fixture policy at startup.
    /// Linux confines the child in namespaces. This remains synthetic-only
    /// until deployment identity and every agent tool boundary are verified.
    pub fn from_vault_with_proxy_policy(vault: &Vault, policy_path: &Path) -> Result<Self> {
        Self::with_proxy_policy(vault, policy_path, false)
    }

    pub(crate) fn from_vault_with_enforced_proxy_policy(
        vault: &Vault,
        policy_path: &Path,
    ) -> Result<Self> {
        Self::with_proxy_policy(vault, policy_path, true)
    }

    fn with_proxy_policy(vault: &Vault, policy_path: &Path, enforce_grant: bool) -> Result<Self> {
        let proxy = Arc::new(ProxyRuntime::load_with_grant(
            vault,
            policy_path,
            enforce_grant,
        )?);
        Ok(Self {
            entries: Mutex::new(BrokerState::default()),
            proxy: Some(proxy),
            host_proxy: tokio::sync::OnceCell::new(),
            tasks: Arc::new(Mutex::new(HashMap::new())),
            task_handles: Mutex::new(Vec::new()),
            host_cancel: Arc::new(Mutex::new(HashMap::new())),
            shutdown: tokio::sync::watch::channel(false).0,
        })
    }

    pub fn request(
        &self,
        owner: &ExecutionSession,
        operation: Operation,
    ) -> Result<Uuid, BrokerError> {
        self.request_at(owner, operation, now_seconds())
    }

    fn canonicalize_operation(&self, mut operation: Operation) -> Result<Operation, BrokerError> {
        let valid = if operation.action == "proxy.run" {
            self.proxy.as_ref().is_some_and(|proxy| {
                let version_matches = match proxy.policy.connection_version {
                    Some(version) => {
                        operation.arguments.get("connection_version") == Some(&json!(version))
                            && operation.arguments.as_object().map(|m| m.len()) == Some(2)
                            && (operation.target.is_empty()
                                || operation.target == proxy.policy.host)
                    }
                    None => {
                        operation.arguments.as_object().map(|m| m.len()) == Some(1)
                            && operation.target.eq_ignore_ascii_case(&proxy.policy.host)
                    }
                };
                operation.connection == proxy.policy.connection
                    && version_matches
                    && operation.arguments.get("command") == Some(&json!(proxy.policy.command))
            })
        } else {
            false
        };
        if !valid {
            return Err(BrokerError::InvalidOperation);
        }
        if operation.action == "proxy.run" && operation.target.is_empty() {
            operation.target = self
                .proxy
                .as_ref()
                .expect("validated proxy operation")
                .policy
                .host
                .clone();
        }
        Ok(operation)
    }

    fn request_at(
        &self,
        owner: &ExecutionSession,
        operation: Operation,
        now: u64,
    ) -> Result<Uuid, BrokerError> {
        let operation = self.canonicalize_operation(operation)?;
        let mut state = self.entries.lock().expect("broker mutex poisoned");
        Self::insert_request(&mut state, owner, operation, now)
    }

    fn insert_request(
        state: &mut BrokerState,
        owner: &ExecutionSession,
        operation: Operation,
        now: u64,
    ) -> Result<Uuid, BrokerError> {
        if state.closed || !owner.is_live() {
            return Err(BrokerError::Denied);
        }
        state
            .requests
            .retain(|_, entry| now < entry.updated_at.saturating_add(REQUEST_RETENTION_SECONDS));
        if state.requests.len() >= MAX_TRACKED_REQUESTS
            || state
                .requests
                .values()
                .filter(|entry| entry.state == RequestState::Pending)
                .count()
                >= MAX_PENDING_REQUESTS
        {
            return Err(BrokerError::CapacityExceeded);
        }
        let id = Uuid::new_v4();
        state.requests.insert(
            id,
            Entry {
                owner: owner.clone(),
                operation,
                state: RequestState::Pending,
                created_at: now,
                updated_at: now,
            },
        );
        Ok(id)
    }

    pub fn review(&self, id: Uuid) -> Result<Review, BrokerError> {
        let (operation, state, execution_session) = {
            let entries = self.entries.lock().expect("broker mutex poisoned");
            let entry = entries
                .requests
                .get(&id)
                .ok_or(BrokerError::UnknownRequest)?;
            (
                entry.operation.clone(),
                entry.state.clone(),
                entry.owner.id(),
            )
        };
        self.build_review(id, operation, state, execution_session)
    }

    pub(crate) fn web_reviews(&self) -> Result<Vec<Review>, BrokerError> {
        let ids: Vec<_> = self
            .entries
            .lock()
            .expect("broker mutex poisoned")
            .requests
            .keys()
            .copied()
            .collect();
        let mut reviews: Vec<_> = ids
            .into_iter()
            .map(|id| self.review(id))
            .collect::<Result<_, _>>()?;
        reviews.sort_by_key(|review| review.id);
        Ok(reviews)
    }

    fn build_review(
        &self,
        id: Uuid,
        operation: Operation,
        state: RequestState,
        execution_session: Uuid,
    ) -> Result<Review, BrokerError> {
        Ok(Review {
            id,
            execution_session,
            task_policy: if operation.action == "proxy.run" {
                self.proxy.as_ref().map(|proxy| TaskPolicySnapshot {
                    host: proxy.policy.host.clone(),
                    command: proxy.policy.command.clone(),
                    connection_version: proxy.policy.connection_version,
                    max_connects: proxy.policy.max_connects,
                    max_requests: proxy.policy.max_requests,
                    max_runtime_seconds: proxy.policy.max_runtime_seconds,
                })
            } else {
                None
            },
            operation,
            state,
        })
    }

    /// The caller must authenticate operator authority. Installed sessions
    /// verify the vault passphrase before reaching this method.
    pub fn decide(
        &self,
        id: Uuid,
        approve: bool,
        now: u64,
        ttl_seconds: u64,
    ) -> Result<RequestState, BrokerError> {
        if approve && (ttl_seconds == 0 || ttl_seconds > 300) {
            return Err(BrokerError::InvalidGrant);
        }
        let mut entries = self.entries.lock().expect("broker mutex poisoned");
        let entry = entries
            .requests
            .get_mut(&id)
            .ok_or(BrokerError::UnknownRequest)?;
        if !entry.owner.is_live() {
            return Err(BrokerError::WrongExecutionSession);
        }
        if entry.state != RequestState::Pending {
            return Err(BrokerError::AlreadyDecided);
        }
        if now >= entry.created_at.saturating_add(REQUEST_RETENTION_SECONDS) {
            return Err(BrokerError::Expired);
        }
        entry.state = if approve {
            RequestState::Approved {
                expires_at: now
                    .checked_add(ttl_seconds)
                    .ok_or(BrokerError::InvalidGrant)?,
                remaining: 1,
            }
        } else {
            RequestState::Denied
        };
        entry.updated_at = now;
        Ok(entry.state.clone())
    }

    /// Execute the frozen intent only on its original live IPC session.
    pub async fn execute_or_start(
        self: &Arc<Self>,
        owner: &ExecutionSession,
        id: Uuid,
        now: u64,
    ) -> Result<Value, BrokerError> {
        self.start_host_proxy_listener()
            .await
            .map_err(|_| BrokerError::StartFailed)?;
        let (status, ready) = self.start_proxy_task_inner(owner, id, now)?;
        if let Some(ready) = ready {
            let details = ready.await.map_err(|_| BrokerError::StartFailed)?;
            Ok(json!({"task_id": status.task_id, "state": status.state, "host_proxy": details}))
        } else {
            Ok(json!(status))
        }
    }

    fn start_proxy_task_inner(
        self: &Arc<Self>,
        owner: &ExecutionSession,
        id: Uuid,
        now: u64,
    ) -> Result<
        (
            TaskStatus,
            Option<tokio::sync::oneshot::Receiver<proxy_task::HostProxyDetails>>,
        ),
        BrokerError,
    > {
        let proxy = self.proxy.as_ref().ok_or(BrokerError::InvalidOperation)?;
        let mut entries = self.entries.lock().expect("broker mutex poisoned");
        let entry = entries
            .requests
            .get_mut(&id)
            .ok_or(BrokerError::UnknownRequest)?;
        entry.owner.authorize(owner)?;
        let expected_action = "proxy.run";
        if entry.operation.action != expected_action {
            return Err(BrokerError::InvalidOperation);
        }
        let expires_at = match entry.state {
            RequestState::Pending => return Err(BrokerError::NotApproved),
            RequestState::Denied => return Err(BrokerError::Denied),
            RequestState::Exhausted => return Err(BrokerError::QuotaExhausted),
            RequestState::Approved { expires_at, .. } if now >= expires_at => {
                return Err(BrokerError::Expired);
            }
            RequestState::Approved { expires_at, .. } => expires_at,
        };
        let mut active_host = self.host_cancel.lock().expect("host cancel mutex poisoned");
        if proxy.policy.host_client && active_host.len() >= MAX_ACTIVE_HOST_TASKS {
            return Err(BrokerError::CapacityExceeded);
        }
        let mut tasks = self.tasks.lock().expect("task mutex poisoned");
        tasks.retain(|_, task| {
            task.status.state == TaskState::Running
                || now < task.updated_at.saturating_add(REQUEST_RETENTION_SECONDS)
        });
        if tasks.len() >= MAX_TRACKED_TASKS {
            return Err(BrokerError::CapacityExceeded);
        }
        let status = TaskStatus {
            task_id: id,
            state: TaskState::Running,
            exit_code: None,
        };
        tasks.insert(
            id,
            TrackedTask {
                status: status.clone(),
                updated_at: now,
            },
        );
        entry.state = RequestState::Exhausted;
        entry.updated_at = now;
        drop(tasks);
        let tasks = Arc::clone(&self.tasks);
        let proxy = Arc::clone(proxy);
        let host_proxy = self.host_proxy.get().cloned();
        let (ready_sender, ready_receiver) = if proxy.policy.host_client {
            let (sender, receiver) = tokio::sync::oneshot::channel();
            (Some(sender), Some(receiver))
        } else {
            (None, None)
        };
        let cancelled = if proxy.policy.host_client {
            let (sender, receiver) = tokio::sync::oneshot::channel();
            active_host.insert(id, Some(sender));
            Some(receiver)
        } else {
            None
        };
        drop(active_host);
        drop(entries);
        let host_cancel = Arc::clone(&self.host_cancel);
        let mut broker_shutdown = self.shutdown.subscribe();
        let mut owner_closed = owner.closure();
        let handle = tokio::spawn(async move {
            let (signal, shutdown) =
                tokio::sync::watch::channel(*broker_shutdown.borrow() || *owner_closed.borrow());
            let forward = tokio::spawn(async move {
                tokio::select! {
                    _ = broker_shutdown.changed() => {},
                    _ = owner_closed.changed() => {},
                    _ = signal.closed() => return,
                }
                signal.send_replace(true);
            });
            let result = if let Some(sender) = ready_sender {
                proxy
                    .run_host_client(
                        host_proxy
                            .as_deref()
                            .expect("host proxy listener initialized"),
                        expires_at,
                        shutdown,
                        sender,
                        cancelled.expect("host cancel channel"),
                    )
                    .await
            } else {
                proxy.run(expires_at, shutdown).await
            };
            forward.abort();
            host_cancel
                .lock()
                .expect("host cancel mutex poisoned")
                .remove(&id);
            let mut tasks = tasks.lock().expect("task mutex poisoned");
            if let Some(task) = tasks.get_mut(&id) {
                task.status.state = if result.is_ok() {
                    TaskState::Finished
                } else {
                    TaskState::Failed
                };
                task.status.exit_code = result.ok();
                task.updated_at = now_seconds();
            }
        });
        let mut handles = self.task_handles.lock().expect("task handles poisoned");
        handles.retain(|handle| !handle.is_finished());
        handles.push(handle);
        Ok((status, ready_receiver))
    }

    /// Closing the original IPC connection revokes pending and active host grants.
    pub fn close_execution_session(&self, owner: &ExecutionSession) {
        let mut entries = self.entries.lock().expect("broker mutex poisoned");
        owner.close();
        let mut active = self.host_cancel.lock().expect("host cancel mutex poisoned");
        for (id, entry) in &mut entries.requests {
            if entry.owner.same_session(owner) {
                if matches!(
                    entry.state,
                    RequestState::Pending | RequestState::Approved { .. }
                ) {
                    entry.state = RequestState::Denied;
                    entry.updated_at = now_seconds();
                }
                if let Some(Some(sender)) = active.remove(id) {
                    let _ = sender.send(1);
                }
            }
        }
    }

    /// MCP may adopt the exact pending intent, but never replace execution ownership.
    pub(crate) fn review_for_adoption(
        &self,
        id: Uuid,
        operation: Operation,
    ) -> Result<Review, BrokerError> {
        let canonical = self.canonicalize_operation(operation)?;
        let entries = self.entries.lock().expect("broker mutex poisoned");
        let entry = entries
            .requests
            .get(&id)
            .ok_or(BrokerError::UnknownRequest)?;
        if !entry.owner.is_live()
            || entry.state != RequestState::Pending
            || canonical != entry.operation
        {
            return Err(BrokerError::InvalidOperation);
        }
        self.build_review(
            id,
            entry.operation.clone(),
            entry.state.clone(),
            entry.owner.id(),
        )
    }

    /// Stop task proxies and runners before discarding this unlocked session.
    pub async fn shutdown(&self) {
        self.entries.lock().expect("broker mutex poisoned").closed = true;
        self.shutdown.send_replace(true);
        let handles =
            std::mem::take(&mut *self.task_handles.lock().expect("task handles poisoned"));
        for handle in handles {
            let _ = handle.await;
        }
        if let Some(proxy) = self.host_proxy.get() {
            let _ = proxy.shutdown().await;
        }
    }

    pub fn task_status(&self, id: Uuid) -> Result<TaskStatus, BrokerError> {
        self.tasks
            .lock()
            .expect("task mutex poisoned")
            .get(&id)
            .map(|task| task.status.clone())
            .ok_or(BrokerError::UnknownRequest)
    }

    pub fn finish_host_proxy(
        &self,
        owner: &ExecutionSession,
        id: Uuid,
        exit_code: i32,
    ) -> Result<(), BrokerError> {
        if !(0..=255).contains(&exit_code) {
            return Err(BrokerError::InvalidOperation);
        }
        if !self
            .proxy
            .as_ref()
            .is_some_and(|proxy| proxy.policy.host_client)
        {
            return Err(BrokerError::InvalidOperation);
        }
        let entries = self.entries.lock().expect("broker mutex poisoned");
        let entry = entries
            .requests
            .get(&id)
            .ok_or(BrokerError::UnknownRequest)?;
        entry.owner.authorize(owner)?;
        let sender = self
            .host_cancel
            .lock()
            .expect("host cancel mutex poisoned")
            .get_mut(&id)
            .and_then(Option::take)
            .ok_or(BrokerError::UnknownRequest)?;
        sender
            .send(exit_code)
            .map_err(|_| BrokerError::UnknownRequest)
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_without_a_proxy_policy_rejects_task_requests() {
        let broker = Broker::default();
        assert_eq!(
            broker.request(
                &ExecutionSession::new(),
                Operation {
                    connection: "demo/work".into(),
                    action: "unsupported.action".into(),
                    target: "local".into(),
                    arguments: json!({"message": "synthetic message"}),
                }
            ),
            Err(BrokerError::InvalidOperation)
        );
    }
}
