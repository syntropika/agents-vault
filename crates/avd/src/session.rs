//! Locked-start session and private operator administration.
//!
//! Administration and approval use a private socket and capability. Agent and
//! runner identities never receive either endpoint access or its capability.

use crate::{
    Broker,
    ipc::Reply,
    management::{self, ManagementOperation},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs, io,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{RwLock, Semaphore},
    time::{Duration, timeout},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_FRAME: u64 = 65_536;

#[derive(Clone)]
pub struct VaultSource {
    pub vault: PathBuf,
    pub proxy_policy: Option<PathBuf>,
    pub service_mode: bool,
}

impl VaultSource {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.service_mode {
            crate::management::bootstrap::validate_complete(&self.vault)?;
            #[cfg(target_os = "macos")]
            {
                use av_vmm::service;
                service::validate_broker_identity()?;
                anyhow::ensure!(
                    self.vault == Path::new(service::BROKER_VAULT),
                    "macOS service requires the installed vault path"
                );
                service::validate_broker_path(&self.vault, true)?;
                let path = self.proxy_policy.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("macOS service requires an installed synthetic policy")
                })?;
                anyhow::ensure!(
                    path == Path::new(service::BROKER_POLICY),
                    "macOS service requires the installed policy path"
                );
                service::validate_broker_path(path, true)?;
                let policy: crate::ProxyPolicy = serde_json::from_slice(&fs::read(path)?)?;
                anyhow::ensure!(
                    (policy.mac_service || policy.host_client)
                        && policy.mac_vmm.is_none()
                        && policy.mac_guest_bundle.is_none(),
                    "macOS service policy must select the installed supervisor or host proxy"
                );
            }
            #[cfg(not(target_os = "macos"))]
            {
                crate::service::validate_trusted_path(&self.vault, true)?;
                if let Some(path) = &crate::task_recipe::existing_path(self)? {
                    crate::service::validate_trusted_path(path, true)?;
                    #[cfg(target_os = "linux")]
                    {
                        let policy: crate::ProxyPolicy = serde_json::from_slice(&fs::read(path)?)?;
                        policy.validate()?;
                        if !policy.host_client {
                            let helper = policy.runner_helper.as_ref().ok_or_else(|| {
                                anyhow::anyhow!("service mode requires the confined runner")
                            })?;
                            anyhow::ensure!(
                                helper == Path::new(av_runner::service::HELPER),
                                "service requires installed runner helper"
                            );
                            crate::service::validate_trusted_path(helper, false)?;
                        }
                        let program = policy
                            .command
                            .first()
                            .ok_or_else(|| anyhow::anyhow!("service command is empty"))?;
                        crate::service::validate_trusted_path(Path::new(program), false)?;
                        crate::proxy_task::read_linux_upstream_ca(&policy.upstream_ca_der, true)?;
                    }
                }
            }
        }
        Ok(())
    }
}

pub struct Session {
    pub(crate) broker: Arc<RwLock<Option<Arc<Broker>>>>,
    pub(crate) source: Option<VaultSource>,
    pub(crate) mcp: crate::mcp_approval::McpApprovals,
    approval_address: std::sync::OnceLock<std::net::SocketAddr>,
    web_epoch: std::sync::atomic::AtomicU64,
}

impl Session {
    pub fn ready(broker: Arc<Broker>) -> Arc<Self> {
        Arc::new(Self {
            broker: Arc::new(RwLock::new(Some(broker))),
            source: None,
            mcp: Default::default(),
            approval_address: std::sync::OnceLock::new(),
            web_epoch: std::sync::atomic::AtomicU64::new(0),
        })
    }

    pub fn locked(source: VaultSource) -> anyhow::Result<Arc<Self>> {
        source.validate()?;
        Ok(Arc::new(Self {
            broker: Arc::new(RwLock::new(None)),
            source: Some(source),
            mcp: Default::default(),
            approval_address: std::sync::OnceLock::new(),
            web_epoch: std::sync::atomic::AtomicU64::new(0),
        }))
    }

    pub(crate) fn enable_approval_ui(&self, address: std::net::SocketAddr) -> io::Result<()> {
        if address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            || self.source.is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "approval UI requires a configured local vault",
            ));
        }
        self.approval_address.set(address).map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "approval UI is already configured",
            )
        })
    }

    pub(crate) fn approval_link(&self, request_id: uuid::Uuid) -> Option<String> {
        self.approval_address
            .get()
            .map(|address| format!("http://{address}/requests/{request_id}"))
    }

    pub(crate) async fn web_authenticate(&self, passphrase: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            !passphrase.is_empty() && passphrase.len() <= 4096,
            "invalid passphrase length"
        );
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("vault is not configured"))?
            .clone();
        let passphrase = Zeroizing::new(passphrase.to_owned());
        tokio::task::spawn_blocking(move || {
            if source.service_mode {
                management::validate_source(&source)?;
            } else {
                source.validate()?;
            }
            av_core::Vault::open(&source.vault, &passphrase).map(drop)
        })
        .await??;
        Ok(())
    }

    pub(crate) async fn web_manage(
        &self,
        passphrase: &str,
        operation: ManagementOperation,
        epoch: u64,
    ) -> anyhow::Result<serde_json::Value> {
        let state = Arc::clone(&self.broker).write_owned().await;
        anyhow::ensure!(self.web_epoch() == epoch, "operator session changed");
        anyhow::ensure!(
            state.is_none(),
            "lock task execution before changing credentials"
        );
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("vault is not configured"))?
            .clone();
        let passphrase = Zeroizing::new(passphrase.to_owned());
        tokio::task::spawn_blocking(move || {
            // Keep the mutation gate even if the HTTP future times out.
            let _state = state;
            if source.service_mode {
                management::validate_source(&source)?;
            } else {
                source.validate()?;
            }
            let vault = av_core::Vault::open(&source.vault, &passphrase)?;
            management::execute(&vault, &source, &operation)
        })
        .await?
    }

    pub async fn is_locked(&self) -> bool {
        self.broker.read().await.is_none()
    }

    pub(crate) async fn start_host_proxy_listener(&self) -> anyhow::Result<()> {
        if let Some(broker) = self.broker.read().await.as_ref() {
            broker.start_host_proxy_listener().await?;
        }
        Ok(())
    }

    pub(crate) async fn unlock(&self, passphrase: &str) -> anyhow::Result<()> {
        self.unlock_checked(passphrase, None).await
    }

    pub(crate) async fn web_unlock(&self, passphrase: &str, epoch: u64) -> anyhow::Result<()> {
        self.unlock_checked(passphrase, Some(epoch)).await
    }

    async fn unlock_checked(&self, passphrase: &str, epoch: Option<u64>) -> anyhow::Result<()> {
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("vault is not configured"))?;
        let mut state = self.broker.write().await;
        anyhow::ensure!(
            epoch.is_none_or(|epoch| self.web_epoch() == epoch),
            "operator session changed"
        );
        anyhow::ensure!(state.is_none(), "session is already unlocked");
        source.validate()?;
        let vault = av_core::Vault::open(&source.vault, passphrase)?;
        let broker = if let Some(policy) = &crate::task_recipe::existing_path(source)? {
            if source.service_mode && cfg!(target_os = "linux") {
                Broker::from_vault_with_enforced_proxy_policy(&vault, policy)?
            } else {
                Broker::from_vault_with_proxy_policy(&vault, policy)?
            }
        } else {
            Broker::from_vault(&vault)?
        };
        drop(vault);
        broker.start_host_proxy_listener().await?;
        *state = Some(Arc::new(broker));
        Ok(())
    }

    /// Management and unlock share the exclusive gate. No live broker can
    /// observe credentials or policy from a partially completed operation.
    async fn manage(
        &self,
        passphrase: &str,
        operation: &ManagementOperation,
    ) -> anyhow::Result<serde_json::Value> {
        let state = self.broker.write().await;
        anyhow::ensure!(state.is_none(), "lock the broker before managing its vault");
        anyhow::ensure!(
            !passphrase.is_empty() && passphrase.len() <= 4096,
            "invalid passphrase length"
        );
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("vault is not configured"))?;
        management::validate_source(source)?;
        let vault = av_core::Vault::open(&source.vault, passphrase)
            .map_err(|_| anyhow::anyhow!("vault unlock failed"))?;
        let result = management::execute(&vault, source, operation);
        drop(vault);
        drop(state);
        result
    }

    pub(crate) async fn decide(
        &self,
        passphrase: &str,
        request_id: uuid::Uuid,
        approve: bool,
        ttl_seconds: u64,
    ) -> anyhow::Result<serde_json::Value> {
        self.decide_checked(passphrase, request_id, approve, ttl_seconds, None)
            .await
    }

    pub(crate) async fn web_decide(
        &self,
        passphrase: &str,
        request_id: uuid::Uuid,
        approve: bool,
        epoch: u64,
    ) -> anyhow::Result<serde_json::Value> {
        self.decide_checked(passphrase, request_id, approve, 60, Some(epoch))
            .await
    }

    async fn decide_checked(
        &self,
        passphrase: &str,
        request_id: uuid::Uuid,
        approve: bool,
        ttl_seconds: u64,
        epoch: Option<u64>,
    ) -> anyhow::Result<serde_json::Value> {
        anyhow::ensure!(
            !passphrase.is_empty() && passphrase.len() <= 4096,
            "invalid passphrase length"
        );
        let state = self.broker.read().await;
        anyhow::ensure!(
            epoch.is_none_or(|epoch| self.web_epoch() == epoch),
            "operator session changed"
        );
        let broker = state
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("broker is locked"))?;
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("vault is not configured"))?;
        let vault_path = source.vault.clone();
        let passphrase = Zeroizing::new(passphrase.to_owned());
        tokio::task::spawn_blocking(move || {
            av_core::Vault::open(vault_path, &passphrase).map(drop)
        })
        .await
        .map_err(|_| anyhow::anyhow!("operator authentication failed"))?
        .map_err(|_| anyhow::anyhow!("operator authentication failed"))?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let decision = broker
            .decide(request_id, approve, now, ttl_seconds)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        Ok(serde_json::to_value(decision)?)
    }

    /// The exclusive gate prevents new requests while proxies/runners stop.
    /// Approvals and loaded credentials are discarded with the old broker.
    pub(crate) fn web_epoch(&self) -> u64 {
        self.web_epoch.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub async fn lock(&self) {
        let mut state = self.broker.write().await;
        self.web_epoch
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.mcp.clear();
        if let Some(broker) = state.take() {
            broker.shutdown().await;
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminRequest {
    Status {
        token: String,
    },
    Unlock {
        token: String,
        passphrase: String,
    },
    Lock {
        token: String,
    },
    Manage {
        token: String,
        passphrase: String,
        operation: ManagementOperation,
    },
    Review {
        token: String,
        request_id: uuid::Uuid,
    },
    Decide {
        token: String,
        passphrase: String,
        request_id: uuid::Uuid,
        approve: bool,
        ttl_seconds: u64,
    },
}

impl Drop for AdminRequest {
    fn drop(&mut self) {
        match self {
            Self::Status { token } | Self::Lock { token } | Self::Review { token, .. } => {
                token.zeroize()
            }
            Self::Unlock { token, passphrase }
            | Self::Manage {
                token, passphrase, ..
            }
            | Self::Decide {
                token, passphrase, ..
            } => {
                token.zeroize();
                passphrase.zeroize();
            }
        }
    }
}

pub struct AdminServer {
    listener: UnixListener,
    socket: PathBuf,
    token_path: PathBuf,
    token: Zeroizing<[u8; 32]>,
    session: Arc<Session>,
    operator_uid: u32,
}

impl AdminServer {
    pub async fn bind(base: &Path, session: Arc<Session>) -> io::Result<Self> {
        let socket = base.join("admin.sock");
        let token_path = base.join("admin.token");
        if socket.exists() || token_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "administration endpoint already exists",
            ));
        }
        let mut token = Zeroizing::new([0_u8; 32]);
        rand::rng().fill_bytes(token.as_mut());
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&token_path)?;
        use std::io::Write;
        let encoded = Zeroizing::new(hex::encode(token.as_ref()));
        if let Err(error) = file
            .write_all(encoded.as_bytes())
            .and_then(|_| file.sync_all())
        {
            let _ = fs::remove_file(&token_path);
            return Err(error);
        }
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = fs::remove_file(&token_path);
                return Err(error);
            }
        };
        if let Err(error) = fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(&socket);
            let _ = fs::remove_file(&token_path);
            return Err(error);
        }
        Ok(Self {
            listener,
            socket,
            token_path,
            token,
            session,
            operator_uid: unsafe { libc::geteuid() },
        })
    }

    pub async fn run(self) -> io::Result<()> {
        let slots = Arc::new(Semaphore::new(2));
        let mut handlers = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted?;
                    if !stream.peer_cred().is_ok_and(|peer| peer.uid() == self.operator_uid) { continue; }
                    let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else { continue; };
                    let token = self.token.clone();
                    let session = Arc::clone(&self.session);
                    handlers.spawn(async move {
                        let _permit = permit;
                        let _ = handle_admin(stream, token, session).await;
                    });
                }
                joined = handlers.join_next(), if !handlers.is_empty() => { let _ = joined; }
            }
        }
    }
}

impl Drop for AdminServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_file(&self.token_path);
    }
}

async fn handle_admin(
    mut stream: UnixStream,
    expected: Zeroizing<[u8; 32]>,
    session: Arc<Session>,
) -> io::Result<()> {
    let mut line = Zeroizing::new(String::new());
    timeout(
        Duration::from_secs(5),
        BufReader::new(&mut stream)
            .take(MAX_FRAME + 1)
            .read_line(&mut line),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "administration frame timed out"))??;
    if line.len() as u64 > MAX_FRAME || !line.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid administration frame",
        ));
    }
    let request: AdminRequest = serde_json::from_str(&line)?;
    line.zeroize();
    let token = match &request {
        AdminRequest::Status { token }
        | AdminRequest::Unlock { token, .. }
        | AdminRequest::Lock { token }
        | AdminRequest::Manage { token, .. }
        | AdminRequest::Review { token, .. }
        | AdminRequest::Decide { token, .. } => token,
    };
    let authenticated = hex::decode(token)
        .ok()
        .map(Zeroizing::new)
        .is_some_and(|bytes| {
            bytes.len() == 32 && bool::from(bytes.as_slice().ct_eq(expected.as_ref()))
        });
    let reply = if !authenticated {
        Reply {
            ok: false,
            data: None,
            error: Some("unauthorized".into()),
        }
    } else {
        match &request {
            AdminRequest::Status { .. } => Reply {
                ok: true,
                data: Some(json!({"locked": session.is_locked().await})),
                error: None,
            },
            AdminRequest::Unlock { passphrase, .. } => {
                if passphrase.is_empty()
                    || passphrase.len() > 4096
                    || session.unlock(passphrase).await.is_err()
                {
                    Reply {
                        ok: false,
                        data: None,
                        error: Some("unlock_failed".into()),
                    }
                } else {
                    Reply {
                        ok: true,
                        data: Some(json!({"locked": false})),
                        error: None,
                    }
                }
            }
            AdminRequest::Manage {
                passphrase,
                operation,
                ..
            } => match session.manage(passphrase, operation).await {
                Ok(data) => Reply {
                    ok: true,
                    data: Some(data),
                    error: None,
                },
                Err(error) => Reply {
                    ok: false,
                    data: None,
                    error: Some(error.to_string()),
                },
            },
            AdminRequest::Review { request_id, .. } => {
                let state = session.broker.read().await;
                match state.as_ref().map(|broker| broker.review(*request_id)) {
                    Some(Ok(review)) => Reply {
                        ok: true,
                        data: Some(serde_json::to_value(review)?),
                        error: None,
                    },
                    Some(Err(error)) => Reply {
                        ok: false,
                        data: None,
                        error: Some(format!("{error:?}")),
                    },
                    None => Reply {
                        ok: false,
                        data: None,
                        error: Some("Locked".into()),
                    },
                }
            }
            AdminRequest::Decide {
                passphrase,
                request_id,
                approve,
                ttl_seconds,
                ..
            } => match session
                .decide(passphrase, *request_id, *approve, *ttl_seconds)
                .await
            {
                Ok(data) => Reply {
                    ok: true,
                    data: Some(data),
                    error: None,
                },
                Err(error) => Reply {
                    ok: false,
                    data: None,
                    error: Some(error.to_string()),
                },
            },
            AdminRequest::Lock { .. } => {
                session.lock().await;
                Reply {
                    ok: true,
                    data: Some(json!({"locked": true})),
                    error: None,
                }
            }
        }
    };
    let mut bytes = serde_json::to_vec(&reply)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await
}

/// The administrator verifies the server UID and keeps wire buffers zeroizing.
pub async fn admin_call(socket: &Path, request: &AdminRequest) -> io::Result<Reply> {
    let mut stream = UnixStream::connect(socket).await?;
    if !stream
        .peer_cred()
        .is_ok_and(|peer| peer.uid() == unsafe { libc::geteuid() })
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wrong administration server identity",
        ));
    }
    let mut bytes = Zeroizing::new(serde_json::to_vec(request)?);
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    bytes.zeroize();
    let mut reply = String::new();
    // Locked-vault key derivation and pinned executable verification can exceed
    // one minute on slow isolated hosts; keep the admin wait finite.
    timeout(
        Duration::from_secs(180),
        BufReader::new(stream)
            .take(MAX_FRAME + 1)
            .read_line(&mut reply),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "administration reply timed out"))??;
    if reply.len() as u64 > MAX_FRAME || !reply.ends_with('\n') {
        return Err(io::Error::other("invalid administration reply"));
    }
    serde_json::from_str(&reply).map_err(io::Error::other)
}
