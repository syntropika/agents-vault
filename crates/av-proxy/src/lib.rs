//! A deliberately narrow HTTPS credential injection proxy prototype.
//!
//! The fixed proxy can route bounded concurrent task capabilities, each with
//! one exact CONNECT host and HTTP/1.1 requests within its TLS tunnel. The host broker must keep the
//! proxy listener and grant minting out of reach of an untrusted agent. This
//! crate itself does not establish an OS-level trust boundary or egress policy.
//! The bearer token alone is only prototype authentication. Protected mode
//! must bind it to a broker-authenticated runner or VM transport identity.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures_core::Stream;
use hyper::body::{Bytes, HttpBody};
use hyper::header::{
    ACCEPT_ENCODING, CONTENT_LENGTH, HOST, HeaderName, HeaderValue, PROXY_AUTHORIZATION, TRAILER,
    TRANSFER_ENCODING,
};
use hyper::service::service_fn;
use hyper::{Body, Request, Response, StatusCode, Uri};
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::{AbortHandle, JoinHandle, JoinSet};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const MAX_CONNECT_HEADER_BYTES: usize = 16 * 1024;
const MAX_ACTIVE_CONNECTIONS: usize = 64;
const MAX_ACTIVE_GRANTS: usize = 16;
const MAX_LIFETIME_GRANTS: usize = 4096;
const CONNECT_HEADER_DEADLINE: Duration = Duration::from_secs(5);
/// Maximum body retained for an opt-in admitted request. Larger request bodies
/// are rejected before credential insertion or an upstream connection.
pub const MAX_ADMITTED_REQUEST_BODY_BYTES: usize = 64 * 1024;
/// Maximum upstream response body retained for opt-in round-trip review.
pub const MAX_ADMITTED_RESPONSE_BODY_BYTES: usize = 64 * 1024;
/// Maximum parsed upstream or sanitized response header bytes for review.
pub const MAX_ADMITTED_RESPONSE_HEADER_BYTES: usize = 16 * 1024;

/// A single broker-created task capability. The bearer must be unpredictable
/// in production and issued only after the broker has authorized this task.
pub struct TaskGrant {
    /// Both `Bearer <token>` and `Basic av:<token>` proxy authentication are
    /// accepted. Basic permits standard `HTTPS_PROXY` client configuration.
    pub bearer_token: String,
    pub expires_at: SystemTime,
    pub max_connects: u32,
    pub max_requests: u32,
}

impl fmt::Debug for TaskGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskGrant")
            .field("bearer_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("max_connects", &self.max_connects)
            .field("max_requests", &self.max_requests)
            .finish()
    }
}

/// The broker-owned header value inserted immediately before the upstream hop.
/// A provider can still reflect this value in a response; the proxy cannot
/// guarantee that a malicious or misconfigured provider will keep it secret.
pub struct CredentialInjection {
    pub header_name: HeaderName,
    pub header_value: HeaderValue,
}

impl fmt::Debug for CredentialInjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialInjection")
            .field("header_name", &self.header_name)
            .field("header_value", &"[REDACTED]")
            .finish()
    }
}

/// Every host binding is explicit. The upstream socket is pinned for this
/// prototype; certificate verification still uses `allowed_host` as the SNI
/// and TLS server name, not the socket IP.
pub struct ProxyConfig {
    pub bind_addr: SocketAddr,
    pub allowed_host: String,
    pub allowed_port: u16,
    pub upstream_addr: SocketAddr,
    pub downstream_tls: Arc<rustls::ServerConfig>,
    pub upstream_tls: Arc<rustls::ClientConfig>,
    pub injection: CredentialInjection,
    pub grant: TaskGrant,
}

/// Broker-owned, fail-closed HTTP request policy. `admit` sees the parsed
/// method, parsed origin-form URI, headers (including duplicates), and the
/// complete body before the proxy inserts a credential or opens upstream
/// transport. A policy may synchronize mutable state to enforce admission
/// order across tunnels. It must reject unexpected encodings and headers;
/// this proxy does not interpret application payloads for it. Requests that
/// declare trailers, trailers exposed by Hyper, and bodies above
/// [`MAX_ADMITTED_REQUEST_BODY_BYTES`] are rejected. The proxy reconstructs
/// the forwarded body, so any undeclared trailers discarded by Hyper cannot
/// reach upstream.
///
/// Admission only controls outbound requests. It does not attest upstream
/// responses or bind a later request to an earlier response. A caller that
/// needs response-dependent authorization must add that broker-owned check.
pub trait RequestAdmission: Send + Sync + 'static {
    fn admit(&self, request: &Request<Bytes>) -> bool;
}

/// Broker-owned request and response policy. Both callbacks see complete,
/// bounded bodies. The request is the parsed pre-injection request; the
/// response is the parsed upstream response before anything is returned to
/// the client. `review_response` must return a sanitized replacement. `None`
/// denies the response with an empty generic error. The policy may use
/// interior mutability to enforce request and response order across tunnels.
/// It must validate application payloads and reject reflected credentials;
/// this proxy only enforces collection limits and isolates denied responses.
/// This interface alone does not authorize a production recipe.
pub trait RoundTripAdmission: Send + Sync + 'static {
    fn admit_request(&self, request: &Request<Bytes>) -> bool;
    fn review_response(
        &self,
        request: &Request<Bytes>,
        upstream: &Response<Bytes>,
    ) -> Option<Response<Bytes>>;
}

/// Explicit opt-in authorization for each validated HTTP request. The caller
/// must atomically register the returned permit with its revocation state.
/// This interface is not installed by `bind` and is not a production custody
/// boundary until a broker supplies and owns its implementation.
pub trait ProtectedRequestGate: Send + Sync + 'static {
    fn begin(&self, exact_host: &str) -> Option<Box<dyn ProtectedRequestPermit>>;
}

/// One request's non-clonable authority. The cancellation future must become
/// ready when authority is revoked, including when created after revocation.
/// `with_write_barrier` must check the monotonic deadline and serialize the
/// operation with the same lock that publishes revocation. It must never call
/// the operation after revocation, and must call it exactly once when returning
/// true. The operation is a single nonblocking poll; it must not await or retain
/// the raw socket. Writes already handed to the kernel before revocation may
/// still arrive afterward.
pub trait ProtectedRequestPermit: Send + Sync + 'static {
    fn deadline(&self) -> Instant;
    fn cancelled(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
    fn with_write_barrier(&self, operation: &mut dyn FnMut()) -> bool;
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyConfig")
            .field("bind_addr", &self.bind_addr)
            .field("allowed_host", &self.allowed_host)
            .field("allowed_port", &self.allowed_port)
            .field("upstream_addr", &self.upstream_addr)
            .field("injection", &self.injection)
            .field("grant", &self.grant)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum ProxyError {
    InvalidConfig(&'static str),
    Io(std::io::Error),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid proxy configuration: {message}")
            }
            Self::Io(error) => write!(formatter, "proxy I/O error: {error}"),
        }
    }
}

impl std::error::Error for ProxyError {}

impl From<std::io::Error> for ProxyError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

struct GrantState {
    connects: u32,
    requests: u32,
}

struct Shared {
    allowed_host: String,
    allowed_port: u16,
    upstream_addr: SocketAddr,
    downstream_tls: TlsAcceptor,
    upstream_tls: TlsConnector,
    injection: CredentialInjection,
    grant: TaskGrant,
    state: Mutex<GrantState>,
    request_gate: Option<Arc<dyn ProtectedRequestGate>>,
    request_admission: Option<Arc<dyn RequestAdmission>>,
    round_trip_admission: Option<Arc<dyn RoundTripAdmission>>,
    protected_workers: Arc<ProtectedWorkers>,
}

struct ProtectedWorkers {
    state: Mutex<ProtectedWorkerState>,
}

struct ProtectedWorkerState {
    closed: bool,
    tasks: JoinSet<()>,
}

impl ProtectedWorkers {
    fn close(&self) {
        let mut state = self.state.lock().expect("worker mutex poisoned");
        state.closed = true;
        state.tasks.abort_all();
    }
}

// A canceled `run` future still closes workers even if connection handlers
// temporarily retain the shared proxy state.
struct RunWorkerGuard(Arc<ProtectedWorkers>);

impl Drop for RunWorkerGuard {
    fn drop(&mut self) {
        self.0.close();
    }
}

struct AbortWorkerOnDrop(Option<AbortHandle>);

impl Drop for AbortWorkerOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = &self.0 {
            handle.abort();
        }
    }
}

struct TrackedBody {
    inner: Body,
    _worker: AbortWorkerOnDrop,
}

impl Stream for TrackedBody {
    type Item = Result<Bytes, hyper::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().inner).poll_data(cx)
    }
}

struct ProtectedUpstream {
    allowed_host: String,
    upstream_addr: SocketAddr,
    upstream_tls: TlsConnector,
    injection: CredentialInjection,
}

/// Bound listener. The caller controls lifecycle and must keep the listening
/// socket inside the broker's protected transport boundary.
pub struct ProxyServer {
    listener: TcpListener,
    shared: Arc<Shared>,
}

impl ProxyServer {
    /// Bind with host-only request checks for lower-assurance preview callers.
    pub async fn bind(config: ProxyConfig) -> Result<Self, ProxyError> {
        Self::bind_inner(config, None, None, None).await
    }

    /// Construct an opt-in proxy whose validated HTTP requests need a fresh
    /// broker-owned permit before credential insertion or upstream I/O.
    pub async fn bind_with_request_gate(
        config: ProxyConfig,
        gate: Arc<dyn ProtectedRequestGate>,
    ) -> Result<Self, ProxyError> {
        Self::bind_inner(config, Some(gate), None, None).await
    }

    /// Bind with HTTP admission before credential insertion and upstream I/O.
    /// The caller must keep this policy under broker control.
    pub async fn bind_with_request_admission(
        config: ProxyConfig,
        admission: Arc<dyn RequestAdmission>,
    ) -> Result<Self, ProxyError> {
        Self::bind_inner(config, None, Some(admission), None).await
    }

    /// Combine HTTP admission with a revocable protected request permit.
    pub async fn bind_with_request_gate_and_admission(
        config: ProxyConfig,
        gate: Arc<dyn ProtectedRequestGate>,
        admission: Arc<dyn RequestAdmission>,
    ) -> Result<Self, ProxyError> {
        Self::bind_inner(config, Some(gate), Some(admission), None).await
    }

    /// Bind with broker-owned review of both requests and complete upstream
    /// responses before any upstream response bytes reach the client.
    pub async fn bind_with_round_trip_admission(
        config: ProxyConfig,
        admission: Arc<dyn RoundTripAdmission>,
    ) -> Result<Self, ProxyError> {
        Self::bind_inner(config, None, None, Some(admission)).await
    }

    /// Combine round-trip admission with a revocable protected request permit.
    pub async fn bind_with_request_gate_and_round_trip_admission(
        config: ProxyConfig,
        gate: Arc<dyn ProtectedRequestGate>,
        admission: Arc<dyn RoundTripAdmission>,
    ) -> Result<Self, ProxyError> {
        Self::bind_inner(config, Some(gate), None, Some(admission)).await
    }

    async fn bind_inner(
        config: ProxyConfig,
        request_gate: Option<Arc<dyn ProtectedRequestGate>>,
        request_admission: Option<Arc<dyn RequestAdmission>>,
        round_trip_admission: Option<Arc<dyn RoundTripAdmission>>,
    ) -> Result<Self, ProxyError> {
        let bind_addr = config.bind_addr;
        let shared = make_shared(
            config,
            request_gate,
            request_admission,
            round_trip_admission,
        )?;
        let listener = TcpListener::bind(bind_addr).await?;
        Ok(Self { listener, shared })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ProxyError> {
        Ok(self.listener.local_addr()?)
    }

    /// Run until shutdown. Active tunnels are aborted when this call returns.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), ProxyError> {
        let worker_guard = RunWorkerGuard(Arc::clone(&self.shared.protected_workers));
        tokio::pin!(shutdown);
        let mut connections = tokio::task::JoinSet::new();
        let permits = Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS));
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    worker_guard.0.close();
                    drain_connections(&mut connections, &worker_guard.0).await;
                    return Ok(());
                },
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted?;
                    spawn_connection(stream, None, Arc::clone(&self.shared), &permits, &mut connections);
                },
                result = connections.join_next(), if !connections.is_empty() => { let _ = result; }
            }
        }
    }
}

fn make_shared(
    config: ProxyConfig,
    request_gate: Option<Arc<dyn ProtectedRequestGate>>,
    request_admission: Option<Arc<dyn RequestAdmission>>,
    round_trip_admission: Option<Arc<dyn RoundTripAdmission>>,
) -> Result<Arc<Shared>, ProxyError> {
    if config.allowed_host.is_empty()
        || !config.allowed_host.is_ascii()
        || config.allowed_host.contains(':')
        || config.allowed_host.contains('/')
        || config.allowed_host.contains(' ')
    {
        return Err(ProxyError::InvalidConfig(
            "allowed_host must be a DNS hostname",
        ));
    }
    if config.allowed_port == 0 {
        return Err(ProxyError::InvalidConfig("allowed_port must be nonzero"));
    }
    if !config.bind_addr.ip().is_loopback() {
        return Err(ProxyError::InvalidConfig(
            "prototype listener must be loopback",
        ));
    }
    if config.grant.bearer_token.is_empty()
        || !config.grant.bearer_token.is_ascii()
        || config
            .grant
            .bearer_token
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || config.grant.max_connects == 0
        || config.grant.max_requests == 0
    {
        return Err(ProxyError::InvalidConfig(
            "grant must have a bearer and nonzero quotas",
        ));
    }
    if config.injection.header_name == HOST
        || config.injection.header_name == PROXY_AUTHORIZATION
        || config.injection.header_name.as_str().starts_with("proxy-")
    {
        return Err(ProxyError::InvalidConfig(
            "cannot inject routing or proxy headers",
        ));
    }

    let shared = Shared {
        allowed_host: config.allowed_host.to_ascii_lowercase(),
        allowed_port: config.allowed_port,
        upstream_addr: config.upstream_addr,
        downstream_tls: TlsAcceptor::from(config.downstream_tls),
        upstream_tls: TlsConnector::from(config.upstream_tls),
        injection: config.injection,
        grant: config.grant,
        state: Mutex::new(GrantState {
            connects: 0,
            requests: 0,
        }),
        request_gate,
        request_admission,
        round_trip_admission,
        protected_workers: Arc::new(ProtectedWorkers {
            state: Mutex::new(ProtectedWorkerState {
                closed: false,
                tasks: JoinSet::new(),
            }),
        }),
    };
    Ok(Arc::new(shared))
}

fn spawn_connection(
    stream: TcpStream,
    header: Option<Vec<u8>>,
    shared: Arc<Shared>,
    permits: &Arc<Semaphore>,
    connections: &mut JoinSet<()>,
) {
    let Ok(permit) = Arc::clone(permits).try_acquire_owned() else {
        return;
    };
    connections.spawn(async move {
        let _permit = permit;
        let until_expiry = shared
            .grant
            .expires_at
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        let lifetime = if until_expiry.is_zero() {
            Duration::from_millis(100)
        } else {
            until_expiry.min(Duration::from_secs(60))
        };
        let _ = tokio::time::timeout(lifetime, handle_connection(stream, header, shared)).await;
    });
}

fn spawn_idle_rejection(
    mut stream: TcpStream,
    permits: &Arc<Semaphore>,
    connections: &mut JoinSet<Option<PendingConnect>>,
) {
    let Ok(permit) = Arc::clone(permits).try_acquire_owned() else {
        return;
    };
    connections.spawn(async move {
        let _permit = permit;
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
            stream.shutdown().await
        })
        .await;
        None
    });
}

async fn drain_connections(connections: &mut JoinSet<()>, workers: &Arc<ProtectedWorkers>) {
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    let mut pending = {
        let mut state = workers.state.lock().expect("worker mutex poisoned");
        std::mem::replace(&mut state.tasks, JoinSet::new())
    };
    while pending.join_next().await.is_some() {}
}

enum HubCommand {
    Activate(ProxyConfig, oneshot::Sender<Result<HubGrantId, ProxyError>>),
    Deactivate(HubGrantId, oneshot::Sender<()>),
    Shutdown(oneshot::Sender<()>),
}

/// Identifies one activation independently of its proxy authentication token.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HubGrantId(u64);

struct ActiveGrant {
    shared: Arc<Shared>,
    connections: JoinSet<()>,
}

struct PendingConnect {
    stream: TcpStream,
    header: Vec<u8>,
    eligible: Vec<HubGrantId>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for ActiveGrant {
    fn drop(&mut self) {
        self.shared.protected_workers.close();
        self.connections.abort_all();
    }
}

/// A broker-owned fixed listener. It rejects every connection while idle and
/// routes simultaneous tasks by distinct capabilities. At most 16 grants can
/// be active and 4096 can be activated during one listener lifetime. Reusing
/// a capability is rejected, including after its task has finished.
pub struct ProxyHub {
    address: SocketAddr,
    commands: mpsc::Sender<HubCommand>,
    task: Mutex<Option<JoinHandle<Result<(), ProxyError>>>>,
}

impl ProxyHub {
    pub async fn bind(address: SocketAddr) -> Result<Self, ProxyError> {
        if !address.ip().is_loopback() {
            return Err(ProxyError::InvalidConfig("proxy hub must bind loopback"));
        }
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let (commands, receiver) = mpsc::channel(8);
        let task = tokio::spawn(run_hub(listener, receiver));
        Ok(Self {
            address,
            commands,
            task: Mutex::new(Some(task)),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    pub async fn activate(&self, config: ProxyConfig) -> Result<HubGrantId, ProxyError> {
        if config.bind_addr != self.address {
            return Err(ProxyError::InvalidConfig(
                "grant address must match fixed listener",
            ));
        }
        let (reply, result) = oneshot::channel();
        self.commands
            .send(HubCommand::Activate(config, reply))
            .await
            .map_err(|_| hub_closed())?;
        result.await.map_err(|_| hub_closed())?
    }

    /// Revoke only this activation and wait for its tunnels and workers.
    pub async fn deactivate(&self, id: HubGrantId) -> Result<(), ProxyError> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(HubCommand::Deactivate(id, reply))
            .await
            .map_err(|_| hub_closed())?;
        result.await.map_err(|_| hub_closed())
    }

    pub async fn shutdown(&self) -> Result<(), ProxyError> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(HubCommand::Shutdown(reply))
            .await
            .map_err(|_| hub_closed())?;
        result.await.map_err(|_| hub_closed())?;
        let task = self.task.lock().expect("hub task mutex poisoned").take();
        if let Some(task) = task {
            task.await.map_err(|_| hub_closed())??;
        }
        Ok(())
    }
}

impl Drop for ProxyHub {
    fn drop(&mut self) {
        if let Some(task) = self.task.lock().expect("hub task mutex poisoned").take() {
            task.abort();
        }
    }
}

fn hub_closed() -> ProxyError {
    ProxyError::Io(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "proxy hub stopped",
    ))
}

async fn run_hub(
    listener: TcpListener,
    mut commands: mpsc::Receiver<HubCommand>,
) -> Result<(), ProxyError> {
    let mut active = std::collections::HashMap::<HubGrantId, ActiveGrant>::new();
    let mut used_capabilities = std::collections::HashSet::<[u8; 32]>::new();
    let mut next_id = 0u64;
    let mut awaiting_auth = JoinSet::new();
    let permits = Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS));
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(HubCommand::Activate(config, reply)) => {
                    let capability_digest: [u8; 32] = Sha256::digest(config.grant.bearer_token.as_bytes()).into();
                    let result = if active.len() >= MAX_ACTIVE_GRANTS {
                        Err(ProxyError::InvalidConfig("proxy hub grant capacity reached"))
                    } else if used_capabilities.len() >= MAX_LIFETIME_GRANTS {
                        Err(ProxyError::InvalidConfig("proxy hub lifetime grant capacity reached"))
                    } else if used_capabilities.contains(&capability_digest) {
                        Err(ProxyError::InvalidConfig("reused proxy capability"))
                    } else {
                        make_shared(config, None, None, None).and_then(|shared| {
                            next_id = next_id.checked_add(1).ok_or(
                                ProxyError::InvalidConfig("proxy hub activation ID exhausted")
                            )?;
                            let id = HubGrantId(next_id);
                            used_capabilities.insert(capability_digest);
                            active.insert(id, ActiveGrant {
                                shared,
                                connections: JoinSet::new(),
                            });
                            Ok(id)
                        })
                    };
                    let activated = result.as_ref().ok().copied();
                    if reply.send(result).is_err() {
                        if let Some(grant) = activated.and_then(|id| active.remove(&id)) {
                            close_grant(grant).await;
                        }
                    }
                }
                Some(HubCommand::Deactivate(id, reply)) => {
                    if let Some(grant) = active.remove(&id) {
                        close_grant(grant).await;
                    }
                    let _ = reply.send(());
                }
                Some(HubCommand::Shutdown(reply)) => {
                    close_all_grants(&mut active, &mut awaiting_auth).await;
                    let _ = reply.send(());
                    return Ok(());
                }
                None => {
                    close_all_grants(&mut active, &mut awaiting_auth).await;
                    return Ok(());
                }
            },
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                if active.is_empty() {
                    spawn_idle_rejection(stream, &permits, &mut awaiting_auth);
                } else if let Ok(permit) = Arc::clone(&permits).try_acquire_owned() {
                    // A CONNECT accepted before activation cannot acquire a later grant.
                    let eligible: Vec<_> = active.keys().copied().collect();
                    awaiting_auth.spawn(async move {
                        let mut stream = stream;
                        let header = tokio::time::timeout(
                            CONNECT_HEADER_DEADLINE,
                            read_connect_header(&mut stream),
                        ).await;
                        match header {
                            Ok(Ok(Some(header))) => Some(PendingConnect {
                                stream, header, eligible, _permit: permit,
                            }),
                            _ => None,
                        }
                    });
                } else {
                    drop(stream);
                }
            }
            result = awaiting_auth.join_next(), if !awaiting_auth.is_empty() => {
                if let Some(Ok(Some(pending))) = result {
                    route_connect(pending, &mut active, &mut awaiting_auth);
                }
            }
        }
    }
}

fn route_connect(
    pending: PendingConnect,
    active: &mut std::collections::HashMap<HubGrantId, ActiveGrant>,
    awaiting_auth: &mut JoinSet<Option<PendingConnect>>,
) {
    let authorization = std::str::from_utf8(&pending.header)
        .ok()
        .and_then(|header| {
            let mut values = header.split("\r\n").filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("proxy-authorization")
                    .then_some(value.trim())
            });
            let value = values.next()?;
            values.next().is_none().then_some(value)
        });
    let match_id = authorization.and_then(|auth| {
        active.iter().find_map(|(id, grant)| {
            (pending.eligible.contains(id)
                && valid_proxy_auth(auth, &grant.shared.grant.bearer_token))
            .then_some(*id)
        })
    });
    if let Some(grant) = match_id.and_then(|id| active.get_mut(&id)) {
        let shared = Arc::clone(&grant.shared);
        grant.connections.spawn(async move {
            let lifetime = shared
                .grant
                .expires_at
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO)
                .min(Duration::from_secs(60));
            let _permit = pending._permit;
            let _ = tokio::time::timeout(
                lifetime,
                handle_connection(pending.stream, Some(pending.header), shared),
            )
            .await;
        });
    } else {
        awaiting_auth.spawn(async move {
            let mut stream = pending.stream;
            let _permit = pending._permit;
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                reject_connect(&mut stream, "407 Proxy Authentication Required"),
            )
            .await;
            None
        });
    }
}

async fn close_grant(mut grant: ActiveGrant) {
    grant.shared.protected_workers.close();
    drain_connections(&mut grant.connections, &grant.shared.protected_workers).await;
}

async fn close_all_grants(
    active: &mut std::collections::HashMap<HubGrantId, ActiveGrant>,
    awaiting_auth: &mut JoinSet<Option<PendingConnect>>,
) {
    awaiting_auth.abort_all();
    while awaiting_auth.join_next().await.is_some() {}
    for (_, grant) in active.drain() {
        close_grant(grant).await;
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    header: Option<Vec<u8>>,
    shared: Arc<Shared>,
) -> std::io::Result<()> {
    let header = match header {
        Some(header) => header,
        None => {
            match tokio::time::timeout(CONNECT_HEADER_DEADLINE, read_connect_header(&mut stream))
                .await
            {
                Ok(Ok(Some(header))) => header,
                Ok(Ok(None)) | Err(_) => return Ok(()),
                Ok(Err(error)) => return Err(error),
            }
        }
    };

    let header = match std::str::from_utf8(&header) {
        Ok(value) => value,
        Err(_) => {
            reject_connect(&mut stream, "400 Bad Request").await?;
            return Ok(());
        }
    };
    let mut lines = header.split("\r\n");
    let Some(request_line) = lines.next() else {
        reject_connect(&mut stream, "400 Bad Request").await?;
        return Ok(());
    };
    let mut words = request_line.split(' ');
    let (Some(method), Some(authority), Some(version), None) =
        (words.next(), words.next(), words.next(), words.next())
    else {
        reject_connect(&mut stream, "400 Bad Request").await?;
        return Ok(());
    };
    let exact_authority = format!("{}:{}", shared.allowed_host, shared.allowed_port);
    if method != "CONNECT"
        || version != "HTTP/1.1"
        || !authority.eq_ignore_ascii_case(&exact_authority)
    {
        reject_connect(&mut stream, "403 Forbidden").await?;
        return Ok(());
    }

    let mut authorization = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            reject_connect(&mut stream, "400 Bad Request").await?;
            return Ok(());
        };
        if name.eq_ignore_ascii_case("proxy-authorization")
            && authorization.replace(value.trim()).is_some()
        {
            reject_connect(&mut stream, "400 Bad Request").await?;
            return Ok(());
        }
    }
    if !authorization.is_some_and(|value| valid_proxy_auth(value, &shared.grant.bearer_token)) {
        reject_connect(&mut stream, "407 Proxy Authentication Required").await?;
        return Ok(());
    }
    let permitted = {
        let mut state = shared.state.lock().expect("grant state mutex poisoned");
        if SystemTime::now() >= shared.grant.expires_at
            || state.connects >= shared.grant.max_connects
            || state.requests >= shared.grant.max_requests
        {
            false
        } else {
            state.connects += 1;
            true
        }
    };
    if !permitted {
        reject_connect(&mut stream, "403 Forbidden").await?;
        return Ok(());
    }

    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let tls = match shared.downstream_tls.accept(stream).await {
        Ok(tls) => tls,
        Err(_) => return Ok(()),
    };
    let negotiated_host = tls.get_ref().1.server_name();
    if !negotiated_host.is_some_and(|name| name.eq_ignore_ascii_case(&shared.allowed_host))
        || tls
            .get_ref()
            .1
            .alpn_protocol()
            .is_some_and(|alpn| alpn != b"http/1.1")
    {
        return Ok(());
    }
    let service = service_fn(move |request| {
        let shared = Arc::clone(&shared);
        async move { Ok::<_, std::convert::Infallible>(forward(request, shared).await) }
    });
    let _ = hyper::server::conn::Http::new()
        .http1_only(true)
        .serve_connection(tls, service)
        .await;
    Ok(())
}

async fn read_connect_header(stream: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    // Read byte by byte until the CONNECT header is complete so no TLS record
    // sent immediately after CONNECT is consumed by the HTTP parser.
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= MAX_CONNECT_HEADER_BYTES {
            reject_connect(stream, "431 Request Header Fields Too Large").await?;
            return Ok(None);
        }
        let mut byte = [0];
        if stream.read_exact(&mut byte).await.is_err() {
            return Ok(None);
        }
        header.push(byte[0]);
    }
    Ok(Some(header))
}

fn valid_proxy_auth(value: &str, token: &str) -> bool {
    let Some((scheme, credential)) = value.split_once(' ') else {
        return false;
    };
    if scheme.eq_ignore_ascii_case("Bearer") {
        return bool::from(credential.as_bytes().ct_eq(token.as_bytes()));
    }
    if scheme.eq_ignore_ascii_case("Basic") {
        let Ok(decoded) = STANDARD.decode(credential) else {
            return false;
        };
        let expected = format!("av:{token}");
        return bool::from(decoded.as_slice().ct_eq(expected.as_bytes()));
    }
    false
}

async fn reject_connect(stream: &mut TcpStream, status: &str) -> std::io::Result<()> {
    stream
        .write_all(
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
}

fn error_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-length", "0")
        .body(Body::empty())
        .expect("static error response")
}

async fn forward(mut request: Request<Body>, shared: Arc<Shared>) -> Response<Body> {
    let host_count = request.headers().get_all(HOST).iter().count();
    let host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok());
    let expected_with_port = format!("{}:{}", shared.allowed_host, shared.allowed_port);
    let host_is_allowed = host.is_some_and(|value| {
        value.eq_ignore_ascii_case(&expected_with_port)
            || (shared.allowed_port == 443 && value.eq_ignore_ascii_case(&shared.allowed_host))
    });
    if host_count != 1
        || !host_is_allowed
        || request.uri().authority().is_some()
        || request.uri().scheme().is_some()
        || request.method() == hyper::Method::CONNECT
        || request.headers().contains_key("upgrade")
    {
        return error_response(StatusCode::FORBIDDEN);
    }
    {
        let mut state = shared.state.lock().expect("grant state mutex poisoned");
        if SystemTime::now() >= shared.grant.expires_at
            || state.requests >= shared.grant.max_requests
        {
            return error_response(StatusCode::FORBIDDEN);
        }
        state.requests += 1;
    }

    let mut review_request = None;
    if shared.request_admission.is_some() || shared.round_trip_admission.is_some() {
        let inspected = match buffer_bounded_request(request).await {
            Ok(request) => request,
            Err(status) => return error_response(status),
        };
        if shared
            .request_admission
            .as_ref()
            .is_some_and(|policy| !policy.admit(&inspected))
            || shared
                .round_trip_admission
                .as_ref()
                .is_some_and(|policy| !policy.admit_request(&inspected))
        {
            return error_response(StatusCode::FORBIDDEN);
        }
        if shared.round_trip_admission.is_some() {
            review_request = Some(snapshot_request(&inspected));
        }
        let (mut parts, body) = inspected.into_parts();
        // The inspected bytes become the only outbound body. Recompute its
        // framing rather than forwarding the client's original framing.
        parts.headers.remove(TRANSFER_ENCODING);
        parts.headers.remove(CONTENT_LENGTH);
        parts.headers.insert(
            CONTENT_LENGTH,
            body.len().to_string().parse().expect("decimal body length"),
        );
        if shared.round_trip_admission.is_some() {
            // Response review operates on bounded JSON bytes, so do not ask
            // upstream to compress the response on this path.
            parts.headers.remove(ACCEPT_ENCODING);
        }
        request = Request::from_parts(parts, Body::from(body));
    }

    if let Some(gate) = &shared.request_gate {
        let Some(permit) = gate.begin(&shared.allowed_host) else {
            return error_response(StatusCode::FORBIDDEN);
        };
        return protected_forward(request, shared, permit, review_request).await;
    }

    // Proxy auth is only for the CONNECT hop. A child-supplied value in the
    // selected auth slot is overwritten before the upstream request.
    request.headers_mut().remove(PROXY_AUTHORIZATION);
    request.headers_mut().insert(
        shared.injection.header_name.clone(),
        shared.injection.header_value.clone(),
    );
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let uri: Uri = match path.parse() {
        Ok(uri) => uri,
        Err(_) => return error_response(StatusCode::BAD_REQUEST),
    };
    *request.uri_mut() = uri;

    let stream = match TcpStream::connect(shared.upstream_addr).await {
        Ok(stream) => stream,
        Err(_) => return error_response(StatusCode::BAD_GATEWAY),
    };
    let name = match ServerName::try_from(shared.allowed_host.clone()) {
        Ok(name) => name,
        Err(_) => return error_response(StatusCode::BAD_GATEWAY),
    };
    let tls = match shared.upstream_tls.connect(name, stream).await {
        Ok(tls) => tls,
        Err(_) => return error_response(StatusCode::BAD_GATEWAY),
    };
    let (mut sender, connection) = match hyper::client::conn::handshake(tls).await {
        Ok(parts) => parts,
        Err(_) => return error_response(StatusCode::BAD_GATEWAY),
    };
    tokio::spawn(async move {
        let _ = connection.await;
    });
    match sender.send_request(request).await {
        Ok(response) => {
            if let (Some(policy), Some(review_request)) =
                (&shared.round_trip_admission, review_request.as_ref())
            {
                let upstream = match buffer_bounded_response(response).await {
                    Ok(response) => response,
                    Err(_) => return error_response(StatusCode::BAD_GATEWAY),
                };
                return reviewed_response(policy.as_ref(), review_request, &upstream);
            }
            response
        }
        Err(_) => error_response(StatusCode::BAD_GATEWAY),
    }
}

fn snapshot_request(request: &Request<Bytes>) -> Request<Bytes> {
    let mut snapshot = Request::builder()
        .method(request.method())
        .uri(request.uri())
        .version(request.version())
        .body(request.body().clone())
        .expect("parsed request metadata");
    *snapshot.headers_mut() = request.headers().clone();
    snapshot
}

async fn buffer_bounded_request(request: Request<Body>) -> Result<Request<Bytes>, StatusCode> {
    let (parts, mut body) = request.into_parts();
    if parts.headers.contains_key("trailer") {
        return Err(StatusCode::BAD_REQUEST);
    }
    let size_hint = HttpBody::size_hint(&body);
    if size_hint.lower() > MAX_ADMITTED_REQUEST_BODY_BYTES as u64
        || size_hint
            .upper()
            .is_some_and(|size| size > MAX_ADMITTED_REQUEST_BODY_BYTES as u64)
    {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let mut collected = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
        if chunk.len() > MAX_ADMITTED_REQUEST_BODY_BYTES - collected.len() {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        collected.extend_from_slice(&chunk);
    }
    // Trailers are not part of the policy input and must never reach upstream.
    if body
        .trailers()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .is_some()
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(Request::from_parts(parts, Bytes::from(collected)))
}

fn headers_within_limit(headers: &hyper::HeaderMap, limit: usize) -> bool {
    let mut bytes = 0usize;
    for (name, value) in headers {
        let Some(next) = bytes
            .checked_add(name.as_str().len())
            .and_then(|count| count.checked_add(value.as_bytes().len()))
            .and_then(|count| count.checked_add(4))
        else {
            return false;
        };
        if next > limit {
            return false;
        }
        bytes = next;
    }
    true
}

async fn buffer_bounded_response(response: Response<Body>) -> Result<Response<Bytes>, ()> {
    let (parts, mut body) = response.into_parts();
    if !headers_within_limit(&parts.headers, MAX_ADMITTED_RESPONSE_HEADER_BYTES)
        || parts.headers.contains_key(TRAILER)
    {
        return Err(());
    }
    let size_hint = HttpBody::size_hint(&body);
    if size_hint.lower() > MAX_ADMITTED_RESPONSE_BODY_BYTES as u64
        || size_hint
            .upper()
            .is_some_and(|size| size > MAX_ADMITTED_RESPONSE_BODY_BYTES as u64)
    {
        return Err(());
    }
    let mut collected = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|_| ())?;
        if chunk.len() > MAX_ADMITTED_RESPONSE_BODY_BYTES - collected.len() {
            return Err(());
        }
        collected.extend_from_slice(&chunk);
    }
    if body.trailers().await.map_err(|_| ())?.is_some() {
        return Err(());
    }
    Ok(Response::from_parts(parts, Bytes::from(collected)))
}

fn reviewed_response(
    policy: &dyn RoundTripAdmission,
    request: &Request<Bytes>,
    upstream: &Response<Bytes>,
) -> Response<Body> {
    let Some(sanitized) = policy.review_response(request, upstream) else {
        return error_response(StatusCode::BAD_GATEWAY);
    };
    if sanitized.body().len() > MAX_ADMITTED_RESPONSE_BODY_BYTES
        || !headers_within_limit(sanitized.headers(), MAX_ADMITTED_RESPONSE_HEADER_BYTES)
    {
        return error_response(StatusCode::BAD_GATEWAY);
    }
    let (mut parts, body) = sanitized.into_parts();
    parts.headers.remove(CONTENT_LENGTH);
    parts.headers.remove(TRANSFER_ENCODING);
    parts.headers.remove(TRAILER);
    Response::from_parts(parts, Body::from(body))
}

async fn protected_forward(
    request: Request<Body>,
    shared: Arc<Shared>,
    permit: Box<dyn ProtectedRequestPermit>,
    review_request: Option<Request<Bytes>>,
) -> Response<Body> {
    let (reply, received) = oneshot::channel();
    let deadline = permit.deadline();
    let cancelled = permit.cancelled();
    let round_trip_admission = shared.round_trip_admission.clone();
    let upstream = ProtectedUpstream {
        allowed_host: shared.allowed_host.clone(),
        upstream_addr: shared.upstream_addr,
        upstream_tls: shared.upstream_tls.clone(),
        injection: CredentialInjection {
            header_name: shared.injection.header_name.clone(),
            header_value: shared.injection.header_value.clone(),
        },
    };
    let abort = {
        let mut state = shared
            .protected_workers
            .state
            .lock()
            .expect("worker mutex poisoned");
        if state.closed {
            return error_response(StatusCode::FORBIDDEN);
        }
        while state.tasks.try_join_next().is_some() {}
        state.tasks.spawn(async move {
            let mut reply = Some(reply);
            tokio::select! {
                biased;
                _ = cancelled => {
                    send_protected_error(&mut reply, StatusCode::FORBIDDEN);
                }
                _ = tokio::time::sleep_until(deadline.into()) => {
                    send_protected_error(&mut reply, StatusCode::FORBIDDEN);
                }
                result = protected_worker(request, upstream, permit, review_request, round_trip_admission, &mut reply) => {
                    if let Err(status) = result {
                        send_protected_error(&mut reply, status);
                    }
                }
            }
        })
    };
    let mut abort = AbortWorkerOnDrop(Some(abort));
    let response = received
        .await
        .unwrap_or_else(|_| error_response(StatusCode::BAD_GATEWAY));
    let (parts, body) = response.into_parts();
    let tracked = TrackedBody {
        inner: body,
        _worker: AbortWorkerOnDrop(abort.0.take()),
    };
    Response::from_parts(parts, Body::wrap_stream(tracked))
}

fn send_protected_error(reply: &mut Option<oneshot::Sender<Response<Body>>>, status: StatusCode) {
    if let Some(reply) = reply.take() {
        let _ = reply.send(error_response(status));
    }
}

async fn protected_worker(
    mut request: Request<Body>,
    upstream: ProtectedUpstream,
    permit: Box<dyn ProtectedRequestPermit>,
    review_request: Option<Request<Bytes>>,
    round_trip_admission: Option<Arc<dyn RoundTripAdmission>>,
    reply: &mut Option<oneshot::Sender<Response<Body>>>,
) -> Result<(), StatusCode> {
    request.headers_mut().remove(PROXY_AUTHORIZATION);
    request.headers_mut().insert(
        upstream.injection.header_name,
        upstream.injection.header_value,
    );
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    *request.uri_mut() = path.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

    let stream = TcpStream::connect(upstream.upstream_addr)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let name = ServerName::try_from(upstream.allowed_host).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let tls = upstream
        .upstream_tls
        .connect(name, GatedSocket { stream, permit })
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let (mut sender, connection) = hyper::client::conn::handshake(tls)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    tokio::pin!(connection);
    let response = tokio::select! {
        response = sender.send_request(request) => response.map_err(|_| StatusCode::BAD_GATEWAY)?,
        _ = &mut connection => return Err(StatusCode::BAD_GATEWAY),
    };
    if let (Some(policy), Some(review_request)) = (round_trip_admission, review_request) {
        let upstream = tokio::select! {
            response = buffer_bounded_response(response) => response.map_err(|_| StatusCode::BAD_GATEWAY)?,
            _ = &mut connection => return Err(StatusCode::BAD_GATEWAY),
        };
        if let Some(reply) = reply.take() {
            let _ = reply.send(reviewed_response(
                policy.as_ref(),
                &review_request,
                &upstream,
            ));
        }
        return Ok(());
    }
    let (parts, mut body) = response.into_parts();
    let (mut body_sender, outbound_body) = Body::channel();
    if let Some(reply) = reply.take()
        && reply
            .send(Response::from_parts(parts, outbound_body))
            .is_err()
    {
        return Ok(());
    }
    loop {
        let next = tokio::select! {
            next = body.data() => next,
            _ = &mut connection => break,
        };
        let Some(Ok(chunk)) = next else { break };
        let sent = tokio::select! {
            sent = body_sender.send_data(chunk) => sent,
            _ = &mut connection => break,
        };
        if sent.is_err() {
            break;
        }
    }
    Ok(())
}

struct GatedSocket {
    stream: TcpStream,
    permit: Box<dyn ProtectedRequestPermit>,
}

impl AsyncRead for GatedSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

fn denied_write<T>() -> Poll<io::Result<T>> {
    Poll::Ready(Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "protected request revoked or expired",
    )))
}

impl AsyncWrite for GatedSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut result = None;
        let allowed = this.permit.with_write_barrier(&mut || {
            result = Some(Pin::new(&mut this.stream).poll_write(cx, buf));
        });
        if allowed {
            result.expect("write barrier did not poll")
        } else {
            denied_write()
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut result = None;
        let allowed = this.permit.with_write_barrier(&mut || {
            result = Some(Pin::new(&mut this.stream).poll_write_vectored(cx, bufs));
        });
        if allowed {
            result.expect("write barrier did not poll")
        } else {
            denied_write()
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut result = None;
        let allowed = this.permit.with_write_barrier(&mut || {
            result = Some(Pin::new(&mut this.stream).poll_flush(cx));
        });
        if allowed {
            result.expect("write barrier did not poll")
        } else {
            denied_write()
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut result = None;
        let allowed = this.permit.with_write_barrier(&mut || {
            result = Some(Pin::new(&mut this.stream).poll_shutdown(cx));
        });
        if allowed {
            result.expect("write barrier did not poll")
        } else {
            denied_write()
        }
    }
}
