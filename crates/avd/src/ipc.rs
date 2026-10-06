//! Agent and selected CLI Unix sockets for the broker.

use std::{
    future::Future,
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    time::{Duration, timeout},
};
use uuid::Uuid;

use crate::{Broker, BrokerError, ExecutionSession, Operation};

const MAX_REQUEST_BYTES: u64 = 65_536;
const MAX_ACTIVE_AGENT_HANDLERS: usize = 48;
const MAX_ACTIVE_CLIENT_HANDLERS: usize = 16;
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);
const ACTION_DEADLINE: Duration = Duration::from_secs(20);
const SESSION_DEADLINE: Duration = Duration::from_secs(420);
const IDLE_DEADLINE: Duration = Duration::from_secs(300);

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub agent_socket: PathBuf,
}

/// Optional human CLI endpoint. It is enabled only by an explicit service UID.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub socket: PathBuf,
    pub uid: u32,
}

/// Kernel-authenticated identity allowed to submit agent requests.
#[derive(Clone, Copy, Debug)]
pub struct PeerPolicy {
    pub agent_uid: u32,
}

pub struct Server {
    agent: UnixListener,
    client: Option<UnixListener>,
    client_config: Option<ClientConfig>,
    config: ServerConfig,
    session: Arc<crate::session::Session>,
    peers: PeerPolicy,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentRequest {
    Request {
        operation: Operation,
    },
    Review {
        request_id: Uuid,
    },
    ApprovalLink {
        request_id: Uuid,
    },
    McpEnroll {
        nonce: String,
    },
    McpRequest {
        nonce: String,
        request_id: Uuid,
        operation: Operation,
    },
    McpReview {
        nonce: String,
        request_id: Uuid,
    },
    McpDecide {
        nonce: String,
        request_id: Uuid,
        review_digest: String,
        approve: bool,
    },
    Execute {
        request_id: Uuid,
    },
    TaskStatus {
        task_id: Uuid,
    },
    FinishHostProxy {
        task_id: Uuid,
        exit_code: i32,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientRequest {
    Request { operation: Operation },
    Execute { request_id: Uuid },
    TaskStatus { task_id: Uuid },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Reply {
    fn data(data: Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(error.into()),
        }
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn broker_reply<T: Serialize>(result: Result<T, BrokerError>) -> Reply {
    match result {
        Ok(data) => Reply::data(serde_json::to_value(data).expect("broker reply serializes")),
        Err(error) => Reply::error(format!("{error:?}")),
    }
}

impl Server {
    pub async fn bind(config: ServerConfig, broker: Arc<Broker>) -> io::Result<Self> {
        let uid = unsafe { libc::geteuid() };
        Self::bind_with_peer_policy(config, broker, PeerPolicy { agent_uid: uid }).await
    }

    pub async fn bind_with_peer_policy(
        config: ServerConfig,
        broker: Arc<Broker>,
        peers: PeerPolicy,
    ) -> io::Result<Self> {
        Self::bind_with_session(config, crate::session::Session::ready(broker), peers).await
    }

    pub async fn bind_with_session(
        config: ServerConfig,
        session: Arc<crate::session::Session>,
        peers: PeerPolicy,
    ) -> io::Result<Self> {
        Self::bind_with_session_and_client(config, session, peers, None).await
    }

    pub async fn bind_with_session_and_client(
        config: ServerConfig,
        session: Arc<crate::session::Session>,
        peers: PeerPolicy,
        client_config: Option<ClientConfig>,
    ) -> io::Result<Self> {
        if client_config.as_ref().is_some_and(|client| {
            client.uid == 0 || client.socket != config.agent_socket.with_file_name("client.sock")
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid client endpoint",
            ));
        }
        for path in std::iter::once(&config.agent_socket)
            .chain(client_config.as_ref().map(|client| &client.socket))
        {
            if path.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("refusing to replace existing path: {}", path.display()),
                ));
            }
        }

        session
            .start_host_proxy_listener()
            .await
            .map_err(io::Error::other)?;

        let mut created = Vec::new();
        let setup = (|| -> io::Result<(UnixListener, Option<UnixListener>)> {
            let agent = UnixListener::bind(&config.agent_socket)?;
            created.push(config.agent_socket.clone());
            let client = if let Some(client) = &client_config {
                let listener = UnixListener::bind(&client.socket)?;
                created.push(client.socket.clone());
                std::fs::set_permissions(
                    &client.socket,
                    std::fs::Permissions::from_mode(if client.uid == unsafe { libc::geteuid() } {
                        0o600
                    } else {
                        0o666
                    }),
                )?;
                Some(listener)
            } else {
                None
            };
            std::fs::set_permissions(
                &config.agent_socket,
                std::fs::Permissions::from_mode(if peers.agent_uid == unsafe { libc::geteuid() } {
                    0o600
                } else {
                    0o666
                }),
            )?;
            Ok((agent, client))
        })();
        let (agent, client) = match setup {
            Ok(listeners) => listeners,
            Err(error) => {
                for path in created {
                    let _ = std::fs::remove_file(path);
                }
                return Err(error);
            }
        };

        Ok(Self {
            agent,
            client,
            client_config,
            config,
            session,
            peers,
        })
    }

    pub async fn run(self, shutdown: impl Future<Output = ()>) -> io::Result<()> {
        tokio::pin!(shutdown);
        let agent_handlers = Arc::new(Semaphore::new(MAX_ACTIVE_AGENT_HANDLERS));
        let client_handlers = Arc::new(Semaphore::new(MAX_ACTIVE_CLIENT_HANDLERS));
        loop {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                connection = self.agent.accept() => {
                    let (stream, _) = connection?;
                    if !peer_is_authorized(&stream, self.peers.agent_uid) { continue; }
                    let Ok(permit) = Arc::clone(&agent_handlers).try_acquire_owned() else { continue; };
                    let session = Arc::clone(&self.session);
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _ = timeout(SESSION_DEADLINE, handle_connection(stream, session, false)).await;
                    });
                }
                connection = async {
                    match &self.client {
                        Some(listener) => listener.accept().await,
                        None => std::future::pending().await,
                    }
                } => {
                    let (stream, _) = connection?;
                    let Some(client) = &self.client_config else { continue; };
                    if !peer_is_authorized(&stream, client.uid) { continue; }
                    let Ok(permit) = Arc::clone(&client_handlers).try_acquire_owned() else { continue; };
                    let session = Arc::clone(&self.session);
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _ = timeout(SESSION_DEADLINE, handle_connection(stream, session, true)).await;
                    });
                }
            }
        }
    }
}

fn peer_is_authorized(stream: &UnixStream, expected_uid: u32) -> bool {
    stream
        .peer_cred()
        .is_ok_and(|credentials| credentials.uid() == expected_uid)
}

impl Drop for Server {
    fn drop(&mut self) {
        for path in std::iter::once(&self.config.agent_socket)
            .chain(self.client_config.as_ref().map(|client| &client.socket))
        {
            let _ = std::fs::remove_file(path);
        }
    }
}

struct ExecutionGuard {
    owner: ExecutionSession,
    brokers: Vec<std::sync::Weak<Broker>>,
    reader: tokio::task::JoinHandle<()>,
}
impl Drop for ExecutionGuard {
    fn drop(&mut self) {
        self.reader.abort();
        for broker in &self.brokers {
            if let Some(broker) = broker.upgrade() {
                broker.close_execution_session(&self.owner);
            }
        }
    }
}

/// One persistent reader preserves pipelined frames and detects EOF during execution.
async fn read_frames(
    stream: tokio::net::unix::OwnedReadHalf,
    sender: tokio::sync::mpsc::Sender<String>,
    closed: tokio::sync::watch::Sender<bool>,
) {
    let mut reader = BufReader::new(stream);
    let mut first = true;
    loop {
        let idle = if first {
            REQUEST_DEADLINE
        } else {
            IDLE_DEADLINE
        };
        first = false;
        match timeout(idle, reader.fill_buf()).await {
            Ok(Ok(bytes)) if !bytes.is_empty() => {}
            _ => break,
        }
        let mut line = String::new();
        let read = timeout(
            REQUEST_DEADLINE,
            (&mut reader)
                .take(MAX_REQUEST_BYTES + 1)
                .read_line(&mut line),
        )
        .await;
        if !matches!(read, Ok(Ok(count)) if count > 0 && count as u64 <= MAX_REQUEST_BYTES)
            || !line.ends_with('\n')
        {
            break;
        }
        // A full queue closes the connection; never block EOF monitoring on a caller.
        if sender.try_send(line).is_err() {
            break;
        }
    }
    closed.send_replace(true);
}

async fn handle_connection(
    stream: UnixStream,
    session: Arc<crate::session::Session>,
    client: bool,
) -> io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let (sender, mut frames) = tokio::sync::mpsc::channel(8);
    let (closed, mut closure) = tokio::sync::watch::channel(false);
    let mut guard = ExecutionGuard {
        owner: ExecutionSession::new(),
        brokers: Vec::new(),
        reader: tokio::spawn(read_frames(reader, sender, closed)),
    };
    loop {
        let line = tokio::select! {
            biased;
            _ = closure.changed() => return Ok(()),
            line = frames.recv() => match line { Some(line) => line, None => return Ok(()) },
        };
        if *closure.borrow() {
            return Ok(());
        }
        let action = async {
            let state = session.broker.read().await;
            let Some(broker) = state.as_ref() else {
                return Reply::error("Locked");
            };
            if !guard
                .brokers
                .iter()
                .any(|b| b.ptr_eq(&Arc::downgrade(broker)))
            {
                guard.brokers.push(Arc::downgrade(broker));
            }
            if client {
                dispatch_client(&line, broker, &guard.owner).await
            } else {
                dispatch_agent(&line, &session, broker, &guard.owner).await
            }
        };
        let reply = tokio::select! {
            biased;
            _ = closure.changed() => return Ok(()),
            result = timeout(ACTION_DEADLINE, action) => match result { Ok(reply) => reply, Err(_) => return Ok(()) },
        };
        let mut bytes = serde_json::to_vec(&reply)?;
        bytes.push(b'\n');
        tokio::select! {
            biased;
            _ = closure.changed() => return Ok(()),
            result = timeout(REQUEST_DEADLINE, writer.write_all(&bytes)) => {
                result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "reply timed out"))??;
            },
        }
    }
}

async fn dispatch_agent(
    line: &str,
    session: &crate::session::Session,
    broker: &Arc<Broker>,
    owner: &ExecutionSession,
) -> Reply {
    match serde_json::from_str::<AgentRequest>(line) {
        Ok(AgentRequest::Request { operation }) => broker_reply(
            broker
                .request(owner, operation)
                .map(|request_id| json!({ "request_id": request_id })),
        ),
        Ok(AgentRequest::Review { request_id }) => broker_reply(broker.review(request_id)),
        Ok(AgentRequest::ApprovalLink { request_id }) => match broker.review(request_id) {
            Ok(review) if review.state == crate::RequestState::Pending => {
                match session.approval_link(request_id) {
                    Some(url) => Reply::data(json!({"url": url})),
                    None => Reply::error("approval_ui_unavailable"),
                }
            }
            Ok(_) => Reply::error("request_not_pending"),
            Err(error) => broker_reply::<Value>(Err(error)),
        },
        Ok(AgentRequest::McpEnroll { nonce }) => {
            mcp_reply(session.mcp.enroll(&nonce, session.web_epoch()))
        }
        Ok(AgentRequest::McpRequest {
            nonce,
            request_id,
            operation,
        }) => mcp_reply(session.mcp.request(
            &nonce,
            request_id,
            operation,
            broker,
            session.web_epoch(),
        )),
        Ok(AgentRequest::McpReview { nonce, request_id }) => mcp_reply(session.mcp.review(
            &nonce,
            request_id,
            broker,
            session.web_epoch(),
        )),
        Ok(AgentRequest::McpDecide {
            nonce,
            request_id,
            review_digest,
            approve,
        }) => mcp_reply(session.mcp.decide(
            &nonce,
            request_id,
            &review_digest,
            approve,
            broker,
            session.web_epoch(),
        )),
        Ok(AgentRequest::Execute { request_id }) => broker_reply(
            broker
                .execute_or_start(owner, request_id, now_seconds())
                .await,
        ),
        Ok(AgentRequest::TaskStatus { task_id }) => broker_reply(broker.task_status(task_id)),
        Ok(AgentRequest::FinishHostProxy { task_id, exit_code }) => {
            broker_reply(broker.finish_host_proxy(owner, task_id, exit_code))
        }
        Err(_) => Reply::error("invalid_request"),
    }
}

async fn dispatch_client(line: &str, broker: &Arc<Broker>, owner: &ExecutionSession) -> Reply {
    match serde_json::from_str::<ClientRequest>(line) {
        Ok(ClientRequest::Request { operation }) if client_action(&operation.action) => {
            broker_reply(
                broker
                    .request(owner, operation)
                    .map(|request_id| json!({ "request_id": request_id })),
            )
        }
        Ok(ClientRequest::Execute { request_id }) => match broker.review(request_id) {
            Ok(review) if client_action(&review.operation.action) => broker_reply(
                broker
                    .execute_or_start(owner, request_id, now_seconds())
                    .await,
            ),
            _ => Reply::error("invalid_request"),
        },
        Ok(ClientRequest::TaskStatus { task_id }) => match broker.review(task_id) {
            Ok(review) if client_action(&review.operation.action) => {
                broker_reply(broker.task_status(task_id))
            }
            _ => Reply::error("invalid_request"),
        },
        Ok(ClientRequest::Request { .. }) | Err(_) => Reply::error("invalid_request"),
    }
}

fn client_action(action: &str) -> bool {
    action == "proxy.run"
}

/// A connection carries execution authority; reconnecting never resumes that authority.
pub struct Connection {
    reader: BufReader<UnixStream>,
}
impl Connection {
    pub async fn connect(socket: &Path) -> io::Result<Self> {
        Ok(Self {
            reader: BufReader::new(UnixStream::connect(socket).await?),
        })
    }
    pub async fn call<T: Serialize>(&mut self, request: &T) -> io::Result<Reply> {
        timeout(ACTION_DEADLINE, async {
            let mut bytes = serde_json::to_vec(request)?;
            if bytes.len() as u64 >= MAX_REQUEST_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "request too large",
                ));
            }
            bytes.push(b'\n');
            self.reader.get_mut().write_all(&bytes).await?;
            let mut reply = String::new();
            (&mut self.reader)
                .take(MAX_REQUEST_BYTES + 1)
                .read_line(&mut reply)
                .await?;
            if reply.len() as u64 > MAX_REQUEST_BYTES || !reply.ends_with('\n') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid broker reply",
                ));
            }
            serde_json::from_str(&reply)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "broker IPC timed out"))?
    }
}

/// Stateless operations may use a temporary connection. A request is revoked on close.
pub async fn call<T: Serialize>(socket: &Path, request: &T) -> io::Result<Reply> {
    Connection::connect(socket).await?.call(request).await
}
pub async fn call_client(socket: &Path, request: &ClientRequest) -> io::Result<Reply> {
    call(socket, request).await
}
pub async fn call_agent(socket: &Path, request: &AgentRequest) -> io::Result<Reply> {
    call(socket, request).await
}

fn mcp_reply(result: anyhow::Result<Value>) -> Reply {
    match result {
        Ok(data) => Reply::data(data),
        Err(_) => Reply::error("mcp_authorization_refused"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn peer_credentials_reject_other_identity() {
        let (left, _right) = UnixStream::pair().unwrap();
        let uid = unsafe { libc::geteuid() };
        assert!(peer_is_authorized(&left, uid));
        assert!(!peer_is_authorized(&left, uid.wrapping_add(1)));
    }

    fn client_test_config(directory: &Path) -> (ServerConfig, ClientConfig, PeerPolicy) {
        let uid = unsafe { libc::geteuid() };
        (
            ServerConfig {
                agent_socket: directory.join("agent.sock"),
            },
            ClientConfig {
                socket: directory.join("client.sock"),
                uid,
            },
            PeerPolicy { agent_uid: uid },
        )
    }

    #[tokio::test]
    async fn client_endpoint_is_opt_in_and_checks_peer_uid() {
        let dir = tempfile::tempdir().unwrap();
        let (config, client, peers) = client_test_config(dir.path());
        let server = Server::bind_with_session(
            config.clone(),
            crate::session::Session::ready(Arc::new(Broker::default())),
            peers,
        )
        .await
        .unwrap();
        assert!(!client.socket.exists());
        drop(server);

        let wrong_uid = ClientConfig {
            uid: client.uid.wrapping_add(1),
            ..client.clone()
        };
        let server = Server::bind_with_session_and_client(
            config,
            crate::session::Session::ready(Arc::new(Broker::default())),
            peers,
            Some(wrong_uid),
        )
        .await
        .unwrap();
        let task = tokio::spawn(server.run(std::future::pending()));
        let rejected = timeout(
            Duration::from_secs(1),
            call(
                &client.socket,
                &ClientRequest::TaskStatus {
                    task_id: Uuid::nil(),
                },
            ),
        )
        .await
        .unwrap();
        assert!(rejected.is_err(), "wrong UID received a client reply");
        task.abort();
    }

    #[tokio::test]
    async fn client_endpoint_rejects_administration_even_with_a_token() {
        let dir = tempfile::tempdir().unwrap();
        let (config, client, peers) = client_test_config(dir.path());
        let server = Server::bind_with_session_and_client(
            config,
            crate::session::Session::ready(Arc::new(Broker::default())),
            peers,
            Some(client.clone()),
        )
        .await
        .unwrap();
        let task = tokio::spawn(server.run(std::future::pending()));
        let request_id = Uuid::new_v4();
        let forbidden = [
            json!({"op":"review","request_id":request_id}),
            json!({"op":"decide","token":"00".repeat(32),"passphrase":"synthetic","request_id":request_id,"approve":true,"ttl_seconds":30}),
            json!({"op":"manage","token":"00".repeat(32),"passphrase":"synthetic","operation":{"action":"list"}}),
            json!({"op":"unlock","token":"00".repeat(32),"passphrase":"synthetic"}),
            json!({"op":"lock","token":"00".repeat(32)}),
            json!({"op":"finish_host_proxy","task_id":request_id,"exit_code":0}),
            json!({"op":"request","operation":{"connection":"demo/work","action":"proxy.run","target":"api.example.test","arguments":{"command":["/bin/true"]}},"token":"00".repeat(32)}),
        ];
        for request in forbidden {
            assert_eq!(
                call(&client.socket, &request)
                    .await
                    .unwrap()
                    .error
                    .as_deref(),
                Some("invalid_request"),
                "client accepted {request}"
            );
        }
        task.abort();
        let _ = task.await;
    }
}
