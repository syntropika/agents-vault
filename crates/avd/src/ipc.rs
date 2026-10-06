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

use crate::{Broker, BrokerError, Operation};

const MAX_REQUEST_BYTES: u64 = 65_536;
const MAX_ACTIVE_AGENT_HANDLERS: usize = 48;
const MAX_ACTIVE_CLIENT_HANDLERS: usize = 16;
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);
const ACTION_DEADLINE: Duration = Duration::from_secs(20);

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
                        let _ = timeout(ACTION_DEADLINE, handle_agent(stream, session)).await;
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
                        let _ = timeout(ACTION_DEADLINE, handle_client(stream, session)).await;
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

async fn read_request(stream: &mut UnixStream) -> io::Result<String> {
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    let count = (&mut reader)
        .take(MAX_REQUEST_BYTES + 1)
        .read_line(&mut line)
        .await?;
    if count == 0 || count as u64 > MAX_REQUEST_BYTES || !line.ends_with('\n') {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid frame"));
    }
    Ok(line)
}

async fn write_reply(stream: &mut UnixStream, reply: &Reply) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(reply)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await
}

async fn handle_agent(
    mut stream: UnixStream,
    session: Arc<crate::session::Session>,
) -> io::Result<()> {
    let request = match timeout(REQUEST_DEADLINE, read_request(&mut stream)).await {
        Ok(request) => request,
        Err(_) => return Ok(()),
    };
    let state = session.broker.read().await;
    let Some(broker) = state.as_ref() else {
        return write_reply(&mut stream, &Reply::error("Locked")).await;
    };
    let reply = match request {
        Ok(line) => match serde_json::from_str::<AgentRequest>(&line) {
            Ok(AgentRequest::Request { operation }) => broker_reply(
                broker
                    .request(operation)
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
            Ok(AgentRequest::McpRequest { nonce, operation }) => mcp_reply(session.mcp.request(
                &nonce,
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
            Ok(AgentRequest::Execute { request_id }) => {
                broker_reply(broker.execute_or_start(request_id, now_seconds()).await)
            }
            Ok(AgentRequest::TaskStatus { task_id }) => broker_reply(broker.task_status(task_id)),
            Ok(AgentRequest::FinishHostProxy { task_id, exit_code }) => {
                broker_reply(broker.finish_host_proxy(task_id, exit_code))
            }
            Err(_) => Reply::error("invalid_request"),
        },
        Err(_) => Reply::error("invalid_frame"),
    };
    write_reply(&mut stream, &reply).await
}

async fn handle_client(
    mut stream: UnixStream,
    session: Arc<crate::session::Session>,
) -> io::Result<()> {
    let request = match timeout(REQUEST_DEADLINE, read_request(&mut stream)).await {
        Ok(request) => request,
        Err(_) => return Ok(()),
    };
    let state = session.broker.read().await;
    if state.is_none() {
        return write_reply(&mut stream, &Reply::error("Locked")).await;
    }
    let reply = match request {
        Ok(line) => match serde_json::from_str::<ClientRequest>(&line) {
            Ok(ClientRequest::Request { operation }) if client_action(&operation.action) => {
                let broker = state.as_ref().expect("checked unlocked");
                broker_reply(
                    broker
                        .request(operation)
                        .map(|request_id| json!({ "request_id": request_id })),
                )
            }
            Ok(ClientRequest::Execute { request_id }) => {
                match state.as_ref().expect("checked unlocked").review(request_id) {
                    Ok(review) if client_action(&review.operation.action) => {
                        let broker = state.as_ref().expect("checked unlocked");
                        broker_reply(broker.execute_or_start(request_id, now_seconds()).await)
                    }
                    _ => Reply::error("invalid_request"),
                }
            }
            Ok(ClientRequest::TaskStatus { task_id }) => {
                match state.as_ref().expect("checked unlocked").review(task_id) {
                    Ok(review) if client_action(&review.operation.action) => {
                        let broker = state.as_ref().expect("checked unlocked");
                        broker_reply(broker.task_status(task_id))
                    }
                    _ => Reply::error("invalid_request"),
                }
            }
            Ok(ClientRequest::Request { .. }) | Err(_) => Reply::error("invalid_request"),
        },
        Err(_) => Reply::error("invalid_frame"),
    };
    write_reply(&mut stream, &reply).await
}

fn client_action(action: &str) -> bool {
    action == "proxy.run"
}

/// One request per connection keeps the prototype protocol inspectable.
pub async fn call<T: Serialize>(socket: &Path, request: &T) -> io::Result<Reply> {
    call_with_deadline(socket, request, REQUEST_DEADLINE).await
}

pub async fn call_client(socket: &Path, request: &ClientRequest) -> io::Result<Reply> {
    let deadline = if matches!(request, ClientRequest::Execute { .. }) {
        ACTION_DEADLINE
    } else {
        REQUEST_DEADLINE
    };
    call_with_deadline(socket, request, deadline).await
}

pub async fn call_agent(socket: &Path, request: &AgentRequest) -> io::Result<Reply> {
    let deadline = if matches!(request, AgentRequest::Execute { .. }) {
        ACTION_DEADLINE
    } else {
        REQUEST_DEADLINE
    };
    call_with_deadline(socket, request, deadline).await
}

async fn call_with_deadline<T: Serialize>(
    socket: &Path,
    request: &T,
    deadline: Duration,
) -> io::Result<Reply> {
    timeout(deadline, call_inner(socket, request))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "broker IPC timed out"))?
}

async fn call_inner<T: Serialize>(socket: &Path, request: &T) -> io::Result<Reply> {
    let mut stream = UnixStream::connect(socket).await?;
    let mut bytes = serde_json::to_vec(request)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    let mut reply = String::new();
    BufReader::new(stream)
        .take(MAX_REQUEST_BYTES + 1)
        .read_line(&mut reply)
        .await?;
    if reply.len() as u64 > MAX_REQUEST_BYTES || !reply.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid broker reply",
        ));
    }
    serde_json::from_str(&reply).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
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
