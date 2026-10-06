//! Public IDs must not confer execution or completion authority on another connection.
use avd::{
    Broker, Operation, RequestState, TaskState,
    ipc::{self, AgentRequest, ClientConfig, PeerPolicy, Server, ServerConfig},
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    time::{Duration, timeout},
};
use uuid::Uuid;

// Deliberately independent of the production client framing implementation.
struct Peer(BufReader<UnixStream>);
impl Peer {
    async fn open(path: &std::path::Path) -> Self {
        Self(BufReader::new(UnixStream::connect(path).await.unwrap()))
    }
    async fn send(&mut self, value: &Value) {
        self.0
            .get_mut()
            .write_all(format!("{value}\n").as_bytes())
            .await
            .unwrap();
    }
    async fn receive(&mut self) -> ipc::Reply {
        let mut line = String::new();
        timeout(Duration::from_secs(5), self.0.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        serde_json::from_str(&line).unwrap()
    }
    async fn call(&mut self, value: Value) -> ipc::Reply {
        self.send(&value).await;
        self.receive().await
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
async fn request(peer: &mut Peer, operation: &Operation) -> Uuid {
    let reply = peer
        .call(json!({"op":"request","operation":operation}))
        .await;
    assert!(reply.ok, "{:?}", reply.error);
    serde_json::from_value(reply.data.unwrap()["request_id"].clone()).unwrap()
}
async fn closed_state(broker: &Broker, id: Uuid) {
    timeout(Duration::from_secs(3), async {
        while broker.review(id).unwrap().state != RequestState::Denied {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "binds fixed port 14322; run serially"]
async fn foreign_connections_cannot_take_approved_execution_or_finish_and_disconnect_revokes() {
    let dir = tempfile::tempdir().unwrap();
    let vault = av_core::create_vault(dir.path().join("vault.db"), "synthetic passphrase")
        .unwrap()
        .vault;
    vault
        .set("demo/token", "av-synthetic-owner-regression")
        .unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["api.example.test".into()]).unwrap();
    let ca = dir.path().join("ca.der");
    fs::write(&ca, certificate.cert.der()).unwrap();
    let policy = dir.path().join("policy.json");
    fs::write(&policy, serde_json::to_vec(&json!({
        "connection":"demo/cli", "secret_name":"demo/token", "host":"api.example.test", "command":["/usr/bin/true"],
        "upstream_addr":"127.0.0.1:9", "upstream_ca_der":ca, "max_connects":2,"max_requests":2,"max_runtime_seconds":20,"host_client":true
    })).unwrap()).unwrap();
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
    let broker = Arc::new(Broker::from_vault_with_proxy_policy(&vault, &policy).unwrap());
    let socket = dir.path().join("agent.sock");
    let client = dir.path().join("client.sock");
    let uid = unsafe { libc::geteuid() };
    let session = avd::session::Session::ready(Arc::clone(&broker));
    let server = Server::bind_with_session_and_client(
        ServerConfig {
            agent_socket: socket.clone(),
        },
        session,
        PeerPolicy { agent_uid: uid },
        Some(ClientConfig {
            socket: client.clone(),
            uid,
        }),
    )
    .await
    .unwrap();
    let server_task = tokio::spawn(server.run(std::future::pending()));
    let operation = Operation {
        connection: "demo/cli".into(),
        action: "proxy.run".into(),
        target: "api.example.test".into(),
        arguments: json!({"command":["/usr/bin/true"]}),
    };
    let mut owner = Peer::open(&socket).await;
    let id = request(&mut owner, &operation).await;
    broker.decide(id, true, now(), 30).unwrap();
    // This is the original first-claim attack, including the optional client endpoint.
    for endpoint in [&socket, &client] {
        let foreign = ipc::call(endpoint, &json!({"op":"execute","request_id":id}))
            .await
            .unwrap();
        assert_eq!(foreign.error.as_deref(), Some("WrongExecutionSession"));
        assert!(foreign.data.is_none());
    }
    let forged = owner.call(json!({"op":"execute","request_id":id,"execution_session":broker.review(id).unwrap().execution_session})).await;
    assert_eq!(forged.error.as_deref(), Some("invalid_request"));
    let execute_request = AgentRequest::Execute { request_id: id };
    let (started, foreign) = tokio::join!(
        owner.call(json!({"op":"execute","request_id":id})),
        ipc::call_agent(&socket, &execute_request)
    );
    assert_eq!(
        foreign.unwrap().error.as_deref(),
        Some("WrongExecutionSession")
    );
    assert!(started.ok);
    assert!(started.data.unwrap().get("host_proxy").is_some());
    let foreign_finish = ipc::call_agent(
        &socket,
        &AgentRequest::FinishHostProxy {
            task_id: id,
            exit_code: 42,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        foreign_finish.error.as_deref(),
        Some("WrongExecutionSession")
    );
    assert_eq!(
        owner
            .call(json!({"op":"execute","request_id":id}))
            .await
            .error
            .as_deref(),
        Some("QuotaExhausted")
    );
    assert_eq!(
        owner
            .call(json!({"op":"finish_host_proxy","task_id":id,"exit_code":256}))
            .await
            .error
            .as_deref(),
        Some("InvalidOperation")
    );
    assert!(
        owner
            .call(json!({"op":"finish_host_proxy","task_id":id,"exit_code":0}))
            .await
            .ok
    );
    timeout(Duration::from_secs(3), async {
        while broker.task_status(id).unwrap().state == TaskState::Running {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(broker.task_status(id).unwrap().exit_code, Some(0));

    for approve in [false, true] {
        let mut departing = Peer::open(&socket).await;
        let id = request(&mut departing, &operation).await;
        if approve {
            broker.decide(id, true, now(), 30).unwrap();
        }
        drop(departing);
        closed_state(&broker, id).await;
        assert!(broker.decide(id, true, now(), 30).is_err());
        assert_eq!(
            ipc::call_agent(&socket, &AgentRequest::Execute { request_id: id })
                .await
                .unwrap()
                .error
                .as_deref(),
            Some("WrongExecutionSession")
        );
    }
    // EOF is monitored while dispatch is awaiting readiness, not just between calls.
    let mut departing = Peer::open(&socket).await;
    let id = request(&mut departing, &operation).await;
    broker.decide(id, true, now(), 30).unwrap();
    departing
        .send(&json!({"op":"execute","request_id":id}))
        .await;
    drop(departing);
    timeout(Duration::from_secs(3), async {
        loop {
            let review = broker.review(id).unwrap();
            if review.state == RequestState::Denied {
                break;
            }
            if broker
                .task_status(id)
                .is_ok_and(|s| s.state != TaskState::Running)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // Closing an already active owner cancels its grant and frees the fixed listener.
    let mut departing = Peer::open(&socket).await;
    let id = request(&mut departing, &operation).await;
    broker.decide(id, true, now(), 30).unwrap();
    assert!(
        departing
            .call(json!({"op":"execute","request_id":id}))
            .await
            .ok
    );
    drop(departing);
    timeout(Duration::from_secs(3), async {
        while broker.task_status(id).unwrap().state == TaskState::Running {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(broker.task_status(id).unwrap().exit_code != Some(0));
    let mut tunnel = tokio::net::TcpStream::connect("127.0.0.1:14322")
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(3), tunnel.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 407"));

    // A legitimate optional-client connection receives authority for its own request.
    let mut selected_client = Peer::open(&client).await;
    let id = request(&mut selected_client, &operation).await;
    broker.decide(id, true, now(), 30).unwrap();
    assert!(
        selected_client
            .call(json!({"op":"execute","request_id":id}))
            .await
            .ok
    );
    assert_eq!(
        owner
            .call(json!({"op":"execute","request_id":id}))
            .await
            .error
            .as_deref(),
        Some("WrongExecutionSession")
    );
    drop(selected_client);
    timeout(Duration::from_secs(3), async {
        while broker.task_status(id).unwrap().state == TaskState::Running {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // Two frames written together retain their buffered bytes and independent replies.
    let unknown = Uuid::new_v4();
    owner
        .send(&json!({"op":"review","request_id":unknown}))
        .await;
    owner
        .send(&json!({"op":"review","request_id":unknown}))
        .await;
    for _ in 0..2 {
        assert_eq!(
            owner.receive().await.error.as_deref(),
            Some("UnknownRequest")
        );
    }
    drop(owner);
    broker.shutdown().await;
    server_task.abort();
}
