use av_core::create_vault;
use avd::{
    Broker, Operation, TaskState,
    ipc::{AgentRequest, PeerPolicy, Server, ServerConfig, call},
    session::{AdminRequest, AdminServer, Session, VaultSource, admin_call},
};
use serde_json::json;
use std::{
    fs,
    sync::Arc,
    time::{Duration, Instant},
};

#[tokio::test]
async fn admin_capability_and_relock_discards_approvals() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("vault.db");
    let created = create_vault(&vault_path, "synthetic-passphrase").unwrap();
    created
        .vault
        .set("demo/provider-token", "av-synthetic-session-token")
        .unwrap();
    drop(created);
    let certificate = rcgen::generate_simple_self_signed(vec!["api.example.test".into()]).unwrap();
    let ca = directory.path().join("ca.der");
    fs::write(&ca, certificate.cert.der()).unwrap();
    let policy = directory.path().join("policy.json");
    fs::write(
        &policy,
        serde_json::to_vec(&json!({
            "connection":"demo/provider", "secret_name":"demo/provider-token",
            "host":"api.example.test", "command":["/bin/true"],
            "upstream_addr":"127.0.0.1:9", "upstream_ca_der":ca,
            "max_connects":1, "max_requests":1, "max_runtime_seconds":30
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
    let session = Session::locked(VaultSource {
        vault: vault_path,
        proxy_policy: Some(policy),
        service_mode: false,
    })
    .unwrap();
    let config = ServerConfig {
        agent_socket: directory.path().join("agent.sock"),
    };
    let uid = unsafe { libc::geteuid() };
    let server = Server::bind_with_session(
        config.clone(),
        Arc::clone(&session),
        PeerPolicy { agent_uid: uid },
    )
    .await
    .unwrap();
    let admin = AdminServer::bind(directory.path(), Arc::clone(&session))
        .await
        .unwrap();
    let server_task = tokio::spawn(server.run(std::future::pending()));
    let admin_task = tokio::spawn(admin.run());
    let admin_socket = directory.path().join("admin.sock");
    let admin_token = fs::read_to_string(directory.path().join("admin.token")).unwrap();
    let operation = Operation {
        connection: "demo/provider".into(),
        action: "proxy.run".into(),
        target: "api.example.test".into(),
        arguments: json!({"command":["/bin/true"]}),
    };
    assert_eq!(
        call(
            &config.agent_socket,
            &AgentRequest::Request {
                operation: operation.clone()
            }
        )
        .await
        .unwrap()
        .error
        .as_deref(),
        Some("Locked")
    );
    assert_eq!(
        admin_call(
            &admin_socket,
            &AdminRequest::Unlock {
                token: "00".repeat(32),
                passphrase: "synthetic-passphrase".into()
            }
        )
        .await
        .unwrap()
        .error
        .as_deref(),
        Some("unauthorized")
    );
    assert_eq!(
        admin_call(
            &admin_socket,
            &AdminRequest::Unlock {
                token: admin_token.clone(),
                passphrase: "wrong".into()
            }
        )
        .await
        .unwrap()
        .error
        .as_deref(),
        Some("unlock_failed")
    );
    assert!(session.is_locked().await);
    assert!(
        admin_call(
            &admin_socket,
            &AdminRequest::Unlock {
                token: admin_token.clone(),
                passphrase: "synthetic-passphrase".into()
            }
        )
        .await
        .unwrap()
        .ok
    );
    let connection_mutation = json!({
        "op":"manage", "token":admin_token,
        "passphrase":"synthetic-passphrase",
        "operation":{"action":"connect_add", "id":"service/work", "host":"api.example.test", "value":"av-synthetic-credential"}
    });
    assert_eq!(
        call(&config.agent_socket, &connection_mutation)
            .await
            .unwrap()
            .error
            .as_deref(),
        Some("invalid_request")
    );
    assert_eq!(
        call(
            &config.agent_socket,
            &json!({"op":"request","operation":operation.clone(),"token":admin_token}),
        )
        .await
        .unwrap()
        .error
        .as_deref(),
        Some("invalid_request")
    );
    let request = call(&config.agent_socket, &AgentRequest::Request { operation })
        .await
        .unwrap();
    let id = serde_json::from_value(request.data.unwrap()["request_id"].clone()).unwrap();
    assert_eq!(
        call(
            &config.agent_socket,
            &json!({"op":"decide","token":admin_token,"passphrase":"synthetic-passphrase",
                "request_id":id,"approve":true,"ttl_seconds":30}),
        )
        .await
        .unwrap()
        .error
        .as_deref(),
        Some("invalid_request")
    );
    assert_eq!(
        admin_call(
            &admin_socket,
            &AdminRequest::Decide {
                token: admin_token.clone(),
                passphrase: "wrong".into(),
                request_id: id,
                approve: true,
                ttl_seconds: 30,
            }
        )
        .await
        .unwrap()
        .error
        .as_deref(),
        Some("operator authentication failed")
    );
    assert!(
        admin_call(
            &admin_socket,
            &AdminRequest::Decide {
                token: admin_token.clone(),
                passphrase: "synthetic-passphrase".into(),
                request_id: id,
                approve: true,
                ttl_seconds: 30,
            }
        )
        .await
        .unwrap()
        .ok
    );
    assert!(
        admin_call(
            &admin_socket,
            &AdminRequest::Lock {
                token: admin_token.clone()
            }
        )
        .await
        .unwrap()
        .ok
    );
    assert_eq!(
        call(
            &config.agent_socket,
            &AgentRequest::Execute { request_id: id }
        )
        .await
        .unwrap()
        .error
        .as_deref(),
        Some("Locked")
    );
    assert!(
        admin_call(
            &admin_socket,
            &AdminRequest::Unlock {
                token: admin_token,
                passphrase: "synthetic-passphrase".into()
            }
        )
        .await
        .unwrap()
        .ok
    );
    assert_eq!(
        call(
            &config.agent_socket,
            &AgentRequest::Execute { request_id: id }
        )
        .await
        .unwrap()
        .error
        .as_deref(),
        Some("UnknownRequest")
    );
    server_task.abort();
    admin_task.abort();
    let _ = server_task.await;
    let _ = admin_task.await;
    session.lock().await;
}

#[tokio::test]
async fn relock_shutdown_cancels_a_running_proxy_task() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let vault = create_vault(directory.path().join("vault.db"), "synthetic-passphrase")
        .unwrap()
        .vault;
    vault
        .set("demo/provider-token", "av-synthetic-cancel-test")
        .unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["api.example.test".into()]).unwrap();
    let ca = directory.path().join("ca.der");
    fs::write(&ca, certificate.cert.der()).unwrap();
    let policy = directory.path().join("policy.json");
    let sleep = if cfg!(target_os = "macos") {
        "/bin/sleep"
    } else {
        "/usr/bin/sleep"
    };
    fs::write(&policy, serde_json::to_vec(&json!({
        "connection":"demo/provider", "secret_name":"demo/provider-token", "host":"api.example.test",
        "command":[sleep,"60"], "upstream_addr":"127.0.0.1:9", "upstream_ca_der":ca,
        "max_connects":1,"max_requests":1,"max_runtime_seconds":60
    })).unwrap()).unwrap();
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
    let broker = Arc::new(Broker::from_vault_with_proxy_policy(&vault, &policy).unwrap());
    let request = broker
        .request(Operation {
            connection: "demo/provider".into(),
            action: "proxy.run".into(),
            target: "api.example.test".into(),
            arguments: json!({"command":[sleep,"60"]}),
        })
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    broker.decide(request, true, now, 60).unwrap();
    broker.execute_or_start(request, now).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        broker.task_status(request).unwrap().state,
        TaskState::Running
    );
    let start = Instant::now();
    broker.shutdown().await;
    assert!(start.elapsed() < Duration::from_secs(3));
    assert_eq!(
        broker.task_status(request).unwrap().state,
        TaskState::Failed
    );
}
