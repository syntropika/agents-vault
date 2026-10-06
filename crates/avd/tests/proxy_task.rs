use std::{
    convert::Infallible, fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration,
};

use av_core::{Vault, create_vault};
use avd::{Broker, BrokerError, Operation, TaskState};
use hyper::header::AUTHORIZATION;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

const HOST: &str = "api.example.test";
const SECRET: &str = "av-synthetic-provider-token";

fn test_certificates() -> (Vec<u8>, Arc<ServerConfig>) {
    test_certificates_for(HOST)
}

fn test_certificates_for(host: &str) -> (Vec<u8>, Arc<ServerConfig>) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "AV synthetic upstream CA");
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let mut leaf_params = CertificateParams::new(vec![host.to_owned()]).unwrap();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, host);
    let leaf_key = KeyPair::generate().unwrap();
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    (ca.der().to_vec(), Arc::new(config))
}

fn write_policy(path: &Path, policy: &serde_json::Value) {
    fs::write(path, serde_json::to_vec(policy).unwrap()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[tokio::test]
async fn approved_fixture_task_injects_synthetic_secret_and_cannot_be_replayed() {
    if !Path::new("/usr/bin/curl").exists() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("vault.db");
    let created = create_vault(&vault_path, "test passphrase").unwrap();
    created.vault.set("demo/fixture-token", SECRET).unwrap();
    drop(created);
    let vault = Vault::open(&vault_path, "test passphrase").unwrap();

    let (ca_der, provider_tls) = test_certificates();
    let ca_path = directory.path().join("provider-ca.der");
    fs::write(&ca_path, ca_der).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_addr = listener.local_addr().unwrap();
    let (seen_tx, seen_rx) = oneshot::channel::<String>();
    let provider_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let tls = TlsAcceptor::from(provider_tls)
            .accept(socket)
            .await
            .unwrap();
        let send = std::sync::Mutex::new(Some(seen_tx));
        let service = service_fn(move |request: Request<Body>| {
            let value = request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("<missing>")
                .to_owned();
            if let Some(send) = send.lock().unwrap().take() {
                let _ = send.send(value);
            }
            async { Ok::<_, Infallible>(Response::new(Body::from("ok"))) }
        });
        hyper::server::conn::Http::new()
            .http1_only(true)
            .serve_connection(tls, service)
            .await
            .unwrap();
    });

    let runner_helper = std::env::var("AVD_TEST_RUNNER_HELPER").ok();
    let mac_vmm = std::env::var("AVD_TEST_VMM").ok();
    let curl_error = directory.path().join("curl.err");
    let command = if runner_helper.is_some() || mac_vmm.is_some() {
        vec![
            if mac_vmm.is_some() {
                "/usr/bin/av-fixture".into()
            } else {
                std::env::var("AVD_TEST_FIXTURE").expect("set AVD_TEST_FIXTURE with runner helper")
            },
            "request".to_owned(),
            "--host".to_owned(),
            HOST.to_owned(),
            "--method".to_owned(),
            "get".to_owned(),
            "--path".to_owned(),
            "/probe".to_owned(),
            "--assert-direct-tcp-blocked".to_owned(),
        ]
    } else {
        vec![
            "/usr/bin/curl".to_owned(),
            "--fail".to_owned(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--stderr".to_owned(),
            curl_error.to_string_lossy().into_owned(),
            "--http1.1".to_owned(),
            "--header".to_owned(),
            "Authorization: Bearer av-placeholder".to_owned(),
            format!("https://{HOST}/probe"),
        ]
    };
    let policy_path = directory.path().join("policy.json");
    let mut policy = json!({
        "connection": "demo/fixture",
        "secret_name": "demo/fixture-token",
        "host": HOST,
        "command": command,
        "upstream_addr": provider_addr,
        "upstream_ca_der": ca_path,
        "max_connects": 1,
        "max_requests": 1,
        "max_runtime_seconds": 20
    });
    if let Some(helper) = runner_helper {
        policy["runner_helper"] = json!(helper);
    }
    if let Some(vmm) = &mac_vmm {
        policy["mac_vmm"] = json!(vmm);
        policy["mac_guest_bundle"] = json!(
            std::env::var("AVD_TEST_GUEST_BUNDLE").expect("set AVD_TEST_GUEST_BUNDLE with VMM")
        );
    }
    write_policy(&policy_path, &policy);
    let broker = Arc::new(Broker::from_vault_with_proxy_policy(&vault, &policy_path).unwrap());
    drop(vault);
    let operation = Operation {
        connection: "demo/fixture".into(),
        action: "proxy.run".into(),
        target: HOST.into(),
        arguments: json!({"command": command}),
    };
    let mut altered = operation.clone();
    altered.target = "other.example.test".into();
    assert_eq!(broker.request(altered), Err(BrokerError::InvalidOperation));
    let mut altered = operation.clone();
    altered.arguments = json!({"command": ["/usr/bin/curl", "https://other.example.test/"]});
    assert_eq!(broker.request(altered), Err(BrokerError::InvalidOperation));
    let mut altered = operation.clone();
    altered.arguments = json!({"command": command, "max_requests": 999});
    assert_eq!(broker.request(altered), Err(BrokerError::InvalidOperation));
    let id = broker.request(operation.clone()).unwrap();
    let review = broker.review(id).unwrap();
    assert_eq!(review.operation, operation);
    let bounds = review.task_policy.expect("broker-owned policy snapshot");
    assert_eq!(bounds.host, HOST);
    assert_eq!(bounds.command, command);
    assert_eq!(bounds.max_connects, 1);
    assert_eq!(bounds.max_requests, 1);
    assert_eq!(bounds.max_runtime_seconds, 20);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let denied = broker.request(operation.clone()).unwrap();
    broker.decide(denied, false, now, 0).unwrap();
    assert_eq!(
        broker.execute_or_start(denied, now).await,
        Err(BrokerError::Denied)
    );
    assert_eq!(
        broker.execute_or_start(id, now).await,
        Err(BrokerError::NotApproved)
    );
    broker.decide(id, true, now, 30).unwrap();
    let started = broker.execute_or_start(id, now).await.unwrap();
    assert_eq!(started["state"], "running");
    assert_eq!(started["task_id"], id.to_string());
    assert!(!started.to_string().contains(SECRET));
    assert_eq!(
        broker.execute_or_start(id, now).await,
        Err(BrokerError::QuotaExhausted)
    );
    let finished = tokio::time::timeout(
        Duration::from_secs(if mac_vmm.is_some() { 30 } else { 10 }),
        async {
            loop {
                let task = broker.task_status(id).unwrap();
                if task.state != TaskState::Running {
                    return task;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(finished.state, TaskState::Finished);
    assert_eq!(
        finished.exit_code,
        Some(0),
        "{}",
        fs::read_to_string(&curl_error).unwrap_or_default()
    );
    assert!(!serde_json::to_string(&finished).unwrap().contains(SECRET));
    assert_eq!(seen_rx.await.unwrap(), format!("Bearer {SECRET}"));
    provider_task.abort();
}

#[test]
fn real_credentials_are_rejected_before_broker_start() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("vault.db");
    let created = create_vault(&vault_path, "test passphrase").unwrap();
    created
        .vault
        .set("demo/fixture-token", "real-looking-token")
        .unwrap();
    let (ca_der, _) = test_certificates();
    let ca_path = directory.path().join("provider-ca.der");
    fs::write(&ca_path, ca_der).unwrap();
    let policy_path = directory.path().join("policy.json");
    write_policy(
        &policy_path,
        &json!({
            "connection": "demo/fixture",
            "secret_name": "demo/fixture-token",
            "host": HOST,
            "command": ["/bin/true"],
            "upstream_addr": "127.0.0.1:31337",
            "upstream_ca_der": ca_path,
            "max_connects": 1,
            "max_requests": 1,
            "max_runtime_seconds": 20
        }),
    );
    assert!(Broker::from_vault_with_proxy_policy(&created.vault, &policy_path).is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn versioned_connection_reaches_synthetic_provider_only_after_approval() {
    use av_core::{
        ApprovalRequirement, DeliveryMode, SecretAccessRequest, SecretGrant, SecretPolicy,
    };
    use sha2::{Digest, Sha256};

    if !Path::new("/usr/bin/curl").exists() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let created = create_vault(directory.path().join("vault.db"), "test passphrase").unwrap();
    created
        .vault
        .add_connection("service/work", HOST, SECRET)
        .unwrap();
    let (ca_der, provider_tls) = test_certificates();
    let ca_path = directory.path().join("provider-ca.der");
    fs::write(&ca_path, &ca_der).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_addr = listener.local_addr().unwrap();
    let command = vec![
        "/usr/bin/curl".to_owned(),
        "--fail".to_owned(),
        "--silent".to_owned(),
        "--show-error".to_owned(),
        "--http1.1".to_owned(),
        "--header".to_owned(),
        "Authorization: Bearer av-placeholder".to_owned(),
        format!("https://{HOST}/probe"),
    ];
    let policy_path = directory.path().join("policy.json");
    let policy = json!({
        "connection": "service/work", "connection_version": 1,
        "host": HOST, "command": command,
        "upstream_addr": provider_addr, "upstream_ca_der": ca_path,
        "max_connects": 1, "max_requests": 1, "max_runtime_seconds": 20,
        "host_client": true
    });
    write_policy(&policy_path, &policy);
    assert!(Broker::from_vault_with_proxy_policy(&created.vault, &policy_path).is_err());
    let source = fs::read(&policy_path).unwrap();
    let mut request = SecretAccessRequest::for_command(
        &command,
        &policy_path,
        &source,
        None,
        DeliveryMode::ProtectedProxy,
        Some(HOST),
    )
    .unwrap();
    request.working_directory = "/".into();
    request.upstream_ca_sha256 = Some(hex::encode(Sha256::digest(&ca_der)));
    request.validate().unwrap();
    created
        .vault
        .set_connection_policy(
            "service/work",
            1,
            &SecretPolicy {
                grants: vec![SecretGrant {
                    request,
                    approval: ApprovalRequirement::EveryRun,
                }],
            },
        )
        .unwrap();
    let broker =
        Arc::new(Broker::from_vault_with_proxy_policy(&created.vault, &policy_path).unwrap());
    let operation = Operation {
        connection: "service/work".into(),
        action: "proxy.run".into(),
        target: String::new(),
        arguments: json!({"command": command, "connection_version": 1}),
    };
    let mut stale = operation.clone();
    stale.arguments["connection_version"] = json!(2);
    assert_eq!(broker.request(stale), Err(BrokerError::InvalidOperation));
    let id = broker.request(operation).unwrap();
    let review = broker.review(id).unwrap();
    assert_eq!(review.operation.target, HOST);
    assert_eq!(review.task_policy.unwrap().connection_version, Some(1));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(
        broker.execute_or_start(id, now).await,
        Err(BrokerError::NotApproved)
    );
    let (seen_tx, seen_rx) = oneshot::channel::<String>();
    let provider_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let tls = TlsAcceptor::from(provider_tls)
            .accept(socket)
            .await
            .unwrap();
        let send = std::sync::Mutex::new(Some(seen_tx));
        let service = service_fn(move |request: Request<Body>| {
            let value = request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("<missing>")
                .to_owned();
            if let Some(send) = send.lock().unwrap().take() {
                let _ = send.send(value);
            }
            async { Ok::<_, Infallible>(Response::new(Body::from("ok"))) }
        });
        hyper::server::conn::Http::new()
            .http1_only(true)
            .serve_connection(tls, service)
            .await
            .unwrap();
    });
    broker.decide(id, true, now, 30).unwrap();
    let started = broker.execute_or_start(id, now).await.unwrap();
    assert!(!started.to_string().contains(SECRET));
    let details = &started["host_proxy"];
    let ca_file = directory.path().join("interception-ca.pem");
    fs::write(&ca_file, details["ca_pem"].as_str().unwrap()).unwrap();
    let output = tokio::process::Command::new("/usr/bin/curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--http1.1",
            "--header",
            "Authorization: Bearer av-placeholder",
            &format!("https://{HOST}/probe"),
        ])
        .env_clear()
        .env("HTTPS_PROXY", details["proxy_url"].as_str().unwrap())
        .env("CURL_CA_BUNDLE", &ca_file)
        .env("NO_PROXY", "")
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(seen_rx.await.unwrap(), format!("Bearer {SECRET}"));
    broker.finish_host_proxy(id, 0).unwrap();
    provider_task.abort();
    broker.shutdown().await;
    drop(broker);
    created
        .vault
        .replace_connection("service/work", 1, "av-synthetic-rotated")
        .unwrap();
    assert!(Broker::from_vault_with_proxy_policy(&created.vault, &policy_path).is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "binds the fixed port 14322; run separately after the workspace suite"]
async fn concurrent_host_tasks_revoke_independently_and_expire() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn connect_status(token: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect("127.0.0.1:14322")
            .await
            .unwrap();
        stream.write_all(format!(
            "CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
        ).as_bytes()).await.unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            response.push(byte[0]);
        }
        String::from_utf8(response).unwrap()
    }

    let directory = tempfile::tempdir().unwrap();
    let created = create_vault(directory.path().join("vault.db"), "synthetic passphrase").unwrap();
    created.vault.set("demo/token", SECRET).unwrap();
    let (ca_der, _) = test_certificates();
    let ca_path = directory.path().join("ca.der");
    fs::write(&ca_path, ca_der).unwrap();
    let policy_path = directory.path().join("policy.json");
    let command = vec!["/usr/bin/curl".to_owned(), format!("https://{HOST}/probe")];
    write_policy(
        &policy_path,
        &json!({
            "connection": "demo/work", "secret_name": "demo/token", "host": HOST,
            "command": command, "upstream_addr": "127.0.0.1:31337",
            "upstream_ca_der": ca_path, "max_connects": 2,
            "max_requests": 2, "max_runtime_seconds": 2, "host_client": true
        }),
    );
    let broker =
        Arc::new(Broker::from_vault_with_proxy_policy(&created.vault, &policy_path).unwrap());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let id = broker
            .request(Operation {
                connection: "demo/work".into(),
                action: "proxy.run".into(),
                target: HOST.into(),
                arguments: json!({"command": command}),
            })
            .unwrap();
        broker.decide(id, true, now, 30).unwrap();
        let started = broker.execute_or_start(id, now).await.unwrap();
        let url = started["host_proxy"]["proxy_url"].as_str().unwrap();
        let token = url
            .strip_prefix("http://av:")
            .unwrap()
            .split_once('@')
            .unwrap()
            .0
            .to_owned();
        tasks.push((id, token));
    }
    assert_ne!(tasks[0].1, tasks[1].1);
    assert!(
        connect_status(&tasks[0].1)
            .await
            .starts_with("HTTP/1.1 200")
    );
    assert!(
        connect_status(&tasks[1].1)
            .await
            .starts_with("HTTP/1.1 200")
    );
    broker.finish_host_proxy(tasks[0].0, 0).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while broker.task_status(tasks[0].0).unwrap().state == TaskState::Running {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        broker.task_status(tasks[0].0).unwrap().state,
        TaskState::Finished
    );
    assert!(
        connect_status(&tasks[0].1)
            .await
            .starts_with("HTTP/1.1 407")
    );
    assert!(
        connect_status(&tasks[1].1)
            .await
            .starts_with("HTTP/1.1 200")
    );
    tokio::time::timeout(Duration::from_secs(4), async {
        while broker.task_status(tasks[1].0).unwrap().state == TaskState::Running {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        broker.task_status(tasks[1].0).unwrap().state,
        TaskState::Failed
    );
    assert!(
        connect_status(&tasks[1].1)
            .await
            .starts_with("HTTP/1.1 407")
    );
    broker.shutdown().await;
    assert!(
        tokio::net::TcpStream::connect("127.0.0.1:14322")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn operator_connection_mutations_require_relock() {
    use avd::{
        management::ManagementOperation,
        session::{AdminRequest, AdminServer, Session, VaultSource, admin_call},
    };

    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("vault.db");
    let created = create_vault(&vault_path, "synthetic passphrase").unwrap();
    created
        .vault
        .add_connection(
            "service/work",
            "api.example.test",
            "av-synthetic-credential-v1",
        )
        .unwrap();
    drop(created);
    let session = Session::locked(VaultSource {
        vault: vault_path,
        proxy_policy: None,
        service_mode: false,
    })
    .unwrap();
    let admin = AdminServer::bind(directory.path(), Arc::clone(&session))
        .await
        .unwrap();
    let server = tokio::spawn(admin.run());
    let token = fs::read_to_string(directory.path().join("admin.token")).unwrap();
    let socket = directory.path().join("admin.sock");
    let passphrase = "synthetic passphrase";
    let unlock = || AdminRequest::Unlock {
        token: token.clone(),
        passphrase: passphrase.into(),
    };
    assert!(admin_call(&socket, &unlock()).await.unwrap().ok);
    for operation in [
        ManagementOperation::ConnectReplace {
            id: "service/work".into(),
            expected_version: 1,
            value: "av-synthetic-credential-v2".into(),
        },
        ManagementOperation::ConnectRevoke {
            id: "service/work".into(),
            expected_version: 1,
        },
        ManagementOperation::ConnectDisconnect {
            id: "service/work".into(),
            expected_version: 1,
        },
    ] {
        let reply = admin_call(
            &socket,
            &AdminRequest::Manage {
                token: token.clone(),
                passphrase: passphrase.into(),
                operation,
            },
        )
        .await
        .unwrap();
        assert!(!reply.ok);
        assert!(
            reply
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("lock the broker before managing")
        );
    }
    assert!(
        admin_call(
            &socket,
            &AdminRequest::Lock {
                token: token.clone()
            }
        )
        .await
        .unwrap()
        .ok
    );
    let rotated = admin_call(
        &socket,
        &AdminRequest::Manage {
            token: token.clone(),
            passphrase: passphrase.into(),
            operation: ManagementOperation::ConnectReplace {
                id: "service/work".into(),
                expected_version: 1,
                value: "av-synthetic-credential-v2".into(),
            },
        },
    )
    .await
    .unwrap();
    assert!(!rotated.ok);
    assert!(
        rotated
            .error
            .unwrap()
            .contains("management requires an installed service vault")
    );
    assert!(session.is_locked().await);
    server.abort();
    let _ = server.await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn task_deadline_stops_descendant_activity() {
    let directory = tempfile::tempdir().unwrap();
    let heartbeat = directory.path().join("heartbeat");
    let script = format!(
        "(while :; do printf x >> '{}'; sleep 0.05; done) & wait",
        heartbeat.display()
    );
    let vault_path = directory.path().join("vault.db");
    let created = create_vault(&vault_path, "test passphrase").unwrap();
    created.vault.set("demo/fixture-token", SECRET).unwrap();
    let (ca_der, _) = test_certificates();
    let ca_path = directory.path().join("provider-ca.der");
    fs::write(&ca_path, ca_der).unwrap();
    let policy_path = directory.path().join("policy.json");
    let command = vec!["/bin/sh".to_owned(), "-c".to_owned(), script];
    let mut policy = json!({
        "connection": "demo/fixture",
        "secret_name": "demo/fixture-token",
        "host": HOST,
        "command": command,
        "upstream_addr": "127.0.0.1:31337",
        "upstream_ca_der": ca_path,
        "max_connects": 1,
        "max_requests": 1,
        "max_runtime_seconds": 1
    });
    if let Ok(helper) = std::env::var("AVD_TEST_RUNNER_HELPER") {
        policy["runner_helper"] = json!(helper);
    }
    write_policy(&policy_path, &policy);
    let broker =
        Arc::new(Broker::from_vault_with_proxy_policy(&created.vault, &policy_path).unwrap());
    let id = broker
        .request(Operation {
            connection: "demo/fixture".into(),
            action: "proxy.run".into(),
            target: HOST.into(),
            arguments: json!({"command": command}),
        })
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    broker.decide(id, true, now, 5).unwrap();
    broker.execute_or_start(id, now).await.unwrap();
    let status = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = broker.task_status(id).unwrap();
            if status.state != TaskState::Running {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(status.state, TaskState::Failed);
    let initial = fs::metadata(&heartbeat).unwrap().len();
    assert!(initial > 0);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(fs::metadata(&heartbeat).unwrap().len(), initial);
}
