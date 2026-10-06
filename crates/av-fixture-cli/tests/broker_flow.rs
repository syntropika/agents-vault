use std::{
    convert::Infallible,
    fs,
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use av_core::create_vault;
use avd::{
    Broker, Operation,
    ipc::{self, AgentRequest, Reply, Server, ServerConfig},
};
use hyper::{Body, Request, Response, service::service_fn};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::{
    ServerConfig as TlsServerConfig,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

const HOST: &str = "api.example.test";
const SECRET: &str = "av-synthetic-fixture-credential";

#[derive(Debug)]
struct Observed {
    path: String,
    authorization: String,
    fixture_input: String,
}

async fn provider(ca_path: &Path) -> (std::net::SocketAddr, mpsc::UnboundedReceiver<Observed>) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Agents Vault Fixture Test Root");
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    fs::write(ca_path, ca.der()).unwrap();
    let mut leaf_params = CertificateParams::new(vec![HOST.to_owned()]).unwrap();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "Agents Vault Fixture Test Provider");
    let leaf_key = KeyPair::generate().unwrap();
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
    let mut tls = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(socket).await else {
                    return;
                };
                let service = service_fn(move |request: Request<Body>| {
                    let tx = tx.clone();
                    async move {
                        let header = |name| {
                            request
                                .headers()
                                .get(name)
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or("<missing>")
                                .to_owned()
                        };
                        let _ = tx.send(Observed {
                            path: request.uri().path().to_owned(),
                            authorization: header("authorization"),
                            fixture_input: header("x-av-fixture-input"),
                        });
                        Ok::<_, Infallible>(Response::new(Body::from("ok")))
                    }
                });
                let _ = hyper::server::conn::Http::new()
                    .http1_only(true)
                    .serve_connection(stream, service)
                    .await;
            });
        }
    });
    (address, rx)
}

fn data(reply: Reply) -> Value {
    assert!(reply.ok, "broker rejected request: {:?}", reply.error);
    reply.data.expect("broker omitted data")
}

fn operation(command: &[String]) -> Operation {
    Operation {
        connection: "demo/fixture".to_owned(),
        action: "proxy.run".to_owned(),
        target: HOST.to_owned(),
        arguments: json!({"command": command}),
    }
}

#[tokio::test]
async fn approved_fixture_injects_only_after_frozen_one_use_decision() {
    run_flow(None, None, false).await;
}

#[tokio::test]
async fn approved_host_client_uses_only_the_broker_proxy() {
    let av_cli = std::env::var_os("AV_CLI_TEST_BINARY").map(PathBuf::from);
    run_flow(None, av_cli.as_deref(), true).await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "build av-runner-helper and av; set AVD_TEST_RUNNER_HELPER and AV_CLI_TEST_BINARY"]
async fn approved_namespaced_fixture_blocks_direct_tcp_and_uses_proxy() {
    let helper = PathBuf::from(
        std::env::var_os("AVD_TEST_RUNNER_HELPER")
            .expect("AVD_TEST_RUNNER_HELPER must name the built helper"),
    );
    let av_cli = PathBuf::from(
        std::env::var_os("AV_CLI_TEST_BINARY").expect("AV_CLI_TEST_BINARY must name the built av"),
    );
    run_flow(Some(&helper), Some(&av_cli), false).await;
}

async fn run_flow(runner_helper: Option<&Path>, av_cli: Option<&Path>, host_client: bool) {
    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("provider-ca.der");
    let (upstream_addr, mut observed) = provider(&ca_path).await;
    let mut command = vec![
        env!("CARGO_BIN_EXE_av-fixture").to_owned(),
        "request".to_owned(),
        "--host".to_owned(),
        HOST.to_owned(),
        "--method".to_owned(),
        "get".to_owned(),
        "--path".to_owned(),
        "/probe".to_owned(),
    ];
    if runner_helper.is_some() {
        command.push("--assert-direct-tcp-blocked".to_owned());
    }
    let policy_path = dir.path().join("policy.json");
    let mut policy = json!({
        "connection": "demo/fixture",
        "secret_name": "demo/fixture-token",
        "host": HOST,
        "command": command,
        "upstream_addr": upstream_addr,
        "upstream_ca_der": ca_path,
        "max_connects": 2,
        "max_requests": 2,
        "max_runtime_seconds": 20
    });
    if host_client {
        policy["host_client"] = json!(true);
    }
    if let Some(helper) = runner_helper {
        policy["runner_helper"] = json!(helper);
    }
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600)).unwrap();
    let vault_path = dir.path().join("vault.db");
    let vault = create_vault(&vault_path, "fixture-passphrase")
        .unwrap()
        .vault;
    vault.set("demo/fixture-token", SECRET).unwrap();
    let broker = Arc::new(Broker::from_vault_with_proxy_policy(&vault, &policy_path).unwrap());
    let config = ServerConfig {
        agent_socket: dir.path().join("agent.sock"),
    };
    let server = Server::bind(config.clone(), Arc::clone(&broker))
        .await
        .unwrap();
    let server_task = tokio::spawn(server.run(std::future::pending()));
    if host_client {
        assert_idle_proxy().await;
    }

    let mut changed = operation(&command);
    changed.target = "other.example.test".to_owned();
    let rejected = ipc::call(
        &config.agent_socket,
        &AgentRequest::Request { operation: changed },
    )
    .await
    .unwrap();
    assert_eq!(rejected.error.as_deref(), Some("InvalidOperation"));
    let mut changed = operation(&command);
    changed.arguments = json!({"command": ["/bin/true"]});
    let rejected = ipc::call(
        &config.agent_socket,
        &AgentRequest::Request { operation: changed },
    )
    .await
    .unwrap();
    assert_eq!(rejected.error.as_deref(), Some("InvalidOperation"));

    let denied_id = request_id(&config, &command).await;
    let pending = ipc::call(
        &config.agent_socket,
        &AgentRequest::Execute {
            request_id: denied_id,
        },
    )
    .await
    .unwrap();
    assert_eq!(pending.error.as_deref(), Some("NotApproved"));
    decide(&broker, denied_id, false, 0);
    let denied = ipc::call(
        &config.agent_socket,
        &AgentRequest::Execute {
            request_id: denied_id,
        },
    )
    .await
    .unwrap();
    assert_eq!(denied.error.as_deref(), Some("Denied"));
    assert!(observed.try_recv().is_err());
    if host_client {
        assert_idle_proxy().await;
    }

    if host_client {
        let expired_id = request_id(&config, &command).await;
        decide(&broker, expired_id, true, 1);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let expired = ipc::call(
            &config.agent_socket,
            &AgentRequest::Execute {
                request_id: expired_id,
            },
        )
        .await
        .unwrap();
        assert_eq!(expired.error.as_deref(), Some("Expired"));
        assert!(observed.try_recv().is_err());
    }

    let approved_id = if let Some(av_cli) = av_cli {
        request_id_via_cli(&config, &command, av_cli).await
    } else {
        request_id(&config, &command).await
    };
    let initial_proxy_settings = if host_client && av_cli.is_some() {
        let path = client_proxy_settings_path(dir.path());
        let source = fs::read(path).expect("av did not create user proxy settings");
        assert!(String::from_utf8_lossy(&source).contains("http://127.0.0.1:14322"));
        assert!(!String::from_utf8_lossy(&source).contains(SECRET));
        Some(source)
    } else {
        None
    };
    let review = serde_json::to_value(broker.review(approved_id).unwrap()).unwrap();
    assert_eq!(
        review["operation"],
        serde_json::to_value(operation(&command)).unwrap()
    );
    decide(&broker, approved_id, true, 60);
    let mut overlapping_host_request = None;
    let mut live_tunnel = None;
    let mut old_token = None;
    if let Some(av_cli) = av_cli {
        let output = tokio::time::timeout(
            Duration::from_secs(8),
            tokio::process::Command::new(av_cli)
                .arg("run")
                .arg("--resume")
                .arg(approved_id.to_string())
                .env("AVD_AGENT_SOCKET", &config.agent_socket)
                .env("HOME", dir.path())
                .env("XDG_CONFIG_HOME", dir.path().join("client-config"))
                .output(),
        )
        .await
        .expect("av resume timed out")
        .unwrap();
        assert!(
            output.status.success(),
            "av resume failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if let Some(initial) = initial_proxy_settings {
            assert_eq!(
                fs::read(client_proxy_settings_path(dir.path())).unwrap(),
                initial,
                "av should reuse the existing fixed proxy settings"
            );
        }
    } else {
        let started = data(
            ipc::call(
                &config.agent_socket,
                &AgentRequest::Execute {
                    request_id: approved_id,
                },
            )
            .await
            .unwrap(),
        );
        assert_eq!(started["task_id"], approved_id.to_string());
        if host_client {
            let overlapping_id = request_id(&config, &command).await;
            decide(&broker, overlapping_id, true, 60);
            let overlapping = data(
                ipc::call(
                    &config.agent_socket,
                    &AgentRequest::Execute {
                        request_id: overlapping_id,
                    },
                )
                .await
                .unwrap(),
            );
            assert_eq!(overlapping["task_id"], overlapping_id.to_string());
            assert!(overlapping.get("host_proxy").is_some());
            assert_ne!(
                overlapping["host_proxy"]["proxy_url"], started["host_proxy"]["proxy_url"],
                "concurrent tasks must receive distinct proxy capabilities"
            );
            overlapping_host_request = Some((overlapping_id, overlapping));
            assert!(!started.to_string().contains(SECRET));
            let details = &started["host_proxy"];
            assert!(
                details["proxy_url"]
                    .as_str()
                    .unwrap()
                    .ends_with("@127.0.0.1:14322"),
                "host proxy must use the fixed loopback endpoint"
            );
            let ca_path = dir.path().join("host-proxy-ca.pem");
            fs::write(&ca_path, details["ca_pem"].as_str().unwrap()).unwrap();
            let output = tokio::time::timeout(
                Duration::from_secs(8),
                tokio::process::Command::new(&command[0])
                    .args(&command[1..])
                    .env_clear()
                    .env("HTTPS_PROXY", details["proxy_url"].as_str().unwrap())
                    .env("SSL_CERT_FILE", &ca_path)
                    .env("AV_FIXTURE_TOKEN", "av-placeholder")
                    .output(),
            )
            .await
            .expect("host fixture timed out")
            .unwrap();
            assert!(
                output.status.success(),
                "host fixture failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let token = details["proxy_url"]
                .as_str()
                .unwrap()
                .strip_prefix("http://av:")
                .unwrap()
                .split_once('@')
                .unwrap()
                .0;
            old_token = Some(token.to_owned());
            let mut tunnel = TcpStream::connect("127.0.0.1:14322").await.unwrap();
            tunnel
                .write_all(
                    format!(
                        "CONNECT {HOST}:443 HTTP/1.1\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut accepted = [0_u8; 39];
            tunnel.read_exact(&mut accepted).await.unwrap();
            assert_eq!(&accepted, b"HTTP/1.1 200 Connection Established\r\n\r\n");
            live_tunnel = Some(tunnel);
            let closed = ipc::call(
                &config.agent_socket,
                &AgentRequest::FinishHostProxy {
                    task_id: approved_id,
                    exit_code: 0,
                },
            )
            .await
            .unwrap();
            assert!(closed.ok, "broker did not close host proxy");
        }
    }
    let replay = ipc::call(
        &config.agent_socket,
        &AgentRequest::Execute {
            request_id: approved_id,
        },
    )
    .await
    .unwrap();
    assert_eq!(replay.error.as_deref(), Some("QuotaExhausted"));

    let status = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let status = data(
                ipc::call(
                    &config.agent_socket,
                    &AgentRequest::TaskStatus {
                        task_id: approved_id,
                    },
                )
                .await
                .unwrap(),
            );
            if status["state"] != "running" {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("fixture task did not finish");
    assert_eq!(status["state"], "finished");
    assert_eq!(status["exit_code"], 0);
    if let Some(mut tunnel) = live_tunnel {
        let mut byte = [0_u8];
        let closed = tokio::time::timeout(Duration::from_secs(2), tunnel.read(&mut byte))
            .await
            .expect("revoked tunnel remained open");
        assert!(
            matches!(closed, Ok(0))
                || closed
                    .as_ref()
                    .err()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset),
            "revoked tunnel remained readable: {closed:?}"
        );
    }
    let sent = tokio::time::timeout(Duration::from_secs(2), observed.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sent.path, "/probe");
    assert_eq!(sent.authorization, format!("Bearer {SECRET}"));
    assert_eq!(sent.fixture_input, "av-placeholder");
    if host_client && overlapping_host_request.is_none() {
        assert_idle_proxy().await;
    }
    if let Some((overlapping_id, overlapping)) = overlapping_host_request {
        let replay = ipc::call(
            &config.agent_socket,
            &AgentRequest::Execute {
                request_id: overlapping_id,
            },
        )
        .await
        .unwrap();
        assert_eq!(replay.error.as_deref(), Some("QuotaExhausted"));
        let mut stale = TcpStream::connect("127.0.0.1:14322").await.unwrap();
        stale
            .write_all(
                format!(
                    "CONNECT {HOST}:443 HTTP/1.1\r\nProxy-Authorization: Bearer {}\r\n\r\n",
                    old_token.as_deref().unwrap()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut denial = Vec::new();
        stale.read_to_end(&mut denial).await.unwrap();
        assert!(
            denial.starts_with(b"HTTP/1.1 407 Proxy Authentication Required\r\n"),
            "previous task capability remained usable"
        );
        let details = &overlapping["host_proxy"];
        let ca_path = dir.path().join("overlapping-host-proxy-ca.pem");
        fs::write(&ca_path, details["ca_pem"].as_str().unwrap()).unwrap();
        let output = tokio::time::timeout(
            Duration::from_secs(8),
            tokio::process::Command::new(&command[0])
                .args(&command[1..])
                .env_clear()
                .env("HTTPS_PROXY", details["proxy_url"].as_str().unwrap())
                .env("SSL_CERT_FILE", &ca_path)
                .env("AV_FIXTURE_TOKEN", "av-placeholder")
                .output(),
        )
        .await
        .expect("overlapping host fixture timed out")
        .unwrap();
        assert!(
            output.status.success(),
            "overlapping host fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let second = tokio::time::timeout(Duration::from_secs(2), observed.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.path, "/probe");
        assert_eq!(second.authorization, format!("Bearer {SECRET}"));
        assert_eq!(second.fixture_input, "av-placeholder");
        let invalid = ipc::call(
            &config.agent_socket,
            &AgentRequest::FinishHostProxy {
                task_id: overlapping_id,
                exit_code: -1,
            },
        )
        .await
        .unwrap();
        assert_eq!(invalid.error.as_deref(), Some("InvalidOperation"));
        let closed = ipc::call(
            &config.agent_socket,
            &AgentRequest::FinishHostProxy {
                task_id: overlapping_id,
                exit_code: 42,
            },
        )
        .await
        .unwrap();
        assert!(closed.ok);
        let status = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let status = data(
                    ipc::call(
                        &config.agent_socket,
                        &AgentRequest::TaskStatus {
                            task_id: overlapping_id,
                        },
                    )
                    .await
                    .unwrap(),
                );
                if status["state"] != "running" {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("overlapping host task did not finish");
        assert_eq!(status["exit_code"], 42);
        assert_idle_proxy().await;
    }
    if host_client {
        let expiring_id = request_id(&config, &command).await;
        decide(&broker, expiring_id, true, 3);
        let started = data(
            ipc::call(
                &config.agent_socket,
                &AgentRequest::Execute {
                    request_id: expiring_id,
                },
            )
            .await
            .unwrap(),
        );
        assert!(started.get("host_proxy").is_some());
        let expired = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = broker.task_status(expiring_id).unwrap();
                if status.state != avd::TaskState::Running {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("active host grant did not expire");
        assert_eq!(expired.state, avd::TaskState::Failed);
        assert_idle_proxy().await;

        let locking_id = request_id(&config, &command).await;
        decide(&broker, locking_id, true, 10);
        let started = data(
            ipc::call(
                &config.agent_socket,
                &AgentRequest::Execute {
                    request_id: locking_id,
                },
            )
            .await
            .unwrap(),
        );
        assert!(started.get("host_proxy").is_some());
        broker.shutdown().await;
        assert_eq!(
            broker.task_status(locking_id).unwrap().state,
            avd::TaskState::Failed
        );
        assert!(TcpStream::connect("127.0.0.1:14322").await.is_err());
    }
    server_task.abort();
}

fn decide(broker: &Broker, request_id: Uuid, approve: bool, ttl_seconds: u64) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    broker
        .decide(request_id, approve, now, ttl_seconds)
        .unwrap();
}

async fn assert_idle_proxy() {
    let mut stream = TcpStream::connect("127.0.0.1:14322")
        .await
        .expect("fixed proxy listener is not bound");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("idle proxy did not close the connection")
        .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 407 Proxy Authentication Required\r\n"),
        "idle proxy did not deny CONNECT: {response:?}"
    );
}

async fn request_id_via_cli(config: &ServerConfig, command: &[String], av_cli: &Path) -> Uuid {
    let home = config.agent_socket.parent().unwrap();
    let output = tokio::process::Command::new(av_cli)
        .args([
            "run",
            "--broker",
            "--broker-connection",
            "demo/fixture",
            "--broker-host",
            HOST,
            "--",
        ])
        .args(command)
        .env("AVD_AGENT_SOCKET", &config.agent_socket)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("client-config"))
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "av broker request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("Pending broker request: "))
        .expect("av did not report the request ID")
        .parse()
        .unwrap()
}

fn client_proxy_settings_path(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/AgentsVault.av/proxy.json")
    } else {
        home.join("client-config/av/proxy.json")
    }
}

async fn request_id(config: &ServerConfig, command: &[String]) -> Uuid {
    let created = data(
        ipc::call(
            &config.agent_socket,
            &AgentRequest::Request {
                operation: operation(command),
            },
        )
        .await
        .unwrap(),
    );
    serde_json::from_value(created["request_id"].clone()).unwrap()
}
