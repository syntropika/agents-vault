//! Run explicitly and serially: the protected host proxy binds port 14322.

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use std::{convert::Infallible, fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc};

    use av_core::create_vault;
    #[cfg(target_os = "linux")]
    use av_core::{
        ApprovalRequirement, DeliveryMode, SecretAccessRequest, SecretGrant, SecretPolicy,
    };
    use avd::{
        Operation, RequestState, TaskState,
        ipc::{AgentRequest, PeerPolicy, Server, ServerConfig, call_agent},
        session::{AdminRequest, AdminServer, Session, VaultSource, admin_call},
    };
    use hyper::{Body, Request, Response, header::AUTHORIZATION, service::service_fn};
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    use rustls::{
        ServerConfig as TlsServerConfig,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use serde_json::json;
    #[cfg(target_os = "linux")]
    use sha2::{Digest, Sha256};
    use tokio::{net::TcpListener, sync::oneshot};
    use tokio_rustls::TlsAcceptor;
    use uuid::Uuid;

    const HOST: &str = "api.example.test";
    const SECRET: &str = "av-synthetic-cli-token";

    fn certificates() -> (Vec<u8>, Arc<TlsServerConfig>) {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_params = CertificateParams::new(vec![HOST.to_owned()]).unwrap();
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
        (ca.der().to_vec(), Arc::new(tls))
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "binds the fixed port 14322; run separately after the workspace suite"]
    async fn public_av_run_checks_approval_lifecycle_and_reaches_synthetic_https() {
        let curl = if Path::new("/usr/bin/curl").exists() {
            "/usr/bin/curl"
        } else if Path::new("/opt/homebrew/bin/curl").exists() {
            "/opt/homebrew/bin/curl"
        } else {
            panic!("curl is required for this explicitly requested integration test");
        };
        let directory = tempfile::tempdir().unwrap();
        let vault_path = directory.path().join("vault.db");
        let created = create_vault(&vault_path, "synthetic passphrase").unwrap();
        #[cfg(target_os = "linux")]
        created
            .vault
            .add_connection("service/work", HOST, SECRET)
            .unwrap();
        #[cfg(target_os = "macos")]
        created.vault.set("demo/token", SECRET).unwrap();
        let (ca_der, provider_tls) = certificates();
        let ca_path = directory.path().join("provider-ca.der");
        fs::write(&ca_path, &ca_der).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider_addr = listener.local_addr().unwrap();
        let command = vec![
            curl.to_owned(),
            "--fail".to_owned(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--http1.1".to_owned(),
            "--header".to_owned(),
            "Authorization: Bearer av-placeholder".to_owned(),
            format!("https://{HOST}/probe"),
        ];
        let policy_path = directory.path().join("policy.json");
        #[cfg(target_os = "linux")]
        let policy = json!({
            "connection": "service/work", "connection_version": 1,
            "host": HOST, "command": command, "upstream_addr": provider_addr,
            "upstream_ca_der": ca_path, "max_connects": 1,
            "max_requests": 1, "max_runtime_seconds": 20, "host_client": true
        });
        #[cfg(target_os = "macos")]
        let policy = json!({
            "connection": "demo/work", "secret_name": "demo/token",
            "host": HOST, "command": command, "upstream_addr": provider_addr,
            "upstream_ca_der": ca_path, "max_connects": 1,
            "max_requests": 1, "max_runtime_seconds": 20, "host_client": true
        });
        let source = serde_json::to_vec(&policy).unwrap();
        fs::write(&policy_path, &source).unwrap();
        fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600)).unwrap();
        #[cfg(target_os = "linux")]
        {
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
            request.upstream_ca_sha256 = Some(format!("{:x}", Sha256::digest(&ca_der)));
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
        }
        drop(created);
        let session = Session::locked(VaultSource {
            vault: vault_path.clone(),
            proxy_policy: Some(policy_path),
            service_mode: false,
        })
        .unwrap();
        let socket = directory.path().join("agent.sock");
        let server = Server::bind_with_session(
            ServerConfig {
                agent_socket: socket.clone(),
            },
            Arc::clone(&session),
            PeerPolicy {
                agent_uid: tokio::net::UnixStream::pair()
                    .unwrap()
                    .0
                    .peer_cred()
                    .unwrap()
                    .uid(),
            },
        )
        .await
        .unwrap();
        let admin = AdminServer::bind(directory.path(), Arc::clone(&session))
            .await
            .unwrap();
        let admin_socket = directory.path().join("admin.sock");
        let token = fs::read_to_string(directory.path().join("admin.token")).unwrap();
        let server_task = tokio::spawn(server.run(std::future::pending()));
        let admin_task = tokio::spawn(admin.run());
        assert!(
            admin_call(
                &admin_socket,
                &AdminRequest::Unlock {
                    token: token.clone(),
                    passphrase: "synthetic passphrase".into(),
                }
            )
            .await
            .unwrap()
            .ok
        );
        let (seen_sender, seen_receiver) = oneshot::channel();
        let provider_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = TlsAcceptor::from(provider_tls)
                .accept(socket)
                .await
                .unwrap();
            let sender = std::sync::Mutex::new(Some(seen_sender));
            let service = service_fn(move |request: Request<Body>| {
                let auth = request
                    .headers()
                    .get(AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("<missing>")
                    .to_owned();
                if let Some(sender) = sender.lock().unwrap().take() {
                    let _ = sender.send(auth);
                }
                async { Ok::<_, Infallible>(Response::new(Body::from("ok"))) }
            });
            hyper::server::conn::Http::new()
                .http1_only(true)
                .serve_connection(tls, service)
                .await
                .unwrap();
        });
        let config = directory.path().join("av.toml");
        #[cfg(target_os = "linux")]
        fs::write(&config, "schema = 2\n[project]\nid = 'curl-test'\n[values.SERVICE_TOKEN]\ntype = 'string'\nconnection = { id = 'service/work', version = 1 }\ndelivery = 'proxy'\nrequired = true\n").unwrap();
        #[cfg(target_os = "macos")]
        fs::write(&config, "schema = 2\n[project]\nid = 'curl-test'\n").unwrap();
        let run_av = |args: Vec<String>| {
            let mut process = tokio::process::Command::new(env!("CARGO_BIN_EXE_av"));
            process
                .arg("--config")
                .arg(&config)
                .arg("--vault")
                .arg(&vault_path)
                .args(args)
                .current_dir("/")
                .env("AVD_AGENT_SOCKET", &socket)
                .env("HOME", directory.path())
                .env("XDG_CONFIG_HOME", directory.path().join("client-config"));
            process
        };
        #[cfg(target_os = "linux")]
        let mut request_args = vec!["run".into(), "--broker".into(), "--".into()];
        #[cfg(target_os = "macos")]
        let mut request_args = vec![
            "run".into(),
            "--broker".into(),
            "--broker-connection".into(),
            "demo/work".into(),
            "--broker-host".into(),
            HOST.into(),
            "--".into(),
        ];
        request_args.extend(command.clone());
        let requested = run_av(request_args).output().await.unwrap();
        assert!(
            requested.status.success(),
            "{}",
            String::from_utf8_lossy(&requested.stderr)
        );
        let stdout = String::from_utf8(requested.stdout).unwrap();
        let id: Uuid = stdout
            .lines()
            .find_map(|line| line.strip_prefix("Pending broker request: "))
            .unwrap()
            .parse()
            .unwrap();
        let review = call_agent(&socket, &AgentRequest::Review { request_id: id })
            .await
            .unwrap();
        let frozen: avd::Review = serde_json::from_value(review.data.unwrap()).unwrap();
        assert_eq!(frozen.state, RequestState::Pending);
        assert!(!serde_json::to_string(&frozen).unwrap().contains(SECRET));
        let resume_args = |id: Uuid| vec!["run".into(), "--resume".into(), id.to_string()];
        let pending = run_av(resume_args(id)).output().await.unwrap();
        assert!(!pending.status.success());
        assert!(String::from_utf8_lossy(&pending.stderr).contains("NotApproved"));
        let forged = avd::ipc::call(
            &socket,
            &json!({
                "op": "decide", "token": token, "passphrase": "synthetic passphrase",
                "request_id": id, "approve": true, "ttl_seconds": 30,
            }),
        )
        .await
        .unwrap();
        assert_eq!(forged.error.as_deref(), Some("invalid_request"));
        let wrong = admin_call(
            &admin_socket,
            &AdminRequest::Decide {
                token: token.clone(),
                passphrase: "wrong".into(),
                request_id: id,
                approve: true,
                ttl_seconds: 30,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            wrong.error.as_deref(),
            Some("operator authentication failed")
        );

        // Exercise denials and expiry through the same public execution command.
        let request_again = || AgentRequest::Request {
            operation: frozen.operation.clone(),
        };
        let denied: Uuid = serde_json::from_value(
            call_agent(&socket, &request_again())
                .await
                .unwrap()
                .data
                .unwrap()["request_id"]
                .clone(),
        )
        .unwrap();
        assert!(
            admin_call(
                &admin_socket,
                &AdminRequest::Decide {
                    token: token.clone(),
                    passphrase: "synthetic passphrase".into(),
                    request_id: denied,
                    approve: false,
                    ttl_seconds: 30,
                }
            )
            .await
            .unwrap()
            .ok
        );
        let result = run_av(resume_args(denied)).output().await.unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("Denied"));
        let expired: Uuid = serde_json::from_value(
            call_agent(&socket, &request_again())
                .await
                .unwrap()
                .data
                .unwrap()["request_id"]
                .clone(),
        )
        .unwrap();
        assert!(
            admin_call(
                &admin_socket,
                &AdminRequest::Decide {
                    token: token.clone(),
                    passphrase: "synthetic passphrase".into(),
                    request_id: expired,
                    approve: true,
                    ttl_seconds: 1,
                }
            )
            .await
            .unwrap()
            .ok
        );
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let result = run_av(resume_args(expired)).output().await.unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("Expired"));
        let mut changed: Operation = frozen.operation.clone();
        changed.arguments["command"] = json!([curl, "https://other.example.test/"]);
        assert_eq!(
            call_agent(&socket, &AgentRequest::Request { operation: changed })
                .await
                .unwrap()
                .error
                .as_deref(),
            Some("InvalidOperation")
        );

        let decision = AdminRequest::Decide {
            token: token.clone(),
            passphrase: "synthetic passphrase".into(),
            request_id: id,
            approve: true,
            ttl_seconds: 30,
        };
        let (first, second) = tokio::join!(
            admin_call(&admin_socket, &decision),
            admin_call(&admin_socket, &decision)
        );
        let replies = [first.unwrap(), second.unwrap()];
        assert_eq!(replies.iter().filter(|reply| reply.ok).count(), 1);
        assert!(
            replies
                .iter()
                .any(|reply| reply.error.as_deref() == Some("AlreadyDecided"))
        );
        let (first, second) = tokio::join!(
            run_av(resume_args(id)).output(),
            run_av(resume_args(id)).output()
        );
        let outputs = [first.unwrap(), second.unwrap()];
        assert_eq!(
            outputs
                .iter()
                .filter(|output| output.status.success())
                .count(),
            1
        );
        let resumed = outputs
            .iter()
            .find(|output| output.status.success())
            .unwrap();
        let refused = outputs
            .iter()
            .find(|output| !output.status.success())
            .unwrap();
        assert!(String::from_utf8_lossy(&refused.stderr).contains("QuotaExhausted"));
        assert!(
            resumed.status.success(),
            "{}",
            String::from_utf8_lossy(&resumed.stderr)
        );
        assert_eq!(resumed.stdout, b"ok");
        assert_eq!(seen_receiver.await.unwrap(), format!("Bearer {SECRET}"));
        let status: avd::TaskStatus = serde_json::from_value(
            call_agent(&socket, &AgentRequest::TaskStatus { task_id: id })
                .await
                .unwrap()
                .data
                .unwrap(),
        )
        .unwrap();
        assert_eq!(status.state, TaskState::Finished);
        assert_eq!(status.exit_code, Some(0));
        let replay = run_av(resume_args(id)).output().await.unwrap();
        assert!(!replay.status.success());
        assert!(String::from_utf8_lossy(&replay.stderr).contains("QuotaExhausted"));
        assert!(
            admin_call(
                &admin_socket,
                &AdminRequest::Lock {
                    token: token.clone()
                }
            )
            .await
            .unwrap()
            .ok
        );
        let locked = run_av(resume_args(id)).output().await.unwrap();
        assert!(!locked.status.success());
        assert!(String::from_utf8_lossy(&locked.stderr).contains("Locked"));
        assert!(
            admin_call(
                &admin_socket,
                &AdminRequest::Unlock {
                    token,
                    passphrase: "synthetic passphrase".into(),
                }
            )
            .await
            .unwrap()
            .ok
        );
        let stale = run_av(resume_args(id)).output().await.unwrap();
        assert!(!stale.status.success());
        assert!(String::from_utf8_lossy(&stale.stderr).contains("UnknownRequest"));
        provider_task.abort();
        server_task.abort();
        admin_task.abort();
        session.lock().await;
    }
}
