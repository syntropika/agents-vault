//! Real encrypted-vault administration through loopback HTTP, without a harness.
use avd::{
    approval::ApprovalServer,
    session::{Session, VaultSource},
};
use hyper::{Body, Client, Method, Request, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;

struct Browser {
    client: Client<hyper::client::HttpConnector>,
    origin: String,
    cookies: String,
    csrf: String,
}
impl Browser {
    async fn call(&mut self, path: &str, value: Option<Value>) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(if value.is_some() {
                Method::POST
            } else {
                Method::GET
            })
            .uri(format!("{}{path}", self.origin))
            .header("cookie", &self.cookies)
            .header("x-av-csrf", &self.csrf);
        if value.is_some() {
            request = request
                .header("origin", &self.origin)
                .header("content-type", "application/json");
        }
        let response = self
            .client
            .request(
                request
                    .body(Body::from(value.map(|v| v.to_string()).unwrap_or_default()))
                    .unwrap(),
            )
            .await
            .unwrap();
        if let Some(cookie) = response.headers().get("set-cookie") {
            let cookie = cookie.to_str().unwrap();
            assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
            let pair = cookie.split(';').next().unwrap();
            self.cookies = pair.to_owned();
        }
        let status = response.status();
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        if let Some(csrf) = value["csrf"].as_str() {
            self.csrf = csrf.to_owned();
        }
        (status, value)
    }
}
#[tokio::test]
async fn operator_session_enforces_authentication_csrf_versions_and_lock() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.db");
    drop(av_core::create_vault(&path, "synthetic passphrase").unwrap());
    let session = Session::locked(VaultSource {
        vault: path.clone(),
        proxy_policy: None,
        service_mode: false,
    })
    .unwrap();
    let server = ApprovalServer::bind(Arc::clone(&session), 0).await.unwrap();
    let origin = format!("http://{}", server.address());
    let task = tokio::spawn(server.run());
    let mut browser = Browser {
        client: Client::new(),
        origin,
        cookies: String::new(),
        csrf: String::new(),
    };
    assert_eq!(
        browser.call("/api/operator/status", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        browser.call("/api/operator/bootstrap", None).await.0,
        StatusCode::OK
    );
    let foreign = Request::post(format!("{}/api/operator/session", browser.origin))
        .header("origin", "https://foreign.example")
        .header("cookie", &browser.cookies)
        .header("x-av-csrf", &browser.csrf)
        .header("content-type", "application/json")
        .body(Body::from("{\"passphrase\":\"synthetic passphrase\"}"))
        .unwrap();
    assert_eq!(
        browser.client.request(foreign).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let old_cookie = browser.cookies.clone();
    let old_csrf = browser.csrf.clone();
    assert_eq!(
        browser
            .call(
                "/api/operator/session",
                Some(json!({"passphrase":"wrong synthetic"}))
            )
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        browser
            .call(
                "/api/operator/session",
                Some(json!({"passphrase":"synthetic passphrase"}))
            )
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    browser.call("/api/operator/bootstrap", None).await;
    assert_eq!(
        browser
            .call(
                "/api/operator/session",
                Some(json!({"passphrase":"synthetic passphrase"}))
            )
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        browser.call("/api/operator/status", None).await.1["locked"],
        true
    );
    let good_csrf = browser.csrf.clone();
    browser.csrf = old_csrf;
    assert_eq!(
        browser
            .call(
                "/api/operator/manage",
                Some(json!({"action":"connect_list"}))
            )
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    browser.csrf = good_csrf;
    assert_eq!(browser.call("/api/operator/manage",Some(json!({"action":"connect_add","id":"demo/example","host":"api.example.test","value":"av-synthetic-web-value"}))).await.0,StatusCode::OK);
    let (_, list) = browser
        .call(
            "/api/operator/manage",
            Some(json!({"action":"connect_list"})),
        )
        .await;
    assert_eq!(list["connections"][0]["version"], 1);
    assert!(!list.to_string().contains("av-synthetic-web-value"));
    let (_, detail) = browser
        .call(
            "/api/operator/manage",
            Some(json!({"action":"connect_show","id":"demo/example"})),
        )
        .await;
    assert_eq!(detail["policy"]["grants"], json!([]));
    assert!(!detail.to_string().contains("av-synthetic-web-value"));
    assert_eq!(
        browser
            .call(
                "/api/operator/manage",
                Some(json!({"action":"connect_grant","id":"demo/example","expected_version":1}))
            )
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(browser.call("/api/operator/manage",Some(json!({"action":"connect_replace","id":"demo/example","expected_version":1,"value":"av-synthetic-rotated"}))).await.0,StatusCode::OK);
    assert_eq!(
        browser
            .call(
                "/api/operator/manage",
                Some(
                    json!({"action":"connect_disconnect","id":"demo/example","expected_version":1})
                )
            )
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        browser
            .call(
                "/api/operator/manage",
                Some(
                    json!({"action":"connect_disconnect","id":"demo/example","expected_version":2})
                )
            )
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        browser
            .call(
                "/api/operator/manage",
                Some(json!({"action":"add","name":"demo/hidden","value":"blocked"}))
            )
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let authenticated_cookie = browser.cookies.clone();
    session.lock().await;
    assert_eq!(
        browser.call("/api/operator/status", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    browser.cookies = old_cookie;
    assert_eq!(
        browser
            .call(
                "/api/operator/session",
                Some(json!({"passphrase":"synthetic passphrase"}))
            )
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    browser.cookies = authenticated_cookie;
    assert_eq!(
        browser
            .call(
                "/api/operator/manage",
                Some(json!({"action":"connect_list"}))
            )
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let vault = av_core::Vault::open(&path, "synthetic passphrase").unwrap();
    assert!(
        !vault
            .connection_metadata("demo/example")
            .unwrap()
            .unwrap()
            .active
    );
    task.abort();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn task_editor_binds_revision_and_revokes_grants() {
    use avd::{
        Operation,
        ipc::{self, AgentRequest, PeerPolicy, Server, ServerConfig},
    };
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("vault.db");
    let ca = directory.path().join("ca.der");
    let certificate =
        rcgen::generate_simple_self_signed(vec!["api.test.example.test".into()]).unwrap();
    std::fs::write(&ca, certificate.cert.der()).unwrap();
    let created = av_core::create_vault(&path, "synthetic passphrase").unwrap();
    created
        .vault
        .add_connection("test/cli", "api.test.example.test", "av-synthetic-web-task")
        .unwrap();
    drop(created);
    let session = Session::locked(VaultSource {
        vault: path.clone(),
        proxy_policy: None,
        service_mode: false,
    })
    .unwrap();
    let server = ApprovalServer::bind(session.clone(), 0).await.unwrap();
    let mut browser = Browser {
        client: Client::new(),
        origin: format!("http://{}", server.address()),
        cookies: String::new(),
        csrf: String::new(),
    };
    let http = tokio::spawn(server.run());
    browser.call("/api/operator/bootstrap", None).await;
    assert_eq!(
        browser
            .call(
                "/api/operator/session",
                Some(json!({"passphrase":"synthetic passphrase"}))
            )
            .await
            .0,
        StatusCode::OK
    );
    let recipe = json!({"connection":"test/cli","connection_version":1,"host":"api.test.example.test","command":["/usr/bin/true"],"max_connects":2,"max_requests":3,"max_runtime_seconds":20,"upstream_addr":"127.0.0.1:19443","upstream_ca_der":ca});
    let (status, saved) = browser
        .call(
            "/api/operator/manage",
            Some(json!({"action":"task_save","expected_revision":null,"recipe":recipe})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(
        std::fs::metadata(path.with_extension("proxy.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        browser
            .call(
                "/api/operator/manage",
                Some(json!({"action":"task_save","expected_revision":null,"recipe":recipe}))
            )
            .await
            .0,
        StatusCode::CONFLICT
    );
    let mut invalid = recipe.clone();
    invalid["max_requests"] = json!(17);
    assert_eq!(browser.call("/api/operator/manage",Some(json!({"action":"task_save","expected_revision":saved["revision"],"recipe":invalid}))).await.0,StatusCode::CONFLICT);
    assert_eq!(
        browser
            .call(
                "/api/operator/manage",
                Some(json!({"action":"connect_grant","id":"test/cli","expected_version":1}))
            )
            .await
            .0,
        StatusCode::OK
    );
    let mut updated = recipe.clone();
    updated["max_requests"] = json!(4);
    assert_eq!(browser.call("/api/operator/manage",Some(json!({"action":"task_save","expected_revision":saved["revision"],"recipe":updated}))).await.0,StatusCode::OK);
    let (_, shown) = browser
        .call(
            "/api/operator/manage",
            Some(json!({"action":"connect_show","id":"test/cli"})),
        )
        .await;
    assert_eq!(shown["policy"]["grants"], json!([]));
    assert_eq!(
        browser
            .call("/api/operator/unlock", Some(json!({})))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        browser
            .call(
                "/api/operator/manage",
                Some(json!({"action":"connect_grant","id":"test/cli","expected_version":1}))
            )
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        browser
            .call("/api/operator/unlock", Some(json!({})))
            .await
            .0,
        StatusCode::OK
    );
    let socket = directory.path().join("agent.sock");
    let agent = Server::bind_with_session(
        ServerConfig {
            agent_socket: socket.clone(),
        },
        session.clone(),
        PeerPolicy {
            agent_uid: unsafe { libc::geteuid() },
        },
    )
    .await
    .unwrap();
    let ipc_task = tokio::spawn(agent.run(std::future::pending()));
    let nonce = "a".repeat(64);
    let other = "b".repeat(64);
    let pair = ipc::call_agent(
        &socket,
        &AgentRequest::McpEnroll {
            nonce: nonce.clone(),
        },
    )
    .await
    .unwrap()
    .data
    .unwrap();
    let id: uuid::Uuid = serde_json::from_value(pair["pairing_id"].clone()).unwrap();
    let operation = Operation {
        connection: "test/cli".into(),
        action: "proxy.run".into(),
        target: "api.test.example.test".into(),
        arguments: json!({"command":["/usr/bin/true"],"connection_version":1}),
    };
    let mut owner = ipc::Connection::connect(&socket).await.unwrap();
    let created = owner
        .call(&AgentRequest::Request {
            operation: operation.clone(),
        })
        .await
        .unwrap()
        .data
        .unwrap();
    let request_id = serde_json::from_value(created["request_id"].clone()).unwrap();
    assert!(
        !ipc::call_agent(
            &socket,
            &AgentRequest::McpRequest {
                request_id,
                nonce: nonce.clone(),
                operation: operation.clone()
            }
        )
        .await
        .unwrap()
        .ok
    );
    assert_eq!(
        browser
            .call(
                "/api/operator/mcp",
                Some(json!({"pairing_id":id,"approve":true}))
            )
            .await
            .0,
        StatusCode::OK
    );
    let task = ipc::call_agent(
        &socket,
        &AgentRequest::McpRequest {
            request_id,
            nonce: nonce.clone(),
            operation: operation.clone(),
        },
    )
    .await
    .unwrap()
    .data
    .unwrap();
    let request_id = serde_json::from_value(task["review"]["id"].clone()).unwrap();
    assert!(
        !ipc::call_agent(
            &socket,
            &AgentRequest::McpReview {
                nonce: other,
                request_id
            }
        )
        .await
        .unwrap()
        .ok
    );
    assert!(
        !ipc::call_agent(
            &socket,
            &AgentRequest::McpDecide {
                nonce: nonce.clone(),
                request_id,
                review_digest: "0".repeat(64),
                approve: true
            }
        )
        .await
        .unwrap()
        .ok
    );
    let digest = task["review_digest"].as_str().unwrap().to_owned();
    let decision = AgentRequest::McpDecide {
        nonce: nonce.clone(),
        request_id,
        review_digest: digest,
        approve: true,
    };
    assert!(ipc::call_agent(&socket, &decision).await.unwrap().ok);
    assert!(!ipc::call_agent(&socket, &decision).await.unwrap().ok);
    assert_eq!(
        browser
            .call(
                "/api/operator/mcp",
                Some(json!({"pairing_id":id,"approve":false}))
            )
            .await
            .0,
        StatusCode::OK
    );
    assert!(
        !ipc::call_agent(&socket, &AgentRequest::McpReview { nonce, request_id })
            .await
            .unwrap()
            .ok
    );
    session.lock().await;
    ipc_task.abort();
    http.abort();
}
