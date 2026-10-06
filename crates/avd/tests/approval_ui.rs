//! Exercise the operator page through HTTP and public broker sockets, without a harness.

use avd::{
    Operation, RequestState, Review,
    approval::ApprovalServer,
    ipc::{AgentRequest, PeerPolicy, Server, ServerConfig, call_agent},
    session::{AdminRequest, AdminServer, Session, VaultSource, admin_call},
};
use hyper::{Body, Client, Request, StatusCode};
use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt, sync::Arc};
use uuid::Uuid;

#[tokio::test]
async fn local_operator_decisions_are_authenticated_bound_and_one_use() {
    let directory = tempfile::tempdir().unwrap();
    let vault = directory.path().join("vault.db");
    let created = av_core::create_vault(&vault, "synthetic passphrase").unwrap();
    created
        .vault
        .set("demo/token", "av-synthetic-ui-token")
        .unwrap();
    drop(created);
    let certificate = rcgen::generate_simple_self_signed(vec!["api.example.test".into()]).unwrap();
    let ca = directory.path().join("ca.der");
    fs::write(&ca, certificate.cert.der()).unwrap();
    let command = vec!["/bin/echo", "<script>fake approval</script>"];
    let policy = directory.path().join("policy.json");
    fs::write(&policy, serde_json::to_vec(&json!({
        "connection":"demo/provider", "secret_name":"demo/token", "host":"api.example.test", "command":command,
        "upstream_addr":"127.0.0.1:9", "upstream_ca_der":ca, "max_connects":1,"max_requests":1,"max_runtime_seconds":20,
    })).unwrap()).unwrap();
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
    let session = Session::locked(VaultSource {
        vault,
        proxy_policy: Some(policy),
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
            agent_uid: unsafe { libc::geteuid() },
        },
    )
    .await
    .unwrap();
    let admin = AdminServer::bind(directory.path(), Arc::clone(&session))
        .await
        .unwrap();
    let server_task = tokio::spawn(server.run(std::future::pending()));
    let admin_task = tokio::spawn(admin.run());
    let admin_socket = directory.path().join("admin.sock");
    let token = fs::read_to_string(directory.path().join("admin.token")).unwrap();
    let ui = ApprovalServer::bind(Arc::clone(&session), 0).await.unwrap();
    let origin = format!("http://{}", ui.address());
    let ui_task = tokio::spawn(ui.run());
    let client = Client::new();
    assert!(
        admin_call(
            &admin_socket,
            &AdminRequest::Unlock {
                token: token.clone(),
                passphrase: "synthetic passphrase".into()
            }
        )
        .await
        .unwrap()
        .ok
    );
    let operation = Operation {
        connection: "demo/provider".into(),
        action: "proxy.run".into(),
        target: "api.example.test".into(),
        arguments: json!({"command":command}),
    };
    let mut owner = avd::ipc::Connection::connect(&socket).await.unwrap();
    let requested = owner
        .call(&AgentRequest::Request {
            operation: operation.clone(),
        })
        .await
        .unwrap();
    let id: Uuid = serde_json::from_value(requested.data.unwrap()["request_id"].clone()).unwrap();
    let url = format!("{origin}/requests/{id}");
    let link = call_agent(&socket, &AgentRequest::ApprovalLink { request_id: id })
        .await
        .unwrap();
    assert_eq!(link.data.unwrap()["url"], url);
    let page = client.get(url.parse().unwrap()).await.unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(page.headers()["cache-control"], "no-store");
    assert_eq!(page.headers()["x-frame-options"], "DENY");
    assert!(
        page.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("form-action 'self'")
    );
    let page = String::from_utf8(
        hyper::body::to_bytes(page.into_body())
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(page.contains("&lt;script&gt;"));
    assert!(!page.contains("<script>"));
    assert!(!page.contains("av-synthetic-ui-token"));
    let nonce = page
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let form = format!("csrf={nonce}&passphrase=synthetic+passphrase&decision=approve");
    let post = |url: &str, origin: &str, body: String| {
        Request::post(url)
            .header("Origin", origin)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap()
    };
    assert_eq!(
        client
            .request(post(&url, "http://evil.test", form.clone()))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .request(post(&url, &origin, format!("{form}&decision=deny")))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client
            .request(post(&url, &origin, format!("{form}&unknown=true")))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client
            .request(post(&url, &origin, "x".repeat(8193)))
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let bad_host = Request::get(&url)
        .header("Host", "evil.test")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        client.request(bad_host).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .get(format!("{url}?next=http://evil.test").parse().unwrap())
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .request(post(
                &url,
                &origin,
                form.replace("synthetic+passphrase", "wrong")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let review: Review = serde_json::from_value(
        call_agent(&socket, &AgentRequest::Review { request_id: id })
            .await
            .unwrap()
            .data
            .unwrap(),
    )
    .unwrap();
    assert_eq!(review.state, RequestState::Pending);
    assert_eq!(
        client
            .request(post(&url, &origin, form))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        owner
            .call(&AgentRequest::Execute { request_id: id })
            .await
            .unwrap()
            .error
            .as_deref(),
        Some("NotApproved")
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let page = hyper::body::to_bytes(client.get(url.parse().unwrap()).await.unwrap().into_body())
        .await
        .unwrap();
    let page = std::str::from_utf8(&page).unwrap();
    let nonce = page
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let body = format!("csrf={nonce}&passphrase=synthetic+passphrase&decision=approve");
    let (first, second) = tokio::join!(
        client.request(post(&url, &origin, body.clone())),
        client.request(post(&url, &origin, body))
    );
    let statuses = [first.unwrap().status(), second.unwrap().status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );
    assert!(statuses.contains(&StatusCode::FORBIDDEN));
    let review: Review = serde_json::from_value(
        call_agent(&socket, &AgentRequest::Review { request_id: id })
            .await
            .unwrap()
            .data
            .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        review.state,
        RequestState::Approved { remaining: 1, .. }
    ));

    let next = owner
        .call(&AgentRequest::Request {
            operation: operation.clone(),
        })
        .await
        .unwrap();
    let next_id: Uuid = serde_json::from_value(next.data.unwrap()["request_id"].clone()).unwrap();
    let next_url = format!("{origin}/requests/{next_id}");
    let page = hyper::body::to_bytes(
        client
            .get(next_url.parse().unwrap())
            .await
            .unwrap()
            .into_body(),
    )
    .await
    .unwrap();
    let page = std::str::from_utf8(&page).unwrap();
    let nonce = page
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    // A form cannot be applied to another request even with the correct password.
    let unknown_url = format!("{origin}/requests/{}", Uuid::new_v4());
    assert_eq!(
        client
            .request(post(
                &unknown_url,
                &origin,
                format!("csrf={nonce}&passphrase=synthetic+passphrase&decision=approve")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
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
    assert_eq!(
        client
            .get(next_url.parse().unwrap())
            .await
            .unwrap()
            .status(),
        StatusCode::LOCKED
    );
    assert!(
        admin_call(
            &admin_socket,
            &AdminRequest::Unlock {
                token,
                passphrase: "synthetic passphrase".into()
            }
        )
        .await
        .unwrap()
        .ok
    );
    assert_eq!(
        client
            .get(next_url.parse().unwrap())
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    session.lock().await;
    ui_task.abort();
    server_task.abort();
    admin_task.abort();
}
