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
