use super::*;
#[test]
fn apps_capability_is_explicit_and_mime_specific() {
    for value in [
        json!({}),
        json!({"elicitation":{}}),
        json!({"extensions":{UI_EXTENSION:{"mimeTypes":["text/html"]}}}),
    ] {
        assert!(!supports_apps(&serde_json::from_value(value).unwrap()));
    }
    assert!(supports_apps(
        &serde_json::from_value(json!({"extensions":{UI_EXTENSION:{"mimeTypes":[APP_MIME]}}}))
            .unwrap()
    ));
}
#[test]
fn decision_arguments_reject_authority_and_extra_fields() {
    assert!(input::<DecisionArgs>(json!({"request_id":Uuid::new_v4(),"review_digest":"a".repeat(64),"approve":true,"nonce":"forged"})).is_err());
}

#[derive(Clone)]
struct AppsClient {
    enabled: bool,
}
impl rmcp::ClientHandler for AppsClient {
    fn get_info(&self) -> ClientConfig {
        let mut info = ClientConfig::default();
        if self.enabled {
            info.capabilities.extensions = Some(
                serde_json::from_value(json!({UI_EXTENSION:{"mimeTypes":[APP_MIME]}})).unwrap(),
            );
        }
        info
    }
}
fn adapter() -> Adapter {
    Adapter {
        agent_socket: "/nonexistent/av-mcp-test.sock".into(),
        nonce: Arc::new(Zeroizing::new("a".repeat(64))),
    }
}
#[tokio::test]
async fn protocol_rejects_clients_without_apps() {
    let (server_transport, client_transport) = tokio::io::duplex(65536);
    let server = tokio::spawn(async move { adapter().serve(server_transport).await });
    let client = AppsClient { enabled: false }.serve(client_transport).await;
    assert!(client.is_err());
    assert!(server.await.unwrap().is_err());
}
#[tokio::test]
async fn protocol_exports_embedded_view_and_app_only_decisions_without_authority() {
    if APP_HTML.is_empty() {
        let (server_transport, client_transport) = tokio::io::duplex(65536);
        let server = tokio::spawn(async move { adapter().serve(server_transport).await });
        assert!(
            AppsClient { enabled: true }
                .serve(client_transport)
                .await
                .is_err()
        );
        assert!(server.await.unwrap().is_err());
        return;
    }
    let (server_transport, client_transport) = tokio::io::duplex(1024 * 1024);
    let server = tokio::spawn(async move {
        let service = adapter().serve(server_transport).await.unwrap();
        service.waiting().await.unwrap();
    });
    let client = AppsClient { enabled: true }
        .serve(client_transport)
        .await
        .unwrap();
    let tools = client.list_tools(Default::default()).await.unwrap();
    assert!(tools.tools.iter().all(|t| t.name != "execute_proxy_task"));
    let decision = tools
        .tools
        .iter()
        .find(|t| t.name == "decide_task")
        .unwrap();
    assert_eq!(
        serde_json::to_value(decision).unwrap()["_meta"]["ui"]["visibility"],
        json!(["app"])
    );
    let resource = client
        .read_resource(ReadResourceRequestParams::new(APP_URI))
        .await
        .unwrap();
    let value = serde_json::to_value(resource).unwrap();
    assert_eq!(value["contents"][0]["mimeType"], APP_MIME);
    assert_eq!(
        value["contents"][0]["_meta"]["ui"]["csp"]["connectDomains"],
        json!([])
    );
    assert!(
        value["contents"][0]["text"]
            .as_str()
            .unwrap()
            .contains("<script type=\"module\">")
    );
    let result = client
        .call_tool(
            CallToolRequestParams::new("decide_task").with_arguments(
                json!({"request_id":Uuid::new_v4(),"review_digest":"a".repeat(64),"approve":true})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(result.is_error, Some(true));
    assert!(result.structured_content.is_none());
    client.cancel().await.unwrap();
    server.abort();
}
