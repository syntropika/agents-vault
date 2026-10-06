//! Unprivileged MCP adapter for broker-owned proxy tasks.
//! Approval is authenticated on a broker-owned local page, outside the MCP transport.

use std::{env, io, path::PathBuf};

use avd::{
    Operation, RequestState, Review,
    approval::review_prompt as proxy_run_prompt,
    ipc::{self, AgentRequest, Reply},
};
use rmcp::{
    Peer, RoleServer, ServerHandler, ServiceExt,
    handler::server::wrapper::Parameters,
    model::{ElicitRequestParams, ElicitationAction},
    service::ElicitationMode,
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

#[derive(Clone)]
struct Adapter {
    agent_socket: PathBuf,
    elicitation_timeout: std::time::Duration,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReviewRequestArgs {
    request_id: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ProxyTaskArgs {
    connection: String,
    connection_version: Option<u64>,
    host: String,
    command: Vec<String>,
}

impl Adapter {
    async fn agent(&self, request: AgentRequest) -> Result<serde_json::Value, String> {
        let reply = ipc::call_agent(&self.agent_socket, &request)
            .await
            .map_err(|error| match error.kind() {
                io::ErrorKind::TimedOut => "broker_timeout".to_owned(),
                _ => "broker_unavailable".to_owned(),
            })?;
        reply_data(reply)
    }

    async fn broker_review(&self, request_id: Uuid) -> Result<Review, String> {
        let data = self.agent(AgentRequest::Review { request_id }).await?;
        let review: Review =
            serde_json::from_value(data).map_err(|_| "invalid_broker_review".to_owned())?;
        if review.id != request_id {
            return Err("broker_review_id_mismatch".into());
        }
        if review.state != RequestState::Pending {
            return Err("request_not_pending".into());
        }
        Ok(review)
    }

    async fn review_existing_request(
        &self,
        request_id: Uuid,
        client: Peer<RoleServer>,
    ) -> Result<String, String> {
        let review = self.broker_review(request_id).await?;
        let prompt = proxy_run_prompt(&review)?;
        let link = self
            .agent(AgentRequest::ApprovalLink { request_id })
            .await?;
        let url = link
            .get("url")
            .and_then(|value| value.as_str())
            .ok_or("invalid_approval_link")?;
        // Only broker-issued loopback URLs can be displayed. Project declarations
        // and tool arguments cannot supply an approval destination.
        validate_approval_link(url, request_id)?;
        let action = if client
            .supported_elicitation_modes()
            .contains(&ElicitationMode::Url)
        {
            let answer = client.create_elicitation_with_timeout(
                ElicitRequestParams::UrlElicitationParams {
                    meta: None,
                    message: format!("{prompt}\nApprove or deny on the local Agents Vault page. Never provide the vault passphrase in chat or MCP."),
                    url: url.to_owned(),
                    elicitation_id: request_id.to_string(),
                },
                Some(self.elicitation_timeout),
            ).await;
            match answer {
                Ok(answer) if answer.action == ElicitationAction::Accept => "CLIENT_ACCEPTED",
                Ok(answer) if answer.action == ElicitationAction::Decline => "CLIENT_DECLINED",
                Ok(_) => "CLIENT_CANCELLED",
                Err(_) => "CLIENT_UNAVAILABLE_OR_TIMED_OUT",
            }
        } else {
            "MANUAL_REVIEW_REQUIRED"
        };
        // The client response is never the decision. Re-read authoritative broker
        // state, including when the client cancels after a real operator decision.
        let data = self.agent(AgentRequest::Review { request_id }).await?;
        let current: Review = serde_json::from_value(data).map_err(|_| "invalid_broker_review")?;
        if current.id != request_id
            || current.operation != review.operation
            || current.task_policy != review.task_policy
        {
            return Err("broker_review_changed".into());
        }
        match current.state {
            RequestState::Approved { expires_at, .. }
                if expires_at
                    <= std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| "invalid_clock")?
                        .as_secs() =>
            {
                Ok(format!("EXPIRED request {request_id}. {action}"))
            }
            RequestState::Approved { .. } => Ok(format!(
                "APPROVED request {request_id}; resume with `av run --resume {request_id}`. {action}"
            )),
            RequestState::Denied => Ok(format!("DENIED request {request_id}. {action}")),
            RequestState::Pending => Ok(format!(
                "PENDING request {request_id}; open {url} to authenticate and decide. {action}; a client response alone does not authorize execution"
            )),
            RequestState::Exhausted => Ok(format!("CONSUMED request {request_id}. {action}")),
        }
    }

    async fn create_proxy_task(&self, args: ProxyTaskArgs) -> Result<String, String> {
        if args.connection.is_empty()
            || args.host.is_empty()
            || args.command.is_empty()
            || args.command[0].is_empty()
            || args.command.iter().any(|part| part.contains('\0'))
        {
            return Err("invalid_proxy_task_arguments".into());
        }
        let mut arguments = json!({"command": args.command});
        if let Some(version) = args.connection_version {
            if version == 0 {
                return Err("invalid_proxy_task_arguments".into());
            }
            arguments["connection_version"] = json!(version);
        }
        let created = self
            .agent(AgentRequest::Request {
                operation: Operation {
                    connection: args.connection,
                    action: "proxy.run".into(),
                    target: args.host,
                    arguments,
                },
            })
            .await?;
        let request_id: Uuid = serde_json::from_value(created["request_id"].clone())
            .map_err(|_| "invalid_request_id".to_owned())?;
        Ok(format!(
            "PENDING request {request_id}; call review_request to review and authenticate on the local approval page"
        ))
    }
}

fn validate_approval_link(url: &str, request_id: Uuid) -> Result<(), String> {
    let suffix = format!("/requests/{request_id}");
    let address = url
        .strip_prefix("http://")
        .and_then(|value| value.strip_suffix(&suffix))
        .and_then(|value| value.parse::<std::net::SocketAddr>().ok())
        .ok_or("invalid_approval_link")?;
    if address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) || address.port() == 0 {
        return Err("invalid_approval_link".into());
    }
    Ok(())
}

fn reply_data(reply: Reply) -> Result<serde_json::Value, String> {
    if reply.ok {
        reply.data.ok_or_else(|| "empty_broker_reply".to_owned())
    } else {
        Err(reply.error.unwrap_or_else(|| "broker_rejected".to_owned()))
    }
}

#[tool_router]
impl Adapter {
    #[tool(
        description = "Create a pending proxy task from connection, optional connection version, exact host, and command argv. The broker checks its frozen task policy. This does not approve or execute it"
    )]
    async fn request_proxy_task(
        &self,
        Parameters(args): Parameters<ProxyTaskArgs>,
    ) -> Result<String, String> {
        self.create_proxy_task(args).await
    }

    #[tool(
        description = "Review a frozen broker task and open its authenticated local approval page through URL elicitation, or return the link for manual review. Never send a passphrase through MCP"
    )]
    async fn review_request(
        &self,
        Parameters(args): Parameters<ReviewRequestArgs>,
        client: Peer<RoleServer>,
    ) -> Result<String, String> {
        let request_id =
            Uuid::parse_str(&args.request_id).map_err(|_| "invalid_request_id".to_owned())?;
        self.review_existing_request(request_id, client).await
    }
}

#[tool_handler]
impl ServerHandler for Adapter {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Adapter {
        agent_socket: env::var_os("AVD_AGENT_SOCKET")
            .ok_or("AVD_AGENT_SOCKET is required")?
            .into(),
        elicitation_timeout: std::time::Duration::from_secs(120),
    };
    adapter
        .serve(rmcp::transport::stdio())
        .await?
        .waiting()
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use avd::{
        TaskPolicySnapshot,
        approval::ApprovalServer,
        ipc::{PeerPolicy, Server, ServerConfig},
        session::{AdminRequest, AdminServer, Session, VaultSource, admin_call},
    };
    use rmcp::{
        ClientHandler, RoleClient,
        model::{
            CallToolRequestParams, ClientCapabilities, ClientConfig, ElicitResult,
            ElicitationCapability, ErrorData, Implementation, UrlElicitationCapability,
        },
        service::RequestContext,
    };
    use serde_json::Value;
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Copy)]
    enum ClientBehavior {
        Reply,
        Error,
        NeverReply,
    }

    #[derive(Clone)]
    struct RawClient {
        action: ElicitationAction,
        content: Option<Value>,
        supports_url: bool,
        decision: Option<bool>,
        behavior: ClientBehavior,
        prompts: Arc<Mutex<Vec<String>>>,
    }
    impl ClientHandler for RawClient {
        fn get_info(&self) -> ClientConfig {
            let mut capabilities = ClientCapabilities::default();
            if self.supports_url {
                capabilities.elicitation =
                    Some(ElicitationCapability::new().with_url(UrlElicitationCapability::new()));
            }
            ClientConfig::new(
                capabilities,
                Implementation::new("synthetic-mcp-client", "0.1"),
            )
        }
        async fn create_elicitation(
            &self,
            request: ElicitRequestParams,
            _: RequestContext<RoleClient>,
        ) -> Result<ElicitResult, ErrorData> {
            if let ElicitRequestParams::UrlElicitationParams { message, url, .. } = request {
                self.prompts.lock().unwrap().push(message);
                match self.behavior {
                    ClientBehavior::Reply => (),
                    ClientBehavior::Error => {
                        return Err(ErrorData::internal_error("synthetic client failure", None));
                    }
                    ClientBehavior::NeverReply => return std::future::pending().await,
                }
                if let Some(approve) = self.decision {
                    // Simulate a separate authenticated browser action. The MCP
                    // response carries neither this passphrase nor the decision proof.
                    let client = hyper::Client::new();
                    let page = client.get(url.parse().unwrap()).await.unwrap();
                    let page = hyper::body::to_bytes(page.into_body()).await.unwrap();
                    let page = std::str::from_utf8(&page).unwrap();
                    let nonce = page
                        .split("name=\"csrf\" value=\"")
                        .nth(1)
                        .unwrap()
                        .split('"')
                        .next()
                        .unwrap();
                    let origin = url.split("/requests/").next().unwrap();
                    let request = hyper::Request::post(&url)
                        .header("Origin", origin)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .body(hyper::Body::from(format!(
                            "csrf={nonce}&passphrase=test-passphrase&decision={}",
                            if approve { "approve" } else { "deny" }
                        )))
                        .unwrap();
                    assert_eq!(
                        client.request(request).await.unwrap().status(),
                        hyper::StatusCode::OK
                    );
                }
            }
            let mut result = ElicitResult::new(self.action.clone());
            if let Some(content) = self.content.clone() {
                result = result.with_content(content);
            }
            Ok(result)
        }
    }

    async fn raw_url_case(
        action: ElicitationAction,
        content: Option<Value>,
        supports_url: bool,
        decision: Option<bool>,
        behavior: ClientBehavior,
    ) -> (String, RequestState, Vec<String>) {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");
        let created = av_core::create_vault(&vault_path, "test-passphrase").unwrap();
        created
            .vault
            .set("demo/fixture-token", "av-synthetic-approval-test")
            .unwrap();
        drop(created);
        let key = rcgen::KeyPair::generate().unwrap();
        let ca = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let ca_path = dir.path().join("provider-ca.der");
        std::fs::write(&ca_path, ca.der()).unwrap();
        let command = vec![
            "/bin/echo",
            "request",
            "--host",
            "api.example.test",
            "--path",
            "/probe",
        ];
        let policy_path = dir.path().join("policy.json");
        std::fs::write(&policy_path, serde_json::to_vec(&json!({
            "connection":"demo/fixture", "secret_name":"demo/fixture-token", "host":"api.example.test", "command":command,
            "upstream_addr":"127.0.0.1:44443", "upstream_ca_der":ca_path, "max_connects":2,"max_requests":2,"max_runtime_seconds":20,
        })).unwrap()).unwrap();
        std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let session = Session::locked(VaultSource {
            vault: vault_path,
            proxy_policy: Some(policy_path),
            service_mode: false,
        })
        .unwrap();
        let admin = AdminServer::bind(dir.path(), Arc::clone(&session))
            .await
            .unwrap();
        let admin_task = tokio::spawn(admin.run());
        let token = std::fs::read_to_string(dir.path().join("admin.token")).unwrap();
        assert!(
            admin_call(
                &dir.path().join("admin.sock"),
                &AdminRequest::Unlock {
                    token,
                    passphrase: "test-passphrase".into()
                }
            )
            .await
            .unwrap()
            .ok
        );
        let ui = ApprovalServer::bind(Arc::clone(&session), 0).await.unwrap();
        let ui_task = tokio::spawn(ui.run());
        let socket = dir.path().join("agent.sock");
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
        let server_task = tokio::spawn(server.run(std::future::pending()));
        let created = ipc::call_agent(
            &socket,
            &AgentRequest::Request {
                operation: Operation {
                    connection: "demo/fixture".into(),
                    action: "proxy.run".into(),
                    target: "api.example.test".into(),
                    arguments: json!({"command":command}),
                },
            },
        )
        .await
        .unwrap();
        let request_id: Uuid =
            serde_json::from_value(created.data.unwrap()["request_id"].clone()).unwrap();
        let adapter = Adapter {
            agent_socket: socket.clone(),
            elicitation_timeout: match behavior {
                ClientBehavior::NeverReply => std::time::Duration::from_millis(200),
                _ => std::time::Duration::from_secs(10),
            },
        };
        let (server_transport, client_transport) = tokio::io::duplex(16384);
        let mcp_task = tokio::spawn(async move {
            let _ = adapter
                .serve(server_transport)
                .await
                .unwrap()
                .waiting()
                .await;
        });
        let prompts = Arc::new(Mutex::new(Vec::new()));
        let client = RawClient {
            action,
            content,
            supports_url,
            decision,
            behavior,
            prompts: Arc::clone(&prompts),
        }
        .serve(client_transport)
        .await
        .unwrap();
        let tools = client.list_tools(Default::default()).await.unwrap();
        assert!(
            !tools
                .tools
                .iter()
                .any(|tool| tool.name == "execute_proxy_task")
        );
        let result = client
            .call_tool(
                CallToolRequestParams::new("review_request").with_arguments(
                    json!({"request_id":request_id.to_string()})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await
            .unwrap();
        let text = result.content[0].as_text().unwrap().text.clone();
        let reviewed = ipc::call_agent(&socket, &AgentRequest::Review { request_id })
            .await
            .unwrap();
        let review: Review = serde_json::from_value(reviewed.data.unwrap()).unwrap();
        let captured = prompts.lock().unwrap().clone();
        client.cancel().await.unwrap();
        mcp_task.abort();
        server_task.abort();
        admin_task.abort();
        ui_task.abort();
        session.lock().await;
        (text, review.state, captured)
    }

    #[tokio::test]
    async fn forged_url_acceptance_and_unsupported_clients_cannot_decide() {
        for (action, content, supports_url) in [
            (
                ElicitationAction::Accept,
                Some(json!({"approve":true})),
                true,
            ),
            (
                ElicitationAction::Accept,
                Some(json!({"approve":true,"extra":true})),
                true,
            ),
            (ElicitationAction::Decline, None, true),
            (ElicitationAction::Cancel, None, true),
            (ElicitationAction::Accept, None, false),
        ] {
            let (result, state, prompts) =
                raw_url_case(action, content, supports_url, None, ClientBehavior::Reply).await;
            assert!(result.starts_with("PENDING"), "{result}");
            assert_eq!(state, RequestState::Pending);
            assert_eq!(prompts.len(), usize::from(supports_url));
            assert!(!result.contains("av-synthetic-approval-test"));
            assert!(
                !prompts
                    .iter()
                    .any(|prompt| prompt.contains("av-synthetic-approval-test"))
            );
        }
    }

    #[tokio::test]
    async fn mcp_reports_only_authenticated_operator_decisions() {
        let (result, state, _) = raw_url_case(
            ElicitationAction::Accept,
            None,
            true,
            Some(true),
            ClientBehavior::Reply,
        )
        .await;
        assert!(result.starts_with("APPROVED"), "{result}");
        assert!(matches!(state, RequestState::Approved { remaining: 1, .. }));
        let (result, state, _) = raw_url_case(
            ElicitationAction::Cancel,
            None,
            true,
            Some(false),
            ClientBehavior::Reply,
        )
        .await;
        assert!(result.starts_with("DENIED"), "{result}");
        assert_eq!(state, RequestState::Denied);
    }

    #[tokio::test]
    async fn client_error_or_timeout_leaves_request_pending() {
        for behavior in [ClientBehavior::Error, ClientBehavior::NeverReply] {
            let (result, state, _) =
                raw_url_case(ElicitationAction::Accept, None, true, None, behavior).await;
            assert!(result.starts_with("PENDING"), "{result}");
            assert!(
                result.contains("CLIENT_UNAVAILABLE_OR_TIMED_OUT"),
                "{result}"
            );
            assert_eq!(state, RequestState::Pending);
        }
    }

    #[test]
    fn approval_links_cannot_redirect_to_a_remote_host_or_another_request() {
        let id = Uuid::new_v4();
        assert!(
            validate_approval_link(&format!("http://127.0.0.1:14323/requests/{id}"), id).is_ok()
        );
        for url in [
            format!("http://evil.test:14323/requests/{id}"),
            format!("http://127.0.0.1:14323/requests/{}", Uuid::new_v4()),
            format!("http://127.0.0.1:14323/requests/{id}?next=evil"),
        ] {
            assert!(validate_approval_link(&url, id).is_err());
        }
    }

    fn proxy_review(arguments: Value) -> Review {
        Review {
            id: Uuid::new_v4(),
            operation: Operation {
                connection: "fixture/cli".into(),
                action: "proxy.run".into(),
                target: "api.example.test".into(),
                arguments,
            },
            state: RequestState::Pending,
            task_policy: Some(TaskPolicySnapshot {
                host: "api.example.test".into(),
                command: vec!["fixture".into(), "--message".into(), "hello\nworld".into()],
                connection_version: None,
                max_connects: 2,
                max_requests: 3,
                max_runtime_seconds: 20,
            }),
        }
    }

    #[test]
    fn review_prompt_displays_frozen_intent_and_escapes_layout_controls() {
        let review = proxy_review(json!({"command":["fixture", "--message", "hello\nworld"]}));
        let prompt = proxy_run_prompt(&review).unwrap();
        assert!(prompt.contains(&review.id.to_string()));
        assert!(prompt.contains("[\"fixture\",\"--message\",\"hello\\nworld\"]"));
        assert!(prompt.contains("Maximum runtime: 20 seconds"));
        assert!(!prompt.contains("hello\nworld"));
        let value = "Title\u{202E}reverse\u{2066}isolate";
        let mut review = proxy_review(json!({"command":["fixture", "--message", value]}));
        review.task_policy.as_mut().unwrap().command[2] = value.into();
        let displayed = proxy_run_prompt(&review).unwrap();
        assert!(displayed.contains("\\u202E"));
        assert!(displayed.contains("\\u2066"));
    }

    #[test]
    fn review_prompt_binds_version_and_rejects_ambiguous_intent() {
        let mut review = proxy_review(json!({
            "command": ["fixture", "--message", "hello\nworld"],
            "connection_version": 3,
        }));
        review.task_policy.as_mut().unwrap().connection_version = Some(3);
        assert!(
            proxy_run_prompt(&review)
                .unwrap()
                .contains("Connection version: 3")
        );
        review.operation.arguments["connection_version"] = json!(2);
        assert_eq!(
            proxy_run_prompt(&review),
            Err("inconsistent_broker_task_policy".into())
        );
        review.operation.arguments["connection_version"] = json!(3);
        review.operation.arguments["extra"] = json!(true);
        assert_eq!(
            proxy_run_prompt(&review),
            Err("inconsistent_broker_task_policy".into())
        );
    }
}
