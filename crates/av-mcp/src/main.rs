//! MCP Apps adapter. Enrollment is authorized separately on the operator console.
use avd::{
    Operation,
    ipc::{self, AgentRequest},
};
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt, model::*, service::RequestContext};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{env, path::PathBuf, sync::Arc};
use uuid::Uuid;
use zeroize::Zeroizing;
include!(concat!(env!("OUT_DIR"), "/mcp_app.rs"));
const APP_URI: &str = "ui://agents-vault/approval.html";
const APP_MIME: &str = "text/html;profile=mcp-app";
const UI_EXTENSION: &str = "io.modelcontextprotocol/ui";
#[derive(Clone)]
struct Adapter {
    agent_socket: PathBuf,
    nonce: Arc<Zeroizing<String>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyTaskArgs {
    connection: String,
    connection_version: u64,
    host: String,
    command: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewArgs {
    request_id: Uuid,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionArgs {
    request_id: Uuid,
    review_digest: String,
    approve: bool,
}
fn supports_apps(capabilities: &ClientCapabilities) -> bool {
    capabilities
        .extensions
        .as_ref()
        .and_then(|e| e.get(UI_EXTENSION))
        .and_then(|v| v.get("mimeTypes"))
        .and_then(Value::as_array)
        .is_some_and(|types| types.iter().any(|t| t.as_str() == Some(APP_MIME)))
}
fn input<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, ErrorData> {
    serde_json::from_value(value)
        .map_err(|_| ErrorData::invalid_params("Invalid task arguments", None))
}
impl Adapter {
    async fn agent(&self, request: AgentRequest) -> Result<Value, ErrorData> {
        let reply = ipc::call_agent(&self.agent_socket, &request)
            .await
            .map_err(|_| ErrorData::internal_error("Local broker unavailable", None))?;
        if !reply.ok {
            return Err(ErrorData::invalid_request(
                "Broker refused this operation. Check enrollment, task ownership, and vault state.",
                None,
            ));
        }
        reply
            .data
            .ok_or_else(|| ErrorData::internal_error("Empty broker reply", None))
    }
    fn proof(&self) -> String {
        self.nonce.as_ref().to_string()
    }
    async fn dispatch(&self, name: &str, args: Value) -> Result<Value, ErrorData> {
        match name {
            "connect_approval" | "approval_session_status" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Empty {}
                let _: Empty = input(args)?;
                self.agent(AgentRequest::McpEnroll {
                    nonce: self.proof(),
                })
                .await
            }
            "request_proxy_task" => {
                let args: ProxyTaskArgs = input(args)?;
                let operation = Operation {
                    connection: args.connection,
                    action: "proxy.run".into(),
                    target: args.host,
                    arguments: json!({"command":args.command,"connection_version":args.connection_version}),
                };
                self.agent(AgentRequest::McpRequest {
                    nonce: self.proof(),
                    operation,
                })
                .await
            }
            "review_request" => {
                let args: ReviewArgs = input(args)?;
                self.agent(AgentRequest::McpReview {
                    nonce: self.proof(),
                    request_id: args.request_id,
                })
                .await
            }
            "decide_task" => {
                let args: DecisionArgs = input(args)?;
                self.agent(AgentRequest::McpDecide {
                    nonce: self.proof(),
                    request_id: args.request_id,
                    review_digest: args.review_digest,
                    approve: args.approve,
                })
                .await
            }
            _ => Err(ErrorData::invalid_params("Unknown tool", None)),
        }
    }
}
fn tool(name: &str, description: &str, properties: Value, required: Value, app_only: bool) -> Tool {
    serde_json::from_value(json!({"name":name,"description":description,
        "inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},
        "_meta":{"ui":{"resourceUri":APP_URI,"visibility":if app_only {json!(["app"])} else {json!(["model","app"])}}}})).unwrap()
}
impl ServerHandler for Adapter {
    fn get_info(&self) -> ServerConfig {
        let extensions =
            serde_json::from_value(json!({UI_EXTENSION:{"mimeTypes":[APP_MIME]}})).unwrap();
        let mut info = ServerConfig::default();
        info.capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_resources()
            .enable_extensions_with(extensions)
            .build();
        info.server_info = Implementation::new("agents-vault", env!("CARGO_PKG_VERSION"));
        info
    }
    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        if !supports_apps(&request.capabilities) {
            return Err(ErrorData::invalid_request(
                "MCP Apps support is required. Approval has no chat or URL fallback.",
                None,
            ));
        }
        if APP_HTML.is_empty() {
            return Err(ErrorData::internal_error(
                "MCP App assets are missing. Build the web bundle before av-mcp.",
                None,
            ));
        }
        context.peer.set_peer_info(request.clone());
        self.negotiate_initialize(&request)
    }
    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let review = json!({"request_id":{"type":"string","format":"uuid"}});
        Ok(ListToolsResult::with_all_items(vec![
            tool(
                "connect_approval",
                "Show the MCP App session ID. Authorize this exact session in the local operator console before requesting approvals. Never send vault passwords through MCP.",
                json!({}),
                json!([]),
                false,
            ),
            tool(
                "request_proxy_task",
                "Request a frozen task. Its MCP App lets the operator approve or deny one execution attempt. Does not execute the command.",
                json!({"connection":{"type":"string"},"connection_version":{"type":"integer","minimum":1},"host":{"type":"string"},"command":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":32}}),
                json!(["connection", "connection_version", "host", "command"]),
                false,
            ),
            tool(
                "review_request",
                "Review a task owned by this enrolled MCP session. Only tasks created through this adapter session can be reviewed.",
                review.clone(),
                json!(["request_id"]),
                false,
            ),
            tool(
                "approval_session_status",
                "Refresh MCP enrollment status from the App.",
                json!({}),
                json!([]),
                true,
            ),
            tool(
                "decide_task",
                "Submit an operator decision for the exact displayed task. Requires an enrolled harness session and matching frozen review digest.",
                json!({"request_id":{"type":"string","format":"uuid"},"review_digest":{"type":"string","minLength":64,"maxLength":64},"approve":{"type":"boolean"}}),
                json!(["request_id", "review_digest", "approve"]),
                true,
            ),
        ]))
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if !context
            .peer
            .peer_info()
            .is_some_and(|p| supports_apps(&p.capabilities))
        {
            return Err(ErrorData::invalid_request(
                "MCP Apps support is required",
                None,
            ));
        }
        let args = Value::Object(request.arguments.unwrap_or_default());
        let data = self.dispatch(&request.name, args).await;
        match data {
            Ok(data) => {
                let mut result = CallToolResult::success(vec![ContentBlock::text(
                    if data.get("review").is_some() {
                        "Review the frozen task in the MCP App. Approval does not execute it."
                    } else {
                        "Authorize this exact MCP session in the local operator console, then refresh the App."
                    },
                )]);
                result.structured_content = Some(data);
                Ok(result.into())
            }
            Err(error) => Ok(CallToolResult::error(vec![ContentBlock::text(error.message)]).into()),
        }
    }
    async fn list_resources(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(vec![
            Resource::new(APP_URI, "Task approval").with_mime_type(APP_MIME),
        ]))
    }
    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        if request.uri != APP_URI || APP_HTML.is_empty() {
            return Err(ErrorData::invalid_params("Unknown App resource", None));
        }
        serde_json::from_value::<ReadResourceResult>(json!({"contents":[{"uri":APP_URI,"mimeType":APP_MIME,"text":APP_HTML,"_meta":{"ui":{"csp":{"connectDomains":[],"resourceDomains":[]},"permissions":{},"prefersBorder":true}}}]})).map(Into::into).map_err(|_| ErrorData::internal_error("Invalid App resource", None))
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use rand::RngCore;
    let mut nonce = [0; 32];
    rand::rng().fill_bytes(&mut nonce);
    let adapter = Adapter {
        agent_socket: env::var_os("AVD_AGENT_SOCKET")
            .ok_or("AVD_AGENT_SOCKET is required")?
            .into(),
        nonce: Arc::new(Zeroizing::new(hex::encode(nonce))),
    };
    adapter
        .serve(rmcp::transport::stdio())
        .await?
        .waiting()
        .await?;
    Ok(())
}
#[cfg(test)]
mod tests;
