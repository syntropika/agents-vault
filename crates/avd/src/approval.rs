//! Local operator approval UI. MCP receives a review link, never the passphrase.

use crate::{RequestState, Review, session::Session};
use hyper::{Body, Method, Request, Response, StatusCode, body::HttpBody, service::service_fn};
use rand::RngCore;
use serde_json::json;
use std::{
    collections::HashMap,
    convert::Infallible,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::Semaphore};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const APPROVAL_PORT: u16 = 14323;
const MAX_BODY: usize = 8192;
const MAX_FORMS: usize = 256;
const FORM_LIFETIME: Duration = Duration::from_secs(120);
const GRANT_LIFETIME: u64 = 60;

struct Form {
    request_id: Uuid,
    deadline: Instant,
}
struct State {
    session: Arc<Session>,
    address: SocketAddr,
    forms: Mutex<HashMap<String, Form>>,
    next_attempt: Mutex<Instant>,
    operator: crate::operator_web::OperatorWeb,
}

pub struct ApprovalServer {
    listener: TcpListener,
    state: Arc<State>,
}

impl ApprovalServer {
    /// The installed daemon uses APPROVAL_PORT. A zero port is useful for tests.
    /// Binding precedes publishing the URL; an occupied port fails startup.
    pub async fn bind(session: Arc<Session>, port: u16) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        let address = listener.local_addr()?;
        session.enable_approval_ui(address)?;
        Ok(Self {
            listener,
            state: Arc::new(State {
                session,
                address,
                forms: Mutex::new(HashMap::new()),
                next_attempt: Mutex::new(Instant::now()),
                operator: crate::operator_web::OperatorWeb::new(),
            }),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.state.address
    }

    pub async fn run(self) -> io::Result<()> {
        let slots = Arc::new(Semaphore::new(16));
        let mut handlers = tokio::task::JoinSet::new();
        let mut cleanup = tokio::time::interval(Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = cleanup.tick() => self.state.operator.prune(self.state.session.web_epoch()),
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted?;
                    let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else { continue; };
                    let state = Arc::clone(&self.state);
                    handlers.spawn(async move {
                        let _permit = permit;
                        let service = service_fn(move |request| handle(Arc::clone(&state), request));
                        let _ = tokio::time::timeout(Duration::from_secs(10),
                            hyper::server::conn::Http::new().http1_only(true)
                                .http1_keep_alive(false).serve_connection(stream, service)).await;
                    });
                }
                joined = handlers.join_next(), if !handlers.is_empty() => { let _ = joined; }
            }
        }
    }
}

fn response(status: StatusCode, body: impl Into<Body>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("Referrer-Policy", "no-referrer")
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        )
        .body(body.into())
        .expect("static response headers")
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&#39;")
}

async fn handle(state: Arc<State>, request: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(dispatch(state, request).await)
}

async fn dispatch(state: Arc<State>, mut request: Request<Body>) -> Response<Body> {
    let host = state.address.to_string();
    if request.headers().get_all("host").iter().count() != 1
        || request
            .headers()
            .get("host")
            .and_then(|value| value.to_str().ok())
            != Some(host.as_str())
        || request.uri().query().is_some()
    {
        return response(StatusCode::FORBIDDEN, "Invalid approval origin.");
    }
    if request.uri().path().starts_with("/api/operator/")
        || request.uri().path() == "/"
        || request.uri().path().starts_with("/assets/")
    {
        return state
            .operator
            .handle(&state.session, state.address, request)
            .await;
    }
    let Some(id) = request
        .uri()
        .path()
        .strip_prefix("/requests/")
        .and_then(|id| Uuid::parse_str(id).ok())
    else {
        return response(
            StatusCode::NOT_FOUND,
            "An approval request link is required.",
        );
    };
    if request.method() == Method::GET {
        let broker = state.session.broker.read().await;
        let Some(broker) = broker.as_ref() else {
            return response(StatusCode::LOCKED, "Vault is locked.");
        };
        let Ok(review) = broker.review(id) else {
            return response(StatusCode::NOT_FOUND, "Unknown request.");
        };
        let Ok(prompt) = review_prompt(&review) else {
            return response(StatusCode::BAD_REQUEST, "Unsupported request.");
        };
        let heading = format!(
            "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Agents Vault approval</title><h1>Review task</h1><pre>{}</pre>",
            escape(&prompt)
        );
        if review.state != RequestState::Pending {
            return response(
                StatusCode::OK,
                format!("{heading}<p>This request is already decided or consumed.</p></html>"),
            );
        }
        let nonce = {
            let mut forms = state.forms.lock().expect("forms mutex poisoned");
            forms.retain(|_, form| form.deadline > Instant::now());
            if forms.len() >= MAX_FORMS {
                return response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many open approval forms.",
                );
            }
            let mut bytes = [0_u8; 32];
            rand::rng().fill_bytes(&mut bytes);
            let nonce = hex::encode(bytes);
            forms.insert(
                nonce.clone(),
                Form {
                    request_id: id,
                    deadline: Instant::now() + FORM_LIFETIME,
                },
            );
            nonce
        };
        return response(
            StatusCode::OK,
            format!(
                "{heading}<p>Enter the vault passphrase here. It is sent directly to the local broker, never through MCP. Approval allows one execution attempt within 60 seconds.</p><form method=\"post\" action=\"/requests/{id}\"><input type=\"hidden\" name=\"csrf\" value=\"{nonce}\"><label>Vault passphrase <input type=\"password\" name=\"passphrase\" required maxlength=\"4096\" autocomplete=\"off\"></label><button name=\"decision\" value=\"approve\">Approve</button><button name=\"decision\" value=\"deny\">Deny</button></form></html>"
            ),
        );
    }
    if request.method() != Method::POST {
        return response(StatusCode::METHOD_NOT_ALLOWED, "Use the approval form.");
    }
    let origin = format!("http://{host}");
    if request.headers().get_all("origin").iter().count() != 1
        || request
            .headers()
            .get("origin")
            .and_then(|value| value.to_str().ok())
            != Some(origin.as_str())
        || request
            .headers()
            .get("sec-fetch-site")
            .is_some_and(|value| value == "cross-site")
        || request.headers().get_all("content-type").iter().count() != 1
        || request
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            != Some("application/x-www-form-urlencoded")
    {
        return response(StatusCode::FORBIDDEN, "Invalid approval origin or form.");
    }
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = request.body_mut().data().await {
        let Ok(chunk) = chunk else {
            return response(StatusCode::BAD_REQUEST, "Invalid form.");
        };
        if body.len().saturating_add(chunk.len()) > MAX_BODY {
            return response(StatusCode::PAYLOAD_TOO_LARGE, "Form is too large.");
        }
        body.extend_from_slice(&chunk);
    }
    let Some(mut fields) = parse_form(&body) else {
        return response(StatusCode::BAD_REQUEST, "Invalid form.");
    };
    let nonce = fields.remove("csrf").expect("validated form");
    let passphrase = fields.remove("passphrase").expect("validated form");
    let decision = fields.remove("decision").expect("validated form");
    if !matches!(decision.as_str(), "approve" | "deny")
        || passphrase.is_empty()
        || passphrase.len() > 4096
    {
        return response(StatusCode::BAD_REQUEST, "Invalid decision or passphrase.");
    }
    let form = state
        .forms
        .lock()
        .expect("forms mutex poisoned")
        .remove(nonce.as_str());
    if !form.is_some_and(|form| form.request_id == id && form.deadline > Instant::now()) {
        return response(
            StatusCode::FORBIDDEN,
            "Approval form expired or already used. Reload the request.",
        );
    }
    {
        let mut next = state.next_attempt.lock().expect("attempt mutex poisoned");
        if *next > Instant::now() {
            return response(
                StatusCode::TOO_MANY_REQUESTS,
                "Wait before trying another decision, then reload the request.",
            );
        }
        *next = Instant::now() + Duration::from_secs(1);
    }
    match state
        .session
        .decide(
            &passphrase,
            id,
            decision.as_str() == "approve",
            GRANT_LIFETIME,
        )
        .await
    {
        Ok(_) => response(
            StatusCode::OK,
            if decision.as_str() == "approve" {
                "Request approved. Return to the client and resume this exact request."
            } else {
                "Request denied. The command cannot start."
            },
        ),
        Err(_) => response(
            StatusCode::UNAUTHORIZED,
            "Decision rejected. Check the passphrase and request state, then reload the request.",
        ),
    }
}

fn parse_form(body: &[u8]) -> Option<HashMap<String, Zeroizing<String>>> {
    let mut fields = HashMap::new();
    for pair in body.split(|byte| *byte == b'&') {
        let equal = pair.iter().position(|byte| *byte == b'=')?;
        let key = decode(&pair[..equal])?;
        if !matches!(key.as_str(), "csrf" | "passphrase" | "decision")
            || fields.contains_key(key.as_str())
        {
            return None;
        }
        fields.insert(key.to_string(), decode(&pair[equal + 1..])?);
    }
    (fields.len() == 3).then_some(fields)
}

fn decode(bytes: &[u8]) -> Option<Zeroizing<String>> {
    let mut output = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => output.push(b' '),
            b'%' => {
                let high = (*bytes.get(index + 1)? as char).to_digit(16)?;
                let low = (*bytes.get(index + 2)? as char).to_digit(16)?;
                output.push((high * 16 + low) as u8);
                index += 2;
            }
            byte => output.push(byte),
        }
        index += 1;
    }
    Some(Zeroizing::new(
        std::str::from_utf8(&output).ok()?.to_owned(),
    ))
}

pub fn review_prompt(review: &Review) -> Result<String, String> {
    let operation = &review.operation;
    if operation.action != "proxy.run"
        || operation.connection.is_empty()
        || operation.target.is_empty()
    {
        return Err("unsupported_broker_intent".into());
    }
    let arguments = operation
        .arguments
        .as_object()
        .ok_or("invalid_broker_intent")?;
    let command = arguments
        .get("command")
        .and_then(|command| command.as_array())
        .filter(|command| !command.is_empty() && command.iter().all(|arg| arg.as_str().is_some()))
        .ok_or("invalid_broker_intent")?;
    if command[0].as_str() == Some("") {
        return Err("invalid_broker_intent".into());
    }
    let policy = review
        .task_policy
        .as_ref()
        .ok_or("missing_broker_task_policy")?;
    let version_matches = match policy.connection_version {
        Some(version) => {
            version > 0
                && arguments.len() == 2
                && arguments.get("connection_version") == Some(&json!(version))
        }
        None => arguments.len() == 1,
    };
    if !operation.target.eq_ignore_ascii_case(&policy.host)
        || !version_matches
        || command
            .iter()
            .map(|arg| arg.as_str().unwrap())
            .collect::<Vec<_>>()
            != policy
                .command
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        || policy.max_connects == 0
        || policy.max_requests == 0
        || policy.max_runtime_seconds == 0
    {
        return Err("inconsistent_broker_task_policy".into());
    }
    // JSON escaping keeps control characters in broker-owned fields from
    // changing the visual structure of the approval prompt.
    Ok(format!(
        "Review this frozen proxy task?\nRequest ID: {}\nConnection: {}\nConnection version: {}\nAction: {}\nTarget host: {}\nCommand argv: {}\nMaximum CONNECT tunnels: {}\nMaximum HTTP requests: {}\nMaximum runtime: {} seconds",
        review.id,
        json_string(&operation.connection)?,
        policy
            .connection_version
            .map_or_else(|| "none".to_owned(), |version| version.to_string()),
        json_string(&operation.action)?,
        json_string(&policy.host)?,
        json_string(command)?,
        policy.max_connects,
        policy.max_requests,
        policy.max_runtime_seconds,
    ))
}

fn json_string<T: serde::Serialize>(value: T) -> Result<String, String> {
    use std::fmt::Write as _;

    let serialized = serde_json::to_string(&value).map_err(|_| "invalid_broker_intent")?;
    let mut visible = String::with_capacity(serialized.len());
    for character in serialized.chars() {
        if character.is_ascii() {
            visible.push(character);
        } else {
            // Keep the displayed JSON parseable while preventing Unicode layout
            // controls from changing how a human sees the approval request.
            let mut units = [0_u16; 2];
            for unit in character.encode_utf16(&mut units) {
                write!(&mut visible, "\\u{unit:04X}").expect("writing to String cannot fail");
            }
        }
    }
    Ok(visible)
}
