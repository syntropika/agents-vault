//! Loopback operator sessions. Passwords and capabilities never enter MCP.
use crate::{management::ManagementOperation, session::Session};
use hyper::{Body, Method, Request, Response, StatusCode, body::HttpBody};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

mod assets {
    include!(concat!(env!("OUT_DIR"), "/web_assets.rs"));
}
const LIFETIME: Duration = Duration::from_secs(900);
const MAX_BODY: usize = 16_384;
struct Login {
    csrf: String,
    deadline: Instant,
}
struct Operator {
    epoch: u64,
    csrf: String,
    passphrase: Zeroizing<String>,
    deadline: Instant,
}
pub(crate) struct OperatorWeb {
    logins: Mutex<HashMap<String, Login>>,
    sessions: Mutex<HashMap<String, Operator>>,
    next_auth: Mutex<Instant>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Password {
    passphrase: String,
}
impl Drop for Password {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    request_id: uuid::Uuid,
    approve: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    pairing_id: uuid::Uuid,
    approve: bool,
}

fn random() -> String {
    let mut bytes = [0; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
fn reply(status: StatusCode, body: Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store")
        .header("Referrer-Policy", "no-referrer")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(body.to_string()))
        .unwrap()
}
fn failure(status: StatusCode, code: &str) -> Response<Body> {
    reply(status, json!({"error":code}))
}
fn cookie(request: &Request<Body>, name: &str) -> Option<String> {
    if request.headers().get_all("cookie").iter().count() != 1 {
        return None;
    }
    let mut found = None;
    for item in request.headers().get("cookie")?.to_str().ok()?.split(';') {
        let (key, value) = item.trim().split_once('=')?;
        if key == name {
            if found.is_some() {
                return None;
            }
            found = Some(value.to_owned());
        }
    }
    found
}
fn csrf(request: &Request<Body>, expected: &str) -> bool {
    request.headers().get_all("x-av-csrf").iter().count() == 1
        && request
            .headers()
            .get("x-av-csrf")
            .and_then(|v| v.to_str().ok())
            == Some(expected)
}
async fn body(request: &mut Request<Body>) -> Result<Zeroizing<Vec<u8>>, StatusCode> {
    if request.headers().get_all("content-type").iter().count() != 1
        || request
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            != Some("application/json")
    {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = request.body_mut().data().await {
        let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
        if bytes.len().saturating_add(chunk.len()) > MAX_BODY {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
fn with_cookie(mut response: Response<Body>, name: &str, token: &str, age: u64) -> Response<Body> {
    response.headers_mut().insert(
        "set-cookie",
        format!("{name}={token}; HttpOnly; SameSite=Strict; Path=/api/operator/; Max-Age={age}")
            .parse()
            .unwrap(),
    );
    response
}
impl OperatorWeb {
    pub(crate) fn new() -> Self {
        Self {
            logins: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            next_auth: Mutex::new(Instant::now()),
        }
    }
    pub(crate) fn prune(&self, epoch: u64) {
        let now = Instant::now();
        self.logins
            .lock()
            .unwrap()
            .retain(|_, login| login.deadline > now);
        self.sessions
            .lock()
            .unwrap()
            .retain(|_, operator| operator.deadline > now && operator.epoch == epoch);
    }

    pub(crate) async fn handle(
        &self,
        session: &Session,
        address: SocketAddr,
        mut request: Request<Body>,
    ) -> Response<Body> {
        let path = request.uri().path().to_owned();
        if path == "/" || path.starts_with("/assets/") {
            if request.method() != Method::GET {
                return failure(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
            }
            let name = if path == "/" { "/index.html" } else { &path };
            let Some((bytes, mime)) = assets::asset(name) else {
                return failure(StatusCode::SERVICE_UNAVAILABLE, "web_assets_unavailable");
            };
            return Response::builder().status(StatusCode::OK).header("Content-Type",mime)
                .header("Cache-Control","no-store").header("X-Content-Type-Options","nosniff")
                .header("Referrer-Policy","no-referrer").header("X-Frame-Options","DENY")
                .header("Content-Security-Policy","default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
                .body(Body::from(bytes)).unwrap();
        }
        let origin = format!("http://{address}");
        if request
            .headers()
            .get("sec-fetch-site")
            .is_some_and(|v| v == "cross-site")
        {
            return failure(StatusCode::FORBIDDEN, "invalid_origin");
        }
        if request.method() != Method::GET
            && (request.headers().get_all("origin").iter().count() != 1
                || request
                    .headers()
                    .get("origin")
                    .and_then(|v| v.to_str().ok())
                    != Some(origin.as_str()))
        {
            return failure(StatusCode::FORBIDDEN, "invalid_origin");
        }
        let now = Instant::now();
        let epoch = session.web_epoch();
        if path == "/api/operator/bootstrap" && request.method() == Method::GET {
            let token = random();
            let csrf = random();
            let mut logins = self.logins.lock().unwrap();
            logins.retain(|_, v| v.deadline > now);
            if logins.len() >= 32 {
                return failure(StatusCode::TOO_MANY_REQUESTS, "too_many_sessions");
            }
            logins.insert(
                token.clone(),
                Login {
                    csrf: csrf.clone(),
                    deadline: now + Duration::from_secs(120),
                },
            );
            return with_cookie(
                reply(
                    StatusCode::OK,
                    json!({"csrf":csrf,"backend":"sqlcipher","service_mode":session.source.as_ref().is_some_and(|s|s.service_mode)}),
                ),
                "av_login",
                &token,
                120,
            );
        }
        if path == "/api/operator/session" && request.method() == Method::POST {
            let Some(token) = cookie(&request, "av_login") else {
                return failure(StatusCode::FORBIDDEN, "login_required");
            };
            {
                let mut logins = self.logins.lock().unwrap();
                let Some(login) = logins.remove(&token) else {
                    return failure(StatusCode::FORBIDDEN, "login_expired");
                };
                if login.deadline <= now || !csrf(&request, &login.csrf) {
                    return failure(StatusCode::FORBIDDEN, "invalid_csrf");
                }
            }
            {
                let mut gate = self.next_auth.lock().unwrap();
                if *gate > now {
                    return failure(StatusCode::TOO_MANY_REQUESTS, "authentication_throttled");
                }
                *gate = now + Duration::from_secs(1);
            }
            let bytes = match body(&mut request).await {
                Ok(b) => b,
                Err(s) => return failure(s, "invalid_body"),
            };
            let Ok(password) = serde_json::from_slice::<Password>(&bytes) else {
                return failure(StatusCode::BAD_REQUEST, "invalid_body");
            };
            if session
                .web_authenticate(&password.passphrase)
                .await
                .is_err()
            {
                return failure(StatusCode::UNAUTHORIZED, "authentication_failed");
            }
            if session.web_epoch() != epoch {
                return failure(StatusCode::UNAUTHORIZED, "session_changed");
            }
            let token = random();
            let csrf = random();
            let mut sessions = self.sessions.lock().unwrap();
            sessions.retain(|_, v| v.deadline > Instant::now());
            if sessions.len() >= 8 {
                return failure(StatusCode::TOO_MANY_REQUESTS, "too_many_sessions");
            }
            sessions.insert(
                token.clone(),
                Operator {
                    epoch,
                    csrf: csrf.clone(),
                    passphrase: Zeroizing::new(password.passphrase.clone()),
                    deadline: Instant::now() + LIFETIME,
                },
            );
            return with_cookie(
                reply(StatusCode::OK, json!({"csrf":csrf,"expires_in":900})),
                "av_operator",
                &token,
                900,
            );
        }
        let Some(token) = cookie(&request, "av_operator") else {
            return failure(StatusCode::UNAUTHORIZED, "session_required");
        };
        let (passphrase, operator_epoch) = {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.retain(|_, v| v.deadline > now);
            let Some(operator) = sessions.get(&token) else {
                return failure(StatusCode::UNAUTHORIZED, "session_expired");
            };
            if operator.epoch != session.web_epoch() {
                return failure(StatusCode::UNAUTHORIZED, "session_changed");
            }
            if !csrf(&request, &operator.csrf) {
                return failure(StatusCode::FORBIDDEN, "invalid_csrf");
            }
            (operator.passphrase.clone(), operator.epoch)
        };
        match (request.method(), path.as_str()) {
            (&Method::GET, "/api/operator/status") => reply(
                StatusCode::OK,
                json!({"locked":session.is_locked().await,"backend":"sqlcipher","service_mode":session.source.as_ref().is_some_and(|s|s.service_mode)}),
            ),
            (&Method::POST, "/api/operator/logout") => {
                self.sessions.lock().unwrap().remove(&token);
                with_cookie(
                    reply(StatusCode::OK, json!({"ok":true})),
                    "av_operator",
                    "",
                    0,
                )
            }
            (&Method::POST, "/api/operator/manage") => {
                let bytes = match body(&mut request).await {
                    Ok(b) => b,
                    Err(s) => return failure(s, "invalid_body"),
                };
                let Ok(operation) = serde_json::from_slice::<ManagementOperation>(&bytes) else {
                    return failure(StatusCode::BAD_REQUEST, "invalid_operation");
                };
                if !matches!(
                    operation,
                    ManagementOperation::TaskShow
                        | ManagementOperation::TaskSave { .. }
                        | ManagementOperation::ConnectAdd { .. }
                        | ManagementOperation::ConnectList
                        | ManagementOperation::ConnectShow { .. }
                        | ManagementOperation::ConnectReplace { .. }
                        | ManagementOperation::ConnectDisconnect { .. }
                        | ManagementOperation::ConnectRevoke { .. }
                        | ManagementOperation::ConnectGrant { .. }
                ) {
                    return failure(StatusCode::BAD_REQUEST, "unsupported_operation");
                }
                match session
                    .web_manage(&passphrase, operation, operator_epoch)
                    .await
                {
                    Ok(value) => reply(StatusCode::OK, value),
                    Err(_) => failure(StatusCode::CONFLICT, "management_refused"),
                }
            }
            (&Method::GET, "/api/operator/mcp") => {
                let _gate = session.broker.read().await;
                if session.web_epoch() != operator_epoch {
                    return failure(StatusCode::UNAUTHORIZED, "session_changed");
                }
                reply(StatusCode::OK, session.mcp.list(operator_epoch))
            }
            (&Method::POST, "/api/operator/mcp") => {
                let bytes = match body(&mut request).await {
                    Ok(b) => b,
                    Err(s) => return failure(s, "invalid_body"),
                };
                let Ok(enrollment) = serde_json::from_slice::<Enrollment>(&bytes) else {
                    return failure(StatusCode::BAD_REQUEST, "invalid_body");
                };
                let gate = session.broker.read().await;
                if gate.is_none() || session.web_epoch() != operator_epoch {
                    return failure(StatusCode::CONFLICT, "mcp_enrollment_refused");
                }
                match session.mcp.authorize(
                    enrollment.pairing_id,
                    enrollment.approve,
                    operator_epoch,
                ) {
                    Ok(()) => reply(StatusCode::OK, json!({"ok":true})),
                    Err(_) => failure(StatusCode::CONFLICT, "mcp_enrollment_refused"),
                }
            }
            (&Method::GET, "/api/operator/requests") => {
                let broker = session.broker.read().await;
                match broker.as_ref().map(|b| b.web_reviews()) {
                    Some(Ok(requests)) => reply(StatusCode::OK, json!({"requests":requests})),
                    _ => reply(StatusCode::OK, json!({"requests":[]})),
                }
            }
            (&Method::POST, "/api/operator/decide") => {
                let bytes = match body(&mut request).await {
                    Ok(b) => b,
                    Err(s) => return failure(s, "invalid_body"),
                };
                let Ok(decision) = serde_json::from_slice::<Decision>(&bytes) else {
                    return failure(StatusCode::BAD_REQUEST, "invalid_decision");
                };
                match session
                    .web_decide(
                        &passphrase,
                        decision.request_id,
                        decision.approve,
                        operator_epoch,
                    )
                    .await
                {
                    Ok(state) => reply(StatusCode::OK, json!({"state":state})),
                    Err(_) => failure(StatusCode::CONFLICT, "decision_refused"),
                }
            }
            (&Method::POST, "/api/operator/unlock") => {
                match session.web_unlock(&passphrase, operator_epoch).await {
                    Ok(()) => reply(StatusCode::OK, json!({"ok":true})),
                    Err(_) => failure(StatusCode::CONFLICT, "unlock_refused"),
                }
            }
            (&Method::POST, "/api/operator/lock") => {
                session.lock().await;
                self.sessions.lock().unwrap().clear();
                with_cookie(
                    reply(StatusCode::OK, json!({"ok":true})),
                    "av_operator",
                    "",
                    0,
                )
            }
            _ => failure(StatusCode::NOT_FOUND, "not_found"),
        }
    }
}
