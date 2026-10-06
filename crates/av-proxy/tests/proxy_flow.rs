use av_proxy::{
    CredentialInjection, MAX_ADMITTED_REQUEST_BODY_BYTES, MAX_ADMITTED_RESPONSE_BODY_BYTES,
    ProtectedRequestGate, ProtectedRequestPermit, ProxyConfig, ProxyHub, ProxyServer,
    RequestAdmission, RoundTripAdmission, TaskGrant,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hyper::body::{Bytes, HttpBody};
use hyper::header::{
    ACCEPT_ENCODING, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION, TRANSFER_ENCODING,
};
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, StatusCode};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::convert::Infallible;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const HOSTNAME: &str = "api.example.test";
const GRANT: &str = "example-task-grant";
const CREDENTIAL: &str = "Bearer fake-provider-credential";

struct Certificates {
    ca: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    leaf_key: PrivateKeyDer<'static>,
}

fn certificates() -> Certificates {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_params = CertificateParams::new(vec![HOSTNAME.to_string()]).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
    Certificates {
        ca: ca.der().clone(),
        leaf: leaf.der().clone(),
        leaf_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    }
}

fn server_config(certificates: &Certificates) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificates.leaf.clone()],
            certificates.leaf_key.clone_key(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

fn client_config(ca: &CertificateDer<'static>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

struct Rig {
    proxy: SocketAddr,
    ca: CertificateDer<'static>,
    received: mpsc::UnboundedReceiver<String>,
    received_headers: mpsc::UnboundedReceiver<hyper::HeaderMap>,
    upstream_accepted: mpsc::UnboundedReceiver<()>,
    proxy_task: JoinHandle<()>,
    provider_task: JoinHandle<()>,
}

#[derive(Clone, Copy)]
enum ProviderReply {
    Ok,
    ReflectAuthorization,
    ReflectAuthorizationAndHeaders,
    InvalidBody,
    OversizedBody,
    OversizedHeaders,
    DelayedBody,
    DeclaredTrailer,
    RedirectOffHost,
    StalledResponse,
    StalledBody,
}

#[derive(Default)]
struct GateState {
    revoked: bool,
    admitted: usize,
    active: usize,
    write_polls: usize,
}

struct TestGate {
    state: Arc<Mutex<GateState>>,
    revoked: watch::Sender<bool>,
    active: watch::Sender<usize>,
    deadline: Instant,
}

impl TestGate {
    fn new(deadline: Instant) -> Arc<Self> {
        let (revoked, _) = watch::channel(false);
        let (active, _) = watch::channel(0);
        Arc::new(Self {
            state: Arc::new(Mutex::new(GateState::default())),
            revoked,
            active,
            deadline,
        })
    }

    async fn revoke_and_wait(&self) {
        {
            let mut state = self.state.lock().unwrap();
            state.revoked = true;
            self.revoked.send_replace(true);
        }
        self.wait_drained().await;
    }

    async fn wait_drained(&self) {
        let mut active = self.active.subscribe();
        active.wait_for(|count| *count == 0).await.unwrap();
    }
}

impl ProtectedRequestGate for TestGate {
    fn begin(&self, exact_host: &str) -> Option<Box<dyn ProtectedRequestPermit>> {
        assert_eq!(exact_host, HOSTNAME);
        let mut state = self.state.lock().unwrap();
        if state.revoked || Instant::now() >= self.deadline {
            return None;
        }
        state.admitted += 1;
        state.active += 1;
        self.active.send_replace(state.active);
        Some(Box::new(TestPermit {
            state: Arc::clone(&self.state),
            revoked: self.revoked.subscribe(),
            active: self.active.clone(),
            deadline: self.deadline,
        }))
    }
}

struct TestPermit {
    state: Arc<Mutex<GateState>>,
    revoked: watch::Receiver<bool>,
    active: watch::Sender<usize>,
    deadline: Instant,
}

impl Drop for TestPermit {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap();
        state.active -= 1;
        self.active.send_replace(state.active);
    }
}

impl ProtectedRequestPermit for TestPermit {
    fn deadline(&self) -> Instant {
        self.deadline
    }

    fn cancelled(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let mut revoked = self.revoked.clone();
        Box::pin(async move {
            let _ = revoked.wait_for(|value| *value).await;
        })
    }

    fn with_write_barrier(&self, operation: &mut dyn FnMut()) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.revoked || Instant::now() >= self.deadline {
            return false;
        }
        state.write_polls += 1;
        operation();
        true
    }
}

const FIRST_BODY: &[u8] = br#"{"operation":"repositoryInfo"}"#;
const SECOND_BODY: &[u8] = br#"{"operation":"issueCreate"}"#;

#[derive(Default)]
struct OrderedAdmission {
    next: Mutex<usize>,
}

impl RequestAdmission for OrderedAdmission {
    fn admit(&self, request: &Request<Bytes>) -> bool {
        if request.method() != Method::POST
            || request.uri().to_string() != "/graphql"
            || request.headers().get_all(CONTENT_TYPE).iter().count() != 1
            || request.headers().get(CONTENT_TYPE).unwrap() != "application/json"
        {
            return false;
        }
        let mut next = self.next.lock().unwrap();
        let expected = match *next {
            0 => FIRST_BODY,
            1 => SECOND_BODY,
            _ => return false,
        };
        if request.body().as_ref() != expected {
            return false;
        }
        *next += 1;
        true
    }
}

#[derive(Default)]
struct SafeRoundTrip {
    state: Mutex<(u8, usize)>,
}

impl RoundTripAdmission for SafeRoundTrip {
    fn admit_request(&self, request: &Request<Bytes>) -> bool {
        if request.method() != Method::POST
            || request.uri().to_string() != "/graphql"
            || request.headers().get(CONTENT_TYPE) != Some(&"application/json".parse().unwrap())
            || request.body().as_ref() != FIRST_BODY
        {
            return false;
        }
        let mut state = self.state.lock().unwrap();
        if state.0 != 0 {
            return false;
        }
        state.0 = 1;
        true
    }

    fn review_response(
        &self,
        request: &Request<Bytes>,
        upstream: &Response<Bytes>,
    ) -> Option<Response<Bytes>> {
        assert_eq!(request.body().as_ref(), FIRST_BODY);
        let mut state = self.state.lock().unwrap();
        state.1 += 1;
        if state.0 != 1
            || upstream.status() != StatusCode::OK
            || upstream.body().as_ref() != b"ok"
            || upstream.headers().contains_key("x-reflected-authorization")
        {
            return None;
        }
        state.0 = 2;
        Some(
            Response::builder()
                .status(StatusCode::ACCEPTED)
                .header(CONTENT_TYPE, "application/json")
                .header("x-sanitized", "yes")
                .header("content-length", "999")
                .body(Bytes::from_static(br#"{"accepted":true}"#))
                .unwrap(),
        )
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.proxy_task.abort();
        self.provider_task.abort();
    }
}

async fn start_rig(
    expires_at: SystemTime,
    max_connects: u32,
    max_requests: u32,
    trust_upstream: bool,
) -> Rig {
    start_rig_with_reply(
        expires_at,
        max_connects,
        max_requests,
        trust_upstream,
        ProviderReply::Ok,
    )
    .await
}

async fn start_rig_with_reply(
    expires_at: SystemTime,
    max_connects: u32,
    max_requests: u32,
    trust_upstream: bool,
    reply: ProviderReply,
) -> Rig {
    start_rig_with_reply_and_gate(
        expires_at,
        max_connects,
        max_requests,
        trust_upstream,
        reply,
        None,
    )
    .await
}

async fn start_rig_with_reply_and_gate(
    expires_at: SystemTime,
    max_connects: u32,
    max_requests: u32,
    trust_upstream: bool,
    reply: ProviderReply,
    gate: Option<Arc<dyn ProtectedRequestGate>>,
) -> Rig {
    start_rig_with_security(
        expires_at,
        max_connects,
        max_requests,
        trust_upstream,
        reply,
        gate,
        None,
        None,
    )
    .await
}

async fn start_rig_with_security(
    expires_at: SystemTime,
    max_connects: u32,
    max_requests: u32,
    trust_upstream: bool,
    reply: ProviderReply,
    gate: Option<Arc<dyn ProtectedRequestGate>>,
    admission: Option<Arc<dyn RequestAdmission>>,
    round_trip: Option<Arc<dyn RoundTripAdmission>>,
) -> Rig {
    let certs = certificates();
    let provider_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let provider_addr = provider_listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config(&certs));
    let (sent, received) = mpsc::unbounded_channel();
    let (headers_sent, received_headers) = mpsc::unbounded_channel();
    let (upstream_sent, upstream_accepted) = mpsc::unbounded_channel();
    let provider_task = tokio::spawn(async move {
        loop {
            let (socket, _) = provider_listener.accept().await.unwrap();
            let _ = upstream_sent.send(());
            let acceptor = acceptor.clone();
            let sent = sent.clone();
            let headers_sent = headers_sent.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(socket).await else {
                    return;
                };
                let service = service_fn(move |request: Request<Body>| {
                    let sent = sent.clone();
                    let headers_sent = headers_sent.clone();
                    async move {
                        let auth = request
                            .headers()
                            .get(AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or("<missing>");
                        let _ = sent.send(auth.to_owned());
                        let _ = headers_sent.send(request.headers().clone());
                        let response = match reply {
                            ProviderReply::Ok => Response::new(Body::from("ok")),
                            ProviderReply::ReflectAuthorization => {
                                Response::new(Body::from(auth.to_owned()))
                            }
                            ProviderReply::ReflectAuthorizationAndHeaders => Response::builder()
                                .header("x-reflected-authorization", auth)
                                .body(Body::from(auth.to_owned()))
                                .unwrap(),
                            ProviderReply::InvalidBody => Response::new(Body::from("unexpected")),
                            ProviderReply::OversizedBody => Response::new(Body::from(vec![
                                b'x';
                                MAX_ADMITTED_RESPONSE_BODY_BYTES
                                    + 1
                            ])),
                            ProviderReply::OversizedHeaders => Response::builder()
                                .header("x-oversized", "x".repeat(16 * 1024))
                                .body(Body::from("ok"))
                                .unwrap(),
                            ProviderReply::DelayedBody => {
                                let (mut sender, body) = Body::channel();
                                tokio::spawn(async move {
                                    tokio::time::sleep(Duration::from_millis(150)).await;
                                    let _ = sender.send_data(Bytes::from_static(b"ok")).await;
                                });
                                Response::new(body)
                            }
                            ProviderReply::DeclaredTrailer => Response::builder()
                                .header("trailer", "x-extra")
                                .body(Body::from("ok"))
                                .unwrap(),
                            ProviderReply::RedirectOffHost => Response::builder()
                                .status(StatusCode::FOUND)
                                .header(LOCATION, "https://other.example.test/next")
                                .body(Body::empty())
                                .unwrap(),
                            ProviderReply::StalledResponse => {
                                std::future::pending::<()>().await;
                                unreachable!()
                            }
                            ProviderReply::StalledBody => {
                                let (sender, body) = Body::channel();
                                tokio::spawn(async move {
                                    let _sender = sender;
                                    std::future::pending::<()>().await;
                                });
                                Response::new(body)
                            }
                        };
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::Http::new()
                    .http1_only(true)
                    .serve_connection(tls, service)
                    .await;
            });
        }
    });

    let upstream_tls = if trust_upstream {
        client_config(&certs.ca)
    } else {
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        )
    };
    let config = ProxyConfig {
        bind_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        allowed_host: HOSTNAME.to_owned(),
        allowed_port: 443,
        upstream_addr: provider_addr,
        downstream_tls: server_config(&certs),
        upstream_tls,
        injection: CredentialInjection {
            header_name: AUTHORIZATION,
            header_value: CREDENTIAL.parse().unwrap(),
        },
        grant: TaskGrant {
            bearer_token: GRANT.to_owned(),
            expires_at,
            max_connects,
            max_requests,
        },
    };
    assert!(!format!("{config:?}").contains(CREDENTIAL));
    assert!(!format!("{config:?}").contains(GRANT));
    let proxy = match (gate, admission, round_trip) {
        (Some(gate), None, Some(round_trip)) => {
            ProxyServer::bind_with_request_gate_and_round_trip_admission(config, gate, round_trip)
                .await
                .unwrap()
        }
        (None, None, Some(round_trip)) => {
            ProxyServer::bind_with_round_trip_admission(config, round_trip)
                .await
                .unwrap()
        }
        (Some(gate), Some(admission), None) => {
            ProxyServer::bind_with_request_gate_and_admission(config, gate, admission)
                .await
                .unwrap()
        }
        (Some(gate), None, None) => ProxyServer::bind_with_request_gate(config, gate)
            .await
            .unwrap(),
        (None, Some(admission), None) => {
            ProxyServer::bind_with_request_admission(config, admission)
                .await
                .unwrap()
        }
        (None, None, None) => ProxyServer::bind(config).await.unwrap(),
        _ => panic!("test rig supports one admission policy"),
    };
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        proxy.run(std::future::pending()).await.unwrap();
    });
    Rig {
        proxy: proxy_addr,
        ca: certs.ca,
        received,
        received_headers,
        upstream_accepted,
        proxy_task,
        provider_task,
    }
}

#[tokio::test]
async fn protected_gate_runs_only_after_exact_http_host_validation() {
    let gate = TestGate::new(Instant::now() + Duration::from_secs(10));
    let mut rig = start_rig_with_reply_and_gate(
        SystemTime::now() + Duration::from_secs(10),
        1,
        2,
        true,
        ProviderReply::Ok,
        Some(gate.clone()),
    )
    .await;
    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let rejected = client
        .send_request(request("other.example.test"))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    assert_eq!(gate.state.lock().unwrap().admitted, 0);

    let accepted = client.send_request(request(HOSTNAME)).await.unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(rig.received.recv().await.unwrap(), CREDENTIAL);
    gate.revoke_and_wait().await;
    let state = gate.state.lock().unwrap();
    assert_eq!(state.admitted, 1);
    assert_eq!(state.active, 0);
    assert!(state.write_polls > 0);
}

#[tokio::test]
async fn revoke_drains_pending_request_and_denies_next_request_on_same_tunnel() {
    let gate = TestGate::new(Instant::now() + Duration::from_secs(10));
    let mut rig = start_rig_with_reply_and_gate(
        SystemTime::now() + Duration::from_secs(10),
        1,
        3,
        true,
        ProviderReply::StalledResponse,
        Some(gate.clone()),
    )
    .await;
    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let first = tokio::spawn(async move {
        let result = client.send_request(request(HOSTNAME)).await;
        (client, result)
    });
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), rig.received.recv())
            .await
            .unwrap()
            .unwrap(),
        CREDENTIAL
    );
    tokio::time::timeout(Duration::from_secs(2), gate.revoke_and_wait())
        .await
        .unwrap();
    let (mut client, first_result) = tokio::time::timeout(Duration::from_secs(2), first)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        first_result.unwrap().status(),
        StatusCode::FORBIDDEN | StatusCode::BAD_GATEWAY
    ));
    let second = client.send_request(request(HOSTNAME)).await.unwrap();
    assert_eq!(second.status(), StatusCode::FORBIDDEN);
    let state = gate.state.lock().unwrap();
    assert_eq!(state.active, 0);
    assert_eq!(state.admitted, 1);
}

#[tokio::test]
async fn monotonic_expiry_cancels_pending_upstream_response() {
    let gate = TestGate::new(Instant::now() + Duration::from_millis(500));
    let mut rig = start_rig_with_reply_and_gate(
        SystemTime::now() + Duration::from_secs(10),
        1,
        1,
        true,
        ProviderReply::StalledResponse,
        Some(gate.clone()),
    )
    .await;
    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        client.send_request(request(HOSTNAME)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(rig.received.recv().await.unwrap(), CREDENTIAL);
    let state = gate.state.lock().unwrap();
    assert_eq!(state.active, 0);
}

#[tokio::test]
async fn response_body_keeps_permit_until_revocation_drains_it() {
    let gate = TestGate::new(Instant::now() + Duration::from_secs(10));
    let mut rig = start_rig_with_reply_and_gate(
        SystemTime::now() + Duration::from_secs(10),
        1,
        1,
        true,
        ProviderReply::StalledBody,
        Some(gate.clone()),
    )
    .await;
    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let mut response = client.send_request(request(HOSTNAME)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(rig.received.recv().await.unwrap(), CREDENTIAL);
    assert_eq!(gate.state.lock().unwrap().active, 1);
    tokio::time::timeout(Duration::from_secs(2), gate.revoke_and_wait())
        .await
        .unwrap();
    let body_end = tokio::time::timeout(Duration::from_secs(2), response.body_mut().data())
        .await
        .unwrap();
    assert!(body_end.is_none() || body_end.is_some_and(|result| result.is_err()));
    assert_eq!(gate.state.lock().unwrap().active, 0);
}

#[tokio::test]
async fn concurrent_tls_requests_stop_writing_before_revoke_barrier_returns() {
    const COUNT: usize = 4;
    let gate = TestGate::new(Instant::now() + Duration::from_secs(10));
    let mut rig = start_rig_with_reply_and_gate(
        SystemTime::now() + Duration::from_secs(10),
        COUNT as u32,
        (COUNT * 2) as u32,
        true,
        ProviderReply::StalledResponse,
        Some(gate.clone()),
    )
    .await;
    let mut tasks = Vec::new();
    for _ in 0..COUNT {
        let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
        assert!(connected.starts_with("HTTP/1.1 200"));
        let mut client = inside_tunnel(socket, &rig.ca).await;
        tasks.push(tokio::spawn(async move {
            client.send_request(request(HOSTNAME)).await
        }));
    }
    for _ in 0..COUNT {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), rig.received.recv())
                .await
                .unwrap()
                .unwrap(),
            CREDENTIAL
        );
    }
    tokio::time::timeout(Duration::from_secs(2), gate.revoke_and_wait())
        .await
        .unwrap();
    let writes_at_barrier = {
        let state = gate.state.lock().unwrap();
        assert_eq!(state.active, 0);
        assert_eq!(state.admitted, COUNT);
        state.write_polls
    };
    for task in tasks {
        let response = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(
            response.status(),
            StatusCode::FORBIDDEN | StatusCode::BAD_GATEWAY
        ));
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(gate.state.lock().unwrap().write_polls, writes_at_barrier);
}

#[tokio::test]
async fn downstream_disconnect_aborts_worker_waiting_for_upstream_headers() {
    let gate = TestGate::new(Instant::now() + Duration::from_secs(10));
    let mut rig = start_rig_with_reply_and_gate(
        SystemTime::now() + Duration::from_secs(10),
        1,
        1,
        true,
        ProviderReply::StalledResponse,
        Some(gate.clone()),
    )
    .await;
    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let (mut client, driver) = inside_tunnel_with_driver(socket, &rig.ca).await;
    let pending = tokio::spawn(async move { client.send_request(request(HOSTNAME)).await });
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), rig.received.recv())
            .await
            .unwrap()
            .unwrap(),
        CREDENTIAL
    );
    assert_eq!(gate.state.lock().unwrap().active, 1);
    driver.abort();
    tokio::time::timeout(Duration::from_secs(2), gate.wait_drained())
        .await
        .unwrap();
    assert_eq!(gate.state.lock().unwrap().active, 0);
    pending.abort();
}

#[tokio::test]
async fn dropping_downstream_response_body_aborts_stalled_upstream_body() {
    let gate = TestGate::new(Instant::now() + Duration::from_secs(10));
    let mut rig = start_rig_with_reply_and_gate(
        SystemTime::now() + Duration::from_secs(10),
        1,
        1,
        true,
        ProviderReply::StalledBody,
        Some(gate.clone()),
    )
    .await;
    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let response = client.send_request(request(HOSTNAME)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(rig.received.recv().await.unwrap(), CREDENTIAL);
    assert_eq!(gate.state.lock().unwrap().active, 1);
    drop(response);
    tokio::time::timeout(Duration::from_secs(2), gate.wait_drained())
        .await
        .unwrap();
    assert_eq!(gate.state.lock().unwrap().active, 0);
}

#[tokio::test]
async fn external_run_abort_closes_worker_with_live_downstream_request() {
    let gate = TestGate::new(Instant::now() + Duration::from_secs(10));
    let mut rig = start_rig_with_reply_and_gate(
        SystemTime::now() + Duration::from_secs(10),
        1,
        1,
        true,
        ProviderReply::StalledResponse,
        Some(gate.clone()),
    )
    .await;
    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let pending = tokio::spawn(async move { client.send_request(request(HOSTNAME)).await });
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), rig.received.recv())
            .await
            .unwrap()
            .unwrap(),
        CREDENTIAL
    );
    assert_eq!(gate.state.lock().unwrap().active, 1);
    rig.proxy_task.abort();
    let stopped = tokio::time::timeout(Duration::from_secs(2), &mut rig.proxy_task)
        .await
        .unwrap();
    assert!(stopped.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(2), gate.wait_drained())
        .await
        .unwrap();
    assert_eq!(gate.state.lock().unwrap().active, 0);
    pending.abort();
}

async fn connect_status(proxy: SocketAddr, target: &str, grant: &str) -> (TcpStream, String) {
    connect_status_with_auth(proxy, target, &format!("Bearer {grant}")).await
}

async fn connect_status_with_auth(
    proxy: SocketAddr,
    target: &str,
    authorization: &str,
) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let connect = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {authorization}\r\n\r\n"
    );
    stream.write_all(connect.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8];
        stream.read_exact(&mut byte).await.unwrap();
        response.push(byte[0]);
    }
    (stream, String::from_utf8(response).unwrap())
}

async fn hub_provider(
    tls: Arc<ServerConfig>,
) -> (SocketAddr, mpsc::UnboundedReceiver<String>, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, receiver) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let sender = sender.clone();
            let acceptor = TlsAcceptor::from(Arc::clone(&tls));
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(move |request: Request<Body>| {
                    let value = request
                        .headers()
                        .get(AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("<missing>")
                        .to_owned();
                    let _ = sender.send(value);
                    async { Ok::<_, Infallible>(Response::new(Body::from("ok"))) }
                });
                let _ = hyper::server::conn::Http::new()
                    .http1_only(true)
                    .serve_connection(tls, service)
                    .await;
            });
        }
    });
    (address, receiver, task)
}

fn hub_config(
    address: SocketAddr,
    upstream_addr: SocketAddr,
    certs: &Certificates,
    token: &str,
    credential: &str,
) -> ProxyConfig {
    ProxyConfig {
        bind_addr: address,
        allowed_host: HOSTNAME.into(),
        allowed_port: 443,
        upstream_addr,
        downstream_tls: server_config(certs),
        upstream_tls: client_config(&certs.ca),
        injection: CredentialInjection {
            header_name: AUTHORIZATION,
            header_value: credential.parse().unwrap(),
        },
        grant: TaskGrant {
            bearer_token: token.into(),
            expires_at: SystemTime::now() + Duration::from_secs(30),
            max_connects: 2,
            max_requests: 2,
        },
    }
}

#[tokio::test]
async fn fixed_hub_routes_by_capability_and_revokes_only_its_task() {
    let hub = ProxyHub::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let certs = certificates();
    let (upstream_a, mut seen_a, provider_a) = hub_provider(server_config(&certs)).await;
    let (upstream_b, mut seen_b, provider_b) = hub_provider(server_config(&certs)).await;
    let (_, idle) = connect_status(hub.local_addr(), "api.example.test:443", "task-a").await;
    assert!(idle.starts_with("HTTP/1.1 407"));
    let a = hub
        .activate(hub_config(
            hub.local_addr(),
            upstream_a,
            &certs,
            "task-a",
            "Bearer secret-a",
        ))
        .await
        .unwrap();
    let b = hub
        .activate(hub_config(
            hub.local_addr(),
            upstream_b,
            &certs,
            "task-b",
            "Bearer secret-b",
        ))
        .await
        .unwrap();
    let (socket_a, connected_a) =
        connect_status(hub.local_addr(), "api.example.test:443", "task-a").await;
    let (socket_b, connected_b) =
        connect_status(hub.local_addr(), "api.example.test:443", "task-b").await;
    assert!(connected_a.starts_with("HTTP/1.1 200"));
    assert!(connected_b.starts_with("HTTP/1.1 200"));
    let mut client_a = inside_tunnel(socket_a, &certs.ca).await;
    let mut client_b = inside_tunnel(socket_b, &certs.ca).await;
    assert_eq!(
        client_a
            .send_request(request(HOSTNAME))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client_b
            .send_request(request(HOSTNAME))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(seen_a.recv().await.unwrap(), "Bearer secret-a");
    assert_eq!(seen_b.recv().await.unwrap(), "Bearer secret-b");
    // The bearer is transferable: a second same-UID process with a copy of
    // task A's capability can consume A's remaining approved quota.
    let (copied_socket, copied_connect) =
        connect_status(hub.local_addr(), "api.example.test:443", "task-a").await;
    assert!(copied_connect.starts_with("HTTP/1.1 200"));
    let mut copied_client = inside_tunnel(copied_socket, &certs.ca).await;
    assert_eq!(
        copied_client
            .send_request(request(HOSTNAME))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(seen_a.recv().await.unwrap(), "Bearer secret-a");
    assert!(seen_b.try_recv().is_err());
    hub.deactivate(a).await.unwrap();
    assert!(client_a.send_request(request(HOSTNAME)).await.is_err());
    let (_, revoked) = connect_status(hub.local_addr(), "api.example.test:443", "task-a").await;
    assert!(revoked.starts_with("HTTP/1.1 407"));
    assert_eq!(
        client_b
            .send_request(request(HOSTNAME))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(seen_b.recv().await.unwrap(), "Bearer secret-b");
    assert!(seen_a.try_recv().is_err());
    assert!(
        hub.activate(hub_config(
            hub.local_addr(),
            upstream_a,
            &certs,
            "task-a",
            "Bearer secret-a"
        ))
        .await
        .is_err()
    );
    hub.deactivate(b).await.unwrap();
    let (_, idle_again) = connect_status(hub.local_addr(), "api.example.test:443", "task-b").await;
    assert!(idle_again.starts_with("HTTP/1.1 407"));
    hub.shutdown().await.unwrap();
    provider_a.abort();
    provider_b.abort();
}

#[tokio::test]
async fn pending_connect_cannot_bind_to_later_grant() {
    let hub = ProxyHub::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let certs = certificates();
    let (upstream, _seen, provider) = hub_provider(server_config(&certs)).await;
    let old = hub
        .activate(hub_config(
            hub.local_addr(),
            upstream,
            &certs,
            "old-token",
            "Bearer old-secret",
        ))
        .await
        .unwrap();
    let mut stale = TcpStream::connect(hub.local_addr()).await.unwrap();
    stale
        .write_all(
            b"CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\nProxy-Authorization: Bearer new-token\r\n",
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    tokio::time::timeout(Duration::from_secs(1), hub.deactivate(old))
        .await
        .unwrap()
        .unwrap();
    let new = hub
        .activate(hub_config(
            hub.local_addr(),
            upstream,
            &certs,
            "new-token",
            "Bearer new-secret",
        ))
        .await
        .unwrap();
    stale.write_all(b"\r\n").await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !response.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stale.read_exact(&mut byte).await.unwrap();
            response.push(byte[0]);
        }
    })
    .await
    .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 407"));
    let (_, current) = connect_status(hub.local_addr(), "api.example.test:443", "new-token").await;
    assert!(current.starts_with("HTTP/1.1 200"));
    hub.deactivate(new).await.unwrap();
    hub.shutdown().await.unwrap();
    provider.abort();
}

#[tokio::test]
async fn standard_basic_proxy_capability_can_inject_for_an_approved_task() {
    let mut rig = start_rig(SystemTime::now() + Duration::from_secs(30), 1, 1, true).await;
    let basic = format!("Basic {}", STANDARD.encode(format!("av:{GRANT}")));
    let (socket, connected) =
        connect_status_with_auth(rig.proxy, "api.example.test:443", &basic).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let response = client.send_request(request(HOSTNAME)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(rig.received.recv().await.unwrap(), CREDENTIAL);
}

async fn inside_tunnel(
    stream: TcpStream,
    ca: &CertificateDer<'static>,
) -> hyper::client::conn::SendRequest<Body> {
    inside_tunnel_with_driver(stream, ca).await.0
}

async fn inside_tunnel_with_driver(
    stream: TcpStream,
    ca: &CertificateDer<'static>,
) -> (hyper::client::conn::SendRequest<Body>, JoinHandle<()>) {
    let connector = TlsConnector::from(client_config(ca));
    let tls = connector
        .connect(ServerName::try_from(HOSTNAME.to_owned()).unwrap(), stream)
        .await
        .unwrap();
    let (sender, connection) = hyper::client::conn::handshake(tls).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    (sender, driver)
}

fn request(host: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri("/probe?x=1")
        .header(HOST, host)
        .header(AUTHORIZATION, "Bearer child-controlled-placeholder")
        .body(Body::empty())
        .unwrap()
}

fn admitted_request(method: Method, uri: &str, content_type: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(HOST, HOSTNAME)
        .header(CONTENT_TYPE, content_type)
        .header(AUTHORIZATION, "Bearer child-controlled-placeholder")
        .body(body)
        .unwrap()
}

#[tokio::test]
async fn admission_rejects_wrong_method_path_headers_body_and_order_before_upstream() {
    let admission = Arc::new(OrderedAdmission::default());
    let gate = TestGate::new(Instant::now() + Duration::from_secs(10));
    let mut rig = start_rig_with_security(
        SystemTime::now() + Duration::from_secs(10),
        1,
        12,
        true,
        ProviderReply::Ok,
        Some(gate.clone()),
        Some(admission.clone()),
        None,
    )
    .await;
    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;

    let denied = [
        admitted_request(
            Method::POST,
            "/graphql",
            "application/json",
            Body::from(SECOND_BODY),
        ),
        admitted_request(
            Method::GET,
            "/graphql",
            "application/json",
            Body::from(FIRST_BODY),
        ),
        admitted_request(
            Method::POST,
            "/other",
            "application/json",
            Body::from(FIRST_BODY),
        ),
        admitted_request(
            Method::POST,
            "/graphql%2fother",
            "application/json",
            Body::from(FIRST_BODY),
        ),
        admitted_request(
            Method::POST,
            "/graphql",
            "text/plain",
            Body::from(FIRST_BODY),
        ),
        {
            let mut request = admitted_request(
                Method::POST,
                "/graphql",
                "application/json",
                Body::from(FIRST_BODY),
            );
            request
                .headers_mut()
                .append(CONTENT_TYPE, "text/plain".parse().unwrap());
            request
        },
        admitted_request(
            Method::POST,
            "/graphql",
            "application/json",
            Body::from("{}"),
        ),
    ];
    for request in denied {
        let response = client.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), rig.upstream_accepted.recv())
                .await
                .is_err(),
            "denied request opened upstream transport"
        );
    }
    assert_eq!(*admission.next.lock().unwrap(), 0);
    assert_eq!(gate.state.lock().unwrap().admitted, 0);

    let first = client
        .send_request(admitted_request(
            Method::POST,
            "/graphql",
            "application/json",
            Body::from(FIRST_BODY),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    rig.upstream_accepted.recv().await.unwrap();
    assert_eq!(rig.received.recv().await.unwrap(), CREDENTIAL);

    let replay = client
        .send_request(admitted_request(
            Method::POST,
            "/graphql",
            "application/json",
            Body::from(FIRST_BODY),
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::FORBIDDEN);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), rig.upstream_accepted.recv())
            .await
            .is_err()
    );

    let second = client
        .send_request(admitted_request(
            Method::POST,
            "/graphql",
            "application/json",
            Body::from(SECOND_BODY),
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    rig.upstream_accepted.recv().await.unwrap();
    assert_eq!(rig.received.recv().await.unwrap(), CREDENTIAL);
    assert_eq!(*admission.next.lock().unwrap(), 2);
    gate.wait_drained().await;
    assert_eq!(gate.state.lock().unwrap().admitted, 2);
}

#[tokio::test]
async fn admission_rejects_known_and_streamed_oversize_bodies_without_upstream() {
    let mut rig = start_rig_with_security(
        SystemTime::now() + Duration::from_secs(10),
        2,
        2,
        true,
        ProviderReply::Ok,
        None,
        Some(Arc::new(OrderedAdmission::default())),
        None,
    )
    .await;
    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let known = client
        .send_request(admitted_request(
            Method::POST,
            "/graphql",
            "application/json",
            Body::from(vec![b'x'; MAX_ADMITTED_REQUEST_BODY_BYTES + 1]),
        ))
        .await
        .unwrap();
    assert_eq!(known.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(rig.upstream_accepted.try_recv().is_err());

    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let (mut sender, chunked) = Body::channel();
    let send_body = tokio::spawn(async move {
        for size in [
            MAX_ADMITTED_REQUEST_BODY_BYTES / 2,
            MAX_ADMITTED_REQUEST_BODY_BYTES / 2 + 1,
        ] {
            if sender
                .send_data(Bytes::from(vec![b'x'; size]))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let streamed = client
        .send_request(admitted_request(
            Method::POST,
            "/graphql",
            "application/json",
            chunked,
        ))
        .await
        .unwrap();
    assert_eq!(streamed.status(), StatusCode::PAYLOAD_TOO_LARGE);
    send_body.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), rig.upstream_accepted.recv())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn admission_waits_for_complete_chunked_body_before_upstream() {
    let mut rig = start_rig_with_security(
        SystemTime::now() + Duration::from_secs(10),
        1,
        1,
        true,
        ProviderReply::Ok,
        None,
        Some(Arc::new(OrderedAdmission::default())),
        None,
    )
    .await;
    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let (mut sender, chunked) = Body::channel();
    let pending = tokio::spawn(async move {
        client
            .send_request(admitted_request(
                Method::POST,
                "/graphql",
                "application/json",
                chunked,
            ))
            .await
    });
    sender
        .send_data(Bytes::from_static(FIRST_BODY))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), rig.upstream_accepted.recv())
            .await
            .is_err()
    );
    drop(sender);
    let response = pending.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    rig.upstream_accepted.recv().await.unwrap();
    assert_eq!(rig.received.recv().await.unwrap(), CREDENTIAL);
    let upstream_headers = rig.received_headers.recv().await.unwrap();
    assert_eq!(
        upstream_headers.get(CONTENT_LENGTH).unwrap(),
        FIRST_BODY.len().to_string().as_str()
    );
    assert!(!upstream_headers.contains_key(TRANSFER_ENCODING));
}

#[tokio::test]
async fn admission_rejects_trailers_before_upstream() {
    let mut rig = start_rig_with_security(
        SystemTime::now() + Duration::from_secs(10),
        1,
        1,
        true,
        ProviderReply::Ok,
        None,
        Some(Arc::new(OrderedAdmission::default())),
        None,
    )
    .await;
    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let mut request = admitted_request(Method::POST, "/graphql", "application/json", Body::empty());
    request
        .headers_mut()
        .insert("trailer", "x-extra".parse().unwrap());
    let response = client.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), rig.upstream_accepted.recv())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn round_trip_review_waits_for_complete_body_and_sends_only_sanitized_response() {
    let policy = Arc::new(SafeRoundTrip::default());
    let gate = TestGate::new(Instant::now() + Duration::from_secs(10));
    let mut rig = start_rig_with_security(
        SystemTime::now() + Duration::from_secs(10),
        1,
        2,
        true,
        ProviderReply::DelayedBody,
        Some(gate.clone()),
        None,
        Some(policy.clone()),
    )
    .await;
    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let denied = client.send_request(request(HOSTNAME)).await.unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(rig.upstream_accepted.try_recv().is_err());
    assert_eq!(gate.state.lock().unwrap().admitted, 0);

    let mut pending = tokio::spawn(async move {
        let mut request = admitted_request(
            Method::POST,
            "/graphql",
            "application/json",
            Body::from(FIRST_BODY),
        );
        request
            .headers_mut()
            .insert(ACCEPT_ENCODING, "gzip".parse().unwrap());
        client.send_request(request).await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(60), &mut pending)
            .await
            .is_err(),
        "upstream headers reached client before body completion"
    );
    let response = pending.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.headers().get("x-sanitized").unwrap(), "yes");
    assert!(response.headers().get("content-length") != Some(&"999".parse().unwrap()));
    if let Some(encoding) = response.headers().get("transfer-encoding") {
        assert_eq!(encoding, "chunked");
    }
    let body = hyper::body::to_bytes(response).await.unwrap();
    assert_eq!(body.as_ref(), br#"{"accepted":true}"#);
    rig.upstream_accepted.recv().await.unwrap();
    assert_eq!(rig.received.recv().await.unwrap(), CREDENTIAL);
    let upstream_headers = rig.received_headers.recv().await.unwrap();
    assert!(!upstream_headers.contains_key(ACCEPT_ENCODING));
    assert_eq!(
        upstream_headers.get(CONTENT_LENGTH).unwrap(),
        FIRST_BODY.len().to_string().as_str()
    );
    assert!(!upstream_headers.contains_key(TRANSFER_ENCODING));
    assert_eq!(*policy.state.lock().unwrap(), (2, 1));
    gate.wait_drained().await;
    assert_eq!(gate.state.lock().unwrap().admitted, 1);
}

#[tokio::test]
async fn round_trip_denial_never_reflects_upstream_credential_or_headers() {
    let policy = Arc::new(SafeRoundTrip::default());
    let mut rig = start_rig_with_security(
        SystemTime::now() + Duration::from_secs(10),
        1,
        1,
        true,
        ProviderReply::ReflectAuthorizationAndHeaders,
        None,
        None,
        Some(policy.clone()),
    )
    .await;
    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let response = client
        .send_request(admitted_request(
            Method::POST,
            "/graphql",
            "application/json",
            Body::from(FIRST_BODY),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(!response.headers().contains_key("x-reflected-authorization"));
    assert!(!format!("{:?}", response.headers()).contains(CREDENTIAL));
    let body = hyper::body::to_bytes(response).await.unwrap();
    assert!(body.is_empty());
    assert_eq!(rig.received.recv().await.unwrap(), CREDENTIAL);
    assert_eq!(policy.state.lock().unwrap().1, 1);
}

#[tokio::test]
async fn round_trip_rejects_oversize_invalid_and_trailer_responses() {
    for (reply, expected_reviews) in [
        (ProviderReply::OversizedBody, 0),
        (ProviderReply::OversizedHeaders, 0),
        (ProviderReply::InvalidBody, 1),
        (ProviderReply::DeclaredTrailer, 0),
    ] {
        let policy = Arc::new(SafeRoundTrip::default());
        let mut rig = start_rig_with_security(
            SystemTime::now() + Duration::from_secs(10),
            1,
            1,
            true,
            reply,
            None,
            None,
            Some(policy.clone()),
        )
        .await;
        let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
        assert!(connected.starts_with("HTTP/1.1 200"));
        let mut client = inside_tunnel(socket, &rig.ca).await;
        let response = client
            .send_request(admitted_request(
                Method::POST,
                "/graphql",
                "application/json",
                Body::from(FIRST_BODY),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(hyper::body::to_bytes(response).await.unwrap().is_empty());
        assert_eq!(rig.received.recv().await.unwrap(), CREDENTIAL);
        assert_eq!(policy.state.lock().unwrap().1, expected_reviews);
    }
}

#[tokio::test]
async fn injects_only_for_exact_host_and_consumes_bounded_task_grant() {
    let mut rig = start_rig(SystemTime::now() + Duration::from_secs(30), 1, 1, true).await;
    let (_, forbidden) = connect_status(rig.proxy, "other.example.test:443", GRANT).await;
    assert!(forbidden.starts_with("HTTP/1.1 403"));

    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let wrong_host = client
        .send_request(request("other.example.test"))
        .await
        .unwrap();
    assert_eq!(wrong_host.status(), StatusCode::FORBIDDEN);

    let response = client.send_request(request(HOSTNAME)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(rig.received.recv().await.unwrap(), CREDENTIAL);
    let response = client.send_request(request(HOSTNAME)).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let (_, replay) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(replay.starts_with("HTTP/1.1 403"));
}

#[tokio::test]
async fn two_connect_grant_shares_two_request_limit_across_tunnels() {
    let mut rig = start_rig(SystemTime::now() + Duration::from_secs(30), 2, 2, true).await;
    let mut clients = Vec::new();
    for _ in 0..2 {
        let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
        assert!(connected.starts_with("HTTP/1.1 200"));
        clients.push(inside_tunnel(socket, &rig.ca).await);
    }
    let (_, third_connect) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(third_connect.starts_with("HTTP/1.1 403"));
    assert!(!third_connect.contains(CREDENTIAL));
    assert!(!third_connect.contains(GRANT));

    for client in &mut clients {
        let response = client.send_request(request(HOSTNAME)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(hyper::body::to_bytes(response).await.unwrap(), "ok");
        assert_eq!(rig.received.recv().await.unwrap(), CREDENTIAL);
    }
    // The third request is denied even though its tunnel has used only one.
    for client in clients.iter_mut().rev() {
        let response = client.send_request(request(HOSTNAME)).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = hyper::body::to_bytes(response).await.unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(!body.contains(CREDENTIAL));
        assert!(!body.contains(GRANT));
    }
    assert!(rig.received.try_recv().is_err());
}

#[tokio::test]
async fn denies_invalid_and_expired_capabilities() {
    let rig = start_rig(SystemTime::now() - Duration::from_secs(1), 1, 1, true).await;
    let (_, invalid) = connect_status(rig.proxy, "api.example.test:443", "wrong-grant").await;
    assert!(invalid.starts_with("HTTP/1.1 407"));
    let (_, expired) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(expired.starts_with("HTTP/1.1 403"));
}

#[tokio::test]
async fn a_stalled_client_is_closed_when_its_grant_expires() {
    let rig = start_rig(SystemTime::now() + Duration::from_secs(1), 1, 1, true).await;
    let mut stalled = TcpStream::connect(rig.proxy).await.unwrap();
    let mut byte = [0_u8; 1];
    let count = tokio::time::timeout(Duration::from_secs(2), stalled.read(&mut byte))
        .await
        .expect("expired tunnel was not closed")
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn unauthenticated_clients_cannot_create_unbounded_handlers() {
    let rig = start_rig(SystemTime::now() + Duration::from_secs(30), 1, 1, true).await;
    let mut held = Vec::new();
    for _ in 0..64 {
        let mut stream = TcpStream::connect(rig.proxy).await.unwrap();
        stream.write_all(b"{").await.unwrap();
        held.push(stream);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut extra = TcpStream::connect(rig.proxy).await.unwrap();
    let mut byte = [0_u8; 1];
    let count = tokio::time::timeout(Duration::from_secs(1), extra.read(&mut byte))
        .await
        .expect("excess unauthenticated connection was retained")
        .unwrap();
    assert_eq!(count, 0);
    drop(held);
}

#[tokio::test]
async fn incomplete_connect_header_has_a_short_deadline() {
    let rig = start_rig(SystemTime::now() + Duration::from_secs(30), 1, 1, true).await;
    let mut stream = TcpStream::connect(rig.proxy).await.unwrap();
    stream
        .write_all(b"CONNECT api.example.test:443")
        .await
        .unwrap();
    let mut byte = [0_u8; 1];
    let count = tokio::time::timeout(Duration::from_secs(6), stream.read(&mut byte))
        .await
        .expect("incomplete CONNECT held a handler past its deadline")
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn refuses_untrusted_upstream_certificate() {
    let mut rig = start_rig(SystemTime::now() + Duration::from_secs(30), 1, 1, false).await;
    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let response = client.send_request(request(HOSTNAME)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(rig.received.try_recv().is_err());
}

#[tokio::test]
async fn off_host_redirect_cannot_open_an_approved_tunnel() {
    let mut rig = start_rig_with_reply(
        SystemTime::now() + Duration::from_secs(30),
        2,
        2,
        true,
        ProviderReply::RedirectOffHost,
    )
    .await;
    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let response = client.send_request(request(HOSTNAME)).await.unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(LOCATION).unwrap(),
        "https://other.example.test/next"
    );
    assert_eq!(rig.received.recv().await.unwrap(), CREDENTIAL);

    let (_, forbidden) = connect_status(rig.proxy, "other.example.test:443", GRANT).await;
    assert!(forbidden.starts_with("HTTP/1.1 403"));
    assert!(rig.received.try_recv().is_err());
}

#[tokio::test]
async fn allowed_host_can_reflect_an_injected_credential() {
    let mut rig = start_rig_with_reply(
        SystemTime::now() + Duration::from_secs(30),
        1,
        1,
        true,
        ProviderReply::ReflectAuthorization,
    )
    .await;
    let (socket, connected) = connect_status(rig.proxy, "api.example.test:443", GRANT).await;
    assert!(connected.starts_with("HTTP/1.1 200"));
    let mut client = inside_tunnel(socket, &rig.ca).await;
    let response = client.send_request(request(HOSTNAME)).await.unwrap();
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    assert_eq!(body.as_ref(), CREDENTIAL.as_bytes());
    assert_eq!(rig.received.recv().await.unwrap(), CREDENTIAL);
}
