# `av-proxy` prototype

This Rust crate demonstrates broker-created task grants flowing through an
HTTPS CONNECT proxy. A client connects with `Proxy-Authorization: Bearer TOKEN`
or standard proxy URL credentials `av:TOKEN` (HTTP Basic). The proxy accepts a
configured number of CONNECT tunnels and inner HTTP requests until expiry. It
checks the CONNECT authority, the client's TLS SNI, and each inner HTTP `Host`
against one exact configured hostname and port. It replaces the selected
authentication header only on the upstream request. The upstream TLS
certificate is verified for that hostname against broker-supplied trust roots,
even when the configured upstream socket is a loopback test server.

The grant token is a **bounded capability visible to the child process**. It
does not authenticate a human or prove which task or VM sent the request. A
protected deployment must issue it only after an authenticated approval and
bind the proxy transport to a broker-authenticated runner or VM instance. A
loopback listener alone does not provide that boundary. This crate neither
confines the child nor prevents direct network egress or access to other host
resources. The current listener is TCP loopback for a self-contained test;
the Linux and macOS service transports in the product plan are separate work.

The proxy does **not** follow redirects. A client that follows a redirect to
another host must attempt another CONNECT, which this instance denies. A
provider can reflect an injected credential in a response, so a permitted host
is not a complete secrecy or action policy. The proxy never writes the
credential to its own logs, and its configuration `Debug` output redacts the
credential and grant token.

Current protocol scope: HTTP/1.1 CONNECT and HTTP/1.1 inside TLS; one exact DNS
host, one pinned upstream socket, and one selected injection header per grant.
The fixed listener routes up to 16 concurrent grants by capability and accepts
up to 4096 activations during its lifetime; after that, the broker must start a
fresh listener. Revoking one grant closes only its tunnels. A copied capability
can consume its original task's quota, so this is not an exclusive process
identity. There is no HTTP/2, WebSocket, arbitrary CLI compatibility, persistence,
or rate limit. The default `bind` remains a host-only preview path with no
operation policy or response filtering.

An opt-in `RoundTripAdmission` checks each complete inner request before
credential insertion or upstream I/O, then checks the complete upstream
response before sending a broker-supplied replacement to the client. It caps
inspected request and response bodies at 64 KiB, rejects trailers, rebuilds
request framing, and removes downstream `Accept-Encoding` upstream. Denied
responses disclose no provider bytes. A broker must implement operation and
response semantics; these transport checks alone do not authorize a live
credential. At most 64 connections are handled concurrently, and a client has five seconds
to finish its CONNECT header. Excess connections close without consuming a
task grant.
The downstream tunnel closes at grant expiry or after 60 seconds, whichever is
sooner. An upstream effect already dispatched cannot be rolled back. The broker
must own grant revocation and lifecycle before this is used outside the
synthetic demo.

Run the local Rust-client and fake HTTPS-provider integration tests:

```sh
cargo test -p av-proxy
```

The tests cover successful header injection, exact host matching, concurrent
grant routing and independent revocation, copied capability use, grant
replay/quota/expiry rejection, standard Basic proxy capability, upstream
certificate verification, request admission, bounded response review, and
sanitized responses. All test credentials and certificates are generated
for the test process; no external service or real credential is used.
