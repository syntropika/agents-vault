# `av-fixture`

`av-fixture` is a small Rust HTTPS client for auditing Agents Vault's synthetic
approval path. Its `request` command requires `HTTPS_PROXY`, `SSL_CERT_FILE`,
and `AV_FIXTURE_TOKEN`. It sends the placeholder in an Authorization header;
the broker proxy must replace that header before the local test provider sees
the request. `X-AV-Fixture-Input` lets the test provider verify the original
placeholder. The optional `--assert-direct-tcp-blocked` flag requires a new
direct Linux TCP socket to fail with `ENETUNREACH` before the proxy request.

The binary is a test fixture, not an authorization boundary by itself. The
broker enforces its frozen task decision, and the test provider only receives
credentials beginning with `av-synthetic-`. The current broker and runner can
share a host UID, so this flow does not establish protected custody.

The default `broker_flow` test covers pending, denial, altered intent, one-use
replay, TLS verification, and header replacement. The ignored Linux test also
uses the `av` two-step CLI and the network namespace. Build `av` and
`av-runner-helper`, then run the explicit command in the repository README.
