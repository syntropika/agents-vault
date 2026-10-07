# Limits and trust

Choose the delivery mode based on what you trust. Direct delivery exposes the secret to the command. Proxy and approval workflows currently require synthetic credentials while protected custody is being verified.

## Direct delivery

**Trust the command and the code it loads.** A direct recipient can read or reveal every secret delivered to its environment.

A grant pins the executable image and arguments. It does not pin scripts, imported modules, libraries, or subprocesses. Those can also read delivered values.

The local vault runs under your user identity. Encryption protects storage at rest, but does not isolate it from every process running as that user.

A passphrase check alone is not proof that a human approved a particular action.

## Proxy delivery

The proxy restricts the exact destination host, lifetime, and quotas. These limits have important boundaries:

- **A host can expose many operations.** Allowing it does not restrict API paths or provider-side actions.
- **Responses may reveal credentials.** A provider can reflect an injected credential back to the client.
- **Proxy settings are not isolation.** A command can ignore them, access host resources, or use direct network connections.
- **Capabilities can be shared.** A copied proxy capability can use the approved host and remaining quota. It does not prove which process made the request.

A compromised approved process can act within those limits. Evaluate the operator, client, broker, and agent-controlled routes together before relying on this boundary.

## Execution connection

The original live CLI connection owns execution authority. A public request ID, task ID, or displayed owner ID identifies the request for review; it cannot authorize another connection to execute or finish it.

Closing that original connection revokes pending approvals and active proxy grants. Reconnecting creates a new connection and does not restore authority.

MCP adoption gives a session scoped review and decision authority. Execution stays with the CLI.

### Shared connections remain a risk

A process can deliberately pass or inherit its socket. That connection may remain alive after the original process exits. The broker does not guarantee detection of the original PID's death or protection against deliberately shared connections.

An approved command can also share its proxy capability. Rejecting takeover through public IDs does not remove these risks.

## Operator and harness authority

The protected broker has a separate service vault and private operator channel. Its agent-facing channel cannot administer credentials.

Installation must also prevent an agent sharing the login account from invoking privileged operator helpers.

MCP enrollment trusts the selected client to enforce App-only decisions. It grants no credential administration or execution authority. SDK compatibility tests do not prove every client enforces the rule.

Unlocking storage does not approve an action. A future native keyring adapter would not prevent shared sockets, malicious client decisions, or credential disclosure in proxy responses.

## Platform and protocol scope

### Platform evidence

| Platform | Verified | Still unverified |
| --- | --- | --- |
| Linux | Components, synthetic CLI flow, and an installed systemd/AppArmor guest. | Complete real-credential custody and whole-agent checks. |
| Apple silicon macOS | Components, synthetic CLI flow, broker and MCP suites. | Installed custody, signing, and acceptance. |
| Windows | MSVC CLI tests and offline package lifecycle. | Interactive secret delivery in a native console. |

The Linux and macOS public `av run` tests used `curl` against a local synthetic HTTPS provider. They did not use a real provider account.

Passing a fixture or unit suite does not establish installed operating-system isolation. **Protected production credential custody remains a release gate.**

### Proxy protocols

Supported: HTTP/1.1 CONNECT, with HTTP/1.1 inside TLS.

Not implemented: HTTP/2, WebSockets, arbitrary CLI compatibility, or broad provider support. See the [proxy crate notes](../../crates/av-proxy/README.md) for transport details.

### Detailed evidence

- [Implementation status](../implementation-status.md) — attack reproduction, regression evidence, and platform results.
- [Work queue](../work-queue.md) — remaining checks and release gates.
