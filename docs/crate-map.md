# Crate map

Status: provider-neutral core after the 2026-10-04 cleanup. The workspace contains eight crates. A provider-specific action crate, a harness launcher, and its inference test crate were removed. The product can add integrations later behind explicit policy and tests.

| Crate | Responsibility |
| --- | --- |
| `av-core` | Project schema, dotenv import, vault policy and versioned connections, storage adapter contract, and the initial SQLCipher adapter. |
| `agents-vault` (directory `av-cli`, binary `av`) | Project commands, local credential and connection management, direct run, proxy preview, protected operator client, and broker task client. |
| `avd` | Broker-owned requests, authenticated local approval, connection administration, shared task supervision, platform task launch, and separate agent/operator IPC. |
| `av-proxy` | HTTPS CONNECT transport, exact-host and TLS checks, credential insertion, and bounded request handling. |
| `av-runner` | Linux child execution and network isolation primitive. |
| `av-vmm` | macOS task guest supervisor using Apple Virtualization.framework. |
| `av-mcp` | MCP Apps request and review adapter with enrolled, bounded decision authority; it holds no credentials or operator administration capability and exposes no execution tool. |
| `av-fixture-cli` (binary `av-fixture`) | Provider-neutral test CLI for placeholder and proxy verification. |

The core connection record stores an ID, exact host, version, active state, credential, and release policy. It does not infer a provider's scopes or authorize arbitrary network operations. Project files can reference values but cannot widen the broker's operator-owned policy.

Direct run and proxy preview are distinct from the installed broker. In direct mode the child receives the value. Proxy preview runs under the user's identity and cannot protect a credential from another process with equivalent access. A brokered proxy task needs a frozen command, exact destination, bounded quota and lifetime, approval where required, and a protected broker identity. Host commands retain their destination URL and use a fixed loopback proxy address. Command isolation is an optional stronger tier and must be verified separately.

Linux and macOS currently share the task completion, relock, deadline, and proxy-failure supervisor in `avd`. The synthetic host-client path runs a frozen command with `HTTPS_PROXY` on either platform. The existing isolated launch adapters remain separate: Linux accepts a pinned native executable, while the optional macOS guest runs only the bundled synthetic fixture. A common generic launch contract for the optional guest tier depends on deciding how the Mac guest receives and verifies a CLI and its runtime files.

## Dependency direction

`av-core` defines stored records and policy. `avd` uses those records and the proxy transport. Platform runners execute bounded tasks. `av-mcp` presents broker-frozen requests and accepts App-only decisions through an explicitly enrolled harness session. Unenrolled sessions cannot authorize a decision, and the harness must enforce the App interaction boundary. The broker-owned page and installed operator helper verify the vault passphrase; the helper uses the private administration channel. A future provider integration must not make the core schema, broker approval state, or base installer depend on one vendor or one harness.

The `web` package owns the local operator console. `avd/build.rs` embeds its compiled assets; `avd::operator_web` owns authenticated HTTP sessions and fixed management endpoints, while domain operations remain in the existing core and broker modules. The frontend is not a new Rust crate and adds no provider or harness launcher.
