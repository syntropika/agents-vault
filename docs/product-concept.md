# Product concept

Status: product direction. The [prototype status](prototype-status.md) separates implemented behavior from release claims.

## Goal

Build `av` as a local-first source of project configuration and connected accounts. Developers declare the values their applications and tools need; `av` validates and resolves them at runtime. An agent can request a bounded use of a connected service without receiving a persistent credential when a protected broker path has been verified. No cloud account is required.

The product combines project configuration, a connection lifecycle, and a credential broker. Its first useful flow imports existing dotenv assignments into an encrypted store and reviewed public project declarations. A future visual operator interface can make connection and policy setup easier, but a local web page alone is not a security boundary.

## Delivery choices

| Path | What the child receives | Required claim |
| --- | --- | --- |
| Public project value | The declared value | No secret custody is involved. |
| Direct secret delivery | The real credential | The child and its editable code can read and reveal it. |
| Proxy delivery | A placeholder and a bounded proxy route | Broker custody, proxy authentication, exact-host checks, and approval authority must be verified. Host execution does not claim command isolation. |
| Broker-executed action | A filtered result from a fixed operation | The operation and returned data need provider-specific validation. This is future integration work. |

A single risk label is not an authorization rule. Operator policy should specify the permitted project or task, destination, delivery path, whether approval is required, and the credential version. Project files may request use but must never expand operator-owned policy.

An exact-host proxy still allows potentially harmful operations on that host unless a specific request policy narrows it. A provider may reflect a credential in a response. The broker must not silently fall back from proxy to direct delivery when the protected path is unsupported.

## Approval and custody

MCP offers the broker-frozen request and a local approval link. With URL elicitation, the client can offer to open the operator page; otherwise the user opens the link manually. The page verifies the vault passphrase directly with the broker before approving or denying the exact request. The private terminal route remains available. A client response alone grants no authority. The broker allows at most one bounded execution attempt. See [authenticated local approval](approval-flow.md) for the implemented synthetic flow and its remaining platform gates.

The initial encrypted store uses SQLCipher, a random data key, an operator passphrase wrap, and independent offline recovery material. On Linux and macOS, a protected installation should place the broker under a hidden service identity. Windows begins with explicit direct mode. Hardware-backed unlock and external KMS are possible later, but an unlocked broker still handles usable key material in memory.

A VM is an optional command-isolation boundary. The default direction for a macOS-only CLI is host execution through a broker-owned proxy at a stable local address, with no change to its HTTPS destination URL. A small no-NIC Linux guest remains an experiment for commands that can run inside it. The user should not have to install a separate runtime for either path.

## Release scope and later ideas

The desired first release includes local project configuration and direct `av run` on Linux, macOS, and Windows, plus a tested protected broker and bounded proxy path on Linux and macOS. The first protected task should use a provider-neutral synthetic CLI and HTTPS service before any real credential or provider integration is claimed.

OAuth and refresh, a large action catalog, multiple logical vaults, hardware or KMS unlock, and protected Windows execution can follow once the core custody and approval boundaries pass their tests. Multiple vaults can be modeled as namespaces later; the current store has one vault per configured path.

See the [decision summary](decision-summary.md), [implementation plan](implementation-plan.md), and [work queue](work-queue.md) for the open gates.
