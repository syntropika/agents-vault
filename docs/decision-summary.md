# Decision summary

Status: product decisions and unresolved engineering choices, updated 2026-10-06. Earlier provider and harness experiments are historical evidence, not dependencies of the base product.

## Agreed direction

- Build a local-first `av` with no mandatory cloud service.
- Offer project configuration, reviewed dotenv import, generic encrypted values, versioned connected accounts, and `av run`.
- Support direct delivery as an explicit lower-protection mode. The recipient can read the delivered value.
- Target a protected broker and bounded proxy task on Linux and macOS in the first release. A native macOS CLI should run on the host through the proxy by default; a full macOS guest is not a default requirement. The CLI should also work in direct mode on Windows.
- Require MCP Apps for the planned in-client approval flow and refuse that flow when the client does not advertise support. Trust the configured harness to collect the human decision for the exact frozen task. Do not automatically fall back to a browser link. This supersedes the earlier local-page product direction; the current implementation still uses URL elicitation and passphrase-authenticated local approval. MCP Apps, its broker authorization channel, and real-client compatibility remain unimplemented. App-only tool visibility is not authentication.
- Avoid requiring users to create a visible login account or install a VM runtime separately. Setup may install hidden service identities and bundle any required guest.
- Keep multiple vaults, OAuth, external KMS, and hardware-backed unlock as later options.
- Keep SQLCipher as the first storage adapter and integrate native Apple/Linux keyrings after the pending security gates. Vault policy remains independent of persistence; see the [storage adapter plan](storage-adapters.md).
- A native keyring stores credential values; `av` still owns enrollment, references, delivery policy, host restrictions, task limits, and confirmation rules. A credential management website is optional, not a prerequisite for a native adapter. Adding or editing a keyring item does not automatically enroll it or authorize its use.

## Architecture decisions

The encrypted vault stores generic connection records and their exact host and version. Local connection management is provider-neutral. The broker has separate agent and private administration channels. A task request freezes the command, target, version when present, time limit, and request quota. MCP presents that frozen intent; it is not the credential authority.

Linux uses a service-owned broker and a confined host runner prototype. macOS has a service broker and a bundled guest prototype from earlier experiments. The current host-proxy path runs a native command whose HTTPS traffic passes through a broker-owned fixed loopback listener. `av run` sets the proxy automatically and leaves the command's HTTPS destination URL untouched. The listener routes concurrent grants by short-lived capabilities. Public synthetic `curl` tests passed on Linux and macOS, but both platforms need complete installed evidence before a protected custody claim. Direct `av run` and same-user proxy preview remain explicitly weaker paths.

Provider-specific recipes and harness launchers developed during exploration have been removed from the base workspace. A future integration must define its own credential format, exact request semantics, response filtering, and versioned compatibility tests without changing the generic core into a single-provider product.

## Security findings that affect the plan

- A same-user process can obtain data that a CLI name check or process-ID check cannot protect. A proxy is not sufficient if the agent can read the vault or operator capability. A host command can also expose or reuse its task proxy capability; the proxy protects the stored credential, not exclusive command identity or general host egress.
- A same-UID agent client that knows an approved request ID can race `av run --resume`, consume `Execute`, and receive the proxy capability. Any holder can spend the task's remaining quota, and a client with the task ID can call `FinishHostProxy`. Public sockets reject administrative messages, but that does not make host execution exclusive to the frozen CLI.
- A real MCP form can elicit an answer, but a raw client can synthesize one. The adapter treats form answers as advisory. The vault-backed broker accepts passphrase-authenticated decisions through its local operator page or private administration. Both terminal approval and the local page passed synthetic installed Linux guest tests; installed macOS and full agent-route validation remain open.
- Host-only credential injection controls the destination, not the API operation. Request/response admission and provider behavior must be measured before asserting narrower permissions.
- An isolated command runner does not itself isolate the agent or the administration channel. The installed service identity, launcher, every agent-controlled route, and runner transport need one joined adversarial test.

## Open choices

1. Implement MCP Apps capability negotiation, exact-task review and decisions through a broker-authorized harness channel. Missing support, cancellation, errors, and timeouts must prevent execution; no browser fallback. Form elicitation is a separate client capability and does not satisfy the Apps requirement. Define unlock separately from approval so an already unlocked vault does not require a password for every task. Verify a real compatible client and retain installed-platform and raw-client tests.
2. Resolve same-UID host task takeover and demonstrate the broker-to-host-client path on an installed macOS service. Signing and packaging remain later distribution work.
3. Choose the first real provider integration only after the synthetic task, request policy, and response filtering pass without harness-specific assumptions.
4. Define backup and recovery for the current vault format.

No production credential should be used to validate an unproven protected boundary. The [work queue](work-queue.md) records acceptance criteria for each gate.

## Local operator console, 2026-10-06

The approved first surface covers credentials, configured permissions, and approvals. Layout 3 uses a top segmented navigation, left credential selector, and grouped details. Dark is the default, light is optional, and controls use compact rounded neutral styling. The browser signs in once for an absolute 15-minute operator session; the broker keeps a zeroizing passphrase copy until sign-out, lock, or expiry cleanup. This local console does not claim MCP Apps support or solve same-UID execution ownership.
