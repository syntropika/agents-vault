# Work queue

Status: tasks after removing provider-specific and harness-specific packages, 2026-10-06. Complete the security gates in order; each gate needs evidence from the current provider-neutral build. Distribution and notarization work is deferred while the approval boundary is tested locally.

## 1. Stabilize the generic workspace

- Build and test all eight crates on Linux. Remove every stale type, feature, package option, and generated notice tied only to deleted integrations.
- Test project import, generic connection lifecycle, direct run, broker request/review/resume, and synthetic HTTPS injection without an agent harness.
- Build and test the macOS components on `sirius`. The format-2 guest is fixture-only; signed synthetic packages require an explicit test override and are not a production distribution path.
- Run a Windows native direct-mode smoke test. Cross-compilation alone is insufficient.
- Audit documentation and installer help against the actual CLI surface.

**Done when:** one workspace test run and platform-specific builds pass, and the base installer has no hidden provider or harness dependency.

## 1a. Complete the fixed-address host proxy

- Completed in the synthetic build: the broker-owned, persistent, default-deny listener at `127.0.0.1:14322` routes up to 16 concurrent task grants by capability. Each grant closes independently on command exit, broker lock, expiry, or cancellation. A copied capability can consume its task's quota; a same-UID caller can also race `Execute` for an approved request ID. The host execution path therefore lacks exclusive task identity.
- Public `av run` with `curl` reached a local synthetic HTTPS provider without changing the destination URL on Linux and macOS. The Linux test used a versioned connection; the macOS test used a development fixture. The Linux container boundary test rejects forged administration on both public sockets. Repeat these checks as installed acceptance tests where applicable.
- Validate the versioned protected-connection path on an installed macOS service. The installed Linux systemd/AppArmor guest has passed the synthetic path through public `av run`. Test that release selection and proxy delivery stay independent of agent-edited project files on both platforms. Keep a credential out of the host command's environment in proxy mode.
- Package and test the signed macOS broker with a host client. Resolve Linux service namespace routing to the host client without exposing the vault or proxy management channel.
- Run the synthetic CLI and local HTTPS provider through the public `av` command on Linux and macOS without an agent harness. Cover deny, expiry, replay, task close, wrong host, TLS failure, credential reflection, and concurrent requests.

**Done when:** a fresh Linux or macOS installation can keep a local proxy listening, run one approved non-fixture CLI task against its unchanged HTTPS URL, and retain the real credential only inside the protected broker.

## 1b. Optional isolated command runner

- Keep the small no-NIC Linux guest as an optional execution tier for commands that can run in it. Define how an approved executable and its runtime files enter the guest, how their bytes are pinned to the grant, and how updates change that identity.
- Replace the fixture-only guest protocol and manifest before claiming general command support. Reject commands that cannot be packaged or verified.
- A macOS-only CLI remains a host proxy task until a native command confinement path has been implemented and validated. A full macOS guest is not a default installation requirement.

**Done when:** the optional isolated tier can execute a selected non-fixture command without broadening broker or host access.

## 2. Finish generic connection and policy handling

- Specify the versioned record schema and direct/proxy release rules without embedding any provider format or action.
- Verify exact-host validation, default deny, stale-version refusal, rotation, revoke, disconnect, and rollback behavior in the local and service-owned vaults.
- Keep connection and project metadata free of credential values and reject attempts to elevate delivery through project edits.

**Done when:** independent tests cover the lifecycle and no generic connection receives an implicit execution grant.

## 3. Prove the approval authority boundary

- Updated product direction: implement approval in MCP Apps through the configured trusted harness. Check client capabilities and refuse the flow without Apps support; do not automatically fall back to the local page. Form elicitation alone does not satisfy this requirement. Define the broker-authorized decision channel and an unlock/session lifecycle that avoids a password per task. Test absent support, cancellation, timeout, forged decisions, exact-request binding, and a genuine compatible client before replacing the current flow. See the [decision summary](decision-summary.md).
- The MCP adapter does not hold the operator token or turn a form answer into approval. A protected terminal decision checks the vault passphrase. A disposable installed Linux guest passed the synthetic wrong-passphrase, `review`, `approve`, and `deny` checks. Keep this safe default while testing macOS and the remaining agent routes.
- Linux and macOS component tests reject Decide messages on agent-controlled sockets and reject unknown agent request fields. The Linux container test rejects forged administration on both public sockets. The macOS installed acceptance script covers the private helper's review, approval, and denial, but has not run on a disposable Mac. A same-UID agent client can still race `Execute` for an approved request and can end a task through `FinishHostProxy`; resolve this before a protected host execution claim.
- Implemented: a broker-owned local approval page authenticates the vault passphrase independently of MCP. URL elicitation offers the link; clients without URL support can open it manually. Forged or cancelled client responses leave the broker decision unchanged. Validate the [local approval flow](approval-flow.md) on installed macOS and in a real client; the UI does not solve same-UID execution takeover.
- Covered in synthetic tests: explicit approve and deny, forged or malformed client responses, unsupported clients, cancellation, client errors and timeouts, wrong HTTP origin, bad password, one-use form replay, expiry, simultaneous decisions and execution, and lock. Complete installed macOS evidence and real-client checks; retain version rotation and every agent-route check.
- Enumerate every agent-controlled shell, MCP tool, hook, browser/computer tool, sub-agent, and resume path in each supported harness.
- Verify privileged operator commands and sockets stay unreachable from those routes.

**Done when:** the installed broker accepts only an authenticated decision for the exact frozen request, and the adversarial routes fail on both Linux and macOS. If this cannot be proven, approval-required protected mode remains disabled.

## 4. Prove runner and proxy containment

- Pin a provider-neutral fixture command, exact host, quota, runtime, executable identity, and minimum inputs.
- On Linux, test child filesystem access, process inspection, raw network egress, direct TCP, proxy bypass, and service socket access under the installed runner.
- On macOS, verify the signed service-owned proxy, fixed loopback listener, task capability, and host client under separate service and login identities. For the optional guest tier, authenticate the guest transport to the broker; do not trust a guest-supplied task ID alone.
- Test TLS trust, redirects, cancellation, response reflection, protocol incompatibility, and request/response size limits. A denied or expired task must not start.
- Measure cold and warm startup, package size, and update integrity.

**Done when:** the same frozen synthetic task cannot reach the credential or forbidden network paths on either installed platform, while one approved request reaches the local HTTPS provider.

## 5. Recovery and distribution

- Test clean installation, restart, update, rollback, uninstall, and retained recovery material on supported Linux and macOS versions.
- Test backup/restore, wrong unlock material, data-key rotation, crash interruption, and power-loss behavior on the selected filesystems.
- Ensure the macOS host-proxy package needs no guest image or separate runtime download. If the isolated guest tier is installed, bundle and verify every required guest asset. Verify signing and notarization before a production claim.
- Complete native Windows direct-mode smoke and restore tests.

**Done when:** a fresh machine can install and recover the supported flow without a development checkout or hand-built artifact.

## 6. First real integration

After gates 1 through 5, select one narrow provider operation and disposable account. Define a standalone integration contract for credential format, request matching, response filtering, and client compatibility. Measure the actual proxy behavior and provider scopes with minimal permissions. Reject unsupported commands rather than widening host-only access. Document provider reflection and operational risks.

## 7. Native storage adapters

After the pending custody, approval, and installed-platform gates, integrate Apple Keychain and Linux Secret Service using the [storage adapter contract and integration plan](storage-adapters.md). The SQLCipher adapter boundary is implemented inside `av-core`; native adapters and backend selection are not. Validate metadata/credential separation, cross-store publication, service identity, prompts, recovery, and the absence of automatic fallback before enabling a native adapter. Native storage and native SQLCipher unlock are separate integrations.

Multiple vaults, OAuth, hardware/KMS unlock, broader action catalogs, and protected Windows execution follow this slice.

## Operator console implementation

Implemented locally: layout 3 with dark default, compact rounded controls, credential lifecycle, configured recipe grants/revocation, task review, and an authenticated 15-minute operator session. React, Tailwind, Effect, strict TypeScript/ESLint, oxfmt, runtime decoding, unit tests, real HTTP tests, and browser workflows are included. The compiled console is embedded into `avd`.

Remaining gates: actual MCP Apps negotiation/integration, native storage adapters, installed macOS protected-connection acceptance, and exclusive ownership of approved execution. The console does not close those gates.
