# Agents Vault handoff

Updated: 2026-10-07. Baseline: `main` at `5f1f797`. This is a continuation checklist, not a new implementation plan.

## Current state

Use `av` for public project variables and explicitly trusted direct secret delivery. Protected proxy actions still require synthetic credentials. Publishing a package does not establish protected credential custody.

Completed:

- Provider-specific packages and the harness launcher were removed. The core remains provider-neutral.
- Project configuration, dotenv import, placeholders, direct grants, connection versions, and SQLCipher persistence are implemented.
- The fixed loopback proxy, local operator console, live CLI approvals, and enrolled MCP Apps sessions have synthetic evidence. Execution belongs to the original live CLI connection; public IDs cannot transfer it.
- All seven production crates are published at `0.1.0`. `cargo install agents-vault --locked` installs `av`; `cargo install av-mcp --locked` installs the adapter. Registry installation and public-variable execution passed on Linux and macOS. The installed MCP binary exposed its embedded App over stdio.
- The public site is deployed at [av.syntropika.ai](https://av.syntropika.ai/). Its 11 guides have been rewritten for readability; Markdown exports and both agent indexes use the same source. Website checks and deployment passed at the baseline commit.
- GitHub has the product description and homepage. Windows MSVC tests and the offline package lifecycle passed at `761e125`; native interactive secret delivery is a separate open check.

The Rust release tag is `v0.1.0`, at `761e125`. Subsequent changes through the baseline commit concern documentation and website presentation.

## Decisions to preserve

- Local-first, with no mandatory cloud service. Linux and macOS are the initial protected targets; Windows currently offers direct delivery.
- A fixed local proxy keeps the command's HTTPS URL unchanged. `av run` supplies temporary proxy settings automatically.
- Native host commands are the default proxy path. A VM is optional, not a required dependency. Do not make a full macOS VM the default.
- The protected service uses an identity separate from the agent's login account. Installation should manage hidden service identities without asking users to create another visible login.
- Direct delivery exposes the real value to the command and its loaded code. Host proxy settings do not confine the command or all its network traffic.
- MCP approval trusts an explicitly enrolled Apps-capable client. Unsupported clients are refused; no automatic chat or browser-link fallback is implemented. The authenticated operator console remains an independent decision surface.
- SQLCipher is the current backend. The storage interface already lives in `av-core`; native keyrings follow the custody checks. Avoid speculative crates or compatibility layers.
- Keep generic behavior independent of a named provider or harness. Use the fixture CLI and synthetic HTTPS provider for boundary tests.

## Remaining work, in order

### 1. Finish the installed macOS host-proxy path

The default-path decision and the existing package are not yet aligned: the macOS package still expects a fixture guest bundle.

- Create a host-proxy installation path that does not require a guest image or VM runtime.
- Validate the versioned protected connection through public `av run`, using the installed service identity and private operator channel.
- Check denial, expiry, replay, disconnect, restart, and independent concurrent-grant revocation.
- Verify that the host command cannot read the service vault or administer the broker. Keep its proxy environment free of the original credential.

**Done when:** the installed native command reaches the synthetic HTTPS provider through the unchanged URL after approval, and unauthorized access is rejected.

Start with [the proxy ADR](adr/0002-host-proxy-default.md), [macOS packaging](../packaging/macos/README.md), `packaging/macos/make-package.sh`, and `packaging/macos/test-service-boundary.py`. The existing boundary script is destructive and guest-oriented; do not run it on an everyday installation as a host-proxy acceptance test. Notarization remains deferred for local testing.

### 2. Complete the joined custody and approval audit

- Enumerate supported agent-controlled paths: shell, hooks, MCP tools, browser/computer tools, subagents, and reconnect/resume behavior.
- Test that none can use the private operator channel, invoke privileged administration, or read protected credential storage on installed Linux and macOS.
- Include deliberately shared sockets, copied proxy capabilities, direct network bypass, redirects, TLS failure, credential reflection, and request/response limits.
- Distinguish enforced restrictions from known host-mode limits. A host allowlist does not constrain every API operation at that host.

**Done when:** current installed-platform evidence covers every supported route and states remaining limitations. Keep real-credential protected use disabled until the applicable custody gates pass.

Start with [implementation status](implementation-status.md), [approval flow](approval-flow.md), and the installed Linux boundary tests in `packaging/linux/`.

### 3. Prove MCP Apps in a genuine installed client

- Choose a client that actually supports MCP Apps; no particular harness is required.
- Exercise enrollment, exact request review, approve, deny, expiry, revocation, replay, and changed intent using the installed adapter and an existing waiting CLI request.
- Confirm the client enforces App-only decision tools. Record this as a client trust assumption, not cryptographic proof of a human click.

**Done when:** a named client/version completes the synthetic workflow and its limitations are documented. SDK bridge tests alone do not close this item.

Start with [MCP Apps](public/mcp-apps.md), `crates/av-mcp`, and `web/src/mcp-main.tsx`.

### 4. Close installed lifecycle and recovery checks

- Verify Linux/macOS installation, restart, update, rollback, and uninstall while preserving vault and recovery material.
- Exercise backup/restore, wrong unlock material, key rotation, interrupted writes, and filesystem recovery in the installed flow.
- Run the native Windows interactive secret journey in `packaging/windows/test-direct-console.ps1`. Its CI syntax check is not execution evidence.
- Defer production notarization, Gatekeeper distribution acceptance, and Windows signing until distribution work is resumed.

**Done when:** each supported flow can install, recover, and uninstall without losing user data or requiring a development checkout.

### 5. Add native storage adapters after the security gates

- Integrate Apple Keychain and Linux Secret Service through the existing persistence boundary.
- Separate credential retrieval from metadata inspection. Define atomic generation publication, cross-process updates, and restart recovery.
- Keep backend selection operator-controlled. Locked, unavailable, or denied stores must fail without silently changing the backend.
- Specify native credential storage and native SQLCipher unlock separately.

**Done when:** genuine installed stores pass the domain/adapter contract and their deployment-specific custody checks.

Use [storage adapters](storage-adapters.md) as the design contract. A direct mapping of database operations to keyring get/set calls is insufficient.

### 6. Validate one real provider operation

After the applicable custody, approval, and recovery gates pass, choose one narrow operation and a disposable account. Define credential format, request matching, response filtering, provider scopes, and supported clients in a separate integration contract.

**Done when:** measured behavior supports the advertised operation without broadening host-only permissions or adding provider assumptions to the core.

## Later work

- Narrow Windows CI triggers to relevant Rust and packaging changes. Documentation-only pushes currently restart or cancel its native build.
- Reconcile older status documents and website source-page counts with this handoff and current evidence.
- Multiple vaults, OAuth, external password managers, KMS, and hardware-backed unlock.
- More than one active action recipe per broker.
- General command packaging for the optional isolated runner; the current guest is fixture-only.
- Broader proxy protocols and provider compatibility. HTTP/2 and WebSockets are not implemented.
- Protected Windows execution and production distribution signing.

## How to continue

1. Read this handoff, the relevant source, and its linked evidence before selecting the next item. The longer [work queue](work-queue.md) includes earlier checklist wording; completed behavior above should not become a new backlog item.
2. Start with the macOS host-proxy package gap. Define the acceptance case before modifying packaging or service policy.
3. Use synthetic credentials and isolated or reversible test installations. Keep machine-specific scripts, paths, screenshots, and logs outside the repository.
4. Test the changed boundary without requiring an agent harness. Add installed-client checks only where client behavior is the subject of the test.
5. Update the evidence ledger and public limits after results are established. Use lowercase Conventional Commits; never merge a pull request.

No new product decision is needed to resume item 1. A compatible installed MCP client, appropriate platform test environments, and production distribution credentials are separate execution prerequisites.
