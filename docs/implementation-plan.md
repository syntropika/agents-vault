# Implementation plan

Status: active plan for the provider-neutral prototype, updated 2026-10-04. This is a sequence of implementation and evidence gates, not a declaration that protected custody is already available.

## Target architecture

```text
project configuration / av CLI / MCP harness
                    |
                    v
          immutable broker request
                    |
     +--------------+---------------+
     |                              |
operator-owned policy         authenticated decision
and encrypted vault          over private channel
     |                              |
     +--------------+---------------+
                    |
             one-use task grant
                    |
          host client or isolated runner + proxy
                    |
             allowed HTTPS host
```

The project file declares needed values and references. It cannot grant itself access. The local vault can provide direct values to a trusted child. The protected service owns its encrypted store, operator policy, and task grants. `av` can execute a frozen command on the host through a stable local proxy address; an optional isolated runner supplies a stronger command boundary. The proxy inserts a credential only for an exact verified host and within its grant limits.

## Milestones

1. **Local core:** Validate `av.toml`, import dotenv without executing it, store generic values, generate placeholders, and run explicit direct commands on Linux, macOS, and Windows. Denied or missing secrets stop before spawn. Explain direct child exposure.
2. **Connection lifecycle:** Add, list, show, replace, revoke, and disconnect provider-neutral records through local and protected operator paths. Version checks reject stale updates. Verify no raw credential appears in CLI results, logs, or agent IPC.
3. **Broker authority:** Separate the agent request and private administration sockets. Bind every approval to immutable broker-owned intent, a connection version, expiry, and one attempt. Test denial, malformed answers, concurrent use, replay, lock, rotation, and revocation.
4. **Synthetic protected task:** Use the fixture CLI and a local HTTPS provider. Verify placeholder delivery, certificate and host checks, bounded CONNECT and HTTP quotas, cancellation, and response reflection checks. Run the host-client protocol on Linux and macOS without changing the fixture's destination URL. Check blocked direct egress separately for the optional isolated runner; a host client retains ordinary host network access.
5. **Installed boundary:** On clean supported hosts, install broker and runner under hidden service identities. Prove an agent-controlled process cannot read encrypted custody, passphrase entry or private administration socket, or escape to unrestricted execution. Audit every shell, MCP, hook, browser, sub-agent, and resumed task route supported by the selected harness.
6. **Distribution and recovery:** Verify clean install, update, restart, uninstall, offline package contents, signing where required, backup/restore, and power-loss behavior. The default macOS host-proxy package should not require a guest image or separately installed virtualization runtime. Test Windows direct workflow natively.
7. **First real integration:** Select a narrowly scoped account and provider only after the synthetic and installed gates pass. Freeze request semantics, measure client proxy behavior, reject unsupported redirects/protocols, filter responses, and document remaining provider reflection and host-scope risks.

## Approval contract

MCP requires MCP Apps and an operator-enrolled trusted harness session. Start `av run` first; the adapter adopts its live request by public ID and exact frozen intent. The App approves or denies one bounded attempt, and the original waiting CLI executes automatically. The broker independently verifies connection ownership before execution and completion; disconnect revokes pending approvals and active grants. The local console and private operator terminal remain separate decision routes, with no automatic adapter fallback. See [local approvals and MCP Apps](approval-flow.md).

Protocol, HTTP and public CLI lifecycle tests cover this flow without a harness; the disposable installed Linux guest also passed local approval and versioned proxy delivery. These checks do not complete installed macOS validation or establish whole-agent confinement beyond connection ownership. No named harness is a required dependency. Real-client compatibility and the joined agent-route review remain open.

## Platform notes

Linux may use a host service and process/network confinement if all model-controlled tools and task egress are covered. A Linux VM is not required by the product. On macOS, native commands should run on the host through a broker-owned proxy when their policy selects proxy delivery. That protects the stored credential but does not confine the command's files or direct network access. The current no-NIC guest remains an optional isolation experiment. The fixed listener has a synthetic default-deny lifecycle; installed service identity, signed packaging, and whole-agent approval isolation still need validation.

All new engine tests use synthetic credentials and local providers. Run macOS-specific builds and tests on `sirius` over SSH. Do not promote a unit test, development guest, or one harness probe into an installed security guarantee.
