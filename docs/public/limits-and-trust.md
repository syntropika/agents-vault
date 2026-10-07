# Limits and trust

Use direct delivery only with code you trust to receive the secret. Use synthetic credentials for proxy and approval tests. Protected production credential custody remains a release gate.

## Direct delivery

A granted child receives real selected values in its environment and can reveal them. The executable image and arguments are pinned by the grant; scripts, imported modules, libraries, and subprocesses remain outside that pinning. An operator must trust that code as well.

The local vault runs under the user's identity. Encrypted storage is not a boundary against every process sharing that identity. A passphrase check or a disclosure message does not authenticate a human approval by itself.

## Proxy delivery

The implementation checks an exact host and applies action lifetime and quotas. An exact host does not restrict API paths or provider-side operations. A provider may reflect an injected credential. A command may ignore proxy settings; the host-client mode does not confine host resources or direct network egress.

The child receives a temporary proxy capability. A copied capability can use the approved destination and remaining quota; it is not an exclusive process identity. A compromised approved host process can also act within that destination and quota. Approval and capability lifecycle must be evaluated together with the operator, harness, broker, and every agent-controlled route.

## Execution connection

The broker assigns execution authority to the original live IPC connection when a request is created. A public request ID, task ID, or displayed owner ID is review context, not authority to execute or finish an action. Another connection cannot claim that authority by knowing those IDs. Closing the original connection revokes its pending approvals and active host-proxy grants; reconnecting does not restore it. MCP adoption permits scoped review and decisions while preserving the CLI connection's execution authority.

This is a connection-lifetime boundary. A deliberately inherited or transferred socket can keep authority alive after the original process exits. The broker does not guarantee original-PID-death detection or protection against a process deliberately sharing its connection. The approved child can also share its proxy capability. These limits remain even though the public-ID execution takeover is rejected.

Real-credential custody remains a release gate. Consult [implementation status](../implementation-status.md) for the original attack reproduction, regression evidence, and remaining platform and whole-agent checks. Keep proxy credentials synthetic.

## Operator and harness authority

The protected broker has a separate service vault and private operator channel. The agent-facing channel cannot administer it. The deployment still needs to prevent an agent sharing the login account from invoking privileged operator helpers.

MCP enrollment explicitly trusts the selected harness to enforce App-only decisions. It grants no credential administration or execution authority. SDK compatibility tests do not prove that every client enforces this rule.

Unlocking storage does not approve a task. Changing storage to a native keyring would not prevent deliberately shared execution connections, malicious harness decisions, or proxy response disclosure.

## Platform and protocol scope

Linux and Apple silicon macOS have component and synthetic CLI evidence. The live public `av run` workflow reached a local synthetic HTTPS provider with `curl` on both platforms; broker and MCP suites also passed on macOS. These tests do not use a genuine provider account. An installed Linux systemd/AppArmor guest has synthetic acceptance evidence. Installed macOS custody, signing, and acceptance remain unverified; Windows MSVC CLI tests and the offline package lifecycle passed; interactive secret delivery in a native Windows console remains unverified.

The proxy currently supports HTTP/1.1 CONNECT with HTTP/1.1 inside TLS. HTTP/2, WebSockets, arbitrary CLI compatibility, and broad provider support are not implemented. See the [proxy crate notes](../../crates/av-proxy/README.md) for transport constraints.

The [implementation status](../implementation-status.md) is the evidence ledger. The [work queue](../work-queue.md) records remaining gates. Neither successful fixture execution nor a passing unit suite establishes installed operating-system isolation.
