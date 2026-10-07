# MCP Apps

The `av-mcp` adapter lets a compatible harness display a frozen action and submit the operator's decision. It holds no credential value and cannot start execution.

## Prerequisites

- An operator-configured Linux or macOS broker with a matching synthetic action recipe.
- An unlocked operator console with action execution enabled.
- A harness advertising MCP Apps support for `text/html;profile=mcp-app`.

Clients without that capability are refused. There is no automatic chat-confirmation fallback. See [actions and approvals](actions-and-approvals.md) for service prerequisites.

## Install the adapter

```sh
cargo install av-mcp --locked
```

Release packages embed the App interface; no Node runtime is needed after installation. Register the absolute path to the installed `av-mcp` executable as a stdio MCP server. Add `AVD_AGENT_SOCKET` using your installed broker's agent socket:

| Platform | Installed agent socket |
| --- | --- |
| Linux | `/run/agents-vault/agent.sock` |
| macOS | `/private/var/db/agents-vault/agent/agent.sock` |

Do not put a vault passphrase or administration token in the harness configuration.

## Connect and approve

1. Call `connect_approval` and note the session ID displayed by its App.
2. In the authenticated console, open Settings and enroll that exact session ID.
3. Refresh the App connection. Enrollment lasts up to 15 minutes.
4. Start the matching `av run`. It waits and reports a public request ID.
5. Call `request_proxy_task` with that ID and the exact frozen intent.
6. Review the command, credential version, destination, runtime, and quotas in the App. Choose **Approve action** or **Deny**.

The original waiting CLI owns execution and resumes after approval. Approval permits one attempt within 60 seconds. Closing its connection revokes pending requests and active grants; reconnecting does not restore authority.

## Trust boundary

Enrollment delegates bounded decisions to the harness. Agents Vault trusts that harness to enforce App-only tools and distinguish operator interaction from model calls; the protocol does not prove a human click cryptographically. An enrolled malicious harness can synthesize decisions.

Use the authenticated console or private operator terminal when that delegation is unsuitable. Protocol details and test evidence are in [console and MCP approvals](../approval-flow.md).
