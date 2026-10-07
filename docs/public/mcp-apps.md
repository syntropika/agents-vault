# MCP Apps

Approve or deny an existing CLI action inside a compatible MCP client. The `av-mcp` adapter displays the request; the original `av run` process executes it after approval.

## Prerequisites

Before adding the adapter, prepare:

- A Linux or macOS broker with a matching **synthetic** action recipe.
- An unlocked operator console with actions enabled.
- A trusted client that advertises MCP Apps support for `text/html;profile=mcp-app`.

Follow [actions and approvals](actions-and-approvals.md) to prepare the service and recipe.

Clients without MCP Apps support are refused. There is no automatic chat-confirmation fallback.

## Install the adapter

```sh
cargo install av-mcp --locked
```

Release packages include the App interface. No Node runtime is needed after installation.

In your client's MCP configuration:

1. Add the absolute path to the installed `av-mcp` executable as a **stdio** server.
2. Set the non-secret `AVD_AGENT_SOCKET` to the installed agent socket.

| Platform | Socket |
| --- | --- |
| Linux | `/run/agents-vault/agent.sock` |
| macOS | `/private/var/db/agents-vault/agent/agent.sock` |

Keep vault passphrases and administration tokens out of the client configuration.

## Connect and approve

### 1. Enroll the client

1. Call `connect_approval`. Its App shows a session ID.
2. In the authenticated operator console, open **Settings**, refresh the session list, and enroll that exact ID.
3. Refresh the App connection to confirm enrollment.

Enroll within **two minutes**. Once enrolled, the session may decide up to **32 adopted requests** over **15 minutes**.

Only enroll a client you trust to enforce App-only decision tools. See the [trust boundary](#trust-boundary) below.

### 2. Start and attach a request

Start the matching `av run` and keep it running. It prints a public request ID while waiting for approval.

Call `request_proxy_task` with:

| Argument | Value |
| --- | --- |
| `request_id` | The ID printed by the still-running CLI. |
| `connection` | The exact connection ID, such as `service/work`. |
| `connection_version` | The version pinned in the project and saved recipe. |
| `host` | The exact destination host in that recipe. |
| `command` | The executable and arguments as an exact array of strings. |

The broker compares these values with the pending request. Changed commands, versions, or hosts are refused. A request must still be pending and cannot already belong to another MCP session.

The adapter cannot create a request without an existing CLI execution owner.

### 3. Review the App

Check the command, credential version, destination, runtime, and quotas. Choose **Approve action** or **Deny**.

Approval allows one execution attempt within **60 seconds**. The original CLI resumes automatically; the adapter never takes over its execution connection.

Closing the CLI connection revokes its pending requests and active grants. Reconnecting does not restore that authority.

## Trust boundary

Enrollment gives the selected client permission to submit bounded decisions. It does not grant credential administration or execution authority.

Agents Vault trusts the client to enforce App-only tools and separate human interaction from model calls. The protocol does not cryptographically prove a human click. A malicious enrolled client can synthesize approvals.

Use the authenticated console or private operator terminal if you do not want to delegate decisions to a client.

Synthetic tests cover the official MCP Apps SDK bridge and the Rust adapter. They do not establish support or enforcement in every installed client. See [console and MCP approvals](../approval-flow.md) for protocol details and test evidence.
