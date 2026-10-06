# Actions and approvals

An action is an operator-saved recipe for one command, credential version, destination, and set of limits. Saving a recipe, granting access, and enabling actions do not approve a run. A live `av run` request waits for a decision, then executes the reviewed command automatically after approval.

The current console supports one active host-proxy recipe per broker. Use synthetic credentials. Start with [configuration and delivery](configuration-and-delivery.md) if you need direct environment delivery instead.

## Configure an action

The local operator console is available at `http://127.0.0.1:14323/` when the daemon is configured with `AVD_APPROVAL_UI=1` and built with its web assets. This setting enables the console; it does not install or initialize a service.

1. Sign in from an operator-controlled browser.
2. Pause action execution before editing credentials, recipes, or permissions.
3. Add or select an active credential in the service vault.
4. In **Actions**, select the credential, set an absolute executable, enter each argument separately, and review runtime and request limits. The broker derives the exact host and credential version.
5. Save the recipe. Saving revokes the affected grants.
6. Grant permission for the new exact recipe, then enable actions.

Review a pending request's executable and argument vector, destination, credential version, runtime, connection quota, and request quota before approving it. Approval permits one attempt by the original waiting CLI connection. A denial prevents that attempt; changing a recipe requires a new matching request.

## Run a synthetic broker action

The service must already have a matching synthetic recipe, its credential permission granted, and actions enabled. Set the non-secret `AVD_AGENT_SOCKET` to the installed socket listed below. With the [project's proxy connection declaration](configuration-and-delivery.md#reference-a-broker-connection), request the exact configured executable and arguments:

```text
av run -- /absolute/path/to/configured-command argument
```

Replace the executable and argument with the operator's recipe. `av run --broker -- COMMAND` also selects the project's connection. The CLI prints `Pending broker request: REQUEST_ID` and stays running for up to 300 seconds while awaiting approval. Review that ID in the authenticated console or through the enrolled MCP Apps flow below. When approved, the same CLI connection executes the frozen command, supplies temporary proxy settings, and reports the result. There is no separate resume command.

Keep the requesting CLI running. Closing its IPC connection revokes its pending approvals and active host-proxy grants. A second process cannot execute or finish the action just by knowing its public request or task ID; reconnecting creates different authority. This boundary does not provide exclusive process identity when a socket or proxy capability is shared. See [limits and trust](limits-and-trust.md).

## Use MCP Apps

`av-mcp` is a stdio adapter for a trusted harness that advertises MCP Apps support. It adopts and reviews an existing live request, with App-only decision tools. It has no execution or credential-reading tool and cannot create a request without a live execution owner. Unsupported clients are refused.

1. Configure the absolute `av-mcp` executable in a compatible harness and set its non-secret `AVD_AGENT_SOCKET` to the installed agent socket.
2. Call `connect_approval`. Its App displays a broker-issued session ID.
3. In the authenticated operator console, refresh Settings and enroll only the exact ID shown in that App. Pending enrollment expires after two minutes.
4. Refresh the App connection. The enrolled harness can submit decisions for 15 minutes and at most 32 requests adopted by that adapter session.
5. Start the versioned project action with `av run` and keep it running. Read its printed request ID.
6. Call `request_proxy_task` with that existing `request_id` and the exact connection, version, host, and command vector. The broker checks the pending frozen intent and retains the original CLI's execution ownership.
7. Review the App's frozen intent and approve or deny it. Approval lets the original waiting CLI execute automatically.

| Tool argument | Required value |
| --- | --- |
| `request_id` | The ID printed by the still-running CLI |
| `connection` | The exact connection ID, such as `service/work` |
| `connection_version` | The version pinned in the project and installed recipe |
| `host` | The exact host in that recipe |
| `command` | The executable and arguments as the exact array of strings |

An altered command, version, or destination is refused. A closed, decided, or already-adopted-by-another-session request cannot be adopted. This MCP workflow uses a versioned connection recipe.

| Platform | Installed agent socket |
| --- | --- |
| Linux | `/run/agents-vault/agent.sock` |
| macOS | `/private/var/db/agents-vault/agent/agent.sock` |

Enrollment delegates bounded decision authority to the trusted harness. App-only visibility is a harness rule, not cryptographic proof of a human click. A malicious enrolled harness can synthesize decisions. A CLI-created request is attached to an MCP session only through explicit adoption; the adapter never takes over its execution connection.

Disconnecting a session prevents further decisions; it does not cancel an already-approved attempt. **Pause and lock** stops actions, discards approvals and loaded credentials, and invalidates console sessions. Signing out ends only that browser session.

The official MCP Apps SDK reference bridge and real Rust adapter have synthetic browser tests. This is not acceptance evidence for a named installed client. Build prerequisites, protocol details, and evidence are in [local approvals and MCP Apps](../approval-flow.md).
