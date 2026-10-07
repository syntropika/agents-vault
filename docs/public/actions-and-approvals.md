# Actions and approvals

Use an action to review a proxy command before it runs. You save the command and its limits, start a matching `av run`, then approve or deny that attempt.

**Use synthetic credentials for this workflow.** The current console supports one active host-proxy recipe per broker. For direct secret delivery, follow the [quickstart](quickstart.md).

## Before you start

You need:

- An [installed Linux or macOS service](installation.md#protected-services-and-mcp).
- Its operator console, enabled with `AVD_APPROVAL_UI=1` and built with web assets.
- A synthetic credential in the service vault.
- A project with a [proxy connection declaration](configuration-and-delivery.md#reference-a-broker-connection).

When enabled, the console is available at `http://127.0.0.1:14323/`. Enabling the console does not install or initialize the service.

## Configure an action

1. Sign in to the console from an operator-controlled browser.
2. **Pause actions** before editing credentials, recipes, or permissions.
3. Add or select an active credential in the service vault.
4. Open **Actions** and select the credential. Enter the absolute executable and each argument separately. Set the runtime and request limits.
5. Save the recipe. The broker records its exact host and credential version; saving revokes the affected permissions.
6. Grant permission for the saved recipe, then enable actions.

Saving a recipe or granting permission does not approve a run. Each attempt still needs a decision.

## Run a synthetic broker action

### 1. Select the service socket

Set the non-secret `AVD_AGENT_SOCKET` environment variable to your installed agent socket:

| Platform | Socket |
| --- | --- |
| Linux | `/run/agents-vault/agent.sock` |
| macOS | `/private/var/db/agents-vault/agent/agent.sock` |

### 2. Start the matching command

Replace the executable and argument with the exact saved recipe:

```text
av run -- /absolute/path/to/configured-command argument
```

The CLI prints:

```text
Pending broker request: REQUEST_ID
```

It waits for approval for up to **300 seconds**. Keep it running while you review the request. `av run --broker -- COMMAND` also selects the project's connection.

### 3. Review and decide

Find the request ID in the authenticated console. Check:

- The executable and every argument.
- The destination host and credential version.
- The runtime, connection quota, and request quota.

Approve to allow **one attempt**, or deny to prevent it. On approval, the waiting CLI runs automatically with temporary proxy settings and reports the result. There is no separate resume command.

Changing the recipe requires a new matching request.

## Use MCP Apps

A trusted, enrolled MCP Apps client can display the same request and submit your decision. It cannot retrieve credentials or start the command.

Follow [MCP Apps](mcp-apps.md) to install the adapter, enroll the client, and review an existing CLI request. Clients without MCP Apps support are refused.

## Stop or cancel

- **Close the requesting CLI connection** to revoke its pending approvals and active proxy grants.
- **Pause and lock** in the console to stop actions, discard approvals and loaded credentials, and invalidate console sessions.
- **Sign out** to end only the current browser session.

Knowing a public request ID does not let another process execute the action. Authority belongs to the original live CLI connection. Deliberately sharing that connection or its proxy capability has additional risks; see [limits and trust](limits-and-trust.md#execution-connection).

Disconnecting an MCP session prevents further decisions. It does not cancel an attempt that was already approved.
