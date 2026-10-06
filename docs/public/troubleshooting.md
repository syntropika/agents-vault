# Troubleshooting

Start by identifying the path: public configuration, direct secret delivery, same-user proxy preview, or brokered action. Local direct-vault commands and installed service commands operate on different vaults.

| Symptom | Check and next step |
| --- | --- |
| `av` is not found | Use the absolute path to the built `target/debug/av`, or add its directory to `PATH`. |
| Configuration already exists | `init` and `import-env` create a new file. Choose a fresh project or an unused `--config` path. |
| Unknown environment or override name | Define the environment in `av.toml`; overrides can replace only existing value names. |
| Missing secret or invalid value type | Confirm the project reference and selected environment. `av check` validates required generic secrets after unlocking the local vault. |
| Direct release denied | Inspect `av secret policy NAME` from an operator terminal. Grant the exact executable and arguments with the same configuration, environment, and directory. |
| Connection version changed | Inspect `av connect show ID` or `av protected connect show ID` in the relevant vault. Review the new version before updating a request or grant. |
| Broker rejects a project configuration | The current path requires exactly one selected connection value. Its version and command must match the installed recipe. |
| Credential edits or action saves are unavailable | Pause action execution in Settings before changing the service configuration. |
| Saved action cannot run | Saving revokes affected permissions. Grant the exact recipe again before enabling actions. |
| MCP client cannot initialize | Check MCP Apps capability support and that `av-mcp` was built with the App assets. There is no chat fallback. |
| MCP session cannot decide | Enroll the exact App session ID in the authenticated console. Check expiry, action ownership, and whether the request belongs to that adapter session. |
| MCP request adoption is refused | Keep the original `av run` process running, use its existing request ID, and match the exact connection version, host, and command. The request must still be pending and cannot belong to another MCP session. |
| Broker approval times out | The CLI waits for up to 300 seconds. Start a new matching request and keep it running while the operator reviews it. |
| A reconnecting client cannot execute or finish | Execution authority belongs to the original IPC connection. A public ID cannot restore it; create a new request instead. |
| Console is unavailable | Check the daemon's `AVD_APPROVAL_UI=1` setting and embedded web assets. It uses loopback port 14323. |
| Proxy settings are rejected | The broker endpoint is fixed at `http://127.0.0.1:14322`; saved settings cannot redirect it to another endpoint. |
| An approved action expires or was already consumed | Review its authoritative state and request a new matching attempt. Approval grants one attempt, not an unlimited reusable permission. |

Do not troubleshoot by weakening a destination, granting an unrelated command, or copying a credential into a prompt. Diagnose proxy behavior using synthetic values and a disposable development broker.

When reporting a problem, include the CLI version, operating system, delivery path, command shape with sensitive arguments removed, and the error message after reviewing it for secrets. Do not attach a vault, key envelope, recovery file, passphrase, proxy capability, or raw secret environment.

For broker execution, follow [actions and approvals](actions-and-approvals.md). The requesting CLI waits and executes automatically after approval; the former `--resume` option is removed.
