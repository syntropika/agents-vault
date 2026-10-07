# Troubleshooting

Find the symptom below, then check the workflow involved. Local vault commands and installed service commands use separate stores.

## Installation

### av is not found

Install with `cargo install agents-vault --locked`. Open a new terminal, then check Cargo's executable directory in `PATH`.

See [make av available in your shell](installation.md#make-av-available-in-your-shell).

### Cargo cannot compile the package

Check your Rust version and native build tools. Cargo compiles the CLI from source.

See [installation prerequisites](installation.md#prerequisites).

## Project configuration

### Configuration already exists

`init` and `import-env` create a new file. Use a fresh project directory or an unused `--config` path.

### Unknown environment or override name

Define the environment in `av.toml`. An override can replace an existing value name, but cannot add a new one.

### Missing secret or invalid value type

Check the project name in the secret reference and the selected environment. Run `av check`; required generic secrets are checked after unlocking the local vault.

See [configuration and delivery](configuration-and-delivery.md).

## Credential permissions

### Direct release denied

From the operator terminal, inspect the policy:

```text
av secret policy NAME
```

Grant the exact executable and arguments. Use the same configuration, environment, and working directory for the grant and the run.

### Connection version changed

Inspect the record in the relevant vault:

```text
av connect show ID
av protected connect show ID
```

Use the local or protected command as appropriate. Review the new version before updating the project reference or granting access again.

## Action configuration

### Broker rejects the project

The current broker workflow requires exactly one selected connection value. Its version and command must match the saved recipe.

### Credential edits or action saves are unavailable

Pause actions in **Settings** before editing the service configuration.

### A saved action cannot run

Saving revokes the affected permissions. Grant the exact saved recipe again, then enable actions.

See [actions and approvals](actions-and-approvals.md).

## Waiting or expired actions

### Broker approval times out

The CLI waits for up to 300 seconds. Start a new matching request and keep it running while you review it.

### An approved action expired or was already used

Approval allows one attempt. Review its current state and request a new matching attempt.

### A reconnecting client cannot execute or finish

Authority belongs to the original live CLI connection. A public ID cannot restore it. Start a new request.

The requesting CLI executes automatically after approval. There is no separate resume command.

## MCP Apps

### The client cannot initialize

Check that the client advertises MCP Apps support and that the adapter includes its App assets. Release packages embed those assets.

Clients without Apps support are refused; there is no chat fallback.

### The session cannot decide

Enroll the exact session ID displayed by the App in the authenticated console. Check whether the session expired and whether it adopted this request.

### Request adoption is refused

Keep the original `av run` process running. Use its existing request ID and the exact connection version, host, and command.

The request must still be pending and cannot belong to another MCP session. See the [MCP Apps workflow](mcp-apps.md).

## Console and proxy

### The console is unavailable

Check that the daemon is configured with `AVD_APPROVAL_UI=1` and includes web assets. The console uses loopback port `14323`.

### Proxy settings are rejected

The broker endpoint is fixed at `http://127.0.0.1:14322`. Saved settings cannot redirect it to another endpoint.

## Report a problem

Include:

- The CLI version and operating system.
- The delivery mode you used.
- The command shape, with sensitive arguments removed.
- The error message, after checking it for secrets.

Do not attach vaults, key envelopes, recovery files, passphrases, proxy capabilities, or raw secret environments.

Use synthetic credentials and a disposable development broker for proxy debugging. Do not broaden permissions or copy credentials into prompts to get past an error.
