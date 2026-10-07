# Quickstart

Run your first project variable, then give a trusted command access to a secret. The public-variable example needs no vault.

## Install the CLI

Install [Rust 1.88 or newer and the required build tools](installation.md#prerequisites), then run:

```sh
cargo install agents-vault --locked
av --help
```

The package is named `agents-vault`; the command is `av`.

## Run public configuration

### 1. Create a project

In a new project directory, run:

```sh
av init --project example
```

This creates `av.toml`.

### 2. Add a variable

Add this block to `av.toml`:

```toml
[values.APP_ENV]
type = "string"
value = "development"
required = true
```

### 3. Check and run

On Linux or macOS:

```sh
av check
av run -- /usr/bin/printenv APP_ENV
```

The command prints `development`.

`av check` validates your configuration. It does not approve a later run.

## Add a direct secret

**The command will receive the real secret.** Choose code you trust, including its libraries and subprocesses. Use a trusted operator terminal for these steps.

### 1. Create the local vault

Initialize the vault once:

```sh
av setup --direct --recovery-file /private/path/av.recovery
av status
```

Replace the recovery path with a private location outside the agent's reach. Setup asks for a passphrase. Move the recovery file offline after creation.

### 2. Store the secret

```sh
av secret add token
```

Enter its value at the hidden prompt. Avoid putting it in a command argument.

### 3. Reference it in your project

Add this block to `av.toml`:

```toml
[values.SERVICE_TOKEN]
type = "string"
secret = "secret://example/token"
required = true
```

The project stores this reference, not the value.

### 4. Grant and run the command

Replace the executable and argument below with the exact command you trust:

```text
av secret grant token -- /absolute/path/to/trusted-command argument
av run -- /absolute/path/to/trusted-command argument
```

The default grant asks for approval on each matching run. Review the prompt and type `approve` to proceed.

Use the same executable, arguments, configuration, environment, and working directory for the grant and the run. Changing them can invalidate the grant. Read [limits and trust](limits-and-trust.md) before using real credentials.

## Import an existing dotenv file

Use a fresh project directory or an unused `--config` path. Import creates a new configuration file:

```sh
av import-env .env --project imported --public APP_ENV
av check
av placeholders --output .env.example
```

- Every assignment is stored as a secret unless you name it with `--public`. Repeat that option for more public values.
- Imported secrets have no release grants. Grant the intended command before running it.
- `.env.example` contains public values and unresolved references.
- The original `.env` stays plaintext. Review and handle that file separately.

## Next steps

- [Configuration and delivery](configuration-and-delivery.md) — environments, value types, and proxy references.
- [Credential lifecycle](credential-lifecycle.md) — rotation and revocation.
- [Actions and approvals](actions-and-approvals.md) — the separate synthetic proxy workflow.

Installing the CLI does not install a protected service. See [installation](installation.md#protected-services-and-mcp) if you need that workflow.

For verified platform workflows and remaining checks, see [implementation status](../implementation-status.md).
