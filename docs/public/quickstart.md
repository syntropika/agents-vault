# Quickstart

This guide runs public project configuration without creating a vault. It then shows how direct secret delivery is authorized. Proxy execution has a separate [action workflow](actions-and-approvals.md).

## Build from a checkout

Use Rust 1.88 or newer. From the repository root:

```sh
cargo build --locked -p av --bin av
./target/debug/av --help
```

The executable is `target/debug/av`. The commands below use `av`; use its absolute path or add that directory to your shell's `PATH` before changing directories. There is no package-manager installation claim in this guide. Platform evidence and packaging progress are listed in [implementation status](../implementation-status.md).

## Run public configuration

In a new project directory:

```sh
av init --project example
```

Add this declaration to the generated `av.toml`:

```toml
[values.APP_ENV]
type = "string"
value = "development"
required = true
```

Check the file and run a trusted command. On Linux or macOS this small example prints only the public value:

```sh
av check
av run -- /usr/bin/printenv APP_ENV
```

Expected output includes `development`. `av check` validates the selected configuration; it does not approve future execution.

## Add a direct secret

From a trusted operator terminal, initialize the local vault once:

```sh
av setup --direct --recovery-file /private/path/av.recovery
av status
```

Replace `/private/path/av.recovery` with a private location outside the agent's reach and move the recovery material offline. Setup prompts for a passphrase. `av status` reports local initialization only; it does not check an installed broker. `av unlock --direct` verifies a passphrase for that process and immediately closes the vault.

Add a value without putting it in a shell argument:

```sh
av secret add token
```

Add its reference to `av.toml`:

```toml
[values.SERVICE_TOKEN]
type = "string"
secret = "secret://example/token"
required = true
```

Choose an absolute executable and arguments that you trust with the value. Grant that exact command from the operator terminal, then run it with the same arguments:

```text
av secret grant token -- /absolute/path/to/trusted-command argument
av run -- /absolute/path/to/trusted-command argument
```

Replace the executable and argument before running these commands. The default grant requires approval for each matching run. The prompt asks you to type `approve`. Direct delivery gives the child the real secret; its loaded code and subprocesses may read it. Changes to the executable, arguments, selected environment, configuration, or working directory can invalidate a grant. See [limits and trust](limits-and-trust.md).

## Import an existing dotenv file

Import requires a new configuration path, so use a fresh project directory or an explicit unused `--config` path:

```sh
av import-env .env --project imported --public APP_ENV
av check
av placeholders --output .env.example
```

Every assignment is secret unless explicitly named with `--public`. Repeat the option for additional public values. Imported secrets start without release grants. The source `.env` remains plaintext; review the import and handle that file separately. The placeholder file contains public literals and references, never resolved credentials.
