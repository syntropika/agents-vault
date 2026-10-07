# CLI reference

Install the `agents-vault` crate and invoke `av`. Use `av help COMMAND` or `av COMMAND --help` for the complete arguments supported by your installed release.

## Project commands

| Command | Purpose |
| --- | --- |
| `av init --project NAME` | Create a new `av.toml`. |
| `av check` | Validate the selected configuration. |
| `av import-env FILE --project NAME` | Import dotenv values into a new configuration; only explicitly selected `--public` assignments stay public. |
| `av placeholders --output FILE` | Write public literals and unresolved secret placeholders. |
| `av run -- /absolute/path/to/command args` | Resolve permitted values and launch the exact command. |

`check`, `placeholders`, and `run` accept `--env NAME` to select a declared environment. See [configuration and delivery](configuration-and-delivery.md).

## Local vault commands

| Command | Purpose |
| --- | --- |
| `av setup --direct --recovery-file PATH` | Create the local direct vault and new recovery material. |
| `av status` | Report local initialization without unlocking. |
| `av unlock --direct` | Verify the passphrase for this process; no persistent unlock is cached. |
| `av secret --help` | Add, rotate, remove, inspect policy, or grant a named secret. |
| `av connect --help` | Manage local versioned connections. |

Credential values and passphrases are entered through protected prompts rather than shell arguments. Administration belongs to the operator; an agent should not request credential values. See [credential lifecycle](credential-lifecycle.md).

## Installed service commands

`av protected --help` lists commands for an already installed protected service. These use the privileged operator helper and private administration channel. Cargo installation of `av` alone does not install that service.

Brokered `av run` requests use the non-secret `AVD_AGENT_SOCKET` setting. See [actions and approvals](actions-and-approvals.md) and [MCP Apps](mcp-apps.md).

## Global options

| Option | Purpose |
| --- | --- |
| `--config PATH` | Select a project file instead of `./av.toml`. |
| `--vault PATH` | Select the local direct vault. Protected administration rejects this override. |
| `--help` | Display command help. |
| `--version` | Display the CLI version. |

`av run` returns the child command's exit status. A denied release fails before the command receives a credential.
