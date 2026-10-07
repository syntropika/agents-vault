# Introduction

Agents Vault (`av`) lets you define project variables, store credentials locally, and choose which commands may use them.

Your project keeps readable references in `av.toml`. The vault keeps the secret values.

## Start here

1. **[Install av](installation.md)** — install the CLI from crates.io.
2. **[Run your first project](quickstart.md)** — load a public variable, then authorize a trusted command to use a secret.
3. **[Understand the concepts](concepts.md)** — learn how configuration, permission, and approval fit together.

## How it works

1. You declare the values a project needs in `av.toml`.
2. You grant a command permission to use a credential.
3. `av run` checks that permission and asks for approval when required.

**Direct delivery gives the command the real secret.** Use it only with code you trust. Proxy actions currently use synthetic credentials while protected custody is being verified. See [limits and trust](limits-and-trust.md).

## Guides

| I want to… | Guide |
| --- | --- |
| Define variables and environments | [Configuration and delivery](configuration-and-delivery.md) |
| Import an existing dotenv file | [Dotenv import](quickstart.md#import-an-existing-dotenv-file) |
| Add, rotate, or revoke credentials | [Credential lifecycle](credential-lifecycle.md) |
| Review a command before it runs | [Actions and approvals](actions-and-approvals.md) |
| Approve through an MCP Apps client | [MCP Apps](mcp-apps.md) |

## Reference and help

- [CLI reference](cli-reference.md) — command groups and options.
- [Troubleshooting](troubleshooting.md) — common errors and next steps.
- [Limits and trust](limits-and-trust.md) — what each mode protects and what it does not.

## For agents

The same guides are available as [an agent index](/llms.txt) and [a complete text bundle](/llms-full.txt).

An agent may inspect public configuration and request an action. The operator manages credentials and permissions. Keep credentials, passphrases, and recovery keys out of agent prompts.
