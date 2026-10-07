# Introduction

Agents Vault (`av`) manages project configuration, encrypted credentials, and reviewed CLI actions locally. Declare readable references in `av.toml`, then decide how a trusted command may use their values.

## Start here

1. [Install from crates.io](installation.md).
2. [Run your first project](quickstart.md).
3. [Understand configuration, permission, and delivery](concepts.md).

## How it works

A project requests a value. The vault checks the operator's permission. A matching run receives direct environment values, or requests a bounded synthetic proxy action for review. Project configuration cannot widen a stored grant.

Direct delivery gives the command the real secret. Proxy actions currently use synthetic credentials; protected custody and installed-platform verification remain incomplete. Read [limits and trust](limits-and-trust.md) before choosing a workflow.

## Guides

| You want to… | Read |
| --- | --- |
| Resolve variables and select a delivery mode | [Configuration and delivery](configuration-and-delivery.md) |
| Add, rotate, revoke, or remove credentials | [Credential lifecycle](credential-lifecycle.md) |
| Configure and review an action | [Actions and approvals](actions-and-approvals.md) |
| Approve from a compatible harness | [MCP Apps](mcp-apps.md) |

## Reference and help

Use the [CLI reference](cli-reference.md) for command groups and [troubleshooting](troubleshooting.md) for failed requests. The [implementation status](../implementation-status.md) records platform evidence and remaining gates.

## For agents

These guides are also published as Markdown, [an agent index](/llms.txt), and [a complete text bundle](/llms-full.txt). An agent can inspect public configuration and request an action; credential administration and permission changes belong to the operator. Never place credentials, passphrases, or recovery keys in an agent prompt.
