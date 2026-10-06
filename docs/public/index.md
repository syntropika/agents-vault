# Agents Vault documentation

Agents Vault (`av`) is a local-first alpha prototype for project configuration, encrypted credentials, and reviewed CLI actions. Start with local configuration and direct delivery to code you trust. Use synthetic credentials for proxy experiments.

## Find your next step

| You want to… | Read |
| --- | --- |
| Build the CLI and run a small project | [Quickstart](quickstart.md) |
| Choose between environment delivery and proxy delivery | [Configuration and delivery](configuration-and-delivery.md) |
| Add, replace, revoke, or remove a credential | [Credential lifecycle](credential-lifecycle.md) |
| Configure the command an agent may request | [Actions and approvals](actions-and-approvals.md) |
| Understand what the prototype protects | [Limits and trust](limits-and-trust.md) |
| Resolve a failed command or approval | [Troubleshooting](troubleshooting.md) |

These files are also the plain Markdown documentation for agents. Follow their relative links for the full workflow. An agent can inspect public configuration and request an action; credential administration and permission changes belong to the operator. Never place credentials, passphrases, or recovery keys in an agent prompt.

The [prototype status](../prototype-status.md) records test evidence and outstanding release gates. The [storage adapter notes](../storage-adapters.md) describe SQLCipher and planned native integrations. This documentation does not establish production readiness.
