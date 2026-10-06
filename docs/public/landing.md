# Agents Vault

Local configuration. Explicit credential access.

Manage project values and encrypted credentials on your machine. Give a trusted command the values it needs, or explore reviewed proxy actions with synthetic credentials.

**Alpha prototype:** direct delivery exposes real values to its recipient. Protected proxy custody and installed macOS acceptance remain under development.

[Start with the CLI](quickstart.md) · [Read the docs](index.md) · [Understand the limits](limits-and-trust.md)

## Keep project configuration readable

Declare public values and credential references in `av.toml`. Select environment overrides, validate the configuration, and generate placeholder dotenv files without resolving credentials into them.

## Grant a command deliberately

New credentials have no release grants. For direct secrets, choose the executable and arguments, review the policy, and approve matching runs from an operator terminal.

## Review an agent's requested action

The local operator console manages credentials, one active action recipe, permissions, and decisions. The CLI waits for approval. A compatible MCP Apps harness can adopt that live request and present its frozen command, destination, version, and limits for review.

## Know the current boundary

SQLCipher is the initial storage adapter. Native keyrings are planned. Proxy actions currently use synthetic credentials; the host command is not confined. Linux and macOS component tests exist, while installed-platform and whole-agent custody gates remain open.

[Build the prototype](quickstart.md) · [See demonstrated behavior](../prototype-status.md)
