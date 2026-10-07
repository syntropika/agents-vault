# Agents Vault (`av`)

Local-first project configuration, encrypted credentials, and reviewed CLI actions.
Keep readable references in `av.toml`, then choose how a trusted command receives its values.

- **Configure:** validate project values, import dotenv files, and generate secret placeholders.
- **Deliver:** run a trusted command with approved environment variables.
- **Review:** request bounded proxy actions through the local console or a compatible MCP Apps harness.

Direct delivery gives the command the real secret. Proxy actions currently use synthetic credentials; protected custody and installed-platform verification remain incomplete. See [limits and trust](https://av.syntropika.ai/docs/limits-and-trust/).

## Get started

Install from [crates.io](https://crates.io/crates/agents-vault) with Rust 1.88 or newer:

```sh
cargo install agents-vault --locked
av --help
```

See [installation](https://av.syntropika.ai/docs/installation/) for platform prerequisites and updates, then follow the [quickstart](https://av.syntropika.ai/docs/quickstart/). Credential administration and permission changes belong to the operator.

## Guides

| You want to… | Read |
| --- | --- |
| Resolve project variables and choose a delivery mode | [Configuration and delivery](https://av.syntropika.ai/docs/configuration-and-delivery/) |
| Add, rotate, revoke, or remove credentials | [Credential lifecycle](https://av.syntropika.ai/docs/credential-lifecycle/) |
| Configure reviewed commands and approvals | [Actions and approvals](https://av.syntropika.ai/docs/actions-and-approvals/) |
| Fix a failed command or approval | [Troubleshooting](https://av.syntropika.ai/docs/troubleshooting/) |

Read the [documentation](https://av.syntropika.ai/docs/) or the [agent index](https://av.syntropika.ai/llms.txt). Both come from the same maintained guides.

## Development

Build from source with `cargo build --locked -p agents-vault --bin av`. Start with the [crate map](https://github.com/syntropika/agents-vault/blob/main/docs/crate-map.md), [implementation status](https://github.com/syntropika/agents-vault/blob/main/docs/implementation-status.md), and [work queue](https://github.com/syntropika/agents-vault/blob/main/docs/work-queue.md).

For integration details, see [connections](https://github.com/syntropika/agents-vault/blob/main/docs/local-connections.md), [console and MCP approvals](https://github.com/syntropika/agents-vault/blob/main/docs/approval-flow.md), and [storage adapters](https://github.com/syntropika/agents-vault/blob/main/docs/storage-adapters.md).
