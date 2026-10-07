# Agents Vault (`av`)

Local-first project configuration, encrypted credentials, and reviewed CLI actions.
Keep readable references in `av.toml`, then choose how a trusted command receives its values.

- **Configure:** validate project values, import dotenv files, and generate secret placeholders.
- **Deliver:** run a trusted command with approved environment variables.
- **Review:** request bounded proxy actions through the local console or a compatible MCP Apps harness.

Direct delivery gives the command the real secret. Proxy actions currently use synthetic credentials; protected custody and installed-platform verification remain incomplete. See [limits and trust](docs/public/limits-and-trust.md).

## Get started

With Rust 1.88 or newer, build from this checkout:

```sh
cargo build --locked -p av --bin av
./target/debug/av --help
```

Follow the [quickstart](docs/public/quickstart.md) to create a project, run public configuration, and add a direct secret. Credential administration and permission changes belong to the operator.

## Guides

| You want to… | Read |
| --- | --- |
| Resolve project variables and choose a delivery mode | [Configuration and delivery](docs/public/configuration-and-delivery.md) |
| Add, rotate, revoke, or remove credentials | [Credential lifecycle](docs/public/credential-lifecycle.md) |
| Configure reviewed commands and approvals | [Actions and approvals](docs/public/actions-and-approvals.md) |
| Fix a failed command or approval | [Troubleshooting](docs/public/troubleshooting.md) |

The [documentation index](docs/public/index.md) is also readable by agents. The [public website](website/README.md) publishes the same guides as human pages, Markdown, and `llms.txt` exports.

## Development

Start with the [crate map](docs/crate-map.md), [implementation status](docs/implementation-status.md), and [work queue](docs/work-queue.md).

For integration details, see [connections](docs/local-connections.md), [console and MCP approvals](docs/approval-flow.md), and [storage adapters](docs/storage-adapters.md).
