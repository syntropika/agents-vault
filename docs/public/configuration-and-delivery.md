# Configuration and delivery

`av.toml` describes a project and its requested values. It contains public literals or credential references. A reference describes what a command needs; it does not grant permission to release a credential.

## Choose a delivery path

| Path | What the command receives | Current use |
| --- | --- | --- |
| Public configuration | Selected literal values in its environment | Local project configuration |
| Direct secret delivery | Real selected secret values in its environment | Explicitly trusted commands |
| Same-user proxy preview | A placeholder and proxy settings; the proxy inserts a credential upstream | Synthetic experiments; no protected custody |
| Brokered host proxy | An action capability and temporary proxy settings; the broker holds the synthetic credential | Approved synthetic actions with an installed matching recipe |

Direct delivery cannot hide a value from the recipient. Proxy delivery avoids giving the original credential as the selected environment value, but requires a compatible command and a trustworthy broker boundary. It does not confine the host command. Read [limits and trust](limits-and-trust.md) before choosing it.

## Declare values

The current schema is `2`. Values support scalar `string`, `integer`, and `boolean` types. Each declaration has at most one source:

```toml
schema = 2

[project]
id = "example"

[values.APP_ENV]
type = "string"
value = "development"

[values.SERVICE_TOKEN]
type = "string"
secret = "secret://example/token"
required = true

[environments.production.values.APP_ENV]
type = "string"
value = "production"
```

Select an environment with `av check --env production` or `av run --env production -- COMMAND`. Overrides replace declarations for existing value names. They cannot introduce unknown names. Interpolation and executable resolver expressions are unsupported. Secret references must belong to the declared project.

The default configuration path is `./av.toml`. `av --config PATH` selects another file. Local direct-vault commands also accept `--vault PATH`; installed protected administration rejects these overrides.

## Reference a broker connection

A proxy project uses a versioned connection declaration:

```toml
schema = 2

[project]
id = "example"

[values.SERVICE_TOKEN]
type = "string"
connection = { id = "service/work", version = 1 }
delivery = "proxy"
required = true
```

This is a separate example from the direct configuration above. The current broker path requires exactly one selected connection value and no additional selected values. The broker independently checks the connection version and the installed recipe. A local direct-vault connection is never copied to the service vault automatically.

`av check` checks connection declarations structurally; it does not verify the service's credential version or grant. `av placeholders` emits `<AV_CONNECTION:service/work@1>` for this reference without fetching its credential.

The base CLI is provider-neutral. A label such as `service/work` does not establish API permissions or provider compatibility.

With a matching synthetic recipe, `av run -- COMMAND` or `av run --broker -- COMMAND` keeps its original broker connection open while waiting for a decision. Approval lets that CLI execute automatically. The printed request ID can be used to review or explicitly adopt the live request through MCP; it does not let another connection execute it. See [actions and approvals](actions-and-approvals.md).
