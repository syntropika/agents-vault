# Configuration and delivery

Use `av.toml` to declare project variables and credential references. This page shows how to define values, select an environment, and reference a proxy connection.

## Choose a delivery path

| Path | The command receives | Current use |
| --- | --- | --- |
| Public configuration | Public values in its environment. | Local project variables. |
| Direct secrets | Real secret values in its environment. | Explicitly trusted code. |
| Proxy preview | A placeholder and temporary proxy settings. | Synthetic experiments under your user identity. |
| Brokered proxy | A temporary proxy capability and settings. | Approved synthetic actions through an installed service. |

**Direct delivery exposes the secret to the command.** A proxy avoids handing it the original credential, but does not isolate the command. See [limits and trust](limits-and-trust.md).

## Declare values

The current schema is `2`. Start with a public value:

```toml
schema = 2

[project]
id = "example"

[values.APP_ENV]
type = "string"
value = "development"
```

Supported scalar types are `string`, `integer`, and `boolean`. Each value may have at most one source. Use `required = true` when the value must be present.

### Add a direct secret reference

```toml
[values.SERVICE_TOKEN]
type = "string"
secret = "secret://example/token"
required = true
```

The project name in the reference must match `[project].id`. Store and grant the secret separately; see the [quickstart](quickstart.md).

### Select an environment

Add an override for an existing value:

```toml
[environments.production.values.APP_ENV]
type = "string"
value = "production"
```

Then select it when checking or running:

```sh
av check --env production
av run --env production -- /usr/bin/printenv APP_ENV
```

The run example uses Linux or macOS. Overrides replace existing declarations; they cannot introduce new value names. Interpolation and executable resolver expressions are unsupported.

### Select another file

`av` reads `./av.toml` by default. Use `av --config PATH` to select another file.

Local vault commands also accept `--vault PATH`. Installed protected administration rejects those project and vault overrides.

## Reference a broker connection

For a proxy action, use a versioned connection instead of a direct secret reference:

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

Use this as a separate configuration. The current broker workflow requires **exactly one selected connection value**, with no additional selected values.

Before running it:

1. Add the synthetic credential to the installed service vault.
2. Configure and grant a matching action recipe.
3. Pin the recipe's current connection version in `av.toml`.

A local connection is not copied to the service automatically. The label `service/work` does not establish provider compatibility or API permissions.

### Validate or export the declaration

`av check` checks the declaration's structure. It does not verify the service's current version or permissions.

`av placeholders` emits `<AV_CONNECTION:service/work@1>` without retrieving the credential.

### Run the action

Use the exact executable and arguments from the saved recipe:

```text
av run -- /absolute/path/to/configured-command argument
```

The CLI waits for approval, then executes automatically on the same connection. `av run --broker -- COMMAND` also selects the project's connection.

Follow [actions and approvals](actions-and-approvals.md) for the full review workflow.
