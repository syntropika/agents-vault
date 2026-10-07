# Core concepts

Agents Vault separates project configuration, stored credentials, permission, and execution. A project can request a value; it cannot grant itself access.

## Project configuration

`av.toml` holds public values and references such as `secret://example/token`. Environment overrides select different values without copying resolved secrets into the project. `av check` validates the selected configuration; `av placeholders` writes a shareable dotenv template.

See [configuration and delivery](configuration-and-delivery.md).

## Credentials and connections

A credential is an encrypted secret referenced by name. A connection adds an ID, exact destination host, version, and lifecycle around a credential. A local direct vault and an installed service vault are separate stores.

SQLCipher is the current storage adapter. Native keyrings are planned. Storage protects values at rest; it does not decide which command may receive them.

See [credential lifecycle](credential-lifecycle.md).

## Permission and approval

New credentials have no release grants. The operator grants an exact command and delivery context. A matching request may still require approval for each run. Unlocking a vault or saving an action does not approve execution.

An action is a bounded command recipe. Review shows the executable, arguments, credential version, destination, duration, and quotas. An approval permits one attempt; changing the request invalidates that decision.

See [actions and approvals](actions-and-approvals.md).

## Delivery modes

| Mode | Who receives the value? | Current use |
| --- | --- | --- |
| Direct | The approved command receives the real environment value. | Commands and dependencies you trust with the credential. |
| Proxy preview | A proxy running under your identity substitutes a credential. | Same-user experiments; it does not provide protected custody. |
| Brokered proxy | A service-held proxy inserts the synthetic credential upstream. | Reviewed synthetic actions with a matching installed recipe. |

A proxy command keeps its original HTTPS destination. `av run` supplies temporary proxy settings rather than requiring a rewritten API URL.

Read [limits and trust](limits-and-trust.md) before choosing a delivery mode.
