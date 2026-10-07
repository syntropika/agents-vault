# Core concepts

Four pieces determine how a command gets a secret: project configuration, a stored credential, permission, and approval.

## Project configuration

`av.toml` declares what your project needs:

- **Public values**, such as `APP_ENV = "development"`.
- **Secret references**, such as `secret://example/token`.
- **Environment overrides**, such as a different public value for production.

A reference does not give the project access to a secret. `av check` validates the configuration; `av placeholders` writes a shareable dotenv template.

[Configure your project →](configuration-and-delivery.md)

## Credentials and connections

A **secret** is an encrypted value with a name. A **connection** also records a destination host and version.

There are two separate stores: the local vault used for direct delivery, and the installed service vault. Adding a credential to one does not add it to the other.

Storage currently uses SQLCipher. Native keyring adapters are planned.

[Manage credentials →](credential-lifecycle.md)

## Permission and approval

**Permission** defines which command may use a credential. New credentials start with no permission to release their values.

**Approval** authorizes a matching run. Having permission may still require approval each time. Unlocking the vault does not approve execution.

For a proxy workflow, an **action** is a saved command recipe with a destination, credential version, duration, and request limits. Approving it permits one attempt.

[Configure and approve an action →](actions-and-approvals.md)

## Delivery modes

| Mode | What happens | Use it for |
| --- | --- | --- |
| Direct | The command receives the real secret in its environment. | Code you trust with that value. |
| Proxy preview | A proxy running as your user adds the credential to outgoing requests. | Same-user experiments; this does not protect custody from that user. |
| Brokered proxy | An installed service adds the synthetic credential to outgoing requests. | Reviewed synthetic actions with a matching recipe. |

Proxy commands keep the original HTTPS destination. `av run` supplies temporary proxy settings, so you do not rewrite the API URL.

**Important:** a proxy does not isolate the command or block all other network traffic. Read [limits and trust](limits-and-trust.md) before choosing a mode.
