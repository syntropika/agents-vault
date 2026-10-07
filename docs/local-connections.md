# Local connections

A connection is a versioned credential record identified by `provider/name` and restricted to one exact HTTPS host. Its provider name is a local label, not proof that the credential has any particular provider scope. New records deny release by default.

## Direct-user vault

Initialize the local vault and keep recovery material outside agent-accessible paths:

    av setup --direct --recovery-file /private/path/av.recovery
    av status
    av unlock --direct

Add and inspect a connection from an operator terminal:

    av connect add service/work --host api.example.test
    av connect list
    av connect show service/work

`add` prompts for the credential without echo and does not call the provider to validate it. List and show print metadata and release policy, never the value. Replace, revoke, and disconnect require the version observed in `show`:

    av connect replace service/work --if-version 1
    av connect revoke service/work --if-version 2
    av connect disconnect service/work --if-version 2

Replacement rotates the local version and invalidates prior grants. Disconnect removes the local credential. Neither action revokes a credential at its issuing service, and an already running direct recipient may retain a value it received.

The local connection commands manage records; they do not grant general use of a credential or automatically inject it into `av run`. The protected broker uses its own service vault, never this user-owned direct vault. There is no provider-specific shortcut in the base CLI.

## Installed service operator

On Linux and macOS, an installed service can own a separate encrypted vault. Its operator commands use a fixed privileged helper and private control channel:

    av protected setup --recovery-file /private/root-owned/path/av.recovery
    av protected status
    av protected connect add service/work --host api.example.test
    av protected connect list
    av protected connect show service/work
    av protected connect grant service/work 1
    av protected connect replace service/work 1
    av protected connect revoke service/work 2
    av protected connect disconnect service/work 2
    av protected unlock
    av protected lock

Setup initializes the service vault; it does not itself install the service. The recovery path must be private and root-owned. The helper prompts for passphrases and credentials outside CLI arguments and environment variables. The agent-facing socket cannot administer the vault. A trusted terminal and harness policy must still stop an agent sharing the login account from invoking privileged operator commands.

For the synthetic host-proxy path, an operator installs a private recipe with `connection`, `connection_version`, exact `host`, pinned `command`, local test upstream and CA, quotas, and `host_client = true`. It contains no credential or `secret_name`. With the broker locked, `av protected connect grant service/work 1` binds that exact recipe to version 1. Replacement or disconnect clears the grant. The broker currently accepts only credentials beginning with `av-synthetic-` on this path.

## Broker task lifecycle

The implementation registers a configured command and host, then requires a decision before execution. A project may declare one proxy connection reference:

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

With an installed matching recipe, `av run -- /absolute/path/to/command` requests the task. From a trusted operator terminal, review and decide the exact pending request while the original CLI remains running:

    av protected review REQUEST_ID
    av protected approve REQUEST_ID

`av protected deny REQUEST_ID` rejects it instead. The installed operator helper shows the broker-owned review before asking for the vault passphrase. A selected project environment currently supports exactly one connection value and no other values in this path. The explicit synthetic fixture form is:

    av run --broker --broker-connection demo/fixture --broker-host api.example.test -- /absolute/path/to/configured-fixture-command

The MCP adapter requires MCP Apps and operator enrollment of its exact session. Start `av run` first and keep it connected. `request_proxy_task` adopts the existing request ID plus its exact connection, version, host and command; `review_request` reviews requests adopted by that enrollment. Approval allows one attempt within 60 seconds and the waiting CLI executes automatically. The CLI waits at most five minutes for a decision. Closing its connection revokes pending approvals and active grants; reconnecting cannot recover execution authority. `--resume` is not supported.

Local direct-vault records are never copied into the protected service automatically. The authenticated local console and private operator terminal remain independent approval routes; the MCP adapter does not automatically fall back to a browser link. See [local approvals and MCP Apps](approval-flow.md).

Current broker policies are fixture-oriented. An exact host does not constrain an API path or operation, a provider response may reflect the credential, and a command that ignores the proxy cannot be assumed safe. Do not treat these commands as broad provider support or a release-level custody guarantee.

