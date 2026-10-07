# Credential lifecycle

Add credentials through a hidden prompt, inspect their permissions, and revoke access when it is no longer needed.

## Choose the vault

| Store | Commands | Used for |
| --- | --- | --- |
| Local vault | `av secret` and `av connect` | Direct delivery and local connection records. |
| Installed service vault | `av protected connect` | Synthetic broker actions. |

These stores have separate records, permissions, and unlock state. Adding a credential to one does not add it to the other.

Run credential administration from a trusted operator terminal.

## Generic direct secrets

After [creating the local vault](quickstart.md), store a secret:

```sh
av secret add token
av secret policy token
```

Enter the value at the hidden prompt. `policy` shows permissions without printing the credential. New secrets have no release grants; follow the [quickstart](quickstart.md) to grant a command access.

A project refers to this secret as `secret://example/token`, where `example` is its project ID.

### Rotate or revoke

```sh
av secret rotate token
av secret revoke token
```

- **Rotate** replaces the value and retains its existing release policy. Review that policy if access should change.
- **Revoke** removes release grants. A command that already received the old value may still retain it.

Use `av secret list` to list names without values. There is currently no generic-secret delete subcommand.

## Local connection records

A connection adds a destination host and a version to a credential:

```sh
av connect add service/work --host api.example.test
av connect show service/work
```

`add` asks for the credential at a hidden prompt. It does not contact the provider to validate it. `show` displays metadata and policy, including the current version; `av connect list` lists records without values.

New connections deny release. Creating this record alone does not make it usable by `av run`. Use synthetic values for proxy experiments.

### Replace a connection

Review the current version, then replace it:

```sh
av connect show service/work
av connect replace service/work --if-version 1
```

Use the version returned by `show`. In this example, replacement creates version `2` and invalidates the existing grants.

### Revoke or disconnect

For the example now at version `2`:

```sh
av connect revoke service/work --if-version 2
av connect disconnect service/work --if-version 2
```

- **Revoke** removes release grants.
- **Disconnect** removes the local credential and its grants. Version history remains so stale changes can be rejected.

Neither operation revokes the credential at its issuing service. Rotate or revoke it there separately.

## Installed service records

First complete the [platform service installation](installation.md#protected-services-and-mcp). `av protected setup` initializes an already installed service; it does not install one.

From the operator terminal:

```text
av protected connect add service/work --host api.example.test
av protected connect show service/work
av protected connect grant service/work 1
```

The grant must match the observed version and an operator-configured action recipe. Keep credentials synthetic while the [protected custody checks](limits-and-trust.md) remain incomplete.

Administration uses the privileged operator helper. The agent-facing socket cannot administer the vault. See the [operator connection guide](../local-connections.md) for setup, replacement, and locking details.

## Recovery and storage

Storage currently uses SQLCipher. Native keyrings and backend selection are planned.

SQLCipher supports encrypted backup, restore, key rotation, and recovery. Use `av secret --help` to inspect those commands before starting.

Keep recovery material offline and outside agent-accessible paths. Rotating keys does not change the keys needed by old backups.

For adapter design details, see [storage adapters](../storage-adapters.md).
