# Credential lifecycle

Agents Vault has a local direct-user vault and an installed service vault. Choose the vault first: their records, permissions, and unlock state are separate.

## Local connection records

After [initializing the direct vault](quickstart.md), add a record from a trusted operator terminal:

```sh
av connect add service/work --host api.example.test
av connect list
av connect show service/work
```

Use a synthetic value when experimenting with a proxy. `add` uses a hidden prompt and does not contact the provider to validate the credential. `list` and `show` print metadata and policy without the value. New connections deny release. These commands alone do not make a connection usable by `av run`.

Review the current version before changing a connection:

```sh
av connect replace service/work --if-version 1
av connect revoke service/work --if-version 2
av connect disconnect service/work --if-version 2
```

These illustrate a replacement from version 1 to 2. Use the version actually returned by `show`. Replacement increments the version and invalidates existing grants. Revocation removes release grants. Disconnect removes the local credential and its grants; the system retains version history to reject stale changes.

Local changes do not revoke a credential at its issuing service. Revoke or rotate it there separately. A direct recipient may retain a value already delivered to it.

## Generic direct secrets

Generic secrets use project references such as `secret://example/token`:

```sh
av secret add token
av secret policy token
av secret rotate token
av secret revoke token
```

Unlike replacing a connection, rotating a generic secret retains its existing release policy. Review that policy if the replacement should have different access. `av secret list` lists generic secret names without credential values. The current generic secret CLI has no delete subcommand.

## Installed service records

Service installation is a separate prerequisite. `av protected setup` initializes an already installed service's vault. Administration uses a privileged operator helper and a private channel; the agent-facing socket cannot administer the vault.

```text
av protected connect add service/work --host api.example.test
av protected connect show service/work
av protected connect grant service/work 1
```

The grant must match an operator-configured recipe and the observed version. Keep proxy credentials synthetic while custody and installed-platform gates remain open. The [operator connection guide](../local-connections.md) describes setup, replacement, and service locking in detail.

## Recovery and storage

The current storage adapter is SQLCipher. Native keyrings and backend selection are planned. SQLCipher supports encrypted backup, restore, key rotation, and recovery commands; consult `av secret --help` before choosing a recovery operation. Keep recovery material offline and outside agent-accessible paths. Old backups retain their original keys after rotation.

See [storage adapters](../storage-adapters.md) for the persistence boundary and the distinction between future native credential storage and native unlock.
