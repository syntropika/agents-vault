# CLI reference

The package is `agents-vault`; the command is `av`. Use built-in help for every option in your installed version:

```sh
av --help
av run --help
av secret --help
```

## Project commands

| Command | Purpose |
| --- | --- |
| `av init --project NAME` | Create a new `av.toml`. |
| `av check` | Validate the selected configuration. |
| `av import-env FILE --project NAME` | Import dotenv values. Add `--public NAME` for each value that should stay public. |
| `av placeholders --output FILE` | Write public values and unresolved secret references. |
| `av run -- /absolute/path/to/command args` | Check permissions, resolve values, and launch the command. |

Add `--env NAME` to `check`, `placeholders`, or `run` to select an environment. See [configuration and delivery](configuration-and-delivery.md).

`av run` returns the child command's exit status. If release is denied, the command does not receive the credential.

## Local vault commands

### Setup and status

| Command | Purpose |
| --- | --- |
| `av setup --direct --recovery-file PATH` | Create the local vault and recovery material. |
| `av status` | Check whether the local vault is initialized. |
| `av unlock --direct` | Verify the passphrase for this process. It does not cache an unlocked session. |

`av status` does not check an installed broker.

### Credentials

| Command | Purpose |
| --- | --- |
| `av secret add NAME` | Store a generic secret through a hidden prompt. |
| `av secret grant NAME -- /absolute/path/to/command args` | Grant that exact command access. |
| `av secret policy NAME` | Show the release policy without the value. |
| `av secret rotate NAME` | Replace the value while retaining its policy. |
| `av secret revoke NAME` | Remove release grants. |
| `av connect --help` | Manage versioned connections. |

Run administration commands from an operator-controlled terminal. Enter credentials and passphrases at prompts, not in shell arguments or agent messages.

For backup, restore, and recovery options, use `av secret --help`. See [credential lifecycle](credential-lifecycle.md) before rotating keys or connections.

## Installed service commands

```sh
av protected --help
```

These commands administer an **already installed** protected service through its privileged operator helper. Installing the CLI with Cargo does not install that service.

For brokered runs, set the non-secret `AVD_AGENT_SOCKET` to the installed agent socket. See [actions and approvals](actions-and-approvals.md).

## Global options

| Option | Purpose |
| --- | --- |
| `--config PATH` | Use a project file other than `./av.toml`. |
| `--vault PATH` | Select the local direct vault. Protected administration rejects this override. |
| `--help` | Show command help. |
| `--version` | Show the CLI version. |

Place global options before the command, for example `av --config ./other.toml check`.
