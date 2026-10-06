# Linux service boundary experiment

This package installs the synthetic broker as `av-broker` and its confined
runner service as `av-runner`. `systemd-sysusers` creates both non-login system
identities automatically with home `/nonexistent` and shell
`/usr/sbin/nologin`. The host agent, broker, and runner must have three distinct,
non-root UIDs. No human login account or external VM runtime is required.
This is an experimental component; real proxy credentials remain rejected.

## Installation

Build and stage the installer without changing host accounts or services:

```sh
cargo build --release -p av -p avd -p av-runner --bins
packaging/linux/install.sh --bin-dir "$PWD/target/release" --agent-uid "$(id -u)" --destdir /tmp/av-install-review
```

A real install requires root. Omitting `--destdir` installs root-owned binaries
and units, creates both identities, and reloads systemd. Every installation
requires the public `av` binary. The installer checks that it is an executable
regular file, verifies the staged copy against the source digest, and installs
it under `/usr/libexec/agents-vault/av` with `/usr/bin/av` as the public entry.
An existing `/usr/bin/av` from another installation is never replaced. The
entry and binary are root-owned in a real installation; staged copies retain
the staging user's ownership. The installer loads
the packaged AppArmor profile when the host exposes AppArmor policy control.
It does not start the services. The host needs systemd and the kernel
facilities listed in [the runner README](../../crates/av-runner/README.md).
Python is used by disposable test scripts but is not a service dependency.
It also creates `/var/lib/agents-vault` as mode 0700, owned by `av-broker`,
before the first service start. A new root-owned mode 0644 `service.env`
contains the default vault path; this configuration contains public paths,
not secrets. Existing configuration is preserved.

The offline staging check is `python3 packaging/linux/test_install_cli.py`.

```sh
sudo /usr/libexec/agents-vault/av-operator init --recovery-file /root/agents-vault.recovery
sudo systemctl enable --now agents-vault.service
```

Initialize before the first start. `init` prompts for the passphrase and its
confirmation, opens a new root-owned mode 0600 recovery file, and drops to the
broker identity before creating the vault. The recovery file's parent must
already be root-owned and mode 0700. The recovery key is not printed and the
broker cannot read its saved copy. Initialization refuses an existing vault,
an unfinished initialization, or a running broker; it shares the broker's
exclusive state lock.
A failed attempt may leave a recovery output file, including an empty file.
Inspect that file and the vault state before retrying; existing recovery output
is never overwritten.

The broker requires `agents-vault-runner.service`. The runner checks namespace
setup before reporting readiness. A blocked user namespace, seccomp filter,
AppArmor restriction, or unsupported private process mount prevents startup
and produces a diagnostic. No unconstrained execution fallback exists.

The AppArmor profile grants `userns` to the installed runner service using a
named profile with `flags=(unconfined)`. It is a scoped permission for namespace
creation, not an AppArmor confinement policy. The service unit uses a private
network namespace; the helper creates another network namespace for each task.
The kernel helper supplies the task's mount, PID, capability, and syscall
restrictions. Hosts that restrict unprivileged user namespaces must have an
AppArmor parser and permit the installed runner profile; the installer never
changes a global kernel sysctl.

The runner unit deliberately omits `ProtectKernelTunables`,
`ProtectKernelLogs`, and `ProtectHostname`. Each installs a mask or read-only
bind under `/proc`; together they prevent an unprivileged nested namespace
from mounting its own proc filesystem on the tested Ubuntu kernel. The broker
unit retains all three settings. The runner instead denies `syslog`,
`sethostname`, and `setdomainname` through systemd's syscall filter. It has no
host capabilities, uses `PrivateDevices`, and runs as an unprivileged UID;
kernel sysctl writes and `/proc/kmsg` access depend on those kernel permission
checks rather than systemd's read-only proc masks. Public sysctl and hostname
reads remain available to the runner service. The guest test checks those
denials under the actual service unit. The helper separately drops task
capabilities and denies namespace, mount, and process-memory syscalls.

## Launch and relay authority

Only the broker UID can use `/run/agents-vault-runner/launch.sock`. The runner
checks `SO_PEERCRED` before reading a launch frame, and the broker's client
checks the server UID. Root, the agent UID, and the runner UID are rejected as
launch peers. The protocol carries bounded command metadata, executable
hashes, and public CA paths. It has no vault, passphrase, approval, or secret
management operations.

The runner seals and verifies the helper and command before execution. The
broker's task relay authenticates the runner UID independently and inserts the
proxy grant. The runner receives only an unauthenticated local proxy. Public
CA files and a peer-checked relay socket live in a randomly named directory
under `/run/agents-vault`; directory contents cannot be listed by other UIDs.
The broker retains the proxy credential and approval capability.

The launch channel lifetime controls the remote task. Client disconnect, task
deadline, or runner service death kills the namespace supervisor and detached
descendants. The broker client also dies with its broker parent. Restarted
runner instances recover stale sockets under an exclusive service lock.

## Locked start and local administration

The installer configures `/var/lib/agents-vault/vault.db` as the default vault.
Configure root-owned `/etc/agents-vault/service.env` with `AVD_VAULT_PATH` and optionally
`AVD_PROXY_POLICY_PATH` to use a synthetic vault. Vault and policy files must be
private, with root/broker-owned, non-writable ancestors. Commands and helpers
must come from trusted paths. Isolated-runner policies require the installed
confined helper; a host-client policy pins a trusted host command instead.
Keep `service.env` readable by the broker; it contains public
paths and must not contain a passphrase.

A configured vault always starts locked. Startup passphrase files and daemon
stdin unlock are disabled. The local operator uses the separate admin channel:

```sh
sudo -u av-broker /usr/libexec/agents-vault/av-operator status
sudo -u av-broker /usr/libexec/agents-vault/av-operator unlock
sudo -u av-broker /usr/libexec/agents-vault/av-operator lock
sudo -u av-broker /usr/libexec/agents-vault/av-operator review REQUEST_ID
sudo -u av-broker /usr/libexec/agents-vault/av-operator approve REQUEST_ID
```

`unlock` prompts with terminal echo disabled. The passphrase travels over the
private admin Unix socket, never in the command line or environment. The
admin socket and random `admin.token` are mode 0600 and accessible only to the
broker identity. The daemon also checks the peer UID. Administration uses its own private capability. `approve` and `deny` display the frozen review and prompt for the vault
passphrase through the private administration channel. MCP form responses leave
the request pending.

Relock prevents new requests, cancels active task proxies, disconnects runners,
and drops loaded credentials and all pending approvals. Unlock creates a fresh
session; old request IDs cannot be replayed. SIGINT/SIGTERM closes the session.
A daemon restart starts locked and creates a fresh administration capability.
Systemd manages runtime-directory cleanup across crashes. The guest test covers
both orderly restart and broker/runner SIGKILL recovery under systemd PID 1.

## Disposable tests

```sh
cargo test -p avd -p av-runner
cargo build -p av -p avd -p av-runner --bins --examples
```

The Docker image runs the real installer, syntax-checks both systemd units and
the packaged AppArmor profile, then runs daemons under the installed UIDs.
It does not boot systemd as PID 1; daemon reload is stubbed only in the image.
Stage `av`, `avd`, `av-operator`, `av-runner-helper`, `av-runner-service`,
`av-runner-client`, `av-runner-canary`, and the `create-test-vault` example in an
external artifact directory and mount it at `/input-binaries:ro`:

```sh
docker build -f packaging/linux/Dockerfile.boundary-tests -t agents-vault-boundary-test:local packaging/linux
docker run --rm --security-opt seccomp=unconfined --security-opt systempaths=unconfined \
  --security-opt apparmor=YOUR_EXISTING_USERNS_TEST_PROFILE \
  -v /absolute/artifact-directory:/input-binaries:ro agents-vault-boundary-test:local
```

The tested host is Ubuntu with Linux 7.0.0-34 and
`apparmor_restrict_unprivileged_userns=1`. The existing `chatgpt` profile allowed
the test container to create user namespaces. Docker's default seccomp and
masked `/proc` mounts prevent the nested namespaces, so those outer container
restrictions were disabled for this test. No host sysctl or AppArmor policy was
changed. The container test compiles the exact packaged profile without loading it.
The separate VM test below loads it in a disposable guest kernel. Docker profiles and kernel
behavior differ across hosts; choose an existing test profile that permits
user namespaces rather than weakening the host policy.

The checks cover actual runner/CLI/descendant host UIDs, denial of broker
state/token/process access and signaling, forged launch/admin peer rejection,
relay authentication, confinement canary behavior, cancel/deadline/crash cleanup,
runner restart, bad executable digests, separate admin capability, wrong
passphrases, local operator unlock/relock, approval invalidation, orderly broker
restart, capability rotation, repeated installation, and uninstall. Rust tests
also cover active proxy cancellation on relock and synthetic HTTPS injection.
Agent tools require separate validation.

### Disposable systemd and AppArmor guest

The VM test builds an Ubuntu 24.04 guest with its own kernel and systemd PID 1.
It uses QEMU software emulation inside an unprivileged Docker container;
neither KVM nor a host QEMU installation is needed. The guest has no external
network device. AppArmor policy, accounts, service installation, and kernel
operations remain inside the guest; the host's services and policy are not
changed. Image construction downloads distribution packages.

```sh
cargo build --release -p av -p avd -p av-runner -p av-fixture --bins --examples
packaging/linux/run-systemd-tests.sh --bin-dir "$PWD/target/release" \
  --artifact-dir /absolute/new/external-artifact-directory
```

Use a new artifact directory outside the repository. The script preserves the
serial log, image-build logs, guest disk, kernel, and initramfs there. It exits
successfully only when the guest emits `AV_VM_TEST_PASS`. This test currently
targets x86-64 Linux binaries.

The guest checks offline vault initialization, root-only recovery, empty-vault
unlock/relock, exact profile loading and process attachment, separate service
UIDs, systemd readiness and private networking, locked startup, operator-owned
secret grants, request approval, and a real brokered HTTPS call to a local
synthetic provider. It also installs a versioned protected connection, invokes
the public `av run` with a single project reference, checks denial before
approval, rejects token-only and wrong-passphrase decisions, exercises the
operator `review`, `approve`, and `deny` commands, and resumes the approved
host-client task through the fixed proxy.
It checks the injected synthetic bearer credential and preserved placeholder,
then executes the confinement canary through another
approved recipe. Further checks cover relock with a running task, broker and
runner crash recovery, capability rotation, kernel sysctl/log/hostname denials,
repeated installation, execution after update, and uninstall with encrypted
state retention. The kernel-denial probe is a test-only `ExecStartPost`; it
inherits the unit's restrictions without relaxing them.

Validation is distribution-specific: the current guest uses Ubuntu 24.04.5,
Linux 6.8.0-146-generic, systemd 255.4, and AppArmor 4.0.1, with
`apparmor_restrict_unprivileged_userns=1`. The full integrated suite passed,
including offline initialization and fresh empty-vault unlock. The serial log
records the tested binary SHA-256 hashes.
The update check reinstalls the same build. Other kernels,
distributions, container managers, and agent tool boundaries remain unverified.
This evidence does not enable real proxy credentials; the synthetic-only
restriction remains.

## Update and uninstall

Re-run the installer with newly built binaries to update. It preserves both
non-login identities and vault state. Restart both services after updating;
a configured vault returns to the locked state.

`sudo packaging/linux/uninstall.sh` stops both services and removes installed
binaries, units, identity configuration, and the scoped AppArmor profile.
It preserves encrypted vault state,
`service.env`, and both service identities for recovery or reinstall. Removing
retained state is a separate destructive operation. `--destdir` supports
reviewing removal in a staging tree.
