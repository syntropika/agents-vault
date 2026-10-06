# Linux confined runner

`prepare_command` starts a bundled helper in user, network, PID, and mount
namespaces. The CLI receives a private filesystem with read-only system
programs and libraries, a private `/proc`, writable temporary storage, a public
CA at `/run/ca.pem`, and one task-specific proxy socket. Host home directories,
broker state, operator sockets, and the host process tree are absent. Direct
IP traffic cannot leave the namespace; isolated loopback reaches the local
proxy relay.

The helper and command must be ELF executables. The launcher copies both into
sealed memory files and executes those snapshots, so replacing a pathname
after preparation cannot change the launched code. `RunSpec.expected_sha256`
and `prepare_verified_command` can check the command and helper against
trusted digests. The broker records both hashes when it loads its policy and
checks them again at task launch. A changed file makes the task fail.

Before executing the CLI, the helper drops all capabilities, sets
`no_new_privs`, and installs a syscall filter that denies namespace switching,
mount changes, ptrace, and cross-process memory access. The supervisor is not
dumpable. The runner closes inherited descriptors other than its sealed images
and standard input/output/error, and rejects network sockets in standard I/O.
The broker uses null standard I/O. Callers must also avoid supplying sensitive
regular files or pipes through standard I/O.

The runner requires Linux user/network/PID/mount namespaces, `pidfd_open`,
`memfd_create` with sealing, and recursive `mount_setattr` (Linux 5.12 or newer).
Missing or forbidden facilities fail closed before the CLI starts. It needs
no external VM runtime, `unshare`, or `ip` executable. Kernel namespace and
syscall isolation remain part of the trust boundary.

The helper supervises PID 1. Killing the outer helper kills the entire private
PID namespace, including descendants that create detached sessions. The
broker additionally limits the task deadline and proxy grant.

Run the checks with:

```sh
cargo test -p av-runner
```

The canary checks blocked direct TCP, blocked host loopback, proxy transport,
hidden host files and pathname Unix sockets, hidden broker process state,
inaccessible supervisor process handles, and denied namespace escape. Other
tests cover executable digest mismatch, executable replacement after snapshot,
and termination of detached descendants.

Direct library callers map namespace UID 0 to the launching UID. Installed
Linux service mode uses a distinct non-login `av-runner` identity. Its daemon
accepts bounded launches only from the `av-broker` peer UID and verifies sealed
executable hashes. The broker authenticates runner relay connections and keeps
proxy credentials outside the runner. An open launch channel represents the
task lifetime; disconnect, timeout, and runner daemon death terminate the
private PID namespace and detached descendants.

The service performs a real namespace preflight before opening its launch
socket. The systemd unit gives the service a private network namespace, and an
AppArmor profile grants the installed service permission to create user
namespaces on restrictive hosts. That profile is a scoped namespace permission,
not an AppArmor confinement policy. The disposable test verifies distinct host
UIDs, authenticated IPC, canary confinement, cancellation, deadlines, daemon
crash/restart, and executable digest checks. Full systemd execution and runtime
loading of the exact packaged AppArmor profile remain unverified.

These controls do **not establish protected credential custody for an entire
agent harness**. Unconfined tools running outside this runner still have their
usual host access. A distinct broker identity, trusted operator channel,
consumer policy, and verification of every enabled agent tool are deployment
gates. The broker remains restricted to synthetic proxy credentials. See
[the Linux service experiment](../../packaging/linux/README.md).
