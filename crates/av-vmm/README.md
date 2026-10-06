# av-vmm

Apple silicon Virtualization.framework runner for a packaged, ephemeral Linux
fixture task. See [the package contract](../../packaging/macos/README.md).

`cargo test -p av-vmm` checks message bounds and resource integrity on any Unix
host. Native execution requires the virtualization entitlement and a verified
guest bundle. A non-macOS VMM invocation fails without launching the fixture.

First run `cargo test -p av-vmm --test macos_vm --no-run`, then copy the built
`target/debug/av-vmm` outside Cargo's target directory and sign that copy with
the virtualization entitlement. Cargo can replace its output executable when
running tests, removing an earlier ad-hoc signature.
With `AVD_TEST_VMM` pointing to the signed copy and `AVD_TEST_GUEST_BUNDLE` set
to absolute paths on the Mac, run
`cargo test -p av-vmm --test macos_vm -- --ignored --test-threads=1` to verify cancellation,
deadline expiry, and image tamper rejection against the real VM. The broker's
`approved_fixture_task_injects_synthetic_secret_and_cannot_be_replayed` test
uses the same variables for the actual synthetic HTTPS flow.

The private broker socket is a transport capability owned by the launcher.
Neither a guest-supplied identifier nor knowledge of the fixed vsock port
authorizes a broker request. The guest only receives a public CA and placeholder.
The macOS-only `service::installed_identity()` verifies the fixed signed
installation. The broker binds that snapshot to an encrypted per-secret grant.
`service::launch(&ServiceIdentity)` rechecks the snapshot, authenticates the
running supervisor, and returns a `ServiceLease` and private stream. The
supervisor authenticates `_avd` using its kernel audit token, Developer ID
signature, and pinned CDHash. It checks the transferred installation commitment
before launching the pinned VMM as `_avrunner`. Protected grants require a
format-2 guest manifest and signing policy, with exact guest resources and all
three helper CDHashes. Its production path has no configurable
executable, identity, guest bundle, or development-signature bypass. The explicit
`prepare_command` API remains the development launcher under the caller's UID.

Native library tests cover descriptor transfer, actual Security.framework
authentication and pin mismatch rejection, path/ACL denial, and lease behavior.
Installed identities, signed positive authentication, `_avrunner` virtualization,
and whole-agent confinement remain unvalidated release gates. See the package
README for the disposable test harness and exact current evidence.
