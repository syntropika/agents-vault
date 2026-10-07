# macOS guest and offline package

This Apple silicon implementation packages a Linux fixture command and runs it with
Virtualization.framework. An installed Mac needs no Docker, QEMU, Homebrew,
Linux installation, or image download. The package has not yet passed Developer
ID signing, notarization, or an installed acceptance test.

## Guest bundle

Build `av-guest` and `av-fixture` as static `aarch64-unknown-linux-musl`
binaries. On Linux, run `build-guest.sh INPUTS AV_GUEST AV_FIXTURE OUTPUT`.
`INPUTS` contains the pinned Alpine 3.22 aarch64 kernel and initramfs inputs;
the build script verifies their hashes before extraction. Keep build inputs
outside the repository.

The output contains `Image`, `initramfs.gz`, and `guest.json`. The package
requires manifest format 2, which pins the kernel, initramfs, and fixture
executable. The VMM verifies the bundle before boot. The installed app's
signature must protect the entire bundle and service policy.

The guest has loopback only, with no shared host directory or persistent disk.
It runs `/usr/bin/av-fixture request ...` as UID/GID 65534 with an empty inherited
environment. The fixture verifies that direct TCP fails before making one HTTPS
request through its private proxy transport. This remains a synthetic test
path, not a general command runner.

## Development tests

Run macOS commands through `ssh sirius`. Build native helpers with the workspace
Rust toolchain and stage a development app:

```sh
cargo build --workspace --bins
packaging/macos/test-development-bundle.sh target/debug /absolute/guest-bundle /absolute/new-test-output
```

That script signs a development copy with an ad-hoc signature and checks guest
integrity, VM cancellation, service authentication, grant denial, and synthetic
HTTPS injection. These tests do not
replace installed Developer ID authentication or execution as `_avrunner`.

## Signed synthetic test package

The current format-2 guest runs only `av-fixture`. The package script refuses
to create a signed artifact unless `AV_ALLOW_SYNTHETIC_PACKAGE=1` is set. Use
this override only for disposable installation tests. A production package
requires a new guest command design and its own validation path.

`make-package.sh RELEASE_BINARIES GUEST_BUNDLE VERSION OUTPUT.pkg` expects
`av`, `avd`, `av-mcp`, `av-vmm`, `av-supervisor`, and `av-operator`. Set
`AV_APPLICATION_IDENTITY` and `AV_INSTALLER_IDENTITY` to existing signing
credentials. The script stages one offline app and an `av` symlink, signs all
native helpers and the resource envelope, and verifies the installer signature.
By default it also requires `AV_NOTARY_PROFILE`, notarizes the installer,
staples the ticket, and verifies Gatekeeper assessment. For a signed test
package without notarization, set `AV_SKIP_NOTARIZATION=1`; that path cannot
validate stapling or Gatekeeper acceptance. The script never installs or enables
a service.

On a Mac with a logged-in desktop session, open `sign-package.command` in
Terminal for an interactive front end to that same package script. It requires
one unambiguous Developer ID Application identity, one Developer ID Installer
identity, and asks whether to notarize; the default is a signed-only test
package that needs no notarytool profile. It shows the selected inputs and
requires `SIGN SYNTHETIC` before running. The front end exists for
the disposable format-2 fixture package only; it does not broaden the package
script's production gate. Run it from the desktop session so macOS can present
Keychain access dialogs. SSH execution can still fail when the login Keychain
is locked in that security context.

To configure notarization once in the same desktop session, open
`setup-notary.command` in Terminal. Create an app-specific password at
`account.apple.com`, enter the Apple Account email in the setup command, and
enter the password only when `notarytool` prompts securely. The command
validates the credentials and stores the `agents-vault` profile in Keychain.
The signing launcher uses that profile by default.

The trusted app path is `/Library/PrivilegedHelperTools/AgentsVault.app`. The
format-2 `service.json` pins the Developer ID team and CDHashes of the broker,
supervisor, and VMM. The service accepts only the installed signed helpers and
bundle. `/usr/local/bin/av` is a convenience symlink, not a trust anchor.

The installer currently supports fresh installations only. It creates hidden
`_avd` and `_avrunner` service identities and leaves the LaunchDaemons disabled.
`configure-service.sh --agent-uid UID` selects the ordinary login UID allowed
to use the agent socket. The broker and supervisor retain private runtime and
state directories under `/private/var/db/agents-vault`. Uninstall retains encrypted
state and the hidden identities; an update or reinstall transaction is still
needed before a production release.

`test-service-boundary.py` is destructive and must run only on a disposable Mac
with a signed, notarized package. It checks service identity, access control,
locked startup, private grants, a synthetic provider, VM execution as
`_avrunner`, replay denial, and restart behavior. It does not test a real
provider or establish whole-agent confinement.
