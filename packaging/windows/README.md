# Windows direct CLI package

This implementation distributes the x64 Windows `av` CLI as one offline zip. The
release recipe uses bundled SQLCipher/OpenSSL and a static C runtime; installation needs
Windows PowerShell 5.1 or PowerShell 7, with no Rust toolchain, service account,
VM, or runtime download. Windows support is direct delivery: the child process
receives approved secret values and can read them. It does not provide protected
broker custody.

Native Windows tests and package installation must pass before release. The
workflow runs direct-mode tests and package lifecycle checks on Windows Server
2022 x64. Linux cross compilation and PowerShell syntax/package checks do not
establish native Windows behavior. Desktop Windows and
Authenticode signing remain release gates. This implementation is unsigned.

## Build the archive

On an x64 Windows build machine with Rust and the MSVC C toolchain:

```powershell
$env:RUSTFLAGS = '-C target-feature=+crt-static'
cargo build --locked --release --target x86_64-pc-windows-msvc -p av
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
.\packaging\windows\make-package.ps1 `
    -Binary .\target\x86_64-pc-windows-msvc\release\av.exe `
    -Version 0.1.0 -OutputDirectory C:\AgentsVaultBuild\packages
```

The output is `agents-vault-0.1.0-windows-x64.zip` and its `.sha256` checksum.
The version argument must match the release being built. On Windows, the
builder runs `av.exe --version` and requires the exact output `av <version>`.
On other hosts, the builder cannot execute the Windows binary and does not
verify that its embedded CLI version matches the argument. In that case,
verify the version on native Windows before release. The builder checks the
PE32+ x64 console executable headers, a bounded section count, and basic
section bounds. This structural check cannot prove that the program will start
or behave correctly.
The build script does not download dependencies.
Only distribute binaries built with the documented static MSVC configuration.
The archive contains `av.exe`, install/uninstall scripts, shared validation,
this README, and a SHA-256 manifest. Checksums detect corruption; obtain the
archive and its checksum from a trusted release channel. They do not prove
publisher identity or replace code signing.

## Install and update offline

Copy the zip and checksum to the destination machine. Compare the zip's
`Get-FileHash -Algorithm SHA256` result with the checksum received through the
trusted release channel. Extract the archive before invoking its installer:

```powershell
Expand-Archive -LiteralPath .\agents-vault-0.1.0-windows-x64.zip -DestinationPath .\agents-vault-package
& .\agents-vault-package\install.ps1
& "$env:LOCALAPPDATA\Programs\AgentsVault\cli\av.exe" --help
```

Run under your normal user account. The default destination is
`%LOCALAPPDATA%\Programs\AgentsVault\cli`; `-InstallDirectory` accepts another
absolute path to a dedicated directory. Add that directory to your user PATH
in Windows Settings if you want to invoke `av` by name, then open a new terminal.
The scripts do not change execution policy. If policy blocks the unsigned
implementation, use your organization's approved script review and signing process.

To update, extract a new archive to a separate directory, close running `av`
processes, and invoke its installer with the same installation directory. The
installer verifies every source file before staging a replacement. It accepts
only an existing validated Agents Vault installation, refuses unexpected files and
reparse points, and restores the previous directory if publishing the staged
directory fails. It never touches the vault or project configuration. Repeating
the same install is supported. Downgrades are refused.

The update uses two directory renames; it is not a power-loss transaction. If
interrupted between renames, a sibling `.agents-vault-previous-*` directory retains
the old installation. Close all Agents Vault processes and restore that directory
to the original installation path before retrying. An installed directory may
contain only package files; store vaults, recovery files, and project data
elsewhere. User-writable package manifests are not a same-user security boundary.

## Uninstall

```powershell
& "$env:LOCALAPPDATA\Programs\AgentsVault\cli\uninstall.ps1"
```

The uninstaller verifies the installation, then removes only its dedicated
directory. It preserves encrypted vault data, recovery material, project files,
and user PATH. Remove your manually added PATH entry in Windows Settings if
desired. Unexpected or changed files cause removal to stop for inspection.

## Verification

```powershell
cargo test --locked -p av-core -p av --all-targets
if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
.\packaging\windows\test-package.ps1 `
    -Binary .\target\x86_64-pc-windows-msvc\release\av.exe
```

The portable check can run with PowerShell on a non-Windows host and a Windows
cross-built `av.exe`:

```powershell
./packaging/windows/test-package.ps1 -Binary ./target/x86_64-pc-windows-gnu/release/av.exe -PortableValidationOnly
```

It checks archive hashes and extraction, manifest validation, and rejection of
DLL, GUI, wrong-architecture, and malformed PE variants. It does not run the
Windows CLI, compare the binary's own version, or test installation.

The native smoke checks installation into a path containing spaces, public-only
`.env` import without creating a vault, direct public environment delivery and
child exit status, secret placeholder generation without unlocking, repeat install, upgrade,
downgrade rejection, damaged package rejection, junction rejection, preservation of unrelated data,
and uninstall. It builds and extracts an archive in a temporary directory and
does not require a network connection. The CLI Rust suite also exercises a
secret-bearing child using the production snapshot/launch function and synthetic
approved values. That test bypasses the interactive vault prompt internally;
an installed CLI session that initializes/unlocks a vault through the native
Windows console remains a separate release gate.

The smoke's higher-version installation is a synthetic manifest edit around
the same binary. It tests version ordering and directory replacement, not a
real binary upgrade. The native builder separately rejects a supplied version
that differs from `av.exe --version`. Before release, test an update between
two distinct, correctly versioned builds on native Windows. The installer
trusts the manifest version after verifying package hashes; it does not run
`av.exe --version` itself.

Run the interactive console gate manually from a normal user's native Windows console, using an
installed `av.exe`. The script requires `-Interactive` to prevent an unattended
job from waiting indefinitely at hidden prompts:

```powershell
.\packaging\windows\test-direct-console.ps1 `
    -Binary "$env:LOCALAPPDATA\Programs\AgentsVault\cli\av.exe" -Interactive
```

Enter invented temporary values only. The script never puts the secret or
passphrase in arguments or its own environment. `av` reads both from the native
console. The script verifies setup, explicit unlock, add, default denial before
child entry, rejected and accepted per-run approval, encrypted backup and
restore, and recovery with a new passphrase. It tests that a child receives a
nonempty `AV_TEST_SECRET` and the expected public project value together,
without printing the secret. All test vault and backup
files live in a unique temporary directory and are removed when the script
ends. The CI workflow syntax-checks this script but cannot claim its console
journey passed until it is run interactively on native Windows. In particular,
preservation of the direct grant after backup/restore and recovery remains
unverified on Windows until those final release checks pass.
