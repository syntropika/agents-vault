# Installation

Install the `agents-vault` package from [crates.io](https://crates.io/crates/agents-vault). Its executable is named `av`.

## Prerequisites

Use Rust 1.88 or newer, including Cargo. [Rust's installation guide](https://www.rust-lang.org/tools/install) explains how to install or update the toolchain.

Cargo compiles the CLI and its bundled SQLCipher/OpenSSL dependencies from source. You need native build tools:

| Platform | Build prerequisites |
| --- | --- |
| Linux | A C compiler, linker, `make`, and Perl. Use your distribution's development toolchain packages. |
| macOS | Xcode Command Line Tools, installed with `xcode-select --install`. |
| Windows | Visual Studio Build Tools with the Desktop development with C++ workload and Windows SDK, plus Perl and NASM for vendored OpenSSL. Use a native MSVC Rust toolchain. |

## Install

```sh
cargo install agents-vault --locked
av --version
av --help
```

`--locked` uses the dependency versions shipped with the release. Installation does not create or unlock a vault.

## Make av available in your shell

Cargo installs executables in `$CARGO_HOME/bin`, normally `~/.cargo/bin` on Linux and macOS and `%USERPROFILE%\.cargo\bin` on Windows. Add that directory to `PATH` if `av` is not found. Rustup normally configures this for you; open a new terminal after installation.

## Update or uninstall

To install the latest release again:

```sh
cargo install agents-vault --locked --force
```

To pin a release, add `--version 0.1.0`. To remove the CLI:

```sh
cargo uninstall agents-vault
```

Uninstalling the executable does not remove your project configuration, vault, or recovery material.

## Protected services and MCP

The CLI installation supports project configuration and local direct delivery. It does not install a privileged service, create service identities, or configure a harness automatically.

Linux and macOS protected services require an operator-reviewed platform installation. See the [Linux service instructions](../../packaging/linux/README.md) and [macOS service instructions](../../packaging/macos/README.md). Proxy credentials remain synthetic while the [custody gates](limits-and-trust.md) are open.

The separate MCP Apps adapter is described in [MCP Apps](mcp-apps.md).

## Build from source

For development, clone the [repository](https://github.com/syntropika/agents-vault) and run from its root:

```sh
cargo build --locked -p agents-vault --bin av
./target/debug/av --help
```

On Windows, the executable is `target\debug\av.exe`. Building the broker and MCP adapter from source also requires their web assets; see [console and MCP build instructions](../approval-flow.md#build-and-configure).

## Next step

Follow the [quickstart](quickstart.md) to validate a project and authorize direct credential delivery.
