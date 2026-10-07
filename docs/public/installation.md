# Installation

Install `agents-vault` from [crates.io](https://crates.io/crates/agents-vault). The installed command is `av`.

## Prerequisites

You need **Rust 1.88 or newer**, including Cargo. Follow [Rust's installation guide](https://www.rust-lang.org/tools/install) to install or update it.

Cargo builds the CLI from source, including SQLCipher and OpenSSL. Install your platform's build tools first:

| Platform | Required tools |
| --- | --- |
| Linux | A C compiler, linker, `make`, and Perl. Use your distribution's development toolchain packages. |
| macOS | Xcode Command Line Tools: `xcode-select --install`. |
| Windows | Visual Studio Build Tools with Desktop development with C++ and the Windows SDK; Perl and NASM for OpenSSL. Use the MSVC Rust toolchain. |

## Install

```sh
cargo install agents-vault --locked
av --version
```

`--locked` uses the dependency versions included with the release. This installs the executable; it does not create or unlock a vault.

**Next:** follow the [quickstart](quickstart.md) to run a project.

## Make av available in your shell

If your shell cannot find `av`, open a new terminal first. Rustup normally adds Cargo's executable directory to `PATH`.

If it is still missing, add the relevant directory:

| Platform | Default directory |
| --- | --- |
| Linux and macOS | `~/.cargo/bin` |
| Windows | `%USERPROFILE%\.cargo\bin` |

A custom `CARGO_HOME` changes that location to its `bin` subdirectory.

## Update or uninstall

Install the latest release:

```sh
cargo install agents-vault --locked --force
```

Add `--version 0.1.0` to install a specific release.

Remove the executable:

```sh
cargo uninstall agents-vault
```

Your project files, vault, and recovery material remain after uninstalling.

## Protected services and MCP

The CLI supports project variables and local direct secret delivery. A protected service needs a separate installation:

- [Linux service installation](../../packaging/linux/README.md)
- [macOS service installation](../../packaging/macos/README.md)

The service uses a separate vault. Proxy credentials remain synthetic while the [custody checks](limits-and-trust.md) are incomplete.

To approve actions through a compatible client, install the separate [MCP Apps adapter](mcp-apps.md).

## Build from source

For development, clone the [repository](https://github.com/syntropika/agents-vault), then run from its root:

```sh
cargo build --locked -p agents-vault --bin av
./target/debug/av --help
```

On Windows, the executable is `target\debug\av.exe`.

Source builds of the broker and MCP adapter also need their web assets. See [console and MCP build instructions](../approval-flow.md#build-and-configure).
