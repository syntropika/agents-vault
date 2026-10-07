# Publishing Rust packages

The public CLI package is `agents-vault`; its executable remains `av`. Internal dependencies are separate crates. The fixture package has `publish = false`.

## Prepare a release

Use the current stable Rust/Cargo release and authenticate with crates.io using Cargo's credential provider. Keep registry tokens outside the repository.

1. Update the changed package versions and their internal dependency requirements.
2. Build and verify the operator interfaces:

   ```sh
   npm --prefix web ci
   npm --prefix web run verify
   ```

   The build runs `scripts/prepare-crates.mjs`, copying production console and MCP App assets into ignored package directories and including the Apache license in each archive. These files are release inputs, not development dependencies. Published binaries need no Node runtime.

3. Verify Rust changes and the complete standalone packages:

   ```sh
   cargo test --locked -p agents-vault -p av-core --all-targets
   cargo publish --workspace --locked --dry-run
   ```

   Cargo resolves workspace dependencies in publication order and verifies extracted archives. Inspect the generated `.crate` archives under `target/package/` before uploading. The broker archive must contain `assets/index.html` and its compiled assets; the MCP archive must contain `assets/mcp-app.html`.

4. Commit the reviewed source and documentation with a lowercase Conventional Commit message. Ensure the working tree is clean.

## Publish

For the initial coordinated workspace release:

```sh
cargo publish --workspace --locked
```

Later releases should select only new versions with `-p PACKAGE`. Publish new dependency versions before packages that require them. crates.io versions cannot be overwritten; consult the [Cargo publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html).

Verify a fresh registry installation, not a path dependency:

```sh
cargo install agents-vault --locked
av --version
av --help
```

Check the public installation guide and the documentation deployment after publication. Tag the published source revision using its release version. Cargo installation supplies the CLI and does not configure a privileged service or unlock a vault.
