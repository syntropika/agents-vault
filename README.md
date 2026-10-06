# Agents Vault (`av`)

Agents Vault is a local-first prototype for project configuration, encrypted credentials, and brokered CLI tasks. Its goal is to replace unmanaged plaintext environment files and let an agent request a bounded operation without receiving a persistent credential.

The current Rust workspace supports project configuration, reviewed dotenv import, encrypted local values, direct `av run`, versioned provider-neutral connections, a same-user proxy preview, and a broker/MCP fixture flow. Direct delivery gives the child the real value. Proxy preview does not establish protected custody. An operator-owned host-proxy recipe can pin a versioned connection; the broker checks its version, host, command, and grant before loading a synthetic credential. The fixed listener at `127.0.0.1:14322` stays bound while unlocked, denies connections without an active task grant, and routes up to 16 concurrent host-client tasks by distinct capabilities. Public `av run` with `curl` reached a local synthetic HTTPS provider on Linux and macOS; the Linux test used a versioned connection, while the macOS test used a development fixture. The versioned path also passed a synthetic acceptance test in an installed Linux systemd/AppArmor guest. The installed macOS connection path remains unverified.

## Start with the local CLI

Use a recent Rust toolchain (the workspace declares Rust 1.88 for the MCP adapter):

    cargo build -p av --bin av
    cargo run -p av -- --help
    cargo test -p av-core
    cargo test -p av --bin av

Create a project and inspect its configuration:

    av init --project example
    av check
    av run -- your-command

`av import-env` imports assignments from a dotenv file. It treats every value as secret unless the operator explicitly marks its name public with `--public NAME`. Review and remove the original plaintext file separately.

## Connections and brokered tasks

`av connect add provider/account --host api.example.test` stores a credential in the local encrypted vault. The command reads it through a hidden terminal prompt. A new connection denies release. Listing and showing connections return metadata, not credentials. The protected service owns a separate vault; an installed recipe and `av protected connect grant` are required before its broker can use a connection. This path remains restricted to synthetic credentials; see [local connections](docs/local-connections.md).

The experimental broker path registers an immutable task with `av run --broker --broker-connection ID --broker-host HOST -- COMMAND`. With `AVD_APPROVAL_UI=1`, the broker serves an authenticated operator page at `127.0.0.1:14323`. MCP `review_request` offers URL elicitation or returns the local link for manual review. The operator enters the vault passphrase directly on the page and approves or denies the exact task. MCP responses alone cannot authorize it. The private terminal route (`av protected review`, `approve`, or `deny`) also remains available. `av run --resume REQUEST_ID` attempts an approved execution; MCP no longer exposes an execution tool. Current policy supports a narrowly configured synthetic fixture. It is not arbitrary provider or CLI compatibility. See [authenticated local approval](docs/approval-flow.md).

When an operator-owned policy sets `host_client`, the resumed `av` process runs the frozen command on the host. It supplies `HTTPS_PROXY` automatically, uses a short-lived proxy capability, and closes the session after the command exits. A project with exactly one selected connection reference can request this path with `av run -- COMMAND`; its version must match the installed recipe. The broker retains the synthetic credential. This mode does not confine the host command or prevent another process with the capability from using the approved host and quota. A process sharing the agent UID can also race `av run --resume` for an approved request ID, receive the capability first, or end a live task through the public agent socket. The installed macOS connection path has not passed signing or acceptance tests.

Project settings live in `./av.toml` by default, or at the path supplied with `av --config`. Brokered `av run` creates a separate user-local proxy setting on first use and reuses it later: `$XDG_CONFIG_HOME/av/proxy.json` on Linux (normally `~/.config/av/proxy.json`) and `~/Library/Application Support/AgentsVault.av/proxy.json` on macOS. The file stores only the fixed `http://127.0.0.1:14322` endpoint. Each approved task receives its own proxy capability and temporary CA from the broker; neither is persisted in this configuration. `av` rejects a saved endpoint that differs from the broker's fixed loopback address. The listener remains bound until the broker locks or shuts down; idle connections are denied.

An arbitrary MCP client can synthesize a positive response, so the adapter reads the broker's authenticated decision instead of trusting that response. The local operator page requires the vault passphrase independently of MCP. Private terminal decisions remain available. A disposable installed Linux guest passed the synthetic negative and positive terminal decision checks; the local page has separate HTTP and lifecycle tests. Installed macOS coverage, the same-UID execution boundary and a joined agent-route audit remain release gates before real credentials are supported.

## What to read next

- [Product concept](docs/product-concept.md): intended user experience and security levels.
- [Crate map](docs/crate-map.md): current component responsibilities.
- [Authenticated local approval](docs/approval-flow.md): operator page, MCP URL elicitation and test coverage.
- [Storage adapters](docs/storage-adapters.md): SQLCipher boundary and the later native keyring integration plan.
- [Decision summary](docs/decision-summary.md): agreed requirements and open choices.
- [Prototype status](docs/prototype-status.md): demonstrated behavior and limits.
- [Implementation plan](docs/implementation-plan.md) and [work queue](docs/work-queue.md): next release gates.

The work uses synthetic credentials and local HTTPS providers for tests. Neither a passing unit suite nor a successful proxy fixture proves installed operating-system isolation.

## Local operator web console

The console manages credentials, configured permissions, and task approvals at `http://127.0.0.1:14323/` when `AVD_APPROVAL_UI=1`. It defaults to dark mode. Sign in once for a 15-minute operator session; enabling task execution remains a separate action. See [approval flow](docs/approval-flow.md) for session and security limits.

Build the embedded console before the daemon:

```sh
cd web
npm ci
npm run verify
cd ..
cargo build --locked -p avd --bin avd
```

Frontend development uses `npm run dev` in `web`, with API requests forwarded to an already running loopback broker. Browser tests require a disposable development broker on port 14323, a vault initialized with the synthetic test passphrase, and the `example/build` record. They must not target an operator's real vault. `npm run test:e2e` runs desktop and mobile workflows. Optional `AV_WEB_BROWSER` selects an existing browser executable; `AV_WEB_TEST_OUTPUT` and `AV_WEB_CAPTURES` place artifacts outside the repository.
