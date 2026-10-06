# Host Proxy as the Default Protected Delivery Path

Status: Accepted direction; the persistent synthetic listener is implemented, while the installed security boundary remains unverified.

## Context

A full macOS guest is too large for the default `av run` path and cannot reuse a native host CLI without installing it inside that guest. A small Linux guest is useful for selected compatible commands, but it cannot execute macOS-only tools. Users should keep the tool's normal HTTPS destination URL.

## Decision

- `av run` executes native macOS commands on the host when the credential policy selects proxy delivery. It sets the proxy environment automatically; the command's HTTPS URL and arguments remain unchanged.
- The broker retains the credential and injects it only for the approved exact host. The listener address is stable. A per-task capability, expiry, CONNECT quota, and HTTP request quota bound use after approval.
- The operator-owned service, encrypted store, approval authority, and proxy injection run outside the agent login identity. A hidden system identity is installed automatically; no additional login account is shown to the user.
- Host proxy delivery makes no claim that the command is confined to the proxy or that only one same-user process can use a copied task capability. An optional isolated runner provides a separate, stronger command boundary for compatible programs.
- The default macOS package should not include a guest image. An optional isolated tier may bundle the small Linux guest.

## Current implementation and required evidence

The synthetic host-client path binds `127.0.0.1:14322` when the broker unlocks and denies connections until a task grant activates it. Brokered `av run` creates or reuses a user-local configuration file containing only that fixed endpoint. `av` receives a temporary proxy capability and a public interception CA, runs the frozen command, and closes its grant when the command exits. The task capability and CA are not persisted in the proxy configuration. The listener routes up to 16 concurrent grants by capability, with independent revocation and a limit of 4096 activations per listener lifetime. Development tests cover approval, denial, expiry, replay, idle denial, concurrent grants, copied-capability use, and HTTPS injection without an MCP harness. Public `av run` launched `curl` against a local HTTPS provider on Linux and macOS. The macOS test used a development fixture; an installed service has not exercised that path.

Before a protected release, verify installed custody and approval boundaries on both platforms and test credential reflection with a narrowly scoped provider account. The host proxy capability is transferable. Execution and completion now require the original live IPC connection; the formerly possible same-UID public-ID race is rejected. A fixed proxy address and a versioned connection do not authenticate the process using them.
