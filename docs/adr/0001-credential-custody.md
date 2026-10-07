# Credential Custody

Status: Proposed baseline; the default macOS execution choice is superseded by [ADR 0002](0002-host-proxy-default.md). Custody and recovery tests remain pending.

## Agreed requirements

- `av` is local and does not require a cloud service.
- An agent must not be able to read persistent credential values or administer the component that holds them merely because it can invoke `av`.
- A credential can be scoped to a specific CLI and can require approval before use.
- Proxy mode injects a credential into an authorized outbound request without directly returning its value to the command; the remote provider may reflect it in a response.
- Direct `av run` may pass a credential to its child process. That child can then reveal the value, so this mode has a different security guarantee from proxy mode.

## Proposed decision

- Use an application-managed SQLCipher store. A random database key is wrapped independently by an operator passphrase and an offline recovery key. On Linux and macOS, non-login service identities own the protected stores; on Windows the first CLI release uses the encrypted format only for explicit direct delivery, without a same-user isolation claim.
- Start with protected host brokers on Linux and macOS. The Linux proxy command uses a confined host runner if its tests pass. The first macOS proxy task uses a Linux-compatible CLI in a no-NIC guest managed through Apple Virtualization.framework; the host broker retains the credential and proxies traffic over a private service channel. KVM is not a prerequisite for either platform.
- Permit the agent and operator to share a host login UID only when every agent-controlled tool is sandboxed away from the broker, trusted harness approval channel, operator control channel, and unrestricted host execution. Isolating only the `av run` child is insufficient.
- Treat a request ID as a lookup handle. The current implementation requires a private, passphrase-checked operator decision for a one-shot grant bound to immutable intent. A generic MCP permission or app-only tool is insufficient. A future harness approval channel requires independent authentication.

## Validation required before acceptance

- Prove service, runner, agent sandbox, and operator channel boundaries on both Linux and macOS against an agent-controlled same-UID process and raw MCP client. A macOS runner VM alone does not confine other host tools.
- Prove encrypted backup, offline recovery, restart lock, and absence of plaintext spills.
- Prove the selected provider CLI's proxy behavior and credential reflection handling with a limited test account.
