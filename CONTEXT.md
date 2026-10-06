# Agents Vault

Agents Vault mediates an agent's use of credentials held outside the agent's environment.

## Language

**Credential**:
A secret value held for an operator and referenced by name during an operation. The agent does not need the value to request its use.

**Project variable**:
A named configuration value declared by a project. It may resolve from a public literal, a derived value, or a protected source. Existing applications may still receive it through an environment variable at runtime.

**Integration**:
A definition of how `av` authenticates to and performs supported actions with an external service.

**Connection**:
An operator's account linked to an integration, with its credentials and lifecycle managed by `av`. An integration may have multiple connections.

**Action**:
A named, structured operation that `av` performs against a connected service on the agent's behalf.

**Credential policy**:
Operator-controlled rules describing which consumers may use a credential, how it may be delivered, where it may be sent, and whether approval is required. Project configuration can request access but cannot widen this policy.

**Run operation**:
One command invocation launched through `av run`. Its child process may receive credential values.

**Proxy request**:
One outbound HTTP request whose credential use is mediated by `av` before the request reaches its destination.

**Brokered task**:
One identified command invocation whose proxy requests share a bounded authorization.

**Approval**:
An operator's authorization for one specific run operation or brokered task that uses a credential configured to require confirmation.
