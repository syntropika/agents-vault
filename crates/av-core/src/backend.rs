//! Trusted persistence adapters for the vault.
//!
//! Policy interpretation and approval remain in `Vault`. An adapter persists
//! opaque entries and must preserve the atomic snapshot and mutation contract.

use std::fmt;

use anyhow::Result;
use zeroize::Zeroizing;

/// One consistent snapshot of a credential and its stored policy metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct BackendEntry {
    pub value: Zeroizing<String>,
    pub policy: Option<String>,
}

impl BackendEntry {
    pub fn new(value: String) -> Self {
        Self {
            value: Zeroizing::new(value),
            policy: None,
        }
    }
}

impl fmt::Debug for BackendEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackendEntry")
            .field("value", &"[REDACTED]")
            .field("policy", &"[REDACTED]")
            .finish()
    }
}

/// Replace or delete an entry only if its entire previous snapshot matches.
/// `expected = None` requires that the key does not exist.
#[derive(Debug)]
pub struct BackendMutation {
    pub key: String,
    pub expected: Option<BackendEntry>,
    pub replacement: Option<BackendEntry>,
}

/// An unlocked, trusted storage session, never an agent-facing capability.
///
/// `read` returns the value and policy from the same snapshot. `apply` checks
/// every expectation and publishes every replacement atomically, including
/// across processes. A conflict or failure must publish none of the batch.
/// Duplicate mutation keys must be rejected. `list` returns sorted unique keys.
///
/// A native keyring adapter will need a metadata/transaction coordinator to
/// satisfy this contract; basic keyring get/set calls alone are insufficient.
/// Errors, denied prompts, and unavailable stores must never trigger fallback
/// to a different credential source. Opening/unlocking and backup/recovery are
/// adapter-specific lifecycle operations outside this interface.
pub trait SecretBackend: Send {
    fn read(&self, key: &str) -> Result<Option<BackendEntry>>;
    fn list(&self) -> Result<Vec<String>>;
    fn apply(&self, mutations: &[BackendMutation]) -> Result<()>;
}
