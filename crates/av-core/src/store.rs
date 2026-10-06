//! Vault policy and credential lifecycle, independent of the persistence adapter.

mod sqlcipher;

use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use zeroize::Zeroizing;

use crate::backend::{BackendEntry, BackendMutation, SecretBackend};
use crate::policy::{ApprovalRequirement, SecretAccessRequest, SecretPolicy};

pub use sqlcipher::{
    SqlCipherBackend, backup_vault, create_vault, recover_vault, restore_vault, rotate_vault_key,
};

pub struct Vault {
    backend: Box<dyn SecretBackend>,
}

pub struct CreatedVault {
    pub vault: Vault,
    pub recovery_key: Zeroizing<String>,
}

impl Vault {
    /// Construct a trusted vault session. Only operator-controlled code may
    /// select an adapter; project configuration and agent requests cannot do so.
    pub fn from_backend(backend: impl SecretBackend + 'static) -> Self {
        Self {
            backend: Box::new(backend),
        }
    }

    /// Open the initial SQLCipher adapter using the operator passphrase.
    pub fn open(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        Ok(Self::from_backend(SqlCipherBackend::open(
            path, passphrase,
        )?))
    }

    /// Trusted operator API. New secrets have no release grants.
    pub fn add(&self, name: &str, value: &str) -> Result<()> {
        generic_key(name)?;
        self.add_entry(name, value)
    }

    pub(crate) fn add_entry(&self, name: &str, value: &str) -> Result<()> {
        validate_key(name)?;
        validate_value(value)?;
        self.apply(&[BackendMutation {
            key: name.into(),
            expected: None,
            replacement: Some(BackendEntry::new(value.into())),
        }])
        .context("secret already exists or storage failed; use rotate to replace an existing value")
    }

    /// Preserve the operator's existing policy while changing its credential.
    pub fn rotate(&self, name: &str, value: &str) -> Result<()> {
        generic_key(name)?;
        validate_value(value)?;
        let previous = self
            .read_entry(name)?
            .context("secret does not exist; use add to create it")?;
        let mut replacement = previous.clone();
        replacement.value = Zeroizing::new(value.into());
        self.replace_entry(name, previous, replacement)
    }

    /// Insert an entire import atomically, refusing any existing secret.
    pub fn import(&self, values: &[(String, Zeroizing<String>)]) -> Result<()> {
        let mut mutations = Vec::with_capacity(values.len());
        for (name, value) in values {
            generic_key(name)?;
            validate_key(name)?;
            validate_value(value)?;
            mutations.push(BackendMutation {
                key: name.clone(),
                expected: None,
                replacement: Some(BackendEntry::new(value.to_string())),
            });
        }
        self.apply(&mutations)
            .context("import conflicts with an existing secret or storage failed")
    }

    pub fn set(&self, name: &str, value: &str) -> Result<()> {
        generic_key(name)?;
        validate_value(value)?;
        let previous = self.read_entry(name)?;
        let mut replacement = previous
            .clone()
            .unwrap_or_else(|| BackendEntry::new(String::new()));
        replacement.value = Zeroizing::new(value.into());
        self.apply(&[BackendMutation {
            key: name.into(),
            expected: previous,
            replacement: Some(replacement),
        }])
    }

    pub fn get(&self, name: &str) -> Result<Option<String>> {
        generic_key(name)?;
        self.get_entry(name)
    }

    pub(crate) fn get_entry(&self, name: &str) -> Result<Option<String>> {
        Ok(self.read_entry(name)?.map(|entry| entry.value.to_string()))
    }

    pub(crate) fn read_entry(&self, name: &str) -> Result<Option<BackendEntry>> {
        validate_key(name)?;
        self.backend.read(name)
    }

    pub(crate) fn apply(&self, mutations: &[BackendMutation]) -> Result<()> {
        for mutation in mutations {
            validate_key(&mutation.key)?;
            if let Some(entry) = &mutation.replacement {
                validate_value(&entry.value)?;
                entry_policy(entry)?;
            }
        }
        self.backend.apply(mutations)
    }

    pub(crate) fn replace_entry(
        &self,
        name: &str,
        previous: BackendEntry,
        replacement: BackendEntry,
    ) -> Result<()> {
        self.apply(&[BackendMutation {
            key: name.into(),
            expected: Some(previous),
            replacement: Some(replacement),
        }])
    }

    pub fn exists(&self, name: &str) -> Result<bool> {
        Ok(self.read_entry(name)?.is_some())
    }

    pub fn list(&self) -> Result<Vec<String>> {
        self.backend.list()
    }

    pub fn policy(&self, name: &str) -> Result<SecretPolicy> {
        match self.read_entry(name)? {
            Some(entry) => entry_policy(&entry),
            None => Ok(SecretPolicy::default()),
        }
    }

    pub fn set_policy(&self, name: &str, policy: &SecretPolicy) -> Result<()> {
        generic_key(name)?;
        policy.validate()?;
        let previous = self.read_entry(name)?.context("secret does not exist")?;
        let mut replacement = previous.clone();
        replacement.policy = Some(serde_json::to_string(policy)?);
        self.replace_entry(name, previous, replacement)
    }

    pub fn authorization(
        &self,
        name: &str,
        request: &SecretAccessRequest,
    ) -> Result<ApprovalRequirement> {
        generic_key(name)?;
        let entry = self.read_entry(name)?.context("secret does not exist")?;
        entry_policy(&entry)?.authorization(request)
    }

    /// Consumers must use this API after constructing a trusted request snapshot.
    /// `approved` must originate from the operator channel, never project data.
    pub fn get_authorized(
        &self,
        name: &str,
        request: &SecretAccessRequest,
        approved: bool,
    ) -> Result<Option<String>> {
        generic_key(name)?;
        let entry = self.read_entry(name)?.context("secret does not exist")?;
        let approval = entry_policy(&entry)?.authorization(request)?;
        ensure!(
            approval == ApprovalRequirement::Preapproved || approved,
            "secret requires operator approval for this run"
        );
        Ok(Some(entry.value.to_string()))
    }
}

pub(crate) fn entry_policy(entry: &BackendEntry) -> Result<SecretPolicy> {
    let policy: SecretPolicy = match &entry.policy {
        Some(encoded) => serde_json::from_str(encoded).context("invalid stored secret policy")?,
        None => SecretPolicy::default(),
    };
    policy.validate()?;
    Ok(policy)
}

fn validate_value(value: &str) -> Result<()> {
    ensure!(
        !value.contains('\0') && value.len() <= 1024 * 1024,
        "secret is too large or contains NUL"
    );
    Ok(())
}

fn generic_key(key: &str) -> Result<()> {
    ensure!(
        !crate::connection::is_connection_storage_key(key),
        "connection records require the versioned connection API"
    );
    Ok(())
}

fn validate_key(key: &str) -> Result<()> {
    let Some((project, name)) = key.split_once('/') else {
        bail!("invalid secret key")
    };
    ensure!(
        !project.is_empty() && !name.is_empty() && !name.contains('/'),
        "invalid secret key"
    );
    ensure!(
        key.len() <= 130
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'/'),
        "invalid secret key"
    );
    Ok(())
}
