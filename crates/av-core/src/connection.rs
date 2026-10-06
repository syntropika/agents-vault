//! Versioned, provider-neutral connection records in the encrypted vault.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::backend::BackendEntry;
use crate::config::validate_connection_id;
use crate::store::entry_policy;
use crate::{ApprovalRequirement, DeliveryMode, SecretAccessRequest, SecretPolicy, Vault};

const PREFIX: &str = "av-connections/";
const FORMAT: u32 = 2;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionMetadata {
    pub format: u32,
    pub id: String,
    pub version: u64,
    pub provider: String,
    pub host: String,
    pub active: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredConnection {
    metadata: ConnectionMetadata,
    credential: Option<String>,
}

impl Drop for StoredConnection {
    fn drop(&mut self) {
        if let Some(value) = self.credential.as_mut() {
            value.zeroize();
        }
    }
}

fn storage_key(id: &str) -> Result<String> {
    validate_connection_id(id)?;
    Ok(format!("{PREFIX}{}", hex::encode(Sha256::digest(id))))
}

pub fn is_connection_storage_key(key: &str) -> bool {
    key.starts_with(PREFIX)
}

fn validate_credential(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 4096 && !value.contains('\0'),
        "connection credential must contain 1 to 4096 bytes and no NUL"
    );
    Ok(())
}

fn validate_host(host: &str) -> Result<()> {
    ensure!(
        !host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            }),
        "connection host must be a canonical lowercase ASCII hostname"
    );
    Ok(())
}

fn load(vault: &Vault, id: &str) -> Result<Option<(StoredConnection, BackendEntry)>> {
    vault
        .read_entry(&storage_key(id)?)?
        .map(|entry| {
            let record: StoredConnection =
                serde_json::from_str(&entry.value).context("invalid connection record")?;
            let (provider, _) = validate_connection_id(id)?;
            ensure!(
                record.metadata.format == FORMAT
                    && record.metadata.id == id
                    && record.metadata.version > 0
                    && record.metadata.provider == provider,
                "invalid connection metadata"
            );
            validate_host(&record.metadata.host)?;
            ensure!(
                record.metadata.active == record.credential.is_some(),
                "invalid connection state"
            );
            if let Some(credential) = &record.credential {
                validate_credential(credential)?;
            }
            Ok((record, entry))
        })
        .transpose()
}

fn active_version(
    vault: &Vault,
    id: &str,
    version: u64,
) -> Result<(StoredConnection, BackendEntry)> {
    let (record, entry) = load(vault, id)?.context("connection does not exist")?;
    ensure!(
        record.metadata.version == version,
        "connection version changed; review and retry"
    );
    ensure!(record.metadata.active, "connection is disconnected");
    Ok((record, entry))
}

fn validate_policy(metadata: &ConnectionMetadata, policy: &SecretPolicy) -> Result<()> {
    policy.validate()?;
    ensure!(
        policy
            .grants
            .iter()
            .all(|grant| grant.request.delivery == DeliveryMode::Direct
                || grant.request.host.as_deref() == Some(metadata.host.as_str())),
        "connection proxy grants require the connection's exact host"
    );
    Ok(())
}

impl Vault {
    pub fn add_connection(
        &self,
        id: &str,
        host: &str,
        credential: &str,
    ) -> Result<ConnectionMetadata> {
        let key = storage_key(id)?;
        let (provider, _) = validate_connection_id(id)?;
        validate_host(host)?;
        validate_credential(credential)?;
        let metadata = ConnectionMetadata {
            format: FORMAT,
            id: id.into(),
            version: 1,
            provider: provider.into(),
            host: host.into(),
            active: true,
        };
        let record = StoredConnection {
            metadata: metadata.clone(),
            credential: Some(credential.into()),
        };
        let encoded = Zeroizing::new(serde_json::to_string(&record)?);
        self.add_entry(&key, &encoded)
            .context("connection already exists; use connect replace")?;
        Ok(metadata)
    }

    pub fn connection_metadata(&self, id: &str) -> Result<Option<ConnectionMetadata>> {
        Ok(load(self, id)?.map(|(record, _)| record.metadata.clone()))
    }

    pub fn list_connections(&self) -> Result<Vec<ConnectionMetadata>> {
        let mut result = Vec::new();
        for key in self.list()? {
            let Some(suffix) = key.strip_prefix(PREFIX) else {
                continue;
            };
            if suffix.len() != 64
                || !suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                continue;
            }
            let encoded = Zeroizing::new(self.get_entry(&key)?.context("connection disappeared")?);
            let record: StoredConnection =
                serde_json::from_str(&encoded).context("invalid connection record")?;
            ensure!(
                storage_key(&record.metadata.id)? == key,
                "invalid connection storage key"
            );
            result.push(
                self.connection_metadata(&record.metadata.id)?
                    .context("connection disappeared")?,
            );
        }
        Ok(result)
    }

    pub fn replace_connection(
        &self,
        id: &str,
        expected_version: u64,
        credential: &str,
    ) -> Result<ConnectionMetadata> {
        validate_credential(credential)?;
        self.change_connection(id, expected_version, Some(credential))
    }

    pub fn disconnect_connection(
        &self,
        id: &str,
        expected_version: u64,
    ) -> Result<ConnectionMetadata> {
        self.change_connection(id, expected_version, None)
    }

    fn change_connection(
        &self,
        id: &str,
        expected_version: u64,
        credential: Option<&str>,
    ) -> Result<ConnectionMetadata> {
        let key = storage_key(id)?;
        let (mut record, previous) = load(self, id)?.context("connection does not exist")?;
        ensure!(
            record.metadata.version == expected_version,
            "connection version changed; review and retry"
        );
        record.metadata.version = record
            .metadata
            .version
            .checked_add(1)
            .context("connection version exhausted")?;
        record.metadata.active = credential.is_some();
        if let Some(previous) = record.credential.as_mut() {
            previous.zeroize();
        }
        record.credential = credential.map(str::to_owned);
        // One conditional publication changes the credential/version and clears
        // all old grants. A racing rotation or policy change cannot be lost.
        self.replace_entry(
            &key,
            previous,
            BackendEntry::new(serde_json::to_string(&record)?),
        )?;
        Ok(record.metadata.clone())
    }

    pub fn connection_policy(&self, id: &str, version: u64) -> Result<SecretPolicy> {
        let (record, entry) = active_version(self, id, version)?;
        let policy = entry_policy(&entry)?;
        validate_policy(&record.metadata, &policy)?;
        Ok(policy)
    }

    pub fn set_connection_policy(
        &self,
        id: &str,
        version: u64,
        policy: &SecretPolicy,
    ) -> Result<()> {
        let (record, previous) = active_version(self, id, version)?;
        validate_policy(&record.metadata, policy)?;
        let mut replacement = previous.clone();
        replacement.policy = Some(serde_json::to_string(policy)?);
        self.replace_entry(&storage_key(id)?, previous, replacement)?;
        Ok(())
    }

    pub fn connection_authorization(
        &self,
        id: &str,
        version: u64,
        request: &SecretAccessRequest,
    ) -> Result<ApprovalRequirement> {
        self.connection_policy(id, version)?.authorization(request)
    }

    /// Trusted operator/broker API. The caller must authorize immutable intent
    /// before reading; this method must never be exposed on an agent socket.
    pub fn connection_credential(
        &self,
        id: &str,
        expected_version: u64,
    ) -> Result<Zeroizing<String>> {
        let (mut record, _) = active_version(self, id, expected_version)?;
        Ok(Zeroizing::new(
            record
                .credential
                .take()
                .context("connection is disconnected")?,
        ))
    }

    pub fn revoke_connection_grants(&self, id: &str, expected_version: u64) -> Result<()> {
        let key = storage_key(id)?;
        let (_, previous) = active_version(self, id, expected_version)?;
        let mut replacement = previous.clone();
        replacement.policy = None;
        self.replace_entry(&key, previous, replacement)?;
        Ok(())
    }

    pub fn get_connection_authorized(
        &self,
        id: &str,
        version: u64,
        request: &SecretAccessRequest,
        approved: bool,
    ) -> Result<Zeroizing<String>> {
        let (mut record, entry) = active_version(self, id, version)?;
        let policy = entry_policy(&entry)?;
        validate_policy(&record.metadata, &policy)?;
        let approval = policy.authorization(request)?;
        ensure!(
            approval == ApprovalRequirement::Preapproved || approved,
            "connection requires operator approval for this run"
        );
        let credential = Zeroizing::new(
            record
                .credential
                .take()
                .context("connection is disconnected")?,
        );
        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SecretGrant;
    use crate::store::create_vault;

    #[test]
    fn provider_neutral_lifecycle_is_versioned_and_default_deny() {
        let directory = tempfile::tempdir().unwrap();
        let vault = create_vault(directory.path().join("vault.db"), "synthetic passphrase")
            .unwrap()
            .vault;
        let id = "service/work";
        assert!(
            vault
                .add_connection(id, "API.EXAMPLE.TEST", "first")
                .is_err()
        );
        let first = vault
            .add_connection(id, "api.example.test", "first")
            .unwrap();
        assert_eq!(first.version, 1);
        assert_eq!(first.provider, "service");
        assert!(
            vault
                .add_connection(id, "api.example.test", "other")
                .is_err()
        );
        assert_eq!(vault.list_connections().unwrap(), vec![first.clone()]);
        assert!(vault.get(&storage_key(id).unwrap()).is_err());
        assert!(vault.connection_policy(id, 1).unwrap().grants.is_empty());

        let config = directory.path().join("av.toml");
        std::fs::write(&config, b"schema=2\n[project]\nid='test'\n").unwrap();
        let command = [std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned()];
        let request = SecretAccessRequest::for_command(
            &command,
            &config,
            b"schema=2\n[project]\nid='test'\n",
            None,
            DeliveryMode::ProtectedProxy,
            Some("api.example.test"),
        )
        .unwrap();
        assert!(
            vault
                .get_connection_authorized(id, 1, &request, true)
                .is_err()
        );
        vault
            .set_connection_policy(
                id,
                1,
                &SecretPolicy {
                    grants: vec![SecretGrant {
                        request: request.clone(),
                        approval: ApprovalRequirement::EveryRun,
                    }],
                },
            )
            .unwrap();
        assert!(
            vault
                .get_connection_authorized(id, 1, &request, false)
                .is_err()
        );
        assert_eq!(
            vault
                .get_connection_authorized(id, 1, &request, true)
                .unwrap()
                .as_str(),
            "first"
        );
        let mut wrong_host = request.clone();
        wrong_host.host = Some("other.example.test".into());
        assert!(
            vault
                .set_connection_policy(
                    id,
                    1,
                    &SecretPolicy {
                        grants: vec![SecretGrant {
                            request: wrong_host,
                            approval: ApprovalRequirement::EveryRun
                        }]
                    }
                )
                .is_err()
        );

        let second = vault.replace_connection(id, 1, "second").unwrap();
        assert_eq!(second.version, 2);
        assert!(vault.connection_credential(id, 1).is_err());
        assert!(vault.connection_policy(id, 2).unwrap().grants.is_empty());
        assert!(
            vault
                .get_connection_authorized(id, 2, &request, true)
                .is_err()
        );
        let disconnected = vault.disconnect_connection(id, 2).unwrap();
        assert_eq!(disconnected.version, 3);
        assert!(!disconnected.active);
        assert!(vault.connection_credential(id, 3).is_err());
    }

    #[test]
    fn connection_records_are_not_generic_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let vault = create_vault(directory.path().join("vault.db"), "synthetic passphrase")
            .unwrap()
            .vault;
        vault
            .add_connection("payments/work", "api.example.test", "value")
            .unwrap();
        assert!(vault.get(&storage_key("payments/work").unwrap()).is_err());
        assert_eq!(vault.list_connections().unwrap().len(), 1);
    }
}
