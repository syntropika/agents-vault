use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{CreatedVault, Vault, entry_policy, validate_key, validate_value};
use crate::backend::{BackendEntry, BackendMutation, SecretBackend};
#[cfg(test)]
use crate::policy::{ApprovalRequirement, SecretPolicy};

const KEY_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEnvelope {
    version: u32,
    passphrase_salt: String,
    passphrase_nonce: String,
    passphrase_wrap: String,
    recovery_nonce: String,
    recovery_wrap: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    database_file: Option<String>,
}

/// SQLCipher storage and its encrypted-file lifecycle.
pub struct SqlCipherBackend {
    conn: Connection,
    // Held for the unlocked session so rekey cannot discard another handle's writes.
    // Advisory locking is not a credential custody boundary.
    _access_lock: Option<fs::File>,
}

pub fn create_vault(path: impl AsRef<Path>, passphrase: &str) -> Result<CreatedVault> {
    let path = path.as_ref();
    ensure!(!passphrase.is_empty(), "passphrase is required");
    ensure!(
        !path.exists() && !key_path(path).exists(),
        "vault already exists"
    );
    let database_key = Zeroizing::new(random_array::<KEY_BYTES>());
    let recovery_bytes = Zeroizing::new(random_array::<KEY_BYTES>());
    let recovery_key = Zeroizing::new(hex::encode(*recovery_bytes));
    let envelope = make_envelope(&database_key, passphrase, &recovery_bytes)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let access_lock = access_lock(path, false)?;
    let mut vault = open_database(path, &database_key, true)?;
    vault._access_lock = Some(access_lock);
    initialize_schema(&vault)?;
    if let Err(error) = write_new_envelope(path, &envelope) {
        drop(vault);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(CreatedVault {
        vault: Vault::from_backend(vault),
        recovery_key,
    })
}

pub fn recover_vault(
    path: impl AsRef<Path>,
    recovery_key: &str,
    new_passphrase: &str,
    new_recovery_file: impl AsRef<Path>,
) -> Result<()> {
    ensure!(!new_passphrase.is_empty(), "new passphrase is required");
    let path = path.as_ref();
    let _access_lock = access_lock(path, true)?;
    let old = read_envelope(path)?;
    let recovery_bytes =
        Zeroizing::new(decode_array::<KEY_BYTES>(recovery_key).context("invalid recovery key")?);
    let database_key = Zeroizing::new(
        decrypt_key(&recovery_bytes, &old.recovery_nonce, &old.recovery_wrap)
            .context("recovery key did not unlock vault")?,
    );
    rotate_generation(
        path,
        &old,
        &database_key,
        new_passphrase,
        new_recovery_file.as_ref(),
    )
}

/// Rotate every encryption key while retaining the secret values and policies.
pub fn rotate_vault_key(
    path: impl AsRef<Path>,
    passphrase: &str,
    new_passphrase: &str,
    new_recovery_file: impl AsRef<Path>,
) -> Result<()> {
    ensure!(!new_passphrase.is_empty(), "new passphrase is required");
    let path = path.as_ref();
    let _access_lock = access_lock(path, true)?;
    let envelope = read_envelope(path)?;
    let key = unlock_database_key(&envelope, passphrase)?;
    rotate_generation(
        path,
        &envelope,
        &key,
        new_passphrase,
        new_recovery_file.as_ref(),
    )
}

fn rotate_generation(
    path: &Path,
    old: &KeyEnvelope,
    database_key: &[u8; KEY_BYTES],
    new_passphrase: &str,
    new_recovery_file: &Path,
) -> Result<()> {
    let old_database = database_path(path, old)?;
    let vault = open_database(&old_database, database_key, false)?;
    let new_database_key = Zeroizing::new(random_array::<KEY_BYTES>());
    let new_recovery_bytes = Zeroizing::new(random_array::<KEY_BYTES>());
    let new_recovery_key = Zeroizing::new(hex::encode(*new_recovery_bytes));
    let mut new = make_envelope(&new_database_key, new_passphrase, &new_recovery_bytes)?;
    let file_name = format!("av-generation-{}.db", hex::encode(random_array::<16>()));
    new.database_file = Some(file_name);
    let new_database = database_path(path, &new)?;
    write_new_recovery_file(new_recovery_file, &new_recovery_key)?;
    // Publish one envelope only after its complete database generation is durable.
    // A crash before publication keeps the old pair usable; after publication the
    // envelope selects the new pair. A leftover generation contains ciphertext.
    let result = (|| -> Result<bool> {
        copy_generation(&vault, &new_database, &new_database_key)?;
        replace_envelope(path, &new)
    })();
    let durable = match result {
        Ok(durable) => durable,
        Err(error) => {
            let _ = fs::remove_file(new_recovery_file);
            let _ = fs::remove_file(&new_database);
            return Err(error);
        }
    };
    drop(vault);
    if durable {
        let _ = fs::remove_file(old_database);
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedBackup {
    version: u32,
    envelope: KeyEnvelope,
    database_hex: String,
}

/// Create a portable encrypted snapshot. It contains no plaintext secret values.
pub fn backup_vault(
    path: impl AsRef<Path>,
    passphrase: &str,
    destination: impl AsRef<Path>,
) -> Result<()> {
    let path = path.as_ref();
    let _access_lock = access_lock(path, false)?;
    let mut envelope = read_envelope(path)?;
    let key = unlock_database_key(&envelope, passphrase)?;
    let database = database_path(path, &envelope)?;
    let mut vault = open_database(&database, &key, false)?;
    let transaction = vault
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    ensure!(
        fs::metadata(&database)?.len() <= 64 * 1024 * 1024,
        "vault exceeds the 64 MiB backup limit"
    );
    let encrypted = fs::read(database)?;
    transaction.commit()?;
    envelope.database_file = None;
    let backup = EncryptedBackup {
        version: 1,
        envelope,
        database_hex: hex::encode(encrypted),
    };
    let destination = destination.as_ref();
    create_private_file(destination)?;
    if let Err(error) = write_synced(destination, &serde_json::to_vec(&backup)?) {
        let _ = fs::remove_file(destination);
        return Err(error).context("cannot write encrypted backup");
    }
    sync_parent(destination)
}

/// Restore into a new vault only, checking credentials and all database pages.
pub fn restore_vault(
    backup_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    passphrase: &str,
) -> Result<()> {
    let backup_path = backup_path.as_ref();
    let destination = destination.as_ref();
    ensure!(
        !destination.exists() && !key_path(destination).exists(),
        "restore destination already exists"
    );
    ensure!(
        fs::metadata(backup_path)?.len() <= 129 * 1024 * 1024,
        "backup is too large"
    );
    let backup: EncryptedBackup =
        serde_json::from_slice(&fs::read(backup_path)?).context("invalid encrypted backup")?;
    ensure!(
        backup.version == 1
            && backup.envelope.version == 2
            && backup.envelope.database_file.is_none(),
        "unsupported encrypted backup"
    );
    let key = unlock_database_key(&backup.envelope, passphrase)?;
    let encrypted = hex::decode(backup.database_hex).context("invalid backup ciphertext")?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let _access_lock = access_lock(destination, true)?;
    create_private_file(destination)?;
    let result = (|| -> Result<()> {
        write_synced(destination, &encrypted)?;
        let vault = open_database(destination, &key, false)?;
        let integrity: String = vault
            .conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        ensure!(integrity == "ok", "backup database integrity check failed");
        let mut statement = vault.conn.prepare("PRAGMA cipher_integrity_check")?;
        ensure!(
            statement.query([])?.next()?.is_none(),
            "backup ciphertext integrity check failed"
        );
        write_new_envelope(destination, &backup.envelope)
    })();
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

fn unlock_database_key(
    envelope: &KeyEnvelope,
    passphrase: &str,
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let salt = decode_array::<SALT_BYTES>(&envelope.passphrase_salt)?;
    let wrapping_key = Zeroizing::new(derive_key(passphrase, &salt)?);
    Ok(Zeroizing::new(
        decrypt_key(
            &wrapping_key,
            &envelope.passphrase_nonce,
            &envelope.passphrase_wrap,
        )
        .context("passphrase did not unlock vault")?,
    ))
}

impl SqlCipherBackend {
    pub fn open(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        let path = path.as_ref();
        let access_lock = access_lock(path, false)?;
        let envelope = read_envelope(path)?;
        let database_key = unlock_database_key(&envelope, passphrase)?;
        let mut backend = open_database(&database_path(path, &envelope)?, &database_key, false)?;
        backend._access_lock = Some(access_lock);
        Ok(backend)
    }
}

fn read_entry(conn: &Connection, key: &str) -> Result<Option<BackendEntry>> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        "SELECT s.value, p.policy FROM secrets s LEFT JOIN secret_policies p ON p.name=s.name WHERE s.name=?1",
        [key],
        |row| Ok(BackendEntry {
            value: Zeroizing::new(row.get(0)?),
            policy: row.get(1)?,
        }),
    ).optional().map_err(Into::into)
}

impl SecretBackend for SqlCipherBackend {
    fn read(&self, key: &str) -> Result<Option<BackendEntry>> {
        read_entry(&self.conn, key)
    }

    fn list(&self) -> Result<Vec<String>> {
        let mut statement = self
            .conn
            .prepare("SELECT name FROM secrets ORDER BY name")?;
        let rows = statement.query_map([], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    fn apply(&self, mutations: &[BackendMutation]) -> Result<()> {
        let mut keys = std::collections::HashSet::new();
        for mutation in mutations {
            ensure!(
                keys.insert(mutation.key.as_str()),
                "duplicate storage mutation key"
            );
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.conn,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        for mutation in mutations {
            ensure!(
                read_entry(&tx, &mutation.key)? == mutation.expected,
                "stored entry changed; review and retry"
            );
        }
        for mutation in mutations {
            tx.execute("DELETE FROM secret_policies WHERE name=?1", [&mutation.key])?;
            match &mutation.replacement {
                Some(entry) => {
                    tx.execute("INSERT INTO secrets(name, value) VALUES(?1, ?2) ON CONFLICT(name) DO UPDATE SET value=excluded.value", params![mutation.key, entry.value.as_str()])?;
                    if let Some(policy) = &entry.policy {
                        tx.execute(
                            "INSERT INTO secret_policies(name, policy) VALUES(?1, ?2)",
                            params![mutation.key, policy],
                        )?;
                    }
                }
                None => {
                    tx.execute("DELETE FROM secrets WHERE name=?1", [&mutation.key])?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }
}

fn make_envelope(
    database_key: &[u8; KEY_BYTES],
    passphrase: &str,
    recovery_key: &[u8; KEY_BYTES],
) -> Result<KeyEnvelope> {
    let salt = random_array::<SALT_BYTES>();
    let wrapping_key = Zeroizing::new(derive_key(passphrase, &salt)?);
    let (passphrase_nonce, passphrase_wrap) = encrypt_key(&wrapping_key, database_key)?;
    let (recovery_nonce, recovery_wrap) = encrypt_key(recovery_key, database_key)?;
    Ok(KeyEnvelope {
        version: 2,
        passphrase_salt: hex::encode(salt),
        passphrase_nonce,
        passphrase_wrap,
        recovery_nonce,
        recovery_wrap,
        database_file: None,
    })
}

fn derive_key(passphrase: &str, salt: &[u8; SALT_BYTES]) -> Result<[u8; KEY_BYTES]> {
    let params = Params::new(64 * 1024, 3, 1, Some(KEY_BYTES))
        .map_err(|_| anyhow::anyhow!("invalid Argon2id parameters"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived = [0u8; KEY_BYTES];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut derived)
        .map_err(|_| anyhow::anyhow!("key derivation failed"))?;
    Ok(derived)
}

fn encrypt_key(key: &[u8; KEY_BYTES], plaintext: &[u8; KEY_BYTES]) -> Result<(String, String)> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
        .map_err(|_| anyhow::anyhow!("key wrap failed"))?;
    Ok((hex::encode(nonce), hex::encode(encrypted)))
}

fn decrypt_key(key: &[u8; KEY_BYTES], nonce: &str, ciphertext: &str) -> Result<[u8; KEY_BYTES]> {
    let nonce = decode_array::<NONCE_BYTES>(nonce)?;
    let ciphertext = hex::decode(ciphertext).context("invalid key wrap")?;
    let cipher = ChaCha20Poly1305::new(key.into());
    let decrypted = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice())
            .map_err(|_| anyhow::anyhow!("key unwrap failed"))?,
    );
    decrypted
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid unwrapped key length"))
}

fn open_database(path: &Path, key: &[u8; KEY_BYTES], create: bool) -> Result<SqlCipherBackend> {
    if create {
        create_private_file(path)?;
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags).context("cannot open encrypted vault")?;
    conn.execute_batch(&format!(
        "PRAGMA key = \"x'{}'\";",
        hex::encode(key.as_slice())
    ))?;
    let version: String = conn
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .context("SQLCipher support is unavailable")?;
    ensure!(!version.is_empty(), "SQLCipher support is unavailable");
    if !create {
        conn.query_row("SELECT count(*) FROM secrets", [], |row| {
            row.get::<_, i64>(0)
        })
        .context("vault could not be opened with this key")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS secret_policies (name TEXT PRIMARY KEY NOT NULL REFERENCES secrets(name), policy TEXT NOT NULL);")?;
    }
    conn.execute_batch(
        "PRAGMA journal_mode = DELETE; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;",
    )?;
    Ok(SqlCipherBackend {
        conn,
        _access_lock: None,
    })
}

fn access_lock(path: &Path, exclusive: bool) -> Result<fs::File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path.with_extension("access.lock"))
        .context("cannot open vault access lock")?;
    let locked = if exclusive {
        fs2::FileExt::try_lock_exclusive(&file)
    } else {
        fs2::FileExt::try_lock_shared(&file)
    };
    locked.context("vault is in use; close other vault consumers before rotation or restore")?;
    Ok(file)
}

fn key_path(path: &Path) -> PathBuf {
    path.with_extension("keys.json")
}

fn read_envelope(path: &Path) -> Result<KeyEnvelope> {
    let content = fs::read(key_path(path)).context("cannot read vault key envelope")?;
    let envelope: KeyEnvelope =
        serde_json::from_slice(&content).context("invalid vault key envelope")?;
    ensure!(envelope.version == 2, "unsupported vault envelope version");
    Ok(envelope)
}

fn write_new_envelope(path: &Path, envelope: &KeyEnvelope) -> Result<()> {
    let serialized = serde_json::to_vec(envelope)?;
    create_private_file(&key_path(path))?;
    if let Err(error) = write_synced(&key_path(path), &serialized)
        .map_err(anyhow::Error::from)
        .and_then(|_| sync_parent(path))
    {
        let _ = fs::remove_file(key_path(path));
        return Err(error).context("cannot persist vault key envelope");
    }
    Ok(())
}

fn replace_envelope(path: &Path, envelope: &KeyEnvelope) -> Result<bool> {
    let target = key_path(path);
    let temporary = target.with_extension("keys.new");
    discard_unpublished_envelope(path, &temporary)?;
    create_private_file(&temporary)?;
    let result = write_synced(&temporary, &serde_json::to_vec(envelope)?).and_then(|_| {
        #[cfg(all(test, unix))]
        tests::rotation_crash_checkpoint(path, "before_publication");
        fs::rename(&temporary, target)
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.context("cannot replace vault key envelope")?;
    // Once renamed, returning an error could cause callers to remove the newly
    // published database. The old generation remains safe if directory sync fails.
    let durable = sync_parent(path).is_ok();
    #[cfg(all(test, unix))]
    tests::rotation_crash_checkpoint(path, "after_publication");
    Ok(durable)
}

/// Rotation and recovery hold the vault's exclusive access lock before reaching
/// this point. A valid leftover envelope was never published; only that file is
/// discarded. Its ciphertext and recovery file remain for operator inspection.
fn discard_unpublished_envelope(path: &Path, temporary: &Path) -> Result<()> {
    let pending_metadata = match fs::symlink_metadata(temporary) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(metadata) => metadata,
    };
    #[cfg(not(unix))]
    {
        let _ = (path, pending_metadata);
        anyhow::bail!(
            "a previous recovery update is pending; secure automatic cleanup is unavailable on this platform"
        );
    }
    #[cfg(unix)]
    {
        use std::{io::Read, os::unix::fs::MetadataExt};
        let published_path = key_path(path);
        let published_metadata = fs::symlink_metadata(&published_path)?;
        let directory = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let directory_metadata = fs::symlink_metadata(directory)?;
        let owner = published_metadata.uid();
        ensure!(
            directory_metadata.is_dir()
                && directory_metadata.uid() == owner
                && directory_metadata.mode() & 0o022 == 0,
            "pending envelope requires a trusted vault directory"
        );
        let private_file = |metadata: &fs::Metadata| {
            metadata.file_type().is_file()
                && metadata.uid() == owner
                && metadata.nlink() == 1
                && metadata.mode() & 0o077 == 0
        };
        ensure!(
            private_file(&published_metadata)
                && private_file(&pending_metadata)
                && pending_metadata.len() <= 16 * 1024,
            "pending envelope ownership, type, permissions, or links are unsafe"
        );
        let pending_file = fs::File::open(temporary)?;
        let opened_metadata = pending_file.metadata()?;
        ensure!(
            opened_metadata.dev() == pending_metadata.dev()
                && opened_metadata.ino() == pending_metadata.ino()
                && private_file(&opened_metadata),
            "pending envelope changed while opening"
        );
        let mut bytes = Vec::new();
        pending_file.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 16 * 1024, "pending envelope is too large");
        let pending: KeyEnvelope =
            serde_json::from_slice(&bytes).context("malformed pending envelope")?;
        ensure!(
            pending.version == 2 && pending.database_file.is_some(),
            "invalid pending envelope generation"
        );
        decode_array::<SALT_BYTES>(&pending.passphrase_salt)?;
        decode_array::<NONCE_BYTES>(&pending.passphrase_nonce)?;
        decode_array::<NONCE_BYTES>(&pending.recovery_nonce)?;
        decode_array::<{ KEY_BYTES + 16 }>(&pending.passphrase_wrap)?;
        decode_array::<{ KEY_BYTES + 16 }>(&pending.recovery_wrap)?;
        let published_bytes = fs::read(&published_path)?;
        let published: KeyEnvelope = serde_json::from_slice(&published_bytes)?;
        let pending_database = database_path(path, &pending)?;
        ensure!(
            pending_database != database_path(path, &published)?,
            "pending envelope names the published database"
        );
        ensure!(
            private_file(&fs::symlink_metadata(&pending_database)?),
            "pending database ownership, type, permissions, or links are unsafe"
        );
        let final_metadata = fs::symlink_metadata(temporary)?;
        ensure!(
            private_file(&final_metadata)
                && final_metadata.dev() == pending_metadata.dev()
                && final_metadata.ino() == pending_metadata.ino(),
            "pending envelope changed before cleanup"
        );
        ensure!(
            fs::read(&published_path)? == published_bytes,
            "published envelope changed during cleanup"
        );
        fs::remove_file(temporary)?;
        sync_parent(temporary)
    }
}

fn initialize_schema(vault: &SqlCipherBackend) -> Result<()> {
    vault.conn.execute_batch("CREATE TABLE secrets (name TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL); CREATE TABLE secret_policies (name TEXT PRIMARY KEY NOT NULL REFERENCES secrets(name), policy TEXT NOT NULL);")?;
    Ok(())
}

fn database_path(path: &Path, envelope: &KeyEnvelope) -> Result<PathBuf> {
    match &envelope.database_file {
        None => Ok(path.to_owned()),
        Some(name) => {
            let id = name
                .strip_prefix("av-generation-")
                .and_then(|n| n.strip_suffix(".db"))
                .context("invalid vault database generation")?;
            ensure!(
                id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid vault database generation"
            );
            Ok(path.with_file_name(name))
        }
    }
}

fn copy_generation(
    source: &SqlCipherBackend,
    destination: &Path,
    key: &[u8; KEY_BYTES],
) -> Result<()> {
    let transaction = source.conn.unchecked_transaction()?;
    let target = open_database(destination, key, true)?;
    initialize_schema(&target)?;
    let target_transaction = target.conn.unchecked_transaction()?;
    for name in source.list()? {
        let entry =
            read_entry(&transaction, &name)?.context("secret disappeared during rotation")?;
        validate_key(&name)?;
        validate_value(&entry.value)?;
        entry_policy(&entry)?;
        target_transaction.execute(
            "INSERT INTO secrets(name, value) VALUES(?1, ?2)",
            params![name, entry.value.as_str()],
        )?;
        if let Some(policy) = &entry.policy {
            target_transaction.execute(
                "INSERT INTO secret_policies(name, policy) VALUES(?1, ?2)",
                params![name, policy],
            )?;
        }
    }
    target_transaction.commit()?;
    transaction.commit()?;
    drop(target);
    OpenOptions::new()
        .write(true)
        .open(destination)?
        .sync_all()
        .context("cannot flush rotated vault database")?;
    sync_parent(destination)
}

fn write_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn write_new_recovery_file(path: &Path, recovery_key: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create new recovery file {}", path.display()))?;
    if let Err(error) = file
        .write_all(recovery_key.as_bytes())
        .and_then(|_| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error).context("cannot persist new recovery key");
    }
    if let Err(error) = sync_parent(path) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error).context("cannot persist recovery file directory entry");
    }
    Ok(())
}

fn create_private_file(path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    Ok(())
}

fn decode_array<const N: usize>(raw: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(raw).context("invalid hexadecimal key data")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid key data length"))
}

fn random_array<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_batch_rolls_back_after_a_database_write_failure() {
        let directory = tempfile::tempdir().unwrap();
        let backend =
            open_database(&directory.path().join("vault.db"), &random_array(), true).unwrap();
        initialize_schema(&backend).unwrap();
        backend.conn.execute_batch("CREATE TRIGGER reject_test_write BEFORE INSERT ON secrets WHEN NEW.name='demo/fail' BEGIN SELECT RAISE(ABORT, 'synthetic write failure'); END;").unwrap();
        let mutations = ["demo/first", "demo/fail"].map(|key| BackendMutation {
            key: key.into(),
            expected: None,
            replacement: Some(BackendEntry::new("synthetic value".into())),
        });
        assert!(backend.apply(&mutations).is_err());
        assert!(backend.list().unwrap().is_empty());
    }

    #[test]
    fn roundtrip_wrong_password_and_independent_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.db");
        let created = create_vault(&path, "old passphrase").unwrap();
        created
            .vault
            .set("demo/token", "synthetic-secret-value")
            .unwrap();
        assert_eq!(created.vault.list().unwrap(), vec!["demo/token"]);
        drop(created.vault);
        assert!(Vault::open(&path, "wrong passphrase").is_err());
        let new_recovery_file = directory.path().join("new.recovery");
        recover_vault(
            &path,
            &created.recovery_key,
            "new passphrase",
            &new_recovery_file,
        )
        .unwrap();
        let new_recovery_key = fs::read_to_string(&new_recovery_file).unwrap();
        assert_ne!(created.recovery_key.as_str(), new_recovery_key);
        assert!(Vault::open(&path, "old passphrase").is_err());
        let reopened = Vault::open(&path, "new passphrase").unwrap();
        assert_eq!(
            reopened.get("demo/token").unwrap().as_deref(),
            Some("synthetic-secret-value")
        );
        let disk = fs::read(database_path(&path, &read_envelope(&path).unwrap()).unwrap()).unwrap();
        assert!(
            !disk
                .windows("synthetic-secret-value".len())
                .any(|w| w == b"synthetic-secret-value")
        );
        let unauthorized_file = directory.path().join("unauthorized.recovery");
        assert!(
            recover_vault(
                &path,
                &created.recovery_key,
                "unauthorized",
                &unauthorized_file
            )
            .is_err()
        );
        assert!(!unauthorized_file.exists());
        drop(reopened);
        recover_vault(
            &path,
            &new_recovery_key,
            "recovered again",
            directory.path().join("third.recovery"),
        )
        .unwrap();
        assert!(Vault::open(&path, "recovered again").is_ok());
    }

    #[test]
    fn invalid_recovery_key_preserves_passphrase() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.db");
        let created = create_vault(&path, "passphrase").unwrap();
        drop(created.vault);
        assert!(
            recover_vault(
                &path,
                &"00".repeat(32),
                "replacement",
                directory.path().join("invalid.recovery")
            )
            .is_err()
        );
        assert!(Vault::open(&path, "passphrase").is_ok());
    }

    #[test]
    fn existing_new_recovery_file_leaves_old_envelope() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.db");
        let created = create_vault(&path, "old passphrase").unwrap();
        drop(created.vault);
        let occupied = directory.path().join("occupied.recovery");
        fs::write(&occupied, b"do not overwrite").unwrap();
        assert!(recover_vault(&path, &created.recovery_key, "new passphrase", &occupied).is_err());
        assert_eq!(fs::read(&occupied).unwrap(), b"do not overwrite");
        assert!(Vault::open(&path, "old passphrase").is_ok());
        assert!(Vault::open(&path, "new passphrase").is_err());
        recover_vault(
            &path,
            &created.recovery_key,
            "retry",
            directory.path().join("retry.recovery"),
        )
        .unwrap();
        assert!(Vault::open(&path, "retry").is_ok());
    }

    #[test]
    fn envelope_replace_failure_keeps_old_credentials_valid() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.db");
        let created = create_vault(&path, "old passphrase").unwrap();
        drop(created.vault);
        let pending = key_path(&path).with_extension("keys.new");
        fs::write(&pending, b"occupied").unwrap();
        let next_recovery_file = directory.path().join("next.recovery");
        assert!(
            recover_vault(
                &path,
                &created.recovery_key,
                "new passphrase",
                &next_recovery_file
            )
            .is_err()
        );
        assert!(!next_recovery_file.exists());
        assert!(Vault::open(&path, "old passphrase").is_ok());
        fs::remove_file(&pending).unwrap();
    }

    #[test]
    fn rotation_reencrypts_pages_and_refuses_live_handles() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.db");
        let created = create_vault(&path, "old passphrase").unwrap();
        created.vault.add("demo/token", "synthetic-value").unwrap();
        let old_envelope = read_envelope(&path).unwrap();
        let old_key = unlock_database_key(&old_envelope, "old passphrase").unwrap();
        let recovery = directory.path().join("new.recovery");
        assert!(rotate_vault_key(&path, "old passphrase", "new passphrase", &recovery).is_err());
        assert!(!recovery.exists());
        drop(created.vault);
        rotate_vault_key(&path, "old passphrase", "new passphrase", &recovery).unwrap();
        let new_envelope = read_envelope(&path).unwrap();
        let new_key = unlock_database_key(&new_envelope, "new passphrase").unwrap();
        assert_ne!(*old_key, *new_key);
        let database = database_path(&path, &new_envelope).unwrap();
        assert!(open_database(&database, &old_key, false).is_err());
        assert_eq!(
            Vault::open(&path, "new passphrase")
                .unwrap()
                .get("demo/token")
                .unwrap()
                .as_deref(),
            Some("synthetic-value")
        );
    }

    #[test]
    fn unpublished_generation_does_not_replace_the_current_vault() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.db");
        let created = create_vault(&path, "old passphrase").unwrap();
        created.vault.add("demo/token", "synthetic-value").unwrap();
        drop(created.vault);

        let old_envelope = read_envelope(&path).unwrap();
        let old_key = unlock_database_key(&old_envelope, "old passphrase").unwrap();
        let mut staged_envelope =
            make_envelope(&random_array(), "new passphrase", &random_array()).unwrap();
        staged_envelope.version = 2;
        staged_envelope.database_file = Some(format!("av-generation-{}.db", "a".repeat(32)));
        let staged_database = database_path(&path, &staged_envelope).unwrap();
        let staged_key = unlock_database_key(&staged_envelope, "new passphrase").unwrap();
        let source = open_database(&path, &old_key, false).unwrap();
        copy_generation(&source, &staged_database, &staged_key).unwrap();
        drop(source);

        // The database was written, but publication did not happen. The old
        // envelope remains the only authority after restart.
        assert_eq!(
            Vault::open(&path, "old passphrase")
                .unwrap()
                .get("demo/token")
                .unwrap()
                .as_deref(),
            Some("synthetic-value")
        );
        assert!(Vault::open(&path, "new passphrase").is_err());
        rotate_vault_key(
            &path,
            "old passphrase",
            "retry passphrase",
            directory.path().join("retry.recovery"),
        )
        .unwrap();
        assert!(Vault::open(&path, "retry passphrase").is_ok());
    }

    #[test]
    fn published_generation_survives_old_database_cleanup_interruption() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.db");
        let created = create_vault(&path, "old passphrase").unwrap();
        created.vault.add("demo/token", "synthetic-value").unwrap();
        drop(created.vault);

        let old_envelope = read_envelope(&path).unwrap();
        let old_key = unlock_database_key(&old_envelope, "old passphrase").unwrap();
        let mut new_envelope =
            make_envelope(&random_array(), "new passphrase", &random_array()).unwrap();
        new_envelope.version = 2;
        new_envelope.database_file = Some(format!("av-generation-{}.db", "b".repeat(32)));
        let new_database = database_path(&path, &new_envelope).unwrap();
        let new_key = unlock_database_key(&new_envelope, "new passphrase").unwrap();
        let source = open_database(&path, &old_key, false).unwrap();
        copy_generation(&source, &new_database, &new_key).unwrap();
        drop(source);
        assert!(replace_envelope(&path, &new_envelope).unwrap());

        // Cleanup did not happen. The newly published pair still opens, and
        // the old passphrase cannot select the old database anymore.
        assert!(path.exists());
        assert!(Vault::open(&path, "old passphrase").is_err());
        assert_eq!(
            Vault::open(&path, "new passphrase")
                .unwrap()
                .get("demo/token")
                .unwrap()
                .as_deref(),
            Some("synthetic-value")
        );
    }

    /// Only the dedicated child test can activate these checkpoints. Killing
    /// it exercises OS lock release and bypasses all Rust cleanup handlers.
    #[cfg(unix)]
    pub(super) fn rotation_crash_checkpoint(path: &Path, stage: &str) {
        if std::env::var("AV_CORE_TEST_CRASH_STAGE").as_deref() != Ok(stage)
            || std::env::var_os("AV_CORE_TEST_CRASH_VAULT").as_deref() != Some(path.as_os_str())
        {
            return;
        }
        println!("AV_CORE_TEST_CHECKPOINT:{stage}");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }

    #[cfg(unix)]
    mod process_interruption {
        use super::*;
        use std::{
            io::{BufRead, BufReader},
            os::unix::{
                fs::{MetadataExt, PermissionsExt},
                process::ExitStatusExt,
            },
            process::{Child, Command, Stdio},
            sync::mpsc,
            time::{Duration, Instant},
        };

        const OLD_PASSPHRASE: &str = "synthetic original passphrase";
        const NEW_PASSPHRASE: &str = "synthetic replacement passphrase";
        const FINAL_PASSPHRASE: &str = "synthetic recovered passphrase";
        const SECRET: &str = "synthetic process interruption value";
        const CHILD_TEST: &str = "store::sqlcipher::tests::process_interruption::child_operation";

        #[derive(Serialize, Deserialize)]
        struct ChildInput {
            vault: PathBuf,
            operation: String,
            recovery_key: String,
            recovery_file: PathBuf,
        }

        struct ChildGuard(Child);

        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        fn spawn_child(input: &ChildInput, stage: Option<&str>) -> ChildGuard {
            // Cargo can replace the on-disk test executable during a concurrent
            // build. Linux can re-exec the exact still-running image through proc.
            #[cfg(target_os = "linux")]
            let executable = PathBuf::from("/proc/self/exe");
            #[cfg(not(target_os = "linux"))]
            let executable = std::env::current_exe().unwrap();
            let mut command = Command::new(executable);
            command
                .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
                .env_remove("AV_CORE_TEST_CRASH_STAGE")
                .env_remove("AV_CORE_TEST_CRASH_VAULT")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
            if let Some(stage) = stage {
                command
                    .env("AV_CORE_TEST_CRASH_STAGE", stage)
                    .env("AV_CORE_TEST_CRASH_VAULT", &input.vault);
            }
            let mut child = ChildGuard(command.spawn().unwrap());
            let mut bytes = Zeroizing::new(serde_json::to_vec(input).unwrap());
            bytes.push(b'\n');
            child.0.stdin.take().unwrap().write_all(&bytes).unwrap();
            child
        }

        fn wait_for_checkpoint(child: &mut ChildGuard, stage: &str) {
            let stdout = child.0.stdout.take().unwrap();
            let expected = format!("AV_CORE_TEST_CHECKPOINT:{stage}");
            let (sender, receiver) = mpsc::channel();
            std::thread::spawn(move || {
                let reached = BufReader::new(stdout)
                    .lines()
                    .any(|line| line.unwrap().contains(&expected));
                let _ = sender.send(reached);
            });
            assert!(
                receiver
                    .recv_timeout(Duration::from_secs(45))
                    .expect("rotation child did not reach checkpoint"),
                "rotation child exited before checkpoint"
            );
        }

        fn verify_in_fresh_process(path: &Path, published: bool) {
            let mut child = spawn_child(
                &ChildInput {
                    vault: path.to_owned(),
                    operation: if published {
                        "verify_new"
                    } else {
                        "verify_old"
                    }
                    .into(),
                    recovery_key: String::new(),
                    recovery_file: PathBuf::new(),
                },
                None,
            );
            let deadline = Instant::now() + Duration::from_secs(45);
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    assert!(status.success(), "restarted vault reader failed");
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "restarted vault reader timed out"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        #[test]
        #[ignore = "subprocess helper; invoked by the interruption tests"]
        fn child_operation() {
            let mut line = Zeroizing::new(String::new());
            std::io::stdin().lock().read_line(&mut line).unwrap();
            let input: ChildInput = serde_json::from_str(&line).unwrap();
            match input.operation.as_str() {
                "rotate" => rotate_vault_key(
                    &input.vault,
                    OLD_PASSPHRASE,
                    NEW_PASSPHRASE,
                    &input.recovery_file,
                )
                .unwrap(),
                "recover" => recover_vault(
                    &input.vault,
                    &input.recovery_key,
                    NEW_PASSPHRASE,
                    &input.recovery_file,
                )
                .unwrap(),
                "verify_old" | "verify_new" => {
                    let (working, rejected) = if input.operation == "verify_old" {
                        (OLD_PASSPHRASE, NEW_PASSPHRASE)
                    } else {
                        (NEW_PASSPHRASE, OLD_PASSPHRASE)
                    };
                    assert!(Vault::open(&input.vault, rejected).is_err());
                    let vault = Vault::open(&input.vault, working).unwrap();
                    assert_fixture(&vault);
                    return;
                }
                _ => panic!("invalid child operation"),
            }
            panic!("rotation unexpectedly returned before its interruption checkpoint");
        }

        fn fixture_policy() -> SecretPolicy {
            SecretPolicy {
                grants: vec![crate::SecretGrant {
                    request: crate::SecretAccessRequest {
                        executable: "/usr/bin/synthetic-fixture".into(),
                        executable_sha256: "a".repeat(64),
                        arguments: vec!["synthetic".into()],
                        config_path: "/synthetic/config.toml".into(),
                        config_sha256: "b".repeat(64),
                        working_directory: "/synthetic".into(),
                        environment: None,
                        delivery: crate::DeliveryMode::Direct,
                        host: None,
                        macos_service: None,
                        upstream_ca_sha256: None,
                    },
                    approval: ApprovalRequirement::EveryRun,
                }],
            }
        }

        fn assert_fixture(vault: &Vault) {
            assert_eq!(vault.get("demo/token").unwrap().as_deref(), Some(SECRET));
            assert_eq!(vault.policy("demo/token").unwrap(), fixture_policy());
        }

        fn exercise_interruption(operation: &str, published: bool) {
            let directory = tempfile::tempdir().unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let path = directory.path().join("vault.db");
            let created = create_vault(&path, OLD_PASSPHRASE).unwrap();
            created.vault.add("demo/token", SECRET).unwrap();
            created
                .vault
                .set_policy("demo/token", &fixture_policy())
                .unwrap();
            let old_envelope_bytes = fs::read(key_path(&path)).unwrap();
            let old_key =
                unlock_database_key(&read_envelope(&path).unwrap(), OLD_PASSPHRASE).unwrap();
            drop(created.vault);
            let next_recovery = directory.path().join("replacement.recovery");
            let stage = if published {
                "after_publication"
            } else {
                "before_publication"
            };
            let mut child = spawn_child(
                &ChildInput {
                    vault: path.clone(),
                    operation: operation.into(),
                    recovery_key: created.recovery_key.to_string(),
                    recovery_file: next_recovery.clone(),
                },
                Some(stage),
            );
            wait_for_checkpoint(&mut child, stage);
            // The writer still holds its exclusive access lock at the checkpoint.
            assert!(Vault::open(&path, OLD_PASSPHRASE).is_err());
            child.0.kill().unwrap();
            assert_eq!(child.0.wait().unwrap().signal(), Some(9));
            drop(child);

            let replacement_key = Zeroizing::new(fs::read_to_string(&next_recovery).unwrap());
            assert!(decode_array::<KEY_BYTES>(&replacement_key).is_ok());
            assert_ne!(replacement_key.as_str(), created.recovery_key.as_str());
            let metadata = fs::metadata(&next_recovery).unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
            assert_eq!(metadata.len(), 64);
            let pending = key_path(&path).with_extension("keys.new");
            assert_eq!(pending.exists(), !published);
            assert!(
                path.exists(),
                "old ciphertext was removed before the cleanup checkpoint"
            );
            verify_in_fresh_process(&path, published);
            let failed_recovery = directory.path().join("rejected.recovery");
            let accepted_recovery = directory.path().join("final.recovery");

            if published {
                assert_ne!(fs::read(key_path(&path)).unwrap(), old_envelope_bytes);
                let current = read_envelope(&path).unwrap();
                let new_database = database_path(&path, &current).unwrap();
                assert!(open_database(&new_database, &old_key, false).is_err());
                assert!(
                    recover_vault(
                        &path,
                        &created.recovery_key,
                        FINAL_PASSPHRASE,
                        &failed_recovery
                    )
                    .is_err()
                );
                assert!(!failed_recovery.exists());
                // Old ciphertext can remain after interrupted cleanup; it is not
                // the active generation and is not represented as secure erasure.
                assert_fixture(&Vault::from_backend(
                    open_database(&path, &old_key, false).unwrap(),
                ));
                recover_vault(
                    &path,
                    &replacement_key,
                    FINAL_PASSPHRASE,
                    &accepted_recovery,
                )
                .unwrap();
            } else {
                assert_eq!(fs::read(key_path(&path)).unwrap(), old_envelope_bytes);
                assert!(
                    recover_vault(&path, &replacement_key, FINAL_PASSPHRASE, &failed_recovery)
                        .is_err()
                );
                assert!(!failed_recovery.exists());
                // Reusing an orphan recovery filename must never overwrite it.
                assert!(
                    recover_vault(
                        &path,
                        &created.recovery_key,
                        FINAL_PASSPHRASE,
                        &next_recovery
                    )
                    .is_err()
                );
                assert_eq!(fs::read(key_path(&path)).unwrap(), old_envelope_bytes);
                assert_eq!(
                    fs::read_to_string(&next_recovery).unwrap(),
                    replacement_key.as_str()
                );
                let staged: KeyEnvelope =
                    serde_json::from_slice(&fs::read(&pending).unwrap()).unwrap();
                let orphan_database = database_path(&path, &staged).unwrap();
                assert!(orphan_database.exists());
                if operation == "rotate" {
                    rotate_vault_key(&path, OLD_PASSPHRASE, FINAL_PASSPHRASE, &accepted_recovery)
                        .unwrap();
                } else {
                    recover_vault(
                        &path,
                        &created.recovery_key,
                        FINAL_PASSPHRASE,
                        &accepted_recovery,
                    )
                    .unwrap();
                }
                assert!(!pending.exists());
                assert!(orphan_database.exists(), "retry removed orphan ciphertext");
                assert_eq!(
                    fs::read_to_string(&next_recovery).unwrap(),
                    replacement_key.as_str()
                );
            }
            assert!(Vault::open(&path, OLD_PASSPHRASE).is_err());
            assert!(Vault::open(&path, NEW_PASSPHRASE).is_err());
            assert_fixture(&Vault::open(&path, FINAL_PASSPHRASE).unwrap());
            let final_key = fs::read_to_string(&accepted_recovery).unwrap();
            assert_ne!(final_key, replacement_key.as_str());
            assert_ne!(final_key, created.recovery_key.as_str());
            for revoked_key in [created.recovery_key.as_str(), replacement_key.as_str()] {
                assert!(
                    recover_vault(
                        &path,
                        revoked_key,
                        "synthetic invalid recovery",
                        &failed_recovery
                    )
                    .is_err()
                );
                assert!(!failed_recovery.exists());
            }
            assert_eq!(
                fs::read_to_string(&next_recovery).unwrap(),
                replacement_key.as_str()
            );
        }

        #[test]
        fn stale_envelope_cleanup_rejects_unsafe_or_unrelated_artifacts() {
            use std::os::unix::fs::symlink;
            let directory = tempfile::tempdir().unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let path = directory.path().join("vault.db");
            let created = create_vault(&path, OLD_PASSPHRASE).unwrap();
            let original = fs::read(key_path(&path)).unwrap();
            let pending = key_path(&path).with_extension("keys.new");
            let mut staged =
                make_envelope(&random_array(), NEW_PASSPHRASE, &random_array()).unwrap();
            staged.version = 2;
            staged.database_file = Some(format!("av-generation-{}.db", "f".repeat(32)));
            let orphan_database = database_path(&path, &staged).unwrap();
            let key = unlock_database_key(&staged, NEW_PASSPHRASE).unwrap();
            let source_key =
                unlock_database_key(&read_envelope(&path).unwrap(), OLD_PASSPHRASE).unwrap();
            let source = open_database(&path, &source_key, false).unwrap();
            copy_generation(&source, &orphan_database, &key).unwrap();
            drop(source);
            drop(created.vault);
            let _exclusive = access_lock(&path, true).unwrap();
            let stage = || {
                create_private_file(&pending).unwrap();
                write_synced(&pending, &serde_json::to_vec(&staged).unwrap()).unwrap();
            };

            symlink(key_path(&path), &pending).unwrap();
            assert!(discard_unpublished_envelope(&path, &pending).is_err());
            assert!(
                fs::symlink_metadata(&pending)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            fs::remove_file(&pending).unwrap();
            fs::hard_link(key_path(&path), &pending).unwrap();
            assert!(discard_unpublished_envelope(&path, &pending).is_err());
            fs::remove_file(&pending).unwrap();
            stage();
            fs::set_permissions(&pending, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(discard_unpublished_envelope(&path, &pending).is_err());
            fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777)).unwrap();
            assert!(discard_unpublished_envelope(&path, &pending).is_err());
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            write_synced(&pending, b"not an envelope").unwrap();
            assert!(discard_unpublished_envelope(&path, &pending).is_err());
            write_synced(&pending, &original).unwrap();
            assert!(discard_unpublished_envelope(&path, &pending).is_err());
            fs::remove_file(&pending).unwrap();
            stage();
            fs::set_permissions(&orphan_database, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(discard_unpublished_envelope(&path, &pending).is_err());
            fs::set_permissions(&orphan_database, fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(fs::read(key_path(&path)).unwrap(), original);
            discard_unpublished_envelope(&path, &pending).unwrap();
            assert!(!pending.exists());
            assert!(orphan_database.exists());
            assert_eq!(fs::read(key_path(&path)).unwrap(), original);
        }

        #[test]
        fn rotation_process_death_before_publication() {
            exercise_interruption("rotate", false);
        }
        #[test]
        fn rotation_process_death_after_publication() {
            exercise_interruption("rotate", true);
        }
        #[test]
        fn recovery_process_death_before_publication() {
            exercise_interruption("recover", false);
        }
        #[test]
        fn recovery_process_death_after_publication() {
            exercise_interruption("recover", true);
        }
    }
}
