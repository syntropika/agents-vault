//! Operator-owned task editing. Saves revoke grants before replacing policy bytes.
use crate::{ProxyPolicy, session::VaultSource};
use anyhow::{Context, Result, ensure};
use av_core::Vault;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRecipe {
    pub connection: String,
    pub connection_version: u64,
    pub host: String,
    pub command: Vec<String>,
    pub max_connects: u32,
    pub max_requests: u32,
    pub max_runtime_seconds: u64,
    pub upstream_addr: std::net::SocketAddr,
    pub upstream_ca_der: PathBuf,
}

pub(crate) fn path(source: &VaultSource) -> PathBuf {
    source
        .proxy_policy
        .clone()
        .unwrap_or_else(|| source.vault.with_extension("proxy.json"))
}
pub(crate) fn existing_path(source: &VaultSource) -> Result<Option<PathBuf>> {
    let path = path(source);
    match fs::symlink_metadata(&path) {
        Ok(_) => Ok(Some(path)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
fn read(path: &Path) -> Result<Option<(ProxyPolicy, Vec<u8>)>> {
    if fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return Ok(None);
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.nlink() == 1 && meta.mode() & 0o077 == 0 && meta.len() <= 16 * 1024,
        "invalid task policy file"
    );
    let mut bytes = Vec::new();
    file.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16 * 1024, "task policy is too large");
    let policy: ProxyPolicy = serde_json::from_slice(&bytes)?;
    policy.validate()?;
    Ok(Some((policy, bytes)))
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn view(policy: &ProxyPolicy) -> Value {
    json!({"connection":policy.connection,"connection_version":policy.connection_version,
        "host":policy.host,"command":policy.command,"max_connects":policy.max_connects,
        "max_requests":policy.max_requests,"max_runtime_seconds":policy.max_runtime_seconds,
        "upstream_addr":policy.upstream_addr,"upstream_ca_der":policy.upstream_ca_der})
}
pub(crate) fn show(source: &VaultSource) -> Result<Value> {
    match read(&path(source))? {
        Some((policy, bytes)) => Ok(
            json!({"recipe":view(&policy),"revision":digest(&bytes),"editable":policy.host_client,"capacity":1}),
        ),
        None => Ok(json!({"recipe":null,"revision":null,"editable":true,"capacity":1})),
    }
}
pub(crate) fn save(
    vault: &Vault,
    source: &VaultSource,
    expected_revision: &Option<String>,
    recipe: &TaskRecipe,
) -> Result<Value> {
    let destination = path(source);
    let previous = read(&destination)?;
    ensure!(
        previous.as_ref().map(|(_, bytes)| digest(bytes)) == *expected_revision,
        "task revision changed; refresh before saving"
    );
    ensure!(
        previous.as_ref().is_none_or(|(p, _)| p.host_client),
        "guest policies must be provisioned by the service installer"
    );
    let metadata = vault
        .connection_metadata(&recipe.connection)?
        .context("connection does not exist")?;
    ensure!(
        metadata.active
            && metadata.version == recipe.connection_version
            && metadata.host == recipe.host,
        "connection version or destination changed"
    );
    let policy = ProxyPolicy {
        connection: recipe.connection.clone(),
        secret_name: String::new(),
        connection_version: Some(recipe.connection_version),
        host: recipe.host.clone(),
        command: recipe.command.clone(),
        upstream_addr: recipe.upstream_addr,
        upstream_ca_der: recipe.upstream_ca_der.clone(),
        max_connects: recipe.max_connects,
        max_requests: recipe.max_requests,
        max_runtime_seconds: recipe.max_runtime_seconds,
        host_client: true,
        #[cfg(target_os = "linux")]
        runner_helper: None,
        mac_vmm: None,
        mac_guest_bundle: None,
        mac_service: false,
    };
    policy.validate()?;
    let program = fs::metadata(&policy.command[0])?;
    ensure!(
        program.is_file() && program.mode() & 0o111 != 0,
        "task executable must be an executable regular file"
    );
    let parent = destination.parent().context("task path has no parent")?;
    let directory = fs::symlink_metadata(parent)?;
    ensure!(
        directory.is_dir()
            && !directory.file_type().is_symlink()
            && directory.uid() == unsafe { libc::geteuid() }
            && directory.mode() & 0o077 == 0,
        "task directory must be private and owned by the broker"
    );
    #[cfg(target_os = "linux")]
    {
        crate::proxy_task::read_linux_upstream_ca(&policy.upstream_ca_der, source.service_mode)?;
        if source.service_mode {
            crate::service::validate_trusted_path(Path::new(&policy.command[0]), false)?;
            crate::service::validate_trusted_path(parent, true)?;
        }
    }
    #[cfg(target_os = "macos")]
    {
        if source.service_mode {
            ensure!(
                destination == Path::new(av_vmm::service::BROKER_POLICY),
                "task must use the installed policy path"
            );
            av_vmm::service::validate_broker_path(Path::new(&policy.command[0]), false)?;
            av_vmm::service::validate_broker_path(&policy.upstream_ca_der, false)?;
        }
        let ca = fs::symlink_metadata(&policy.upstream_ca_der)?;
        ensure!(
            ca.is_file() && !ca.file_type().is_symlink() && (1..=16 * 1024).contains(&ca.len()),
            "invalid upstream CA"
        );
    }
    let bytes = serde_json::to_vec_pretty(&policy)?;
    ensure!(bytes.len() <= 16 * 1024, "task policy is too large");
    // A crash or write failure leaves access revoked, never implicitly widened.
    if let Some((previous, _)) = &previous
        && let Some(version) = previous.connection_version
        && vault
            .connection_metadata(&previous.connection)?
            .is_some_and(|m| m.active && m.version == version)
    {
        vault.revoke_connection_grants(&previous.connection, version)?;
    }
    vault.revoke_connection_grants(&recipe.connection, recipe.connection_version)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(&destination)?;
    fs::File::open(parent)?.sync_all()?;
    show(source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn recipe_creation_rejects_stale_versions_and_invalid_limits() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("vault.db");
        let ca = directory.path().join("ca.der");
        fs::write(&ca, [1, 2, 3]).unwrap();
        let created = av_core::create_vault(&path, "synthetic passphrase").unwrap();
        created
            .vault
            .add_connection("test/cli", "api.example.test", "av-synthetic-task")
            .unwrap();
        let source = VaultSource {
            vault: path,
            proxy_policy: None,
            service_mode: false,
        };
        let mut recipe = TaskRecipe {
            connection: "test/cli".into(),
            connection_version: 1,
            host: "api.example.test".into(),
            command: vec![std::env::current_exe().unwrap().display().to_string()],
            max_connects: 2,
            max_requests: 3,
            max_runtime_seconds: 20,
            upstream_addr: "127.0.0.1:19443".parse().unwrap(),
            upstream_ca_der: ca,
        };
        let saved = save(&created.vault, &source, &None, &recipe).unwrap();
        let revision = Some(saved["revision"].as_str().unwrap().to_owned());
        assert!(save(&created.vault, &source, &None, &recipe).is_err());
        recipe.connection_version = 2;
        assert!(save(&created.vault, &source, &revision, &recipe).is_err());
        recipe.connection_version = 1;
        recipe.max_requests = 17;
        assert!(save(&created.vault, &source, &revision, &recipe).is_err());
        recipe.max_requests = 3;
        recipe.command.push("a\0b".into());
        assert!(save(&created.vault, &source, &revision, &recipe).is_err());
        assert_eq!(show(&source).unwrap()["revision"], saved["revision"]);
    }
}
