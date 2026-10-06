//! Private administration of a locked, installed service vault.
//!
//! Callers must hold the session's exclusive gate while opening the vault and
//! applying an operation. Agent and client endpoints cannot access these operations.

#[cfg(not(target_os = "macos"))]
use anyhow::bail;
use anyhow::{Context, Result, ensure};
use av_core::{ApprovalRequirement, SecretAccessRequest, SecretGrant, SecretPolicy, Vault};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

use crate::{ProxyPolicy, session::VaultSource};

pub mod bootstrap;

pub const MAX_SECRET_BYTES: usize = 4096;

#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagementOperation {
    Add {
        name: String,
        value: String,
    },
    Rotate {
        name: String,
        value: String,
    },
    Grant {
        name: String,
        #[serde(default)]
        preapprove: bool,
    },
    Revoke {
        name: String,
    },
    Policy {
        name: String,
    },
    ConnectAdd {
        id: String,
        host: String,
        value: String,
    },
    ConnectList,
    ConnectShow {
        id: String,
    },
    ConnectReplace {
        id: String,
        expected_version: u64,
        value: String,
    },
    ConnectDisconnect {
        id: String,
        expected_version: u64,
    },
    ConnectRevoke {
        id: String,
        expected_version: u64,
    },
    ConnectGrant {
        id: String,
        expected_version: u64,
    },
}

impl Drop for ManagementOperation {
    fn drop(&mut self) {
        match self {
            Self::Add { value, .. }
            | Self::Rotate { value, .. }
            | Self::ConnectAdd { value, .. }
            | Self::ConnectReplace { value, .. } => value.zeroize(),
            _ => (),
        }
    }
}

pub fn installed_runtime() -> PathBuf {
    #[cfg(target_os = "macos")]
    return PathBuf::from(av_vmm::service::BROKER_RUNTIME);
    #[cfg(not(target_os = "macos"))]
    PathBuf::from("/run/agents-vault")
}

/// Administrative commands run as the non-login broker, never root or the agent.
pub fn validate_operator_identity() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        av_vmm::service::validate_broker_identity()?;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        ensure!(
            uid != 0 && unsafe { libc::getuid() } == uid && unsafe { libc::getgid() } == gid,
            "administration requires the non-login av-broker identity"
        );
        let passwd = fs::read_to_string("/etc/passwd")?;
        ensure!(
            passwd.lines().any(|line| {
                let fields: Vec<_> = line.split(':').collect();
                fields.len() == 7
                    && fields[0] == "av-broker"
                    && fields[2].parse::<u32>().ok() == Some(uid)
                    && fields[3].parse::<u32>().ok() == Some(gid)
                    && matches!(
                        fields[6],
                        "/usr/sbin/nologin" | "/sbin/nologin" | "/bin/false"
                    )
            }),
            "administration requires the non-login av-broker identity"
        );
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    bail!("installed service administration is unavailable on this platform")
}

/// Resolve authority from installed configuration, rather than client input or
/// a caller's environment. Source validation occurs again under the session gate.
pub(crate) fn validate_source(source: &VaultSource) -> Result<()> {
    ensure!(
        source.service_mode,
        "management requires an installed service vault"
    );
    validate_operator_identity()?;
    source.validate()?;
    #[cfg(target_os = "linux")]
    {
        let configuration = read_root_configuration(Path::new("/etc/agents-vault/service.env"))?;
        let (vault, proxy_policy) = parse_service_paths(&configuration)?;
        ensure!(
            source.vault == vault && source.proxy_policy == proxy_policy,
            "running vault configuration differs from /etc/agents-vault/service.env; restart the service"
        );
    }
    validate_vault_files(&source.vault)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_root_configuration(path: &Path) -> Result<String> {
    for (index, ancestor) in path.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(ancestor)?;
        ensure!(
            !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0,
            "service configuration and ancestors must be root-owned and not writable by other identities"
        );
        if index == 0 {
            ensure!(
                metadata.is_file() && metadata.nlink() == 1 && metadata.len() <= 16 * 1024,
                "service configuration must be a bounded regular file with one link"
            );
        }
    }
    let mut content = String::new();
    fs::File::open(path)?
        .take(16 * 1024 + 1)
        .read_to_string(&mut content)?;
    ensure!(
        content.len() <= 16 * 1024,
        "service configuration is too large"
    );
    Ok(content)
}

#[cfg(target_os = "linux")]
fn parse_service_paths(content: &str) -> Result<(PathBuf, Option<PathBuf>)> {
    let mut vault = None;
    let mut policy = None;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        let Some((key, raw)) = line.split_once('=') else {
            bail!("invalid service configuration assignment");
        };
        let target = match key.trim() {
            "AVD_VAULT_PATH" => &mut vault,
            "AVD_PROXY_POLICY_PATH" => &mut policy,
            _ => continue,
        };
        ensure!(target.is_none(), "duplicate service path assignment");
        let raw = raw.trim();
        let path = if let Some(quoted) = raw.strip_prefix('"') {
            quoted
                .strip_suffix('"')
                .context("invalid quoted service path")?
        } else if let Some(quoted) = raw.strip_prefix('\'') {
            quoted
                .strip_suffix('\'')
                .context("invalid quoted service path")?
        } else {
            raw
        };
        ensure!(
            path.starts_with('/')
                && !path
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '\\' | '\'' | '"')),
            "service paths must be simple absolute paths without escapes"
        );
        ensure!(
            !Path::new(path)
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir)),
            "service paths cannot contain parent traversal"
        );
        *target = Some(PathBuf::from(path));
    }
    Ok((
        vault.context("configure AVD_VAULT_PATH in /etc/agents-vault/service.env")?,
        policy,
    ))
}

fn validate_private_vault_file(path: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    av_vmm::service::validate_broker_path(path, true)?;
    #[cfg(not(target_os = "macos"))]
    crate::service::validate_trusted_path(path, true)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1 && metadata.uid() == unsafe { libc::geteuid() },
        "vault components must be private regular files owned by the broker with one link"
    );
    Ok(())
}

fn validate_vault_files(path: &Path) -> Result<()> {
    let directory = path.parent().context("vault requires a parent directory")?;
    let metadata = fs::symlink_metadata(directory)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "vault directory must be private and owned by the broker"
    );
    validate_private_vault_file(path)?;
    let envelope = path.with_extension("keys.json");
    validate_private_vault_file(&envelope)?;
    validate_private_vault_file(&path.with_extension("access.lock"))?;
    let mut bytes = Vec::new();
    fs::File::open(&envelope)?
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16 * 1024, "vault envelope is too large");
    let envelope: Value = serde_json::from_slice(&bytes)?;
    let database = match envelope.get("database_file").and_then(Value::as_str) {
        None => path.to_path_buf(),
        Some(name) => {
            let id = name
                .strip_prefix("av-generation-")
                .and_then(|v| v.strip_suffix(".db"))
                .context("invalid vault generation")?;
            ensure!(
                id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid vault generation"
            );
            directory.join(name)
        }
    };
    validate_private_vault_file(&database)?;
    for suffix in ["-journal", "-wal", "-shm"] {
        let sibling = PathBuf::from(format!("{}{suffix}", database.display()));
        match fs::symlink_metadata(&sibling) {
            Ok(_) => validate_private_vault_file(&sibling)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// The broker and grant writer derive the same platform-specific snapshot.
pub(crate) fn proxy_access_request(
    policy: &ProxyPolicy,
    path: &Path,
    source: &[u8],
    _trusted_ca: bool,
) -> Result<SecretAccessRequest> {
    #[cfg(target_os = "macos")]
    return if policy.host_client {
        macos_host_proxy_access_request(policy, path, source)
    } else {
        macos_proxy_access_request(policy, path, source).map(|(request, _)| request)
    };
    #[cfg(not(target_os = "macos"))]
    {
        ensure!(
            !policy.mac_service && policy.mac_vmm.is_none() && policy.mac_guest_bundle.is_none(),
            "macOS guest grants must be issued by the installed macOS service"
        );
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, source);
            bail!("protected proxy grants currently support only Linux installed executables");
        }
        #[cfg(target_os = "linux")]
        {
            let mut request = SecretAccessRequest::for_command(
                &policy.command,
                path,
                source,
                None,
                av_core::DeliveryMode::ProtectedProxy,
                Some(&policy.host),
            )?;
            request.working_directory = "/".into();
            bind_linux_upstream_ca(&mut request, policy, _trusted_ca)?;
            request.validate()?;
            Ok(request)
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_host_proxy_access_request(
    policy: &ProxyPolicy,
    path: &Path,
    source: &[u8],
) -> Result<SecretAccessRequest> {
    use av_core::DeliveryMode;
    use av_vmm::service;
    use sha2::{Digest, Sha256};

    policy.validate()?;
    ensure!(policy.host_client, "policy does not select a host client");
    service::validate_broker_identity()?;
    ensure!(
        path == Path::new(service::BROKER_POLICY),
        "macOS host proxy policy must use the installed path"
    );
    service::validate_broker_path(path, true)?;
    service::validate_broker_path(Path::new(&policy.command[0]), false)?;
    service::validate_broker_path(&policy.upstream_ca_der, false)?;
    ensure!(
        source.len() <= 16 * 1024 && fs::read(path)? == source,
        "host proxy policy changed while deriving the grant"
    );
    let ca = fs::read(&policy.upstream_ca_der)?;
    ensure!(
        !ca.is_empty() && ca.len() <= 16 * 1024,
        "invalid upstream CA size"
    );
    let mut request = SecretAccessRequest::for_command(
        &policy.command,
        path,
        source,
        None,
        DeliveryMode::ProtectedProxy,
        Some(&policy.host),
    )?;
    request.working_directory = "/".into();
    request.upstream_ca_sha256 = Some(hex::encode(Sha256::digest(ca)));
    request.validate()?;
    Ok(request)
}

#[cfg(target_os = "linux")]
fn bind_linux_upstream_ca(
    request: &mut SecretAccessRequest,
    policy: &ProxyPolicy,
    trusted_ca: bool,
) -> Result<()> {
    use sha2::{Digest, Sha256};

    let ca = crate::proxy_task::read_linux_upstream_ca(&policy.upstream_ca_der, trusted_ca)?;
    request.upstream_ca_sha256 = Some(hex::encode(Sha256::digest(ca)));
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_proxy_access_request(
    policy: &ProxyPolicy,
    path: &Path,
    source: &[u8],
) -> Result<(SecretAccessRequest, av_vmm::service::ServiceIdentity)> {
    let (identity, installed) = macos_verified_service_identity(policy, path, source)?;
    let request = SecretAccessRequest::for_macos_service(
        &policy.command,
        path,
        source,
        &policy.host,
        identity,
    )?;
    Ok((request, installed))
}

#[cfg(target_os = "macos")]
fn macos_verified_service_identity(
    policy: &ProxyPolicy,
    path: &Path,
    source: &[u8],
) -> Result<(
    av_core::policy::MacOsServiceIdentity,
    av_vmm::service::ServiceIdentity,
)> {
    use av_core::policy::MacOsServiceIdentity;
    use av_vmm::service;
    use sha2::{Digest, Sha256};
    ensure!(
        policy.mac_service && policy.mac_vmm.is_none() && policy.mac_guest_bundle.is_none(),
        "protected macOS grants require the installed service, not development paths"
    );
    policy.validate()?;
    service::validate_broker_identity()?;
    ensure!(
        path == Path::new(service::BROKER_POLICY),
        "macOS grant policy must use the installed path"
    );
    service::validate_broker_path(path, true)?;
    ensure!(
        source.len() <= 16 * 1024 && fs::read(path)? == source,
        "proxy policy changed while deriving the grant"
    );
    service::validate_broker_path(&policy.upstream_ca_der, false)?;
    let metadata = fs::symlink_metadata(&policy.upstream_ca_der)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 16 * 1024,
        "invalid synthetic upstream CA file"
    );
    let mut ca = Vec::new();
    fs::File::open(&policy.upstream_ca_der)?
        .take(16 * 1024 + 1)
        .read_to_end(&mut ca)?;
    ensure!(
        !ca.is_empty() && ca.len() <= 16 * 1024,
        "invalid synthetic upstream CA size"
    );
    let installed = service::installed_identity()?;
    let identity = MacOsServiceIdentity {
        format: installed.format,
        team_identifier: installed.team_identifier.clone(),
        broker_cdhash: installed.broker_cdhash.clone(),
        supervisor_cdhash: installed.supervisor_cdhash.clone(),
        runner_cdhash: installed.runner_cdhash.clone(),
        service_policy_sha256: installed.service_policy_sha256.clone(),
        guest_manifest_sha256: installed.guest_manifest_sha256.clone(),
        kernel_sha256: installed.kernel_sha256.clone(),
        initramfs_sha256: installed.initramfs_sha256.clone(),
        fixture_sha256: installed.fixture_sha256.clone(),
        upstream_ca_sha256: format!("{:x}", Sha256::digest(ca)),
    };
    Ok((identity, installed))
}

pub(crate) fn execute(
    vault: &Vault,
    source: &VaultSource,
    operation: &ManagementOperation,
) -> Result<Value> {
    match operation {
        ManagementOperation::Add { name, value } => {
            validate_secret(value)?;
            vault.add(name, value)?;
            Ok(json!({"action": "add", "name": name, "grants": 0, "locked": true}))
        }
        ManagementOperation::Rotate { name, value } => {
            validate_secret(value)?;
            vault.rotate(name, value)?;
            Ok(json!({"action": "rotate", "name": name, "policy_retained": true, "locked": true}))
        }
        ManagementOperation::Grant { name, preapprove } => {
            ensure!(vault.exists(name)?, "secret does not exist");
            let path = source
                .proxy_policy
                .as_ref()
                .context("service has no installed proxy policy")?;
            let bytes = fs::read(path)?;
            ensure!(bytes.len() <= 16 * 1024, "proxy policy is too large");
            let proxy: ProxyPolicy = serde_json::from_slice(&bytes)?;
            proxy.validate()?;
            ensure!(
                proxy.connection_version.is_none() && proxy.secret_name == *name,
                "secret does not match the installed proxy policy"
            );
            let request = proxy_access_request(&proxy, path, &bytes, source.service_mode)?;
            let mut policy = vault.policy(name)?;
            policy.grants.retain(|grant| grant.request != request);
            policy.grants.push(SecretGrant {
                request,
                approval: if *preapprove {
                    ApprovalRequirement::Preapproved
                } else {
                    ApprovalRequirement::EveryRun
                },
            });
            let reply = json!({"action": "grant", "name": name, "policy": policy, "locked": true});
            ensure!(
                serde_json::to_vec(&reply)?.len() <= 60 * 1024,
                "policy exceeds administration output limit; revoke obsolete grants first"
            );
            vault.set_policy(name, &policy)?;
            Ok(reply)
        }
        ManagementOperation::Revoke { name } => {
            vault.set_policy(name, &SecretPolicy::default())?;
            Ok(json!({"action": "revoke", "name": name, "grants": 0, "locked": true}))
        }
        ManagementOperation::Policy { name } => {
            ensure!(vault.exists(name)?, "secret does not exist");
            let reply = json!({"name": name, "policy": vault.policy(name)?, "locked": true});
            ensure!(
                serde_json::to_vec(&reply)?.len() <= 60 * 1024,
                "policy exceeds administration output limit"
            );
            Ok(reply)
        }
        ManagementOperation::ConnectAdd { id, host, value } => {
            validate_secret(value)?;
            let metadata = vault.add_connection(id, host, value)?;
            Ok(
                json!({"action": "connect_add", "connection": metadata, "grants": 0, "locked": true}),
            )
        }
        ManagementOperation::ConnectList => {
            let reply = json!({"connections": vault.list_connections()?, "locked": true});
            bounded_admin_reply(reply)
        }
        ManagementOperation::ConnectShow { id } => {
            let metadata = vault
                .connection_metadata(id)?
                .context("connection does not exist")?;
            let policy = if metadata.active {
                Some(vault.connection_policy(id, metadata.version)?)
            } else {
                None
            };
            bounded_admin_reply(json!({
                "connection": metadata, "policy": policy, "locked": true
            }))
        }
        ManagementOperation::ConnectReplace {
            id,
            expected_version,
            value,
        } => {
            let metadata = vault.replace_connection(id, *expected_version, value)?;
            Ok(
                json!({"action": "connect_replace", "connection": metadata, "grants": 0, "locked": true}),
            )
        }
        ManagementOperation::ConnectDisconnect {
            id,
            expected_version,
        } => {
            let metadata = vault.disconnect_connection(id, *expected_version)?;
            Ok(
                json!({"action": "connect_disconnect", "connection": metadata, "grants": 0, "locked": true}),
            )
        }
        ManagementOperation::ConnectRevoke {
            id,
            expected_version,
        } => {
            vault.revoke_connection_grants(id, *expected_version)?;
            Ok(
                json!({"action": "connect_revoke", "id": id, "version": expected_version, "grants": 0, "locked": true}),
            )
        }
        ManagementOperation::ConnectGrant {
            id,
            expected_version,
        } => {
            let path = source
                .proxy_policy
                .as_ref()
                .context("service has no installed proxy policy")?;
            let bytes = fs::read(path)?;
            ensure!(bytes.len() <= 16 * 1024, "proxy policy is too large");
            let proxy: ProxyPolicy = serde_json::from_slice(&bytes)?;
            proxy.validate()?;
            let metadata = vault
                .connection_metadata(id)?
                .context("connection does not exist")?;
            ensure!(
                metadata.active
                    && metadata.version == *expected_version
                    && proxy.connection == *id
                    && proxy.connection_version == Some(*expected_version)
                    && proxy.host == metadata.host,
                "connection version or host differs from installed proxy policy"
            );
            let request = proxy_access_request(&proxy, path, &bytes, source.service_mode)?;
            let policy = SecretPolicy {
                grants: vec![SecretGrant {
                    request,
                    approval: ApprovalRequirement::EveryRun,
                }],
            };
            let reply = bounded_admin_reply(json!({
                "action": "connect_grant", "id": id, "version": expected_version,
                "policy": policy, "locked": true
            }))?;
            vault.set_connection_policy(id, *expected_version, &policy)?;
            Ok(reply)
        }
    }
}

fn bounded_admin_reply(reply: Value) -> Result<Value> {
    ensure!(
        serde_json::to_vec(&reply)?.len() <= 60 * 1024,
        "connection administration output exceeds the limit"
    );
    Ok(reply)
}

fn validate_secret(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= MAX_SECRET_BYTES && !value.contains('\0'),
        "secret must contain 1 to 4096 bytes without NUL"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_connection_management_hides_credentials_and_checks_versions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.db");
        let created = av_core::create_vault(&path, "synthetic passphrase").unwrap();
        let source = VaultSource {
            vault: path,
            proxy_policy: None,
            service_mode: false,
        };
        let first = "private credential one";
        let second = "private credential two";
        let added = execute(
            &created.vault,
            &source,
            &ManagementOperation::ConnectAdd {
                id: "service/work".into(),
                host: "api.example.test".into(),
                value: first.into(),
            },
        )
        .unwrap();
        assert_eq!(added["connection"]["host"], "api.example.test");
        assert!(!added.to_string().contains(first));
        let shown = execute(
            &created.vault,
            &source,
            &ManagementOperation::ConnectShow {
                id: "service/work".into(),
            },
        )
        .unwrap();
        assert_eq!(shown["connection"]["version"], 1);
        assert!(!shown.to_string().contains(first));
        assert!(
            execute(
                &created.vault,
                &source,
                &ManagementOperation::ConnectReplace {
                    id: "service/work".into(),
                    expected_version: 2,
                    value: second.into(),
                },
            )
            .is_err()
        );
        let replaced = execute(
            &created.vault,
            &source,
            &ManagementOperation::ConnectReplace {
                id: "service/work".into(),
                expected_version: 1,
                value: second.into(),
            },
        )
        .unwrap();
        assert_eq!(replaced["connection"]["version"], 2);
        assert!(!replaced.to_string().contains(second));
        execute(
            &created.vault,
            &source,
            &ManagementOperation::ConnectRevoke {
                id: "service/work".into(),
                expected_version: 2,
            },
        )
        .unwrap();
        let disconnected = execute(
            &created.vault,
            &source,
            &ManagementOperation::ConnectDisconnect {
                id: "service/work".into(),
                expected_version: 2,
            },
        )
        .unwrap();
        assert_eq!(disconnected["connection"]["version"], 3);
        assert_eq!(disconnected["connection"]["active"], false);
        assert!(!disconnected.to_string().contains(second));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn connection_grant_requires_installed_recipe_host_and_version() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let vault_path = directory.path().join("vault.db");
        let created = av_core::create_vault(&vault_path, "synthetic passphrase").unwrap();
        created
            .vault
            .add_connection("service/work", "api.example.test", "av-synthetic-token")
            .unwrap();
        let ca_path = directory.path().join("ca.der");
        fs::write(&ca_path, b"synthetic-ca").unwrap();
        let policy_path = directory.path().join("policy.json");
        let policy = json!({
            "connection": "service/work", "connection_version": 1,
            "host": "api.example.test", "command": ["/bin/true"],
            "upstream_addr": "127.0.0.1:9", "upstream_ca_der": ca_path,
            "max_connects": 1, "max_requests": 1, "max_runtime_seconds": 10,
            "host_client": true
        });
        fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
        fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600)).unwrap();
        let source = VaultSource {
            vault: vault_path,
            proxy_policy: Some(policy_path.clone()),
            service_mode: false,
        };
        let grant = |version| ManagementOperation::ConnectGrant {
            id: "service/work".into(),
            expected_version: version,
        };
        assert!(execute(&created.vault, &source, &grant(2)).is_err());
        let result = execute(&created.vault, &source, &grant(1)).unwrap();
        assert_eq!(result["version"], 1);
        assert!(!result.to_string().contains("av-synthetic-token"));
        assert_eq!(
            created
                .vault
                .connection_policy("service/work", 1)
                .unwrap()
                .grants
                .len(),
            1
        );
        let mut changed = policy;
        changed["host"] = json!("other.example.test");
        fs::write(&policy_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(execute(&created.vault, &source, &grant(1)).is_err());
        created
            .vault
            .replace_connection("service/work", 1, "av-synthetic-new")
            .unwrap();
        assert!(execute(&created.vault, &source, &grant(1)).is_err());
        assert!(
            created
                .vault
                .connection_policy("service/work", 2)
                .unwrap()
                .grants
                .is_empty()
        );
    }
}
