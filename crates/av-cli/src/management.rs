use super::{Config, Path, Result, SecretCommand, SecretRef, Vault, fs, unlock, write_new_private};
use anyhow::{Context, bail, ensure};
use av_core::{ApprovalRequirement, DeliveryMode, SecretAccessRequest, SecretGrant};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum CliDelivery {
    Direct,
    ProxyPreview,
    ProtectedProxy,
}

impl From<CliDelivery> for DeliveryMode {
    fn from(mode: CliDelivery) -> Self {
        match mode {
            CliDelivery::Direct => Self::Direct,
            CliDelivery::ProxyPreview => Self::ProxyPreview,
            CliDelivery::ProtectedProxy => Self::ProtectedProxy,
        }
    }
}

fn storage_key(config_path: &Path, name: &str) -> Result<String> {
    let config = Config::load(config_path)?;
    Ok(SecretRef::parse(
        &format!("secret://{}/{name}", config.project.id),
        &config.project.id,
    )?
    .storage_key())
}

pub fn secret_command(command: SecretCommand, config_path: &Path, vault_path: &Path) -> Result<u8> {
    match command {
        SecretCommand::Rotate { name } => {
            let key = storage_key(config_path, &name)?;
            let vault = unlock(vault_path)?;
            ensure!(vault.exists(&key)?, "secret does not exist; use add first");
            let value = Zeroizing::new(rpassword::prompt_password("Replacement secret value: ")?);
            vault.rotate(&key, &value)?;
            println!("Rotated {key}; existing release policy retained");
        }
        SecretCommand::Grant {
            name,
            env,
            mode,
            host,
            preapprove,
            command,
        } => {
            let source = fs::read(config_path).context("cannot read project configuration")?;
            let config = Config::parse(std::str::from_utf8(&source)?)?;
            let key = SecretRef::parse(
                &format!("secret://{}/{name}", config.project.id),
                &config.project.id,
            )?
            .storage_key();
            ensure!(
                super::referenced_secrets(&config, env.as_deref())?.contains(&key),
                "selected project configuration does not reference this secret"
            );
            let delivery: DeliveryMode = mode.into();
            let request = SecretAccessRequest::for_command(
                &command,
                config_path,
                &source,
                env.as_deref(),
                delivery,
                host.as_deref(),
            )?;
            if matches!(delivery, DeliveryMode::Direct | DeliveryMode::ProxyPreview) {
                // Reject unsupported executable formats before persisting a grant.
                let _execution = super::VerifiedExecution::prepare(request.clone())?;
            }
            if delivery == DeliveryMode::Direct {
                eprintln!("{}", super::DIRECT_CODE_SCOPE);
            }
            let vault = unlock(vault_path)?;
            let mut policy = vault.policy(&key)?;
            policy.grants.retain(|grant| grant.request != request);
            policy.grants.push(SecretGrant {
                request,
                approval: if preapprove {
                    ApprovalRequirement::Preapproved
                } else {
                    ApprovalRequirement::EveryRun
                },
            });
            vault.set_policy(&key, &policy)?;
            println!(
                "Granted {key} for this executable, arguments, configuration, directory, mode, and host"
            );
            println!(
                "Approval: {}",
                if preapprove {
                    "preapproved"
                } else {
                    "required for every run"
                }
            );
        }
        SecretCommand::Policy { name } => {
            let key = storage_key(config_path, &name)?;
            let vault = unlock(vault_path)?;
            ensure!(vault.exists(&key)?, "secret does not exist");
            println!("{}", serde_json::to_string_pretty(&vault.policy(&key)?)?);
        }
        SecretCommand::Revoke { name } => {
            let key = storage_key(config_path, &name)?;
            let vault = unlock(vault_path)?;
            vault.set_policy(&key, &Default::default())?;
            println!("Revoked every release grant for {key}");
        }
        SecretCommand::Backup { output } => {
            let passphrase = Zeroizing::new(rpassword::prompt_password("Vault passphrase: ")?);
            av_core::backup_vault(vault_path, &passphrase, &output)?;
            println!("Encrypted backup created at {}", output.display());
        }
        SecretCommand::Restore { backup } => {
            let passphrase =
                Zeroizing::new(rpassword::prompt_password("Backup vault passphrase: ")?);
            av_core::restore_vault(&backup, vault_path, &passphrase)?;
            println!("Restored encrypted vault to {}", vault_path.display());
        }
        SecretCommand::RotateKey { new_recovery_file } => {
            ensure!(
                !new_recovery_file.exists(),
                "new recovery file already exists"
            );
            let passphrase =
                Zeroizing::new(rpassword::prompt_password("Current vault passphrase: ")?);
            let new_passphrase = Zeroizing::new(super::prompt_new_passphrase()?);
            av_core::rotate_vault_key(
                vault_path,
                &passphrase,
                &new_passphrase,
                &new_recovery_file,
            )?;
            println!(
                "Vault data key, passphrase, and recovery key rotated. Old backups retain their original keys. Move the new recovery file offline."
            );
        }
        _ => bail!("unsupported management command"),
    }
    Ok(0)
}

pub fn authorize_run(
    vault: &Vault,
    names: &[String],
    request: &SecretAccessRequest,
) -> Result<bool> {
    let mut approval_required = false;
    for name in names {
        approval_required |= vault.authorization(name, request).with_context(|| {
            format!("release denied for {name}; use av secret grant from the operator terminal")
        })? == ApprovalRequirement::EveryRun;
    }
    if approval_required {
        approve_run(names, request)?;
    }
    Ok(approval_required)
}

pub fn approve_run(names: &[String], request: &SecretAccessRequest) -> Result<()> {
    eprintln!(
        "Secret release requires approval for {names:?} to {} {:?} in {:?} mode",
        request.executable, request.arguments, request.delivery
    );
    let answer = Zeroizing::new(rpassword::prompt_password(
        "Type approve to authorize this run: ",
    )?);
    ensure!(
        answer.as_str() == "approve",
        "secret release was not approved"
    );
    Ok(())
}

pub fn import_env(
    file: &Path,
    project: &str,
    public: &[String],
    config_path: &Path,
    vault_path: &Path,
) -> Result<u8> {
    ensure!(
        !config_path.exists(),
        "project configuration already exists; import requires a new config path"
    );
    ensure!(
        fs::metadata(file)?.len() <= 1024 * 1024,
        ".env file exceeds the 1 MiB import limit"
    );
    let source = Zeroizing::new(fs::read_to_string(file).context("cannot read .env file")?);
    let values = av_core::dotenv::parse(&source)?;
    let public_names = public.iter().cloned().collect::<BTreeSet<_>>();
    ensure!(
        public_names.len() == public.len(),
        "duplicate --public name"
    );
    for name in &public_names {
        ensure!(
            values.contains_key(name),
            "--public names an unknown .env variable: {name}"
        );
    }
    let config_source = av_core::dotenv::reference_config_with_public(
        project,
        values
            .keys()
            .filter(|name| !public_names.contains(*name))
            .cloned(),
        values
            .iter()
            .filter(|(name, _)| public_names.contains(*name))
            .map(|(name, value)| (name.clone(), value.to_string())),
    )?;
    let entries = values
        .into_iter()
        .filter(|(name, _)| !public_names.contains(name))
        .map(|(name, value)| (format!("{project}/{name}"), value))
        .collect::<Vec<_>>();
    let vault = (!entries.is_empty())
        .then(|| unlock(vault_path))
        .transpose()?;
    write_new_private(config_path, config_source.as_bytes())?;
    if let Some(vault) = vault
        && let Err(error) = vault.import(&entries)
    {
        let _ = fs::remove_file(config_path);
        return Err(error);
    }
    println!(
        "Imported {} secrets and {} public values; created {}. Secrets have no release grants.",
        entries.len(),
        public_names.len(),
        config_path.display()
    );
    println!(
        "The source .env still contains plaintext values; remove it from agent-accessible paths after checking the import."
    );
    Ok(0)
}

pub fn placeholders(config_path: &Path, environment: Option<&str>, output: &Path) -> Result<u8> {
    let config = Config::load(config_path)?;
    let mut template = String::from("# Generated by av. Secret values are placeholders.\n");
    for (name, declaration) in config.selected(environment)? {
        let value = if let Some(reference) = &declaration.connection {
            format!("<AV_CONNECTION:{}@{}>", reference.id, reference.version)
        } else if let Some(reference) = &declaration.secret {
            format!(
                "<AV_SECRET:{}>",
                SecretRef::parse(reference, &config.project.id)?.storage_key()
            )
        } else if let Some(value) = &declaration.value {
            value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string())
        } else {
            "<AV_REQUIRED>".to_owned()
        };
        template.push_str(&format!("{name}={}\n", serde_json::to_string(&value)?));
    }
    write_new_private(output, template.as_bytes())?;
    println!("Wrote secret placeholders to {}", output.display());
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONNECTION_CONFIG: &str = "schema = 2\n[project]\nid = 'demo'\n[values.APP_ENV]\ntype = 'string'\nvalue = 'development'\n[values.SERVICE_TOKEN]\ntype = 'string'\nconnection = { id = 'service/work', version = 1 }\ndelivery = 'proxy'\nrequired = true\n[environments.prod.values.SERVICE_TOKEN]\ntype = 'string'\nconnection = { id = 'service/work', version = 2 }\ndelivery = 'proxy'\nrequired = true\n";

    #[test]
    fn connection_placeholders_select_version_without_a_vault() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("av.toml");
        let output = directory.path().join(".env.example");
        fs::write(&config, CONNECTION_CONFIG).unwrap();
        assert_eq!(placeholders(&config, Some("prod"), &output).unwrap(), 0);
        let template = fs::read_to_string(&output).unwrap();
        assert!(template.contains("SERVICE_TOKEN=\"<AV_CONNECTION:service/work@2>\""));
        assert!(template.contains("APP_ENV=\"development\""));
        assert!(!template.contains("<AV_REQUIRED>"));
        assert!(placeholders(&config, Some("prod"), &output).is_err());
    }

    #[test]
    fn check_accepts_connection_declarations_without_unlocking_a_vault() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("av.toml");
        let vault = directory.path().join("missing-vault.db");
        fs::write(&config, CONNECTION_CONFIG).unwrap();
        assert_eq!(
            crate::execute(crate::Cli {
                config: Some(config),
                vault: Some(vault.clone()),
                command: crate::Commands::Check {
                    env: Some("prod".into()),
                },
            })
            .unwrap(),
            0
        );
        assert!(!vault.exists());
    }
}
