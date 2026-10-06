//! Local connection management. The installed broker has a separate operator channel.
use super::*;
use av_core::ConnectionMetadata;

#[derive(Subcommand)]
pub enum ConnectCommand {
    /// Store a credential with an exact HTTPS host. New connections deny release.
    Add {
        id: String,
        #[arg(long, required = true)]
        host: String,
    },
    /// Print connection metadata without credentials.
    List,
    /// Print metadata and release policy without credentials.
    Show { id: String },
    /// Replace or reconnect a credential and invalidate its grants.
    Replace {
        id: String,
        #[arg(long)]
        if_version: u64,
    },
    /// Remove the local credential and grants.
    Disconnect {
        id: String,
        #[arg(long)]
        if_version: u64,
    },
    /// Revoke release grants for the observed version.
    Revoke {
        id: String,
        #[arg(long)]
        if_version: u64,
    },
}

pub fn manage(command: ConnectCommand, vault_path: &Path) -> Result<u8> {
    let vault = unlock(vault_path)?;
    match command {
        ConnectCommand::Add { id, host } => {
            let credential = Zeroizing::new(rpassword::prompt_password("Connection credential: ")?);
            print_metadata(&vault.add_connection(&id, &host, &credential)?)?;
        }
        ConnectCommand::List => {
            println!(
                "{}",
                serde_json::to_string_pretty(&vault.list_connections()?)?
            );
        }
        ConnectCommand::Show { id } => {
            let metadata = metadata(&vault, &id)?;
            let policy = if metadata.active {
                Some(vault.connection_policy(&id, metadata.version)?)
            } else {
                None
            };
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"connection": metadata, "release_policy": policy})
                )?
            );
        }
        ConnectCommand::Replace { id, if_version } => {
            ensure!(
                metadata(&vault, &id)?.version == if_version,
                "connection version changed; review and retry"
            );
            let credential =
                Zeroizing::new(rpassword::prompt_password("Replacement credential: ")?);
            print_metadata(&vault.replace_connection(&id, if_version, &credential)?)?;
        }
        ConnectCommand::Disconnect { id, if_version } => {
            print_metadata(&vault.disconnect_connection(&id, if_version)?)?;
            println!(
                "Local credential and grants removed. Revoke the credential at its provider separately."
            );
        }
        ConnectCommand::Revoke { id, if_version } => {
            vault.revoke_connection_grants(&id, if_version)?;
            println!("Connection grants revoked for {id} version {if_version}");
        }
    }
    Ok(0)
}

fn print_metadata(metadata: &ConnectionMetadata) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(metadata)?);
    Ok(())
}

fn metadata(vault: &Vault, id: &str) -> Result<ConnectionMetadata> {
    vault
        .connection_metadata(id)?
        .context("connection does not exist")
}
