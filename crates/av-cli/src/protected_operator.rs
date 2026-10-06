//! Public, typed entry point for the installed broker's private operator channel.

use std::ffi::OsString;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::fs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::MetadataExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::Path;
use std::path::{Component, PathBuf};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use anyhow::bail;
use anyhow::{Context, Result, ensure};
use av_core::config::validate_connection_id;
use clap::Subcommand;

#[cfg(target_os = "linux")]
const OPERATOR: &str = "/usr/libexec/agents-vault/av-operator";
#[cfg(target_os = "linux")]
const OPERATOR_USER: &str = "av-broker";
#[cfg(target_os = "macos")]
const OPERATOR: &str = "/Library/PrivilegedHelperTools/AgentsVault.app/Contents/MacOS/av-operator";
#[cfg(target_os = "macos")]
const OPERATOR_USER: &str = "_avd";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const SUDO: &str = "/usr/bin/sudo";

#[derive(Subcommand)]
pub(super) enum ProtectedCommand {
    /// Initialize the installed service vault with a private root-owned recovery output.
    Setup {
        #[arg(long)]
        recovery_file: PathBuf,
    },
    /// Report the installed service state without disclosing credentials.
    Status,
    /// Unlock the installed service; the helper prompts for the passphrase privately.
    Unlock,
    /// Relock the service and invalidate active tasks and approvals.
    Lock,
    /// Show the immutable broker request before making a decision.
    Review { request_id: uuid::Uuid },
    /// Approve one frozen request through the private operator channel.
    Approve { request_id: uuid::Uuid },
    /// Deny one frozen request through the private operator channel.
    Deny { request_id: uuid::Uuid },
    /// Manage versioned connections in the installed service.
    Connect {
        #[command(subcommand)]
        command: ProtectedConnectionCommand,
    },
}

#[derive(Subcommand)]
pub(super) enum ProtectedConnectionCommand {
    /// Add a credential with an exact HTTPS host through the private helper.
    Add {
        id: String,
        #[arg(long)]
        host: String,
    },
    List,
    Show {
        id: String,
    },
    Replace {
        id: String,
        version: u64,
    },
    Disconnect {
        id: String,
        version: u64,
    },
    Revoke {
        id: String,
        version: u64,
    },
    /// Grant the installed proxy recipe for this exact connection version.
    Grant {
        id: String,
        version: u64,
    },
}

struct Invocation {
    init: bool,
    arguments: Vec<OsString>,
}

impl ProtectedCommand {
    fn invocation(self) -> Result<Invocation> {
        let mut args = Vec::new();
        let init = matches!(self, Self::Setup { .. });
        match self {
            Self::Setup { recovery_file } => {
                ensure!(
                    recovery_file.is_absolute()
                        && recovery_file.components().all(|part| {
                            !matches!(part, Component::CurDir | Component::ParentDir)
                        })
                        && !recovery_file
                            .as_os_str()
                            .as_encoded_bytes()
                            .split(|byte| *byte == b'/')
                            .any(|part| part == b"." || part == b".."),
                    "recovery output must be an absolute path without dot components"
                );
                args.extend(["init".into(), "--recovery-file".into()]);
                args.push(recovery_file.into_os_string());
            }
            Self::Status => args.push("status".into()),
            Self::Unlock => args.push("unlock".into()),
            Self::Lock => args.push("lock".into()),
            Self::Review { request_id } => {
                args.extend(["review".into(), request_id.to_string().into()]);
            }
            Self::Approve { request_id } => {
                args.extend(["approve".into(), request_id.to_string().into()]);
            }
            Self::Deny { request_id } => {
                args.extend(["deny".into(), request_id.to_string().into()]);
            }
            Self::Connect { command } => command.extend_arguments(&mut args)?,
        }
        Ok(Invocation {
            init,
            arguments: args,
        })
    }
}

impl ProtectedConnectionCommand {
    fn extend_arguments(self, args: &mut Vec<OsString>) -> Result<()> {
        match self {
            Self::Add { id, host } => {
                validate_connection_id(&id)?;
                validate_host(&host)?;
                args.extend(["connect-add".into(), id.into(), host.into()]);
            }
            Self::List => args.push("connect-list".into()),
            Self::Show { id } => {
                validate_connection_id(&id)?;
                args.extend(["connect-show".into(), id.into()]);
            }
            Self::Replace { id, version } => {
                add_versioned(args, "connect-replace", id, version)?;
            }
            Self::Disconnect { id, version } => {
                add_versioned(args, "connect-disconnect", id, version)?;
            }
            Self::Revoke { id, version } => {
                add_versioned(args, "connect-revoke", id, version)?;
            }
            Self::Grant { id, version } => {
                add_versioned(args, "connect-grant", id, version)?;
            }
        }
        Ok(())
    }
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
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            }),
        "invalid exact destination host"
    );
    Ok(())
}

fn add_versioned(args: &mut Vec<OsString>, action: &str, id: String, version: u64) -> Result<()> {
    validate_connection_id(&id)?;
    ensure!(version > 0, "connection version must be positive");
    args.extend([action.into(), id.into(), version.to_string().into()]);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn execute(command: ProtectedCommand) -> Result<u8> {
    // Every variable is checked before any privileged process is started.
    let invocation = command.invocation()?;
    validate_installed_binary(Path::new(SUDO))?;
    validate_installed_binary(Path::new(OPERATOR))?;

    let status = sudo_command(invocation)
        .status()
        .context("cannot launch installed operator helper")?;
    let cleanup = Command::new(SUDO)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg("-k")
        .status()
        .context("cannot invalidate operator privilege timestamp")?;
    ensure!(
        cleanup.success(),
        "cannot invalidate operator privilege timestamp"
    );
    Ok(status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .unwrap_or(1))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sudo_command(invocation: Invocation) -> Command {
    let mut child = Command::new(SUDO);
    child.env_clear().env("PATH", "/usr/bin:/bin").arg("-k");
    if !invocation.init {
        child.args(["-u", OPERATOR_USER]);
    }
    child.arg("--").arg(OPERATOR).args(invocation.arguments);
    child
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn execute(command: ProtectedCommand) -> Result<u8> {
    let invocation = command.invocation()?;
    let _ = (invocation.init, invocation.arguments);
    bail!("installed protected administration is unavailable on this platform")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn validate_installed_binary(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "installed operator dependency is unavailable: {}",
            path.display()
        )
    })?;
    ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o111 != 0,
        "installed operator dependency is untrusted: {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn arguments(args: &[&str]) -> Result<Vec<String>> {
        let cli = crate::Cli::try_parse_from(args)?;
        let crate::Commands::Protected { command } = cli.command else {
            panic!("expected protected command")
        };
        Ok(command
            .invocation()?
            .arguments
            .into_iter()
            .map(|part| part.into_string().unwrap())
            .collect())
    }

    #[test]
    fn helper_arguments_are_typed_and_provider_neutral() {
        assert_eq!(
            arguments(&["av", "protected", "status"]).unwrap(),
            ["status"]
        );
        assert_eq!(
            arguments(&[
                "av",
                "protected",
                "connect",
                "add",
                "service/work",
                "--host",
                "api.example.test"
            ])
            .unwrap(),
            ["connect-add", "service/work", "api.example.test"]
        );
        assert_eq!(
            arguments(&["av", "protected", "connect", "revoke", "service/work", "2"]).unwrap(),
            ["connect-revoke", "service/work", "2"]
        );
        assert_eq!(
            arguments(&["av", "protected", "connect", "grant", "service/work", "2"]).unwrap(),
            ["connect-grant", "service/work", "2"]
        );
        assert!(
            arguments(&[
                "av",
                "protected",
                "connect",
                "add",
                "bad/../id",
                "--host",
                "api.example.test"
            ])
            .is_err()
        );
        assert!(
            arguments(&[
                "av",
                "protected",
                "connect",
                "add",
                "service/work",
                "--host",
                "API.EXAMPLE.TEST"
            ])
            .is_err()
        );
        assert!(
            arguments(&["av", "protected", "connect", "replace", "service/work", "0"]).is_err()
        );
    }

    #[test]
    fn protected_request_decision_uses_only_a_uuid() {
        let id = "123e4567-e89b-12d3-a456-426614174000";
        for action in ["review", "approve", "deny"] {
            assert_eq!(
                arguments(&["av", "protected", action, id]).unwrap(),
                [action, id]
            );
            assert!(arguments(&["av", "protected", action, "invalid"]).is_err());
        }
    }
}
