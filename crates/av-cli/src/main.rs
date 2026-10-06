use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail, ensure};
use av_core::config::ValueType;
use av_core::{Config, SecretRef, Vault, check, create_vault, recover_vault, resolve};
use av_core::{DeliveryMode, SecretAccessRequest};
use av_proxy::{CredentialInjection, ProxyConfig, ProxyServer, TaskGrant};
#[cfg(unix)]
use avd::{
    Operation,
    ipc::{self, AgentRequest, Reply},
};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
#[cfg(unix)]
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::process::Command as AsyncCommand;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

mod connections;
mod management;
mod protected_operator;
#[cfg(unix)]
mod proxy_settings;

#[derive(Parser)]
#[command(
    name = "av",
    version,
    about = "Local-first project configuration and credentials"
)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[arg(long, global = true)]
    vault: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the local direct-mode vault. Protected installation is separate.
    Setup {
        #[arg(long, required = true)]
        direct: bool,
        #[arg(long)]
        recovery_file: PathBuf,
    },
    /// Report local vault initialization without unlocking or checking a broker.
    Status,
    /// Verify the local vault passphrase for this process; no unlock is cached.
    Unlock {
        #[arg(long, required = true)]
        direct: bool,
    },
    /// Manage local versioned connections.
    Connect {
        #[command(subcommand)]
        command: connections::ConnectCommand,
    },
    /// Administer the installed protected service through the privileged operator helper.
    Protected {
        #[command(subcommand)]
        command: protected_operator::ProtectedCommand,
    },
    Init {
        #[arg(long)]
        project: String,
    },
    Check {
        #[arg(long)]
        env: Option<String>,
    },
    /// Import .env values as secrets, except names explicitly marked public.
    ImportEnv {
        file: PathBuf,
        #[arg(long)]
        project: String,
        /// Store this named assignment as a public literal in av.toml. Repeat for more names.
        #[arg(long = "public", value_name = "NAME")]
        public: Vec<String>,
    },
    /// Write a .env template with placeholders for every secret reference.
    Placeholders {
        #[arg(long)]
        env: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    Run {
        #[arg(long)]
        env: Option<String>,
        /// Register an experimental synthetic proxy task for operator approval.
        #[arg(long)]
        broker: bool,
        #[arg(long)]
        broker_connection: Option<String>,
        #[arg(long)]
        broker_host: Option<String>,
        /// Experimental same-UID credential injection proxy. Not protected custody.
        #[arg(long)]
        proxy_preview: bool,
        #[arg(long, requires = "proxy_preview")]
        proxy_secret_env: Option<String>,
        #[arg(long, requires = "proxy_preview")]
        proxy_host: Option<String>,
        #[arg(last = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum SecretCommand {
    Init {
        #[arg(long)]
        recovery_file: PathBuf,
    },
    #[command(alias = "set")]
    Add {
        name: String,
    },
    Rotate {
        name: String,
    },
    /// Add a release grant pinned to this command and project configuration.
    Grant {
        name: String,
        #[arg(long)]
        env: Option<String>,
        #[arg(long, value_enum, default_value = "direct")]
        mode: management::CliDelivery,
        #[arg(long)]
        host: Option<String>,
        /// Allow future matching runs without an additional approval prompt.
        #[arg(long)]
        preapprove: bool,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    Policy {
        name: String,
    },
    Revoke {
        name: String,
    },
    Backup {
        output: PathBuf,
    },
    Restore {
        backup: PathBuf,
    },
    RotateKey {
        #[arg(long)]
        new_recovery_file: PathBuf,
    },
    List,
    Recover {
        #[arg(long)]
        recovery_file: PathBuf,
        #[arg(long)]
        new_recovery_file: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match execute(cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("av: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: Cli) -> Result<u8> {
    let explicit_config = cli.config.is_some();
    let config_path = cli.config.unwrap_or_else(|| PathBuf::from("av.toml"));
    let explicit_vault = cli.vault.is_some();
    let vault_path = cli.vault.unwrap_or(default_vault_path()?);
    match cli.command {
        Commands::Protected { command } => {
            ensure!(
                !explicit_vault && !explicit_config,
                "installed protected administration does not accept local --vault or --config options"
            );
            protected_operator::execute(command)
        }
        Commands::Setup {
            direct,
            recovery_file,
        } => {
            ensure!(direct, "this setup command requires explicit --direct");
            secret_command(
                SecretCommand::Init { recovery_file },
                &config_path,
                &vault_path,
            )
        }
        Commands::Status => {
            println!(
                "Local direct vault: {}",
                if vault_path.with_extension("keys.json").is_file() {
                    "initialization present; locked until each command unlocks it"
                } else {
                    "not initialized; use av setup --direct"
                }
            );
            println!("Protected service: not checked by this command");
            Ok(0)
        }
        Commands::Unlock { direct } => {
            ensure!(direct, "this unlock check requires explicit --direct");
            drop(unlock(&vault_path)?);
            println!(
                "Local vault passphrase verified. This command has closed the vault; no unlock is cached."
            );
            Ok(0)
        }
        Commands::Connect { command } => connections::manage(command, &vault_path),
        Commands::Init { project } => {
            let source = format!("schema = 2\n\n[project]\nid = {project:?}\n");
            Config::parse(&source)?;
            write_new_private(&config_path, source.as_bytes())?;
            println!("Created {}", config_path.display());
            Ok(0)
        }
        Commands::Check { env } => {
            let config = Config::load(&config_path)?;
            if has_secret_refs(&config, env.as_deref())? {
                let vault = unlock(&vault_path)?;
                check(&config, env.as_deref(), |reference| {
                    vault.get(&reference.storage_key())
                })?;
            } else {
                check(&config, env.as_deref(), |_| Ok(None))?;
            }
            println!("Configuration valid");
            Ok(0)
        }
        Commands::ImportEnv {
            file,
            project,
            public,
        } => management::import_env(&file, &project, &public, &config_path, &vault_path),
        Commands::Placeholders { env, output } => {
            management::placeholders(&config_path, env.as_deref(), &output)
        }
        Commands::Secret { command } => secret_command(command, &config_path, &vault_path),
        Commands::Run {
            env,
            broker,
            broker_connection,
            broker_host,
            proxy_preview,
            proxy_secret_env,
            proxy_host,
            command,
        } => {
            if broker {
                ensure!(
                    !proxy_preview && proxy_secret_env.is_none() && proxy_host.is_none(),
                    "broker tasks cannot use proxy preview options"
                );
                if broker && broker_connection.is_none() && broker_host.is_none() {
                    let config = Config::load(&config_path)?;
                    let reference = single_broker_connection(&config, env.as_deref())?;
                    return run_broker(
                        true,
                        Some(&reference.id),
                        None,
                        Some(reference.version),
                        &command,
                    );
                }
                ensure!(
                    env.is_none(),
                    "explicit broker tasks do not use project environment selection"
                );
                return run_broker(
                    broker,
                    broker_connection.as_deref(),
                    broker_host.as_deref(),
                    None,
                    &command,
                );
            }
            ensure!(
                broker_connection.is_none() && broker_host.is_none(),
                "broker connection and host require --broker"
            );
            ensure!(!command.is_empty(), "command is required");
            let source = fs::read(&config_path).context("cannot read project configuration")?;
            let config = Config::parse(std::str::from_utf8(&source)?)?;
            if !config.connection_refs(env.as_deref())?.is_empty() {
                ensure!(
                    !proxy_preview && proxy_secret_env.is_none() && proxy_host.is_none(),
                    "project connection references cannot use proxy preview"
                );
                let reference = single_broker_connection(&config, env.as_deref())?;
                return run_broker(
                    true,
                    Some(&reference.id),
                    None,
                    Some(reference.version),
                    &command,
                );
            }
            if proxy_preview {
                let secret_env = proxy_secret_env
                    .context("--proxy-secret-env is required with --proxy-preview")?;
                let host = proxy_host.context("--proxy-host is required with --proxy-preview")?;
                let selection = preview_selection(&config, env.as_deref(), &secret_env)?;
                let test_override = TestUpstream {
                    addr: None,
                    ca_der: None,
                };
                test_override.validate()?;
                eprintln!("{}", preview_disclosure(&command, &selection, &host));
                let vault = unlock(&vault_path)?;
                let request = SecretAccessRequest::for_command(
                    &command,
                    &config_path,
                    &source,
                    env.as_deref(),
                    DeliveryMode::ProxyPreview,
                    Some(&host),
                )?;
                let execution = VerifiedExecution::prepare(request.clone())?;
                let approved = management::authorize_run(
                    &vault,
                    std::slice::from_ref(&selection.storage_key),
                    &request,
                )?;
                let secret = Zeroizing::new(
                    vault
                        .get_authorized(&selection.storage_key, &request, approved)?
                        .context("selected proxy secret is missing")?,
                );
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .context("cannot start proxy preview runtime")?;
                return runtime.block_on(run_proxy_preview(
                    &config,
                    &secret,
                    env.as_deref(),
                    &selection,
                    &host,
                    &execution,
                    &test_override,
                ));
            }
            ensure!(
                proxy_secret_env.is_none() && proxy_host.is_none(),
                "proxy options require --proxy-preview"
            );
            let references = referenced_secrets(&config, env.as_deref())?;
            eprintln!("{}", direct_disclosure(&command, &references));
            if !references.is_empty() {
                let vault = unlock(&vault_path)?;
                let request = SecretAccessRequest::for_command(
                    &command,
                    &config_path,
                    &source,
                    env.as_deref(),
                    DeliveryMode::Direct,
                    None,
                )?;
                let execution = VerifiedExecution::prepare(request.clone())?;
                let approved = management::authorize_run(
                    &vault,
                    &references.iter().cloned().collect::<Vec<_>>(),
                    &request,
                )?;
                let resolved = resolve(&config, env.as_deref(), |reference| {
                    vault.get_authorized(&reference.storage_key(), &request, approved)
                })?;
                run_verified_direct(&execution, &resolved.values)
            } else {
                let resolved = resolve(&config, env.as_deref(), |_| Ok(None))?;
                run_direct(&command, &resolved.values)
            }
        }
    }
}

fn secret_command(command: SecretCommand, config_path: &Path, vault_path: &Path) -> Result<u8> {
    match command {
        SecretCommand::Init { recovery_file } => {
            ensure!(!recovery_file.exists(), "recovery file already exists");
            let mut passphrase = prompt_new_passphrase()?;
            let created = create_vault(vault_path, &passphrase);
            passphrase.zeroize();
            let created = created?;
            if let Err(error) = write_new_private(&recovery_file, created.recovery_key.as_bytes()) {
                drop(created.vault);
                let _ = fs::remove_file(vault_path);
                let _ = fs::remove_file(vault_path.with_extension("keys.json"));
                return Err(error);
            }
            println!(
                "Vault created. Move the recovery file outside agent-accessible paths and keep it offline."
            );
            Ok(0)
        }
        SecretCommand::Add { name } => {
            let config = Config::load(config_path)?;
            let reference = SecretRef::parse(
                &format!("secret://{}/{name}", config.project.id),
                &config.project.id,
            )?;
            let vault = unlock(vault_path)?;
            let value = Zeroizing::new(rpassword::prompt_password("Secret value: ")?);
            vault.add(&reference.storage_key(), &value)?;
            println!("Stored {}", reference.storage_key());
            Ok(0)
        }
        SecretCommand::List => {
            let vault = unlock(vault_path)?;
            for name in vault.list()? {
                if !av_core::connection::is_connection_storage_key(&name) {
                    println!("{name}");
                }
            }
            Ok(0)
        }
        SecretCommand::Recover {
            recovery_file,
            new_recovery_file,
        } => {
            ensure!(
                recovery_file != new_recovery_file,
                "new recovery file must be distinct"
            );
            ensure!(
                !new_recovery_file.exists(),
                "new recovery file already exists"
            );
            let mut recovery_key =
                fs::read_to_string(&recovery_file).context("cannot read recovery file")?;
            let mut new_passphrase = prompt_new_passphrase()?;
            let result = recover_vault(
                vault_path,
                recovery_key.trim(),
                &new_passphrase,
                &new_recovery_file,
            );
            new_passphrase.zeroize();
            recovery_key.zeroize();
            result?;
            println!(
                "Vault data key, passphrase, and recovery key replaced. Old backups retain their original keys. Move the new recovery file offline."
            );
            Ok(0)
        }
        other => management::secret_command(other, config_path, vault_path),
    }
}

fn default_vault_path() -> Result<PathBuf> {
    let dirs =
        ProjectDirs::from("", "AgentsVault", "av").context("user data directory unavailable")?;
    Ok(dirs.data_local_dir().join("vault.db"))
}

fn unlock(path: &Path) -> Result<Vault> {
    let mut passphrase = rpassword::prompt_password("Vault passphrase: ")?;
    let vault = Vault::open(path, &passphrase);
    passphrase.zeroize();
    vault
}

fn prompt_new_passphrase() -> Result<String> {
    let mut first = rpassword::prompt_password("New vault passphrase: ")?;
    let mut again = rpassword::prompt_password("Confirm vault passphrase: ")?;
    if first != again {
        first.zeroize();
        again.zeroize();
        bail!("passphrases do not match");
    }
    again.zeroize();
    ensure!(!first.is_empty(), "passphrase cannot be empty");
    Ok(first)
}

fn has_secret_refs(config: &Config, environment: Option<&str>) -> Result<bool> {
    Ok(config
        .selected(environment)?
        .values()
        .any(|decl| decl.secret.is_some()))
}

fn referenced_secrets(config: &Config, environment: Option<&str>) -> Result<BTreeSet<String>> {
    config
        .selected(environment)?
        .values()
        .filter_map(|decl| decl.secret.as_deref())
        .map(|reference| SecretRef::parse(reference, &config.project.id).map(|r| r.storage_key()))
        .collect()
}

fn direct_disclosure(command: &[String], references: &BTreeSet<String>) -> String {
    let mut notice = format!(
        "av: direct run {command:?}; referenced secrets: {references:?}. The child can read delivered values. This notice is not an authorization boundary."
    );
    if !references.is_empty() {
        notice.push(' ');
        notice.push_str(DIRECT_CODE_SCOPE);
    }
    notice
}

const DIRECT_CODE_SCOPE: &str = "The grant pins the executable image and command arguments. Scripts, imported modules, libraries, and programs it starts remain unpinned and can read delivered values. Use only code you trust with those values.";

fn single_broker_connection(
    config: &Config,
    environment: Option<&str>,
) -> Result<av_core::config::ConnectionRef> {
    let references = config.connection_refs(environment)?;
    ensure!(
        references.len() == 1 && config.selected(environment)?.len() == 1,
        "brokered run currently requires exactly one selected connection value"
    );
    Ok((*references.into_values().next().expect("checked length")).clone())
}

#[cfg(unix)]
fn run_broker(
    _broker: bool,
    connection: Option<&str>,
    host: Option<&str>,
    version: Option<u64>,
    command: &[String],
) -> Result<u8> {
    eprintln!(
        "av: Broker task request; the installed service enforces its own approval and custody policy."
    );
    let socket = std::env::var_os("AVD_AGENT_SOCKET")
        .map(PathBuf::from)
        .context("AVD_AGENT_SOCKET is required for broker tasks")?;
    let proxy_settings = proxy_settings::ProxySettings::load_or_initialize()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start broker client runtime")?;
    #[cfg(target_os = "linux")]
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "cannot protect broker client from same-user tracing"
    );
    runtime.block_on(async {
        let mut channel = ipc::Connection::connect(&socket).await.context("cannot connect to broker")?;
        let pending_id;
        {
            let connection = connection.context("--broker-connection is required")?;
            ensure!(
                host.is_some() != version.is_some(),
                "broker request requires either an explicit fixture host or a project connection version"
            );
            ensure!(!command.is_empty(), "broker command is required");
            let arguments = if let Some(version) = version {
                json!({ "command": command, "connection_version": version })
            } else {
                json!({ "command": command })
            };
            let created = broker_data(
                &mut channel,
                AgentRequest::Request {
                    operation: Operation {
                        connection: connection.to_owned(),
                        action: "proxy.run".to_owned(),
                        target: host.unwrap_or_default().to_owned(),
                        arguments,
                    },
                },
            )
            .await?;
            let request_id: Uuid = serde_json::from_value(created["request_id"].clone())
                .context("broker returned an invalid request ID")?;
            pending_id = Some(request_id);
            println!("Pending broker request: {request_id}");
            println!("Keep this process running. Review this request in the operator console or adopt it through MCP request_proxy_task.");
            std::io::stdout().flush().context("cannot flush pending request")?;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
            loop {
                ensure!(tokio::time::Instant::now() < deadline, "broker approval timed out");
                let review = broker_data(&mut channel, AgentRequest::Review { request_id }).await?;
                match review["state"].as_str() {
                    Some("pending") => tokio::time::sleep(Duration::from_millis(250)).await,
                    Some("denied") => bail!("broker request denied or revoked"),
                    Some(_) => bail!("broker request is no longer executable"),
                    None if review["state"].get("approved").is_some() => break,
                    _ => bail!("invalid broker review"),
                }
            }
        }
        // The request ID is public, but this connection retains the server-side owner.
        let request_id: Uuid = {
            // The created request is the only execution request on this connection.
            pending_id.context("missing broker request")?
        };
        let started = broker_data(&mut channel, AgentRequest::Execute { request_id }).await?;
        let task_id: Uuid = serde_json::from_value(started["task_id"].clone())
            .context("broker returned an invalid task ID")?;
        if let Some(host_proxy) = started.get("host_proxy") {
            let result = run_host_proxy_client(host_proxy, &proxy_settings).await;
            let exit_code = result.as_ref().map_or(1, |code| i32::from(*code));
            let finished = channel.call(&AgentRequest::FinishHostProxy { task_id, exit_code })
            .await
            .context("cannot report host proxy task outcome")
            .and_then(|reply| {
                ensure!(
                    reply.ok,
                    "broker rejected host proxy task outcome: {}",
                    reply.error.unwrap_or_default()
                );
                Ok(())
            });
            return result.and_then(|code| finished.map(|_| code));
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
        loop {
            ensure!(
                tokio::time::Instant::now() < deadline,
                "broker task status timed out"
            );
            let status = broker_data(&mut channel, AgentRequest::TaskStatus { task_id }).await?;
            match status["state"].as_str() {
                Some("running") => tokio::time::sleep(Duration::from_millis(250)).await,
                Some("finished") => {
                    let exit_code = status["exit_code"]
                        .as_i64()
                        .context("broker omitted finished task exit code")?;
                    println!("Broker task {task_id} finished with exit code {exit_code}");
                    return Ok(exit_code.clamp(0, 255) as u8);
                }
                Some("failed") => {
                    eprintln!("Broker task {task_id} failed");
                    return Ok(1);
                }
                _ => bail!("broker returned an invalid task state"),
            }
        }
    })
}

#[cfg(unix)]
async fn run_host_proxy_client(
    details: &Value,
    settings: &proxy_settings::ProxySettings,
) -> Result<u8> {
    let command: Vec<String> = serde_json::from_value(details["command"].clone())
        .context("broker returned an invalid host command")?;
    let (program, args) = command
        .split_first()
        .context("broker omitted host command")?;
    ensure!(
        Path::new(program).is_absolute(),
        "broker host command is not absolute"
    );
    let broker_proxy_url = details["proxy_url"]
        .as_str()
        .context("broker omitted host proxy")?;
    let proxy_url = settings.authorized_url(broker_proxy_url)?;
    let ca_pem = details["ca_pem"]
        .as_str()
        .context("broker omitted host CA")?;
    ensure!(ca_pem.len() <= 16 * 1024, "broker host CA is too large");
    let timeout_seconds = details["timeout_seconds"]
        .as_u64()
        .context("broker omitted host timeout")?;
    ensure!((1..=60).contains(&timeout_seconds), "invalid host timeout");
    let directory = tempfile::tempdir().context("cannot prepare host proxy CA")?;
    let ca_path = directory.path().join("ca.pem");
    fs::write(&ca_path, ca_pem).context("cannot write host proxy CA")?;
    let mut child = AsyncCommand::new(program);
    child
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", directory.path())
        .env("HTTPS_PROXY", &proxy_url)
        .env("https_proxy", &proxy_url)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .env("SSL_CERT_FILE", &ca_path)
        .env("CURL_CA_BUNDLE", &ca_path)
        .env("REQUESTS_CA_BUNDLE", &ca_path)
        .env("GIT_SSL_CAINFO", &ca_path)
        .env("NODE_EXTRA_CA_CERTS", &ca_path)
        .env("AV_FIXTURE_TOKEN", "av-placeholder")
        .kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(timeout_seconds), child.status())
        .await
        .context("host proxy task timed out")?
        .context("cannot execute host proxy command")?;
    Ok(status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .unwrap_or(1))
}

#[cfg(not(unix))]
fn run_broker(
    _: bool,
    _: Option<&str>,
    _: Option<&str>,
    _: Option<u64>,
    _: &[String],
) -> Result<u8> {
    bail!("broker IPC is unavailable on this platform; direct mode remains available")
}

#[cfg(unix)]
async fn broker_data(channel: &mut ipc::Connection, request: AgentRequest) -> Result<Value> {
    let Reply { ok, data, error } = channel
        .call(&request)
        .await
        .context("cannot communicate with broker")?;
    if ok {
        data.context("broker omitted response data")
    } else {
        bail!("broker rejected request: {}", error.unwrap_or_default())
    }
}

#[derive(Debug)]
struct PreviewSelection {
    env_name: String,
    storage_key: String,
}

struct TestUpstream {
    addr: Option<SocketAddr>,
    ca_der: Option<PathBuf>,
}

impl TestUpstream {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.addr.is_some() == self.ca_der.is_some(),
            "test upstream address and CA must be provided together"
        );
        if let Some(addr) = self.addr {
            ensure!(addr.ip().is_loopback(), "test upstream must be loopback");
            ensure!(
                cfg!(debug_assertions),
                "test upstream override is unavailable in release builds"
            );
        }
        Ok(())
    }
}

fn preview_selection(
    config: &Config,
    environment: Option<&str>,
    requested_env: &str,
) -> Result<PreviewSelection> {
    let selected = config.selected(environment)?;
    let mut secrets = selected
        .iter()
        .filter(|(_, declaration)| declaration.secret.is_some());
    let (name, declaration) = secrets
        .next()
        .context("proxy preview requires exactly one configured secret-backed value")?;
    ensure!(
        secrets.next().is_none(),
        "proxy preview refuses configurations with multiple secret-backed values"
    );
    ensure!(
        *name == requested_env,
        "--proxy-secret-env must name the only selected secret-backed value"
    );
    ensure!(
        ![
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "SSL_CERT_FILE",
            "CURL_CA_BUNDLE",
            "REQUESTS_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
            "GIT_SSL_CAINFO",
        ]
        .iter()
        .any(|reserved| requested_env.eq_ignore_ascii_case(reserved)),
        "the selected secret variable conflicts with proxy preview runtime variables"
    );
    ensure!(
        matches!(declaration.kind, ValueType::String),
        "proxy preview secret must be a string value"
    );
    let reference = SecretRef::parse(
        declaration
            .secret
            .as_deref()
            .expect("filtered secret declaration"),
        &config.project.id,
    )?;
    Ok(PreviewSelection {
        env_name: requested_env.to_owned(),
        storage_key: reference.storage_key(),
    })
}

fn preview_disclosure(command: &[String], selection: &PreviewSelection, host: &str) -> String {
    format!(
        "av: EXPERIMENTAL proxy preview for {command:?}; {} uses a placeholder and HTTPS injection for exact host {host}. This is NOT protected custody: the child and agent share the user identity, network egress is not confined, and there is no MCP approval. A child can bypass this proxy; exact-host matching permits any path or action on that host; and the provider may reflect the injected credential. The child receives a minimal environment plus configured values and proxy settings. Upstream TLS uses bundled WebPKI public roots, or an explicit synthetic test CA in test builds. Only use a test credential for this prototype.",
        selection.env_name,
    )
}

fn preview_certificate(host: &str) -> Result<(Arc<ServerConfig>, String)> {
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).context("cannot configure preview CA")?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().context("cannot create preview CA key")?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("cannot create preview CA")?;

    let leaf_params =
        CertificateParams::new(vec![host.to_owned()]).context("invalid preview proxy host")?;
    let leaf_key = KeyPair::generate().context("cannot create preview leaf key")?;
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .context("cannot create preview leaf certificate")?;
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf_cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .context("cannot configure preview TLS")?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((Arc::new(tls), ca_cert.pem()))
}

fn upstream_tls(test_upstream: &TestUpstream) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    if let Some(path) = &test_upstream.ca_der {
        let ca = fs::read(path).context("cannot read synthetic upstream CA")?;
        roots
            .add(CertificateDer::from(ca))
            .context("invalid synthetic upstream CA")?;
    } else {
        // Bundle public WebPKI roots so upstream verification is independent of
        // the temporary interception CA delivered to the child.
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let mut tls = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(tls))
}

async fn pinned_upstream(host: &str, test_upstream: &TestUpstream) -> Result<SocketAddr> {
    if let Some(addr) = test_upstream.addr {
        return Ok(addr);
    }
    tokio::net::lookup_host((host, 443))
        .await
        .context("cannot resolve preview host")?
        .next()
        .context("preview host has no upstream address")
}

async fn run_proxy_preview(
    config: &Config,
    secret: &str,
    environment: Option<&str>,
    selection: &PreviewSelection,
    host: &str,
    execution: &VerifiedExecution,
    test_upstream: &TestUpstream,
) -> Result<u8> {
    ensure!(
        !host.is_empty() && host.is_ascii() && !host.contains([':', '/', ' ']),
        "proxy host must be one DNS hostname"
    );
    let program = &execution.request.executable;
    let task_token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let placeholder = format!("av-proxy-placeholder-{}", Uuid::new_v4().simple());
    let mut values = resolve(config, environment, |reference| {
        ensure!(
            reference.storage_key() == selection.storage_key,
            "proxy preview refuses another secret-backed value"
        );
        Ok(Some(placeholder.clone()))
    })?
    .values;
    ensure!(
        values.get(&selection.env_name) == Some(&placeholder),
        "selected proxy environment value was not resolved"
    );

    let (downstream_tls, ca_pem) = preview_certificate(host)?;
    let ca_directory = tempfile::tempdir().context("cannot create preview CA directory")?;
    let ca_path = ca_directory.path().join("ca.pem");
    write_new_private(&ca_path, ca_pem.as_bytes())?;
    let upstream_addr = pinned_upstream(host, test_upstream).await?;

    let mut auth = Zeroizing::new(format!("Bearer {secret}"));
    let auth_header = auth
        .parse()
        .context("selected secret is not usable as an HTTP Authorization header")?;
    auth.zeroize();
    let proxy = ProxyServer::bind(ProxyConfig {
        bind_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        allowed_host: host.to_owned(),
        allowed_port: 443,
        upstream_addr,
        downstream_tls,
        upstream_tls: upstream_tls(test_upstream)?,
        injection: CredentialInjection {
            header_name: hyper::header::AUTHORIZATION,
            header_value: auth_header,
        },
        grant: TaskGrant {
            bearer_token: task_token.clone(),
            expires_at: SystemTime::now() + Duration::from_secs(120),
            max_connects: 8,
            max_requests: 16,
        },
    })
    .await
    .context("cannot start preview proxy")?;
    let proxy_addr = proxy
        .local_addr()
        .context("cannot read preview proxy address")?;
    let proxy_url = format!("http://av:{task_token}@{proxy_addr}");
    values.insert("HTTPS_PROXY".to_owned(), proxy_url.clone());
    values.insert("https_proxy".to_owned(), proxy_url);
    values.insert("NO_PROXY".to_owned(), String::new());
    values.insert("no_proxy".to_owned(), String::new());
    for name in [
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "GIT_SSL_CAINFO",
    ] {
        values.insert(name.to_owned(), ca_path.to_string_lossy().into_owned());
    }

    let mut child_command = AsyncCommand::from(execution.command()?);
    child_command
        .envs(values)
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .env_remove("FTP_PROXY")
        .env_remove("ftp_proxy");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let mut proxy_task = tokio::spawn(async move {
        proxy
            .run(async {
                let _ = stopped.await;
            })
            .await
    });
    let child = child_command.spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            let _ = stop.send(());
            let _ = proxy_task.await;
            return Err(error).with_context(|| format!("cannot start command {program}"));
        }
    };
    let status_result = tokio::select! {
        result = child.wait() => Some(result),
        _ = tokio::time::sleep(Duration::from_secs(150)) => {
            let _ = child.kill().await;
            None
        },
        proxy_result = &mut proxy_task => {
            let _ = child.kill().await;
            bail!("preview proxy stopped before child: {proxy_result:?}");
        }
    };
    let _ = stop.send(());
    proxy_task.await.context("preview proxy task failed")??;
    let status = status_result
        .context("preview command exceeded its 150-second runtime limit")?
        .with_context(|| format!("cannot wait for command {program}"))?;
    Ok(status
        .code()
        .map(|code| code.clamp(0, 255) as u8)
        .unwrap_or(1))
}

/// Holds the executable snapshot through child exit. Only the primary image is
/// pinned; libraries, interpreter input, and application configuration are not.
struct VerifiedExecution {
    request: SecretAccessRequest,
    image: fs::File,
    image_path: PathBuf,
    _directory: Option<tempfile::TempDir>,
}

impl VerifiedExecution {
    fn prepare(request: SecretAccessRequest) -> Result<Self> {
        let mut source = fs::File::open(&request.executable)
            .context("cannot open approved executable for snapshot")?;
        ensure!(
            source.metadata()?.is_file(),
            "executable must be a regular file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                source.metadata()?.permissions().mode() & 0o111 != 0,
                "approved executable has no execute permission"
            );
        }

        #[cfg(target_os = "linux")]
        let (mut image, image_path, directory) = {
            use std::os::fd::{AsRawFd, FromRawFd};
            // A sealed anonymous file cannot be replaced or modified between
            // digest verification and exec, including by another same-UID task.
            let fd = unsafe {
                libc::memfd_create(
                    c"av-approved-executable".as_ptr(),
                    libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
                )
            };
            ensure!(
                fd >= 0,
                "cannot create executable snapshot: {}",
                std::io::Error::last_os_error()
            );
            let mut image = unsafe { fs::File::from_raw_fd(fd) };
            std::io::copy(&mut source, &mut image)
                .context("cannot snapshot approved executable")?;
            let result = unsafe {
                libc::fcntl(
                    image.as_raw_fd(),
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_WRITE
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_SEAL,
                )
            };
            ensure!(
                result == 0,
                "cannot seal executable snapshot: {}",
                std::io::Error::last_os_error()
            );
            let path = PathBuf::from(format!("/proc/self/fd/{}", image.as_raw_fd()));
            (image, path, None)
        };

        #[cfg(not(target_os = "linux"))]
        let (mut image, image_path, directory) = {
            let directory = tempfile::Builder::new()
                .prefix("av-exec-")
                .tempdir()
                .context("cannot create private executable directory")?;
            let path = directory.path().join(if cfg!(windows) {
                "command.exe"
            } else {
                "command"
            });
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            std::io::copy(&mut source, &mut output)
                .context("cannot snapshot approved executable")?;
            output.sync_all()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                output.set_permissions(fs::Permissions::from_mode(0o500))?;
            }
            drop(output);
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                // Deny writes and deletion for the lifetime of the child.
                options.share_mode(0x0000_0001); // FILE_SHARE_READ
            }
            let image = options.open(&path)?;
            (image, path, Some(directory))
        };

        verify_executable_image(&mut image, &request.executable_sha256)?;
        Ok(Self {
            request,
            image,
            image_path,
            _directory: directory,
        })
    }

    fn command(&self) -> Result<Command> {
        // macOS has no Linux-style file seals. A private read-only copy and a
        // final digest check narrow the race but do not resist same-UID tampering.
        verify_executable_image(
            &mut self.image.try_clone()?,
            &self.request.executable_sha256,
        )?;
        let mut command = Command::new(&self.image_path);
        command
            .args(&self.request.arguments)
            .current_dir(&self.request.working_directory);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.arg0(&self.request.executable);
        }
        minimal_child_environment(&mut command)?;
        Ok(command)
    }
}

fn verify_executable_image(image: &mut fs::File, expected: &str) -> Result<()> {
    image.seek(SeekFrom::Start(0))?;
    let mut magic = [0; 4];
    image
        .read_exact(&mut magic)
        .context("executable image is too short")?;
    ensure!(
        !magic.starts_with(b"#!"),
        "secret-bearing commands require a native executable; a script's interpreter is not pinned by its grant. Pass the absolute path of a trusted, snapshot-compatible interpreter before the script path"
    );
    #[cfg(target_os = "linux")]
    ensure!(
        magic == *b"\x7fELF",
        "secret-bearing commands require a native ELF executable"
    );
    #[cfg(windows)]
    ensure!(
        magic.starts_with(b"MZ"),
        "secret-bearing commands require a native Windows executable"
    );
    image.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let length = image.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        hash.update(&buffer[..length]);
    }
    ensure!(
        format!("{:x}", hash.finalize()) == expected,
        "executable image changed since policy verification"
    );
    Ok(())
}

fn minimal_child_environment(command: &mut Command) -> Result<()> {
    command.env_clear().env("LANG", "C");
    #[cfg(unix)]
    command.env("PATH", "/usr/bin:/bin");
    #[cfg(windows)]
    {
        // Query the OS rather than inheriting a caller-controlled SystemRoot.
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
        }
        use std::os::windows::ffi::OsStringExt;
        let mut buffer = vec![0_u16; 32768];
        let length =
            unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        ensure!(
            length > 0 && length < buffer.len(),
            "cannot determine Windows system directory"
        );
        let root = std::ffi::OsString::from_wide(&buffer[..length]);
        let mut path = PathBuf::from(&root).join("System32").into_os_string();
        path.push(";");
        path.push(&root);
        command
            .env("SystemRoot", &root)
            .env("WINDIR", &root)
            .env("PATH", path);
    }
    Ok(())
}

fn run_verified_direct(
    execution: &VerifiedExecution,
    values: &BTreeMap<String, String>,
) -> Result<u8> {
    let status = execution
        .command()?
        .envs(values)
        .status()
        .with_context(|| {
            format!(
                "cannot start verified command {}",
                execution.request.executable
            )
        })?;
    Ok(status
        .code()
        .map(|code| code.clamp(0, 255) as u8)
        .unwrap_or(1))
}

fn run_direct(command: &[String], values: &BTreeMap<String, String>) -> Result<u8> {
    let (program, args) = command.split_first().context("command is required")?;
    let status = Command::new(program)
        .args(args)
        .envs(values)
        .status()
        .with_context(|| format!("cannot start command {program}"))?;
    Ok(status
        .code()
        .map(|code| code.clamp(0, 255) as u8)
        .unwrap_or(1))
}

fn write_new_private(path: &Path, content: &[u8]) -> Result<()> {
    #[cfg(unix)]
    let mut missing_ancestor_count = 0;
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        for ancestor in parent.ancestors() {
            if ancestor.as_os_str().is_empty() || ancestor.exists() {
                break;
            }
            missing_ancestor_count += 1;
        }
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    let persisted = file
        .write_all(content)
        .and_then(|_| file.sync_all())
        .and_then(|_| {
            #[cfg(unix)]
            {
                let directory = path
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                for ancestor in directory.ancestors().take(missing_ancestor_count + 1) {
                    let ancestor = if ancestor.as_os_str().is_empty() {
                        Path::new(".")
                    } else {
                        ancestor
                    };
                    fs::File::open(ancestor)?.sync_all()?;
                }
            }
            Ok(())
        });
    if let Err(error) = persisted {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use hyper::service::service_fn;
    use hyper::{Body, Request, StatusCode};
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[test]
    fn child_receives_environment_value() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("child.txt");
        let config = directory.path().join("av.toml");
        fs::write(&config, format!("schema = 2\n[project]\nid = 'demo'\n[values.AV_TEST_SENTINEL]\ntype = 'string'\nvalue = 'synthetic-value'\n[values.AV_TEST_OUTPUT]\ntype = 'string'\nvalue = {:?}\n", output.to_str().unwrap())).unwrap();
        let cli = Cli::try_parse_from([
            "av",
            "--config",
            config.to_str().unwrap(),
            "--vault",
            directory.path().join("unused.db").to_str().unwrap(),
            "run",
            "--",
            std::env::current_exe().unwrap().to_str().unwrap(),
            "--exact",
            "tests::direct_rust_child",
            "--nocapture",
        ])
        .unwrap();
        assert_eq!(execute(cli).unwrap(), 0);
        assert_eq!(fs::read_to_string(output).unwrap(), "synthetic-value");
    }

    #[test]
    fn project_connection_never_falls_back_to_direct_run() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("unexpected-child.txt");
        let config = directory.path().join("av.toml");
        fs::write(
            &config,
            format!(
                "schema = 2\n[project]\nid = 'demo'\n[values.AV_TEST_OUTPUT]\ntype = 'string'\nvalue = {:?}\n[values.SERVICE_TOKEN]\ntype = 'string'\nconnection = {{ id = 'service/work', version = 1 }}\ndelivery = 'proxy'\nrequired = true\n",
                output.to_str().unwrap()
            ),
        )
        .unwrap();
        let cli = Cli::try_parse_from([
            "av",
            "--config",
            config.to_str().unwrap(),
            "--vault",
            directory.path().join("unused.db").to_str().unwrap(),
            "run",
            "--",
            std::env::current_exe().unwrap().to_str().unwrap(),
            "--exact",
            "tests::direct_rust_child",
            "--nocapture",
        ])
        .unwrap();
        assert!(
            execute(cli)
                .unwrap_err()
                .to_string()
                .contains("exactly one selected connection value")
        );
        assert!(!output.exists());
    }

    #[test]
    fn single_connection_reference_selects_the_pinned_broker_version() {
        let config = Config::parse(
            "schema = 2\n[project]\nid = 'demo'\n[values.SERVICE_TOKEN]\ntype = 'string'\nconnection = { id = 'service/work', version = 3 }\ndelivery = 'proxy'\nrequired = true\n",
        )
        .unwrap();
        let reference = single_broker_connection(&config, None).unwrap();
        assert_eq!(reference.id, "service/work");
        assert_eq!(reference.version, 3);
    }

    #[test]
    fn direct_rust_child() {
        let Ok(output) = std::env::var("AV_TEST_OUTPUT") else {
            return;
        };
        fs::write(output, std::env::var("AV_TEST_SENTINEL").unwrap()).unwrap();
    }

    #[test]
    fn verified_direct_executes_snapshot_with_only_defined_environment() {
        let directory = tempfile::tempdir().unwrap();
        // Put ambient values on a separate launcher process; never mutate the
        // environment of the parallel test runner.
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::verified_direct_probe_launcher",
                "--nocapture",
            ])
            .env("AV_EXECUTION_PROBE_DIRECTORY", directory.path())
            .env("AV_AMBIENT_SECRET", "ambient-secret-must-not-reach-child")
            .env("PYTHONPATH", "/untrusted/python")
            .env("NODE_OPTIONS", "--no-warnings")
            .env("LD_LIBRARY_PATH", "/untrusted/libraries")
            .env("HTTP_PROXY", "http://untrusted-proxy.invalid")
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            fs::read_to_string(directory.path().join("verified.txt")).unwrap(),
            "approved-secret"
        );
        assert_eq!(
            fs::read_to_string(directory.path().join("ambient.txt")).unwrap(),
            "ambient-secret-must-not-reach-child"
        );
    }

    #[test]
    fn verified_direct_probe_launcher() {
        let Some(directory) = std::env::var_os("AV_EXECUTION_PROBE_DIRECTORY").map(PathBuf::from)
        else {
            return;
        };
        let config = directory.join("av.toml");
        fs::write(&config, "schema = 2\n[project]\nid = 'demo'\n").unwrap();
        let original = directory.join(if cfg!(windows) {
            "approved.exe"
        } else {
            "approved"
        });
        fs::copy(std::env::current_exe().unwrap(), &original).unwrap();
        let command = vec![
            original.to_str().unwrap().to_owned(),
            "--exact".into(),
            "tests::verified_direct_rust_child".into(),
            "--nocapture".into(),
        ];
        let request = SecretAccessRequest::for_command(
            &command,
            &config,
            &fs::read(&config).unwrap(),
            None,
            DeliveryMode::Direct,
            None,
        )
        .unwrap();
        let execution = VerifiedExecution::prepare(request).unwrap();
        #[cfg(target_os = "linux")]
        {
            let mut writable = OpenOptions::new()
                .write(true)
                .open(&execution.image_path)
                .unwrap();
            assert!(writable.write_all(b"tamper").is_err());
        }
        let moved = directory.join("previous-image");
        fs::rename(&original, &moved).unwrap();
        fs::write(&original, b"replacement must never execute").unwrap();
        fs::write(&moved, b"in-place edits must not change the snapshot").unwrap();
        let values = BTreeMap::from([
            (
                "AV_VERIFIED_OUTPUT".into(),
                directory.join("verified.txt").to_str().unwrap().into(),
            ),
            ("AV_VERIFIED_SECRET".into(), "approved-secret".into()),
            (
                "AV_EXPECTED_ARGV0".into(),
                execution.request.executable.clone(),
            ),
        ]);
        assert_eq!(run_verified_direct(&execution, &values).unwrap(), 0);

        let command = vec![
            std::env::current_exe().unwrap().to_str().unwrap().into(),
            "--exact".into(),
            "tests::ambient_direct_rust_child".into(),
            "--nocapture".into(),
        ];
        let values = BTreeMap::from([(
            "AV_AMBIENT_OUTPUT".into(),
            directory.join("ambient.txt").to_str().unwrap().into(),
        )]);
        assert_eq!(run_direct(&command, &values).unwrap(), 0);
    }

    #[test]
    fn verified_direct_rust_child() {
        let Ok(output) = std::env::var("AV_VERIFIED_OUTPUT") else {
            return;
        };
        let allowed = [
            "LANG",
            "PATH",
            "AV_VERIFIED_OUTPUT",
            "AV_VERIFIED_SECRET",
            "AV_EXPECTED_ARGV0",
            "SYSTEMROOT",
            "WINDIR",
            // macOS adds this locale hint when a process starts, even after env_clear.
            #[cfg(target_os = "macos")]
            "__CF_USER_TEXT_ENCODING",
        ];
        for (name, _) in std::env::vars_os() {
            assert!(
                allowed.contains(&name.to_string_lossy().to_ascii_uppercase().as_str()),
                "unexpected child environment name: {name:?}"
            );
        }
        #[cfg(unix)]
        {
            assert_eq!(std::env::var("PATH").unwrap(), "/usr/bin:/bin");
            assert_eq!(
                std::env::args().next().unwrap(),
                std::env::var("AV_EXPECTED_ARGV0").unwrap()
            );
        }
        assert_eq!(std::env::var("LANG").unwrap(), "C");
        fs::write(output, std::env::var("AV_VERIFIED_SECRET").unwrap()).unwrap();
    }

    #[test]
    fn ambient_direct_rust_child() {
        let Ok(output) = std::env::var("AV_AMBIENT_OUTPUT") else {
            return;
        };
        fs::write(output, std::env::var("AV_AMBIENT_SECRET").unwrap()).unwrap();
    }

    #[test]
    fn executable_change_before_snapshot_is_denied() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("av.toml");
        fs::write(&config, "schema = 2\n[project]\nid = 'demo'\n").unwrap();
        let program = directory.path().join("approved");
        fs::copy(std::env::current_exe().unwrap(), &program).unwrap();
        let request = SecretAccessRequest::for_command(
            &[program.to_str().unwrap().into()],
            &config,
            &fs::read(&config).unwrap(),
            None,
            DeliveryMode::Direct,
            None,
        )
        .unwrap();
        OpenOptions::new()
            .append(true)
            .open(&program)
            .unwrap()
            .write_all(b"changed")
            .unwrap();
        let error = match VerifiedExecution::prepare(request) {
            Ok(_) => panic!("changed image was accepted"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("changed since policy verification")
        );
    }

    #[cfg(unix)]
    #[test]
    fn script_grant_cannot_authorize_an_unpinned_interpreter() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("av.toml");
        fs::write(&config, "schema = 2\n[project]\nid = 'demo'\n").unwrap();
        let program = directory.path().join("script");
        fs::write(&program, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        let request = SecretAccessRequest::for_command(
            &[program.to_str().unwrap().into()],
            &config,
            &fs::read(&config).unwrap(),
            None,
            DeliveryMode::Direct,
            None,
        )
        .unwrap();
        let error = match VerifiedExecution::prepare(request) {
            Ok(_) => panic!("script image was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("interpreter is not pinned"));
    }

    #[test]
    fn placeholders_require_no_vault_and_never_read_secret_values() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("av.toml");
        let output = directory.path().join(".env.example");
        fs::write(&config, "schema = 2\n[project]\nid = 'demo'\n[values.TOKEN]\ntype = 'string'\nsecret = 'secret://demo/token'\n[values.MODE]\ntype = 'string'\nvalue = 'dev'\n").unwrap();
        management::placeholders(&config, None, &output).unwrap();
        let source = fs::read_to_string(&output).unwrap();
        assert!(source.contains("TOKEN=\"<AV_SECRET:demo/token>\""));
        assert!(source.contains("MODE=\"dev\""));
        assert!(management::placeholders(&config, None, &output).is_err());
    }

    #[test]
    fn direct_disclosure_names_command_and_references_without_values() {
        let config = Config::parse(
            "schema = 2\n[project]\nid = 'demo'\n[values.API_TOKEN]\ntype = 'string'\nsecret = 'secret://demo/token'\n",
        )
        .unwrap();
        let references = referenced_secrets(&config, None).unwrap();
        let notice = direct_disclosure(&["gh".into(), "issue".into(), "list".into()], &references);
        assert!(notice.contains("gh"));
        assert!(notice.contains("demo/token"));
        assert!(notice.contains("not an authorization boundary"));
        assert!(notice.contains(
            "Scripts, imported modules, libraries, and programs it starts remain unpinned"
        ));
        assert!(!notice.contains("synthetic-secret-value"));
    }

    #[cfg(unix)]
    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "requires AV_DIRECT_TEST_INTERPRETER naming an installed snapshot-compatible interpreter"
    )]
    fn pinned_shell_preserves_script_arguments_values_and_mutable_code_scope() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("av.toml");
        let script = directory.path().join("development task.sh");
        let output = directory.path().join("result.txt");
        fs::write(&config, "schema = 2\n[project]\nid = 'shell-workflow'\n[values.MODE]\ntype = 'string'\nvalue = 'development #1'\n[values.TOKEN]\ntype = 'string'\nsecret = 'secret://shell-workflow/token'\n").unwrap();
        fs::write(&script, "set -eu\n[ \"$MODE\" = 'development #1' ]\n[ \"$TOKEN\" = 'av-synthetic-script-token' ]\n[ \"$1\" = 'argument with spaces' ]\nprintf '%s\\n' \"$PWD\" > \"$2\"\nexit 37\n").unwrap();
        let interpreter =
            std::env::var("AV_DIRECT_TEST_INTERPRETER").unwrap_or_else(|_| "/bin/sh".into());
        let command = vec![
            interpreter,
            script.to_str().unwrap().into(),
            "argument with spaces".into(),
            output.to_str().unwrap().into(),
        ];
        let request = SecretAccessRequest::for_command(
            &command,
            &config,
            &fs::read(&config).unwrap(),
            None,
            DeliveryMode::Direct,
            None,
        )
        .unwrap();
        let execution = VerifiedExecution::prepare(request.clone()).unwrap();
        let parsed = Config::load(&config).unwrap();
        let resolved = resolve(&parsed, None, |_| {
            Ok(Some("av-synthetic-script-token".into()))
        })
        .unwrap();
        assert_eq!(
            run_verified_direct(&execution, &resolved.values).unwrap(),
            37
        );
        assert_eq!(
            fs::read_to_string(&output).unwrap().trim_end(),
            request.working_directory
        );

        // Direct delivery deliberately trusts project code. Editing a script
        // changes the recipient's behavior without changing interpreter bytes or argv.
        fs::write(
            &script,
            "set -eu\n[ -n \"$TOKEN\" ]\nprintf changed-script > \"$2\"\n",
        )
        .unwrap();
        let after_edit = SecretAccessRequest::for_command(
            &command,
            &config,
            &fs::read(&config).unwrap(),
            None,
            DeliveryMode::Direct,
            None,
        )
        .unwrap();
        assert_eq!(request, after_edit);
        assert_eq!(
            run_verified_direct(&execution, &resolved.values).unwrap(),
            0
        );
        assert_eq!(fs::read_to_string(output).unwrap(), "changed-script");
    }

    #[test]
    fn recovery_refuses_to_replace_the_supplied_key_file() {
        let directory = tempfile::tempdir().unwrap();
        let key_file = directory.path().join("recovery.txt");
        let result = secret_command(
            SecretCommand::Recover {
                recovery_file: key_file.clone(),
                new_recovery_file: key_file,
            },
            &directory.path().join("av.toml"),
            &directory.path().join("vault.db"),
        );
        assert!(result.unwrap_err().to_string().contains("must be distinct"));
    }

    #[test]
    fn proxy_preview_rejects_more_than_one_secret_reference() {
        let config = Config::parse(
            "schema = 2\n[project]\nid = 'demo'\n[values.SERVICE_TOKEN]\ntype = 'string'\nsecret = 'secret://demo/token'\n[values.OTHER_TOKEN]\ntype = 'string'\nsecret = 'secret://demo/other'\n",
        )
        .unwrap();
        assert!(
            preview_selection(&config, None, "SERVICE_TOKEN")
                .unwrap_err()
                .to_string()
                .contains("multiple secret-backed")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn proxy_preview_passes_placeholder_to_rust_child_and_injects_at_fake_provider() {
        if std::env::var("AV_PROXY_AMBIENT_PROBE").ok().as_deref() != Some("1") {
            let status = AsyncCommand::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::proxy_preview_passes_placeholder_to_rust_child_and_injects_at_fake_provider", "--nocapture"])
                .env("AV_PROXY_AMBIENT_PROBE", "1")
                .env("AV_AMBIENT_SECRET", "ambient-secret-must-not-reach-child")
                .env("PYTHONPATH", "/untrusted/python")
                .env("NODE_OPTIONS", "--no-warnings")
                .env("LD_LIBRARY_PATH", "/untrusted/libraries")
                .env("HTTP_PROXY", "http://untrusted-proxy.invalid")
                .status().await.unwrap();
            assert!(status.success());
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let vault_path = directory.path().join("vault.db");
        let created = create_vault(&vault_path, "synthetic-passphrase").unwrap();
        created
            .vault
            .set("demo/token", "synthetic-provider-token")
            .unwrap();
        let config = Config::parse(
            "schema = 2\n[project]\nid = 'demo'\n[values.SERVICE_TOKEN]\ntype = 'string'\nsecret = 'secret://demo/token'\n[values.AV_PROXY_PROBE]\ntype = 'string'\nvalue = '1'\n",
        )
        .unwrap();
        let selection = preview_selection(&config, None, "SERVICE_TOKEN").unwrap();
        let (provider_addr, ca_path, mut received, provider_task) =
            fake_https_provider(directory.path()).await;
        let child_binary = directory.path().join(if cfg!(windows) {
            "proxy-child.exe"
        } else {
            "proxy-child"
        });
        fs::copy(std::env::current_exe().unwrap(), &child_binary).unwrap();
        let command = vec![
            child_binary.to_string_lossy().into_owned(),
            "--exact".into(),
            "tests::proxy_preview_rust_child".into(),
            "--nocapture".into(),
        ];
        let config_path = directory.path().join("av.toml");
        fs::write(&config_path, "schema = 2\n[project]\nid = 'demo'\n").unwrap();
        let request = SecretAccessRequest::for_command(
            &command,
            &config_path,
            &fs::read(&config_path).unwrap(),
            None,
            DeliveryMode::ProxyPreview,
            Some("api.example.test"),
        )
        .unwrap();
        let execution = VerifiedExecution::prepare(request).unwrap();
        fs::write(&child_binary, b"replaced executable must never run").unwrap();
        let notice = preview_disclosure(&command, &selection, "api.example.test");
        assert!(notice.contains("NOT protected custody"));
        assert!(notice.contains("no MCP approval"));
        assert!(!notice.contains("synthetic-provider-token"));
        let result = run_proxy_preview(
            &config,
            "synthetic-provider-token",
            None,
            &selection,
            "api.example.test",
            &execution,
            &TestUpstream {
                addr: Some(provider_addr),
                ca_der: Some(ca_path),
            },
        )
        .await
        .unwrap();
        assert_eq!(result, 0);
        assert_eq!(
            received.recv().await.unwrap(),
            "Bearer synthetic-provider-token"
        );
        provider_task.abort();
    }

    async fn fake_https_provider(
        directory: &Path,
    ) -> (
        SocketAddr,
        PathBuf,
        mpsc::UnboundedReceiver<String>,
        tokio::task::JoinHandle<()>,
    ) {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca_params, &ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["api.example.test".to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        let ca_path = directory.join("upstream-ca.der");
        fs::write(&ca_path, ca_cert.der().as_ref()).unwrap();
        let mut tls = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .unwrap();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (sent, received) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(socket).await.unwrap();
            let service = service_fn(move |request: Request<Body>| {
                let sent = sent.clone();
                async move {
                    let auth = request
                        .headers()
                        .get(hyper::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("<missing>");
                    let _ = sent.send(auth.to_owned());
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(Body::from("ok")))
                }
            });
            let _ = hyper::server::conn::Http::new()
                .http1_only(true)
                .serve_connection(tls, service)
                .await;
        });
        (addr, ca_path, received, task)
    }

    #[test]
    fn proxy_preview_rust_child() {
        if std::env::var("AV_PROXY_PROBE").ok().as_deref() != Some("1") {
            return;
        }
        let placeholder = std::env::var("SERVICE_TOKEN").unwrap();
        assert!(placeholder.starts_with("av-proxy-placeholder-"));
        assert!(!placeholder.contains("synthetic-provider-token"));
        assert_eq!(std::env::var("NO_PROXY").unwrap(), "");
        assert!(std::env::var("HTTP_PROXY").is_err());
        assert!(std::env::var("ALL_PROXY").is_err());
        for name in [
            "AV_AMBIENT_SECRET",
            "AV_PROXY_AMBIENT_PROBE",
            "PYTHONPATH",
            "NODE_OPTIONS",
            "LD_LIBRARY_PATH",
            "HOME",
            "USERPROFILE",
        ] {
            assert!(
                std::env::var_os(name).is_none(),
                "unexpected ambient variable {name}"
            );
        }
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let proxy = std::env::var("HTTPS_PROXY").unwrap();
            let without_scheme = proxy.strip_prefix("http://av:").unwrap();
            let (task_token, proxy_addr) = without_scheme.split_once('@').unwrap();
            let proxy_addr: SocketAddr = proxy_addr.parse().unwrap();
            let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
            let proxy_auth = base64::engine::general_purpose::STANDARD
                .encode(format!("av:{task_token}"));
            let connect = format!(
                "CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\nProxy-Authorization: Basic {proxy_auth}\r\n\r\n"
            );
            stream.write_all(connect.as_bytes()).await.unwrap();
            let mut response = Vec::new();
            while !response.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).await.unwrap();
                response.push(byte[0]);
            }
            assert!(response.starts_with(b"HTTP/1.1 200"));
            let ca_path = std::env::var("SSL_CERT_FILE").unwrap();
            let ca_pem = fs::read(ca_path).unwrap();
            let mut ca_cursor = std::io::Cursor::new(ca_pem);
            let ca = rustls_pemfile::certs(&mut ca_cursor)
                .next()
                .unwrap()
                .unwrap();
            let mut roots = RootCertStore::empty();
            roots.add(ca).unwrap();
            let client_tls = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let tls = TlsConnector::from(Arc::new(client_tls))
                .connect(ServerName::try_from("api.example.test".to_owned()).unwrap(), stream)
                .await
                .unwrap();
            let (mut sender, connection) = hyper::client::conn::handshake(tls).await.unwrap();
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let request = Request::builder()
                .uri("/test")
                .header(hyper::header::HOST, "api.example.test")
                .header(hyper::header::AUTHORIZATION, placeholder)
                .body(Body::empty())
                .unwrap();
            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        });
    }
}
