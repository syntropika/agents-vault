//! Synthetic broker-owned proxy task orchestration.
//!
//! Credentials remain restricted to synthetic fixtures. Linux can confine its
//! child filesystem and process view and pin sealed executables; a distinct
//! broker identity and a trusted operator approval path are deployment gates.

use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use av_core::Vault;
use av_proxy::{CredentialInjection, ProxyConfig, ProxyHub, ProxyServer, TaskGrant};
use hyper::header::AUTHORIZATION;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use tokio::process::Command;
use tokio::sync::oneshot;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixStream},
};
#[cfg(target_os = "linux")]
use tokio::{net::UnixListener, sync::Semaphore};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const HOST_PROXY_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 14322);

/// Installed trust is read through checked directory descriptors so replacing
/// a path with a symlink cannot redirect the bytes after its ownership check.
#[cfg(target_os = "linux")]
pub(crate) fn read_linux_upstream_ca(path: &Path, trusted: bool) -> Result<Vec<u8>> {
    use std::{
        ffi::CString,
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt, fs::OpenOptionsExt},
        },
        path::Component,
    };

    const MAX_CA_BYTES: u64 = 16 * 1024;
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|part| matches!(part, Component::ParentDir)),
        "upstream CA path must be absolute without parent traversal"
    );
    let trusted_metadata = |metadata: &fs::Metadata| -> Result<()> {
        ensure!(
            [0, unsafe { libc::geteuid() }].contains(&metadata.uid())
                && metadata.mode() & 0o022 == 0,
            "upstream CA and ancestors must be root or broker owned and not writable by other identities"
        );
        Ok(())
    };
    let file = if trusted {
        let mut directory = fs::File::open("/")?;
        trusted_metadata(&directory.metadata()?)?;
        let components: Vec<_> = path
            .components()
            .filter_map(|part| match part {
                Component::Normal(name) => Some(name),
                _ => None,
            })
            .collect();
        ensure!(!components.is_empty(), "upstream CA must be a regular file");
        for (index, component) in components.iter().enumerate() {
            let name = CString::new(component.as_bytes())?;
            let leaf = index + 1 == components.len();
            let flags = libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | if leaf { 0 } else { libc::O_DIRECTORY };
            let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
            ensure!(
                fd >= 0,
                "cannot open trusted upstream CA path: {}",
                std::io::Error::last_os_error()
            );
            // openat returned a fresh descriptor, now owned only by this file.
            directory = unsafe { fs::File::from_raw_fd(fd) };
            trusted_metadata(&directory.metadata()?)?;
        }
        directory
    } else {
        // Development fixtures may live under temporary directories, but never
        // follow a leaf symlink or block while opening a FIFO as a certificate.
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && (1..=MAX_CA_BYTES).contains(&metadata.len()),
        "upstream CA must be a nonempty bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(MAX_CA_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_CA_BYTES,
        "upstream CA changed size while reading"
    );
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn validate_linux_ca_binding(request: &av_core::SecretAccessRequest, ca: &[u8]) -> Result<()> {
    ensure!(
        request.upstream_ca_sha256.as_deref() == Some(hex::encode(Sha256::digest(ca)).as_str()),
        "upstream CA changed while loading the granted recipe"
    );
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyPolicy {
    pub connection: String,
    #[serde(default)]
    pub secret_name: String,
    #[serde(default)]
    pub connection_version: Option<u64>,
    pub host: String,
    pub command: Vec<String>,
    pub upstream_addr: SocketAddr,
    pub upstream_ca_der: PathBuf,
    pub max_connects: u32,
    pub max_requests: u32,
    pub max_runtime_seconds: u64,
    #[serde(default)]
    pub host_client: bool,
    #[cfg(target_os = "linux")]
    pub runner_helper: Option<PathBuf>,
    #[serde(default)]
    pub mac_vmm: Option<PathBuf>,
    #[serde(default)]
    pub mac_guest_bundle: Option<PathBuf>,
    #[serde(default)]
    pub mac_service: bool,
}

impl ProxyPolicy {
    pub(crate) fn validate(&self) -> Result<()> {
        if let Some(version) = self.connection_version {
            av_core::config::validate_connection_id(&self.connection)?;
            ensure!(version > 0, "connection version must be positive");
            ensure!(
                self.secret_name.is_empty(),
                "connection policy cannot name a separate secret"
            );
            ensure!(
                self.host_client,
                "versioned connections require the host proxy"
            );
        } else {
            ensure!(
                self.connection.starts_with("demo/") && self.connection.len() <= 130,
                "proxy only accepts a demo connection"
            );
            ensure!(
                self.secret_name.starts_with("demo/") && self.secret_name.len() <= 130,
                "proxy policy requires a demo secret"
            );
        }
        ensure!(
            !self.host.is_empty()
                && self.host.is_ascii()
                && self
                    .host
                    .bytes()
                    .all(|byte| { byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-' })
                && !self.host.starts_with('-')
                && !self.host.ends_with('-')
                && self.host.len() <= 253,
            "proxy host must be an exact DNS hostname"
        );
        ensure!(
            !self.command.is_empty()
                && self.command.len() <= 32
                && Path::new(&self.command[0]).is_absolute()
                && self
                    .command
                    .iter()
                    .all(|arg| arg.len() <= 4096 && !arg.contains('\0')),
            "policy must pin one absolute executable and a bounded command vector"
        );
        ensure!(
            self.upstream_addr.ip().is_loopback() && self.upstream_addr.port() != 0,
            "synthetic upstream must be on loopback"
        );
        ensure!(
            self.upstream_ca_der.is_absolute(),
            "synthetic upstream CA path must be absolute"
        );
        ensure!(
            (1..=8).contains(&self.max_connects)
                && (1..=16).contains(&self.max_requests)
                && (1..=60).contains(&self.max_runtime_seconds),
            "action limits exceed the supported bounds"
        );
        #[cfg(target_os = "linux")]
        if let Some(helper) = &self.runner_helper {
            ensure!(helper.is_absolute(), "runner helper path must be absolute");
        }
        if self.host_client {
            #[cfg(target_os = "linux")]
            ensure!(
                self.runner_helper.is_none(),
                "host-client proxy cannot launch a runner helper"
            );
            ensure!(
                self.mac_vmm.is_none() && !self.mac_service,
                "host-client proxy cannot launch a macOS guest"
            );
        }
        ensure!(
            self.mac_vmm.is_some() == self.mac_guest_bundle.is_some(),
            "macOS runner requires both VMM and guest bundle paths"
        );
        ensure!(
            !self.mac_service || (self.mac_vmm.is_none() && self.mac_guest_bundle.is_none()),
            "macOS service mode uses only the installed runner and guest"
        );
        #[cfg(not(target_os = "macos"))]
        ensure!(
            self.mac_vmm.is_none() && !self.mac_service,
            "macOS runner is unavailable on this platform"
        );
        if self.mac_service {
            ensure!(
                self.command[0] == "/usr/bin/av-fixture",
                "macOS service supports only bundled /usr/bin/av-fixture"
            );
        }
        if let Some(vmm) = &self.mac_vmm {
            ensure!(
                vmm.is_absolute()
                    && self
                        .mac_guest_bundle
                        .as_ref()
                        .is_some_and(|bundle| bundle.is_absolute()),
                "macOS runner paths must be absolute"
            );
            ensure!(
                self.command[0] == "/usr/bin/av-fixture",
                "macOS guest supports only bundled /usr/bin/av-fixture"
            );
        }
        Ok(())
    }
}

pub struct ProxyRuntime {
    pub policy: ProxyPolicy,
    secret: Zeroizing<String>,
    upstream_ca_der: Vec<u8>,
    #[cfg(target_os = "linux")]
    trusted_ca: bool,
    #[cfg(target_os = "linux")]
    program_sha256: Option<[u8; 32]>,
    #[cfg(target_os = "linux")]
    helper_sha256: Option<[u8; 32]>,
    #[cfg(target_os = "macos")]
    mac_grant: Option<AuthorizedMacGrant>,
    #[cfg(target_os = "macos")]
    mac_host_grant: Option<AuthorizedMacHostGrant>,
}

#[derive(Clone, Serialize)]
pub struct HostProxyDetails {
    pub proxy_url: String,
    pub ca_pem: String,
    pub command: Vec<String>,
    pub timeout_seconds: u64,
}

#[cfg(target_os = "macos")]
#[derive(Clone)]
struct AuthorizedMacGrant {
    request: av_core::SecretAccessRequest,
    installed: av_vmm::service::ServiceIdentity,
    policy_path: PathBuf,
}

#[cfg(target_os = "macos")]
#[derive(Clone)]
struct AuthorizedMacHostGrant {
    request: av_core::SecretAccessRequest,
    policy_path: PathBuf,
}

#[cfg(target_os = "macos")]
impl AuthorizedMacHostGrant {
    fn revalidate(&self) -> Result<()> {
        let source = fs::read(&self.policy_path)?;
        ensure!(source.len() <= 16 * 1024, "proxy policy is too large");
        let policy: ProxyPolicy = serde_json::from_slice(&source)?;
        let request = crate::management::macos_host_proxy_access_request(
            &policy,
            &self.policy_path,
            &source,
        )?;
        ensure!(request == self.request, "macOS host proxy grant changed");
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl AuthorizedMacGrant {
    fn revalidate(&self) -> Result<()> {
        let source = fs::read(&self.policy_path)?;
        ensure!(source.len() <= 16 * 1024, "proxy policy is too large");
        let policy: ProxyPolicy = serde_json::from_slice(&source)?;
        let (request, installed) =
            crate::management::macos_proxy_access_request(&policy, &self.policy_path, &source)?;
        ensure!(
            request == self.request && installed == self.installed,
            "macOS service, host, CA, or policy changed since secret grant authorization"
        );
        Ok(())
    }
}

impl ProxyRuntime {
    pub(crate) fn load_with_grant(vault: &Vault, path: &Path, enforce_grant: bool) -> Result<Self> {
        let metadata = fs::symlink_metadata(path).context("cannot inspect proxy policy")?;
        ensure!(metadata.is_file(), "proxy policy must be a regular file");
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "proxy policy must not be group or world accessible"
        );
        let bytes = fs::read(path).context("cannot read proxy policy")?;
        ensure!(bytes.len() <= 16 * 1024, "proxy policy is too large");
        let policy: ProxyPolicy =
            serde_json::from_slice(&bytes).context("invalid proxy policy JSON")?;
        policy.validate()?;
        #[cfg(target_os = "linux")]
        let trusted_ca = std::env::var_os("AVD_SERVICE_AGENT_UID").is_some();
        #[cfg(target_os = "linux")]
        let grant_trusted_ca = trusted_ca;
        #[cfg(not(target_os = "linux"))]
        let grant_trusted_ca = false;
        #[cfg(target_os = "linux")]
        let upstream_ca_der = read_linux_upstream_ca(&policy.upstream_ca_der, trusted_ca)?;
        #[cfg(not(target_os = "macos"))]
        if enforce_grant && policy.connection_version.is_none() {
            let request =
                crate::management::proxy_access_request(&policy, path, &bytes, trusted_ca)?;
            #[cfg(target_os = "linux")]
            validate_linux_ca_binding(&request, &upstream_ca_der)?;
            vault.authorization(&policy.secret_name, &request)?;
        }
        #[cfg(target_os = "macos")]
        let mac_grant = if policy.mac_service {
            // An installed macOS task always requires a per-secret grant,
            // including callers using the development library entry point.
            let (request, installed) =
                crate::management::macos_proxy_access_request(&policy, path, &bytes)?;
            vault.authorization(&policy.secret_name, &request)?;
            Some(AuthorizedMacGrant {
                request,
                installed,
                policy_path: path.to_path_buf(),
            })
        } else {
            if enforce_grant && !policy.host_client {
                let request =
                    crate::management::proxy_access_request(&policy, path, &bytes, false)?;
                vault.authorization(&policy.secret_name, &request)?;
            }
            None
        };
        #[cfg(target_os = "macos")]
        let mac_host_grant =
            if policy.host_client && (enforce_grant || policy.connection_version.is_some()) {
                let request =
                    crate::management::macos_host_proxy_access_request(&policy, path, &bytes)?;
                if policy.connection_version.is_none() {
                    vault.authorization(&policy.secret_name, &request)?;
                }
                Some(AuthorizedMacHostGrant {
                    request,
                    policy_path: path.to_path_buf(),
                })
            } else {
                None
            };
        let secret = if let Some(version) = policy.connection_version {
            let request =
                crate::management::proxy_access_request(&policy, path, &bytes, grant_trusted_ca)?;
            #[cfg(target_os = "linux")]
            validate_linux_ca_binding(&request, &upstream_ca_der)?;
            let metadata = vault
                .connection_metadata(&policy.connection)?
                .context("proxy connection is missing")?;
            ensure!(
                metadata.active && metadata.version == version && metadata.host == policy.host,
                "proxy connection version or host differs from installed policy"
            );
            vault.get_connection_authorized(&policy.connection, version, &request, true)?
        } else {
            Zeroizing::new(
                vault
                    .get(&policy.secret_name)?
                    .context("synthetic proxy secret is missing")?,
            )
        };
        ensure!(
            secret.starts_with("av-synthetic-") && secret.len() <= 256,
            "proxy only accepts av-synthetic- credentials"
        );
        ensure!(
            policy
                .command
                .iter()
                .all(|argument| !argument.contains(secret.as_str())),
            "policy command cannot include its credential"
        );
        #[cfg(not(target_os = "linux"))]
        let upstream_ca_der = fs::read(&policy.upstream_ca_der)
            .context("cannot read synthetic upstream certificate")?;
        #[cfg(target_os = "macos")]
        if let Some(grant) = &mac_grant {
            use sha2::{Digest, Sha256};
            ensure!(
                grant
                    .request
                    .macos_service
                    .as_ref()
                    .context("missing macOS grant identity")?
                    .upstream_ca_sha256
                    == format!("{:x}", Sha256::digest(&upstream_ca_der)),
                "upstream CA changed while loading the granted recipe"
            );
        }
        #[cfg(target_os = "macos")]
        if let Some(grant) = &mac_host_grant {
            use sha2::{Digest, Sha256};
            ensure!(
                grant.request.upstream_ca_sha256.as_deref()
                    == Some(hex::encode(Sha256::digest(&upstream_ca_der)).as_str()),
                "upstream CA changed while loading the host proxy grant"
            );
        }
        ensure!(
            !upstream_ca_der.is_empty() && upstream_ca_der.len() <= 16 * 1024,
            "invalid synthetic upstream certificate size"
        );
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(upstream_ca_der.clone()))
            .context("invalid synthetic upstream certificate")?;
        #[cfg(target_os = "linux")]
        let (program_sha256, helper_sha256) = match &policy.runner_helper {
            Some(helper) => (
                Some(av_runner::executable_sha256(Path::new(&policy.command[0]))?),
                Some(av_runner::executable_sha256(helper)?),
            ),
            None => (None, None),
        };
        Ok(Self {
            #[cfg(target_os = "macos")]
            mac_grant,
            #[cfg(target_os = "macos")]
            mac_host_grant,
            #[cfg(target_os = "linux")]
            program_sha256,
            #[cfg(target_os = "linux")]
            helper_sha256,
            policy,
            secret,
            upstream_ca_der,
            #[cfg(target_os = "linux")]
            trusted_ca,
        })
    }

    #[cfg(target_os = "linux")]
    fn revalidate_linux_upstream_ca(&self) -> Result<()> {
        let current = read_linux_upstream_ca(&self.policy.upstream_ca_der, self.trusted_ca)?;
        ensure!(
            current == self.upstream_ca_der,
            "upstream CA changed since grant authorization"
        );
        Ok(())
    }

    pub async fn run(
        &self,
        expires_at: u64,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<i32> {
        ensure!(
            !self.policy.host_client,
            "host-client policy requires a client lease"
        );
        self.run_task(expires_at, shutdown).await
    }

    pub async fn run_host_client(
        &self,
        hub: &ProxyHub,
        expires_at: u64,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
        ready: oneshot::Sender<HostProxyDetails>,
        cancelled: oneshot::Receiver<i32>,
    ) -> Result<i32> {
        ensure!(
            self.policy.host_client,
            "policy does not permit a host client"
        );
        ensure!(!*shutdown.borrow(), "broker session is locked");
        #[cfg(target_os = "linux")]
        self.revalidate_linux_upstream_ca()?;
        #[cfg(target_os = "macos")]
        if let Some(grant) = &self.mac_host_grant {
            let grant = grant.clone();
            tokio::task::spawn_blocking(move || grant.revalidate())
                .await
                .context("macOS host grant validation worker failed")??;
            ensure!(
                !*shutdown.borrow(),
                "broker session relocked during grant validation"
            );
        }
        let remaining = (UNIX_EPOCH + Duration::from_secs(expires_at))
            .duration_since(SystemTime::now())
            .context("proxy approval expired before task start")?;
        ensure!(!remaining.is_zero(), "proxy approval expired");
        let lifetime = remaining.min(Duration::from_secs(self.policy.max_runtime_seconds));
        let (config, ca_pem, token) = self.proxy_config(lifetime, hub.local_addr())?;
        let grant_id = hub
            .activate(config)
            .await
            .context("cannot activate host proxy")?;
        let proxy_url = format!("http://av:{token}@{}", hub.local_addr());
        if ready
            .send(HostProxyDetails {
                proxy_url,
                ca_pem,
                command: self.policy.command.clone(),
                timeout_seconds: lifetime.as_secs().max(1),
            })
            .is_err()
        {
            hub.deactivate(grant_id).await?;
            anyhow::bail!("host client disconnected before proxy start");
        }
        let outcome = tokio::select! {
            _ = tokio::time::sleep(lifetime) => None,
            _ = shutdown.changed() => None,
            result = cancelled => result.ok(),
        };
        hub.deactivate(grant_id)
            .await
            .context("cannot revoke host proxy")?;
        outcome.context("host proxy task expired or broker locked before completion")
    }

    fn proxy_config(
        &self,
        lifetime: Duration,
        bind_addr: SocketAddr,
    ) -> Result<(ProxyConfig, String, String)> {
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let (downstream_tls, ca_pem) = interception_certificate(&self.policy.host)?;
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(self.upstream_ca_der.clone()))?;
        let mut upstream_tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        upstream_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut auth = Zeroizing::new(format!("Bearer {}", self.secret.as_str()));
        let auth_value = auth
            .parse()
            .context("invalid synthetic Authorization value")?;
        auth.zeroize();
        Ok((
            ProxyConfig {
                bind_addr,
                allowed_host: self.policy.host.clone(),
                allowed_port: 443,
                upstream_addr: self.policy.upstream_addr,
                downstream_tls,
                upstream_tls: Arc::new(upstream_tls),
                injection: CredentialInjection {
                    header_name: AUTHORIZATION,
                    header_value: auth_value,
                },
                grant: TaskGrant {
                    bearer_token: token.clone(),
                    expires_at: SystemTime::now() + lifetime,
                    max_connects: self.policy.max_connects,
                    max_requests: self.policy.max_requests,
                },
            },
            ca_pem,
            token,
        ))
    }

    async fn bind_proxy(
        &self,
        lifetime: Duration,
        host_client: bool,
    ) -> Result<(ProxyServer, SocketAddr, String, String, String)> {
        let bind_addr = if host_client {
            HOST_PROXY_ADDR
        } else {
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
        };
        let (config, ca_pem, token) = self.proxy_config(lifetime, bind_addr)?;
        let proxy = ProxyServer::bind(config)
            .await
            .context("cannot bind synthetic proxy")?;
        let address = proxy
            .local_addr()
            .context("cannot inspect proxy listener")?;
        let url = format!("http://av:{token}@{address}");
        Ok((proxy, address, url, ca_pem, token))
    }

    async fn run_task(
        &self,
        expires_at: u64,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<i32> {
        ensure!(!*shutdown.borrow(), "broker session is locked");
        #[cfg(target_os = "linux")]
        self.revalidate_linux_upstream_ca()?;
        #[cfg(target_os = "macos")]
        if self.policy.mac_service {
            let grant = self
                .mac_grant
                .as_ref()
                .context("installed macOS execution requires an authorized secret grant")?
                .clone();
            tokio::task::spawn_blocking(move || grant.revalidate())
                .await
                .context("macOS grant validation worker failed")??;
            ensure!(
                !*shutdown.borrow(),
                "broker session relocked during grant validation"
            );
        }
        let approval_deadline = UNIX_EPOCH + Duration::from_secs(expires_at);
        let remaining = approval_deadline
            .duration_since(SystemTime::now())
            .context("proxy approval expired before task start")?;
        ensure!(!remaining.is_zero(), "proxy approval expired");
        let lifetime = remaining.min(Duration::from_secs(self.policy.max_runtime_seconds));
        let (proxy, proxy_addr, proxy_url, ca_pem, token) =
            self.bind_proxy(lifetime, false).await?;
        #[cfg(target_os = "linux")]
        let service_runner_uid = if std::env::var_os("AVD_SERVICE_AGENT_UID").is_some() {
            Some(av_runner::service::service_uid("av-runner")?)
        } else {
            None
        };
        #[cfg(target_os = "linux")]
        let ca_dir = if service_runner_uid.is_some() {
            let directory = tempfile::Builder::new()
                .prefix("task-")
                .tempdir_in("/run/agents-vault")?;
            // The directory contains only public CA data and a relay guarded
            // by SO_PEERCRED. Names cannot be listed by the runner or agent.
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o711))?;
            directory
        } else {
            tempfile::tempdir()?
        };
        #[cfg(not(target_os = "linux"))]
        let ca_dir = tempfile::tempdir().context("cannot create temporary proxy CA directory")?;
        let ca_path = ca_dir.path().join("ca.pem");
        fs::write(&ca_path, &ca_pem).context("cannot write temporary proxy CA")?;
        fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o600))?;
        #[cfg(target_os = "linux")]
        if service_runner_uid.is_some() {
            fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o444))?;
        }

        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let mut cleanup = AbortTasksOnDrop(Vec::new());
        let mut proxy_task = tokio::spawn(async move {
            proxy
                .run(async {
                    let _ = stopped.await;
                })
                .await
        });
        cleanup.0.push(proxy_task.abort_handle());

        let selected_command = self.policy.command.clone();
        let (program, args) = selected_command.split_first().expect("validated command");
        #[cfg(target_os = "macos")]
        if self.policy.mac_service {
            // Explicit service mode has its own launch path. Its fixed endpoint
            // authenticates _avd and the exact installed broker signature.
            let mut relay = None;
            let expected_identity = self
                .mac_grant
                .as_ref()
                .context("installed macOS execution requires an authorized secret grant")?
                .installed
                .clone();
            let work = async {
                let (mut lease, mut bridge) = tokio::task::spawn_blocking(move || {
                    av_vmm::service::launch(&expected_identity)
                })
                .await
                .context("supervisor launch worker failed")?
                .context("cannot launch installed macOS runner")?;
                bridge.set_write_timeout(Some(Duration::from_secs(5)))?;
                av_vmm::write_task(
                    &mut bridge,
                    &av_vmm::TaskSpec {
                        args: args.to_vec(),
                        ca_pem,
                        timeout_secs: lifetime.as_secs().clamp(1, 120) as u32,
                    },
                )?;
                bridge.set_nonblocking(true)?;
                let stream = UnixStream::from_std(bridge)?;
                let relay_task =
                    tokio::spawn(async move { relay_connection(stream, proxy_addr, &token).await });
                cleanup.0.push(relay_task.abort_handle());
                relay = Some(relay_task);
                loop {
                    if let Some(code) = lease.try_wait().context("macOS supervisor task failed")? {
                        return Ok::<i32, anyhow::Error>(code);
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                // The lease is dropped on cancellation, timeout, or proxy exit.
            };
            let (event, proxy_exited) =
                crate::isolation::supervise_task(work, &mut shutdown, lifetime, &mut proxy_task)
                    .await;
            let outcome = event.into_result();
            if let Some(relay) = relay {
                relay.abort();
                let _ = relay.await;
            }
            let _ = stop.send(());
            if !proxy_exited {
                proxy_task.await.context("proxy task failed")??;
            }
            return outcome;
        }
        #[cfg(target_os = "linux")]
        let (mut command, mut relay) = if let Some(helper) = &self.policy.runner_helper {
            let socket_path = ca_dir.path().join("runner-proxy.sock");
            let listener = UnixListener::bind(&socket_path)
                .context("cannot bind broker-owned runner relay")?;
            fs::set_permissions(
                &socket_path,
                fs::Permissions::from_mode(if service_runner_uid.is_some() {
                    0o666
                } else {
                    0o600
                }),
            )?;
            let (relay_stop, relay_stopped) = tokio::sync::oneshot::channel();
            let relay_task = tokio::spawn(run_relay(
                listener,
                proxy_addr,
                token,
                service_runner_uid.unwrap_or_else(|| unsafe { libc::geteuid() }),
                relay_stopped,
            ));
            cleanup.0.push(relay_task.abort_handle());
            let mut spec = av_runner::RunSpec::new(program);
            spec.args.extend(args.iter().map(Into::into));
            spec.ca_file = Some(ca_path.clone());
            let selected_program_sha256 = self.program_sha256;
            spec.env = vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), "/tmp".into()),
                ("SSL_CERT_FILE".into(), "/run/ca.pem".into()),
                ("CURL_CA_BUNDLE".into(), "/run/ca.pem".into()),
                ("REQUESTS_CA_BUNDLE".into(), "/run/ca.pem".into()),
                ("GIT_SSL_CAINFO".into(), "/run/ca.pem".into()),
                ("NODE_EXTRA_CA_CERTS".into(), "/run/ca.pem".into()),
            ];
            spec.env
                .push(("AV_FIXTURE_TOKEN".into(), "av-placeholder".into()));
            ensure!(
                spec.env
                    .iter()
                    .all(|(_, value)| { !value.to_string_lossy().contains(self.secret.as_str()) }),
                "runner environment contains a credential"
            );
            let prepared = if service_runner_uid.is_some() {
                ensure!(
                    helper == Path::new(av_runner::service::HELPER),
                    "service requires installed runner helper"
                );
                av_runner::service::prepare_service_command(av_runner::service::LaunchRequest {
                    proxy_socket: socket_path,
                    program: PathBuf::from(program),
                    args: args.to_vec(),
                    env: spec
                        .env
                        .iter()
                        .map(|(key, value)| {
                            (
                                key.to_string_lossy().into_owned(),
                                value.to_string_lossy().into_owned(),
                            )
                        })
                        .collect(),
                    ca_file: spec.ca_file.clone(),
                    program_sha256: selected_program_sha256
                        .context("missing pinned program digest")?,
                    helper_sha256: self.helper_sha256.context("missing helper digest")?,
                    timeout_seconds: lifetime.as_secs().max(1),
                })
            } else {
                av_runner::prepare_verified_command(helper, &socket_path, &spec, self.helper_sha256)
            }
            .context("cannot prepare namespaced fixture command")?;
            (Command::from(prepared), Some((relay_stop, relay_task)))
        } else {
            (
                direct_command(program, args, &proxy_url, ca_dir.path(), &ca_path),
                None,
            )
        };
        #[cfg(target_os = "macos")]
        let (mut command, mut vmm_bridge) = if let Some(vmm) = &self.policy.mac_vmm {
            let (command, bridge) = av_vmm::prepare_command(
                vmm,
                self.policy
                    .mac_guest_bundle
                    .as_ref()
                    .expect("validated bundle"),
            )?;
            (Command::from(command), Some(bridge))
        } else {
            (
                direct_command(program, args, &proxy_url, ca_dir.path(), &ca_path),
                None,
            )
        };
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let mut command = direct_command(program, args, &proxy_url, ca_dir.path(), &ca_path);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = stop.send(());
                let _ = proxy_task.await;
                #[cfg(target_os = "linux")]
                if let Some((relay_stop, relay_task)) = relay.take() {
                    let _ = relay_stop.send(());
                    let _ = relay_task.await;
                }
                return Err(error).context("cannot start policy-pinned fixture command");
            }
        };
        drop(command);
        #[cfg(target_os = "macos")]
        let vmm_relay = if let Some(mut bridge) = vmm_bridge.take() {
            bridge.set_write_timeout(Some(Duration::from_secs(5)))?;
            av_vmm::write_task(
                &mut bridge,
                &av_vmm::TaskSpec {
                    args: args.to_vec(),
                    ca_pem,
                    timeout_secs: lifetime.as_secs().max(1).min(u32::MAX as u64) as u32,
                },
            )?;
            bridge.set_nonblocking(true)?;
            let stream = UnixStream::from_std(bridge)?;
            Some(tokio::spawn(async move {
                relay_connection(stream, proxy_addr, &token).await
            }))
        } else {
            None
        };
        #[cfg(target_os = "macos")]
        if let Some(relay) = &vmm_relay {
            cleanup.0.push(relay.abort_handle());
        }
        let child_group = child.id().and_then(|pid| i32::try_from(pid).ok());
        let (event, proxy_exited) = crate::isolation::supervise_task(
            async {
                child
                    .wait()
                    .await
                    .context("cannot wait for fixture command")
                    .map(|status| status.code().unwrap_or(1))
            },
            &mut shutdown,
            lifetime,
            &mut proxy_task,
        )
        .await;
        if !matches!(event, crate::isolation::TaskEvent::Exited(_)) {
            kill_process_group(child_group);
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        let outcome = event.into_result();
        let _ = stop.send(());
        if !proxy_exited {
            proxy_task.await.context("proxy task failed")??;
        }
        #[cfg(target_os = "linux")]
        if let Some((relay_stop, relay_task)) = relay {
            let _ = relay_stop.send(());
            relay_task.await.context("runner relay failed")??;
        }
        #[cfg(target_os = "macos")]
        if let Some(relay) = vmm_relay {
            relay.abort();
            let _ = relay.await;
        }
        outcome
    }
}

/// Abort detached transport tasks if preparation fails or this future is dropped.
struct AbortTasksOnDrop(Vec<tokio::task::AbortHandle>);

impl Drop for AbortTasksOnDrop {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

fn kill_process_group(group: Option<i32>) {
    if let Some(group) = group.filter(|group| *group > 0) {
        // The command is placed in its own group before spawn. ESRCH is fine:
        // the group may already have exited.
        unsafe { libc::kill(-group, libc::SIGKILL) };
    }
}

fn direct_command(
    program: &str,
    args: &[String],
    proxy_url: &str,
    home: &Path,
    ca_path: &Path,
) -> Command {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("HTTPS_PROXY", proxy_url)
        .env("https_proxy", proxy_url)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .env("SSL_CERT_FILE", ca_path)
        .env("CURL_CA_BUNDLE", ca_path)
        .env("REQUESTS_CA_BUNDLE", ca_path)
        .env("GIT_SSL_CAINFO", ca_path)
        .env("NODE_EXTRA_CA_CERTS", ca_path)
        .env("AV_FIXTURE_TOKEN", "av-placeholder");
    command
}

#[cfg(target_os = "linux")]
async fn run_relay(
    listener: UnixListener,
    proxy_addr: SocketAddr,
    token: String,
    runner_uid: u32,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    let mut connections = tokio::task::JoinSet::new();
    let permits = Arc::new(Semaphore::new(8));
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                return Ok(());
            }
            connection = listener.accept() => {
                let (stream, _) = connection?;
                if !stream.peer_cred().is_ok_and(|peer| peer.uid() == runner_uid) { continue; }
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else { continue; };
                let token = token.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(60),
                        relay_connection(stream, proxy_addr, &token),
                    ).await;
                });
            }
            joined = connections.join_next(), if !connections.is_empty() => { let _ = joined; }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn relay_connection(
    mut child: UnixStream,
    proxy_addr: SocketAddr,
    token: &str,
) -> std::io::Result<()> {
    // The helper's localhost proxy is unauthenticated. Only this host relay
    // owns the broker capability; a child-provided auth header is rejected.
    let header = tokio::time::timeout(Duration::from_secs(5), async {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() >= 16 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "CONNECT header too large",
                ));
            }
            let mut byte = [0_u8];
            child.read_exact(&mut byte).await?;
            header.push(byte[0]);
        }
        Ok::<_, std::io::Error>(header)
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "CONNECT header timed out"))??;
    let text = std::str::from_utf8(&header).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid CONNECT header")
    })?;
    if text.lines().skip(1).any(|line| {
        line.split_once(':')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("proxy-authorization"))
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "child proxy authorization is forbidden",
        ));
    }
    let mut upstream = TcpStream::connect(proxy_addr).await?;
    upstream.write_all(&header[..header.len() - 2]).await?;
    upstream
        .write_all(format!("Proxy-Authorization: Bearer {token}\r\n\r\n").as_bytes())
        .await?;
    tokio::io::copy_bidirectional(&mut child, &mut upstream).await?;
    Ok(())
}

fn interception_certificate(host: &str) -> Result<(Arc<ServerConfig>, String)> {
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "AV synthetic interception CA");
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let mut leaf_params = CertificateParams::new(vec![host.to_owned()])?;
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, host);
    let leaf_key = KeyPair::generate()?;
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer)?;
    let mut server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf_cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((Arc::new(server), ca_cert.pem()))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use av_core::{ApprovalRequirement, SecretGrant, SecretPolicy, create_vault};

    #[test]
    fn installed_ca_read_rejects_symlinks_writable_paths_and_non_files() {
        use std::os::unix::fs::symlink;

        // A home directory has trusted ancestors, unlike shared /tmp.
        let directory = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        let directory = directory.path().canonicalize().unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let parent = directory.join("certificates");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
        let ca = parent.join("ca.der");
        fs::write(&ca, b"public certificate bytes").unwrap();
        fs::set_permissions(&ca, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_linux_upstream_ca(&ca, true).unwrap(),
            b"public certificate bytes"
        );

        fs::set_permissions(&ca, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_linux_upstream_ca(&ca, true).is_err());
        fs::set_permissions(&ca, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(read_linux_upstream_ca(&ca, true).is_err());
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();

        let link = directory.join("linked-ca.der");
        symlink(&ca, &link).unwrap();
        assert!(read_linux_upstream_ca(&link, true).is_err());
        assert!(read_linux_upstream_ca(&link, false).is_err());
        let linked_parent = directory.join("linked-directory");
        symlink(&parent, &linked_parent).unwrap();
        assert!(read_linux_upstream_ca(&linked_parent.join("ca.der"), true).is_err());
        assert!(read_linux_upstream_ca(&parent, true).is_err());

        let fifo = directory.join("ca.fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_linux_upstream_ca(&fifo, true).is_err());
        assert!(read_linux_upstream_ca(&fifo, false).is_err());
        fs::write(&ca, []).unwrap();
        assert!(read_linux_upstream_ca(&ca, true).is_err());
        fs::write(&ca, vec![0; 16 * 1024 + 1]).unwrap();
        assert!(read_linux_upstream_ca(&ca, true).is_err());
    }

    #[test]
    #[ignore = "requires root to create a CA owned by an unrelated UID"]
    fn installed_ca_read_rejects_foreign_owner() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let directory = tempfile::tempdir_in("/root").unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let ca = directory.path().join("ca.der");
        fs::write(&ca, b"public certificate bytes").unwrap();
        fs::set_permissions(&ca, fs::Permissions::from_mode(0o644)).unwrap();
        let name = std::ffi::CString::new(ca.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(name.as_ptr(), 12345, 12345) }, 0);
        assert!(read_linux_upstream_ca(&ca, true).is_err());
    }

    #[test]
    fn policy_rejects_unexpected_provider_fields() {
        let parsed: Result<ProxyPolicy, _> = serde_json::from_value(serde_json::json!({
            "connection":"demo/work", "secret_name":"demo/token",
            "host":"api.example.test", "command":["/tmp/av-fixture","request"],
            "upstream_addr":"127.0.0.1:443", "upstream_ca_der":"/tmp/ca.der",
            "max_connects":1, "max_requests":1, "max_runtime_seconds":10,
            "provider_specific":true
        }));
        assert!(parsed.is_err());
    }

    #[tokio::test]
    async fn installed_proxy_requires_exact_secret_grant() {
        let directory = tempfile::tempdir().unwrap();
        let vault_path = directory.path().join("vault.db");
        let created = create_vault(&vault_path, "test passphrase").unwrap();
        created
            .vault
            .set("demo/fixture-token", "av-synthetic-provider-token")
            .unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap();
        let ca_path = directory.path().join("ca.der");
        fs::write(&ca_path, ca.der()).unwrap();
        let policy_path = directory.path().join("policy.json");
        let mut policy = serde_json::json!({
            "connection": "demo/fixture",
            "secret_name": "demo/fixture-token",
            "host": "api.example.test",
            "command": ["/bin/true"],
            "upstream_addr": "127.0.0.1:31337",
            "upstream_ca_der": ca_path,
            "max_connects": 1,
            "max_requests": 1,
            "max_runtime_seconds": 10
        });
        let write_policy = |value: &serde_json::Value| {
            fs::write(&policy_path, serde_json::to_vec(value).unwrap()).unwrap();
            fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600)).unwrap();
        };
        write_policy(&policy);
        assert!(ProxyRuntime::load_with_grant(&created.vault, &policy_path, true).is_err());

        let bytes = fs::read(&policy_path).unwrap();
        let parsed: ProxyPolicy = serde_json::from_slice(&bytes).unwrap();
        let request =
            crate::management::proxy_access_request(&parsed, &policy_path, &bytes, false).unwrap();
        assert_eq!(
            request.upstream_ca_sha256,
            Some(hex::encode(Sha256::digest(ca.der())))
        );
        let mut incomplete_request = request.clone();
        incomplete_request.upstream_ca_sha256 = None;
        created
            .vault
            .set_policy(
                "demo/fixture-token",
                &SecretPolicy {
                    grants: vec![SecretGrant {
                        request: incomplete_request,
                        approval: ApprovalRequirement::EveryRun,
                    }],
                },
            )
            .unwrap();
        assert!(ProxyRuntime::load_with_grant(&created.vault, &policy_path, true).is_err());
        created
            .vault
            .set_policy(
                "demo/fixture-token",
                &SecretPolicy {
                    grants: vec![SecretGrant {
                        request: request.clone(),
                        approval: ApprovalRequirement::EveryRun,
                    }],
                },
            )
            .unwrap();
        let runtime = ProxyRuntime::load_with_grant(&created.vault, &policy_path, true).unwrap();
        let replacement = CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap();
        fs::write(&ca_path, replacement.der()).unwrap();
        assert!(ProxyRuntime::load_with_grant(&created.vault, &policy_path, true).is_err());
        assert!(validate_linux_ca_binding(&request, replacement.der()).is_err());
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 30;
        let error = runtime
            .run(expires_at, tokio::sync::watch::channel(false).1)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("upstream CA changed"), "{error}");
        fs::write(&ca_path, ca.der()).unwrap();
        assert!(ProxyRuntime::load_with_grant(&created.vault, &policy_path, true).is_ok());
        let replacement_path = directory.path().join("replacement.der");
        fs::write(&replacement_path, ca.der()).unwrap();
        fs::remove_file(&ca_path).unwrap();
        std::os::unix::fs::symlink(&replacement_path, &ca_path).unwrap();
        assert!(
            crate::management::proxy_access_request(&parsed, &policy_path, &bytes, false).is_err()
        );
        assert!(ProxyRuntime::load_with_grant(&created.vault, &policy_path, true).is_err());
        fs::remove_file(&ca_path).unwrap();
        fs::write(&ca_path, ca.der()).unwrap();

        policy["max_requests"] = serde_json::json!(2);
        write_policy(&policy);
        assert!(ProxyRuntime::load_with_grant(&created.vault, &policy_path, true).is_err());
        write_policy(&serde_json::from_slice(&bytes).unwrap());
        created
            .vault
            .set_policy("demo/fixture-token", &SecretPolicy::default())
            .unwrap();
        assert!(ProxyRuntime::load_with_grant(&created.vault, &policy_path, true).is_err());
    }

    #[tokio::test]
    async fn relay_rejects_child_supplied_proxy_authorization() {
        let (mut child, relay) = UnixStream::pair().unwrap();
        let task = tokio::spawn(async move {
            relay_connection(relay, "127.0.0.1:1".parse().unwrap(), "broker-token").await
        });
        child
            .write_all(b"CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\n Proxy-Authorization: child-token\r\n\r\n")
            .await
            .unwrap();
        let error = task.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
