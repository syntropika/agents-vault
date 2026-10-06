//! One-time installed-vault initialization with recovery output held by root.
//!
//! Root opens an exclusive recovery file, then permanently becomes the broker
//! before prompting or creating encryption keys. Recovery never resides in the
//! broker-accessible state; only a write descriptor is retained.

use anyhow::{Context, Result, ensure};
use std::{
    ffi::CStr,
    fs,
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};

use super::{installed_runtime, validate_operator_identity};

pub struct ServiceStateGuard {
    vault: PathBuf,
    _file: fs::File,
}

pub struct Bootstrap {
    vault: PathBuf,
    recovery_path: PathBuf,
    recovery: fs::File,
    _guard: ServiceStateGuard,
}

/// Resolve this path independently of caller-controlled environment variables.
fn installed_vault() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let configuration =
            super::read_root_configuration(Path::new("/etc/agents-vault/service.env"))?;
        Ok(super::parse_service_paths(&configuration)?.0)
    }
    #[cfg(target_os = "macos")]
    {
        Ok(PathBuf::from(av_vmm::service::BROKER_VAULT))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("installed service initialization is unavailable on this platform")
    }
}

/// avd holds this for its entire service lifetime; init holds the same lock
/// until the root-owned recovery output and complete vault are durable.
pub fn hold_service_state() -> Result<ServiceStateGuard> {
    validate_operator_identity()?;
    let vault = installed_vault()?;
    validate_state_parent(&vault, unsafe { libc::geteuid() })?;
    let guard = acquire_state_guard(&vault)?;
    validate_complete(&vault)?;
    Ok(guard)
}

fn acquire_state_guard(vault: &Path) -> Result<ServiceStateGuard> {
    let path = vault
        .parent()
        .context("vault requires a parent directory")?
        .join("broker-state.lock");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.nlink() == 1,
        "unsafe service state lock"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "broker or another initialization process already owns the service state"
    );
    Ok(ServiceStateGuard {
        vault: vault.to_path_buf(),
        _file: file,
    })
}

fn pending_path(vault: &Path) -> PathBuf {
    vault.with_extension("init.pending")
}

/// A partial bootstrap must never be silently converted into a usable service.
pub fn validate_complete(vault: &Path) -> Result<()> {
    match fs::symlink_metadata(pending_path(vault)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => anyhow::bail!(
            "vault initialization is incomplete; keep the service stopped and inspect the pending state"
        ),
    }
}

fn validate_state_parent(vault: &Path, broker_uid: u32) -> Result<()> {
    ensure!(
        vault.is_absolute()
            && !vault
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir)),
        "installed vault path must be absolute without traversal"
    );
    let directory = vault
        .parent()
        .context("vault requires a parent directory")?;
    let metadata = fs::symlink_metadata(directory)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == broker_uid && metadata.mode() & 0o077 == 0,
        "installed vault directory must be private and owned by the broker"
    );
    for ancestor in directory.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        ensure!(
            !metadata.file_type().is_symlink()
                && [0, broker_uid].contains(&metadata.uid())
                && metadata.mode() & 0o022 == 0,
            "untrusted installed vault ancestor"
        );
    }
    #[cfg(target_os = "macos")]
    if unsafe { libc::geteuid() } == broker_uid {
        av_vmm::service::validate_broker_path(directory, true)?;
    }
    Ok(())
}

fn reject_prior_state(vault: &Path) -> Result<()> {
    let directory = vault
        .parent()
        .context("vault requires a parent directory")?;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .context("unexpected non-UTF-8 service state entry")?;
        ensure!(
            entry.path() != vault
                && entry.path() != pending_path(vault)
                && !name.starts_with("av-generation-")
                && !name.ends_with(".db")
                && !name.ends_with(".keys.json")
                && !name.ends_with(".keys.new")
                && !name.ends_with(".access.lock")
                && !name.ends_with(".recovery"),
            "vault or prior initialization artifacts already exist; initialization never overwrites state"
        );
    }
    let runtime = installed_runtime();
    match fs::symlink_metadata(&runtime) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
        Ok(metadata) => {
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "invalid installed runtime directory"
            );
            ensure!(
                fs::read_dir(&runtime)?.next().is_none(),
                "service runtime contains prior state; stop the service and inspect it before initialization"
            );
        }
    }
    #[cfg(target_os = "macos")]
    match fs::symlink_metadata(av_vmm::service::AGENT_SOCKET) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
        Ok(_) => {
            anyhow::bail!("agent endpoint already exists; stop the service and inspect its state")
        }
    }
    Ok(())
}

fn validate_recovery_parent(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path.file_name().is_some()
            && !path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir)),
        "recovery path must be absolute without traversal"
    );
    let parent = path
        .parent()
        .context("recovery file requires a parent directory")?;
    for (index, ancestor) in parent.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(ancestor)?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0
                && (index != 0 || metadata.mode() & 0o077 == 0),
            "recovery output requires a private root-owned parent and trusted root-owned ancestors"
        );
    }
    #[cfg(target_os = "macos")]
    av_vmm::service::validate_root_owned_path(parent)?;
    Ok(())
}

fn broker_identity() -> Result<(libc::uid_t, libc::gid_t)> {
    #[cfg(target_os = "macos")]
    let name = c"_avd";
    #[cfg(not(target_os = "macos"))]
    let name = c"av-broker";
    let mut record = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_i8; 16384];
    let status = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut record,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    ensure!(
        status == 0 && !result.is_null() && !record.pw_shell.is_null(),
        "installed broker identity is missing"
    );
    let shell = unsafe { CStr::from_ptr(record.pw_shell) }.to_bytes();
    ensure!(
        record.pw_uid != 0
            && record.pw_gid != 0
            && matches!(
                shell,
                b"/usr/sbin/nologin" | b"/sbin/nologin" | b"/bin/false" | b"/usr/bin/false"
            ),
        "installed broker must be a non-root non-login identity"
    );
    Ok((record.pw_uid, record.pw_gid))
}

fn become_broker(uid: libc::uid_t, gid: libc::gid_t) -> Result<()> {
    let core_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core_limit) } == 0,
        "cannot disable core dumps"
    );
    ensure!(
        unsafe { libc::setgroups(0, std::ptr::null()) } == 0,
        "cannot discard supplementary groups"
    );
    #[cfg(target_os = "linux")]
    {
        ensure!(
            unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) } == 0,
            "cannot discard retained capabilities"
        );
        ensure!(
            unsafe { libc::setresgid(gid, gid, gid) } == 0,
            "cannot permanently adopt broker group"
        );
        ensure!(
            unsafe { libc::setresuid(uid, uid, uid) } == 0,
            "cannot permanently adopt broker identity"
        );
        ensure!(
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
            "cannot protect bootstrap memory"
        );
        ensure!(
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0,
            "cannot restrict privilege acquisition"
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        ensure!(
            unsafe { libc::setgid(gid) } == 0,
            "cannot adopt broker group"
        );
        ensure!(
            unsafe { libc::setuid(uid) } == 0,
            "cannot permanently adopt broker identity"
        );
    }
    ensure!(
        unsafe { libc::getuid() } == uid
            && unsafe { libc::geteuid() } == uid
            && unsafe { libc::getgid() } == gid
            && unsafe { libc::getegid() } == gid
            && unsafe { libc::getgroups(0, std::ptr::null_mut()) } == 0,
        "broker credential transition is incomplete"
    );
    ensure!(
        unsafe { libc::setuid(0) } != 0 && unsafe { libc::geteuid() } == uid,
        "root credentials were not permanently discarded"
    );
    validate_operator_identity()
}

impl Bootstrap {
    /// Call only from the synchronous CLI entry point, before a Tokio runtime
    /// or any worker threads exist. No passphrase or key is read while root.
    pub fn prepare(recovery_path: &Path) -> Result<Self> {
        ensure!(
            unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0,
            "init requires sudo so recovery output can remain private to root"
        );
        let (uid, gid) = broker_identity()?;
        let vault = installed_vault()?;
        validate_state_parent(&vault, uid)?;
        reject_prior_state(&vault)?;
        validate_recovery_parent(recovery_path)?;
        let recovery = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(recovery_path)
            .context("cannot create new root-private recovery output")?;
        let metadata = recovery.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.mode() & 0o777 == 0o600
                && metadata.nlink() == 1
                && metadata.len() == 0,
            "unsafe recovery output file"
        );
        #[cfg(target_os = "macos")]
        av_vmm::service::validate_root_owned_path(recovery_path)?;
        recovery.sync_all()?;
        fs::File::open(recovery_path.parent().unwrap())?.sync_all()?;
        become_broker(uid, gid)?;
        let guard = hold_service_state()?;
        ensure!(
            guard.vault == vault,
            "installed vault configuration changed during initialization"
        );
        reject_prior_state(&vault)?;
        Ok(Self {
            vault,
            recovery_path: recovery_path.to_owned(),
            recovery,
            _guard: guard,
        })
    }

    pub fn finish(mut self, passphrase: &str) -> Result<serde_json::Value> {
        ensure!(
            installed_vault()? == self.vault,
            "installed vault configuration changed during initialization"
        );
        validate_operator_identity()?;
        reject_prior_state(&self.vault)?;
        let metadata = self.recovery.metadata()?;
        ensure!(
            metadata.uid() == 0
                && metadata.nlink() == 1
                && metadata.len() == 0
                && metadata.mode() & 0o777 == 0o600,
            "recovery output changed during initialization"
        );
        initialize_files(&self.vault, passphrase, |key| {
            self.recovery.write_all(key.as_bytes())?;
            self.recovery.sync_all()?;
            let metadata = self.recovery.metadata()?;
            ensure!(
                metadata.uid() == 0
                    && metadata.nlink() == 1
                    && metadata.len() == 64
                    && metadata.mode() & 0o777 == 0o600,
                "recovery output changed before publication completed"
            );
            Ok(())
        })?;
        Ok(
            serde_json::json!({"initialized": true, "vault": self.vault, "recovery_file": self.recovery_path, "locked": true}),
        )
    }
}

fn initialize_files(
    vault: &Path,
    passphrase: &str,
    save_recovery: impl FnOnce(&str) -> Result<()>,
) -> Result<()> {
    ensure!(
        !passphrase.is_empty() && passphrase.len() <= 4096,
        "invalid passphrase length"
    );
    let parent = vault
        .parent()
        .context("vault requires a parent directory")?;
    let pending = pending_path(vault);
    let mut marker = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pending)?;
    marker.write_all(b"format=1\n")?;
    marker.sync_all()?;
    fs::File::open(parent)?.sync_all()?;
    let created = av_core::create_vault(vault, passphrase)?;
    drop(created.vault);
    fs::File::open(vault)?.sync_all()?;
    fs::File::open(vault.with_extension("keys.json"))?.sync_all()?;
    save_recovery(&created.recovery_key)?;
    fs::remove_file(&pending)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn recovery_write_failure_keeps_published_vault_unusable_by_service() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let vault = directory.path().join("vault.db");
        let result = initialize_files(&vault, "synthetic bootstrap passphrase", |_| {
            anyhow::bail!("synthetic recovery output failure")
        });
        assert!(result.is_err());
        assert!(vault.exists() && vault.with_extension("keys.json").exists());
        assert!(validate_complete(&vault).is_err());
        assert!(initialize_files(&vault, "other passphrase", |_| Ok(())).is_err());
        assert!(av_core::Vault::open(&vault, "synthetic bootstrap passphrase").is_ok());
    }

    #[test]
    fn state_guard_excludes_service_and_second_initializer() {
        let directory = tempfile::tempdir().unwrap();
        let vault = directory.path().join("vault.db");
        let first = acquire_state_guard(&vault).unwrap();
        assert!(acquire_state_guard(&vault).is_err());
        drop(first);
        assert!(acquire_state_guard(&vault).is_ok());
    }

    #[test]
    fn successful_bootstrap_publishes_recovery_before_clearing_pending_marker() {
        let directory = tempfile::tempdir().unwrap();
        let vault = directory.path().join("vault.db");
        let mut recovery = zeroize::Zeroizing::new(String::new());
        initialize_files(&vault, "synthetic bootstrap passphrase", |key| {
            assert!(validate_complete(&vault).is_err());
            assert!(vault.exists() && vault.with_extension("keys.json").exists());
            recovery.push_str(key);
            Ok(())
        })
        .unwrap();
        validate_complete(&vault).unwrap();
        assert!(
            av_core::Vault::open(&vault, "synthetic bootstrap passphrase")
                .unwrap()
                .list()
                .unwrap()
                .is_empty()
        );
        av_core::recover_vault(
            &vault,
            &recovery,
            "synthetic recovered",
            directory.path().join("next.recovery"),
        )
        .unwrap();
        assert!(av_core::Vault::open(&vault, "synthetic recovered").is_ok());
    }
}
