//! Installed broker identity, private state, and restart lifetime guard.

use super::{check_no_acl, denied, service_identity};
use std::{
    fs, io,
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path},
};

pub const BROKER_RUNTIME: &str = "/private/var/db/agents-vault/broker/runtime";
pub const BROKER_VAULT: &str = "/private/var/db/agents-vault/broker/vault.db";
pub const BROKER_POLICY: &str = "/private/var/db/agents-vault/broker/proxy-policy.json";
pub const AGENT_SOCKET: &str = "/private/var/db/agents-vault/agent/agent.sock";

pub fn validate_broker_identity() -> io::Result<()> {
    let identity = service_identity(c"_avd")?;
    if unsafe { libc::getuid() } != identity.uid
        || unsafe { libc::geteuid() } != identity.uid
        || unsafe { libc::getgid() } != identity.gid
        || unsafe { libc::getegid() } != identity.gid
    {
        return Err(denied(
            "service launch requires the installed broker identity",
        ));
    }
    Ok(())
}

pub fn validate_agent_uid(uid: u32) -> io::Result<()> {
    let broker = service_identity(c"_avd")?;
    let runner = service_identity(c"_avrunner")?;
    if uid < 500 || uid == broker.uid || uid == runner.uid {
        return Err(denied("agent must be a distinct login identity"));
    }
    let mut record = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_i8; 16384];
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut record,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(denied("agent login identity does not exist"));
    }
    let shell = unsafe { std::ffi::CStr::from_ptr(record.pw_shell) }.to_bytes();
    if shell.is_empty() || shell.ends_with(b"/false") || shell.ends_with(b"/nologin") {
        return Err(denied("agent identity must have a login shell"));
    }
    Ok(())
}

pub fn validate_broker_path(path: &Path, private: bool) -> io::Result<()> {
    validate_broker_identity()?;
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(denied(
            "broker path must be absolute without parent traversal",
        ));
    }
    let broker_uid = unsafe { libc::geteuid() };
    for (index, ancestor) in path.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink()
            || ![0, broker_uid].contains(&metadata.uid())
            || metadata.mode() & 0o022 != 0
            || (index == 0 && private && metadata.mode() & 0o077 != 0)
        {
            return Err(denied("untrusted broker path ownership or permissions"));
        }
        check_no_acl(ancestor)?;
    }
    Ok(())
}

/// Hold this guard until the broker exits. A second process cannot delete a
/// live broker's endpoints, and a restart can remove only known stale entries.
pub struct BrokerRuntimeLock {
    _file: fs::File,
}

pub fn prepare_broker_runtime() -> io::Result<BrokerRuntimeLock> {
    validate_broker_path(Path::new(BROKER_RUNTIME), true)?;
    validate_broker_path(Path::new(AGENT_SOCKET).parent().unwrap(), false)?;
    let lock = Path::new(BROKER_RUNTIME).join("broker.lock");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(denied("invalid broker runtime lock"));
    }
    check_no_acl(&lock)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(denied("another broker already owns the runtime"));
    }
    for (path, socket) in stale_runtime_entries() {
        remove_stale_runtime_entry(&path, socket)?;
    }
    Ok(BrokerRuntimeLock { _file: file })
}

fn remove_stale_runtime_entry(path: &Path, socket: bool) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.uid() != unsafe { libc::geteuid() }
                || if socket {
                    !metadata.file_type().is_socket()
                } else {
                    !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0
                }
            {
                return Err(denied("refusing unexpected broker runtime entry"));
            }
            fs::remove_file(path)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    Ok(())
}

fn stale_runtime_entries() -> [(std::path::PathBuf, bool); 4] {
    [
        (Path::new(AGENT_SOCKET).to_path_buf(), true),
        (Path::new(AGENT_SOCKET).with_file_name("client.sock"), true),
        (Path::new(BROKER_RUNTIME).join("admin.sock"), true),
        (Path::new(BROKER_RUNTIME).join("admin.token"), false),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_tracks_active_endpoints_and_private_token() {
        let entries = stale_runtime_entries();
        assert_eq!(entries.len(), 4);
        assert!(entries.contains(&(Path::new(AGENT_SOCKET).with_file_name("client.sock"), true)));
        assert!(entries.contains(&(Path::new(BROKER_RUNTIME).join("admin.token"), false)));
    }

    #[test]
    fn restart_removes_expected_entries_and_refuses_symlinks() {
        use std::os::unix::{fs::PermissionsExt, net::UnixListener};

        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("admin.sock");
        let token = directory.path().join("admin.token");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::write(&token, b"synthetic token").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        remove_stale_runtime_entry(&socket, true).unwrap();
        remove_stale_runtime_entry(&token, false).unwrap();
        assert!(!socket.exists());
        assert!(!token.exists());
        drop(listener);

        let outside = directory.path().join("outside");
        fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, &socket).unwrap();
        assert!(remove_stale_runtime_entry(&socket, true).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"keep");
    }
}
