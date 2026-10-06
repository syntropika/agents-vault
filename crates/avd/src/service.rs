//! Deployment checks for the synthetic Linux system service.

use std::{fs, io, os::unix::fs::MetadataExt, path::Path};

/// A distinct identity is necessary but not sufficient for protected custody.
/// This mode deliberately retains the synthetic credential restriction.
pub fn validate_service_identity(agent_uid: u32) -> io::Result<()> {
    let broker_uid = unsafe { libc::geteuid() };
    if broker_uid == 0 || agent_uid == 0 || broker_uid == agent_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "service broker and agent must have distinct non-root UIDs",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        let runner_uid = av_runner::service::service_uid("av-runner")?;
        if runner_uid == broker_uid || runner_uid == agent_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "service runner, broker, and agent must have distinct non-root UIDs",
            ));
        }
    }
    let passwd = fs::read_to_string("/etc/passwd")?;
    let service_identity = passwd.lines().any(|line| {
        let fields: Vec<_> = line.split(':').collect();
        fields.len() == 7
            && fields[0] == "av-broker"
            && fields[2].parse::<u32>().ok() == Some(broker_uid)
            && matches!(
                fields[6],
                "/usr/sbin/nologin" | "/sbin/nologin" | "/bin/false"
            )
    });
    if !service_identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "service mode requires the non-login av-broker system identity",
        ));
    }
    Ok(())
}

/// Reject symlinks and agent-writable ancestors before trusting deployment data.
pub fn validate_trusted_path(path: &Path, private: bool) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "trusted path must be absolute without parent traversal",
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
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("untrusted service path: {}", ancestor.display()),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_rejects_same_identity_and_root_agent() {
        assert!(validate_service_identity(unsafe { libc::geteuid() }).is_err());
        assert!(validate_service_identity(0).is_err());
    }

    #[test]
    fn service_rejects_world_writable_ancestors() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("policy.json");
        fs::write(&file, "{}").unwrap();
        assert!(validate_trusted_path(&file, false).is_err());
    }
}
