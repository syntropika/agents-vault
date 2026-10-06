//! Linux network-isolated command launcher.
//!
//! This crate is an experimental building block. A new user and network
//! namespace with only loopback blocks direct IP egress through new sockets
//! from the launched command. A private PID namespace ties the CLI and its
//! descendants to the helper's lifetime. A local TCP listener forwards to a
//! Unix socket on the host.
//! The caller must arrange the host-side forwarding and authorization.
//!
//! A private mount tree hides host files and sockets from the CLI. Executables
//! are copied to sealed memory files before launch. Local library callers map
//! the CLI to their own host UID. Installed service mode uses a separate
//! non-login runner identity and kernel-authenticated launch/relay IPC. Trusted
//! policy and control of every agent tool remain required for protected custody.

#[cfg(target_os = "linux")]
pub mod service;

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug)]
pub struct RunSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// Explicit environment to pass to the CLI. The inherited environment is cleared.
    /// Do not place raw secrets here.
    pub env: Vec<(OsString, OsString)>,
    /// Only `/tmp` is available as a writable working directory in the sandbox.
    pub current_dir: Option<PathBuf>,
    /// Public TLS trust bundle exposed at `/run/ca.pem` in the sandbox.
    pub ca_file: Option<PathBuf>,
    /// Expected digest from trusted broker policy; checked before sealing.
    pub expected_sha256: Option<[u8; 32]>,
}

impl RunSpec {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            current_dir: None,
            ca_file: None,
            expected_sha256: None,
        }
    }
}

/// Prepare the bundled helper process; callers choose stdio and process lifetime.
///
/// A successful `Command::spawn` only means that the helper started. Namespace
/// setup errors are reported by its nonzero exit status. Killing the helper
/// also kills its private PID namespace process tree. The host Unix socket
/// must accept raw proxy connections and connect them to an authorized proxy.
pub fn prepare_command(
    helper_path: &Path,
    proxy_socket: &Path,
    spec: &RunSpec,
) -> io::Result<Command> {
    prepare_verified_command(helper_path, proxy_socket, spec, None)
}

/// Also verify the helper against a digest captured from trusted policy.
pub fn prepare_verified_command(
    helper_path: &Path,
    proxy_socket: &Path,
    spec: &RunSpec,
    helper_sha256: Option<[u8; 32]>,
) -> io::Result<Command> {
    if !helper_path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "helper must be an absolute path",
        ));
    }
    if !spec.program.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "program must be an absolute path",
        ));
    }
    if !proxy_socket.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "proxy socket must be an absolute path",
        ));
    }
    if spec
        .env
        .iter()
        .any(|(key, _)| reserved_environment_key(key))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "proxy environment is owned by the runner",
        ));
    }
    if spec.env.iter().any(|(key, _)| {
        let key = key.to_string_lossy();
        key.is_empty() || key.contains('=') || key.contains('\0')
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid environment variable name",
        ));
    }

    if spec
        .current_dir
        .as_deref()
        .is_some_and(|dir| dir != Path::new("/tmp"))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sandbox working directory must be /tmp",
        ));
    }
    #[cfg(not(target_os = "linux"))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "runner requires Linux",
    ));
    #[cfg(target_os = "linux")]
    let mut command = {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        let helper = sealed_executable(helper_path, helper_sha256)?;
        let program = sealed_executable(&spec.program, spec.expected_sha256)?;
        let helper_fd = helper.as_raw_fd();
        let program_fd = program.as_raw_fd();
        let mut command = Command::new(format!("/proc/self/fd/{helper_fd}"));
        command
            .env_clear()
            .arg("run")
            .arg(proxy_socket)
            .arg("--helper-fd")
            .arg(helper_fd.to_string())
            .arg("--program-fd")
            .arg(program_fd.to_string());
        if let Some(ca_file) = &spec.ca_file {
            command.arg("--ca").arg(ca_file);
        }
        for (key, value) in &spec.env {
            command.arg("--env").arg(key).arg(value);
        }
        command.arg("--").arg(&spec.program).args(&spec.args);
        // Capturing the files keeps them alive until spawn. Only these sealed
        // descriptors survive exec; the helper closes inherited descriptors.
        unsafe {
            command.pre_exec(move || {
                let _keep_alive = (&helper, &program);
                for fd in [helper_fd, program_fd] {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        command
    };
    #[cfg(target_os = "linux")]
    {
        command.current_dir("/");
        Ok(command)
    }
}

fn reserved_environment_key(key: &OsStr) -> bool {
    let key = key.to_string_lossy().to_ascii_uppercase();
    matches!(
        key.as_str(),
        "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY"
    )
}

/// Hash the file contents that trusted startup intends to permit.
pub fn executable_sha256(path: &Path) -> io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let contents = std::fs::read(path)?;
    Ok(Sha256::digest(contents).into())
}

#[cfg(target_os = "linux")]
fn sealed_executable(path: &Path, expected: Option<[u8; 32]>) -> io::Result<std::fs::File> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;
    let mut source = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !source.metadata()?.is_file() || source.metadata()?.len() > 128 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "executable must be a regular file of at most 128 MiB",
        ));
    }
    let mut contents = Vec::new();
    (&mut source)
        .take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut contents)?;
    if contents.len() > 128 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "executable exceeds 128 MiB",
        ));
    }
    if !contents.starts_with(b"\x7fELF") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sandbox executable must be ELF",
        ));
    }
    let actual: [u8; 32] = Sha256::digest(&contents).into();
    if expected.is_some_and(|expected| expected != actual) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executable SHA-256 does not match trusted policy",
        ));
    }
    let fd = unsafe {
        libc::memfd_create(
            c"av-executable".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut snapshot = unsafe { std::fs::File::from_raw_fd(fd) };
    snapshot.write_all(&contents)?;
    snapshot.rewind()?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(snapshot.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_proxy_environment_override() {
        let mut spec = RunSpec::new("/bin/true");
        spec.env.push(("https_proxy".into(), "http://other".into()));
        assert!(prepare_command(Path::new("/bin/true"), Path::new("/tmp/proxy"), &spec).is_err());
    }

    #[test]
    fn rejects_relative_paths() {
        let spec = RunSpec::new("sh");
        assert!(prepare_command(Path::new("/bin/true"), Path::new("/tmp/proxy"), &spec).is_err());
    }
}
