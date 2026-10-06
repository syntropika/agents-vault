//! Linux launch service. The broker and runner have distinct host identities.
//!
//! This protocol contains command metadata and public trust data only. Proxy
//! credentials and operator operations never enter the runner service.

use std::{
    fs,
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crate::{RunSpec, prepare_verified_command};
use serde::{Deserialize, Serialize};

pub const SOCKET: &str = "/run/agents-vault-runner/launch.sock";
pub const HELPER: &str = "/usr/libexec/agents-vault/av-runner-helper";
pub const CLIENT: &str = "/usr/libexec/agents-vault/av-runner-client";
const MAX_FRAME: usize = 65_536;
const MAX_TASKS: usize = 8;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRequest {
    pub proxy_socket: PathBuf,
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub ca_file: Option<PathBuf>,
    pub program_sha256: [u8; 32],
    pub helper_sha256: [u8; 32],
    pub timeout_seconds: u64,
}

impl LaunchRequest {
    fn validate(&self) -> io::Result<()> {
        if !self.proxy_socket.is_absolute()
            || !self.program.is_absolute()
            || self.args.len() > 32
            || self.env.len() > 32
            || self.args.iter().any(|value| value.len() > 4096)
            || self
                .env
                .iter()
                .any(|(key, value)| key.len() > 128 || value.len() > 4096)
            || !(1..=60).contains(&self.timeout_seconds)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid runner launch limits",
            ));
        }
        Ok(())
    }
}

/// Look up only the installed non-login service identities; there is no UID
/// parameter in the launch protocol that a peer can forge.
pub fn service_uid(name: &str) -> io::Result<u32> {
    let passwd = fs::read_to_string("/etc/passwd")?;
    for line in passwd.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() == 7
            && fields[0] == name
            && fields[5] == "/nonexistent"
            && matches!(
                fields[6],
                "/usr/sbin/nologin" | "/sbin/nologin" | "/bin/false"
            )
        {
            let uid: u32 = fields[2].parse().map_err(io::Error::other)?;
            if uid != 0 {
                return Ok(uid);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "missing non-login service identity",
    ))
}

pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut size,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::other("invalid peer credentials"));
    }
    Ok(unsafe { credentials.assume_init() }.uid)
}

/// The client runs under the broker UID, holds the launch channel open, and
/// exits with the remote task status. Killing it cancels the remote task.
pub fn prepare_service_command(request: LaunchRequest) -> io::Result<Command> {
    request.validate()?;
    let broker_uid = service_uid("av-broker")?;
    let runner_uid = service_uid("av-runner")?;
    if unsafe { libc::geteuid() } != broker_uid || broker_uid == runner_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runner launch requires distinct broker and runner identities",
        ));
    }
    validate_root_owned_file(Path::new(CLIENT))?;
    let client = crate::sealed_executable(Path::new(CLIENT), None)?;
    let client_fd = client.as_raw_fd();
    let mut command = Command::new(format!("/proc/self/fd/{client_fd}"));
    command
        .env_clear()
        .arg(serde_json::to_string(&request)?)
        .current_dir("/");
    let parent = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                libc::_exit(125);
            }
            let _keep_alive = &client;
            if libc::fcntl(client_fd, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(command)
}

pub fn client_main() -> io::Result<i32> {
    let request = std::env::args()
        .nth(1)
        .ok_or_else(|| io::Error::other("missing launch request"))?;
    if request.len() > MAX_FRAME {
        return Err(io::Error::other("runner request too large"));
    }
    let request: LaunchRequest = serde_json::from_str(&request)?;
    request.validate()?;
    if unsafe { libc::geteuid() } != service_uid("av-broker")? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "client requires broker identity",
        ));
    }
    let mut stream = UnixStream::connect(SOCKET)?;
    if peer_uid(&stream)? != service_uid("av-runner")? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wrong runner service peer",
        ));
    }
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.set_read_timeout(Some(Duration::from_secs(request.timeout_seconds + 10)))?;
    write_frame(&mut stream, &serde_json::to_vec(&request)?)?;
    let status: i32 = serde_json::from_slice(&read_frame(&mut stream)?)?;
    Ok(status.clamp(0, 255))
}

fn validate_root_owned_file(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(io::Error::other("trusted file must be absolute"));
    }
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "runner executable must be installed under root-owned paths",
            ));
        }
    }
    Ok(())
}

pub fn server_main() -> io::Result<()> {
    let runner_uid = service_uid("av-runner")?;
    let broker_uid = service_uid("av-broker")?;
    if unsafe { libc::geteuid() } != runner_uid || runner_uid == broker_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runner requires its distinct non-login service identity",
        ));
    }
    validate_root_owned_file(Path::new(HELPER))?;
    let directory = Path::new(SOCKET).parent().unwrap();
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != runner_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted runner runtime directory",
        ));
    }
    // A private advisory lock prevents live socket replacement. After a crash
    // the next instance can remove its stale socket while holding that lock.
    use std::os::unix::fs::OpenOptionsExt;
    let lock = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join("service.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if Path::new(SOCKET).symlink_metadata().is_ok() {
        fs::remove_file(SOCKET)?;
    }
    namespace_preflight(directory)?;
    let listener = UnixListener::bind(SOCKET)?;
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o666))?;
    if let Some(address) = std::env::var_os("NOTIFY_SOCKET") {
        use std::os::{
            linux::net::SocketAddrExt,
            unix::{
                ffi::OsStrExt,
                net::{SocketAddr, UnixDatagram},
            },
        };
        let address = address.as_os_str().as_bytes();
        let address = if address.first() == Some(&b'@') {
            SocketAddr::from_abstract_name(&address[1..])?
        } else {
            SocketAddr::from_pathname(Path::new(std::ffi::OsStr::from_bytes(address)))?
        };
        UnixDatagram::unbound()?.send_to_addr(b"READY=1", &address)?;
    }
    let active = Arc::new(AtomicUsize::new(0));
    for connection in listener.incoming() {
        let stream = connection?;
        if peer_uid(&stream)? != broker_uid {
            continue;
        }
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_TASKS {
            active.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let active = Arc::clone(&active);
        thread::spawn(move || {
            let result = serve_launch(stream, broker_uid);
            if let Err(error) = result {
                eprintln!("av-runner-service: launch failed: {error}");
            }
            active.fetch_sub(1, Ordering::AcqRel);
        });
    }
    Ok(())
}

/// Exercise the installed namespace helper before accepting any launch. This
/// reports restrictive kernel, AppArmor, seccomp, or mount policy explicitly.
fn namespace_preflight(directory: &Path) -> io::Result<()> {
    let socket = directory.join("preflight.sock");
    if socket.symlink_metadata().is_ok() {
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    let spec = RunSpec::new("/usr/bin/true");
    let mut command = prepare_verified_command(Path::new(HELPER), &socket, &spec, None)?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    drop(command);
    let deadline = Instant::now() + Duration::from_secs(5);
    let result = loop {
        if let Some(status) = child.try_wait()? {
            let output = child.wait_with_output()?;
            break if status.success() {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "namespace preflight failed; check user namespaces, scoped AppArmor permission, seccomp and proc mounts: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    ),
                ))
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "namespace preflight timed out",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };
    drop(listener);
    let _ = fs::remove_file(socket);
    result
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(io::Error::other("invalid runner frame size"));
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)
}

fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(io::Error::other("invalid runner frame size"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn serve_launch(mut stream: UnixStream, broker_uid: u32) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request: LaunchRequest = serde_json::from_slice(&read_frame(&mut stream)?)?;
    request.validate()?;
    let relay = fs::symlink_metadata(&request.proxy_socket)?;
    use std::os::unix::fs::FileTypeExt;
    if !relay.file_type().is_socket() || relay.uid() != broker_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "relay must belong to broker",
        ));
    }
    let mut spec = RunSpec::new(request.program);
    spec.args = request.args.into_iter().map(Into::into).collect();
    spec.env = request
        .env
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect();
    spec.ca_file = request.ca_file;
    spec.expected_sha256 = Some(request.program_sha256);
    let mut command = prepare_verified_command(
        Path::new(HELPER),
        &request.proxy_socket,
        &spec,
        Some(request.helper_sha256),
    )?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let parent = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                libc::_exit(125);
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    drop(command);
    let deadline = Instant::now() + Duration::from_secs(request.timeout_seconds);
    // Poll readiness instead of blocking on client input. Every exit path
    // below kills/reaps the outer helper, which owns namespace PID 1.
    let result = (|| -> io::Result<Option<i32>> {
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(Some(status.code().unwrap_or(125)));
            }
            if Instant::now() >= deadline {
                return Ok(Some(124));
            }
            let mut descriptor = libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            };
            if unsafe { libc::poll(&mut descriptor, 1, 20) } < 0 {
                return Err(io::Error::last_os_error());
            }
            if descriptor.revents != 0 {
                return Ok(None);
            }
        }
    })();
    // Kill the whole helper process group too. Detached descendants are
    // terminated by the PID namespace supervisor's parent-death signal.
    if child.try_wait()?.is_none() {
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    if let Some(status) = result? {
        write_frame(&mut stream, &serde_json::to_vec(&status)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_identity_comes_from_kernel() {
        let (left, _right) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&left).unwrap(), unsafe { libc::geteuid() });
    }

    #[test]
    fn frame_limit_precedes_allocation() {
        let (mut left, mut right) = UnixStream::pair().unwrap();
        left.write_all(&u32::MAX.to_be_bytes()).unwrap();
        assert!(read_frame(&mut right).is_err());
    }
}
