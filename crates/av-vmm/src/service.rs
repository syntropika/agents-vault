//! Fixed-path, authenticated macOS service launcher. Installation, service
//! execution, Developer ID signing, and notarization still require validation.
//!
//! The broker transfers one private socket endpoint with SCM_RIGHTS. The
//! supervisor authenticates the connection's audit token, never a claimed PID.
//! Keeping the returned lease alive keeps the runner alive; dropping it cancels.

mod broker;
mod identity;
mod signing;
pub use broker::{
    AGENT_SOCKET, BROKER_POLICY, BROKER_RUNTIME, BROKER_VAULT, BrokerRuntimeLock,
    prepare_broker_runtime, validate_agent_uid, validate_broker_identity, validate_broker_path,
};
pub use identity::{ServiceIdentity, installed_identity};

use serde::Deserialize;
use std::{
    ffi::CStr,
    fs,
    io::{self, Read, Write},
    mem,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{fs::MetadataExt, net::UnixStream, process::CommandExt},
    },
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

const APP: &str = "/Library/PrivilegedHelperTools/AgentsVault.app";
const BROKER: &str = "/Library/PrivilegedHelperTools/AgentsVault.app/Contents/MacOS/avd";
const SUPERVISOR: &str =
    "/Library/PrivilegedHelperTools/AgentsVault.app/Contents/MacOS/av-supervisor";
const VMM: &str = "/Library/PrivilegedHelperTools/AgentsVault.app/Contents/MacOS/av-vmm";
const BUNDLE: &str = "/Library/PrivilegedHelperTools/AgentsVault.app/Contents/Resources/guest";
const POLICY: &str =
    "/Library/PrivilegedHelperTools/AgentsVault.app/Contents/Resources/service.json";
pub const SOCKET: &str = "/private/var/db/agents-vault/run/supervisor.sock";
const MAX_RUNNERS: usize = 4;
const MAX_LIFETIME: Duration = Duration::from_secs(130);
const TASK_LAUNCH: u8 = b'L';
// Darwin lacks MSG_CMSG_CLOEXEC. Serialize receipt/fcntl against every child
// spawn so a concurrent fork cannot inherit another task's descriptor.
static DESCRIPTOR_SPAWN_LOCK: Mutex<()> = Mutex::new(());

/// Root-owned installer output. Hashes pin the exact signed service helpers;
/// the Developer ID requirement also rejects ad-hoc and unrelated signatures.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    format: u32,
    team_identifier: String,
    broker_cdhash: String,
    supervisor_cdhash: String,
    runner_cdhash: String,
}

impl Policy {
    fn validate(&self) -> io::Result<()> {
        if self.format != 2
            || self.team_identifier.len() != 10
            || !self
                .team_identifier
                .bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            || [
                &self.broker_cdhash,
                &self.supervisor_cdhash,
                &self.runner_cdhash,
            ]
            .iter()
            .any(|hash| hash.len() != 40 || !hash.bytes().all(|c| c.is_ascii_hexdigit()))
        {
            return Err(denied("invalid installed signing policy"));
        }
        Ok(())
    }

    fn requirement(&self, identifier: &str, hash: &str) -> String {
        format!(
            "{} and cdhash H\"{}\"",
            self.publisher_requirement(identifier),
            hash
        )
    }

    fn publisher_requirement(&self, identifier: &str) -> String {
        format!(
            "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists \
             and certificate leaf[field.1.2.840.113635.100.6.1.13] exists \
             and certificate leaf[subject.OU] = \"{}\" and identifier \"{}\"",
            self.team_identifier, identifier,
        )
    }
}

/// A supervisor connection owns one task. No PID is exposed as a kill handle.
pub struct ServiceLease {
    control: UnixStream,
    result: Option<i32>,
    frame: Vec<u8>,
}

impl ServiceLease {
    /// Polls the supervisor's exit frame without blocking. EOF is a failure.
    pub fn try_wait(&mut self) -> io::Result<Option<i32>> {
        if self.result.is_some() {
            return Ok(self.result);
        }
        let mut bytes = [0_u8; 5];
        loop {
            match self.control.read(&mut bytes[..5 - self.frame.len()]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "supervisor disconnected",
                    ));
                }
                Ok(count) => self.frame.extend_from_slice(&bytes[..count]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
            if self.frame.len() == 5 {
                if self.frame[0] != b'E' {
                    return Err(denied("invalid supervisor result"));
                }
                self.result = Some(i32::from_be_bytes(self.frame[1..].try_into().unwrap()));
                return Ok(self.result);
            }
        }
    }

    /// Requests cancellation. The supervisor also kills the VMM on lease EOF.
    pub fn kill(&mut self) -> io::Result<()> {
        self.control.shutdown(std::net::Shutdown::Both)
    }

    pub fn wait(&mut self) -> io::Result<i32> {
        loop {
            if let Some(code) = self.try_wait()? {
                return Ok(code);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for ServiceLease {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

/// Launches the installed pinned VMM as `_avrunner`. Only the installed signed
/// broker under `_avd` is accepted. There are deliberately no path arguments.
/// Write `TaskSpec` to the stream after success, then relay the raw proxy bytes.
pub fn launch(expected: &ServiceIdentity) -> io::Result<(ServiceLease, UnixStream)> {
    validate_broker_identity()?;
    if installed_identity()? != *expected {
        return Err(denied(
            "installed service changed since grant authorization",
        ));
    }
    check_root_path(Path::new(SOCKET).parent().unwrap())?;
    let metadata = fs::symlink_metadata(SOCKET)?;
    if metadata.uid() != 0 || metadata.mode() & 0o007 != 0 {
        return Err(denied("untrusted supervisor socket"));
    }
    let mut control = UnixStream::connect(SOCKET)?;
    let (uid, _) = peer_identity(&control)?;
    if uid != 0 {
        return Err(denied("supervisor is not root"));
    }
    signing::authenticate(&control, &expected.supervisor_requirement())?;
    control.set_read_timeout(Some(Duration::from_secs(10)))?;
    control.set_write_timeout(Some(Duration::from_secs(5)))?;
    let (broker, child) = UnixStream::pair()?;
    send_descriptor(&control, child.as_raw_fd())?;
    control.write_all(&expected.fingerprint()?)?;
    drop(child);
    let mut ready = [0_u8; 1];
    control.read_exact(&mut ready)?;
    if ready != [b'R'] {
        return Err(denied("supervisor rejected launch"));
    }
    control.set_nonblocking(true)?;
    Ok((
        ServiceLease {
            control,
            result: None,
            frame: Vec::with_capacity(5),
        },
        broker,
    ))
}

fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn peer_identity(stream: &UnixStream) -> io::Result<(libc::uid_t, libc::gid_t)> {
    let (mut uid, mut gid) = (0, 0);
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((uid, gid))
}

/// Validate an existing root-owned path and every ancestor, rejecting symlinks,
/// writable ownership permissions, and extended ACLs. Does not require a broker UID.
/// Callers must separately require private permissions where confidentiality matters.
pub fn validate_root_owned_path(path: &Path) -> io::Result<()> {
    check_root_path(path)
}

/// Reject symlinks, non-root ownership, writable ancestors, and macOS ACLs.
/// The protected app lives outside the normally admin-writable /Applications.
fn check_root_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(denied("installed path must be absolute"));
    }
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return Err(denied("installed path is writable or not root-owned"));
        }
        check_no_acl(ancestor)?;
    }
    Ok(())
}

fn check_no_acl(path: &Path) -> io::Result<()> {
    unsafe extern "C" {
        fn acl_get_file(path: *const libc::c_char, kind: u32) -> *mut libc::c_void;
        fn acl_get_entry(
            acl: *mut libc::c_void,
            entry_id: libc::c_int,
            entry: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_free(value: *mut libc::c_void) -> libc::c_int;
    }
    use std::os::unix::ffi::OsStrExt;
    let path =
        std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| denied("invalid path"))?;
    unsafe {
        let acl = acl_get_file(path.as_ptr(), 0x0000_0100);
        if acl.is_null() {
            let error = io::Error::last_os_error();
            // macOS 27 returns ENOENT for an absent extended ACL even when the
            // inode exists. Recheck the path rather than accepting a missing
            // object. All ancestors are independently checked for ownership.
            if error.raw_os_error() == Some(libc::ENOENT) {
                fs::symlink_metadata(std::ffi::OsStr::from_bytes(path.as_bytes()))?;
                return Ok(());
            }
            return Err(error);
        }
        let mut entry = std::ptr::null_mut();
        let status = acl_get_entry(acl, 0, &mut entry);
        let error = io::Error::last_os_error();
        acl_free(acl);
        // Darwin returns -1/EINVAL for an empty ACL. acl_valid does not indicate
        // whether an entry grants permission, so accept only the empty case.
        if status == 0 {
            return Err(denied("installed path has an ACL"));
        }
        if error.raw_os_error() != Some(libc::EINVAL) {
            return Err(error);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Identity {
    uid: libc::uid_t,
    gid: libc::gid_t,
}

fn service_identity(name: &CStr) -> io::Result<Identity> {
    let mut record = unsafe { mem::zeroed::<libc::passwd>() };
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
    if status != 0 || result.is_null() {
        return Err(denied("installed service identity is missing"));
    }
    if record.pw_uid == 0
        || record.pw_gid == 0
        || unsafe { CStr::from_ptr(record.pw_dir) }.to_bytes() != b"/var/empty"
        || unsafe { CStr::from_ptr(record.pw_shell) }.to_bytes() != b"/usr/bin/false"
    {
        return Err(denied("invalid service identity"));
    }
    Ok(Identity {
        uid: record.pw_uid,
        gid: record.pw_gid,
    })
}

/// Entry point for the root LaunchDaemon. No runtime configuration is accepted.
pub fn run_supervisor() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 || std::env::args_os().len() != 1 {
        return Err(denied("supervisor requires root and takes no arguments"));
    }
    let broker = service_identity(c"_avd")?;
    let runner = service_identity(c"_avrunner")?;
    if broker.uid == runner.uid || broker.gid == runner.gid {
        return Err(denied("service identities must be distinct"));
    }
    let (policy, _) = identity::load_policy()?;
    installed_identity()?;
    let policy = Arc::new(policy);
    let directory = Path::new(SOCKET).parent().unwrap();
    check_root_path(directory)?;
    // launchd restarts can leave a socket inode; only remove an actual root
    // socket inside the protected directory, never an arbitrary path.
    if let Ok(metadata) = fs::symlink_metadata(SOCKET) {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_socket() || metadata.uid() != 0 {
            return Err(denied("unsafe existing supervisor socket"));
        }
        fs::remove_file(SOCKET)?;
    }
    unsafe {
        libc::umask(0o077);
    }
    let listener = std::os::unix::net::UnixListener::bind(SOCKET)?;
    use std::os::unix::fs::PermissionsExt;
    let socket_name = std::ffi::CString::new(SOCKET).unwrap();
    if unsafe { libc::chown(socket_name.as_ptr(), 0, broker.gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o660))?;
    let active = Arc::new(AtomicUsize::new(0));
    for connection in listener.incoming() {
        let control = connection?;
        if active.load(Ordering::Acquire) >= MAX_RUNNERS {
            continue;
        }
        active.fetch_add(1, Ordering::AcqRel);
        let active = Arc::clone(&active);
        let policy = Arc::clone(&policy);
        std::thread::spawn(move || {
            if let Err(error) = serve(control, broker, runner, &policy) {
                eprintln!("av-supervisor: rejected or failed task: {error}");
            }
            active.fetch_sub(1, Ordering::AcqRel);
        });
    }
    Ok(())
}

fn verify_code(path: &str, requirement: &str) -> io::Result<()> {
    let _guard = DESCRIPTOR_SPAWN_LOCK
        .lock()
        .map_err(|_| denied("descriptor lock poisoned"))?;
    let requirement_argument = format!("-R={requirement}");
    let output = Command::new("/usr/bin/codesign")
        .env_clear()
        .args([
            "--verify",
            "--strict",
            "--all-architectures",
            &requirement_argument,
            path,
        ])
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(denied("installed code signature rejected"));
    }
    Ok(())
}

fn serve(
    mut control: UnixStream,
    broker: Identity,
    runner: Identity,
    policy: &Policy,
) -> io::Result<()> {
    control.set_read_timeout(Some(Duration::from_secs(5)))?;
    control.set_write_timeout(Some(Duration::from_secs(5)))?;
    if peer_identity(&control)? != (broker.uid, broker.gid) {
        return Err(denied("caller is not the broker service identity"));
    }
    signing::authenticate(
        &control,
        &policy.requirement("dev.agentsvault.avd", &policy.broker_cdhash),
    )?;
    let transport = {
        let _guard = DESCRIPTOR_SPAWN_LOCK
            .lock()
            .map_err(|_| denied("descriptor lock poisoned"))?;
        receive_descriptor(&control)?
    };
    let mut commitment = [0_u8; 32];
    control.read_exact(&mut commitment)?;
    if installed_identity()?.fingerprint()? != commitment {
        return Err(denied("launch does not match the granted service identity"));
    }
    check_root_path(Path::new(VMM))?;
    for name in ["guest.json", "Image", "initramfs.gz"] {
        check_root_path(&Path::new(BUNDLE).join(name))?;
    }
    verify_code(
        VMM,
        &policy.requirement("dev.agentsvault.av-vmm", &policy.runner_cdhash),
    )?;
    crate::verify_bundle(Path::new(BUNDLE))?;
    let mut command = Command::new(VMM);
    command
        .env_clear()
        .args(["run", BUNDLE])
        .current_dir("/var/empty")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(runner.gid) != 0
                || libc::setuid(runner.uid) != 0
                || libc::getuid() != runner.uid
                || libc::geteuid() != runner.uid
                || libc::getgid() != runner.gid
                || libc::getegid() != runner.gid
            {
                return Err(io::Error::last_os_error());
            }
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                return Err(io::Error::last_os_error());
            }
            if transport.as_raw_fd() != 3 && libc::dup2(transport.as_raw_fd(), 3) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = {
        let _guard = DESCRIPTOR_SPAWN_LOCK
            .lock()
            .map_err(|_| denied("descriptor lock poisoned"))?;
        command.spawn()?
    };
    drop(command);
    // Every return path from here, including client disconnect or protocol
    // errors, kills and reaps the owned child before dropping the lease.
    supervise_spawned(control, KillOnDrop(child), MAX_LIFETIME)
}

fn supervise_spawned(
    mut control: UnixStream,
    mut child: KillOnDrop,
    lifetime: Duration,
) -> io::Result<()> {
    control.write_all(b"R")?;
    control.set_nonblocking(true)?;
    let deadline = Instant::now() + lifetime;
    loop {
        if let Some(status) = child.0.try_wait()? {
            write_exit_frame(&mut control, status.code().unwrap_or(1))?;
            return Ok(());
        }
        let mut request = [0_u8; 1];
        match control.read(&mut request) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            _ => return Err(denied("broker cancelled or sent invalid control data")),
        }
        if Instant::now() >= deadline {
            return Err(denied("supervisor task deadline expired"));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn write_exit_frame(control: &mut UnixStream, code: i32) -> io::Result<()> {
    let mut result = [b'E', 0, 0, 0, 0];
    result[1..].copy_from_slice(&code.to_be_bytes());
    control.write_all(&result)
}

struct KillOnDrop(std::process::Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// Aligned ancillary storage; no unaligned cmsghdr or RawFd references.
#[repr(C)]
struct Ancillary([usize; 32]);

fn send_descriptor(stream: &UnixStream, descriptor: RawFd) -> io::Result<()> {
    unsafe {
        let mut byte = TASK_LAUNCH;
        let mut vector = libc::iovec {
            iov_base: (&mut byte as *mut u8).cast(),
            iov_len: 1,
        };
        let mut ancillary = Ancillary([0; 32]);
        let mut message: libc::msghdr = mem::zeroed();
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.0.as_mut_ptr().cast();
        message.msg_controllen = libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32);
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32);
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), descriptor);
        if libc::sendmsg(stream.as_raw_fd(), &message, 0) != 1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn receive_descriptor(stream: &UnixStream) -> io::Result<OwnedFd> {
    let (tag, descriptor) = receive_launch_descriptor(stream)?;
    if tag != TASK_LAUNCH {
        return Err(denied("task launch requires the task descriptor tag"));
    }
    Ok(descriptor)
}

fn receive_launch_descriptor(stream: &UnixStream) -> io::Result<(u8, OwnedFd)> {
    unsafe {
        let mut byte = 0_u8;
        let mut vector = libc::iovec {
            iov_base: (&mut byte as *mut u8).cast(),
            iov_len: 1,
        };
        let mut ancillary = Ancillary([0; 32]);
        let mut message: libc::msghdr = mem::zeroed();
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.0.as_mut_ptr().cast();
        message.msg_controllen = mem::size_of_val(&ancillary) as _;
        let count = libc::recvmsg(stream.as_raw_fd(), &mut message, 0);
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut descriptors = Vec::new();
        let mut invalid_control = false;
        message.msg_controllen =
            (message.msg_controllen as usize).min(mem::size_of_val(&ancillary)) as _;
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level != libc::SOL_SOCKET || (*header).cmsg_type != libc::SCM_RIGHTS {
                invalid_control = true;
            } else {
                let base = libc::CMSG_LEN(0) as usize;
                let length = (*header).cmsg_len as usize;
                if length < base || !(length - base).is_multiple_of(mem::size_of::<RawFd>()) {
                    invalid_control = true;
                } else {
                    let data_offset = (libc::CMSG_DATA(header) as usize)
                        .saturating_sub(message.msg_control as usize);
                    let available = (message.msg_controllen as usize)
                        .min(mem::size_of_val(&ancillary))
                        .saturating_sub(data_offset);
                    let copied = (length - base).min(available);
                    if copied < length - base || !copied.is_multiple_of(mem::size_of::<RawFd>()) {
                        invalid_control = true;
                    }
                    for index in 0..copied / mem::size_of::<RawFd>() {
                        let raw = std::ptr::read_unaligned(
                            libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                        );
                        descriptors.push(OwnedFd::from_raw_fd(raw));
                    }
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
        if count != 1
            || byte != TASK_LAUNCH
            || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
            || invalid_control
            || descriptors.len() != 1
        {
            return Err(denied(
                "launch requires exactly one private stream descriptor",
            ));
        }
        let descriptor = descriptors.pop().unwrap();
        if libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) != 0 {
            return Err(io::Error::last_os_error());
        }
        validate_transport(descriptor.as_raw_fd())?;
        Ok((byte, descriptor))
    }
}

fn validate_transport(descriptor: RawFd) -> io::Result<()> {
    unsafe {
        let mut kind: libc::c_int = 0;
        let mut size = mem::size_of_val(&kind) as libc::socklen_t;
        let mut address: libc::sockaddr_storage = mem::zeroed();
        let mut address_size = mem::size_of_val(&address) as libc::socklen_t;
        if libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut size,
        ) != 0
            || kind != libc::SOCK_STREAM
            || libc::getpeername(
                descriptor,
                (&mut address as *mut libc::sockaddr_storage).cast(),
                &mut address_size,
            ) != 0
            || i32::from(address.ss_family) != libc::AF_UNIX
        {
            return Err(denied("transport must be a connected Unix stream"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_transfer_preserves_private_stream_and_sets_close_on_exec() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let (mut broker, transport) = UnixStream::pair().unwrap();
        send_descriptor(&sender, transport.as_raw_fd()).unwrap();
        let received = receive_descriptor(&receiver).unwrap();
        assert_ne!(
            unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let mut received = UnixStream::from(received);
        broker.write_all(b"private").unwrap();
        let mut bytes = [0; 7];
        received.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"private");
    }

    #[test]
    fn oversized_launch_ancillary_is_rejected_without_owning_unreceived_fds() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let (_broker, transport) = UnixStream::pair().unwrap();
        let fds = [transport.as_raw_fd(); 80];
        let mut frame = TASK_LAUNCH;
        let mut vector = libc::iovec {
            iov_base: (&mut frame as *mut u8).cast(),
            iov_len: 1,
        };
        let control_len = unsafe { libc::CMSG_SPACE(mem::size_of_val(&fds) as u32) } as usize;
        let mut ancillary = vec![0_usize; control_len.div_ceil(mem::size_of::<usize>())];
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.as_mut_ptr().cast();
        message.msg_controllen = control_len as _;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(mem::size_of_val(&fds) as u32) as _;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(header),
                mem::size_of_val(&fds),
            );
            assert_eq!(libc::sendmsg(sender.as_raw_fd(), &message, 0), 1);
        }
        assert!(receive_launch_descriptor(&receiver).is_err());
    }

    #[test]
    fn rejects_files_missing_descriptors_and_network_sockets() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let file = fs::File::open("/dev/null").unwrap();
        send_descriptor(&sender, file.as_raw_fd()).unwrap();
        assert!(receive_descriptor(&receiver).is_err());
        (&sender).write_all(b"L").unwrap();
        assert!(receive_descriptor(&receiver).is_err());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _accepted = listener.accept().unwrap();
        send_descriptor(&sender, client.as_raw_fd()).unwrap();
        assert!(receive_descriptor(&receiver).is_err());
    }

    #[test]
    fn audit_token_authentication_rejects_an_unrelated_signature() {
        // A real connected socket exercises LOCAL_PEERTOKEN and Security.framework.
        // A socketpair's audit token is not populated on every macOS version.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("peer.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let client = UnixStream::connect(path).unwrap();
        let (server, _) = listener.accept().unwrap();
        signing::authenticate(&server, "true").unwrap();
        let signature = Command::new("/usr/bin/codesign")
            .args(["-dv", "--verbose=4"])
            .arg(std::env::current_exe().unwrap())
            .output()
            .unwrap();
        assert!(signature.status.success());
        let details = String::from_utf8(signature.stderr).unwrap();
        let hash = details
            .lines()
            .find_map(|line| line.strip_prefix("CDHash="))
            .unwrap();
        assert_eq!(hash.len(), 40);
        signing::authenticate(&server, &format!("cdhash H\"{hash}\"")).unwrap();
        // The broker also authenticates the listening supervisor before any
        // descriptor is transferred. Exercise that direction independently.
        signing::authenticate(&client, &format!("cdhash H\"{hash}\"")).unwrap();
        assert!(
            signing::authenticate(&client, &format!("cdhash H\"{}\"", "0".repeat(40))).is_err()
        );
        assert!(
            signing::authenticate(&server, &format!("cdhash H\"{}\"", "0".repeat(40))).is_err()
        );
        let error = signing::authenticate(&server, "identifier \"dev.agentsvault.nonexistent\"")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let policy = Policy {
            format: 2,
            team_identifier: "AAAAAAAAAA".into(),
            broker_cdhash: "0".repeat(40),
            supervisor_cdhash: "0".repeat(40),
            runner_cdhash: "0".repeat(40),
        };
        let error = signing::authenticate(
            &server,
            &policy.requirement("dev.agentsvault.avd", &policy.broker_cdhash),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn rejects_user_owned_paths_and_policy_injection() {
        let directory = tempfile::tempdir().unwrap();
        assert!(check_root_path(directory.path()).is_err());
        check_root_path(Path::new("/Library/PrivilegedHelperTools")).unwrap();
        let policy = Policy {
            format: 2,
            team_identifier: "x\" or true".into(),
            broker_cdhash: "0".repeat(40),
            supervisor_cdhash: "0".repeat(40),
            runner_cdhash: "0".repeat(40),
        };
        assert!(policy.validate().is_err());
        let unsupported_format = Policy {
            format: 1,
            team_identifier: "ABCDEFGHIJ".into(),
            broker_cdhash: "0".repeat(40),
            supervisor_cdhash: "0".repeat(40),
            runner_cdhash: "0".repeat(40),
        };
        assert!(unsupported_format.validate().is_err());
    }

    #[test]
    fn rejects_acl_permissions_even_when_mode_bits_look_private() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("acl-probe");
        fs::write(&path, b"synthetic").unwrap();
        check_no_acl(&path).unwrap();
        assert!(
            Command::new("/bin/chmod")
                .args(["+a", "everyone allow write"])
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        assert!(check_no_acl(&path).is_err());
    }

    #[test]
    fn ordinary_login_cannot_use_service_launch_or_start_supervisor() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        assert_eq!(
            run_supervisor().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let identity = ServiceIdentity {
            format: 1,
            team_identifier: "ABCDEFGHIJ".into(),
            broker_cdhash: "a".repeat(40),
            supervisor_cdhash: "b".repeat(40),
            runner_cdhash: "c".repeat(40),
            service_policy_sha256: "d".repeat(64),
            guest_manifest_sha256: "e".repeat(64),
            kernel_sha256: "a".repeat(64),
            initramfs_sha256: "b".repeat(64),
            fixture_sha256: "c".repeat(64),
        };
        assert!(launch(&identity).is_err());
    }

    #[test]
    fn lease_drop_cancels_and_exit_frame_is_bounded() {
        let (mut server, client) = UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        let mut lease = ServiceLease {
            control: client,
            result: None,
            frame: Vec::new(),
        };
        assert_eq!(lease.try_wait().unwrap(), None);
        server.write_all(&[b'E', 0]).unwrap();
        assert_eq!(lease.try_wait().unwrap(), None);
        server.write_all(&[0, 0, 7]).unwrap();
        assert_eq!(lease.try_wait().unwrap(), Some(7));
        drop(lease);
        assert_eq!(server.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn task_launch_still_rejects_cancel_byte_without_ack() {
        let (mut broker, supervisor) = UnixStream::pair().unwrap();
        broker
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let child = Command::new("/bin/sleep").arg("10").spawn().unwrap();
        let pid = child.id() as libc::pid_t;
        let worker = std::thread::spawn(move || {
            supervise_spawned(supervisor, KillOnDrop(child), Duration::from_secs(2))
        });
        broker.read_exact(&mut [0_u8; 1]).unwrap();
        broker.write_all(b"C").unwrap();
        assert_eq!(broker.read(&mut [0_u8; 1]).unwrap(), 0);
        assert_eq!(
            worker.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }
}
