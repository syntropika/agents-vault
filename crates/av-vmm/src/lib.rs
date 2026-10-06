//! A bounded task protocol for the packaged macOS Linux guest.
//!
//! The inherited socket is a broker-created transport capability. No pathname
//! listener, provider credential, or proxy capability is delivered to the guest.
//! Service identity and whole-agent host confinement are separate release gates.

extern crate self as av_vmm;

#[cfg(target_os = "macos")]
pub mod service;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

pub const CONTROL_PORT: u32 = 14322;
pub const PROXY_PORT: u32 = 14323;
pub const MAX_FRAME: usize = 64 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSpec {
    pub args: Vec<String>,
    /// Public interception CA certificate only; never a private key.
    pub ca_pem: String,
    pub timeout_secs: u32,
}

impl TaskSpec {
    pub fn validate(&self) -> io::Result<()> {
        let recipe_valid = self.args.first().map(String::as_str) == Some("request")
            && self.args.len() <= 20
            && self.args.iter().all(|arg| arg.len() <= 8192);
        if !recipe_valid
            || self.args.iter().any(|arg| arg.contains('\0'))
            || !self.ca_pem.starts_with("-----BEGIN CERTIFICATE-----")
            || self.ca_pem.contains("PRIVATE KEY")
            || self.ca_pem.len() > 16 * 1024
            || !(1..=120).contains(&self.timeout_secs)
        {
            return Err(invalid("invalid guest fixture task"));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskOutcome {
    pub exit_code: i32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestManifest {
    pub format: u32,
    pub architecture: String,
    pub kernel_sha256: String,
    pub initramfs_sha256: String,
    pub fixture_sha256: String,
}

/// Hashes authenticate files relative to the installed manifest. The installer
/// must protect the entire bundle, including this manifest, against mutation.
pub fn verify_bundle(directory: &Path) -> io::Result<(PathBuf, PathBuf)> {
    let bytes = fs::read(directory.join("guest.json"))?;
    if bytes.len() > 4096 {
        return Err(invalid("guest manifest too large"));
    }
    let manifest: GuestManifest = serde_json::from_slice(&bytes).map_err(invalid)?;
    if manifest.format != 2 || manifest.architecture != "aarch64" {
        return Err(invalid("unsupported guest bundle"));
    }
    if manifest.fixture_sha256.len() != 64
        || !manifest
            .fixture_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("invalid fixture identity in guest manifest"));
    }
    let kernel = directory.join("Image");
    let initramfs = directory.join("initramfs.gz");
    for (path, expected) in [
        (&kernel, &manifest.kernel_sha256),
        (&initramfs, &manifest.initramfs_sha256),
    ] {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.len() > 128 * 1024 * 1024 {
            return Err(invalid("invalid guest image file"));
        }
        let mut file = fs::File::open(path)?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 65536];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        let actual = format!("{:x}", digest.finalize());
        if actual != *expected {
            return Err(invalid("guest image integrity failure"));
        }
    }
    Ok((kernel, initramfs))
}

pub fn write_task(stream: &mut impl Write, task: &TaskSpec) -> io::Result<()> {
    task.validate()?;
    write_frame(stream, task)
}

pub fn write_frame(stream: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(invalid)?;
    if bytes.len() > MAX_FRAME {
        return Err(invalid("task frame too large"));
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()
}

pub fn read_frame<T: DeserializeOwned>(stream: &mut impl Read) -> io::Result<T> {
    let mut size = [0_u8; 4];
    stream.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err(invalid("invalid task frame size"));
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(invalid)
}

fn invalid(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

/// The returned parent stream receives a task frame after spawn, then carries
/// one raw proxy connection. The broker adds its own proxy authorization.
/// Drop the returned `Command` immediately after spawning so the parent no
/// longer holds the child end of the socket; cancellation then produces EOF.
#[cfg(unix)]
pub fn prepare_command(
    vmm: &Path,
    bundle: &Path,
) -> io::Result<(std::process::Command, std::os::unix::net::UnixStream)> {
    use std::os::{
        fd::AsRawFd,
        unix::{net::UnixStream, process::CommandExt},
    };
    if !vmm.is_absolute() || !bundle.is_absolute() {
        return Err(invalid("VMM and bundle paths must be absolute"));
    }
    let (parent, child) = UnixStream::pair()?;
    let mut command = std::process::Command::new(vmm);
    command.env_clear().arg("run").arg(bundle);
    // Capturing the child socket keeps it alive until spawn. Only dup2/fcntl,
    // which are async-signal-safe, run between fork and exec.
    unsafe {
        command.pre_exec(move || {
            let fd = child.as_raw_fd();
            if fd != 3 && libc::dup2(fd, 3) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok((command, parent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_rejects_oversize_and_private_key() {
        assert!(
            read_frame::<TaskSpec>(&mut ((MAX_FRAME + 1) as u32).to_be_bytes().as_slice()).is_err()
        );
        let task = TaskSpec {
            args: vec!["request".into()],
            ca_pem: "-----BEGIN CERTIFICATE-----\nPRIVATE KEY".into(),
            timeout_secs: 10,
        };
        assert!(write_task(&mut Vec::new(), &task).is_err());
        assert!(read_frame::<TaskOutcome>(&mut [0, 0, 0, 2, b'{', b'}'].as_slice()).is_err());
    }

    #[test]
    fn bundle_rejects_changed_resources_and_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("Image"), b"kernel").unwrap();
        fs::write(directory.path().join("initramfs.gz"), b"guest").unwrap();
        let manifest = GuestManifest {
            format: 2,
            architecture: "aarch64".into(),
            kernel_sha256: format!("{:x}", Sha256::digest(b"kernel")),
            initramfs_sha256: format!("{:x}", Sha256::digest(b"guest")),
            fixture_sha256: "a".repeat(64),
        };
        fs::write(
            directory.path().join("guest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        verify_bundle(directory.path()).unwrap();
        fs::write(directory.path().join("Image"), b"changed").unwrap();
        assert!(verify_bundle(directory.path()).is_err());
        #[cfg(unix)]
        {
            fs::remove_file(directory.path().join("Image")).unwrap();
            fs::write(directory.path().join("kernel-copy"), b"kernel").unwrap();
            std::os::unix::fs::symlink("kernel-copy", directory.path().join("Image")).unwrap();
            assert!(verify_bundle(directory.path()).is_err());
        }
    }

    #[test]
    fn format_two_requires_a_canonical_fixture_digest() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("Image"), b"kernel").unwrap();
        fs::write(directory.path().join("initramfs.gz"), b"guest").unwrap();
        let mut manifest = GuestManifest {
            format: 2,
            architecture: "aarch64".into(),
            kernel_sha256: format!("{:x}", Sha256::digest(b"kernel")),
            initramfs_sha256: format!("{:x}", Sha256::digest(b"guest")),
            fixture_sha256: "a".repeat(64),
        };
        let write = |manifest: &GuestManifest| {
            fs::write(
                directory.path().join("guest.json"),
                serde_json::to_vec(manifest).unwrap(),
            )
            .unwrap();
        };
        write(&manifest);
        verify_bundle(directory.path()).unwrap();
        for hash in ["", &"a".repeat(63), &"A".repeat(64), &"g".repeat(64)] {
            manifest.fixture_sha256 = hash.to_owned();
            write(&manifest);
            assert!(verify_bundle(directory.path()).is_err());
        }
        manifest.fixture_sha256 = "a".repeat(64);
        manifest.format = 3;
        write(&manifest);
        assert!(verify_bundle(directory.path()).is_err());
        manifest.format = 2;
        let mut value = serde_json::to_value(&manifest).unwrap();
        value["extra_executable_sha256"] = serde_json::json!("a".repeat(64));
        fs::write(
            directory.path().join("guest.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert!(verify_bundle(directory.path()).is_err());
    }
}
