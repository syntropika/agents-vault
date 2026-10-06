//! Exact installed identity used by per-secret grants and supervisor launches.
//! No development path, alternate trust anchor, or caller-supplied manifest is
//! accepted by the production identity reader.

use super::{
    APP, BROKER, BUNDLE, POLICY, Policy, SUPERVISOR, VMM, check_root_path, denied, verify_code,
};
use crate::GuestManifest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    path::Path,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceIdentity {
    pub format: u32,
    pub team_identifier: String,
    pub broker_cdhash: String,
    pub supervisor_cdhash: String,
    pub runner_cdhash: String,
    pub service_policy_sha256: String,
    pub guest_manifest_sha256: String,
    pub kernel_sha256: String,
    pub initramfs_sha256: String,
    pub fixture_sha256: String,
}

impl ServiceIdentity {
    /// A domain-separated, fixed-size launch commitment. Serialization order
    /// is fixed by this versioned struct; no arbitrary caller JSON is hashed.
    pub fn fingerprint(&self) -> io::Result<[u8; 32]> {
        let mut hash = Sha256::new();
        if self.format != 1 {
            return Err(denied("invalid installed service identity version"));
        }
        hash.update(b"agents-vault-macos-service-identity-v1\0");
        hash.update(serde_json::to_vec(self).map_err(io::Error::other)?);
        Ok(hash.finalize().into())
    }

    pub(super) fn supervisor_requirement(&self) -> String {
        Policy {
            format: self.format + 1,
            team_identifier: self.team_identifier.clone(),
            broker_cdhash: self.broker_cdhash.clone(),
            supervisor_cdhash: self.supervisor_cdhash.clone(),
            runner_cdhash: self.runner_cdhash.clone(),
        }
        .requirement("dev.agentsvault.av-supervisor", &self.supervisor_cdhash)
    }
}

pub(super) fn load_policy() -> io::Result<(Policy, Vec<u8>)> {
    check_root_path(Path::new(POLICY))?;
    let bytes = bounded_file(Path::new(POLICY), 4096)?;
    let policy: Policy = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    policy.validate()?;
    Ok((policy, bytes))
}

pub fn installed_identity() -> io::Result<ServiceIdentity> {
    let (policy, policy_bytes) = load_policy()?;
    check_root_path(Path::new(APP))?;
    verify_code(APP, &policy.publisher_requirement("dev.agentsvault.cli"))?;
    for (path, identifier, hash) in [
        (BROKER, "dev.agentsvault.avd", &policy.broker_cdhash),
        (
            SUPERVISOR,
            "dev.agentsvault.av-supervisor",
            &policy.supervisor_cdhash,
        ),
        (VMM, "dev.agentsvault.av-vmm", &policy.runner_cdhash),
    ] {
        check_root_path(Path::new(path))?;
        verify_code(path, &policy.requirement(identifier, hash))?;
    }
    for resource in ["guest.json", "Image", "initramfs.gz"] {
        check_root_path(&Path::new(BUNDLE).join(resource))?;
    }
    let manifest_bytes = bounded_file(&Path::new(BUNDLE).join("guest.json"), 4096)?;
    let manifest: GuestManifest =
        serde_json::from_slice(&manifest_bytes).map_err(io::Error::other)?;
    if policy.format != manifest.format
        || manifest.format != 2
        || manifest.architecture != "aarch64"
    {
        return Err(denied(
            "protected grants require a matching guest and service format",
        ));
    }
    crate::verify_bundle(Path::new(BUNDLE))?;
    identity_from_verified(&policy, &policy_bytes, &manifest, &manifest_bytes)
}

fn identity_from_verified(
    policy: &Policy,
    policy_bytes: &[u8],
    manifest: &GuestManifest,
    manifest_bytes: &[u8],
) -> io::Result<ServiceIdentity> {
    policy.validate()?;
    if policy.format != manifest.format || manifest.format != 2 {
        return Err(denied("installed service policy and guest format differ"));
    }
    let fixture = &manifest.fixture_sha256;
    for hash in [&manifest.kernel_sha256, &manifest.initramfs_sha256, fixture] {
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(denied("invalid guest resource identity"));
        }
    }
    Ok(ServiceIdentity {
        format: manifest.format - 1,
        team_identifier: policy.team_identifier.clone(),
        broker_cdhash: policy.broker_cdhash.to_ascii_lowercase(),
        supervisor_cdhash: policy.supervisor_cdhash.to_ascii_lowercase(),
        runner_cdhash: policy.runner_cdhash.to_ascii_lowercase(),
        service_policy_sha256: format!("{:x}", Sha256::digest(policy_bytes)),
        guest_manifest_sha256: format!("{:x}", Sha256::digest(manifest_bytes)),
        kernel_sha256: manifest.kernel_sha256.clone(),
        initramfs_sha256: manifest.initramfs_sha256.clone(),
        fixture_sha256: fixture.clone(),
    })
}

fn bounded_file(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(denied("invalid installed resource"));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(denied("installed resource grew beyond its limit"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn launch_commitment_changes_with_every_installed_component() {
        let policy = Policy {
            format: 2,
            team_identifier: "ABCDEFGHIJ".into(),
            broker_cdhash: "a".repeat(40),
            supervisor_cdhash: "b".repeat(40),
            runner_cdhash: "c".repeat(40),
        };
        let manifest = GuestManifest {
            format: 2,
            architecture: "aarch64".into(),
            kernel_sha256: "d".repeat(64),
            initramfs_sha256: "e".repeat(64),
            fixture_sha256: "f".repeat(64),
        };
        let original = identity_from_verified(&policy, b"policy", &manifest, b"manifest").unwrap();
        let encoded = serde_json::to_value(&original).unwrap();
        for field in [
            "team_identifier",
            "broker_cdhash",
            "supervisor_cdhash",
            "runner_cdhash",
            "service_policy_sha256",
            "guest_manifest_sha256",
            "kernel_sha256",
            "initramfs_sha256",
            "fixture_sha256",
        ] {
            let mut changed = encoded.clone();
            changed[field] = serde_json::json!("changed");
            let changed: ServiceIdentity = serde_json::from_value(changed).unwrap();
            assert_ne!(
                original.fingerprint().unwrap(),
                changed.fingerprint().unwrap(),
                "{field}"
            );
        }
        assert_ne!(
            original.fingerprint().unwrap(),
            identity_from_verified(&policy, b"policy ", &manifest, b"manifest")
                .unwrap()
                .fingerprint()
                .unwrap()
        );
    }
}
