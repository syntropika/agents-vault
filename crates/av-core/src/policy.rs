//! Operator-owned secret release policy, stored inside the encrypted vault.
use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    Direct,
    ProxyPreview,
    ProtectedProxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRequirement {
    EveryRun,
    Preapproved,
}

/// Verified identity of the installed macOS guest service. Callers must obtain
/// these values from the protected, signed installation, never an agent request.
/// Present only for the macOS guest service; native requests omit it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacOsServiceIdentity {
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
    pub upstream_ca_sha256: String,
}

impl MacOsServiceIdentity {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.format == 1, "unsupported macOS service grant format");
        ensure!(
            self.team_identifier.len() == 10
                && self
                    .team_identifier
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
            "invalid macOS signing team"
        );
        for digest in [
            &self.broker_cdhash,
            &self.supervisor_cdhash,
            &self.runner_cdhash,
        ] {
            ensure!(
                canonical_digest(digest, 40),
                "invalid macOS signed code identity"
            );
        }
        for digest in [
            &self.service_policy_sha256,
            &self.guest_manifest_sha256,
            &self.kernel_sha256,
            &self.initramfs_sha256,
            &self.fixture_sha256,
            &self.upstream_ca_sha256,
        ] {
            ensure!(
                canonical_digest(digest, 64),
                "invalid macOS service resource identity"
            );
        }
        Ok(())
    }
}

fn canonical_digest(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Every field participates in matching. Configuration is a digest, never its values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretAccessRequest {
    pub executable: String,
    pub executable_sha256: String,
    pub arguments: Vec<String>,
    pub config_path: String,
    pub config_sha256: String,
    pub working_directory: String,
    pub environment: Option<String>,
    pub delivery: DeliveryMode,
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos_service: Option<MacOsServiceIdentity>,
    /// Exact upstream trust bytes for native protected proxy grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_ca_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretGrant {
    pub request: SecretAccessRequest,
    pub approval: ApprovalRequirement,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPolicy {
    pub grants: Vec<SecretGrant>,
}

impl SecretAccessRequest {
    pub fn for_command(
        command: &[String],
        config_path: &Path,
        config_source: &[u8],
        environment: Option<&str>,
        delivery: DeliveryMode,
        host: Option<&str>,
    ) -> Result<Self> {
        let (program, arguments) = command.split_first().context("command is required")?;
        ensure!(
            Path::new(program).is_absolute(),
            "secret access requires an absolute executable path"
        );
        let executable = fs::canonicalize(program).context("cannot resolve executable")?;
        ensure!(executable.is_file(), "executable must be a regular file");
        let mut file = fs::File::open(&executable).context("cannot read executable")?;
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let length = file.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            hash.update(&buffer[..length]);
        }
        let request = Self {
            executable: executable
                .to_str()
                .context("executable path must be UTF-8")?
                .to_owned(),
            executable_sha256: hex::encode(hash.finalize()),
            arguments: arguments.to_vec(),
            config_path: fs::canonicalize(config_path)?
                .to_str()
                .context("config path must be UTF-8")?
                .to_owned(),
            config_sha256: hex::encode(Sha256::digest(config_source)),
            working_directory: std::env::current_dir()?
                .to_str()
                .context("working directory must be UTF-8")?
                .to_owned(),
            environment: environment.map(str::to_owned),
            delivery,
            host: host.map(str::to_ascii_lowercase),
            macos_service: None,
            upstream_ca_sha256: None,
        };
        request.validate()?;
        Ok(request)
    }

    /// Build a guest request without resolving a guest path on the host.
    /// `identity` must already have passed installed signature/resource checks.
    pub fn for_macos_service(
        command: &[String],
        config_path: &Path,
        config_source: &[u8],
        host: &str,
        identity: MacOsServiceIdentity,
    ) -> Result<Self> {
        let (program, arguments) = command.split_first().context("guest command is required")?;
        let request = Self {
            executable: program.clone(),
            executable_sha256: identity.fixture_sha256.clone(),
            arguments: arguments.to_vec(),
            config_path: config_path
                .to_str()
                .context("policy path must be UTF-8")?
                .into(),
            config_sha256: hex::encode(Sha256::digest(config_source)),
            working_directory: "/".into(),
            environment: None,
            delivery: DeliveryMode::ProtectedProxy,
            host: Some(host.to_ascii_lowercase()),
            macos_service: Some(identity),
            upstream_ca_sha256: None,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(digest) = &self.upstream_ca_sha256 {
            ensure!(
                self.delivery == DeliveryMode::ProtectedProxy
                    && self.macos_service.is_none()
                    && canonical_digest(digest, 64),
                "upstream CA binding requires a canonical native protected proxy digest"
            );
        }
        if let Some(identity) = &self.macos_service {
            identity.validate()?;
            let shared = self.delivery == DeliveryMode::ProtectedProxy
                && self.config_path == "/private/var/db/agents-vault/broker/proxy-policy.json"
                && self.working_directory == "/";
            let fixture = self.executable == "/usr/bin/av-fixture"
                && self.executable_sha256 == identity.fixture_sha256
                && self.environment.is_none()
                && self.arguments.first().map(String::as_str) == Some("request")
                && self.arguments.len() <= 20
                && self.arguments.iter().all(|argument| argument.len() <= 8192);
            ensure!(
                shared && fixture,
                "macOS grants require a pinned installed guest recipe"
            );
        }
        ensure!(
            Path::new(&self.executable).is_absolute(),
            "policy executable must be absolute"
        );
        ensure!(
            Path::new(&self.config_path).is_absolute(),
            "policy config path must be absolute"
        );
        ensure!(
            Path::new(&self.working_directory).is_absolute(),
            "policy working directory must be absolute"
        );
        for digest in [&self.executable_sha256, &self.config_sha256] {
            ensure!(
                digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid policy digest"
            );
        }
        ensure!(
            self.arguments.len() <= 256
                && self
                    .arguments
                    .iter()
                    .all(|a| a.len() <= 16 * 1024 && !a.contains('\0')),
            "invalid policy arguments"
        );
        match self.delivery {
            DeliveryMode::Direct => ensure!(
                self.host.is_none(),
                "direct delivery cannot enforce a destination host"
            ),
            DeliveryMode::ProxyPreview | DeliveryMode::ProtectedProxy => {
                let host = self
                    .host
                    .as_deref()
                    .context("proxy delivery requires an exact host")?;
                ensure!(
                    host.len() <= 253
                        && !host.is_empty()
                        && host.split('.').all(|label| !label.is_empty()
                            && label.len() <= 63
                            && !label.starts_with('-')
                            && !label.ends_with('-')
                            && label.bytes().all(|b| b.is_ascii_lowercase()
                                || b.is_ascii_digit()
                                || b == b'-')),
                    "invalid exact destination host"
                );
            }
        }
        Ok(())
    }
}

impl SecretPolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.grants.len() <= 128, "too many secret grants");
        for grant in &self.grants {
            grant.request.validate()?;
        }
        Ok(())
    }

    pub fn authorization(&self, request: &SecretAccessRequest) -> Result<ApprovalRequirement> {
        request.validate()?;
        self.validate()?;
        let mut matched = self.grants.iter().filter(|grant| &grant.request == request);
        let first = matched
            .next()
            .context("secret policy denies this command, configuration, or delivery")?;
        // Duplicate entries cannot weaken an approval requirement.
        Ok(
            if first.approval == ApprovalRequirement::EveryRun
                || matched.any(|g| g.approval == ApprovalRequirement::EveryRun)
            {
                ApprovalRequirement::EveryRun
            } else {
                ApprovalRequirement::Preapproved
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac_request() -> SecretAccessRequest {
        SecretAccessRequest::for_macos_service(
            &["/usr/bin/av-fixture".into(), "request".into()],
            Path::new("/private/var/db/agents-vault/broker/proxy-policy.json"),
            b"exact policy bytes",
            "api.example.test",
            MacOsServiceIdentity {
                format: 1,
                team_identifier: "ABCDEFGHIJ".into(),
                broker_cdhash: "a".repeat(40),
                supervisor_cdhash: "b".repeat(40),
                runner_cdhash: "c".repeat(40),
                service_policy_sha256: "a".repeat(64),
                guest_manifest_sha256: "b".repeat(64),
                kernel_sha256: "c".repeat(64),
                initramfs_sha256: "d".repeat(64),
                fixture_sha256: "e".repeat(64),
                upstream_ca_sha256: "f".repeat(64),
            },
        )
        .unwrap()
    }

    #[test]
    fn macos_grant_denies_each_changed_identity_and_recipe_field() {
        let original = mac_request();
        let policy = SecretPolicy {
            grants: vec![SecretGrant {
                request: original.clone(),
                approval: ApprovalRequirement::EveryRun,
            }],
        };
        assert_eq!(
            policy.authorization(&original).unwrap(),
            ApprovalRequirement::EveryRun
        );
        let encoded = serde_json::to_value(&original).unwrap();
        for field in [
            "broker_cdhash",
            "supervisor_cdhash",
            "runner_cdhash",
            "service_policy_sha256",
            "guest_manifest_sha256",
            "kernel_sha256",
            "initramfs_sha256",
            "fixture_sha256",
            "upstream_ca_sha256",
        ] {
            let mut changed = encoded.clone();
            let size = changed["macos_service"][field].as_str().unwrap().len();
            changed["macos_service"][field] = serde_json::json!("0".repeat(size));
            if field == "fixture_sha256" {
                changed["executable_sha256"] = serde_json::json!("0".repeat(64));
            }
            let changed: SecretAccessRequest = serde_json::from_value(changed).unwrap();
            changed.validate().unwrap();
            assert!(policy.authorization(&changed).is_err(), "{field}");
        }
        for (field, value) in [
            ("host", serde_json::json!("other.example.test")),
            (
                "arguments",
                serde_json::json!(["request", "--path", "/other"]),
            ),
            ("config_sha256", serde_json::json!("0".repeat(64))),
            ("macos_service", serde_json::Value::Null),
        ] {
            let mut changed = encoded.clone();
            changed[field] = value;
            let changed: SecretAccessRequest = serde_json::from_value(changed).unwrap();
            changed.validate().unwrap();
            assert!(policy.authorization(&changed).is_err(), "{field}");
        }
        let mut changed = original.clone();
        changed.macos_service.as_mut().unwrap().team_identifier = "0123456789".into();
        assert!(policy.authorization(&changed).is_err());
        let mut changed = original.clone();
        changed.config_sha256 = hex::encode(Sha256::digest(b"exact policy bytes "));
        assert!(policy.authorization(&changed).is_err());
        assert!(SecretPolicy::default().authorization(&original).is_err());
    }

    #[test]
    fn macos_binding_rejects_development_recipe_and_malformed_identity() {
        let original = serde_json::to_value(mac_request()).unwrap();
        for (field, value) in [
            ("executable", serde_json::json!("/tmp/fixture")),
            ("config_path", serde_json::json!("/tmp/policy.json")),
            ("delivery", serde_json::json!("proxy_preview")),
            ("working_directory", serde_json::json!("/tmp")),
            ("environment", serde_json::json!("development")),
            ("arguments", serde_json::json!(["other"])),
            ("executable_sha256", serde_json::json!("0".repeat(64))),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            assert!(
                serde_json::from_value::<SecretAccessRequest>(changed)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{field}"
            );
        }
        for (field, value) in [
            ("format", serde_json::json!(2)),
            ("team_identifier", serde_json::json!("bad\"team")),
            ("supervisor_cdhash", serde_json::json!("A".repeat(40))),
            ("guest_manifest_sha256", serde_json::json!("f".repeat(63))),
        ] {
            let mut changed = original.clone();
            changed["macos_service"][field] = value;
            assert!(
                serde_json::from_value::<SecretAccessRequest>(changed)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn native_requests_round_trip_without_a_macos_field() {
        let mut native = serde_json::to_value(mac_request()).unwrap();
        native.as_object_mut().unwrap().remove("macos_service");
        let parsed: SecretAccessRequest = serde_json::from_value(native.clone()).unwrap();
        assert!(parsed.macos_service.is_none());
        assert_eq!(serde_json::to_value(parsed).unwrap(), native);
    }

    #[test]
    fn native_proxy_ca_digest_is_exact_and_cannot_be_downgraded() {
        let mut request = mac_request();
        request.macos_service = None;
        request.upstream_ca_sha256 = Some("a".repeat(64));
        let policy = SecretPolicy {
            grants: vec![SecretGrant {
                request: request.clone(),
                approval: ApprovalRequirement::EveryRun,
            }],
        };
        assert_eq!(
            policy.authorization(&request).unwrap(),
            ApprovalRequirement::EveryRun
        );
        for digest in [None, Some("b".repeat(64))] {
            let mut changed = request.clone();
            changed.upstream_ca_sha256 = digest;
            assert!(policy.authorization(&changed).is_err());
        }
        let mut missing_ca = request.clone();
        missing_ca.upstream_ca_sha256 = None;
        let incomplete_policy = SecretPolicy {
            grants: vec![SecretGrant {
                request: missing_ca,
                approval: ApprovalRequirement::EveryRun,
            }],
        };
        assert!(incomplete_policy.authorization(&request).is_err());
        for digest in ["A".repeat(64), "a".repeat(63), "z".repeat(64)] {
            let mut changed = request.clone();
            changed.upstream_ca_sha256 = Some(digest);
            assert!(changed.validate().is_err());
        }
        for delivery in [DeliveryMode::Direct, DeliveryMode::ProxyPreview] {
            let mut changed = request.clone();
            changed.delivery = delivery;
            assert!(changed.validate().is_err());
        }
        let mut mac = mac_request();
        mac.upstream_ca_sha256 = request.upstream_ca_sha256;
        assert!(mac.validate().is_err());
    }
}
