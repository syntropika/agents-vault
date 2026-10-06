use std::fs;

use av_core::{
    ApprovalRequirement, DeliveryMode, SecretAccessRequest, SecretGrant, SecretPolicy, Vault,
    backup_vault, create_vault, restore_vault,
};
use zeroize::Zeroizing;

fn request(directory: &std::path::Path) -> SecretAccessRequest {
    let config = directory.join("av.toml");
    fs::write(&config, "schema = 2\n[project]\nid = 'demo'\n").unwrap();
    SecretAccessRequest::for_command(
        &[
            std::env::current_exe()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned(),
            "--task".to_owned(),
        ],
        &config,
        &fs::read(&config).unwrap(),
        None,
        DeliveryMode::Direct,
        None,
    )
    .unwrap()
}

#[test]
fn policy_is_default_deny_and_binds_every_release_dimension() {
    let directory = tempfile::tempdir().unwrap();
    let created = create_vault(directory.path().join("vault.db"), "passphrase").unwrap();
    let vault = created.vault;
    vault.add("demo/token", "synthetic-value").unwrap();
    let request = request(directory.path());
    assert!(vault.get_authorized("demo/token", &request, true).is_err());
    vault
        .set_policy(
            "demo/token",
            &SecretPolicy {
                grants: vec![SecretGrant {
                    request: request.clone(),
                    approval: ApprovalRequirement::EveryRun,
                }],
            },
        )
        .unwrap();
    assert!(vault.get_authorized("demo/token", &request, false).is_err());
    assert_eq!(
        vault
            .get_authorized("demo/token", &request, true)
            .unwrap()
            .as_deref(),
        Some("synthetic-value")
    );
    let mut changes = Vec::new();
    let mut changed = request.clone();
    changed.arguments.push("--changed".into());
    changes.push(changed);
    let mut changed = request.clone();
    changed.executable_sha256 = "a".repeat(64);
    changes.push(changed);
    let mut changed = request.clone();
    changed.config_sha256 = "b".repeat(64);
    changes.push(changed);
    let mut changed = request.clone();
    changed.environment = Some("production".into());
    changes.push(changed);
    let mut changed = request.clone();
    changed.working_directory.push_str("/different");
    changes.push(changed);
    let mut changed = request.clone();
    changed.delivery = DeliveryMode::ProxyPreview;
    changed.host = Some("api.example.test".into());
    changes.push(changed);
    for changed in changes {
        assert!(vault.get_authorized("demo/token", &changed, true).is_err());
    }
    let mut policy = vault.policy("demo/token").unwrap();
    policy.grants.push(SecretGrant {
        request: request.clone(),
        approval: ApprovalRequirement::Preapproved,
    });
    vault.set_policy("demo/token", &policy).unwrap();
    assert!(vault.get_authorized("demo/token", &request, false).is_err());
    vault.rotate("demo/token", "replacement").unwrap();
    assert_eq!(vault.policy("demo/token").unwrap(), policy);
    vault
        .set_policy("demo/token", &SecretPolicy::default())
        .unwrap();
    assert!(vault.get_authorized("demo/token", &request, true).is_err());
}

#[test]
fn proxy_policy_pins_host_and_cannot_cross_delivery_modes() {
    let directory = tempfile::tempdir().unwrap();
    let mut request = request(directory.path());
    request.delivery = DeliveryMode::ProtectedProxy;
    request.host = Some("api.example.test".to_owned());
    let policy = SecretPolicy {
        grants: vec![SecretGrant {
            request: request.clone(),
            approval: ApprovalRequirement::Preapproved,
        }],
    };
    assert!(policy.authorization(&request).is_ok());
    request.host = Some("attacker.example".to_owned());
    assert!(policy.authorization(&request).is_err());
    request.host = Some("api.example.test".to_owned());
    request.delivery = DeliveryMode::ProxyPreview;
    assert!(policy.authorization(&request).is_err());
    request.host = Some("*.example.test".to_owned());
    assert!(request.validate().is_err());
}

#[test]
fn add_rotate_and_import_do_not_silently_replace_secrets() {
    let directory = tempfile::tempdir().unwrap();
    let vault = create_vault(directory.path().join("vault.db"), "passphrase")
        .unwrap()
        .vault;
    vault.add("demo/existing", "original").unwrap();
    assert!(vault.add("demo/existing", "replacement").is_err());
    assert!(vault.rotate("demo/missing", "replacement").is_err());
    assert!(
        vault
            .import(&[
                ("demo/new".into(), Zeroizing::new("new".into())),
                ("demo/existing".into(), Zeroizing::new("replacement".into()))
            ])
            .is_err()
    );
    assert!(!vault.exists("demo/new").unwrap());
    assert_eq!(
        vault.get("demo/existing").unwrap().as_deref(),
        Some("original")
    );
}

#[test]
fn encrypted_backup_restores_values_and_policy_and_rejects_bad_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.db");
    let destination = directory.path().join("restored.db");
    let backup = directory.path().join("backup.avbackup");
    let vault = create_vault(&source, "passphrase").unwrap().vault;
    vault.add("demo/token", "synthetic-secret-value").unwrap();
    let policy = SecretPolicy {
        grants: vec![SecretGrant {
            request: request(directory.path()),
            approval: ApprovalRequirement::EveryRun,
        }],
    };
    vault.set_policy("demo/token", &policy).unwrap();
    backup_vault(&source, "passphrase", &backup).unwrap();
    assert!(
        !fs::read_to_string(&backup)
            .unwrap()
            .contains("synthetic-secret-value")
    );
    assert!(backup_vault(&source, "passphrase", &backup).is_err());
    assert!(restore_vault(&backup, &destination, "wrong").is_err());
    assert!(!destination.exists());
    restore_vault(&backup, &destination, "passphrase").unwrap();
    let restored = Vault::open(&destination, "passphrase").unwrap();
    assert_eq!(
        restored.get("demo/token").unwrap().as_deref(),
        Some("synthetic-secret-value")
    );
    assert_eq!(restored.policy("demo/token").unwrap(), policy);
    assert!(restore_vault(&backup, &destination, "passphrase").is_err());
    let mut archive: serde_json::Value =
        serde_json::from_slice(&fs::read(&backup).unwrap()).unwrap();
    let mut damaged = archive["database_hex"].as_str().unwrap().to_owned();
    damaged.replace_range(0..64, &"0".repeat(64));
    archive["database_hex"] = damaged.into();
    let corrupt = directory.path().join("corrupt.avbackup");
    fs::write(&corrupt, serde_json::to_vec(&archive).unwrap()).unwrap();
    let rejected = directory.path().join("rejected.db");
    assert!(restore_vault(&corrupt, &rejected, "passphrase").is_err());
    assert!(!rejected.exists());
    assert!(!rejected.with_extension("keys.json").exists());
}
