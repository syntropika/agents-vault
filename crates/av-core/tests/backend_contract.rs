use std::{
    collections::BTreeMap,
    sync::{Arc, Barrier, Mutex},
};

use anyhow::{Result, ensure};
use av_core::backend::{BackendEntry, BackendMutation, SecretBackend};
use av_core::store::SqlCipherBackend;
use av_core::{
    ApprovalRequirement, DeliveryMode, SecretAccessRequest, SecretGrant, SecretPolicy, Vault,
    create_vault,
};

#[derive(Clone, Default)]
struct MemoryBackend(Arc<Mutex<BTreeMap<String, BackendEntry>>>);

impl SecretBackend for MemoryBackend {
    fn read(&self, key: &str) -> Result<Option<BackendEntry>> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }

    fn list(&self) -> Result<Vec<String>> {
        Ok(self.0.lock().unwrap().keys().cloned().collect())
    }

    fn apply(&self, mutations: &[BackendMutation]) -> Result<()> {
        let mut entries = self.0.lock().unwrap();
        let mut keys = std::collections::HashSet::new();
        for mutation in mutations {
            ensure!(keys.insert(&mutation.key), "duplicate key");
            ensure!(
                entries.get(&mutation.key) == mutation.expected.as_ref(),
                "conflict"
            );
        }
        for mutation in mutations {
            match &mutation.replacement {
                Some(entry) => {
                    entries.insert(mutation.key.clone(), entry.clone());
                }
                None => {
                    entries.remove(&mutation.key);
                }
            }
        }
        Ok(())
    }
}

fn mutation(key: &str, expected: Option<BackendEntry>, value: Option<&str>) -> BackendMutation {
    BackendMutation {
        key: key.into(),
        expected,
        replacement: value.map(|value| BackendEntry::new(value.into())),
    }
}

fn storage_contract(backend: &dyn SecretBackend) {
    backend
        .apply(&[
            mutation("demo/b", None, Some("b")),
            mutation("demo/a", None, Some("a")),
        ])
        .unwrap();
    assert_eq!(backend.list().unwrap(), ["demo/a", "demo/b"]);
    let previous = backend.read("demo/a").unwrap().unwrap();
    let mut policy_changed = previous.clone();
    policy_changed.policy = Some("opaque policy metadata".into());
    backend
        .apply(&[BackendMutation {
            key: "demo/a".into(),
            expected: Some(previous.clone()),
            replacement: Some(policy_changed.clone()),
        }])
        .unwrap();
    // Matching the credential alone must not overwrite a concurrent policy change.
    assert!(
        backend
            .apply(&[mutation("demo/a", Some(previous), Some("stale"))])
            .is_err()
    );
    // The valid first write must also roll back when the second expectation fails.
    assert!(
        backend
            .apply(&[
                mutation("demo/c", None, Some("c")),
                mutation("demo/a", None, Some("conflict"))
            ])
            .is_err()
    );
    assert!(backend.read("demo/c").unwrap().is_none());
    assert_eq!(
        backend.read("demo/a").unwrap(),
        Some(policy_changed.clone())
    );
    assert!(
        backend
            .apply(&[
                mutation("demo/c", None, Some("c")),
                mutation("demo/c", None, Some("duplicate"))
            ])
            .is_err()
    );
    assert!(backend.read("demo/c").unwrap().is_none());
    backend
        .apply(&[mutation("demo/a", Some(policy_changed), None)])
        .unwrap();
    assert!(backend.read("demo/a").unwrap().is_none());
    backend
        .apply(&[mutation("demo/a", None, Some("fresh"))])
        .unwrap();
    assert!(backend.read("demo/a").unwrap().unwrap().policy.is_none());
}

#[test]
fn memory_adapter_obeys_storage_contract() {
    storage_contract(&MemoryBackend::default());
}

#[test]
fn sqlcipher_adapter_obeys_storage_contract() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.db");
    drop(create_vault(&path, "test passphrase").unwrap());
    storage_contract(&SqlCipherBackend::open(path, "test passphrase").unwrap());
}

#[test]
fn sqlcipher_competing_sessions_cannot_both_publish_the_same_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.db");
    let created = create_vault(&path, "test passphrase").unwrap();
    created.vault.add("demo/a", "original").unwrap();
    drop(created);
    let first = SqlCipherBackend::open(&path, "test passphrase").unwrap();
    let second = SqlCipherBackend::open(&path, "test passphrase").unwrap();
    let snapshot = first.read("demo/a").unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let tasks: Vec<_> = [(first, "first"), (second, "second")]
        .into_iter()
        .map(|(backend, value)| {
            let barrier = Arc::clone(&barrier);
            let snapshot = snapshot.clone();
            std::thread::spawn(move || {
                barrier.wait();
                backend
                    .apply(&[mutation("demo/a", snapshot, Some(value))])
                    .is_ok()
            })
        })
        .collect();
    let successes = tasks
        .into_iter()
        .map(|task| task.join().unwrap())
        .filter(|succeeded| *succeeded)
        .count();
    assert_eq!(successes, 1);
    let vault = Vault::open(path, "test passphrase").unwrap();
    assert!(matches!(
        vault.get("demo/a").unwrap().as_deref(),
        Some("first" | "second")
    ));
}

fn request() -> SecretAccessRequest {
    SecretAccessRequest {
        executable: "/synthetic/tool".into(),
        executable_sha256: "a".repeat(64),
        arguments: vec![],
        config_path: "/synthetic/av.toml".into(),
        config_sha256: "b".repeat(64),
        working_directory: "/synthetic".into(),
        environment: None,
        delivery: DeliveryMode::ProtectedProxy,
        host: Some("api.example.test".into()),
        macos_service: None,
        upstream_ca_sha256: None,
    }
}

#[test]
fn vault_enforces_connection_policy_with_an_alternative_adapter() {
    let vault = Vault::from_backend(MemoryBackend::default());
    let request = request();
    vault
        .add_connection("service/work", "api.example.test", "first")
        .unwrap();
    assert!(
        vault
            .get_connection_authorized("service/work", 1, &request, true)
            .is_err()
    );
    let policy = SecretPolicy {
        grants: vec![SecretGrant {
            request: request.clone(),
            approval: ApprovalRequirement::EveryRun,
        }],
    };
    vault
        .set_connection_policy("service/work", 1, &policy)
        .unwrap();
    assert!(
        vault
            .get_connection_authorized("service/work", 1, &request, false)
            .is_err()
    );
    assert_eq!(
        vault
            .get_connection_authorized("service/work", 1, &request, true)
            .unwrap()
            .as_str(),
        "first"
    );
    let mut changed = request.clone();
    changed.arguments.push("different".into());
    assert!(
        vault
            .get_connection_authorized("service/work", 1, &changed, true)
            .is_err()
    );
    assert_eq!(
        vault
            .replace_connection("service/work", 1, "second")
            .unwrap()
            .version,
        2
    );
    assert!(
        vault
            .get_connection_authorized("service/work", 1, &request, true)
            .is_err()
    );
    assert!(
        vault
            .connection_policy("service/work", 2)
            .unwrap()
            .grants
            .is_empty()
    );
    vault
        .set_connection_policy("service/work", 2, &policy)
        .unwrap();
    vault.revoke_connection_grants("service/work", 2).unwrap();
    assert!(
        vault
            .get_connection_authorized("service/work", 2, &request, true)
            .is_err()
    );
    vault.disconnect_connection("service/work", 2).unwrap();
    assert!(vault.connection_credential("service/work", 3).is_err());
    assert!(!vault.list_connections().unwrap()[0].active);
    for key in vault.list().unwrap() {
        assert!(vault.get(&key).is_err());
    }

    vault.add("demo/token", "value").unwrap();
    assert!(vault.get_authorized("demo/token", &request, true).is_err());
    vault.set_policy("demo/token", &policy).unwrap();
    vault.rotate("demo/token", "rotated").unwrap();
    assert!(vault.get_authorized("demo/token", &request, false).is_err());
    assert_eq!(
        vault
            .get_authorized("demo/token", &request, true)
            .unwrap()
            .as_deref(),
        Some("rotated")
    );
    assert!(
        !format!("{:?}", BackendEntry::new("private credential".into()))
            .contains("private credential")
    );
}
