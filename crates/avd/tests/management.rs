use av_core::create_vault;
use avd::{
    management::ManagementOperation,
    session::{AdminRequest, AdminServer, Session, VaultSource, admin_call},
};
use std::{fs, sync::Arc};

#[tokio::test]
async fn private_admin_management_rejects_invalid_capability_and_unlocked_state() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.db");
    let created = create_vault(&path, "synthetic passphrase").unwrap();
    drop(created);
    let session = Session::locked(VaultSource {
        vault: path.clone(),
        proxy_policy: None,
        service_mode: false,
    })
    .unwrap();
    let admin = AdminServer::bind(directory.path(), Arc::clone(&session))
        .await
        .unwrap();
    let token = fs::read_to_string(directory.path().join("admin.token")).unwrap();
    let task = tokio::spawn(admin.run());
    let socket = directory.path().join("admin.sock");
    let operation = || ManagementOperation::Add {
        name: "demo/token".into(),
        value: "av-synthetic-must-not-appear".into(),
    };
    let reply = admin_call(
        &socket,
        &AdminRequest::Manage {
            token: "ab".repeat(32),
            passphrase: "synthetic passphrase".into(),
            operation: operation(),
        },
    )
    .await
    .unwrap();
    assert_eq!(reply.error.as_deref(), Some("unauthorized"));
    assert!(
        !serde_json::to_string(&reply)
            .unwrap()
            .contains("av-synthetic-must-not-appear")
    );
    let reply = admin_call(
        &socket,
        &AdminRequest::Manage {
            token: token.clone(),
            passphrase: "synthetic passphrase".into(),
            operation: operation(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        reply.error.as_deref(),
        Some("management requires an installed service vault")
    );
    assert!(session.is_locked().await);
    assert!(
        admin_call(
            &socket,
            &AdminRequest::Unlock {
                token: token.clone(),
                passphrase: "synthetic passphrase".into()
            }
        )
        .await
        .unwrap()
        .ok
    );
    let reply = admin_call(
        &socket,
        &AdminRequest::Manage {
            token: token.clone(),
            passphrase: "synthetic passphrase".into(),
            operation: operation(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        reply.error.as_deref(),
        Some("lock the broker before managing its vault")
    );
    assert!(
        !serde_json::to_string(&reply)
            .unwrap()
            .contains("av-synthetic-must-not-appear")
    );
    assert!(
        !av_core::Vault::open(&path, "synthetic passphrase")
            .unwrap()
            .exists("demo/token")
            .unwrap()
    );
    session.lock().await;
    task.abort();
    let _ = task.await;
}
