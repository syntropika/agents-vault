use avd::{
    ipc::{ClientConfig, PeerPolicy, Server, ServerConfig},
    session::{AdminServer, Session, VaultSource},
};
use std::{path::PathBuf, sync::Arc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::var_os("AVD_RUNTIME_DIR")
        .map(PathBuf::from)
        .ok_or("set AVD_RUNTIME_DIR to a private directory")?;
    let service_agent_uid = std::env::var("AVD_SERVICE_AGENT_UID")
        .ok()
        .map(|value| value.parse::<u32>())
        .transpose()?;
    let mac_service = match std::env::var("AVD_MAC_SERVICE") {
        Ok(value) if value == "1" => true,
        Err(std::env::VarError::NotPresent) => false,
        _ => return Err("AVD_MAC_SERVICE must be 1 when present".into()),
    };
    #[cfg(not(target_os = "macos"))]
    if mac_service {
        return Err("macOS service mode is unavailable on this platform".into());
    }
    if mac_service && service_agent_uid.is_some() {
        return Err("macOS service mode does not use AVD_SERVICE_AGENT_UID".into());
    }
    let _service_state_guard = if service_agent_uid.is_some() || mac_service {
        Some(avd::management::bootstrap::hold_service_state()?)
    } else {
        None
    };
    if let Some(agent_uid) = service_agent_uid {
        avd::service::validate_service_identity(agent_uid)?;
        avd::service::validate_trusted_path(&base, false)?;
        if base.as_path() != std::path::Path::new("/run/agents-vault") {
            return Err("service runtime directory must be /run/agents-vault".into());
        }
    } else if !mac_service {
        std::fs::create_dir_all(&base)?;
    }
    #[cfg(target_os = "macos")]
    let (mac_agent_uid, _mac_runtime_guard) = if mac_service {
        use av_vmm::service;
        service::validate_broker_identity()?;
        if base.as_path() != std::path::Path::new(service::BROKER_RUNTIME) {
            return Err("macOS service requires the installed private runtime directory".into());
        }
        let agent_uid: u32 = std::env::var("AVD_MAC_AGENT_UID")
            .map_err(|_| "configure AVD_MAC_AGENT_UID before starting the macOS broker")?
            .parse()?;
        service::validate_agent_uid(agent_uid)?;
        (Some(agent_uid), Some(service::prepare_broker_runtime()?))
    } else {
        (None, None)
    };
    if std::env::var_os("AVD_PASSPHRASE_FILE").is_some() {
        return Err("startup passphrase files are disabled; use av-operator unlock on the private admin channel".into());
    }
    let vault = std::env::var_os("AVD_VAULT_PATH").ok_or("AVD_VAULT_PATH is required")?;
    let session = Session::locked(VaultSource {
        vault: PathBuf::from(vault),
        proxy_policy: std::env::var_os("AVD_PROXY_POLICY_PATH").map(PathBuf::from),
        service_mode: service_agent_uid.is_some() || mac_service,
    })?;
    let uid = unsafe { libc::geteuid() };
    let agent_uid = service_agent_uid.unwrap_or(uid);
    #[cfg(target_os = "macos")]
    let agent_uid = mac_agent_uid.unwrap_or(agent_uid);
    let peers = PeerPolicy { agent_uid };
    let client_uid = match std::env::var("AVD_CLIENT_UID") {
        Ok(value) => Some(value.parse::<u32>()?),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.into()),
    };
    if client_uid.is_some_and(|client_uid| {
        (service_agent_uid.is_none() && !mac_service) || client_uid == 0 || client_uid == uid
    }) {
        return Err(
            "client endpoint requires an installed service and a distinct non-root client UID"
                .into(),
        );
    }
    #[cfg(target_os = "macos")]
    if mac_service && let Some(client_uid) = client_uid {
        av_vmm::service::validate_agent_uid(client_uid)?;
    }
    let agent_socket = base.join("agent.sock");
    #[cfg(target_os = "macos")]
    let agent_socket = if mac_service {
        PathBuf::from(av_vmm::service::AGENT_SOCKET)
    } else {
        agent_socket
    };
    let client_socket = agent_socket.with_file_name("client.sock");
    let server = Server::bind_with_session_and_client(
        ServerConfig { agent_socket },
        Arc::clone(&session),
        peers,
        client_uid.map(|uid| ClientConfig {
            socket: client_socket,
            uid,
        }),
    )
    .await?;
    let admin = AdminServer::bind(&base, Arc::clone(&session)).await?;
    let approval_ui = match std::env::var("AVD_APPROVAL_UI") {
        Ok(value) if value == "1" => Some(
            avd::approval::ApprovalServer::bind(Arc::clone(&session), avd::approval::APPROVAL_PORT)
                .await?,
        ),
        Err(std::env::VarError::NotPresent) => None,
        _ => return Err("AVD_APPROVAL_UI must be 1 when present".into()),
    };
    println!(
        "avd synthetic broker listening in {}; locked={}",
        base.display(),
        session.is_locked().await
    );
    let result = tokio::select! {
        result = server.run(std::future::pending()) => result,
        result = admin.run() => result,
        result = async {
            match approval_ui { Some(server) => server.run().await, None => std::future::pending().await }
        } => result,
        _ = shutdown_signal() => Ok(()),
    };
    session.lock().await;
    result?;
    Ok(())
}

async fn shutdown_signal() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = terminate.recv() => {},
    }
}
