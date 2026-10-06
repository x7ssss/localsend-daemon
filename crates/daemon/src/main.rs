//! LocalSend Headless Daemon (`localsendd`)

#![deny(unsafe_code)]

use localsend_daemon::{
    build_tls_server_config, scavenge_orphaned_parts, AppState, ReceiverServer,
    SessionCoordinator,
};
use localsend_discovery::PeerRegistry;
use localsend_protocol::crypto::generate_tls_identity;
use localsend_protocol::{DeviceType, InfoResponseDto, ProtocolType};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "localsend_daemon=info,info".into()),
        )
        .init();

    let port: u16 = std::env::var("LOCALSEND_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(53317);

    let alias = std::env::var("LOCALSEND_ALIAS")
        .unwrap_or_else(|_| format!("localsendd-{}", &uuid::Uuid::new_v4().to_string()[..6]));

    let save_dir = std::env::var("LOCALSEND_SAVE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    tokio::fs::create_dir_all(&save_dir).await?;

    // Startup cleanup: scavenge orphaned .part files older than 24 hours
    let scavenged = scavenge_orphaned_parts(&save_dir, Duration::from_secs(86400)).await?;
    if scavenged > 0 {
        tracing::info!("Scavenged {scavenged} orphaned staging files from {save_dir:?}");
    }

    // Generate in-memory TLS identity
    let identity = generate_tls_identity(&alias, &[])?;
    let tls_config = build_tls_server_config(&identity)?;

    tracing::info!(
        "Initialized LocalSend node '{}' (fingerprint: {})",
        alias,
        identity.fingerprint
    );

    let device_info = InfoResponseDto {
        alias: alias.clone(),
        version: "2.0".to_string(),
        device_model: Some("localsendd headless".to_string()),
        device_type: Some(DeviceType::Headless),
        fingerprint: identity.fingerprint,
        port,
        protocol: ProtocolType::Https,
        download: true,
    };

    let coordinator = SessionCoordinator::default();
    let registry = PeerRegistry::new();

    let state = AppState {
        coordinator,
        registry,
        device_info,
        save_dir: save_dir.clone(),
    };

    let server = ReceiverServer::new(state, tls_config);
    let bind_addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!("Receiver listening on https://{bind_addr} (saving to {save_dir:?})");

    let cancel_token = CancellationToken::new();
    let cancel_trigger = cancel_token.clone();

    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Termination signal received, beginning graceful drain...");
        cancel_trigger.cancel();
    });

    server.run(listener, cancel_token).await?;
    tracing::info!("localsendd exited cleanly");

    Ok(())
}
