//! LocalSend Headless Daemon (`localsendd`)

#![deny(unsafe_code)]

use localsend_daemon::{
    AppState, AutoAcceptMode, DaemonEvent, ReceiverServer, SessionCoordinator, TrustStore,
    build_tls_server_config, scavenge_orphaned_parts,
};
#[cfg(unix)]
use localsend_daemon::{DEFAULT_UDS_SOCKET_PATH, IpcServerState};
use localsend_discovery::PeerRegistry;
use localsend_protocol::crypto::generate_tls_identity;
use localsend_protocol::{DeviceType, InfoResponseDto, ProtocolType};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, broadcast};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "localsend_daemon=info,info".into()),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let mut cli_port = None;
    let mut cli_alias = None;
    let mut cli_save_dir = None;
    let mut cli_config_path = None;
    let mut cli_auto_accept = None;
    let mut cli_pin = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" | "-p" => {
                if let Some(val) = args.next() {
                    cli_port = val.parse::<u16>().ok();
                }
            }
            "--alias" | "-a" => {
                cli_alias = args.next();
            }
            "--save-dir" | "-d" => {
                cli_save_dir = args.next().map(PathBuf::from);
            }
            "--config" | "-c" => {
                cli_config_path = args.next().map(PathBuf::from);
            }
            "--auto-accept" => {
                if let Some(val) = args.next() {
                    match val.to_lowercase().as_str() {
                        "always" => cli_auto_accept = Some(AutoAcceptMode::Always),
                        "never" => cli_auto_accept = Some(AutoAcceptMode::Never),
                        "trusted-only" | "trusted_only" | "trusted" => {
                            cli_auto_accept = Some(AutoAcceptMode::TrustedOnly)
                        }
                        other => {
                            eprintln!("Warning: unknown auto-accept mode: {other}");
                        }
                    }
                }
            }
            "--pin" => {
                cli_pin = args.next();
            }
            "--help" | "-h" => {
                println!("LocalSend Headless Transfer Daemon (localsendd)");
                println!();
                println!("Usage: localsendd [OPTIONS]");
                println!();
                println!("Options:");
                println!("  -d, --save-dir <PATH>     Directory to store incoming files");
                println!("  -p, --port <PORT>         TCP/UDP port to listen on [default: 53317]");
                println!("  -a, --alias <NAME>        Device announcement alias");
                println!("  -c, --config <PATH>       Path to trusted_devices.yaml");
                println!(
                    "      --auto-accept <MODE>  Auto-accept mode (always, trusted-only, never)"
                );
                println!("      --pin <PIN>           Require authorization PIN");
                println!("  -h, --help                Print help");
                println!("  -V, --version             Print version");
                return Ok(());
            }
            "--version" | "-V" => {
                println!("localsendd {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            _ => {}
        }
    }

    let port: u16 = cli_port
        .or_else(|| {
            std::env::var("LOCALSEND_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
        })
        .unwrap_or(53317);

    let alias = cli_alias
        .or_else(|| std::env::var("LOCALSEND_ALIAS").ok())
        .unwrap_or_else(|| format!("localsendd-{}", &uuid::Uuid::new_v4().to_string()[..6]));

    let save_dir = cli_save_dir
        .or_else(|| std::env::var("LOCALSEND_SAVE_DIR").ok().map(PathBuf::from))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    tokio::fs::create_dir_all(&save_dir).await?;

    // Startup cleanup: scavenge orphaned .part files older than 24 hours
    let scavenged = scavenge_orphaned_parts(&save_dir, Duration::from_secs(86400)).await?;
    if scavenged > 0 {
        tracing::info!("Scavenged {scavenged} orphaned staging files from {save_dir:?}");
    }

    // Trust store configuration
    let config_path = cli_config_path
        .or_else(|| {
            std::env::var("LOCALSEND_CONFIG_PATH")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| {
            let default_dir = std::env::var("LOCALSEND_CONFIG_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/localsend"));
            default_dir.join("trusted_devices.yaml")
        });

    let mut trust_store_data = TrustStore::load_or_create(&config_path)?;
    if let Some(mode) = cli_auto_accept {
        trust_store_data.set_auto_accept_mode(mode)?;
    }
    if let Some(pin) = cli_pin {
        trust_store_data.set_pin(Some(pin))?;
    }
    let trust_store = Arc::new(RwLock::new(trust_store_data));
    tracing::info!("Loaded trust store from {:?}", config_path);

    // Event broadcast channel
    let (event_tx, _) = broadcast::channel::<DaemonEvent>(128);

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
        coordinator: coordinator.clone(),
        registry: registry.clone(),
        device_info,
        save_dir: save_dir.clone(),
        trust_store: trust_store.clone(),
        event_tx: event_tx.clone(),
    };

    let cancel_token = CancellationToken::new();
    let cancel_trigger = cancel_token.clone();

    // Start Unix Domain Socket IPC server on Unix platforms
    #[cfg(unix)]
    {
        let socket_path = std::env::var("LOCALSEND_SOCKET_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_UDS_SOCKET_PATH));

        let ipc_state = IpcServerState {
            coordinator: coordinator.clone(),
            registry: registry.clone(),
            trust_store: trust_store.clone(),
            event_tx: event_tx.clone(),
            start_time: Instant::now(),
            bound_ips: vec![],
        };

        let ipc_cancel = cancel_token.clone();
        tokio::spawn(async move {
            if let Err(e) =
                localsend_daemon::run_uds_server(&socket_path, ipc_state, ipc_cancel).await
            {
                tracing::error!("IPC UDS server error: {e}");
            }
        });
    }

    let server = ReceiverServer::new(state, tls_config);
    let bind_addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!("Receiver listening on https://{bind_addr} (saving to {save_dir:?})");

    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Termination signal received, beginning graceful drain...");
        cancel_trigger.cancel();
    });

    server.run(listener, cancel_token).await?;
    tracing::info!("localsendd exited cleanly");

    Ok(())
}
