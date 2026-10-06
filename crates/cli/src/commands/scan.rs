//! `lsend scan` subcommand
//!
//! Discovers nearby LocalSend peers using passive UDP multicast and optional active subnet HTTP probe.

use console::style;
use localsend_discovery::{DiscoveryEngine, MulticastConfig, PeerRegistry};
use localsend_protocol::{MulticastAnnouncement, ProtocolType, RegisterDto};
use std::time::Duration;

/// Peer entry serialized when `--json` flag is provided.
#[derive(serde::Serialize)]
pub struct DiscoveredPeerOutput {
    /// Human-friendly device alias.
    pub alias: String,
    /// Hardware/device model name.
    pub device_model: Option<String>,
    /// Device category.
    pub device_type: Option<String>,
    /// IP address string.
    pub ip: String,
    /// Listening TCP port.
    pub port: u16,
    /// Protocol (http or https).
    pub protocol: String,
    /// SHA-256 certificate fingerprint.
    pub fingerprint: String,
}

/// Execute the `lsend scan` command.
pub async fn run(
    duration_secs: u64,
    http_scan: bool,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let registry = PeerRegistry::new();

    let announcement = MulticastAnnouncement::new(
        "lsend-scanner",
        "SCANNER_TEMP_FP",
        53317,
        ProtocolType::Https,
    );

    let config = MulticastConfig {
        port: 53317,
        local_fingerprint: "SCANNER_TEMP_FP".to_string(),
        heartbeat_interval: Duration::from_millis(500),
    };

    if !json_output {
        eprintln!(
            "{}",
            style(format!(
                "Scanning local network for LocalSend peers ({duration_secs}s)..."
            ))
            .cyan()
            .bold()
        );
    }

    let engine = DiscoveryEngine::new(config, registry.clone())?;
    let (rx_handle, hb_handle) = engine.start(announcement.clone());

    if http_scan {
        let our_dto: RegisterDto = announcement.into();
        let _ = engine.sweep_subnets(our_dto).await;
    }

    tokio::time::sleep(Duration::from_secs(duration_secs)).await;
    engine.stop();
    rx_handle.abort();
    hb_handle.abort();

    let peers = registry.list().await;

    if json_output {
        let outputs: Vec<DiscoveredPeerOutput> = peers
            .into_iter()
            .map(|p| DiscoveredPeerOutput {
                alias: p.alias,
                device_model: p.device_model,
                device_type: p.device_type.map(|d| format!("{d:?}")),
                ip: p.ip.to_string(),
                port: p.port,
                protocol: p.protocol.to_string(),
                fingerprint: p.fingerprint,
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&outputs)?);
    } else {
        if peers.is_empty() {
            println!(
                "{}",
                style("No LocalSend peers discovered on the local network.").yellow()
            );
        } else {
            println!(
                "\n{:<20} {:<16} {:<20} {:<8} {:<32}",
                style("ALIAS").bold(),
                style("DEVICE").bold(),
                style("ADDRESS").bold(),
                style("PORT").bold(),
                style("FINGERPRINT").bold()
            );
            println!("{}", "-".repeat(100));
            for p in peers {
                let addr = format!("{}", p.ip);
                let dev = p
                    .device_model
                    .or_else(|| p.device_type.map(|d| format!("{d:?}")))
                    .unwrap_or_else(|| "Unknown".to_string());
                let short_fp = if p.fingerprint.len() > 18 {
                    format!("{}...", &p.fingerprint[..18])
                } else {
                    p.fingerprint
                };

                println!(
                    "{:<20} {:<16} {:<20} {:<8} {:<32}",
                    style(p.alias).green().bold(),
                    dev,
                    addr,
                    p.port,
                    style(short_fp).dim()
                );
            }
            println!();
        }
    }

    Ok(())
}
