//! `lsend status` subcommand
//!
//! Queries running daemon operational health, uptime, and active transfer sessions.

use crate::ipc_client::IpcClient;
use console::style;
use std::path::PathBuf;

/// Execute the `lsend status` command.
pub async fn run(
    socket_path: Option<PathBuf>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = socket_path.unwrap_or_else(|| PathBuf::from(IpcClient::DEFAULT_PATH));
    let mut client = IpcClient::connect(&path).await?;
    let status = client.get_status().await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("{}", style("LocalSend Daemon Status").green().bold());
        println!("{}", "-".repeat(40));
        println!("  Uptime:         {}s", status.uptime_secs);
        println!(
            "  Active Session: {}",
            status
                .active_session
                .as_deref()
                .unwrap_or("None (Idle)")
        );
        println!(
            "  Bound IPs:      {}",
            if status.bound_ips.is_empty() {
                "All interfaces (0.0.0.0)".to_string()
            } else {
                status
                    .bound_ips
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        );
    }

    Ok(())
}
