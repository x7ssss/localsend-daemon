//! `lsend peers` subcommand
//!
//! Queries discovered peer table cached in running daemon's in-memory registry.

use crate::ipc_client::IpcClient;
use console::style;
use std::path::PathBuf;

/// Execute the `lsend peers` command.
pub async fn run(
    socket_path: Option<PathBuf>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = socket_path.unwrap_or_else(|| PathBuf::from(IpcClient::DEFAULT_PATH));
    let mut client = IpcClient::connect(&path).await?;
    let peers = client.get_peers().await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&peers)?);
    } else {
        if peers.is_empty() {
            println!("{}", style("No peers registered in daemon cache.").yellow());
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
                let dev = p.device_model.unwrap_or_else(|| "Unknown".to_string());
                let addr = format!("{}", p.ip);
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
