//! `lsend trust` subcommand
//!
//! Manages persistent trust store policies and pinned device fingerprints via IPC.

use crate::ipc_client::IpcClient;
use console::style;
use std::path::PathBuf;

/// Execute the `lsend trust add` command.
pub async fn add(
    fingerprint: String,
    alias: String,
    socket_path: Option<PathBuf>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = socket_path.unwrap_or_else(|| PathBuf::from(IpcClient::DEFAULT_PATH));
    let mut client = IpcClient::connect(&path).await?;
    client
        .add_trust(fingerprint.clone(), alias.clone())
        .await?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "action": "trust_add",
                "fingerprint": fingerprint,
                "alias": alias,
                "success": true
            })
        );
    } else {
        println!(
            "{} Peer '{}' [{}] added to trusted store.",
            style("✔").green().bold(),
            style(&alias).bold(),
            style(&fingerprint).dim()
        );
    }

    Ok(())
}
