//! `lsend accept` and `lsend reject` subcommands
//!
//! Interactively approves or declines pending inbound transfer sessions via IPC.

use crate::ipc_client::IpcClient;
use console::style;
use std::path::PathBuf;

/// Execute the `lsend accept` command.
pub async fn accept(
    session_id: String,
    socket_path: Option<PathBuf>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = socket_path.unwrap_or_else(|| PathBuf::from(IpcClient::DEFAULT_PATH));
    let mut client = IpcClient::connect(&path).await?;
    client.accept_session(session_id.clone()).await?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "action": "accept",
                "session_id": session_id,
                "success": true
            })
        );
    } else {
        println!(
            "{} Session {} approved for transfer.",
            style("✔").green().bold(),
            style(session_id).cyan()
        );
    }

    Ok(())
}

/// Execute the `lsend reject` command.
pub async fn reject(
    session_id: String,
    reason: Option<String>,
    socket_path: Option<PathBuf>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = socket_path.unwrap_or_else(|| PathBuf::from(IpcClient::DEFAULT_PATH));
    let mut client = IpcClient::connect(&path).await?;
    client
        .reject_session(session_id.clone(), reason.clone())
        .await?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "action": "reject",
                "session_id": session_id,
                "reason": reason,
                "success": true
            })
        );
    } else {
        println!(
            "{} Session {} rejected.",
            style("✘").red().bold(),
            style(session_id).cyan()
        );
    }

    Ok(())
}
