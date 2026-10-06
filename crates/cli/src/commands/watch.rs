//! `lsend watch` subcommand
//!
//! Subscribes to daemon IPC event stream, displaying real-time incoming transfer
//! requests, transfer progress, and peer discovery events.

use crate::ipc_client::IpcClient;
use console::style;
use futures_util::StreamExt;
use localsend_daemon::DaemonEvent;
use std::path::PathBuf;

/// Execute the `lsend watch` command.
pub async fn run(
    socket_path: Option<PathBuf>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = socket_path.unwrap_or_else(|| PathBuf::from(IpcClient::DEFAULT_PATH));

    #[cfg(unix)]
    let client = IpcClient::connect(&path).await?;

    #[cfg(not(unix))]
    let client = IpcClient::connect(&path).await?; // Will return clean platform error

    if !json_output {
        eprintln!(
            "{}",
            style("Subscribing to LocalSend daemon event stream (press Ctrl+C to exit)...")
                .cyan()
                .bold()
        );
    }

    let mut stream = client.subscribe_events().await?;

    while let Some(event_res) = stream.next().await {
        match event_res {
            Ok(event) => {
                if json_output {
                    println!("{}", serde_json::to_string(&event)?);
                } else {
                    display_event(&event);
                }
            }
            Err(e) => {
                eprintln!("{}", style(format!("Event stream error: {e}")).red());
                break;
            }
        }
    }

    Ok(())
}

fn display_event(event: &DaemonEvent) {
    match event {
        DaemonEvent::IncomingSession {
            session_id,
            peer_alias,
            peer_ip,
            files,
        } => {
            let total_bytes: u64 = files.iter().map(|f| f.size).sum();
            println!(
                "\n{}",
                style("🔔 INCOMING TRANSFER REQUEST").yellow().bold()
            );
            println!("   Sender:  {} ({})", style(peer_alias).bold(), peer_ip);
            println!("   Session: {}", style(session_id).cyan());
            println!(
                "   Files:   {} file(s) (total {})",
                files.len(),
                indicatif::HumanBytes(total_bytes)
            );
            for f in files {
                println!("     - {} ({})", f.file_name, indicatif::HumanBytes(f.size));
            }
            println!(
                "   👉 Run {} to accept or {} to decline.\n",
                style(format!("lsend accept {session_id}")).green().bold(),
                style(format!("lsend reject {session_id}")).red().bold()
            );
        }
        DaemonEvent::TransferProgress {
            session_id,
            file_id,
            bytes_written,
            total_bytes,
        } => {
            println!(
                "{} [{}] File {}: {} / {}",
                style("⏳ PROGRESS").blue(),
                &session_id[..8.min(session_id.len())],
                file_id,
                indicatif::HumanBytes(*bytes_written),
                indicatif::HumanBytes(*total_bytes)
            );
        }
        DaemonEvent::TransferComplete {
            session_id,
            file_id,
            success,
        } => {
            if *success {
                println!(
                    "{} [{}] File {} transfer finished",
                    style("✅ COMPLETE").green(),
                    &session_id[..8.min(session_id.len())],
                    file_id
                );
            } else {
                println!(
                    "{} [{}] File {} transfer failed",
                    style("❌ FAILED").red(),
                    &session_id[..8.min(session_id.len())],
                    file_id
                );
            }
        }
        DaemonEvent::SessionTerminated { session_id, reason } => {
            println!(
                "{} [{}] Session terminated: {}",
                style("⏹ TERMINATED").magenta(),
                &session_id[..8.min(session_id.len())],
                reason
            );
        }
        DaemonEvent::PeerDiscovered(p) => {
            println!(
                "{} Discovered '{}' at {}:{}",
                style("📡 PEER").cyan(),
                p.alias,
                p.ip,
                p.port
            );
        }
        DaemonEvent::PeerLost(fp) => {
            println!(
                "{} Peer lost ({})",
                style("💨 LOST").dim(),
                &fp[..16.min(fp.len())]
            );
        }
    }
}
