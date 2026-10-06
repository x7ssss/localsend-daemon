//! LocalSend Command-Line Utility (`lsend`)
//!
//! Provides command-line file transfer, peer discovery, daemon status querying,
//! live event streaming, and interactive transfer approvals.

#![deny(unsafe_code)]

use clap::Parser;
use localsend_cli::commands::{peers, scan, send, session, status, trust, watch};
use localsend_cli::{Cli, Commands, TrustAction};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let json_output = cli.json;

    if let Err(e) = run_app(cli).await {
        if json_output {
            println!("{}", serde_json::json!({ "error": e.to_string() }));
        } else {
            eprintln!("{} {}", console::style("error:").red().bold(), e);
        }
        std::process::exit(1);
    }
}

async fn run_app(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let json = cli.json;
    let socket = cli.socket;

    match cli.command {
        Commands::Scan {
            duration,
            http_scan,
        } => scan::run(duration, http_scan, json).await,

        Commands::Send {
            target,
            files,
            pin,
            fingerprint,
            standalone,
        } => send::run(&target, &files, pin, fingerprint, standalone, json).await,

        Commands::Watch => watch::run(socket, json).await,

        Commands::Accept { session_id } => session::accept(session_id, socket, json).await,

        Commands::Reject { session_id, reason } => {
            session::reject(session_id, reason, socket, json).await
        }

        Commands::Status => status::run(socket, json).await,

        Commands::Peers => peers::run(socket, json).await,

        Commands::Trust { action } => match action {
            TrustAction::Add { fingerprint, alias } => {
                trust::add(fingerprint, alias, socket, json).await
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_cli_argument_parsing() {
        // Test scan
        let parsed =
            Cli::try_parse_from(["lsend", "scan", "--duration", "5", "--http-scan"]).unwrap();
        assert_eq!(
            parsed.command,
            Commands::Scan {
                duration: 5,
                http_scan: true
            }
        );

        // Test send
        let parsed = Cli::try_parse_from([
            "lsend",
            "send",
            "192.168.1.50",
            "Cargo.toml",
            "--pin",
            "1234",
            "--standalone",
        ])
        .unwrap();
        assert_eq!(
            parsed.command,
            Commands::Send {
                target: "192.168.1.50".to_string(),
                files: vec![PathBuf::from("Cargo.toml")],
                pin: Some("1234".to_string()),
                fingerprint: None,
                standalone: true,
            }
        );

        // Test accept
        let parsed = Cli::try_parse_from(["lsend", "accept", "sess-123"]).unwrap();
        assert_eq!(
            parsed.command,
            Commands::Accept {
                session_id: "sess-123".to_string()
            }
        );

        // Test reject
        let parsed =
            Cli::try_parse_from(["lsend", "reject", "sess-123", "--reason", "busy"]).unwrap();
        assert_eq!(
            parsed.command,
            Commands::Reject {
                session_id: "sess-123".to_string(),
                reason: Some("busy".to_string())
            }
        );

        // Test status
        let parsed = Cli::try_parse_from(["lsend", "status", "--json"]).unwrap();
        assert!(parsed.json);
        assert_eq!(parsed.command, Commands::Status);

        // Test trust add
        let parsed = Cli::try_parse_from([
            "lsend",
            "trust",
            "add",
            "AABBCCDDEEFF",
            "--alias",
            "MyPhone",
        ])
        .unwrap();
        assert_eq!(
            parsed.command,
            Commands::Trust {
                action: TrustAction::Add {
                    fingerprint: "AABBCCDDEEFF".to_string(),
                    alias: "MyPhone".to_string(),
                }
            }
        );
    }
}
