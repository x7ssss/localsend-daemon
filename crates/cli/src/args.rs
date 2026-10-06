//! CLI Argument Parsing Schema
//!
//! Strongly typed clap schemas for `lsend` command-line flags and subcommands.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Command-line arguments schema for `lsend`.
#[derive(Parser, Debug, Clone, PartialEq)]
#[command(
    name = "lsend",
    author,
    version,
    about = "LocalSend command-line file transfer utility and daemon IPC client",
    long_about = None
)]
pub struct Cli {
    /// Output raw JSON instead of human-friendly formatting
    #[arg(global = true, long)]
    pub json: bool,

    /// Custom IPC socket path (overrides default /run/localsend/daemon.sock)
    #[arg(global = true, long, env = "LOCALSEND_SOCKET_PATH")]
    pub socket: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

/// Available subcommands for `lsend`.
#[derive(Subcommand, Debug, Clone, PartialEq)]
pub enum Commands {
    /// Discover nearby LocalSend peers via multicast and optional HTTP subnet sweep
    Scan {
        /// Scan duration in seconds
        #[arg(short, long, default_value_t = 3)]
        duration: u64,

        /// Proactively sweep candidate subnet IPs with unicast HTTP probes
        #[arg(long)]
        http_scan: bool,
    },

    /// Transmit one or more files to a remote LocalSend peer
    Send {
        /// Target peer address (IP, IP:PORT, or peer alias)
        target: String,

        /// Local file paths to transmit
        #[arg(required = true)]
        files: Vec<PathBuf>,

        /// Authorization PIN code configured on the remote peer
        #[arg(long)]
        pin: Option<String>,

        /// Pinned SHA-256 certificate fingerprint of the remote peer
        #[arg(long)]
        fingerprint: Option<String>,

        /// Execute direct peer-to-peer transfer without delegating to running daemon
        #[arg(long)]
        standalone: bool,
    },

    /// Subscribe to real-time events from the running daemon
    Watch,

    /// Approve an incoming transfer session
    Accept {
        /// Session ID to approve
        session_id: String,
    },

    /// Decline an incoming transfer session
    Reject {
        /// Session ID to decline
        session_id: String,

        /// Optional reason message sent to remote peer
        #[arg(short, long)]
        reason: Option<String>,
    },

    /// Display running daemon health and active transfer session
    Status,

    /// List active peers discovered by the running daemon
    Peers,

    /// Manage trusted peers in the daemon trust store
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },
}

/// Subcommands under `lsend trust`.
#[derive(Subcommand, Debug, Clone, PartialEq)]
pub enum TrustAction {
    /// Add a peer certificate fingerprint to the trusted devices store
    Add {
        /// Canonical SHA-256 certificate fingerprint
        fingerprint: String,

        /// Human-friendly peer alias
        #[arg(short, long)]
        alias: String,
    },
}
