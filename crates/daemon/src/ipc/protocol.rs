//! LocalSend IPC Wire Protocol Schemas
//!
//! Strongly typed newline-delimited JSON messages exchanged between `localsendd` and `lsend`.

use crate::trust::{AutoAcceptMode, TrustStoreData};
use std::net::IpAddr;

/// Top-level framed IPC message wrapper.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IpcMessage {
    /// Optional identifier for request-response correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Message payload variant.
    pub payload: IpcPayload,
}

impl IpcMessage {
    /// Creates a new request message.
    pub fn request(id: impl Into<String>, req: IpcRequest) -> Self {
        Self {
            id: Some(id.into()),
            payload: IpcPayload::Request(req),
        }
    }

    /// Creates a new response message.
    pub fn response(id: Option<String>, resp: IpcResponse) -> Self {
        Self {
            id,
            payload: IpcPayload::Response(resp),
        }
    }

    /// Creates an asynchronous event message.
    pub fn event(event: DaemonEvent) -> Self {
        Self {
            id: None,
            payload: IpcPayload::Event(event),
        }
    }
}

/// IPC payload envelope.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "content", rename_all = "snake_case")]
pub enum IpcPayload {
    /// Inbound request from client.
    Request(IpcRequest),
    /// Response from daemon.
    Response(IpcResponse),
    /// Asynchronous push event from daemon.
    Event(DaemonEvent),
}

/// Commands submitted by client over IPC.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum IpcRequest {
    /// Retrieve operational health and runtime statistics.
    GetStatus,
    /// Retrieve active peers from in-memory registry.
    ListPeers,
    /// Proactively sweep candidate subnet IPs.
    ScanSubnet {
        /// Optional subnet CIDR string (e.g., "192.168.1.0/24").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cidr: Option<String>,
    },
    /// Authorize a pending incoming transfer session.
    AcceptSession {
        /// Unique session ID.
        session_id: String,
    },
    /// Reject an incoming transfer session.
    RejectSession {
        /// Unique session ID.
        session_id: String,
        /// Optional reason string.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Abort an active transfer session.
    CancelSession {
        /// Unique session ID.
        session_id: String,
    },
    /// Retrieve current trust store configuration.
    GetTrustConfig,
    /// Update auto-acceptance policy mode.
    SetTrustMode {
        /// Mode (never, trusted_only, always).
        mode: AutoAcceptMode,
    },
    /// Add remote peer fingerprint to trust store.
    AddTrustedPeer {
        /// Pinned certificate fingerprint.
        fingerprint: String,
        /// Peer alias.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alias: Option<String>,
    },
    /// Remove remote peer fingerprint from trust store.
    RemoveTrustedPeer {
        /// Pinned certificate fingerprint.
        fingerprint: String,
    },
    /// Add allowed CIDR subnet to trust store.
    AddTrustedSubnet {
        /// CIDR representation (e.g. "192.168.1.0/24").
        cidr: String,
    },
    /// Remove allowed CIDR subnet from trust store.
    RemoveTrustedSubnet {
        /// CIDR representation.
        cidr: String,
    },
    /// Configure or clear shared secret PIN.
    SetPin {
        /// New PIN, or None to clear.
        #[serde(default)]
        pin: Option<String>,
    },
    /// Subscribe connection to daemon asynchronous events.
    SubscribeEvents,
}

/// Structured response payloads returned by daemon.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum IpcResponse {
    /// Daemon status metrics.
    Status(DaemonStatus),
    /// Current discovered peer list.
    Peers(Vec<PeerSummary>),
    /// Operation acknowledged successfully.
    Ok,
    /// Error message.
    Error(String),
    /// Trust store configuration.
    TrustConfig(TrustStoreData),
    /// Event forwarded.
    Event(DaemonEvent),
}

/// Summary metrics describing running daemon state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DaemonStatus {
    /// Running uptime in seconds.
    pub uptime_secs: u64,
    /// Local network IPs bound by the service.
    pub bound_ips: Vec<IpAddr>,
    /// Currently active transfer session ID (if running).
    pub active_session: Option<String>,
}

/// Compact peer overview for CLI listing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerSummary {
    /// Canonical certificate fingerprint.
    pub fingerprint: String,
    /// Peer alias.
    pub alias: String,
    /// Remote IP.
    pub ip: IpAddr,
    /// Port.
    pub port: u16,
    /// Device model.
    pub device_model: Option<String>,
}

/// Metadata describing a file in an incoming session.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileInfo {
    /// File ID.
    pub id: String,
    /// File name.
    pub file_name: String,
    /// Byte size.
    pub size: u64,
    /// MIME / file type.
    pub file_type: String,
}

/// Asynchronous events streamed from daemon to connected IPC clients.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum DaemonEvent {
    /// A new network peer was discovered.
    PeerDiscovered(PeerSummary),
    /// A known peer has timed out or disconnected.
    PeerLost(String),
    /// An incoming transfer session is awaiting interactive approval.
    IncomingSession {
        /// Session ID.
        session_id: String,
        /// Peer alias.
        peer_alias: String,
        /// Peer IP address.
        peer_ip: IpAddr,
        /// Files offered in the transfer.
        files: Vec<FileInfo>,
    },
    /// Streaming transfer progress update.
    TransferProgress {
        /// Session ID.
        session_id: String,
        /// File ID.
        file_id: String,
        /// Bytes written so far.
        bytes_written: u64,
        /// Total file size.
        total_bytes: u64,
    },
    /// File transfer concluded.
    TransferComplete {
        /// Session ID.
        session_id: String,
        /// File ID.
        file_id: String,
        /// Whether transfer succeeded.
        success: bool,
    },
    /// Session terminated or cancelled.
    SessionTerminated {
        /// Session ID.
        session_id: String,
        /// Reason description.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_message_roundtrip() {
        let msg = IpcMessage::request("req-1", IpcRequest::GetStatus);
        let serialized = serde_json::to_string(&msg).unwrap();
        let parsed: IpcMessage = serde_json::from_str(&serialized).unwrap();
        assert_eq!(msg, parsed);

        let resp = IpcMessage::response(
            Some("req-1".into()),
            IpcResponse::Status(DaemonStatus {
                uptime_secs: 120,
                bound_ips: vec![],
                active_session: None,
            }),
        );
        let ser_resp = serde_json::to_string(&resp).unwrap();
        let parsed_resp: IpcMessage = serde_json::from_str(&ser_resp).unwrap();
        assert_eq!(resp, parsed_resp);
    }
}
