//! IPC Server Implementation
//!
//! Provides the Unix Domain Socket (UDS) server handling newline-delimited JSON commands,
//! event streaming via broadcast channels, and daemon state management.

use super::protocol::{
    DaemonEvent, DaemonStatus, IpcMessage, IpcPayload, IpcRequest, IpcResponse, PeerSummary,
};
use crate::session::SessionCoordinator;
use crate::trust::TrustStore;
use futures_util::{SinkExt, StreamExt};
use localsend_discovery::PeerRegistry;
use std::net::IpAddr;
#[cfg(unix)]
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, RwLock};
use tokio_util::codec::{Framed, LinesCodec};
#[cfg(unix)]
use tokio_util::sync::CancellationToken;

/// Default filesystem socket location.
pub const DEFAULT_UDS_SOCKET_PATH: &'static str = "/run/localsend/daemon.sock";

/// Maximum line length for newline-delimited JSON messages (256 KiB).
pub const MAX_IPC_LINE_LENGTH: usize = 256 * 1024;

/// Shared daemon state accessed by IPC request handlers.
#[derive(Clone)]
pub struct IpcServerState {
    /// Session coordinator.
    pub coordinator: SessionCoordinator,
    /// Discovered peer registry.
    pub registry: PeerRegistry,
    /// Persistent trust store.
    pub trust_store: Arc<RwLock<TrustStore>>,
    /// Event broadcast channel.
    pub event_tx: broadcast::Sender<DaemonEvent>,
    /// Daemon start timestamp.
    pub start_time: Instant,
    /// Local IP addresses bound by the daemon.
    pub bound_ips: Vec<IpAddr>,
}

/// Handle a single IPC client connection stream (generic over any async stream).
pub async fn handle_ipc_client<S>(
    stream: S,
    state: IpcServerState,
) -> Result<(), std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let codec = LinesCodec::new_with_max_length(MAX_IPC_LINE_LENGTH);
    let mut framed = Framed::new(stream, codec);
    let mut event_rx = state.event_tx.subscribe();
    let mut is_subscribed = false;

    loop {
        tokio::select! {
            // Read incoming line from client
            client_msg = framed.next() => {
                let line = match client_msg {
                    Some(Ok(l)) => l,
                    Some(Err(e)) => {
                        tracing::debug!("IPC framing decode error: {e}");
                        break;
                    }
                    None => break, // Connection closed
                };

                let message: IpcMessage = match serde_json::from_str(&line) {
                    Ok(m) => m,
                    Err(e) => {
                        let err_resp = IpcMessage::response(
                            None,
                            IpcResponse::Error(format!("Invalid JSON: {e}")),
                        );
                        let _ = framed.send(serde_json::to_string(&err_resp).unwrap()).await;
                        continue;
                    }
                };

                if let IpcPayload::Request(req) = message.payload {
                    let mut subscribe_now = false;
                    let resp = match req {
                        IpcRequest::GetStatus => {
                            let uptime_secs = state.start_time.elapsed().as_secs();
                            let active_session = state.coordinator.get_active_session().await.map(|s| s.session_id);
                            IpcResponse::Status(DaemonStatus {
                                uptime_secs,
                                bound_ips: state.bound_ips.clone(),
                                active_session,
                            })
                        }
                        IpcRequest::ListPeers => {
                            let peers = state.registry.list().await.into_iter().map(|p| PeerSummary {
                                fingerprint: p.fingerprint,
                                alias: p.alias,
                                ip: p.ip,
                                port: p.port,
                                device_model: p.device_model,
                            }).collect();
                            IpcResponse::Peers(peers)
                        }
                        IpcRequest::ScanSubnet { cidr: _ } => {
                            IpcResponse::Ok
                        }
                        IpcRequest::AcceptSession { session_id } => {
                            if state.coordinator.approve_pending_session(&session_id).await {
                                IpcResponse::Ok
                            } else {
                                IpcResponse::Error("Pending session not found or expired".to_string())
                            }
                        }
                        IpcRequest::RejectSession { session_id, reason } => {
                            if state.coordinator.reject_pending_session(&session_id).await {
                                tracing::info!("Session {session_id} rejected via IPC: {reason:?}");
                                IpcResponse::Ok
                            } else {
                                IpcResponse::Error("Pending session not found or expired".to_string())
                            }
                        }
                        IpcRequest::CancelSession { session_id } => {
                            if state.coordinator.cancel_session(&session_id).await.is_ok() {
                                IpcResponse::Ok
                            } else {
                                IpcResponse::Error("Active session not found".to_string())
                            }
                        }
                        IpcRequest::GetTrustConfig => {
                            let store = state.trust_store.read().await;
                            IpcResponse::TrustConfig(store.data().clone())
                        }
                        IpcRequest::SetTrustMode { mode } => {
                            let mut store = state.trust_store.write().await;
                            match store.set_mode(mode) {
                                Ok(_) => IpcResponse::Ok,
                                Err(e) => IpcResponse::Error(e.to_string()),
                            }
                        }
                        IpcRequest::AddTrustedPeer { fingerprint, alias } => {
                            let mut store = state.trust_store.write().await;
                            match store.add_fingerprint(fingerprint, alias) {
                                Ok(_) => IpcResponse::Ok,
                                Err(e) => IpcResponse::Error(e.to_string()),
                            }
                        }
                        IpcRequest::RemoveTrustedPeer { fingerprint } => {
                            let mut store = state.trust_store.write().await;
                            match store.remove_fingerprint(&fingerprint) {
                                Ok(_) => IpcResponse::Ok,
                                Err(e) => IpcResponse::Error(e.to_string()),
                            }
                        }
                        IpcRequest::AddTrustedSubnet { cidr } => {
                            match cidr.parse::<ipnet::IpNet>() {
                                Ok(net) => {
                                    let mut store = state.trust_store.write().await;
                                    match store.add_subnet(net) {
                                        Ok(_) => IpcResponse::Ok,
                                        Err(e) => IpcResponse::Error(e.to_string()),
                                    }
                                }
                                Err(e) => IpcResponse::Error(format!("Invalid CIDR: {e}")),
                            }
                        }
                        IpcRequest::RemoveTrustedSubnet { cidr } => {
                            match cidr.parse::<ipnet::IpNet>() {
                                Ok(net) => {
                                    let mut store = state.trust_store.write().await;
                                    match store.remove_subnet(&net) {
                                        Ok(_) => IpcResponse::Ok,
                                        Err(e) => IpcResponse::Error(e.to_string()),
                                    }
                                }
                                Err(e) => IpcResponse::Error(format!("Invalid CIDR: {e}")),
                            }
                        }
                        IpcRequest::SetPin { pin } => {
                            let mut store = state.trust_store.write().await;
                            match store.set_pin(pin) {
                                Ok(_) => IpcResponse::Ok,
                                Err(e) => IpcResponse::Error(e.to_string()),
                            }
                        }
                        IpcRequest::SubscribeEvents => {
                            subscribe_now = true;
                            IpcResponse::Ok
                        }
                    };

                    let response = IpcMessage::response(message.id, resp);
                    if let Ok(json_line) = serde_json::to_string(&response) {
                        if framed.send(json_line).await.is_err() {
                            break;
                        }
                    }

                    if subscribe_now {
                        is_subscribed = true;
                    }
                }
            }

            // Stream server push events if client subscribed
            event_res = event_rx.recv(), if is_subscribed => {
                match event_res {
                    Ok(event) => {
                        let msg = IpcMessage::event(event);
                        if let Ok(json_line) = serde_json::to_string(&msg) {
                            if framed.send(json_line).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(dropped)) => {
                        tracing::warn!("IPC client event stream lagged by {dropped} events");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Run Unix Domain Socket server on Unix platforms.
#[cfg(unix)]
pub async fn run_uds_server(
    socket_path: &Path,
    state: IpcServerState,
    cancel_token: CancellationToken,
) -> Result<(), std::io::Error> {
    // Unlink stale socket file
    if socket_path.exists() {
        let _ = std::fs::remove_file(socket_path);
    }

    // Create parent directory if missing
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = tokio::net::UnixListener::bind(socket_path)?;

    // Set 0660 file permissions (accessible by localsend group)
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660));

    tracing::info!("IPC Unix Domain Socket listening at {:?}", socket_path);

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => break,
            accept_res = listener.accept() => {
                let (stream, _) = match accept_res {
                    Ok(val) => val,
                    Err(e) => {
                        tracing::debug!("UDS accept error: {e}");
                        continue;
                    }
                };

                let client_state = state.clone();
                tokio::spawn(async move {
                    let _ = handle_ipc_client(stream, client_state).await;
                });
            }
        }
    }

    let _ = std::fs::remove_file(socket_path);
    Ok(())
}
