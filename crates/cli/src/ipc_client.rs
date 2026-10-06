//! Unix Domain Socket IPC Client
//!
//! Provides an asynchronous client to communicate with the running `localsendd` service
//! over `/run/localsend/daemon.sock` using newline-delimited JSON messages.

use futures_util::{SinkExt, StreamExt};
use localsend_daemon::{
    DEFAULT_UDS_SOCKET_PATH, DaemonEvent, DaemonStatus, IpcMessage, IpcPayload, IpcRequest,
    IpcResponse, PeerSummary,
};
use std::path::Path;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LinesCodec};

/// Error type for IPC client interactions.
#[derive(Debug, thiserror::Error)]
pub enum IpcClientError {
    /// Filesystem or socket I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization or deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// Lines codec framing error.
    #[error("Framing error: {0}")]
    Lines(#[from] tokio_util::codec::LinesCodecError),
    /// Daemon rejected request with an error message.
    #[error("Daemon error: {0}")]
    Daemon(String),
    /// Unexpected response payload received.
    #[error("Unexpected response: {0}")]
    UnexpectedResponse(String),
    /// Server closed connection unexpectedly.
    #[error("Connection closed unexpectedly")]
    ConnectionClosed,
}

/// Helper trait for boxed async read/write streams.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncStream for T {}

/// Asynchronous IPC client for communicating with `localsendd`.
pub struct IpcClient {
    framed: Framed<Box<dyn AsyncStream>, LinesCodec>,
    next_request_id: u64,
}

impl IpcClient {
    /// Default filesystem socket location.
    pub const DEFAULT_PATH: &'static str = DEFAULT_UDS_SOCKET_PATH;

    /// Connect to the daemon over a Unix Domain Socket at `path`.
    #[cfg(unix)]
    pub async fn connect(path: &Path) -> Result<Self, IpcClientError> {
        let stream = tokio::net::UnixStream::connect(path).await?;
        Ok(Self::from_stream(stream))
    }

    /// Connect to the daemon over a Unix Domain Socket (unsupported on non-Unix platforms).
    #[cfg(not(unix))]
    pub async fn connect(_path: &Path) -> Result<Self, IpcClientError> {
        Err(IpcClientError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Unix Domain Sockets are only supported on Unix systems",
        )))
    }

    /// Construct an IPC client from any bidirectional async stream (used for in-memory tests).
    pub fn from_stream<S>(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            framed: Framed::new(Box::new(stream), LinesCodec::new()),
            next_request_id: 1,
        }
    }

    /// Send an IPC request and await the correlated response.
    async fn send_request(&mut self, req: IpcRequest) -> Result<IpcResponse, IpcClientError> {
        let id = self.next_request_id.to_string();
        self.next_request_id += 1;

        let msg = IpcMessage::request(&id, req);
        let line = serde_json::to_string(&msg)?;
        self.framed.send(line).await?;

        while let Some(line_res) = self.framed.next().await {
            let line = line_res?;
            let resp_msg: IpcMessage = serde_json::from_str(&line)?;
            match resp_msg.payload {
                IpcPayload::Response(resp) => {
                    if resp_msg.id.as_deref() == Some(&id) {
                        match resp {
                            IpcResponse::Error(err) => return Err(IpcClientError::Daemon(err)),
                            other => return Ok(other),
                        }
                    }
                }
                IpcPayload::Event(_) => {
                    // Ignore background push events while waiting for request response
                    continue;
                }
                IpcPayload::Request(_) => continue,
            }
        }

        Err(IpcClientError::ConnectionClosed)
    }

    /// Query daemon operational status and active session.
    pub async fn get_status(&mut self) -> Result<DaemonStatus, IpcClientError> {
        match self.send_request(IpcRequest::GetStatus).await? {
            IpcResponse::Status(status) => Ok(status),
            other => Err(IpcClientError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    /// Query daemon discovered peer registry.
    pub async fn get_peers(&mut self) -> Result<Vec<PeerSummary>, IpcClientError> {
        match self.send_request(IpcRequest::ListPeers).await? {
            IpcResponse::Peers(peers) => Ok(peers),
            other => Err(IpcClientError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    /// Approve a pending incoming transfer session.
    pub async fn accept_session(&mut self, session_id: String) -> Result<(), IpcClientError> {
        match self
            .send_request(IpcRequest::AcceptSession { session_id })
            .await?
        {
            IpcResponse::Ok => Ok(()),
            other => Err(IpcClientError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    /// Reject a pending incoming transfer session.
    pub async fn reject_session(
        &mut self,
        session_id: String,
        reason: Option<String>,
    ) -> Result<(), IpcClientError> {
        match self
            .send_request(IpcRequest::RejectSession { session_id, reason })
            .await?
        {
            IpcResponse::Ok => Ok(()),
            other => Err(IpcClientError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    /// Cancel an active transfer session.
    pub async fn cancel_session(&mut self, session_id: String) -> Result<(), IpcClientError> {
        match self
            .send_request(IpcRequest::CancelSession { session_id })
            .await?
        {
            IpcResponse::Ok => Ok(()),
            other => Err(IpcClientError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    /// Add a trusted remote peer to the persistent trust store.
    pub async fn add_trust(
        &mut self,
        fingerprint: String,
        alias: String,
    ) -> Result<(), IpcClientError> {
        match self
            .send_request(IpcRequest::AddTrustedPeer {
                fingerprint,
                alias: Some(alias),
            })
            .await?
        {
            IpcResponse::Ok => Ok(()),
            other => Err(IpcClientError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    /// Subscribe to asynchronous daemon events and return a stream yielding `DaemonEvent`s.
    pub async fn subscribe_events(
        mut self,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<DaemonEvent, IpcClientError>>,
        IpcClientError,
    > {
        match self.send_request(IpcRequest::SubscribeEvents).await? {
            IpcResponse::Ok => {}
            other => return Err(IpcClientError::UnexpectedResponse(format!("{other:?}"))),
        }

        let stream = futures_util::stream::unfold(self.framed, |mut framed| async move {
            while let Some(res) = framed.next().await {
                match res {
                    Ok(line) => {
                        if let Ok(msg) = serde_json::from_str::<IpcMessage>(&line)
                            && let IpcPayload::Event(event) = msg.payload
                        {
                            return Some((Ok(event), framed));
                        }
                    }
                    Err(e) => return Some((Err(IpcClientError::Lines(e)), framed)),
                }
            }
            None
        });

        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use localsend_daemon::{
        AutoAcceptMode, IpcServerState, SessionCoordinator, TrustStore, handle_ipc_client,
    };
    use localsend_discovery::PeerRegistry;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::io::duplex;
    use tokio::sync::{RwLock, broadcast};

    #[tokio::test]
    async fn test_ipc_client_roundtrip_methods() {
        let temp_dir = std::env::temp_dir().join(format!("client_ipc_{}", uuid::Uuid::new_v4()));
        let cfg_path = temp_dir.join("trusted.yaml");
        let trust_store = Arc::new(RwLock::new(TrustStore::load_or_create(&cfg_path).unwrap()));
        let (event_tx, _) = broadcast::channel::<DaemonEvent>(64);
        let coordinator = SessionCoordinator::default();
        let registry = PeerRegistry::new();

        let state = IpcServerState {
            coordinator,
            registry,
            trust_store: trust_store.clone(),
            event_tx: event_tx.clone(),
            start_time: Instant::now(),
            bound_ips: vec![],
        };

        let (client_stream, server_stream) = duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = handle_ipc_client(server_stream, state).await;
        });

        let mut client = IpcClient::from_stream(client_stream);

        // Status
        let status = client.get_status().await.unwrap();
        assert_eq!(status.active_session, None);

        // Peers
        let peers = client.get_peers().await.unwrap();
        assert!(peers.is_empty());

        // Add trust
        client
            .add_trust("AABB11".to_string(), "Phone".to_string())
            .await
            .unwrap();
        assert_eq!(
            trust_store.read().await.auto_accept_mode(),
            AutoAcceptMode::TrustedOnly
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
