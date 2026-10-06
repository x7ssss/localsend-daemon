//! Inter-Process Communication (IPC) Module
//!
//! Provides the Unix Domain Socket (UDS) server and framed message schemas
//! connecting the background daemon to CLI utilities and management scripts.

pub mod protocol;
pub mod server;

pub use protocol::{
    DaemonEvent, DaemonStatus, FileInfo, IpcMessage, IpcPayload, IpcRequest, IpcResponse,
    PeerSummary,
};
pub use server::{DEFAULT_UDS_SOCKET_PATH, IpcServerState, MAX_IPC_LINE_LENGTH, handle_ipc_client};

#[cfg(unix)]
pub use server::run_uds_server;
