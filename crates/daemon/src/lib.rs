//! LocalSend Daemon Library
//!
//! Provides the core HTTPS receiver, session coordinator, atomic storage pipeline,
//! trust policy engine, and IPC server.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod ipc;
pub mod server;
pub mod session;
pub mod storage;
pub mod trust;

pub use ipc::{
    handle_ipc_client, DaemonEvent, DaemonStatus, FileInfo, IpcMessage, IpcPayload, IpcRequest,
    IpcResponse, IpcServerState, PeerSummary, DEFAULT_UDS_SOCKET_PATH,
};
#[cfg(unix)]
pub use ipc::run_uds_server;

pub use server::{build_tls_server_config, create_router, AppState, ReceiverServer};
pub use session::{
    ActiveSession, FileStatus, PendingSession, SessionCoordinator, SessionError, StagedFile,
    DEFAULT_SESSION_TIMEOUT,
};
pub use storage::{
    commit_file_atomically, get_temp_file_path, scavenge_orphaned_parts, stream_to_disk_and_hash,
    StorageError, TempFileGuard, STREAM_BUFFER_CAPACITY,
};
pub use trust::{AutoAcceptMode, TrustError, TrustStore, TrustStoreData, TrustedPeer};
