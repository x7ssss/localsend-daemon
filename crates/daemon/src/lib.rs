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

#[cfg(unix)]
pub use ipc::run_uds_server;
pub use ipc::{
    DEFAULT_UDS_SOCKET_PATH, DaemonEvent, DaemonStatus, FileInfo, IpcMessage, IpcPayload,
    IpcRequest, IpcResponse, IpcServerState, PeerSummary, handle_ipc_client,
};

pub use server::{AppState, ReceiverServer, build_tls_server_config, create_router};
pub use session::{
    ActiveSession, DEFAULT_SESSION_TIMEOUT, FileStatus, PendingSession, SessionCoordinator,
    SessionError, StagedFile,
};
pub use storage::{
    STREAM_BUFFER_CAPACITY, StorageError, TempFileGuard, commit_file_atomically,
    get_temp_file_path, scavenge_orphaned_parts, stream_to_disk_and_hash,
};
pub use trust::{AutoAcceptMode, TrustError, TrustStore, TrustStoreData, TrustedPeer};
