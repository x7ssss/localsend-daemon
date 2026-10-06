//! LocalSend Daemon Library
//!
//! Provides the core HTTPS receiver, session coordinator, atomic storage pipeline,
//! and server engine.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod server;
pub mod session;
pub mod storage;

pub use server::{build_tls_server_config, create_router, AppState, ReceiverServer};
pub use session::{ActiveSession, FileStatus, SessionCoordinator, SessionError, StagedFile};
pub use storage::{
    commit_file_atomically, get_temp_file_path, scavenge_orphaned_parts, stream_to_disk_and_hash,
    StorageError, TempFileGuard, STREAM_BUFFER_CAPACITY,
};
