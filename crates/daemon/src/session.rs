//! Transfer Session Coordinator
//!
//! Manages single-active transfer session concurrency locks (HTTP 409 Conflict),
//! interactive approval hooks via IPC, upload token validation, and session timeouts.

use localsend_protocol::{FileMetadata, PrepareUploadResponse, UploadParams};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, oneshot};
use uuid::Uuid;

/// Default session inactivity expiration (5 minutes).
pub const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Status of an individual file within an active transfer session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FileStatus {
    /// Waiting for sender to initiate upload stream.
    Pending,
    /// Currently actively streaming chunks to disk.
    Streaming,
    /// Successfully written, verified, and committed to destination.
    Completed,
    /// Failed or aborted during transmission.
    Failed,
}

/// Metadata and state for a file scheduled in the current session.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StagedFile {
    /// Unique identifier within the session.
    pub id: String,
    /// Desired destination file name.
    pub file_name: String,
    /// Expected byte size.
    pub size: u64,
    /// Expected SHA-256 hash (if provided).
    pub sha256: Option<String>,
    /// Transmission lifecycle status.
    pub status: FileStatus,
}

/// An active multi-file transfer session.
#[derive(Debug, Clone)]
pub struct ActiveSession {
    /// Unique session UUID.
    pub session_id: String,
    /// Sender peer alias.
    pub sender_alias: String,
    /// Sender certificate fingerprint.
    pub sender_fingerprint: String,
    /// Authorized sender IP address.
    pub sender_ip: IpAddr,
    /// Creation timestamp.
    pub created_at: Instant,
    /// Last transmission activity timestamp.
    pub last_activity: Instant,
    /// Files included in this transfer.
    pub files: HashMap<String, StagedFile>,
    /// Secret per-file upload tokens (fileId -> token).
    pub tokens: HashMap<String, String>,
}

/// A pending session waiting for manual user approval via IPC.
pub struct PendingSession {
    /// Session ID.
    pub session_id: String,
    /// Sender peer alias.
    pub sender_alias: String,
    /// Sender certificate fingerprint.
    pub sender_fingerprint: String,
    /// Sender IP address.
    pub sender_ip: IpAddr,
    /// File manifest.
    pub files: HashMap<String, FileMetadata>,
    /// Creation timestamp.
    pub created_at: Instant,
    /// Approval oneshot channel sender.
    pub approve_tx: Option<oneshot::Sender<bool>>,
}

/// Errors occurring during session coordination.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    /// Another session is currently running.
    #[error("Conflict: another transfer session is already in progress")]
    Conflict,
    /// Session was not found, cancelled, or expired.
    #[error("Session not found or expired")]
    SessionNotFound,
    /// Upload token is incorrect.
    #[error("Invalid upload token")]
    InvalidToken,
    /// Request originated from an unauthorized IP.
    #[error("Client IP does not match session initiator IP")]
    ForbiddenIp,
    /// File ID was not part of the manifest.
    #[error("File ID not found in session manifest")]
    FileNotFound,
    /// Session was explicitly rejected by user via IPC.
    #[error("Session rejected")]
    Rejected,
    /// Interactive session approval timed out.
    #[error("Session approval timed out")]
    ApprovalTimeout,
}

/// Single-session concurrency, approval, and token coordinator.
#[derive(Clone)]
pub struct SessionCoordinator {
    session: Arc<RwLock<Option<ActiveSession>>>,
    pending: Arc<RwLock<Option<PendingSession>>>,
    timeout: Duration,
}

impl Default for SessionCoordinator {
    fn default() -> Self {
        Self::new(DEFAULT_SESSION_TIMEOUT)
    }
}

impl SessionCoordinator {
    /// Creates a new coordinator with specified inactivity timeout.
    pub fn new(timeout: Duration) -> Self {
        Self {
            session: Arc::new(RwLock::new(None)),
            pending: Arc::new(RwLock::new(None)),
            timeout,
        }
    }

    /// Checks if a session or pending approval is currently running.
    pub async fn is_busy(&self) -> bool {
        let mut guard = self.session.write().await;
        if let Some(active) = &*guard {
            if active.last_activity.elapsed() > self.timeout {
                *guard = None;
            } else {
                return true;
            }
        }
        self.pending.read().await.is_some()
    }

    /// Retrieve the current active session if not expired.
    pub async fn get_active_session(&self) -> Option<ActiveSession> {
        let mut guard = self.session.write().await;
        if let Some(active) = &*guard {
            if active.last_activity.elapsed() > self.timeout {
                *guard = None;
                None
            } else {
                Some(active.clone())
            }
        } else {
            None
        }
    }

    /// Helper to convert files map into staged files and tokens.
    fn create_active_session_internal(
        session_id: String,
        sender_alias: String,
        sender_fingerprint: String,
        sender_ip: IpAddr,
        files_map: HashMap<String, FileMetadata>,
    ) -> (ActiveSession, PrepareUploadResponse) {
        let mut staged_files = HashMap::new();
        let mut tokens = HashMap::new();

        for (id, meta) in files_map {
            let secret_token = Uuid::new_v4().to_string();
            tokens.insert(id.clone(), secret_token);
            staged_files.insert(
                id.clone(),
                StagedFile {
                    id,
                    file_name: meta.file_name,
                    size: meta.size,
                    sha256: meta.sha256,
                    status: FileStatus::Pending,
                },
            );
        }

        let active = ActiveSession {
            session_id: session_id.clone(),
            sender_alias,
            sender_fingerprint,
            sender_ip,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            files: staged_files,
            tokens: tokens.clone(),
        };

        let response = PrepareUploadResponse {
            session_id,
            files: tokens,
        };

        (active, response)
    }

    /// Attempt to immediately create a session (used for auto-accepted transfers).
    pub async fn try_create_session(
        &self,
        sender_alias: String,
        sender_fingerprint: String,
        sender_ip: IpAddr,
        files_map: HashMap<String, FileMetadata>,
    ) -> Result<PrepareUploadResponse, SessionError> {
        let mut guard = self.session.write().await;

        if let Some(existing) = &*guard {
            if existing.last_activity.elapsed() <= self.timeout {
                return Err(SessionError::Conflict);
            }
            *guard = None;
        }

        let session_id = Uuid::new_v4().to_string();
        let (active, resp) = Self::create_active_session_internal(
            session_id,
            sender_alias,
            sender_fingerprint,
            sender_ip,
            files_map,
        );

        *guard = Some(active);
        Ok(resp)
    }

    /// Register a pending approval session and wait for manual approval.
    pub async fn request_session_approval(
        &self,
        session_id: String,
        sender_alias: String,
        sender_fingerprint: String,
        sender_ip: IpAddr,
        files_map: HashMap<String, FileMetadata>,
        approval_timeout: Duration,
    ) -> Result<PrepareUploadResponse, SessionError> {
        let (tx, rx) = oneshot::channel();

        {
            let mut guard = self.session.write().await;
            if let Some(existing) = &*guard {
                if existing.last_activity.elapsed() <= self.timeout {
                    return Err(SessionError::Conflict);
                }
                *guard = None;
            }

            let mut pending_guard = self.pending.write().await;
            if pending_guard.is_some() {
                return Err(SessionError::Conflict);
            }

            *pending_guard = Some(PendingSession {
                session_id: session_id.clone(),
                sender_alias: sender_alias.clone(),
                sender_fingerprint: sender_fingerprint.clone(),
                sender_ip,
                files: files_map.clone(),
                created_at: Instant::now(),
                approve_tx: Some(tx),
            });
        }

        // Wait for decision with timeout
        match tokio::time::timeout(approval_timeout, rx).await {
            Ok(Ok(true)) => {
                // Approved! Move from pending to active
                let mut guard = self.session.write().await;
                let mut pending_guard = self.pending.write().await;
                *pending_guard = None;

                let (active, resp) = Self::create_active_session_internal(
                    session_id,
                    sender_alias,
                    sender_fingerprint,
                    sender_ip,
                    files_map,
                );
                *guard = Some(active);
                Ok(resp)
            }
            Ok(Ok(false)) => {
                // Explicitly rejected
                let mut pending_guard = self.pending.write().await;
                *pending_guard = None;
                Err(SessionError::Rejected)
            }
            Ok(Err(_)) => {
                // Channel dropped
                let mut pending_guard = self.pending.write().await;
                *pending_guard = None;
                Err(SessionError::Rejected)
            }
            Err(_) => {
                // Timeout
                let mut pending_guard = self.pending.write().await;
                *pending_guard = None;
                Err(SessionError::ApprovalTimeout)
            }
        }
    }

    /// Approve a pending session by session ID.
    pub async fn approve_pending_session(&self, session_id: &str) -> bool {
        let mut guard = self.pending.write().await;
        if let Some(pending) = &mut *guard
            && pending.session_id == session_id
            && let Some(tx) = pending.approve_tx.take()
        {
            let _ = tx.send(true);
            return true;
        }
        false
    }

    /// Reject a pending session by session ID.
    pub async fn reject_pending_session(&self, session_id: &str) -> bool {
        let mut guard = self.pending.write().await;
        if let Some(pending) = &mut *guard
            && pending.session_id == session_id
            && let Some(tx) = pending.approve_tx.take()
        {
            let _ = tx.send(false);
            return true;
        }
        false
    }

    /// Validate an incoming upload stream against session parameters and client IP.
    pub async fn validate_upload(
        &self,
        params: &UploadParams,
        client_ip: IpAddr,
    ) -> Result<StagedFile, SessionError> {
        let mut guard = self.session.write().await;

        let active = match &mut *guard {
            Some(s) => s,
            None => return Err(SessionError::SessionNotFound),
        };

        if active.last_activity.elapsed() > self.timeout {
            *guard = None;
            return Err(SessionError::SessionNotFound);
        }

        if active.session_id != params.session_id {
            return Err(SessionError::SessionNotFound);
        }

        // Validate client IP (ignore port)
        if active.sender_ip != client_ip {
            let is_loopback = active.sender_ip.is_loopback() && client_ip.is_loopback();
            if !is_loopback {
                return Err(SessionError::ForbiddenIp);
            }
        }

        // Validate token
        match active.tokens.get(&params.file_id) {
            Some(expected_tok) if expected_tok == &params.token => {}
            _ => return Err(SessionError::InvalidToken),
        }

        let file = match active.files.get_mut(&params.file_id) {
            Some(f) => f,
            None => return Err(SessionError::FileNotFound),
        };

        file.status = FileStatus::Streaming;
        active.last_activity = Instant::now();

        Ok(file.clone())
    }

    /// Mark a file as completed. Clears the session if all scheduled files have completed.
    pub async fn complete_file(
        &self,
        session_id: &str,
        file_id: &str,
    ) -> Result<bool, SessionError> {
        let mut guard = self.session.write().await;

        let active = match &mut *guard {
            Some(s) if s.session_id == session_id => s,
            _ => return Err(SessionError::SessionNotFound),
        };

        if let Some(file) = active.files.get_mut(file_id) {
            file.status = FileStatus::Completed;
            active.last_activity = Instant::now();
        } else {
            return Err(SessionError::FileNotFound);
        }

        let all_done = active
            .files
            .values()
            .all(|f| f.status == FileStatus::Completed);

        if all_done {
            *guard = None;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Mark a file as failed.
    pub async fn fail_file(&self, session_id: &str, file_id: &str) -> Result<(), SessionError> {
        let mut guard = self.session.write().await;

        let active = match &mut *guard {
            Some(s) if s.session_id == session_id => s,
            _ => return Err(SessionError::SessionNotFound),
        };

        if let Some(file) = active.files.get_mut(file_id) {
            file.status = FileStatus::Failed;
            active.last_activity = Instant::now();
        } else {
            return Err(SessionError::FileNotFound);
        }

        let all_terminal = active
            .files
            .values()
            .all(|f| f.status == FileStatus::Completed || f.status == FileStatus::Failed);

        if all_terminal {
            *guard = None;
        }

        Ok(())
    }

    /// Cancel and clear active session, returning session metadata if found.
    pub async fn cancel_session(&self, session_id: &str) -> Result<ActiveSession, SessionError> {
        let mut guard = self.session.write().await;

        let active = match &*guard {
            Some(s) if s.session_id == session_id => s.clone(),
            _ => return Err(SessionError::SessionNotFound),
        };

        *guard = None;
        Ok(active)
    }
}
