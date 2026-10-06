//! Transfer Session Coordinator
//!
//! Manages single-active transfer session concurrency locks (HTTP 409 Conflict),
//! issued upload token validation, file lifecycle state tracking, and session timeouts.

use localsend_protocol::{FileMetadata, PrepareUploadResponse, UploadParams};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
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
}

/// Single-session concurrency and token coordinator.
#[derive(Debug, Clone)]
pub struct SessionCoordinator {
    session: Arc<RwLock<Option<ActiveSession>>>,
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
            timeout,
        }
    }

    /// Checks if a session is currently running (and has not timed out).
    pub async fn is_busy(&self) -> bool {
        let mut guard = self.session.write().await;
        if let Some(active) = &*guard {
            if active.last_activity.elapsed() > self.timeout {
                *guard = None;
                false
            } else {
                true
            }
        } else {
            false
        }
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

    /// Attempt to create a new session, returning 409 Conflict if one is already active.
    pub async fn try_create_session(
        &self,
        sender_alias: String,
        sender_fingerprint: String,
        sender_ip: IpAddr,
        files_map: HashMap<String, FileMetadata>,
    ) -> Result<PrepareUploadResponse, SessionError> {
        let mut guard = self.session.write().await;

        // Check for active session
        if let Some(existing) = &*guard {
            if existing.last_activity.elapsed() <= self.timeout {
                return Err(SessionError::Conflict);
            }
            // Expired: reset and allow new session
            *guard = None;
        }

        let session_id = Uuid::new_v4().to_string();
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

        *guard = Some(active);

        Ok(PrepareUploadResponse {
            session_id,
            files: tokens,
        })
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
            // Permit loopback equivalence if testing on localhost
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

        // Retrieve file and mark Streaming
        let file = match active.files.get_mut(&params.file_id) {
            Some(f) => f,
            None => return Err(SessionError::FileNotFound),
        };

        file.status = FileStatus::Streaming;
        active.last_activity = Instant::now();

        Ok(file.clone())
    }

    /// Mark a file as completed. Clears the session if all scheduled files have completed.
    ///
    /// Returns `true` if all files finished and session was cleared.
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

        // Check if all files in session are complete
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
            Ok(())
        } else {
            Err(SessionError::FileNotFound)
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_session_lifecycle_and_conflict() {
        let coordinator = SessionCoordinator::default();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));

        let mut files = HashMap::new();
        files.insert(
            "file-1".to_string(),
            FileMetadata {
                id: "file-1".to_string(),
                file_name: "test.pdf".to_string(),
                size: 1000,
                file_type: "application/pdf".to_string(),
                sha256: None,
                preview: None,
                metadata: None,
            },
        );

        // 1. Create session
        let resp = coordinator
            .try_create_session("Sender1".to_string(), "FP1".to_string(), ip, files)
            .await
            .expect("First session must succeed");

        assert!(coordinator.is_busy().await);
        let token = resp.files.get("file-1").unwrap().clone();

        // 2. Conflicting concurrent session must be rejected with 409 Conflict
        let conflict_err = coordinator
            .try_create_session("Sender2".to_string(), "FP2".to_string(), ip, HashMap::new())
            .await;
        assert_eq!(conflict_err.unwrap_err(), SessionError::Conflict);

        // 3. Validate upload parameters
        let valid_params = UploadParams {
            session_id: resp.session_id.clone(),
            file_id: "file-1".to_string(),
            token: token.clone(),
        };
        let staged = coordinator
            .validate_upload(&valid_params, ip)
            .await
            .expect("Validation must succeed");
        assert_eq!(staged.status, FileStatus::Streaming);

        // 4. Invalid token rejected
        let bad_params = UploadParams {
            session_id: resp.session_id.clone(),
            file_id: "file-1".to_string(),
            token: "wrong-token".to_string(),
        };
        let err = coordinator.validate_upload(&bad_params, ip).await;
        assert_eq!(err.unwrap_err(), SessionError::InvalidToken);

        // 5. Complete file -> all files done -> session cleared
        let all_done = coordinator
            .complete_file(&resp.session_id, "file-1")
            .await
            .unwrap();
        assert!(all_done);
        assert!(!coordinator.is_busy().await);
    }
}
