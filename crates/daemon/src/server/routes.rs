//! LocalSend v2 Receiver REST API Routes
//!
//! Implements `/api/localsend/v2/info`, `/register`, `/prepare-upload`, `/upload`, and `/cancel`.

use crate::ipc::protocol::{DaemonEvent, FileInfo};
use crate::session::{SessionCoordinator, SessionError};
use crate::storage::{
    commit_file_atomically, get_temp_file_path, stream_to_disk_and_hash, StorageError,
};
use crate::trust::{AutoAcceptMode, TrustStore};
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use localsend_discovery::PeerRegistry;
use localsend_protocol::{
    InfoResponseDto, PrepareUploadRequest, RegisterDto, UploadParams,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

/// Application state shared across all HTTP handlers.
#[derive(Clone)]
pub struct AppState {
    /// Session coordinator managing concurrency locks and upload tokens.
    pub coordinator: SessionCoordinator,
    /// Discovered peer registry.
    pub registry: PeerRegistry,
    /// Local daemon device identity.
    pub device_info: InfoResponseDto,
    /// Destination directory for saved transfers.
    pub save_dir: PathBuf,
    /// Persistent trust store.
    pub trust_store: Arc<RwLock<TrustStore>>,
    /// Event broadcast channel.
    pub event_tx: broadcast::Sender<DaemonEvent>,
}

/// Query parameters for session cancellation.
#[derive(Debug, serde::Deserialize)]
pub struct CancelParams {
    /// Target session ID to abort.
    #[serde(rename = "sessionId")]
    pub session_id: Option<String>,
}

/// Query parameters for upload preparation (optional PIN).
#[derive(Debug, Default, serde::Deserialize)]
pub struct PrepareUploadQuery {
    /// Optional PIN code.
    pub pin: Option<String>,
}

/// Construct the complete Axum router for the LocalSend v2 receiver API.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/api/localsend/v2/info", get(handle_info))
        .route("/api/localsend/v2/register", post(handle_register))
        .route("/api/localsend/v2/prepare-upload", post(handle_prepare_upload))
        .route("/api/localsend/v2/upload", post(handle_upload))
        .route("/api/localsend/v2/cancel", post(handle_cancel))
        .with_state(state)
}

/// GET `/api/localsend/v2/info`
///
/// Returns local daemon identity, version, and device capabilities.
async fn handle_info(State(state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, Json(state.device_info))
}

/// POST `/api/localsend/v2/register`
///
/// Registers the remote peer in the local registry and echoes local device identity.
async fn handle_register(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    Json(dto): Json<RegisterDto>,
) -> impl IntoResponse {
    state.registry.upsert_from_register(&dto, peer_addr).await;

    (StatusCode::OK, Json(state.device_info))
}

/// POST `/api/localsend/v2/prepare-upload`
///
/// Evaluates incoming upload request against PIN and trust store policies.
/// Auto-accepts if trusted or mode is Always; otherwise awaits IPC approval for 30s.
async fn handle_prepare_upload(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    Query(query): Query<PrepareUploadQuery>,
    headers: HeaderMap,
    Json(req): Json<PrepareUploadRequest>,
) -> Response {
    let client_ip = peer_addr.ip();

    // 1. PIN verification
    let provided_pin = query
        .pin
        .as_deref()
        .or_else(|| headers.get("pin").and_then(|h| h.to_str().ok()))
        .or_else(|| headers.get("x-pin").and_then(|h| h.to_str().ok()))
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|h| h.to_str().ok())
                .and_then(|auth| auth.strip_prefix("Bearer "))
        });

    {
        let trust = state.trust_store.read().await;
        if !trust.verify_pin(provided_pin) {
            return (StatusCode::UNAUTHORIZED, "Invalid or missing PIN").into_response();
        }
    }

    // Also register peer in the discovery registry
    let reg_addr = SocketAddr::new(client_ip, req.info.port);
    state.registry.upsert_from_register(&req.info, reg_addr).await;

    // 2. Check Trust policy
    let (is_trusted, auto_accept_mode) = {
        let trust = state.trust_store.read().await;
        (
            trust.is_trusted(client_ip, Some(&req.info.fingerprint)),
            trust.auto_accept_mode(),
        )
    };

    let auto_accept = match auto_accept_mode {
        AutoAcceptMode::Always => true,
        AutoAcceptMode::TrustedOnly => is_trusted,
        AutoAcceptMode::Never => false,
    };

    if auto_accept {
        match state
            .coordinator
            .try_create_session(req.info.alias, req.info.fingerprint, client_ip, req.files)
            .await
        {
            Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
            Err(SessionError::Conflict) => (
                StatusCode::CONFLICT,
                "Another transfer session is currently in progress",
            )
                .into_response(),
            Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        }
    } else {
        // Broadcast incoming session event for interactive approval
        let session_id = uuid::Uuid::new_v4().to_string();
        let files_summary: Vec<FileInfo> = req
            .files
            .iter()
            .map(|(id, f)| FileInfo {
                id: id.clone(),
                file_name: f.file_name.clone(),
                size: f.size,
                file_type: f.file_type.clone(),
            })
            .collect();

        let _ = state.event_tx.send(DaemonEvent::IncomingSession {
            session_id: session_id.clone(),
            peer_alias: req.info.alias.clone(),
            peer_ip: client_ip,
            files: files_summary,
        });

        match state
            .coordinator
            .request_session_approval(
                session_id,
                req.info.alias,
                req.info.fingerprint,
                client_ip,
                req.files,
                std::time::Duration::from_secs(30),
            )
            .await
        {
            Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
            Err(SessionError::Conflict) => (
                StatusCode::CONFLICT,
                "Another transfer session is currently in progress",
            )
                .into_response(),
            Err(SessionError::Rejected) => (
                StatusCode::FORBIDDEN,
                "Session was rejected",
            )
                .into_response(),
            Err(SessionError::ApprovalTimeout) => (
                StatusCode::FORBIDDEN,
                "Session approval timed out",
            )
                .into_response(),
            Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        }
    }
}

/// POST `/api/localsend/v2/upload`
///
/// Streams binary file payload to staging `.part` file, verifies hash and size,
/// and atomically commits to destination folder.
async fn handle_upload(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    Query(params): Query<UploadParams>,
    body: axum::body::Body,
) -> Response {
    let client_ip = peer_addr.ip();

    // 1. Validate session, token, and IP
    let staged_file = match state.coordinator.validate_upload(&params, client_ip).await {
        Ok(f) => f,
        Err(SessionError::SessionNotFound) => {
            return (StatusCode::CONFLICT, "Session not found or expired").into_response();
        }
        Err(SessionError::InvalidToken) => {
            return (StatusCode::FORBIDDEN, "Invalid upload token").into_response();
        }
        Err(SessionError::ForbiddenIp) => {
            return (StatusCode::FORBIDDEN, "Unauthorized client IP").into_response();
        }
        Err(SessionError::FileNotFound) => {
            return (StatusCode::NOT_FOUND, "File not in session manifest").into_response();
        }
        Err(SessionError::Conflict) => {
            return (StatusCode::CONFLICT, "Session conflict").into_response();
        }
        Err(e) => {
            return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
    };

    // 2. Stream to disk and hash
    let temp_path = get_temp_file_path(&state.save_dir, &params.session_id, &params.file_id);
    let stream_result = stream_to_disk_and_hash(
        body,
        &temp_path,
        Some(staged_file.size),
        staged_file.sha256.as_deref(),
    )
    .await;

    match stream_result {
        Ok(_) => {
            // 3. Atomically commit file to final location
            match commit_file_atomically(&temp_path, &state.save_dir, &staged_file.file_name).await {
                Ok(_final_path) => {
                    let _ = state
                        .coordinator
                        .complete_file(&params.session_id, &params.file_id)
                        .await;
                    let _ = state.event_tx.send(DaemonEvent::TransferComplete {
                        session_id: params.session_id.clone(),
                        file_id: params.file_id.clone(),
                        success: true,
                    });
                    StatusCode::OK.into_response()
                }
                Err(e) => {
                    let _ = state
                        .coordinator
                        .fail_file(&params.session_id, &params.file_id)
                        .await;
                    let _ = state.event_tx.send(DaemonEvent::TransferComplete {
                        session_id: params.session_id.clone(),
                        file_id: params.file_id.clone(),
                        success: false,
                    });
                    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
                }
            }
        }
        Err(StorageError::HashMismatch {
            expected,
            calculated,
        }) => {
            let _ = state
                .coordinator
                .fail_file(&params.session_id, &params.file_id)
                .await;
            let _ = state.event_tx.send(DaemonEvent::TransferComplete {
                session_id: params.session_id.clone(),
                file_id: params.file_id.clone(),
                success: false,
            });
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Hash mismatch: expected {expected}, got {calculated}"),
            )
                .into_response()
        }
        Err(e) => {
            let _ = state
                .coordinator
                .fail_file(&params.session_id, &params.file_id)
                .await;
            let _ = state.event_tx.send(DaemonEvent::TransferComplete {
                session_id: params.session_id.clone(),
                file_id: params.file_id.clone(),
                success: false,
            });
            (StatusCode::BAD_REQUEST, e.to_string()).into_response()
        }
    }
}

/// POST `/api/localsend/v2/cancel`
///
/// Aborts active session and cleans up leftover staging files.
async fn handle_cancel(
    State(state): State<AppState>,
    Query(params): Query<CancelParams>,
) -> Response {
    if let Some(session_id) = params.session_id {
        if let Ok(active) = state.coordinator.cancel_session(&session_id).await {
            let _ = state.event_tx.send(DaemonEvent::SessionTerminated {
                session_id: session_id.clone(),
                reason: "Remote peer cancelled session".to_string(),
            });
            // Unlink any staging files for this session
            for file_id in active.files.keys() {
                let temp_path = get_temp_file_path(&state.save_dir, &session_id, file_id);
                if temp_path.exists() {
                    let _ = tokio::fs::remove_file(temp_path).await;
                }
            }
            return StatusCode::OK.into_response();
        }
    }

    StatusCode::OK.into_response()
}
