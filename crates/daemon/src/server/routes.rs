//! LocalSend v2 Receiver REST API Routes
//!
//! Implements `/api/localsend/v2/info`, `/register`, `/prepare-upload`, `/upload`, and `/cancel`.

use crate::session::{SessionCoordinator, SessionError};
use crate::storage::{
    commit_file_atomically, get_temp_file_path, stream_to_disk_and_hash, StorageError,
};
use axum::extract::{ConnectInfo, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use localsend_discovery::PeerRegistry;
use localsend_protocol::{
    InfoResponseDto, PrepareUploadRequest, RegisterDto, UploadParams,
};
use std::net::SocketAddr;
use std::path::PathBuf;

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
}

/// Query parameters for session cancellation.
#[derive(Debug, serde::Deserialize)]
pub struct CancelParams {
    /// Target session ID to abort.
    #[serde(rename = "sessionId")]
    pub session_id: Option<String>,
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
/// Evaluates incoming upload request. Returns HTTP 409 Conflict if another transfer
/// is currently running. Otherwise, creates a session and returns secret tokens per file.
async fn handle_prepare_upload(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    Json(req): Json<PrepareUploadRequest>,
) -> Response {
    let client_ip = peer_addr.ip();

    // Also register peer in the discovery registry
    let reg_addr = SocketAddr::new(client_ip, req.info.port);
    state.registry.upsert_from_register(&req.info, reg_addr).await;

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
                    StatusCode::OK.into_response()
                }
                Err(e) => {
                    let _ = state
                        .coordinator
                        .fail_file(&params.session_id, &params.file_id)
                        .await;
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
