//! End-to-End Loopback Integration Tests
//!
//! Validates real network transfers over ephemeral loopback ports without external hardware:
//! - Full transfer happy path with 5 MiB payload using `lsend` client with pinned TLS
//! - Hash mismatch detection, HTTP 422 response, and staging .part file cleanup
//! - Path traversal defense rejecting directory traversal and confining writes to destination root
//! - Concurrency conflict enforcement returning HTTP 409 Conflict

use localsend_cli::commands::send;
use localsend_daemon::{
    AppState, AutoAcceptMode, DaemonEvent, ReceiverServer, SessionCoordinator, TrustStore,
    build_tls_server_config,
};
use localsend_discovery::PeerRegistry;
use localsend_protocol::crypto::generate_tls_identity;
use localsend_protocol::{
    DeviceType, FileMetadata, InfoResponseDto, PrepareUploadRequest, PrepareUploadResponse,
    ProtocolType, RegisterDto,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, broadcast};
use tokio_util::sync::CancellationToken;

struct TestServerHandle {
    port: u16,
    fingerprint: String,
    save_dir: PathBuf,
    cancel: CancellationToken,
}

impl Drop for TestServerHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn spawn_test_server(auto_accept: AutoAcceptMode) -> TestServerHandle {
    let temp_root = std::env::temp_dir().join(format!("localsend_e2e_{}", uuid::Uuid::new_v4()));
    let save_dir = temp_root.join("incoming");
    tokio::fs::create_dir_all(&save_dir).await.unwrap();

    let server_identity = generate_tls_identity("E2ETestDaemon", &[]).unwrap();
    let server_tls = build_tls_server_config(&server_identity).unwrap();

    let trust_cfg = temp_root.join("trusted.yaml");
    let mut trust_store = TrustStore::load_or_create(&trust_cfg).unwrap();
    trust_store.set_mode(auto_accept).unwrap();
    let trust_store = Arc::new(RwLock::new(trust_store));
    let (event_tx, _) = broadcast::channel::<DaemonEvent>(128);

    let state = AppState {
        coordinator: SessionCoordinator::default(),
        registry: PeerRegistry::new(),
        device_info: InfoResponseDto {
            alias: "E2ETestDaemon".to_string(),
            version: "2.0".to_string(),
            device_model: Some("Loopback Test Harness".to_string()),
            device_type: Some(DeviceType::Headless),
            fingerprint: server_identity.fingerprint.clone(),
            port: 0,
            protocol: ProtocolType::Https,
            download: true,
        },
        save_dir: save_dir.clone(),
        trust_store,
        event_tx,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cancel = CancellationToken::new();
    let server = ReceiverServer::new(state, server_tls);
    let cancel_server = cancel.clone();

    tokio::spawn(async move {
        let _ = server.run(listener, cancel_server).await;
    });

    TestServerHandle {
        port,
        fingerprint: server_identity.fingerprint,
        save_dir,
        cancel,
    }
}

fn create_test_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

fn sample_sender_info() -> RegisterDto {
    RegisterDto {
        alias: "E2EClient".to_string(),
        version: "2.0".to_string(),
        device_model: Some("CLI Tester".to_string()),
        device_type: Some(DeviceType::Desktop),
        fingerprint: "CLIENT_FINGERPRINT_SAMPLE_HEX".to_string(),
        port: 53317,
        protocol: ProtocolType::Https,
        download: true,
    }
}

/// Test 1: Full Transfer Happy Path
///
/// Spins up an in-memory localsendd server on 127.0.0.1:0 with AutoAcceptMode::Always.
/// Sends a 5 MiB test file of pseudorandom data via `lsend` send client with pinned TLS.
/// Verifies prepare-upload, streaming bytes, 200 OK, exact byte size, and SHA-256 match.
#[tokio::test]
async fn test_full_transfer_happy_path() {
    let server = spawn_test_server(AutoAcceptMode::Always).await;
    let target_addr = format!("127.0.0.1:{}", server.port);

    // Prepare 5 MiB payload
    let send_dir = server.save_dir.parent().unwrap().join("send");
    tokio::fs::create_dir_all(&send_dir).await.unwrap();
    let test_file = send_dir.join("payload_5mib.bin");

    const PAYLOAD_SIZE: usize = 5 * 1024 * 1024;
    let mut payload = Vec::with_capacity(PAYLOAD_SIZE);
    let mut hasher = Sha256::new();
    for i in 0..PAYLOAD_SIZE {
        let b = ((i * 37 + 101) % 256) as u8;
        payload.push(b);
    }
    hasher.update(&payload);
    let expected_sha256 = hex::encode_upper(hasher.finalize());

    tokio::fs::write(&test_file, &payload).await.unwrap();

    // Use lsend send command with pinned fingerprint
    let send_result = send::run(
        &target_addr,
        &[test_file],
        None,
        Some(server.fingerprint.clone()),
        true, // standalone
        true, // json
    )
    .await;

    assert!(
        send_result.is_ok(),
        "5 MiB transfer should succeed: {:?}",
        send_result.err()
    );

    // Verify committed file in server destination directory
    let received_file = server.save_dir.join("payload_5mib.bin");
    assert!(
        received_file.exists(),
        "Transferred file must exist in receiver directory"
    );

    let metadata = tokio::fs::metadata(&received_file).await.unwrap();
    assert_eq!(
        metadata.len(),
        PAYLOAD_SIZE as u64,
        "Committed file length must exactly match 5 MiB"
    );

    let received_bytes = tokio::fs::read(&received_file).await.unwrap();
    let mut received_hasher = Sha256::new();
    received_hasher.update(&received_bytes);
    let received_sha256 = hex::encode_upper(received_hasher.finalize());

    assert_eq!(
        received_sha256, expected_sha256,
        "Committed file SHA-256 digest must match exactly"
    );

    // Verify no leftover .part files exist
    let mut dir = tokio::fs::read_dir(&server.save_dir).await.unwrap();
    while let Ok(Some(entry)) = dir.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(
            !name.ends_with(".part"),
            "Zero .part files must remain in destination folder: found {name}"
        );
    }

    let _ = tokio::fs::remove_dir_all(server.save_dir.parent().unwrap()).await;
}

/// Test 2: Hash Mismatch Rejection
///
/// Simulates an upload with corrupted payload bytes differing from declared SHA-256 metadata.
/// Verifies the server returns HTTP 422 Unprocessable Entity, unlinks the staging .part file,
/// and leaves zero partial artifacts.
#[tokio::test]
async fn test_hash_mismatch_rejection() {
    let server = spawn_test_server(AutoAcceptMode::Always).await;
    let client = create_test_client();
    let base_url = format!("https://127.0.0.1:{}/api/localsend/v2", server.port);

    let file_id = "file-corrupt-001";
    let file_name = "corrupted_document.pdf";
    let original_bytes = b"Authentic payload bytes before intentional transmission corruption";
    let corrupted_bytes = b"Tampered payload bytes differing from declared SHA-256 digest";

    let mut hasher = Sha256::new();
    hasher.update(original_bytes);
    let authentic_sha256 = hex::encode_upper(hasher.finalize());

    let mut files = HashMap::new();
    files.insert(
        file_id.to_string(),
        FileMetadata {
            id: file_id.to_string(),
            file_name: file_name.to_string(),
            size: corrupted_bytes.len() as u64,
            file_type: "application/pdf".to_string(),
            sha256: Some(authentic_sha256),
            preview: None,
            metadata: None,
        },
    );

    let prep_req = PrepareUploadRequest {
        info: sample_sender_info(),
        files,
    };

    let prep_res = client
        .post(format!("{base_url}/prepare-upload"))
        .json(&prep_req)
        .send()
        .await
        .expect("prepare-upload request must succeed");

    assert_eq!(prep_res.status(), reqwest::StatusCode::OK);
    let prep_data: PrepareUploadResponse = prep_res.json().await.unwrap();
    let session_id = prep_data.session_id;
    let token = prep_data.files.get(file_id).unwrap();

    // Perform upload with corrupted bytes
    let upload_url =
        format!("{base_url}/upload?sessionId={session_id}&fileId={file_id}&token={token}");
    let upload_res = client
        .post(&upload_url)
        .body(corrupted_bytes.to_vec())
        .send()
        .await
        .expect("upload request failed");

    // Server must reject with HTTP 422 Unprocessable Entity
    assert_eq!(
        upload_res.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "Server must return HTTP 422 on hash mismatch"
    );

    // Staging .part file and final file must not exist
    let committed_file = server.save_dir.join(file_name);
    assert!(
        !committed_file.exists(),
        "Corrupted file must never be committed to destination"
    );

    let mut dir = tokio::fs::read_dir(&server.save_dir).await.unwrap();
    let mut part_files = 0;
    while let Ok(Some(entry)) = dir.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".part") {
            part_files += 1;
        }
    }
    assert_eq!(
        part_files, 0,
        "Staging .part file must be unlinked and purged on hash mismatch"
    );

    let _ = tokio::fs::remove_dir_all(server.save_dir.parent().unwrap()).await;
}

/// Test 3: Path Traversal Defense
///
/// Issues uploads with malicious filenames (../../etc/passwd, ..\..\cmd.exe) and nested paths.
/// Verifies the server sanitizes paths, rejects directory escapes, and strictly prevents
/// traversal out of the destination root.
#[tokio::test]
async fn test_path_traversal_defense() {
    let server = spawn_test_server(AutoAcceptMode::Always).await;
    let client = create_test_client();
    let base_url = format!("https://127.0.0.1:{}/api/localsend/v2", server.port);

    // 1. Test traversal sequence: ../../etc/passwd
    let unix_traversal = "../../etc/passwd";
    let payload = b"malicious exploit payload";
    let mut files = HashMap::new();
    files.insert(
        "f-unix".to_string(),
        FileMetadata {
            id: "f-unix".to_string(),
            file_name: unix_traversal.to_string(),
            size: payload.len() as u64,
            file_type: "text/plain".to_string(),
            sha256: None,
            preview: None,
            metadata: None,
        },
    );

    let prep_res = client
        .post(format!("{base_url}/prepare-upload"))
        .json(&PrepareUploadRequest {
            info: sample_sender_info(),
            files,
        })
        .send()
        .await
        .unwrap();

    let prep_data: PrepareUploadResponse = prep_res.json().await.unwrap();
    let token = prep_data.files.get("f-unix").unwrap();

    let upload_res = client
        .post(format!(
            "{base_url}/upload?sessionId={}&fileId=f-unix&token={token}",
            prep_data.session_id
        ))
        .body(payload.to_vec())
        .send()
        .await
        .unwrap();

    // Must not succeed in escaping
    assert!(
        !upload_res.status().is_success() || upload_res.status().is_client_error(),
        "Path traversal attempt must be rejected or denied"
    );

    // Verify traversal target does not exist outside destination root
    let parent_dir = server.save_dir.parent().unwrap();
    assert!(
        !parent_dir.join("etc").join("passwd").exists(),
        "Path traversal must never create files outside destination directory"
    );

    // 2. Test Windows backslash traversal: ..\..\cmd.exe
    let win_traversal = r"..\..\cmd.exe";
    let mut files_win = HashMap::new();
    files_win.insert(
        "f-win".to_string(),
        FileMetadata {
            id: "f-win".to_string(),
            file_name: win_traversal.to_string(),
            size: payload.len() as u64,
            file_type: "application/octet-stream".to_string(),
            sha256: None,
            preview: None,
            metadata: None,
        },
    );

    let prep_win = client
        .post(format!("{base_url}/prepare-upload"))
        .json(&PrepareUploadRequest {
            info: sample_sender_info(),
            files: files_win,
        })
        .send()
        .await
        .unwrap();

    let prep_win_data: PrepareUploadResponse = prep_win.json().await.unwrap();
    let token_win = prep_win_data.files.get("f-win").unwrap();

    let upload_win_res = client
        .post(format!(
            "{base_url}/upload?sessionId={}&fileId=f-win&token={token_win}",
            prep_win_data.session_id
        ))
        .body(payload.to_vec())
        .send()
        .await
        .unwrap();

    assert!(
        !upload_win_res.status().is_success() || upload_win_res.status().is_client_error(),
        "Windows path traversal attempt must be rejected"
    );

    assert!(
        !parent_dir.join("cmd.exe").exists(),
        "Traversal out of destination root must be completely prevented"
    );

    // 3. Test nested path: sanitized to safe local basename
    let nested_file = "nested/subfolder/safe_file.txt";
    let mut files_nested = HashMap::new();
    files_nested.insert(
        "f-nested".to_string(),
        FileMetadata {
            id: "f-nested".to_string(),
            file_name: nested_file.to_string(),
            size: payload.len() as u64,
            file_type: "text/plain".to_string(),
            sha256: None,
            preview: None,
            metadata: None,
        },
    );

    let prep_nested = client
        .post(format!("{base_url}/prepare-upload"))
        .json(&PrepareUploadRequest {
            info: sample_sender_info(),
            files: files_nested,
        })
        .send()
        .await
        .unwrap();

    let prep_nested_data: PrepareUploadResponse = prep_nested.json().await.unwrap();
    let token_nested = prep_nested_data.files.get("f-nested").unwrap();

    let upload_nested_res = client
        .post(format!(
            "{base_url}/upload?sessionId={}&fileId=f-nested&token={token_nested}",
            prep_nested_data.session_id
        ))
        .body(payload.to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(upload_nested_res.status(), reqwest::StatusCode::OK);
    let committed_nested = server.save_dir.join("safe_file.txt");
    assert!(
        committed_nested.exists(),
        "Sanitized basename safe_file.txt must exist inside destination root"
    );

    let _ = tokio::fs::remove_dir_all(parent_dir).await;
}

/// Test 4: Concurrency Conflict
///
/// While one upload session is active, attempts a concurrent prepare-upload from
/// a different session. Verifies the server returns HTTP 409 Conflict.
#[tokio::test]
async fn test_concurrency_conflict() {
    let server = spawn_test_server(AutoAcceptMode::Always).await;
    let client = create_test_client();
    let base_url = format!("https://127.0.0.1:{}/api/localsend/v2", server.port);

    let mut files1 = HashMap::new();
    files1.insert(
        "file-sess1".to_string(),
        FileMetadata {
            id: "file-sess1".to_string(),
            file_name: "sess1_doc.pdf".to_string(),
            size: 1024,
            file_type: "application/pdf".to_string(),
            sha256: None,
            preview: None,
            metadata: None,
        },
    );

    let prep1_res = client
        .post(format!("{base_url}/prepare-upload"))
        .json(&PrepareUploadRequest {
            info: sample_sender_info(),
            files: files1,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(
        prep1_res.status(),
        reqwest::StatusCode::OK,
        "Initial session prepare-upload must succeed"
    );
    let prep1_data: PrepareUploadResponse = prep1_res.json().await.unwrap();

    // 2. Attempt concurrent session while session 1 is active
    let mut files2 = HashMap::new();
    files2.insert(
        "file-sess2".to_string(),
        FileMetadata {
            id: "file-sess2".to_string(),
            file_name: "sess2_image.png".to_string(),
            size: 2048,
            file_type: "image/png".to_string(),
            sha256: None,
            preview: None,
            metadata: None,
        },
    );

    let prep2_res = client
        .post(format!("{base_url}/prepare-upload"))
        .json(&PrepareUploadRequest {
            info: sample_sender_info(),
            files: files2.clone(),
        })
        .send()
        .await
        .unwrap();

    assert_eq!(
        prep2_res.status(),
        reqwest::StatusCode::CONFLICT,
        "Concurrent prepare-upload must return HTTP 409 Conflict"
    );

    // 3. Cancel active session 1
    let cancel_res = client
        .post(format!(
            "{base_url}/cancel?sessionId={}",
            prep1_data.session_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(cancel_res.status(), reqwest::StatusCode::OK);

    // 4. Retry session 2: must now succeed with 200 OK
    let prep2_retry = client
        .post(format!("{base_url}/prepare-upload"))
        .json(&PrepareUploadRequest {
            info: sample_sender_info(),
            files: files2,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(
        prep2_retry.status(),
        reqwest::StatusCode::OK,
        "Subsequent session must succeed after previous session termination"
    );

    let _ = tokio::fs::remove_dir_all(server.save_dir.parent().unwrap()).await;
}
