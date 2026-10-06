use localsend_daemon::{
    build_tls_server_config, commit_file_atomically, get_temp_file_path, stream_to_disk_and_hash,
    AppState, AutoAcceptMode, DaemonEvent, ReceiverServer, SessionCoordinator, StorageError,
    TrustStore,
};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use localsend_discovery::PeerRegistry;
use localsend_protocol::crypto::generate_tls_identity;
use localsend_protocol::{
    DeviceType, FileMetadata, InfoResponseDto, PrepareUploadRequest, PrepareUploadResponse,
    ProtocolType, RegisterDto,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn test_storage_streaming_and_atomic_commit() {
    let temp_dir = std::env::temp_dir().join(format!("daemon_storage_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let content = b"High performance atomic disk streaming verification payload.";
    let mut hasher = Sha256::new();
    hasher.update(content);
    let expected_hash = hex::encode_upper(hasher.finalize());

    let temp_file = get_temp_file_path(&temp_dir, "s_test", "f_test");

    // 1. Stream to disk and hash
    let body = axum::body::Body::from(content.to_vec());
    let calculated = stream_to_disk_and_hash(
        body,
        &temp_file,
        Some(content.len() as u64),
        Some(&expected_hash),
    )
    .await
    .expect("Stream should succeed");

    assert_eq!(calculated, expected_hash);
    assert!(temp_file.exists());

    // 2. Commit atomically
    let final_path = commit_file_atomically(&temp_file, &temp_dir, "verified_document.pdf")
        .await
        .expect("Atomic commit must succeed");

    assert!(!temp_file.exists(), ".part file must no longer exist");
    assert!(final_path.exists());
    let read_back = tokio::fs::read(&final_path).await.unwrap();
    assert_eq!(read_back, content);

    // 3. Collision resolution check
    let temp_file_2 = get_temp_file_path(&temp_dir, "s_test_2", "f_test_2");
    tokio::fs::write(&temp_file_2, b"v2").await.unwrap();
    let second_commit = commit_file_atomically(&temp_file_2, &temp_dir, "verified_document.pdf")
        .await
        .unwrap();

    assert_eq!(
        second_commit.file_name().unwrap().to_str().unwrap(),
        "verified_document (1).pdf"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_storage_hash_mismatch_cleans_up_part_file() {
    let temp_dir =
        std::env::temp_dir().join(format!("daemon_mismatch_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let content = b"Actual file data";
    let bad_hash = "DEADBEEF0000111122223333444455556666777788889999AAAABBBBCCCCDDDD";
    let temp_file = get_temp_file_path(&temp_dir, "s_bad", "f_bad");

    let body = axum::body::Body::from(content.to_vec());
    let res = stream_to_disk_and_hash(
        body,
        &temp_file,
        Some(content.len() as u64),
        Some(bad_hash),
    )
    .await;

    assert!(matches!(res, Err(StorageError::HashMismatch { .. })));
    assert!(
        !temp_file.exists(),
        "Staging .part file must be cleaned up on hash mismatch"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_full_https_receiver_flow() {
    let temp_dir = std::env::temp_dir().join(format!("daemon_e2e_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    // 1. Initialize TLS & Server
    let identity = generate_tls_identity("TestServer", &[]).unwrap();
    let tls_config = build_tls_server_config(&identity).unwrap();

    let coordinator = SessionCoordinator::default();
    let registry = PeerRegistry::new();
    let device_info = InfoResponseDto {
        alias: "TestDaemon".to_string(),
        version: "2.0".to_string(),
        device_model: Some("Headless Server".to_string()),
        device_type: Some(DeviceType::Headless),
        fingerprint: identity.fingerprint.clone(),
        port: 0,
        protocol: ProtocolType::Https,
        download: true,
    };

    let trust_config_path = temp_dir.join("trusted_devices.yaml");
    let mut trust_store = TrustStore::load_or_create(&trust_config_path).unwrap();
    trust_store.set_mode(AutoAcceptMode::Always).unwrap();
    let trust_store = Arc::new(RwLock::new(trust_store));
    let (event_tx, _) = broadcast::channel::<DaemonEvent>(128);

    let state = AppState {
        coordinator,
        registry,
        device_info,
        save_dir: temp_dir.clone(),
        trust_store,
        event_tx,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let port = local_addr.port();

    let server = ReceiverServer::new(state, tls_config);
    let cancel = CancellationToken::new();
    let cancel_server = cancel.clone();

    tokio::spawn(async move {
        let _ = server.run(listener, cancel_server).await;
    });

    // 2. Client Setup
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let base_url = format!("https://127.0.0.1:{port}/api/localsend/v2");

    // A. Query /info
    let info_res = client
        .get(format!("{base_url}/info"))
        .send()
        .await
        .expect("GET /info failed");
    assert_eq!(info_res.status(), reqwest::StatusCode::OK);
    let info_body: InfoResponseDto = info_res.json().await.unwrap();
    assert_eq!(info_body.alias, "TestDaemon");

    // B. Query /register
    let reg_dto = RegisterDto {
        alias: "ClientNode".to_string(),
        version: "2.0".to_string(),
        device_model: Some("Client".to_string()),
        device_type: Some(DeviceType::Desktop),
        fingerprint: "CLIENT_FINGERPRINT_123".to_string(),
        port: 53317,
        protocol: ProtocolType::Https,
        download: true,
    };
    let reg_res = client
        .post(format!("{base_url}/register"))
        .json(&reg_dto)
        .send()
        .await
        .expect("POST /register failed");
    assert_eq!(reg_res.status(), reqwest::StatusCode::OK);

    // C. Prepare upload
    let file_content = b"Content to transfer over LocalSend v2 HTTPS.";
    let mut hasher = Sha256::new();
    hasher.update(file_content);
    let file_sha256 = hex::encode_upper(hasher.finalize());

    let mut files = HashMap::new();
    files.insert(
        "file-abc-1".to_string(),
        FileMetadata {
            id: "file-abc-1".to_string(),
            file_name: "test_report.pdf".to_string(),
            size: file_content.len() as u64,
            file_type: "application/pdf".to_string(),
            sha256: Some(file_sha256.clone()),
            preview: None,
            metadata: None,
        },
    );

    let prep_req = PrepareUploadRequest {
        info: reg_dto.clone(),
        files,
    };

    let prep_res = client
        .post(format!("{base_url}/prepare-upload"))
        .json(&prep_req)
        .send()
        .await
        .expect("POST /prepare-upload failed");
    assert_eq!(prep_res.status(), reqwest::StatusCode::OK);

    let prep_body: PrepareUploadResponse = prep_res.json().await.unwrap();
    let session_id = prep_body.session_id;
    let token = prep_body.files.get("file-abc-1").unwrap().clone();

    // D. Test Concurrency Lock: second prepare-upload while session active must return 409 Conflict
    let conflict_res = client
        .post(format!("{base_url}/prepare-upload"))
        .json(&prep_req)
        .send()
        .await
        .unwrap();
    assert_eq!(conflict_res.status(), reqwest::StatusCode::CONFLICT);

    // E. Execute Upload
    let upload_url = format!(
        "{base_url}/upload?sessionId={session_id}&fileId=file-abc-1&token={token}"
    );
    let upload_res = client
        .post(&upload_url)
        .body(file_content.to_vec())
        .send()
        .await
        .expect("POST /upload failed");
    assert_eq!(upload_res.status(), reqwest::StatusCode::OK);

    // Verify file committed to disk
    let destination_file = temp_dir.join("test_report.pdf");
    assert!(
        destination_file.exists(),
        "Transferred file must exist at destination"
    );
    let read_data = tokio::fs::read(&destination_file).await.unwrap();
    assert_eq!(read_data, file_content);

    // Clean up
    cancel.cancel();
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_cancel_session_flow() {
    let temp_dir =
        std::env::temp_dir().join(format!("daemon_cancel_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let identity = generate_tls_identity("CancelServer", &[]).unwrap();
    let tls_config = build_tls_server_config(&identity).unwrap();

    let coordinator = SessionCoordinator::default();
    let registry = PeerRegistry::new();
    let device_info = InfoResponseDto {
        alias: "CancelDaemon".to_string(),
        version: "2.0".to_string(),
        device_model: None,
        device_type: None,
        fingerprint: identity.fingerprint,
        port: 0,
        protocol: ProtocolType::Https,
        download: true,
    };

    let trust_config_path = temp_dir.join("trusted_devices_cancel.yaml");
    let mut trust_store = TrustStore::load_or_create(&trust_config_path).unwrap();
    trust_store.set_mode(AutoAcceptMode::Always).unwrap();
    let trust_store = Arc::new(RwLock::new(trust_store));
    let (event_tx, _) = broadcast::channel::<DaemonEvent>(128);

    let state = AppState {
        coordinator: coordinator.clone(),
        registry,
        device_info,
        save_dir: temp_dir.clone(),
        trust_store,
        event_tx,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cancel = CancellationToken::new();
    let cancel_server = cancel.clone();

    let server = ReceiverServer::new(state, tls_config);
    tokio::spawn(async move {
        let _ = server.run(listener, cancel_server).await;
    });

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let base_url = format!("https://127.0.0.1:{port}/api/localsend/v2");

    // Prepare upload
    let reg_dto = RegisterDto {
        alias: "Sender".to_string(),
        version: "2.0".to_string(),
        device_model: None,
        device_type: None,
        fingerprint: "FP".to_string(),
        port: 53317,
        protocol: ProtocolType::Https,
        download: true,
    };
    let mut files = HashMap::new();
    files.insert(
        "file-cancel-1".to_string(),
        FileMetadata {
            id: "file-cancel-1".to_string(),
            file_name: "will_cancel.txt".to_string(),
            size: 50,
            file_type: "text/plain".to_string(),
            sha256: None,
            preview: None,
            metadata: None,
        },
    );

    let prep_res: PrepareUploadResponse = client
        .post(format!("{base_url}/prepare-upload"))
        .json(&PrepareUploadRequest {
            info: reg_dto,
            files,
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(coordinator.is_busy().await);

    // Cancel session
    let cancel_res = client
        .post(format!("{base_url}/cancel?sessionId={}", prep_res.session_id))
        .send()
        .await
        .unwrap();
    assert_eq!(cancel_res.status(), reqwest::StatusCode::OK);

    assert!(!coordinator.is_busy().await, "Session must be cleared after cancel");

    cancel.cancel();
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}
