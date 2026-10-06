//! Phase 4 Integration Tests: IPC, Trust Store, PIN Security, and Interactive Approvals

use futures_util::{SinkExt, StreamExt};
use localsend_daemon::{
    build_tls_server_config, handle_ipc_client, AppState, AutoAcceptMode, DaemonEvent,
    IpcMessage, IpcPayload, IpcRequest, IpcResponse, IpcServerState, ReceiverServer,
    SessionCoordinator, SessionError, TrustStore,
};
use localsend_discovery::PeerRegistry;
use localsend_protocol::crypto::generate_tls_identity;
use localsend_protocol::{
    DeviceType, FileMetadata, InfoResponseDto, PrepareUploadRequest, PrepareUploadResponse,
    ProtocolType, RegisterDto,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::duplex;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};
use tokio_util::codec::{Framed, LinesCodec};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn test_trust_store_cidr_fingerprint_and_pin() {
    let temp_dir = std::env::temp_dir().join(format!("trust_it_{}", uuid::Uuid::new_v4()));
    let cfg_path = temp_dir.join("trusted_devices.yaml");

    let mut store = TrustStore::load_or_create(&cfg_path).unwrap();
    assert_eq!(store.auto_accept_mode(), AutoAcceptMode::TrustedOnly);

    let ip_in_range = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
    let ip_out_of_range = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let fp = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";

    // 1. Initial state: untrusted
    assert!(!store.is_trusted(ip_in_range, Some(fp)));

    // 2. Add pinned fingerprint
    store
        .add_fingerprint(fp.to_string(), Some("My Laptop".to_string()))
        .unwrap();
    assert!(store.is_trusted(ip_out_of_range, Some(fp)));

    // 3. Add CIDR subnet
    let cidr = ipnet::IpNet::from_str("192.168.1.0/24").unwrap();
    store.add_subnet(cidr).unwrap();
    assert!(store.is_trusted(ip_in_range, None));
    assert!(!store.is_trusted(ip_out_of_range, None));

    // 4. Constant-time PIN validation
    assert!(store.verify_pin(None));
    store.set_pin(Some("482910".to_string())).unwrap();
    assert!(!store.verify_pin(None));
    assert!(!store.verify_pin(Some("111111")));
    assert!(store.verify_pin(Some("482910")));

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_ipc_roundtrip_commands_and_event_streaming() {
    let temp_dir = std::env::temp_dir().join(format!("ipc_test_{}", uuid::Uuid::new_v4()));
    let cfg_path = temp_dir.join("trusted.yaml");

    let trust_store = Arc::new(RwLock::new(TrustStore::load_or_create(&cfg_path).unwrap()));
    let (event_tx, _) = broadcast::channel::<DaemonEvent>(64);
    let coordinator = SessionCoordinator::default();
    let registry = PeerRegistry::new();

    let ipc_state = IpcServerState {
        coordinator,
        registry,
        trust_store: trust_store.clone(),
        event_tx: event_tx.clone(),
        start_time: Instant::now(),
        bound_ips: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
    };

    // Use in-memory duplex channel to test framed IPC stream cross-platform
    let (client_stream, server_stream) = duplex(64 * 1024);

    tokio::spawn(async move {
        let _ = handle_ipc_client(server_stream, ipc_state).await;
    });

    let mut client_framed = Framed::new(client_stream, LinesCodec::new());

    // 1. Send GetStatus
    let msg1 = IpcMessage::request("1", IpcRequest::GetStatus);
    client_framed
        .send(serde_json::to_string(&msg1).unwrap())
        .await
        .unwrap();
    let resp1_str = client_framed.next().await.unwrap().unwrap();
    let resp1: IpcMessage = serde_json::from_str(&resp1_str).unwrap();
    assert_eq!(resp1.id.as_deref(), Some("1"));
    if let IpcPayload::Response(IpcResponse::Status(status)) = resp1.payload {
        assert_eq!(status.bound_ips, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
        assert_eq!(status.active_session, None);
    } else {
        panic!("Expected Status response");
    }

    // 2. Send ListPeers
    let msg2 = IpcMessage::request("2", IpcRequest::ListPeers);
    client_framed
        .send(serde_json::to_string(&msg2).unwrap())
        .await
        .unwrap();
    let resp2_str = client_framed.next().await.unwrap().unwrap();
    let resp2: IpcMessage = serde_json::from_str(&resp2_str).unwrap();
    assert_eq!(resp2.id.as_deref(), Some("2"));
    if let IpcPayload::Response(IpcResponse::Peers(peers)) = resp2.payload {
        assert!(peers.is_empty());
    } else {
        panic!("Expected Peers response");
    }

    // 3. Send SetTrustMode
    let msg3 = IpcMessage::request(
        "3",
        IpcRequest::SetTrustMode {
            mode: AutoAcceptMode::Always,
        },
    );
    client_framed
        .send(serde_json::to_string(&msg3).unwrap())
        .await
        .unwrap();
    let resp3_str = client_framed.next().await.unwrap().unwrap();
    let resp3: IpcMessage = serde_json::from_str(&resp3_str).unwrap();
    assert_eq!(resp3.payload, IpcPayload::Response(IpcResponse::Ok));
    assert_eq!(
        trust_store.read().await.auto_accept_mode(),
        AutoAcceptMode::Always
    );

    // 4. Send AddTrustedPeer
    let msg4 = IpcMessage::request(
        "4",
        IpcRequest::AddTrustedPeer {
            fingerprint: "112233".to_string(),
            alias: Some("Peer1".to_string()),
        },
    );
    client_framed
        .send(serde_json::to_string(&msg4).unwrap())
        .await
        .unwrap();
    let resp4_str = client_framed.next().await.unwrap().unwrap();
    let resp4: IpcMessage = serde_json::from_str(&resp4_str).unwrap();
    assert_eq!(resp4.payload, IpcPayload::Response(IpcResponse::Ok));
    assert!(trust_store
        .read()
        .await
        .is_trusted(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), Some("112233")));

    // 5. Subscribe to events
    let msg5 = IpcMessage::request("5", IpcRequest::SubscribeEvents);
    client_framed
        .send(serde_json::to_string(&msg5).unwrap())
        .await
        .unwrap();
    let resp5_str = client_framed.next().await.unwrap().unwrap();
    let resp5: IpcMessage = serde_json::from_str(&resp5_str).unwrap();
    assert_eq!(resp5.payload, IpcPayload::Response(IpcResponse::Ok));

    // 6. Broadcast event and verify receipt
    let test_event = DaemonEvent::SessionTerminated {
        session_id: "sess-abc".to_string(),
        reason: "User cancelled".to_string(),
    };
    event_tx.send(test_event.clone()).unwrap();

    let event_str = client_framed.next().await.unwrap().unwrap();
    let event_msg: IpcMessage = serde_json::from_str(&event_str).unwrap();
    assert_eq!(event_msg.payload, IpcPayload::Event(test_event));

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_interactive_session_approval_and_rejection() {
    let temp_dir = std::env::temp_dir().join(format!("approval_test_{}", uuid::Uuid::new_v4()));
    let cfg_path = temp_dir.join("trusted.yaml");
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let mut store = TrustStore::load_or_create(&cfg_path).unwrap();
    store.set_mode(AutoAcceptMode::Never).unwrap(); // Requires approval!
    let trust_store = Arc::new(RwLock::new(store));
    let (event_tx, _) = broadcast::channel::<DaemonEvent>(64);
    let coordinator = SessionCoordinator::default();
    let registry = PeerRegistry::new();

    let identity = generate_tls_identity("ApprovalDaemon", &[]).unwrap();
    let tls_config = build_tls_server_config(&identity).unwrap();

    let device_info = InfoResponseDto {
        alias: "ApprovalDaemon".to_string(),
        version: "2.0".to_string(),
        device_model: None,
        device_type: Some(DeviceType::Headless),
        fingerprint: identity.fingerprint.clone(),
        port: 0,
        protocol: ProtocolType::Https,
        download: true,
    };

    let app_state = AppState {
        coordinator: coordinator.clone(),
        registry: registry.clone(),
        device_info,
        save_dir: temp_dir.clone(),
        trust_store: trust_store.clone(),
        event_tx: event_tx.clone(),
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cancel = CancellationToken::new();
    let server = ReceiverServer::new(app_state, tls_config);
    let cancel_server = cancel.clone();
    tokio::spawn(async move {
        let _ = server.run(listener, cancel_server).await;
    });

    let http_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let mut files = HashMap::new();
    files.insert(
        "file-1".to_string(),
        FileMetadata {
            id: "file-1".to_string(),
            file_name: "test.txt".to_string(),
            size: 100,
            file_type: "text/plain".to_string(),
            sha256: None,
            preview: None,
            metadata: None,
        },
    );

    let prepare_req = PrepareUploadRequest {
        info: RegisterDto {
            alias: "UntrustedPhone".to_string(),
            version: "2.0".to_string(),
            device_model: None,
            device_type: Some(DeviceType::Mobile),
            fingerprint: "UNTRUSTED_FP".to_string(),
            port: 53317,
            protocol: ProtocolType::Https,
            download: true,
        },
        files,
    };

    // --- Scenario A: IPC approves session ---
    let mut event_rx = event_tx.subscribe();
    let prepare_url = format!("https://127.0.0.1:{port}/api/localsend/v2/prepare-upload");

    let client_post = {
        let http = http_client.clone();
        let body = prepare_req.clone();
        let url = prepare_url.clone();
        tokio::spawn(async move {
            http.post(&url).json(&body).send().await
        })
    };

    // Wait for DaemonEvent::IncomingSession
    let received_session_id = match event_rx.recv().await.unwrap() {
        DaemonEvent::IncomingSession { session_id, peer_alias, .. } => {
            assert_eq!(peer_alias, "UntrustedPhone");
            session_id
        }
        other => panic!("Unexpected event: {other:?}"),
    };

    // Coordinator approves pending session
    assert!(coordinator.approve_pending_session(&received_session_id).await);

    // HTTP POST should now resolve with 200 OK
    let post_resp = client_post.await.unwrap().unwrap();
    assert_eq!(post_resp.status(), reqwest::StatusCode::OK);
    let upload_prep: PrepareUploadResponse = post_resp.json().await.unwrap();
    assert_eq!(upload_prep.session_id, received_session_id);
    assert!(upload_prep.files.contains_key("file-1"));

    // Clean up active session
    let _ = coordinator.cancel_session(&received_session_id).await;

    // --- Scenario B: IPC rejects session ---
    let client_post_reject = {
        let http = http_client.clone();
        let body = prepare_req.clone();
        let url = prepare_url.clone();
        tokio::spawn(async move {
            http.post(&url).json(&body).send().await
        })
    };

    let reject_session_id = match event_rx.recv().await.unwrap() {
        DaemonEvent::IncomingSession { session_id, .. } => session_id,
        other => panic!("Unexpected event: {other:?}"),
    };

    // Coordinator rejects pending session
    assert!(coordinator.reject_pending_session(&reject_session_id).await);

    // HTTP POST should resolve with 403 Forbidden
    let reject_resp = client_post_reject.await.unwrap().unwrap();
    assert_eq!(reject_resp.status(), reqwest::StatusCode::FORBIDDEN);

    // --- Scenario C: PIN protection ---
    trust_store.write().await.set_pin(Some("777888".to_string())).unwrap();

    // Post without PIN -> 401 Unauthorized
    let unauth_resp = http_client
        .post(&prepare_url)
        .json(&prepare_req)
        .send()
        .await
        .unwrap();
    assert_eq!(unauth_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Post with wrong PIN query parameter -> 401 Unauthorized
    let wrong_pin_resp = http_client
        .post(&format!("{prepare_url}?pin=000000"))
        .json(&prepare_req)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_pin_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    cancel.cancel();
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_session_approval_timeout() {
    let coordinator = SessionCoordinator::default();
    let mut files = HashMap::new();
    files.insert(
        "f1".to_string(),
        FileMetadata {
            id: "f1".to_string(),
            file_name: "timeout_test.txt".to_string(),
            size: 50,
            file_type: "text/plain".to_string(),
            sha256: None,
            preview: None,
            metadata: None,
        },
    );

    // Request approval with 50ms timeout and never approve
    let result = coordinator
        .request_session_approval(
            "timeout_sess".to_string(),
            "Peer".to_string(),
            "FP".to_string(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            files,
            Duration::from_millis(50),
        )
        .await;

    assert_eq!(result, Err(SessionError::ApprovalTimeout));
}
