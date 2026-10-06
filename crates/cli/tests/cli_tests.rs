//! Phase 5 Integration Tests: CLI Commands, Pinned TLS Sender, and End-to-End File Transfer

use clap::Parser;
use localsend_cli::commands::send;
use localsend_cli::tls_client::FingerprintVerifier;
use localsend_cli::{Cli, Commands, TrustAction};
use localsend_daemon::{
    build_tls_server_config, AppState, AutoAcceptMode, DaemonEvent, ReceiverServer,
    SessionCoordinator, TrustStore,
};
use localsend_discovery::PeerRegistry;
use localsend_protocol::crypto::generate_tls_identity;
use localsend_protocol::{DeviceType, InfoResponseDto, ProtocolType};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};
use tokio_util::sync::CancellationToken;

#[test]
fn test_cli_subcommands_syntax_and_defaults() {
    // 1. scan defaults
    let cli = Cli::try_parse_from(["lsend", "scan"]).unwrap();
    assert_eq!(
        cli.command,
        Commands::Scan {
            duration: 3,
            http_scan: false,
        }
    );
    assert!(!cli.json);

    // 2. scan custom
    let cli = Cli::try_parse_from(["lsend", "--json", "scan", "--duration", "10", "--http-scan"]).unwrap();
    assert_eq!(
        cli.command,
        Commands::Scan {
            duration: 10,
            http_scan: true,
        }
    );
    assert!(cli.json);

    // 3. send full arguments
    let cli = Cli::try_parse_from([
        "lsend",
        "--socket",
        "/tmp/custom.sock",
        "send",
        "10.0.0.5:53317",
        "file1.txt",
        "file2.png",
        "--pin",
        "999888",
        "--fingerprint",
        "AABBCCDDEEFF",
        "--standalone",
    ])
    .unwrap();
    assert_eq!(cli.socket, Some(PathBuf::from("/tmp/custom.sock")));
    assert_eq!(
        cli.command,
        Commands::Send {
            target: "10.0.0.5:53317".to_string(),
            files: vec![PathBuf::from("file1.txt"), PathBuf::from("file2.png")],
            pin: Some("999888".to_string()),
            fingerprint: Some("AABBCCDDEEFF".to_string()),
            standalone: true,
        }
    );

    // 4. watch
    let cli = Cli::try_parse_from(["lsend", "watch"]).unwrap();
    assert_eq!(cli.command, Commands::Watch);

    // 5. peers and status
    let cli = Cli::try_parse_from(["lsend", "peers"]).unwrap();
    assert_eq!(cli.command, Commands::Peers);

    let cli = Cli::try_parse_from(["lsend", "status"]).unwrap();
    assert_eq!(cli.command, Commands::Status);

    // 6. trust add
    let cli = Cli::try_parse_from([
        "lsend",
        "trust",
        "add",
        "1122334455",
        "--alias",
        "DeskNode",
    ])
    .unwrap();
    assert_eq!(
        cli.command,
        Commands::Trust {
            action: TrustAction::Add {
                fingerprint: "1122334455".to_string(),
                alias: "DeskNode".to_string(),
            }
        }
    );
}

#[test]
fn test_fingerprint_verifier_validation() {
    let identity = generate_tls_identity("PinnedNode", &[]).unwrap();
    let verifier = FingerprintVerifier::new(&identity.fingerprint);

    let cert_der = CertificateDer::from(identity.cert_der.clone());
    let server_name = ServerName::try_from("127.0.0.1").unwrap();

    // 1. Matches expected fingerprint -> Ok
    let valid = verifier.verify_server_cert(
        &cert_der,
        &[],
        &server_name,
        &[],
        UnixTime::now(),
    );
    assert!(valid.is_ok());

    // 2. Mismatched fingerprint -> ApplicationVerificationFailure
    let wrong_verifier = FingerprintVerifier::new("0000000000000000000000000000000000000000000000000000000000000000");
    let invalid = wrong_verifier.verify_server_cert(
        &cert_der,
        &[],
        &server_name,
        &[],
        UnixTime::now(),
    );
    assert!(invalid.is_err());
}

#[tokio::test]
async fn test_e2e_send_with_pinned_tls_client() {
    let temp_dir = std::env::temp_dir().join(format!("cli_e2e_{}", uuid::Uuid::new_v4()));
    let save_dir = temp_dir.join("saved_files");
    let send_dir = temp_dir.join("send_files");
    tokio::fs::create_dir_all(&save_dir).await.unwrap();
    tokio::fs::create_dir_all(&send_dir).await.unwrap();

    // 1. Create test file to send
    let test_file = send_dir.join("document.txt");
    let test_content = b"LocalSend CLI end-to-end transfer verified content.";
    tokio::fs::write(&test_file, test_content).await.unwrap();

    // 2. Start Receiver Server
    let server_identity = generate_tls_identity("ReceiverServer", &[]).unwrap();
    let server_tls = build_tls_server_config(&server_identity).unwrap();

    let trust_cfg = temp_dir.join("trusted.yaml");
    let mut trust_store = TrustStore::load_or_create(&trust_cfg).unwrap();
    trust_store.set_mode(AutoAcceptMode::Always).unwrap(); // Auto-accept
    let trust_store = Arc::new(RwLock::new(trust_store));
    let (event_tx, _) = broadcast::channel::<DaemonEvent>(64);

    let state = AppState {
        coordinator: SessionCoordinator::default(),
        registry: PeerRegistry::new(),
        device_info: InfoResponseDto {
            alias: "ReceiverServer".to_string(),
            version: "2.0".to_string(),
            device_model: None,
            device_type: Some(DeviceType::Headless),
            fingerprint: server_identity.fingerprint.clone(),
            port: 0,
            protocol: ProtocolType::Https,
            download: true,
        },
        save_dir: save_dir.clone(),
        trust_store: trust_store.clone(),
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

    let target_addr = format!("127.0.0.1:{port}");

    // 3. Send file using `send::run` with valid pinned fingerprint
    let send_result = send::run(
        &target_addr,
        &[test_file.clone()],
        None,
        Some(server_identity.fingerprint.clone()),
        true, // standalone
        true, // json
    )
    .await;

    assert!(send_result.is_ok(), "Transfer with valid fingerprint should succeed: {:?}", send_result.err());

    // Verify file exists at receiver save_dir
    let received_file = save_dir.join("document.txt");
    assert!(received_file.exists(), "Received file must exist on receiver disk");
    let received_content = tokio::fs::read(&received_file).await.unwrap();
    assert_eq!(received_content, test_content);

    // 4. Send file with mismatched pinned fingerprint -> MUST FAIL
    let mismatched_fp = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF".to_string();
    let fail_result = send::run(
        &target_addr,
        &[test_file.clone()],
        None,
        Some(mismatched_fp),
        true,
        true,
    )
    .await;

    assert!(fail_result.is_err(), "Transfer with mismatched fingerprint must fail");

    cancel.cancel();
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_e2e_send_with_pin_protection() {
    let temp_dir = std::env::temp_dir().join(format!("cli_pin_{}", uuid::Uuid::new_v4()));
    let save_dir = temp_dir.join("saved");
    let send_dir = temp_dir.join("send");
    tokio::fs::create_dir_all(&save_dir).await.unwrap();
    tokio::fs::create_dir_all(&send_dir).await.unwrap();

    let test_file = send_dir.join("secret.bin");
    tokio::fs::write(&test_file, b"top secret bytes").await.unwrap();

    let server_identity = generate_tls_identity("PinServer", &[]).unwrap();
    let server_tls = build_tls_server_config(&server_identity).unwrap();

    let trust_cfg = temp_dir.join("trusted.yaml");
    let mut trust_store = TrustStore::load_or_create(&trust_cfg).unwrap();
    trust_store.set_mode(AutoAcceptMode::Always).unwrap();
    trust_store.set_pin(Some("123456".to_string())).unwrap(); // PIN required!
    let trust_store = Arc::new(RwLock::new(trust_store));
    let (event_tx, _) = broadcast::channel::<DaemonEvent>(64);

    let state = AppState {
        coordinator: SessionCoordinator::default(),
        registry: PeerRegistry::new(),
        device_info: InfoResponseDto {
            alias: "PinServer".to_string(),
            version: "2.0".to_string(),
            device_model: None,
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

    let target_addr = format!("127.0.0.1:{port}");

    // A. Attempt send without PIN -> Must fail (401 Unauthorized)
    let no_pin_res = send::run(
        &target_addr,
        &[test_file.clone()],
        None,
        Some(server_identity.fingerprint.clone()),
        true,
        true,
    )
    .await;
    assert!(no_pin_res.is_err());

    // B. Attempt send with incorrect PIN -> Must fail
    let wrong_pin_res = send::run(
        &target_addr,
        &[test_file.clone()],
        Some("000000".to_string()),
        Some(server_identity.fingerprint.clone()),
        true,
        true,
    )
    .await;
    assert!(wrong_pin_res.is_err());

    // C. Send with correct PIN -> Must succeed
    let correct_pin_res = send::run(
        &target_addr,
        &[test_file.clone()],
        Some("123456".to_string()),
        Some(server_identity.fingerprint.clone()),
        true,
        true,
    )
    .await;
    assert!(correct_pin_res.is_ok());

    cancel.cancel();
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}
