use localsend_protocol::{
    compute_fingerprint, generate_tls_identity, is_windows_reserved, resolve_collision,
    sanitize_filename, verify_fingerprint_constant_time, DeviceType, FileMetadata,
    MulticastAnnouncement, PrepareUploadRequest, PrepareUploadResponse, ProtocolType, RegisterDto,
    SanitizeError, UploadParams,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_multicast_announcement_serialization_roundtrip() {
    let json_vector = r#"{
        "alias": "Fresh Orange",
        "version": "2.0",
        "deviceModel": "Pixel 7",
        "deviceType": "mobile",
        "fingerprint": "B4B384B4254848DF1058DE4384B9E904B8C13EF6840BF28156ECB15BA13B1358",
        "port": 53317,
        "protocol": "https",
        "download": true,
        "announce": true
    }"#;

    let announcement: MulticastAnnouncement =
        serde_json::from_str(json_vector).expect("Must deserialize valid announcement");

    assert_eq!(announcement.alias, "Fresh Orange");
    assert_eq!(announcement.version, "2.0");
    assert_eq!(announcement.device_model.as_deref(), Some("Pixel 7"));
    assert_eq!(announcement.device_type, Some(DeviceType::Mobile));
    assert_eq!(announcement.port, 53317);
    assert_eq!(announcement.protocol, ProtocolType::Https);
    assert!(announcement.download);
    assert!(announcement.announce);

    // Re-serialize and deserialize back
    let serialized = serde_json::to_string(&announcement).unwrap();
    let roundtripped: MulticastAnnouncement = serde_json::from_str(&serialized).unwrap();
    assert_eq!(announcement, roundtripped);
}

#[test]
fn test_announcement_alias_compatibility() {
    // Official LocalSend clients sometimes send "announcement": true
    let json_with_announcement = r#"{
        "alias": "Blue Lake",
        "version": "2.0",
        "fingerprint": "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
        "port": 53317,
        "protocol": "http",
        "download": true,
        "announcement": true
    }"#;

    let announcement: MulticastAnnouncement =
        serde_json::from_str(json_with_announcement).expect("Must support announcement alias");
    assert!(announcement.announce);
    assert_eq!(announcement.protocol, ProtocolType::Http);
}

#[test]
fn test_device_type_fallback_deserializer() {
    // Unknown third-party device strings should fallback to Desktop
    let json = r#"{
        "alias": "Smart Fridge",
        "version": "2.0",
        "deviceType": "smart_refrigerator_v9",
        "fingerprint": "AAAA",
        "protocol": "https",
        "download": false
    }"#;

    let announcement: MulticastAnnouncement = serde_json::from_str(json).unwrap();
    assert_eq!(announcement.device_type, Some(DeviceType::Desktop));

    // Test case insensitive known types
    let json_mobile = r#"{"alias":"A","version":"2.0","deviceType":"MoBiLe","fingerprint":"F","protocol":"https","download":true}"#;
    let ann_mobile: MulticastAnnouncement = serde_json::from_str(json_mobile).unwrap();
    assert_eq!(ann_mobile.device_type, Some(DeviceType::Mobile));
}

#[test]
fn test_prepare_upload_models() {
    let mut files = HashMap::new();
    files.insert(
        "file-1".to_string(),
        FileMetadata {
            id: "file-1".to_string(),
            file_name: "archive.zip".to_string(),
            size: 1048576,
            file_type: "application/zip".to_string(),
            sha256: Some(
                "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855".to_string(),
            ),
            preview: None,
            metadata: None,
        },
    );

    let register = RegisterDto {
        alias: "Sender Node".to_string(),
        version: "2.0".to_string(),
        device_model: None,
        device_type: Some(DeviceType::Server),
        fingerprint: "FINGERPRINT".to_string(),
        port: 53317,
        protocol: ProtocolType::Https,
        download: false,
    };

    let req = PrepareUploadRequest {
        info: register,
        files,
    };

    let req_json = serde_json::to_string(&req).unwrap();
    assert!(req_json.contains("fileName"));
    assert!(req_json.contains("archive.zip"));

    let parsed_req: PrepareUploadRequest = serde_json::from_str(&req_json).unwrap();
    assert_eq!(parsed_req.files.get("file-1").unwrap().size, 1048576);

    // PrepareUploadResponse
    let mut token_map = HashMap::new();
    token_map.insert("file-1".to_string(), "secret-token-123".to_string());
    let resp = PrepareUploadResponse {
        session_id: "session-abc".to_string(),
        files: token_map,
    };

    let resp_json = serde_json::to_string(&resp).unwrap();
    assert!(resp_json.contains("sessionId"));

    // UploadParams
    let params = UploadParams {
        session_id: "session-abc".to_string(),
        file_id: "file-1".to_string(),
        token: "secret-token-123".to_string(),
    };
    let params_json = serde_json::to_string(&params).unwrap();
    assert!(params_json.contains("sessionId"));
    assert!(params_json.contains("fileId"));
}

#[test]
fn test_generate_tls_identity_and_fingerprint() {
    let san_ips = vec![
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    ];

    let identity = generate_tls_identity("TestNode", &san_ips).expect("Must generate TLS identity");

    // Check non-empty outputs
    assert!(!identity.cert_der.is_empty());
    assert!(!identity.key_der_pkcs8.is_empty());
    assert!(identity.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(identity.key_pem.contains("BEGIN PRIVATE KEY"));

    // Fingerprint must be exactly 64 uppercase hex characters
    assert_eq!(identity.fingerprint.len(), 64);
    assert!(
        identity
            .fingerprint
            .chars()
            .all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c)),
        "Fingerprint must be uppercase hex: {}",
        identity.fingerprint
    );

    // Independent digest verification
    let manual_fp = compute_fingerprint(&identity.cert_der);
    assert_eq!(identity.fingerprint, manual_fp);
}

#[test]
fn test_constant_time_fingerprint_verification() {
    let identity = generate_tls_identity("Node", &[]).unwrap();

    // Exact match
    assert!(verify_fingerprint_constant_time(
        &identity.fingerprint,
        &identity.cert_der
    ));

    // Match with lowercase
    let lower_fp = identity.fingerprint.to_ascii_lowercase();
    assert!(verify_fingerprint_constant_time(
        &lower_fp,
        &identity.cert_der
    ));

    // Match with colon delimiters (common in cert visualizers)
    let colon_fp = identity
        .fingerprint
        .as_bytes()
        .chunks(2)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join(":");
    assert!(verify_fingerprint_constant_time(
        &colon_fp,
        &identity.cert_der
    ));

    // Mismatched fingerprints
    let mut mutated_fp = identity.fingerprint.clone();
    let last_char = mutated_fp.pop().unwrap();
    mutated_fp.push(if last_char == 'A' { 'B' } else { 'A' });
    assert!(!verify_fingerprint_constant_time(
        &mutated_fp,
        &identity.cert_der
    ));

    // Short/invalid length
    assert!(!verify_fingerprint_constant_time(
        "INVALID",
        &identity.cert_der
    ));

    // Empty
    assert!(!verify_fingerprint_constant_time("", &identity.cert_der));
}

#[test]
fn test_sanitize_filename_malicious_rejections() {
    // 1. Relative traversal
    let res = sanitize_filename("../../etc/shadow");
    assert!(matches!(res, Err(SanitizeError::PathTraversal(_))));

    // 2. Windows traversal with backslashes
    let res = sanitize_filename(r"..\..\Windows\cmd.exe");
    assert!(matches!(res, Err(SanitizeError::PathTraversal(_))));

    // 3. Absolute path / Unix
    let res = sanitize_filename("/bin/sh");
    assert!(matches!(res, Err(SanitizeError::PathTraversal(_))));

    // 4. Windows DOS reserved device name
    let res = sanitize_filename("CON.txt");
    assert!(matches!(res, Err(SanitizeError::WindowsReserved(_))));

    let res = sanitize_filename("aux.json");
    assert!(matches!(res, Err(SanitizeError::WindowsReserved(_))));

    let res = sanitize_filename("NUL");
    assert!(matches!(res, Err(SanitizeError::WindowsReserved(_))));

    let res = sanitize_filename("com1.dat");
    assert!(matches!(res, Err(SanitizeError::WindowsReserved(_))));

    // 5. Windows absolute drive letter
    let res = sanitize_filename(r"C:\Windows\System32\drivers\etc\hosts");
    assert!(matches!(res, Err(SanitizeError::PathTraversal(_))));

    // 6. Traversal symbols . and ..
    assert!(matches!(sanitize_filename("."), Err(SanitizeError::PathTraversal(_))));
    assert!(matches!(sanitize_filename(".."), Err(SanitizeError::PathTraversal(_))));

    // 7. Null byte injection
    let res = sanitize_filename("safe_file\0.exe");
    assert!(matches!(res, Err(SanitizeError::NullByte)));

    // 8. Empty string
    assert!(matches!(sanitize_filename(""), Err(SanitizeError::Empty)));
    assert!(matches!(sanitize_filename("   "), Err(SanitizeError::Empty)));

    // 9. Excessively long filename (> 255 bytes)
    let long_name = "a".repeat(256);
    assert!(matches!(sanitize_filename(&long_name), Err(SanitizeError::TooLong(256))));
}

#[test]
fn test_sanitize_filename_valid_cases() {
    assert_eq!(sanitize_filename("photo.jpg").unwrap(), "photo.jpg");
    assert_eq!(
        sanitize_filename("nested/subfolder/document.pdf").unwrap(),
        "document.pdf"
    );
    assert_eq!(
        sanitize_filename("archive.tar.gz").unwrap(),
        "archive.tar.gz"
    );
    assert_eq!(
        sanitize_filename("utf8_测试_файл.png").unwrap(),
        "utf8_测试_файл.png"
    );
}

#[test]
fn test_windows_reserved_detection() {
    assert!(is_windows_reserved("CON"));
    assert!(is_windows_reserved("con.txt"));
    assert!(is_windows_reserved("PRN.pdf"));
    assert!(is_windows_reserved("AUX"));
    assert!(is_windows_reserved("NUL.tar.gz"));
    assert!(is_windows_reserved("COM1"));
    assert!(is_windows_reserved("com9.bin"));
    assert!(is_windows_reserved("LPT1"));
    assert!(is_windows_reserved("lpt8.log"));
    assert!(!is_windows_reserved("contact.vcf"));
    assert!(!is_windows_reserved("auxiliary.txt"));
    assert!(!is_windows_reserved("normal.jpg"));
}

#[test]
fn test_resolve_collision_increments_correctly() {
    let temp_dir = std::env::temp_dir().join(format!("localsend_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    // Initial: target does not exist yet
    let target = "report.pdf";
    let resolved = resolve_collision(&temp_dir, target);
    assert_eq!(resolved, temp_dir.join("report.pdf"));

    // Create report.pdf
    std::fs::write(&resolved, b"v1").unwrap();

    // Now collision occurs -> report (1).pdf
    let resolved_1 = resolve_collision(&temp_dir, target);
    assert_eq!(resolved_1, temp_dir.join("report (1).pdf"));

    // Create report (1).pdf
    std::fs::write(&resolved_1, b"v2").unwrap();

    // Next collision -> report (2).pdf
    let resolved_2 = resolve_collision(&temp_dir, target);
    assert_eq!(resolved_2, temp_dir.join("report (2).pdf"));

    // File without extension
    let no_ext = "README";
    let resolved_no_ext = resolve_collision(&temp_dir, no_ext);
    assert_eq!(resolved_no_ext, temp_dir.join("README"));
    std::fs::write(&resolved_no_ext, b"readme").unwrap();

    let resolved_no_ext_1 = resolve_collision(&temp_dir, no_ext);
    assert_eq!(resolved_no_ext_1, temp_dir.join("README (1)"));

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}
