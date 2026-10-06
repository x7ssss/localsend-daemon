use localsend_discovery::{
    contains_subslice, is_eligible_interface_name, is_eligible_ipv4, should_process_packet,
    DiscoveredPeer, MulticastConfig, NetworkInterfaceInfo, PeerRegistry, RegistryEvent,
    SubnetScanner, DEFAULT_PORT, MULTICAST_IPV4, MULTICAST_IPV6,
};
use localsend_protocol::{
    DeviceType, MulticastAnnouncement, ProtocolType, RegisterDto,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

const LOCAL_FP: &str = "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333444455556666777788889999";
const REMOTE_FP: &str = "1111222233334444555566667777888899990000AAAABBBBCCCCDDDDEEEEFFFF";

#[test]
fn test_filter_screening_rules() {
    // 1. Legitimate announcement packet
    let valid_json = format!(
        r#"{{"alias":"Peer1","version":"2.0","deviceModel":"Linux","deviceType":"desktop","fingerprint":"{REMOTE_FP}","port":53317,"protocol":"https","download":true,"announce":true}}"#
    );
    assert!(should_process_packet(valid_json.as_bytes(), LOCAL_FP));

    // 2. Self-echo loopback packet (contains our local fingerprint)
    let self_echo_json = format!(
        r#"{{"alias":"MySelf","version":"2.0","deviceModel":"Host","deviceType":"desktop","fingerprint":"{LOCAL_FP}","port":53317,"protocol":"https","download":true,"announce":true}}"#
    );
    assert!(!should_process_packet(self_echo_json.as_bytes(), LOCAL_FP));

    // 3. Size constraints
    assert!(!should_process_packet(b"{}", LOCAL_FP));
    let oversized = vec![b' '; 2049];
    assert!(!should_process_packet(&oversized, LOCAL_FP));

    // 4. Missing JSON framing
    let broken_json = format!(r#"{{"alias":"Peer1","protocol":"https""#);
    assert!(!should_process_packet(broken_json.as_bytes(), LOCAL_FP));

    // 5. Missing protocol discriminator
    let no_protocol = format!(
        r#"{{"alias":"Peer1","version":"2.0","fingerprint":"{REMOTE_FP}","port":53317,"download":true}}"#
    );
    assert!(!should_process_packet(no_protocol.as_bytes(), LOCAL_FP));
}

#[test]
fn test_contains_subslice() {
    assert!(contains_subslice(b"hello world", b"world"));
    assert!(contains_subslice(b"hello world", b"hello"));
    assert!(contains_subslice(b"hello world", b""));
    assert!(!contains_subslice(b"hello world", b"missing"));
    assert!(!contains_subslice(b"short", b"very long pattern"));
}

#[test]
fn test_interface_name_filtering() {
    // Excluded virtual / VPN / container adapters
    assert!(!is_eligible_interface_name("docker0"));
    assert!(!is_eligible_interface_name("vethabc123"));
    assert!(!is_eligible_interface_name("br-ff89ab"));
    assert!(!is_eligible_interface_name("virbr0"));
    assert!(!is_eligible_interface_name("tailscale0"));
    assert!(!is_eligible_interface_name("wg0"));
    assert!(!is_eligible_interface_name("tun0"));
    assert!(!is_eligible_interface_name("tap1"));
    assert!(!is_eligible_interface_name("zt0"));

    // Allowed physical / standard adapters
    assert!(is_eligible_interface_name("eth0"));
    assert!(is_eligible_interface_name("enp3s0"));
    assert!(is_eligible_interface_name("wlan0"));
    assert!(is_eligible_interface_name("Wi-Fi"));
    assert!(is_eligible_interface_name("Ethernet 2"));
}

#[test]
fn test_ipv4_address_eligibility() {
    assert!(!is_eligible_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
    assert!(!is_eligible_ipv4(Ipv4Addr::new(0, 0, 0, 0)));
    assert!(!is_eligible_ipv4(Ipv4Addr::new(169, 254, 10, 20)));
    assert!(!is_eligible_ipv4(Ipv4Addr::new(224, 0, 0, 167)));
    assert!(!is_eligible_ipv4(Ipv4Addr::new(255, 255, 255, 255)));

    assert!(is_eligible_ipv4(Ipv4Addr::new(192, 168, 1, 105)));
    assert!(is_eligible_ipv4(Ipv4Addr::new(10, 200, 0, 1)));
    assert!(is_eligible_ipv4(Ipv4Addr::new(172, 20, 1, 50)));
}

#[tokio::test]
async fn test_peer_registry_lifecycle_and_events() {
    let registry = PeerRegistry::new();
    let mut rx = registry.subscribe();

    assert!(registry.is_empty().await);

    // 1. Initial peer insertion
    let peer = DiscoveredPeer {
        fingerprint: REMOTE_FP.to_string(),
        alias: "Phone Node".to_string(),
        device_model: Some("Pixel 8".to_string()),
        device_type: Some(DeviceType::Mobile),
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)),
        port: 53317,
        protocol: ProtocolType::Https,
        download: true,
        last_seen: Instant::now(),
    };

    let is_new = registry.upsert(peer.clone()).await;
    assert!(is_new);
    assert_eq!(registry.len().await, 1);

    // Verify broadcast event
    let event = rx.recv().await.unwrap();
    match event {
        RegistryEvent::Discovered(p) => assert_eq!(p.fingerprint, REMOTE_FP),
        _ => panic!("Expected Discovered event"),
    }

    // 2. Case-insensitive lookup
    let retrieved = registry
        .get(&REMOTE_FP.to_ascii_lowercase())
        .await
        .expect("Should retrieve peer case-insensitively");
    assert_eq!(retrieved.alias, "Phone Node");

    // 3. Update existing peer
    let mut updated = peer.clone();
    updated.alias = "Renamed Phone".to_string();
    let is_new_2 = registry.upsert(updated).await;
    assert!(!is_new_2);

    let event_2 = rx.recv().await.unwrap();
    match event_2 {
        RegistryEvent::Updated(p) => assert_eq!(p.alias, "Renamed Phone"),
        _ => panic!("Expected Updated event"),
    }

    // 4. Stale peer pruning
    let stale_peer = DiscoveredPeer {
        fingerprint: "OLD_FINGERPRINT_123456789".to_string(),
        alias: "Ghost Node".to_string(),
        device_model: None,
        device_type: None,
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99)),
        port: 53317,
        protocol: ProtocolType::Http,
        download: false,
        last_seen: Instant::now() - Duration::from_secs(300),
    };
    registry.upsert(stale_peer).await;
    let _ = rx.recv().await.unwrap(); // Consume discovered event
    assert_eq!(registry.len().await, 2);

    let evicted_count = registry.prune_stale(Duration::from_secs(120)).await;
    assert_eq!(evicted_count, 1);
    assert_eq!(registry.len().await, 1);

    let event_3 = rx.recv().await.unwrap();
    match event_3 {
        RegistryEvent::Evicted(fp) => assert_eq!(fp, "OLD_FINGERPRINT_123456789"),
        _ => panic!("Expected Evicted event"),
    }
}

#[tokio::test]
async fn test_registry_upsert_from_announcement_and_register() {
    let registry = PeerRegistry::new();

    let ann = MulticastAnnouncement {
        alias: "Tablet".to_string(),
        version: "2.0".to_string(),
        device_model: Some("iPad".to_string()),
        device_type: Some(DeviceType::Mobile),
        fingerprint: "TABLET_FP".to_string(),
        port: 53317,
        protocol: ProtocolType::Https,
        download: true,
        announce: true,
    };

    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)), 49152);
    let is_new = registry.upsert_from_announcement(&ann, src).await;
    assert!(is_new);

    let peer = registry.get("TABLET_FP").await.unwrap();
    assert_eq!(peer.ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)));
    assert_eq!(peer.port, 53317);

    // RegisterDto upsert
    let reg = RegisterDto {
        alias: "Workstation".to_string(),
        version: "2.0".to_string(),
        device_model: Some("Dell XPS".to_string()),
        device_type: Some(DeviceType::Desktop),
        fingerprint: "DESKTOP_FP".to_string(),
        port: 53318,
        protocol: ProtocolType::Https,
        download: true,
    };
    let src2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 201)), 53318);
    let is_new_reg = registry.upsert_from_register(&reg, src2).await;
    assert!(is_new_reg);
    assert_eq!(registry.len().await, 2);
}

#[test]
fn test_scanner_candidate_ip_enumeration() {
    let ifaces = vec![
        NetworkInterfaceInfo {
            name: "eth0".to_string(),
            ip: Ipv4Addr::new(192, 168, 10, 15),
            netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
        },
        NetworkInterfaceInfo {
            name: "eth1".to_string(),
            ip: Ipv4Addr::new(10, 0, 5, 100),
            netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
        },
    ];

    let candidates = SubnetScanner::enumerate_candidate_ips(&ifaces);
    // 253 hosts for 192.168.10.x + 253 hosts for 10.0.5.x = 506 candidates
    assert_eq!(candidates.len(), 506);

    // Our own IPs must be excluded
    assert!(!candidates.contains(&Ipv4Addr::new(192, 168, 10, 15)));
    assert!(!candidates.contains(&Ipv4Addr::new(10, 0, 5, 100)));

    // Boundaries included
    assert!(candidates.contains(&Ipv4Addr::new(192, 168, 10, 1)));
    assert!(candidates.contains(&Ipv4Addr::new(192, 168, 10, 254)));
    assert!(candidates.contains(&Ipv4Addr::new(10, 0, 5, 1)));
    assert!(candidates.contains(&Ipv4Addr::new(10, 0, 5, 254)));
}

#[test]
fn test_multicast_constants() {
    assert_eq!(DEFAULT_PORT, 53317);
    assert_eq!(MULTICAST_IPV4, Ipv4Addr::new(224, 0, 0, 167));
    assert_eq!(
        MULTICAST_IPV6,
        std::net::Ipv6Addr::new(0xff12, 0, 0, 0, 0, 0, 0xfd3a, 0xe420)
    );

    let cfg = MulticastConfig::default();
    assert_eq!(cfg.port, 53317);
    assert_eq!(cfg.heartbeat_interval, Duration::from_secs(60));
}
