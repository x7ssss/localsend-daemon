//! Network Interface Enumeration & Eligibility Filtering
//!
//! Enumerates active network adapters and discards loopback, link-local,
//! and virtual/container/VPN interfaces (Docker, Tailscale, WireGuard, veth, etc.).

use std::net::Ipv4Addr;

/// Prefixes of virtual, tunnel, or bridge network interfaces that should be discarded.
pub const FORBIDDEN_IFACE_PREFIXES: &[&str] = &[
    "docker",
    "veth",
    "br-",
    "virbr",
    "tailscale",
    "wg",
    "tun",
    "tap",
    "zt",
];

/// Errors encountered during interface enumeration.
#[derive(Debug, thiserror::Error)]
pub enum InterfaceError {
    /// Failed to query system network adapters.
    #[error("Failed to enumerate network interfaces: {0}")]
    Io(#[from] std::io::Error),
    /// No eligible physical LAN IPv4 interface found.
    #[error("No eligible physical LAN IPv4 interfaces found")]
    NoEligibleInterfaces,
}

/// Metadata describing an eligible local network interface.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkInterfaceInfo {
    /// Interface name (e.g., "eth0", "en0", "Ethernet").
    pub name: String,
    /// Local IPv4 address.
    pub ip: Ipv4Addr,
    /// Subnet mask (if known).
    pub netmask: Option<Ipv4Addr>,
}

/// Checks if an interface name is eligible (not virtual/bridge/tunnel).
pub fn is_eligible_interface_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    for &prefix in FORBIDDEN_IFACE_PREFIXES {
        if lower.starts_with(prefix) {
            return false;
        }
    }
    true
}

/// Checks if an IPv4 address is an eligible physical LAN address.
pub fn is_eligible_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_broadcast() {
        return false;
    }

    let octets = ip.octets();
    // 169.254.0.0/16 Link-Local
    if octets[0] == 169 && octets[1] == 254 {
        return false;
    }

    // 224.0.0.0/4 Multicast
    if ip.is_multicast() {
        return false;
    }

    true
}

/// Query and filter all eligible LAN IPv4 interfaces on the local host.
pub fn get_eligible_interfaces() -> Result<Vec<NetworkInterfaceInfo>, InterfaceError> {
    let addrs = if_addrs::get_if_addrs()?;
    let mut eligible = Vec::new();
    let mut seen_ips = std::collections::HashSet::new();

    for iface in addrs {
        if iface.is_loopback() {
            continue;
        }

        if !is_eligible_interface_name(&iface.name) {
            continue;
        }

        if let if_addrs::IfAddr::V4(v4) = iface.addr
            && is_eligible_ipv4(v4.ip)
            && seen_ips.insert(v4.ip)
        {
            eligible.push(NetworkInterfaceInfo {
                name: iface.name,
                ip: v4.ip,
                netmask: Some(v4.netmask),
            });
        }
    }

    if eligible.is_empty() {
        Err(InterfaceError::NoEligibleInterfaces)
    } else {
        Ok(eligible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtual_interface_prefix_filtering() {
        assert!(!is_eligible_interface_name("docker0"));
        assert!(!is_eligible_interface_name("veth1234a"));
        assert!(!is_eligible_interface_name("br-abcdef"));
        assert!(!is_eligible_interface_name("virbr0"));
        assert!(!is_eligible_interface_name("tailscale0"));
        assert!(!is_eligible_interface_name("wg0"));
        assert!(!is_eligible_interface_name("tun0"));
        assert!(!is_eligible_interface_name("tap0"));
        assert!(!is_eligible_interface_name("zt123"));

        // Valid physical / standard names
        assert!(is_eligible_interface_name("eth0"));
        assert!(is_eligible_interface_name("en0"));
        assert!(is_eligible_interface_name("wlan0"));
        assert!(is_eligible_interface_name("Ethernet"));
        assert!(is_eligible_interface_name("Wi-Fi"));
    }

    #[test]
    fn test_ipv4_eligibility() {
        assert!(!is_eligible_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_eligible_ipv4(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(!is_eligible_ipv4(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(!is_eligible_ipv4(Ipv4Addr::new(224, 0, 0, 167)));
        assert!(!is_eligible_ipv4(Ipv4Addr::new(255, 255, 255, 255)));

        assert!(is_eligible_ipv4(Ipv4Addr::new(192, 168, 1, 100)));
        assert!(is_eligible_ipv4(Ipv4Addr::new(10, 0, 0, 5)));
        assert!(is_eligible_ipv4(Ipv4Addr::new(172, 16, 0, 2)));
    }
}
