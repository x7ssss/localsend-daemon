//! Zero-Allocation Packet Screening
//!
//! Provides ultra-fast pre-deserialization checks on raw incoming datagram bytes
//! directly on the stack before invoking `serde_json`, rejecting noise, self-echo
//! loopback announcements, and malformed frames.

/// Minimum valid length for a LocalSend announcement JSON payload.
pub const MIN_PACKET_LEN: usize = 32;

/// Maximum reasonable length for a LocalSend announcement JSON payload.
pub const MAX_PACKET_LEN: usize = 2048;

/// Protocol discriminator substring required in all valid LocalSend announcements.
pub const PROTOCOL_DISCRIMINATOR: &[u8] = b"\"protocol\"";

/// Fast, zero-allocation subslice containment test on byte slices.
#[inline]
pub fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Evaluates whether a raw incoming datagram should proceed to full JSON deserialization.
///
/// Pre-deserialization checks:
/// 1. Byte length bounds: 32 <= len <= 2048 bytes.
/// 2. Outer JSON framing: first non-whitespace byte is '{', last is '}'.
/// 3. Self-echo loopback suppression: drops packets containing local node's fingerprint.
/// 4. Protocol discriminator: drops packets lacking `"protocol"`.
pub fn should_process_packet(packet: &[u8], local_fingerprint: &str) -> bool {
    // 1. Length bounds check
    let len = packet.len();
    if !(MIN_PACKET_LEN..=MAX_PACKET_LEN).contains(&len) {
        return false;
    }

    // 2. Outer JSON framing check
    let first = packet.iter().find(|&&b| !b.is_ascii_whitespace());
    let last = packet.iter().rfind(|&&b| !b.is_ascii_whitespace());
    if first != Some(&b'{') || last != Some(&b'}') {
        return false;
    }

    // 3. Self-echo loopback suppression
    if !local_fingerprint.is_empty() && contains_subslice(packet, local_fingerprint.as_bytes()) {
        return false;
    }

    // 4. Protocol discriminator search
    if !contains_subslice(packet, PROTOCOL_DISCRIMINATOR) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_FP: &str = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";
    const OTHER_FP: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

    #[test]
    fn test_valid_packet_accepted() {
        let valid_json = format!(
            r#"{{"alias":"Remote","version":"2.0","fingerprint":"{OTHER_FP}","port":53317,"protocol":"https","download":true,"announce":true}}"#
        );
        assert!(should_process_packet(valid_json.as_bytes(), SAMPLE_FP));
    }

    #[test]
    fn test_self_echo_rejected() {
        let self_json = format!(
            r#"{{"alias":"Local","version":"2.0","fingerprint":"{SAMPLE_FP}","port":53317,"protocol":"https","download":true,"announce":true}}"#
        );
        assert!(!should_process_packet(self_json.as_bytes(), SAMPLE_FP));
    }

    #[test]
    fn test_length_bounds() {
        // Too short (< 32 bytes)
        assert!(!should_process_packet(b"{}", SAMPLE_FP));
        assert!(!should_process_packet(b"{\"a\":1}", SAMPLE_FP));

        // Too long (> 2048 bytes)
        let mut long_buf = vec![b' '; 2049];
        long_buf[0] = b'{';
        long_buf[2048] = b'}';
        assert!(!should_process_packet(&long_buf, SAMPLE_FP));
    }

    #[test]
    fn test_json_framing_rejected() {
        // Missing closing brace
        let invalid =
            format!(r#"{{"alias":"Remote","protocol":"https","fingerprint":"{OTHER_FP}""#);
        assert!(!should_process_packet(invalid.as_bytes(), SAMPLE_FP));

        // Non-JSON noise
        let noise = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n                 ";
        assert!(!should_process_packet(noise, SAMPLE_FP));
    }

    #[test]
    fn test_protocol_discriminator_missing() {
        let no_proto = format!(
            r#"{{"alias":"Remote","version":"2.0","fingerprint":"{OTHER_FP}","port":53317}}"#
        );
        assert!(!should_process_packet(no_proto.as_bytes(), SAMPLE_FP));
    }
}
