//! Protocol detection utilities.
//!
//! Provides functions to detect protocol types from initial bytes,
//! enabling transparent TLS/cleartext handling.

/// Check if the first 6 bytes look like a TLS ClientHello.
///
/// TLS record format:
/// - Byte 0: Content type (0x16 = Handshake)
/// - Byte 1-2: Version (0x03 0x0X for TLS)
/// - Byte 3-4: Length (big-endian)
/// - Byte 5: Handshake type (0x01 = ClientHello)
#[inline]
pub fn looks_like_tls_client_hello(hdr6: &[u8]) -> bool {
    if hdr6.len() < 6 {
        return false;
    }
    // Content type must be Handshake (0x16)
    if hdr6[0] != 0x16 {
        return false;
    }
    // Version major must be 0x03 (SSL/TLS)
    if hdr6[1] != 0x03 {
        return false;
    }
    // Version minor should be 0x00-0x04 (SSLv3 through TLS 1.3)
    if hdr6[2] > 0x04 {
        return false;
    }
    // Length must be reasonable (1 to 16KB)
    let len = u16::from_be_bytes([hdr6[3], hdr6[4]]) as usize;
    if len == 0 || len > (16 * 1024) {
        return false;
    }
    // Handshake type must be ClientHello (0x01)
    hdr6[5] == 0x01
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_header_positive_and_negative() {
        // Valid TLS 1.2 ClientHello header
        let good = [0x16, 0x03, 0x03, 0x00, 0x2a, 0x01];
        assert!(looks_like_tls_client_hello(&good));

        // Cleartext Lumina frame (not TLS)
        let clear = [0x00, 0x00, 0x00, 0x05, 0x01, 0xff];
        assert!(!looks_like_tls_client_hello(&clear));
    }

    #[test]
    fn tls_header_edge_cases() {
        // Too short
        let short = [0x16, 0x03, 0x03];
        assert!(!looks_like_tls_client_hello(&short));

        // Wrong content type
        let wrong_type = [0x17, 0x03, 0x03, 0x00, 0x2a, 0x01];
        assert!(!looks_like_tls_client_hello(&wrong_type));

        // Wrong version major
        let wrong_ver = [0x16, 0x02, 0x03, 0x00, 0x2a, 0x01];
        assert!(!looks_like_tls_client_hello(&wrong_ver));

        // Zero length
        let zero_len = [0x16, 0x03, 0x03, 0x00, 0x00, 0x01];
        assert!(!looks_like_tls_client_hello(&zero_len));

        // Not ClientHello
        let not_hello = [0x16, 0x03, 0x03, 0x00, 0x2a, 0x02];
        assert!(!looks_like_tls_client_hello(&not_hello));
    }
}
