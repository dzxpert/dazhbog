//! Protocol detection utilities.
//!
//! Provides functions to detect protocol types from initial bytes,
//! enabling transparent TLS/cleartext handling and HTTP/HTTP2 detection.

/// HTTP/1.x methods that we recognize for protocol detection.
const HTTP_METHODS: &[&[u8; 4]] = &[
    b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", // DELETE
    b"OPTI", // OPTIONS
    b"PATC", // PATCH
    b"CONN", // CONNECT
    b"TRAC", // TRACE
];

/// HTTP/2 connection preface.
///
/// HTTP/2 connections begin with "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
/// We only need to check the first few bytes for detection.
const HTTP2_PREFACE_PREFIX: &[u8] = b"PRI *";

/// Check if the first bytes look like an HTTP/1.x request.
///
/// HTTP/1.x requests start with a method name followed by a space and path.
/// We check for common HTTP methods: GET, POST, PUT, HEAD, DELETE, OPTIONS, PATCH, CONNECT, TRACE
#[inline]
pub fn looks_like_http(hdr: &[u8]) -> bool {
    if hdr.len() < 4 {
        return false;
    }
    let prefix: &[u8; 4] = hdr[..4].try_into().unwrap();
    HTTP_METHODS.contains(&prefix)
}

/// Check if the first bytes look like an HTTP/2 connection preface (h2c).
///
/// HTTP/2 cleartext connections start with: `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`
/// This is the "connection preface" that clients send to initiate HTTP/2.
#[inline]
pub fn looks_like_http2_preface(hdr: &[u8]) -> bool {
    if hdr.len() < 5 {
        return false;
    }
    hdr.starts_with(HTTP2_PREFACE_PREFIX)
}

/// Check if the bytes look like any HTTP protocol (HTTP/1.x or HTTP/2).
#[inline]
pub fn looks_like_any_http(hdr: &[u8]) -> bool {
    looks_like_http(hdr) || looks_like_http2_preface(hdr)
}

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
    fn http_detection() {
        assert!(looks_like_http(b"GET /"));
        assert!(looks_like_http(b"GET / HTTP/1.1"));
        assert!(looks_like_http(b"POST /api/test"));
        assert!(looks_like_http(b"PUT /resource"));
        assert!(looks_like_http(b"HEAD /"));
        assert!(looks_like_http(b"DELETE /item"));
        assert!(looks_like_http(b"OPTIONS /"));
        assert!(looks_like_http(b"PATCH /update"));

        // Not HTTP/1.x
        assert!(!looks_like_http(b"\x00\x00\x00\x05")); // Binary frame
        assert!(!looks_like_http(b"\x16\x03\x03")); // TLS
        assert!(!looks_like_http(b"INVALID"));
        assert!(!looks_like_http(b"get ")); // lowercase
        assert!(!looks_like_http(b"GE")); // too short
        assert!(!looks_like_http(b"PRI *")); // HTTP/2, not HTTP/1.x
    }

    #[test]
    fn http2_preface_detection() {
        // Full HTTP/2 connection preface
        assert!(looks_like_http2_preface(
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        ));
        // Just the prefix is enough for detection
        assert!(looks_like_http2_preface(b"PRI * "));
        assert!(looks_like_http2_preface(b"PRI *"));

        // Not HTTP/2
        assert!(!looks_like_http2_preface(b"GET /")); // HTTP/1.x
        assert!(!looks_like_http2_preface(b"\x00\x00\x00\x05")); // Binary frame
        assert!(!looks_like_http2_preface(b"PRI")); // Too short
        assert!(!looks_like_http2_preface(b"pri *")); // Lowercase
    }

    #[test]
    fn any_http_detection() {
        // HTTP/1.x
        assert!(looks_like_any_http(b"GET /"));
        assert!(looks_like_any_http(b"POST /api"));

        // HTTP/2
        assert!(looks_like_any_http(b"PRI * HTTP/2.0"));

        // Not HTTP
        assert!(!looks_like_any_http(b"\x00\x00\x00\x05")); // Binary
        assert!(!looks_like_any_http(b"\x16\x03\x03")); // TLS
    }

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
