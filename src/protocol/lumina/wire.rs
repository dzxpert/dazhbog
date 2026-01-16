//! Wire format utilities for Lumina protocol.
//!
//! Implements IDA's variable-length integer encoding and C-string handling.

use crate::common::error::LuminaError;

/// Unpack a variable-length 32-bit integer (IDA format).
pub fn unpack_dd(data: &[u8]) -> (u32, usize) {
    if data.is_empty() {
        return (0, 0);
    }
    let b = data[0];
    if (b & 0x80) == 0 {
        return (b as u32, 1);
    }
    if (b & 0xC0) == 0x80 {
        if data.len() < 2 {
            return (0, 0);
        }
        let val = (((b & 0x3F) as u32) << 8) | (data[1] as u32);
        return (val, 2);
    }
    if (b & 0xE0) == 0xC0 {
        if data.len() < 4 {
            return (0, 0);
        }
        let val = u32::from_le_bytes([data[3], data[2], data[1], b & 0x1F]);
        return (val, 4);
    }
    if b == 0xFF {
        if data.len() < 5 {
            return (0, 0);
        }
        let val = u32::from_le_bytes([data[4], data[3], data[2], data[1]]);
        return (val, 5);
    }
    if data.len() < 4 {
        return (0, 0);
    }
    let val = (((b & 0x1F) as u32) << 24)
        | ((data[1] as u32) << 16)
        | ((data[2] as u32) << 8)
        | (data[3] as u32);
    (val, 4)
}

/// Pack a variable-length 32-bit integer (IDA format).
///
/// The IDA dd format encoding:
/// - 1 byte: 0x00-0x7F for values 0-127
/// - 2 bytes: for values 0x80-0x3FFF
/// - 4 bytes: for values 0x4000-0x1FFFFF  
/// - 5 bytes: for values 0x200000+
pub fn pack_dd(v: u32) -> Vec<u8> {
    match v {
        0..=0x7f => vec![v as u8],
        0x80..=0x3fff => {
            // 2-byte encoding: 0x80 | (v >> 8), v & 0xFF
            // unpack: ((b & 0x3F) << 8) | data[1]
            vec![0x80 | ((v >> 8) as u8 & 0x3f), (v & 0xff) as u8]
        }
        0x4000..=0x1fffff => {
            // 4-byte encoding with 0xC0 prefix
            // unpack: u32::from_le_bytes([data[3], data[2], data[1], b & 0x1F])
            //       = data[3] | (data[2] << 8) | (data[1] << 16) | ((b & 0x1F) << 24)
            // So: b & 0x1F = v >> 16, data[1] = (v >> 8) & 0xFF, data[2] = v & 0xFF, data[3] = 0
            // Wait, that only encodes 21 bits but we need up to 0x1FFFFF which is 21 bits...
            // Actually unpack reads 4 bytes and reconstructs as:
            //   data[3] + data[2]*256 + data[1]*65536 + (b&0x1F)*16777216
            // For value v, we need:
            //   (b & 0x1F) = (v >> 16) & 0x1F  (bits 16-20, but max v is 0x1FFFFF so this is at most 0x1F)
            //   data[1] = (v >> 8) & 0xFF
            //   data[2] = v & 0xFF
            //   data[3] = 0 (unused since we only have 21 bits)
            // No wait, that's still wrong. Let me re-read...
            // u32::from_le_bytes([A, B, C, D]) = A + B*256 + C*65536 + D*16777216
            // So [data[3], data[2], data[1], b&0x1F] means:
            //   data[3] + data[2]*256 + data[1]*65536 + (b&0x1F)*16777216
            // For v = 0x123456:
            //   (b&0x1F) should encode 0x12 but 0x1F max means 5 bits, so (0x12 >> 0) = 0x12, too big!
            // Actually 0x1FFFFF = 0b0001_1111_1111_1111_1111_1111 = 21 bits
            // (0x1FFFFF >> 16) = 0x1F, so (b&0x1F) can hold bits 16-20
            // data[1] holds bits 8-15
            // data[2] holds bits 0-7
            // data[3] would hold bits below 0, so always 0
            // Wait no, from_le_bytes reverses order. Let me think again...
            // Actually the encoding seems wrong in unpack. Let's just match what unpack expects:
            // unpack produces: data[3] | (data[2] << 8) | (data[1] << 16) | ((b&0x1F) << 24)
            // For v, we need b&0x1F = 0 (since v <= 0x1FFFFF means v >> 24 = 0)
            // No wait, unpack puts (b&0x1F) in bits 24-28, but for v=0x1FFFFF that's 0.
            // Hmm, but then how does it encode values above 0xFFFFFF?
            // Oh I see - the encoding is: (b&0x1F)<<24 | data[1]<<16 | data[2]<<8 | data[3]
            // For v=0x1FFFFF = 0x001F_FFFF:
            //   (b&0x1F)<<24 should be 0 (since v < 0x0100_0000)
            //   data[1]<<16 = 0x1F0000  => data[1] = 0x1F
            //   data[2]<<8 = 0xFF00 => data[2] = 0xFF
            //   data[3] = 0xFF
            // So pack should be: [0xC0 | 0, 0x1F, 0xFF, 0xFF]
            vec![
                0xc0, // No high bits in first byte for this range
                ((v >> 16) & 0xff) as u8,
                ((v >> 8) & 0xff) as u8,
                (v & 0xff) as u8,
            ]
        }
        0x200000..=u32::MAX => {
            // 5-byte encoding: 0xFF marker, then value
            // unpack: u32::from_le_bytes([data[4], data[3], data[2], data[1]])
            //       = data[4] | (data[3] << 8) | (data[2] << 16) | (data[1] << 24)
            vec![
                0xff,
                ((v >> 24) & 0xff) as u8,
                ((v >> 16) & 0xff) as u8,
                ((v >> 8) & 0xff) as u8,
                (v & 0xff) as u8,
            ]
        }
    }
}

/// Pack a variable-length 64-bit integer as dd(low) + dd(high).
///
/// NOTE: pack_dq must encode the low 32 bits first, then the high 32 bits,
/// matching how IDA expects dd(low) followed by dd(high).
pub fn pack_dq(v: u64) -> Vec<u8> {
    let low = (v & 0xFFFF_FFFF) as u32;
    let high = (v >> 32) as u32;
    let mut result = pack_dd(low);
    result.extend_from_slice(&pack_dd(high));
    result
}

/// Unpack a null-terminated C-string with maximum length check.
pub fn unpack_cstr_capped(data: &[u8], max: usize) -> Result<(String, usize), LuminaError> {
    let null_pos = data
        .iter()
        .position(|&b| b == 0)
        .ok_or(LuminaError::UnexpectedEof)?;
    if null_pos > max {
        return Err(LuminaError::InvalidData);
    }
    let s = std::str::from_utf8(&data[..null_pos]).map_err(|_| LuminaError::InvalidData)?;
    Ok((s.to_string(), null_pos + 1))
}

/// Unpack variable-length bytes with maximum length check.
pub fn unpack_var_bytes_capped(data: &[u8], max_len: usize) -> Result<(&[u8], usize), LuminaError> {
    let (len, consumed) = unpack_dd(data);
    if consumed == 0 {
        return Err(LuminaError::UnexpectedEof);
    }
    let len = len as usize;
    if len > max_len {
        return Err(LuminaError::InvalidData);
    }
    let data = &data[consumed..];
    if data.len() < len {
        return Err(LuminaError::UnexpectedEof);
    }
    Ok((&data[..len], consumed + len))
}

/// Pack variable-length bytes as dd(len) + bytes.
#[allow(dead_code)]
pub fn pack_var_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + bytes.len());
    out.extend_from_slice(&pack_dd(bytes.len() as u32));
    out.extend_from_slice(bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unpack_dd_basic() {
        assert_eq!(unpack_dd(&[0x42]), (0x42, 1));
        assert_eq!(unpack_dd(&[0x00]), (0x00, 1));
        assert_eq!(unpack_dd(&[0x7F]), (0x7F, 1));
        assert_eq!(unpack_dd(&[0x80, 0x00]), (0x0000, 2));
        assert_eq!(unpack_dd(&[0x81, 0x23]), (0x0123, 2));
        assert_eq!(unpack_dd(&[0xBF, 0xFF]), (0x3FFF, 2));
        assert_eq!(unpack_dd(&[0xC0, 0x00, 0x00, 0x00]), (0x00000000, 4));
        assert_eq!(unpack_dd(&[0xC1, 0x23, 0x45, 0x00]), (0x01234500, 4));
        assert_eq!(unpack_dd(&[0xFF, 0x78, 0x56, 0x34, 0x12]), (0x78563412, 5));
    }

    #[test]
    fn test_unpack_cstr_capped() {
        assert_eq!(
            unpack_cstr_capped(b"hello\0", 16).unwrap(),
            ("hello".to_string(), 6)
        );
        assert!(unpack_cstr_capped(b"no null terminator", 64).is_err());
        assert!(unpack_cstr_capped(&[b'a'; 10_000], 1024).is_err());
    }

    #[test]
    fn test_pack_dq_low_then_high() {
        let v: u64 = 0x11223344_55667788;
        let enc = pack_dq(v);
        let (lo, c1) = unpack_dd(&enc[..]);
        let (hi, _c2) = unpack_dd(&enc[c1..]);
        assert_eq!(lo, 0x55667788);
        assert_eq!(hi, 0x11223344);
    }
}
