//! Low-level binary serialization primitives.
//!
//! Wire protocol uses big-endian (network byte order) for length prefix,
//! and little-endian for internal data fields.

use crate::common::error::CodecError;
use bytes::{BufMut, BytesMut};

/// Write a u128 in little-endian format.
#[allow(dead_code)]
pub fn put_u128_le(dst: &mut BytesMut, v: u128) {
    dst.put_u64_le(v as u64);
    dst.put_u64_le((v >> 64) as u64);
}

/// Read a u128 in little-endian format.
pub fn get_u128_le(src: &mut &[u8]) -> Result<u128, CodecError> {
    if src.len() < 16 {
        return Err(CodecError::Short);
    }

    let lo = u64::from_le_bytes(src[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(src[8..16].try_into().unwrap());

    *src = &src[16..];

    Ok((hi as u128) << 64 | (lo as u128))
}

/// Write a length-prefixed string (4-byte LE length + bytes).
pub fn put_str(dst: &mut BytesMut, s: &str) {
    dst.put_u32_le(s.len() as u32);
    dst.extend_from_slice(s.as_bytes());
}

/// Read a length-prefixed string.
pub fn get_str(src: &mut &[u8]) -> Result<String, CodecError> {
    if src.len() < 4 {
        return Err(CodecError::Short);
    }

    let len = u32::from_le_bytes(src[0..4].try_into().unwrap()) as usize;

    *src = &src[4..];

    if src.len() < len {
        return Err(CodecError::Short);
    }

    let s = std::str::from_utf8(&src[..len]).map_err(|_| CodecError::Malformed("utf8"))?;

    *src = &src[len..];

    Ok(s.to_string())
}

/// Read a length-prefixed string with maximum length enforcement.
pub fn get_str_max(src: &mut &[u8], max_len: usize) -> Result<String, CodecError> {
    if src.len() < 4 {
        return Err(CodecError::Short);
    }

    let len = u32::from_le_bytes(src[0..4].try_into().unwrap()) as usize;

    if len > max_len {
        return Err(CodecError::Malformed("string too large"));
    }

    *src = &src[4..];

    if src.len() < len {
        return Err(CodecError::Short);
    }

    let s = std::str::from_utf8(&src[..len]).map_err(|_| CodecError::Malformed("utf8"))?;

    *src = &src[len..];

    Ok(s.to_string())
}

/// Write a length-prefixed byte array (4-byte LE length + bytes).
pub fn put_bytes(dst: &mut BytesMut, b: &[u8]) {
    dst.put_u32_le(b.len() as u32);
    dst.extend_from_slice(b);
}

/// Read a length-prefixed byte array with maximum length enforcement.
pub fn get_bytes_max(src: &mut &[u8], max_len: usize) -> Result<Vec<u8>, CodecError> {
    if src.len() < 4 {
        return Err(CodecError::Short);
    }

    let len = u32::from_le_bytes(src[0..4].try_into().unwrap()) as usize;

    if len > max_len {
        return Err(CodecError::Malformed("bytes too large"));
    }

    *src = &src[4..];

    if src.len() < len {
        return Err(CodecError::Short);
    }

    let v = src[..len].to_vec();

    *src = &src[len..];

    Ok(v)
}

/// Create a wire-format frame with message type and payload.
pub fn frame(msg_type: u8, payload: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(4 + 1 + payload.len());

    // Wire protocol uses big-endian (network byte order) for length prefix
    buf.put_u32((1 + payload.len()) as u32);
    buf.put_u8(msg_type);
    buf.extend_from_slice(payload);

    buf
}
