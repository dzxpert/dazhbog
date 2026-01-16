//! RPC protocol message decoders.

use crate::api::metrics::METRICS;
use crate::common::error::CodecError;
use crate::protocol::codec::{get_bytes_max, get_str, get_str_max, get_u128_le};

use super::types::{HelloReq, PushCaps, PushItem};

/// Decode a Hello request.
pub fn decode_hello(payload: &[u8]) -> Result<HelloReq, CodecError> {
    let mut p = payload;

    if p.len() < 4 {
        return Err(CodecError::Short);
    }

    let pv = u32::from_le_bytes(p[0..4].try_into().unwrap());
    p = &p[4..];

    let user = get_str(&mut p)?;
    let pass = get_str(&mut p)?;

    Ok(HelloReq {
        protocol_version: pv,
        username: user,
        password: pass,
    })
}

/// Decode a Pull request.
pub fn decode_pull(payload: &[u8], max_items: usize) -> Result<Vec<u128>, CodecError> {
    let mut p = payload;

    if p.len() < 4 {
        return Err(CodecError::Short);
    }

    let n = u32::from_le_bytes(p[0..4].try_into().unwrap()) as usize;

    if n > max_items {
        METRICS.inc_decoder_rejects();
        return Err(CodecError::Malformed("pull count exceeds cap"));
    }

    p = &p[4..];

    if p.len() < 16 * n {
        return Err(CodecError::Short);
    }

    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(get_u128_le(&mut p)?);
    }

    Ok(v)
}

/// Decode a Push request.
pub fn decode_push(payload: &[u8], caps: &PushCaps) -> Result<Vec<PushItem>, CodecError> {
    let mut p = payload;

    if p.len() < 4 {
        return Err(CodecError::Short);
    }

    let n = u32::from_le_bytes(p[0..4].try_into().unwrap()) as usize;

    if n > caps.max_items {
        METRICS.inc_decoder_rejects();
        return Err(CodecError::Malformed("push count exceeds cap"));
    }

    p = &p[4..];

    let mut v = Vec::with_capacity(n);

    for _ in 0..n {
        let key = get_u128_le(&mut p)?;
        if p.len() < 8 {
            return Err(CodecError::Short);
        }
        let popularity = u32::from_le_bytes(p[0..4].try_into().unwrap());
        let len_bytes_declared = u32::from_le_bytes(p[4..8].try_into().unwrap());
        p = &p[8..];
        let name = match get_str_max(&mut p, caps.max_name_bytes) {
            Ok(s) => s,
            Err(CodecError::Malformed("string too large")) => {
                METRICS.inc_decoder_rejects();
                return Err(CodecError::Malformed("string too large"));
            }
            Err(e) => return Err(e),
        };
        let data = match get_bytes_max(&mut p, caps.max_data_bytes) {
            Ok(b) => b,
            Err(CodecError::Malformed("bytes too large")) => {
                METRICS.inc_decoder_rejects();
                return Err(CodecError::Malformed("bytes too large"));
            }
            Err(e) => return Err(e),
        };
        v.push(PushItem {
            key,
            popularity,
            len_bytes: len_bytes_declared,
            name,
            data,
        });
    }

    Ok(v)
}

/// Decode a Del request (same format as Pull).
pub fn decode_del(payload: &[u8], max_items: usize) -> Result<Vec<u128>, CodecError> {
    decode_pull(payload, max_items)
}

/// Decode a Hist request.
pub fn decode_hist(payload: &[u8], max_items: usize) -> Result<(u32, Vec<u128>), CodecError> {
    let mut p = payload;

    if p.len() < 8 {
        return Err(CodecError::Short);
    }

    let limit = u32::from_le_bytes(p[0..4].try_into().unwrap());
    let n = u32::from_le_bytes(p[4..8].try_into().unwrap()) as usize;

    if n > max_items {
        METRICS.inc_decoder_rejects();
        return Err(CodecError::Malformed("hist count exceeds cap"));
    }

    p = &p[8..];

    if p.len() < 16 * n {
        return Err(CodecError::Short);
    }

    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(get_u128_le(&mut p)?);
    }

    Ok((limit, v))
}
