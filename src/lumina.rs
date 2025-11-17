// Lumina protocol support for IDA Pro's Lumina plugin
use log::*;
use bytes::BytesMut;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::io;

#[derive(Debug)]
pub enum LuminaError {
    UnexpectedEof,
    InvalidData,
}

impl std::fmt::Display for LuminaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LuminaError::UnexpectedEof => write!(f, "unexpected EOF"),
            LuminaError::InvalidData => write!(f, "invalid data"),
        }
    }
}

impl std::error::Error for LuminaError {}

pub struct LuminaHello {
    pub protocol_version: u32,
    pub username: String,
    pub password: String,
}

#[derive(Clone, Copy, Debug)]
pub struct LuminaCaps {
    pub max_funcs: usize,
    pub max_name_bytes: usize,
    pub max_data_bytes: usize,
    pub max_cstr_bytes: usize,
    pub max_hash_bytes: usize,
}

fn unpack_dd(data: &[u8]) -> (u32, usize) {
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
    let val = (((b & 0x1F) as u32) << 24) | ((data[1] as u32) << 16) | ((data[2] as u32) << 8) | (data[3] as u32);
    (val, 4)
}

fn unpack_cstr_capped(data: &[u8], max: usize) -> Result<(String, usize), LuminaError> {
    let null_pos = data.iter().position(|&b| b == 0).ok_or(LuminaError::UnexpectedEof)?;
    if null_pos > max { return Err(LuminaError::InvalidData); }
    let s = std::str::from_utf8(&data[..null_pos]).map_err(|_| LuminaError::InvalidData)?;
    Ok((s.to_string(), null_pos + 1))
}

fn pack_dd(v: u32) -> Vec<u8> {
    let bytes = v.to_le_bytes();
    match v {
        0..=0x7f => vec![bytes[0]],
        0x80..=0x3fff => vec![0x80 | bytes[1], bytes[0]],
        0x4000..=0x1fffff => vec![0xc0, bytes[2], bytes[1], bytes[0]],
        0x200000..=u32::MAX => {
            let mut out = Vec::with_capacity(5);
            out.extend_from_slice(&[0xff]);
            out.extend_from_slice(&bytes);
            out
        },
    }
}

// NOTE: pack_dq must encode the low 32 bits first, then the high 32 bits,
// matching how IDA expects dd(low) followed by dd(high). This fixes the
// erroneous far-future timestamps reported by some clients.
fn pack_dq(v: u64) -> Vec<u8> {
    let low = (v & 0xFFFF_FFFF) as u32;
    let high = (v >> 32) as u32;
    let mut result = pack_dd(low);
    result.extend_from_slice(&pack_dd(high));
    result
}

fn unpack_var_bytes_capped(data: &[u8], max_len: usize) -> Result<(&[u8], usize), LuminaError> {
    let (len, consumed) = unpack_dd(data);
    if consumed == 0 {
        return Err(LuminaError::UnexpectedEof);
    }
    let len = len as usize;
    if len > max_len { return Err(LuminaError::InvalidData); }
    let data = &data[consumed..];
    if data.len() < len {
        return Err(LuminaError::UnexpectedEof);
    }
    Ok((&data[..len], consumed + len))
}

/// Helper (client): pack var-bytes as dd(len) + bytes
pub fn pack_var_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + bytes.len());
    out.extend_from_slice(&pack_dd(bytes.len() as u32));
    out.extend_from_slice(bytes);
    out
}

pub fn parse_lumina_hello(payload: &[u8]) -> Result<LuminaHello, LuminaError> {
    let mut offset = 0;
    let (protocol_version, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LuminaError::UnexpectedEof); }
    offset += consumed;
    debug!("Lumina Hello: protocol_version={}", protocol_version);

    let (_license_data, consumed) = unpack_var_bytes_capped(&payload[offset..], 16384)?;
    offset += consumed;

    if payload.len() < offset + 6 { return Err(LuminaError::UnexpectedEof); }
    offset += 6;

    let (_unk2, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LuminaError::UnexpectedEof); }
    offset += consumed;

    let (username, password) = if protocol_version > 2 && offset < payload.len() {
        match unpack_cstr_capped(&payload[offset..], 256) {
            Ok((user, consumed)) => {
                offset += consumed;
                match unpack_cstr_capped(&payload[offset..], 256) {
                    Ok((pass, _)) => (user, pass),
                    Err(_) => (user, String::new()),
                }
            }
            Err(_) => ("guest".to_string(), String::new()),
        }
    } else {
        ("guest".to_string(), String::new())
    };

    Ok(LuminaHello { protocol_version, username, password })
}

pub struct LuminaPullMetadataFunc {
    pub unk0: u32,
    pub mb_hash: Vec<u8>,
}

pub struct LuminaPullMetadata {
    pub unk0: u32,
    pub unk1: Vec<u32>,
    pub funcs: Vec<LuminaPullMetadataFunc>,
}

pub struct LuminaPushMetadataFunc {
    pub name: String,
    pub func_len: u32,
    pub func_data: Vec<u8>,
    pub unk2: u32,
    pub hash: Vec<u8>,
}

pub struct LuminaPushMetadata {
    pub unk0: u32,
    pub idb_path: String,
    pub file_path: String,
    pub md5: [u8; 16],
    pub hostname: String,
    pub funcs: Vec<LuminaPushMetadataFunc>,
    pub unk1: Vec<u64>,
}

pub struct LuminaGetFuncHistories {
    pub funcs: Vec<LuminaPullMetadataFunc>,
    pub unk0: u32,
}

pub fn parse_lumina_pull_metadata(payload: &[u8], caps: LuminaCaps) -> Result<LuminaPullMetadata, LuminaError> {
    let mut offset = 0;
    debug!("parse_lumina_pull_metadata: payload len={}", payload.len());

    let (unk0, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LuminaError::UnexpectedEof); }
    offset += consumed;

    let (count1, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LuminaError::UnexpectedEof); }
    offset += consumed;

    let mut unk1 = Vec::with_capacity((count1 as usize).min(1024));
    for _ in 0..count1 {
        let (v, c) = unpack_dd(&payload[offset..]);
        if c == 0 { return Err(LuminaError::UnexpectedEof); }
        offset += c;
        unk1.push(v);
    }

    let (count_funcs, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LuminaError::UnexpectedEof); }
    offset += consumed;

    let n = (count_funcs as usize).min(caps.max_funcs);
    let mut funcs = Vec::with_capacity(n);

    for i in 0..count_funcs {
        let (func_unk0, c) = unpack_dd(&payload[offset..]);
        if c == 0 { return Err(LuminaError::UnexpectedEof); }
        offset += c;

        let (hash, c) = unpack_var_bytes_capped(&payload[offset..], caps.max_hash_bytes)?;
        offset += c;

        if (i as usize) < n {
            funcs.push(LuminaPullMetadataFunc { unk0: func_unk0, mb_hash: hash.to_vec() });
        }
    }

    Ok(LuminaPullMetadata { unk0, unk1, funcs })
}

pub fn parse_lumina_push_metadata(payload: &[u8], caps: LuminaCaps) -> Result<LuminaPushMetadata, LuminaError> {
    let mut offset = 0;
    debug!("parse_lumina_push_metadata: payload len={}", payload.len());

    let (unk0, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LuminaError::UnexpectedEof); }
    offset += consumed;

    let (idb_path, c) = unpack_cstr_capped(&payload[offset..], caps.max_cstr_bytes)?;
    offset += c;

    let (file_path, c) = unpack_cstr_capped(&payload[offset..], caps.max_cstr_bytes)?;
    offset += c;

    if payload.len() < offset + 16 { return Err(LuminaError::UnexpectedEof); }
    let mut md5 = [0u8; 16];
    md5.copy_from_slice(&payload[offset..offset+16]);
    offset += 16;

    let (hostname, c) = unpack_cstr_capped(&payload[offset..], caps.max_cstr_bytes)?;
    offset += c;

    let (count_funcs, c) = unpack_dd(&payload[offset..]);
    if c == 0 { return Err(LuminaError::UnexpectedEof); }
    offset += c;

    if count_funcs as usize > caps.max_funcs {
        log::warn!("Push request contains {} functions but limit is {}", count_funcs, caps.max_funcs);
        return Err(LuminaError::InvalidData);
    }

    let n = count_funcs as usize;
    let mut funcs = Vec::with_capacity(n);

    for _ in 0..count_funcs {
        let (name, c) = unpack_cstr_capped(&payload[offset..], caps.max_name_bytes)?;
        offset += c;

        let (func_len, c) = unpack_dd(&payload[offset..]);
        if c == 0 { return Err(LuminaError::UnexpectedEof); }
        offset += c;

        let (func_data, c) = unpack_var_bytes_capped(&payload[offset..], caps.max_data_bytes)?;
        offset += c;

        let (unk2, c) = unpack_dd(&payload[offset..]);
        if c == 0 { return Err(LuminaError::UnexpectedEof); }
        offset += c;

        let (hash, c) = unpack_var_bytes_capped(&payload[offset..], caps.max_hash_bytes)?;
        offset += c;

        funcs.push(LuminaPushMetadataFunc {
            name, func_len, func_data: func_data.to_vec(), unk2, hash: hash.to_vec(),
        });
    }

    let (count_u64, c) = unpack_dd(&payload[offset..]);
    if c == 0 { return Err(LuminaError::UnexpectedEof); }
    offset += c;

    let cap_u64s = 4096usize.min(count_u64 as usize);
    let mut unk1 = Vec::with_capacity(cap_u64s);

    for i in 0..count_u64 {
        let (low, c) = unpack_dd(&payload[offset..]);
        if c == 0 { return Err(LuminaError::UnexpectedEof); }
        offset += c;

        let (high, c) = unpack_dd(&payload[offset..]);
        if c == 0 { return Err(LuminaError::UnexpectedEof); }
        offset += c;

        if (i as usize) < cap_u64s {
            unk1.push(((high as u64) << 32) | (low as u64));
        }
    }

    Ok(LuminaPushMetadata {
        unk0, idb_path, file_path, md5, hostname, funcs, unk1,
    })
}

pub fn parse_lumina_get_func_histories(payload: &[u8], caps: LuminaCaps) -> Result<LuminaGetFuncHistories, LuminaError> {
    let mut offset = 0;

    let (count, c) = unpack_dd(&payload[offset..]);
    if c == 0 { return Err(LuminaError::UnexpectedEof); }
    offset += c;

    let n = (count as usize).min(caps.max_funcs);
    let mut funcs = Vec::with_capacity(n);

    for i in 0..count {
        let (func_unk0, c) = unpack_dd(&payload[offset..]);
        if c == 0 { return Err(LuminaError::UnexpectedEof); }
        offset += c;

        let (hash, c) = unpack_var_bytes_capped(&payload[offset..], caps.max_hash_bytes)?;
        offset += c;

        if (i as usize) < n {
            funcs.push(LuminaPullMetadataFunc { unk0: func_unk0, mb_hash: hash.to_vec() });
        }
    }

    let (unk0, _c) = unpack_dd(&payload[offset..]);

    Ok(LuminaGetFuncHistories { funcs, unk0 })
}

/// Build a Lumina Hello payload (client-side)
pub fn build_lumina_hello_payload(protocol_version: u32, license_data: &[u8], lic_number: [u8;6], username: &str, password: &str, unk2: u32) -> Vec<u8> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(protocol_version));
    payload.extend_from_slice(&pack_dd(license_data.len() as u32));
    payload.extend_from_slice(license_data);
    payload.extend_from_slice(&lic_number);
    payload.extend_from_slice(&pack_dd(unk2));
    if protocol_version > 2 {
        payload.extend_from_slice(username.as_bytes());
        payload.extend_from_slice(b"\0");
        payload.extend_from_slice(password.as_bytes());
        payload.extend_from_slice(b"\0");
    }
    payload.to_vec()
}

/// Build PullMetadata payload for a set of 16-byte hashes (client-side)
pub fn build_pull_metadata_payload(hashes_be: &[[u8;16]]) -> Vec<u8> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(0));
    payload.extend_from_slice(&pack_dd(0));
    payload.extend_from_slice(&pack_dd(hashes_be.len() as u32));
    // For each hash, write unk0 followed immediately by the var-bytes hash
    for h in hashes_be {
        payload.extend_from_slice(&pack_dd(0));
        // variable-length mb_hash: dd(length) + bytes
        payload.extend_from_slice(&pack_dd(16));
        payload.extend_from_slice(h);
    }
    payload.to_vec()
}

/// Read a legacy Lumina packet (client-side)
pub async fn read_lumina_packet<R: AsyncReadExt + Unpin>(r: &mut R, max_len: usize) -> io::Result<(u8, Vec<u8>)> {
    let mut lenb = [0u8;4];
    r.read_exact(&mut lenb).await?;
    let len = u32::from_be_bytes(lenb) as usize;
    if len > max_len { return Err(io::Error::new(io::ErrorKind::InvalidData, "remote frame too large")); }
    let mut typb = [0u8;1];
    r.read_exact(&mut typb).await?;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok((typb[0], payload))
}

/// Decode Fail message payload (0x0b): returns (code, message)
pub fn decode_lumina_fail(payload: &[u8]) -> Result<(u32, String), LuminaError> {
    let (code, consumed) = unpack_dd(payload);
    if consumed == 0 { return Err(LuminaError::UnexpectedEof); }
    let msg_bytes = &payload[consumed..];
    let null_pos = msg_bytes.iter().position(|&b| b == 0).unwrap_or(msg_bytes.len());
    let message = std::str::from_utf8(&msg_bytes[..null_pos])
        .unwrap_or("<invalid utf8>")
        .to_string();
    Ok((code, message))
}

/// Decode PullResult payload (0x0f): returns (statuses, funcs)
pub fn decode_lumina_pull_result(payload: &[u8]) -> Result<(Vec<u32>, Vec<(u32,u32,String,Vec<u8>)>), LuminaError> {
    let mut off = 0usize;
    let (n_status, c) = unpack_dd(&payload[off..]);
    if c == 0 { return Err(LuminaError::UnexpectedEof); }
    off += c;
    let mut statuses = Vec::with_capacity(n_status as usize);
    for _ in 0..n_status {
        let (s, c) = unpack_dd(&payload[off..]);
        if c == 0 { return Err(LuminaError::UnexpectedEof); }
        off += c;
        statuses.push(s);
    }
    let (n_funcs, c) = unpack_dd(&payload[off..]);
    if c == 0 { return Err(LuminaError::UnexpectedEof); }
    off += c;

    let mut funcs = Vec::with_capacity(n_funcs as usize);
    for _ in 0..n_funcs {
        // cstr name
        let (name, c) = {
            let null_pos = payload[off..].iter().position(|&b| b == 0).ok_or(LuminaError::UnexpectedEof)?;
            let s = std::str::from_utf8(&payload[off..off+null_pos]).map_err(|_| LuminaError::InvalidData)?.to_string();
            off += null_pos + 1;
            (s, null_pos + 1)
        };
        let (decl_len, c) = unpack_dd(&payload[off..]);
        if c == 0 { return Err(LuminaError::UnexpectedEof); }
        off += c;
        let (meta_len, c) = unpack_dd(&payload[off..]);
        if c == 0 { return Err(LuminaError::UnexpectedEof); }
        off += c;
        if payload.len() < off + (meta_len as usize) { return Err(LuminaError::UnexpectedEof); }
        let data = payload[off..off+(meta_len as usize)].to_vec();
        off += meta_len as usize;
        let (pop, c) = unpack_dd(&payload[off..]);
        if c == 0 { return Err(LuminaError::UnexpectedEof); }
        off += c;
        funcs.push((pop, decl_len, name, data));
    }
    Ok((statuses, funcs))
}

/// Write a packet in Lumina format (server + client)
pub async fn write_lumina_packet<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    msg_type: u8,
    payload: &[u8],
) -> io::Result<()> {
    let len = payload.len() as u32;
    let len_bytes = len.to_be_bytes();
    debug!("write_lumina_packet: type=0x{:02x}, payload_len={}", msg_type, len);
    w.write_all(&len_bytes).await?;
    w.write_u8(msg_type).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

pub async fn send_lumina_ok<W: AsyncWriteExt + Unpin>(w: &mut W) -> io::Result<()> {
    write_lumina_packet(w, 0x0a, &[]).await
}

pub async fn send_lumina_hello_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    features: u32,
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(b"\0");
    payload.extend_from_slice(b"\0");
    payload.extend_from_slice(b"\0");
    payload.extend_from_slice(b"\0");
    payload.extend_from_slice(&[0x00]);
    payload.extend_from_slice(&[0x00, 0x00]);
    if features < 0x80 {
        payload.extend_from_slice(&[features as u8]);
    } else {
        let b1 = 0x80 | ((features >> 8) as u8);
        let b2 = (features & 0xFF) as u8;
        payload.extend_from_slice(&[b1, b2]);
    }
    write_lumina_packet(w, 0x31, &payload).await
}

pub async fn send_lumina_fail<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    code: u32,
    message: &str,
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(code));
    payload.extend_from_slice(message.as_bytes());
    payload.extend_from_slice(b"\0");
    write_lumina_packet(w, 0x0b, &payload).await
}

pub async fn send_lumina_pull_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    statuses: &[u32],
    funcs: &[(u32, u32, String, Vec<u8>)],
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(statuses.len() as u32));
    for &status in statuses {
        payload.extend_from_slice(&pack_dd(status));
    }
    payload.extend_from_slice(&pack_dd(funcs.len() as u32));
    for (pop, len, name, data) in funcs {
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(b"\0");
        payload.extend_from_slice(&pack_dd(*len));
        payload.extend_from_slice(&pack_dd(data.len() as u32));
        payload.extend_from_slice(data);
        payload.extend_from_slice(&pack_dd(*pop));
    }
    write_lumina_packet(w, 0x0f, &payload).await
}

pub async fn send_lumina_push_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    status: &[u32],
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(status.len() as u32));
    for &s in status {
        payload.extend_from_slice(&pack_dd(s));
    }
    write_lumina_packet(w, 0x11, &payload).await
}

pub async fn send_lumina_del_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    deleted_mds: u32,
) -> io::Result<()> {
    let payload = pack_dd(deleted_mds);
    write_lumina_packet(w, 0x19, &payload).await
}

pub async fn send_lumina_histories_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    statuses: &[u32],
    histories: &[Vec<(u64, String, Vec<u8>)>],
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(statuses.len() as u32));
    for &status in statuses {
        payload.extend_from_slice(&pack_dd(status));
    }
    payload.extend_from_slice(&pack_dd(histories.len() as u32));
    for history in histories {
        payload.extend_from_slice(&pack_dd(history.len() as u32));
        for (ts, name, metadata) in history {
            payload.extend_from_slice(&pack_dq(0));
            payload.extend_from_slice(&pack_dq(0));
            payload.extend_from_slice(name.as_bytes());
            payload.extend_from_slice(b"\0");
            payload.extend_from_slice(&pack_dd(metadata.len() as u32));
            payload.extend_from_slice(metadata);
            payload.extend_from_slice(&pack_dq(*ts));
            payload.extend_from_slice(&pack_dd(0));
            payload.extend_from_slice(&pack_dd(0));
        }
    }
    payload.extend_from_slice(&pack_dd(0));
    payload.extend_from_slice(&pack_dd(0));
    write_lumina_packet(w, 0x30, &payload).await
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
        assert_eq!(unpack_cstr_capped(b"hello\0", 16).unwrap(), ("hello".to_string(), 6));
        assert!(unpack_cstr_capped(b"no null terminator", 64).is_err());
        assert!(unpack_cstr_capped(&[b'a'; 10_000], 1024).is_err());
    }

    #[test]
    fn test_decode_pull_result_roundtrip() {
        // Build a synthetic payload using the encoder and decode it back.
        let funcs = vec![(10u32, 4u32, "name".to_string(), vec![1,2,3,4])];
        let statuses = vec![0u32];
        let mut buf = Vec::new();
        tokio_test::block_on(async {
            let mut payload = BytesMut::new();
            payload.extend_from_slice(&super::pack_dd(funcs.len() as u32));
            for (pop, len, name, data) in &funcs {
                payload.extend_from_slice(name.as_bytes());
                payload.extend_from_slice(b"\0");
                payload.extend_from_slice(&super::pack_dd(*len));
                payload.extend_from_slice(&super::pack_dd(data.len() as u32));
                payload.extend_from_slice(data);
                payload.extend_from_slice(&super::pack_dd(*pop));
            }
            buf = payload.to_vec();
        });
        let mut final_payload = Vec::new();
        final_payload.extend_from_slice(&pack_dd(statuses.len() as u32));
        for s in &statuses { final_payload.extend_from_slice(&pack_dd(*s)); }
        final_payload.extend_from_slice(&buf);
        let (st, ff) = decode_lumina_pull_result(&final_payload).unwrap();
        assert_eq!(st, statuses);
        assert_eq!(ff.len(), 1);
        assert_eq!(ff[0].0, 10);
        assert_eq!(ff[0].1, 4);
        assert_eq!(ff[0].2, "name");
        assert_eq!(ff[0].3, vec![1,2,3,4]);
    }

    #[test]
    fn test_pack_dq_low_then_high() {
        // Ensure pack_dq encodes low 32 then high 32 bits.
        let v: u64 = 0x11223344_55667788;
        let enc = pack_dq(v);
        // First dd encodes low 32 (0x55667788) using variable form; start byte must reflect the dd encoding.
        // Here we only test that decoding restores the original when read back in our hist writer.
        // Decode back using the same dd decoder twice:
        let (lo, c1) = super::unpack_dd(&enc[..]);
        let (hi, _c2) = super::unpack_dd(&enc[c1..]);
        assert_eq!(lo, 0x55667788);
        assert_eq!(hi, 0x11223344);
    }
}
