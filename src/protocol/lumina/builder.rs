//! Lumina protocol response builders.

use bytes::BytesMut;
use log::*;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::wire::*;

/// Write a packet in Lumina format with chunking for large payloads.
pub async fn write_lumina_packet<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    msg_type: u8,
    payload: &[u8],
) -> io::Result<()> {
    let len = payload.len() as u32;
    let len_bytes = len.to_be_bytes();
    debug!(
        "write_lumina_packet: type=0x{:02x}, payload_len={}",
        msg_type, len
    );
    w.write_all(&len_bytes).await?;
    w.write_u8(msg_type).await?;

    // Write payload in chunks with yield points for large responses
    write_all_chunked(w, payload).await?;

    w.flush().await?;
    Ok(())
}

/// Write bytes in chunks with yield points to prevent worker thread starvation.
async fn write_all_chunked<W: AsyncWriteExt + Unpin>(w: &mut W, buf: &[u8]) -> io::Result<()> {
    const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks

    if buf.len() <= CHUNK_SIZE {
        // Small write, no need to chunk
        return w.write_all(buf).await;
    }

    // Large write - chunk it and yield between chunks
    let mut offset = 0;
    while offset < buf.len() {
        let end = (offset + CHUNK_SIZE).min(buf.len());
        w.write_all(&buf[offset..end]).await?;
        offset = end;

        // Yield to the runtime to allow other tasks to run
        if offset < buf.len() {
            tokio::task::yield_now().await;
        }
    }

    Ok(())
}

/// Read a Lumina packet (client-side).
pub async fn read_lumina_packet<R: AsyncReadExt + Unpin>(
    r: &mut R,
    max_len: usize,
) -> io::Result<(u8, Vec<u8>)> {
    let mut lenb = [0u8; 4];
    r.read_exact(&mut lenb).await?;
    let len = u32::from_be_bytes(lenb) as usize;
    if len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "remote frame too large",
        ));
    }
    let mut typb = [0u8; 1];
    r.read_exact(&mut typb).await?;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok((typb[0], payload))
}

/// Send a Lumina OK response (0x0a).
pub async fn send_lumina_ok<W: AsyncWriteExt + Unpin>(w: &mut W) -> io::Result<()> {
    write_lumina_packet(w, 0x0a, &[]).await
}

/// Send a Lumina Hello result (0x31).
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

/// Send a Lumina Fail response (0x0b).
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

/// Send a Lumina PullResult response (0x0f).
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

/// Send a Lumina PushResult response (0x11).
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

/// Send a Lumina DelResult response (0x19).
pub async fn send_lumina_del_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    deleted_mds: u32,
) -> io::Result<()> {
    let payload = pack_dd(deleted_mds);
    write_lumina_packet(w, 0x19, &payload).await
}

/// Send a Lumina Histories result response (0x30).
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

/// Build a Lumina Hello payload (client-side).
pub fn build_lumina_hello_payload(
    protocol_version: u32,
    license_data: &[u8],
    lic_number: [u8; 6],
    username: &str,
    password: &str,
    unk2: u32,
) -> Vec<u8> {
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

/// Build a PullMetadata payload for a set of 16-byte hashes (client-side).
pub fn build_pull_metadata_payload(hashes_be: &[[u8; 16]]) -> Vec<u8> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(0));
    payload.extend_from_slice(&pack_dd(0));
    payload.extend_from_slice(&pack_dd(hashes_be.len() as u32));
    for h in hashes_be {
        payload.extend_from_slice(&pack_dd(0));
        payload.extend_from_slice(&pack_dd(16));
        payload.extend_from_slice(h);
    }
    payload.to_vec()
}
