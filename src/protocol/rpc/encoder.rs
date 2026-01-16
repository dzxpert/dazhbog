//! RPC protocol message encoders.

use bytes::{BufMut, BytesMut};
use tokio::io::AsyncWriteExt;

use super::{MSG_DEL_OK, MSG_FAIL, MSG_HELLO_OK, MSG_HIST_OK, MSG_OK, MSG_PULL_OK, MSG_PUSH_OK};
use crate::protocol::codec::{frame, put_bytes, put_str};

/// Write all bytes and flush.
pub async fn write_all<W: AsyncWriteExt + Unpin>(w: &mut W, buf: &[u8]) -> std::io::Result<()> {
    w.write_all(buf).await?;
    w.flush().await
}

/// Encode an OK response.
pub fn encode_ok() -> BytesMut {
    frame(MSG_OK, &[])
}

/// Encode a Fail response.
pub fn encode_fail(code: u32, msg: &str) -> BytesMut {
    let mut p = BytesMut::with_capacity(4 + 4 + msg.len());
    p.put_u32_le(code);
    put_str(&mut p, msg);
    frame(MSG_FAIL, &p)
}

/// Encode a Hello OK response.
pub fn encode_hello_ok(features: u32) -> BytesMut {
    let mut p = BytesMut::with_capacity(4);
    p.put_u32_le(features);
    frame(MSG_HELLO_OK, &p)
}

/// Encode a Pull OK response.
pub fn encode_pull_ok(status: &[u32], funcs: &[(u32, u32, String, Vec<u8>)]) -> BytesMut {
    let mut p = BytesMut::new();
    p.put_u32_le(status.len() as u32);

    for s in status {
        p.put_u32_le(*s);
    }

    p.put_u32_le(funcs.len() as u32);

    for (pop, len, name, data) in funcs {
        p.put_u32_le(*pop);
        p.put_u32_le(*len);
        put_str(&mut p, name);
        put_bytes(&mut p, data);
    }

    frame(MSG_PULL_OK, &p)
}

/// Encode a Push OK response.
pub fn encode_push_ok(status: &[u32]) -> BytesMut {
    let mut p = BytesMut::new();
    p.put_u32_le(status.len() as u32);

    for s in status {
        p.put_u32_le(*s);
    }

    frame(MSG_PUSH_OK, &p)
}

/// Encode a Del OK response.
pub fn encode_del_ok(deleted: u32) -> BytesMut {
    let mut p = BytesMut::new();
    p.put_u32_le(deleted);
    frame(MSG_DEL_OK, &p)
}

/// Encode a Hist OK response.
pub fn encode_hist_ok(status: &[u32], logs: &[Vec<(u64, String, Vec<u8>)>]) -> BytesMut {
    let mut p = BytesMut::new();
    p.put_u32_le(status.len() as u32);

    for s in status {
        p.put_u32_le(*s);
    }

    p.put_u32_le(logs.len() as u32);

    for log in logs {
        p.put_u32_le(log.len() as u32);
        for (ts, name, data) in log {
            p.put_u64_le(*ts);
            put_str(&mut p, name);
            put_bytes(&mut p, data);
        }
    }

    frame(MSG_HIST_OK, &p)
}
