//! Hash functions including CRC32C and wyhash64.
//!
//! CRC-32C (Castagnoli, reflected) with compatibility for legacy non-reflected use.
//! The canonical reflected polynomial is 0x82F63B78.
//! Some earlier builds accidentally used 0x1EDC6F41 with LSB-first update, which
//! yields mismatched checksums. We keep a compatibility table to be able to read
//! such records and rewrite them.

use std::sync::Once;

const POLY_REFLECTED: u32 = 0x82F63B78;
const POLY_NONREFLECTED: u32 = 0x1EDC6F41;

static INIT_REF: Once = Once::new();
static mut TABLE_REF: [u32; 256] = [0; 256];

static INIT_LEGACY: Once = Once::new();
static mut TABLE_LEGACY: [u32; 256] = [0; 256];

fn init_reflected() {
    unsafe {
        for i in 0..256 {
            let mut crc = i as u32;
            for _ in 0..8 {
                if (crc & 1) != 0 {
                    crc = (crc >> 1) ^ POLY_REFLECTED;
                } else {
                    crc >>= 1;
                }
            }
            TABLE_REF[i] = crc;
        }
    }
}

fn init_legacy() {
    // Kept only for on-read compatibility with previously written data.
    unsafe {
        for i in 0..256 {
            let mut crc = i as u32;
            for _ in 0..8 {
                if (crc & 1) != 0 {
                    crc = (crc >> 1) ^ POLY_NONREFLECTED;
                } else {
                    crc >>= 1;
                }
            }
            TABLE_LEGACY[i] = crc;
        }
    }
}

/// Canonical CRC-32C (Castagnoli, reflected).
pub fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
    INIT_REF.call_once(init_reflected);
    crc = !crc;
    for &b in data {
        let idx = (crc ^ (b as u32)) & 0xFF;
        let t = unsafe { TABLE_REF[idx as usize] };
        crc = (crc >> 8) ^ t;
    }
    !crc
}

/// Legacy non-reflected polynomial use (compatibility read-path only).
pub fn crc32c_legacy(mut crc: u32, data: &[u8]) -> u32 {
    INIT_LEGACY.call_once(init_legacy);
    crc = !crc;
    for &b in data {
        let idx = (crc ^ (b as u32)) & 0xFF;
        let t = unsafe { TABLE_LEGACY[idx as usize] };
        crc = (crc >> 8) ^ t;
    }
    !crc
}

/// Fast 64-bit hash function (wyhash variant).
#[inline]
pub fn wyhash64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^ (x >> 33)
}

/// Hash a key for sharding purposes.
#[allow(dead_code)]
#[inline]
pub fn key_tag(key: u128) -> u64 {
    let lo = key as u64;
    let hi = (key >> 64) as u64;
    wyhash64(lo ^ hi)
}

/// Compute a hash of a byte slice into a u64.
#[inline]
fn hash_bytes64(b: &[u8]) -> u64 {
    // Simple streaming mix into a u64 seed
    let mut h: u64 = 0x9e3779b185ebca87;
    let mut i = 0usize;
    while i + 8 <= b.len() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[i..i + 8]);
        let v = u64::from_le_bytes(w);
        h = h.wrapping_add(v);
        h = wyhash64(h);
        i += 8;
    }
    if i < b.len() {
        let mut tail = [0u8; 8];
        let remain = &b[i..];
        tail[..remain.len()].copy_from_slice(remain);
        let v = u64::from_le_bytes(tail);
        h = h.wrapping_add(v);
        h = wyhash64(h);
    }
    h ^ (b.len() as u64)
}

/// Stable version identifier: 16-byte key (LE) + 8-byte hash(name) + 8-byte hash(data).
pub fn version_id(key: u128, name: &str, data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..16].copy_from_slice(&key.to_le_bytes());
    let name_hash = wyhash64(hash_bytes64(name.as_bytes()));
    let data_hash = wyhash64(hash_bytes64(data));
    out[16..24].copy_from_slice(&name_hash.to_le_bytes());
    out[24..32].copy_from_slice(&data_hash.to_le_bytes());
    out
}

/// Format bytes as a hex dump for debugging.
pub fn hex_dump(data: &[u8], max_bytes: usize) -> String {
    let limit = data.len().min(max_bytes);
    let mut result = String::new();

    for (i, chunk) in data[..limit].chunks(16).enumerate() {
        result.push_str(&format!("{:04x}: ", i * 16));

        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                result.push(' ');
            }
            result.push_str(&format!("{:02x} ", byte));
        }

        for j in chunk.len()..16 {
            if j == 8 {
                result.push(' ');
            }
            result.push_str("   ");
        }

        result.push_str(" |");

        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                result.push(*byte as char);
            } else {
                result.push('.');
            }
        }

        result.push_str("|\n");
    }

    if data.len() > max_bytes {
        result.push_str(&format!("... ({} more bytes)\n", data.len() - max_bytes));
    }

    result
}
