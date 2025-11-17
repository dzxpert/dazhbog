// CRC-32C (Castagnoli, reflected) with compatibility for legacy non-reflected use.
// The canonical reflected polynomial is 0x82F63B78.
// Some earlier builds accidentally used 0x1EDC6F41 with LSB-first update, which
// yields mismatched checksums. We keep a compatibility table to be able to read
// such records and rewrite them.
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
