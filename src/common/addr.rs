//! Address packing utilities for segment storage.
//!
//! Addresses are packed as 64-bit values containing:
//! - Bits 63-48: Segment ID (16 bits)
//! - Bits 47-8: Offset within segment (40 bits, max ~1TB per segment)
//! - Bits 7-0: Flags (8 bits)

/// Packed address type (segment_id | offset | flags).
pub type Addr = u64;

/// Pack segment ID, offset, and flags into a single 64-bit address.
#[inline]
pub const fn pack_addr(seg_id: u16, offset: u64, flags: u8) -> Addr {
    ((seg_id as u64) << 48) | ((offset & ((1u64 << 40) - 1)) << 8) | (flags as u64)
}

/// Extract segment ID from a packed address.
#[inline]
pub const fn addr_seg(addr: Addr) -> u16 {
    (addr >> 48) as u16
}

/// Extract offset from a packed address.
#[inline]
pub const fn addr_off(addr: Addr) -> u64 {
    (addr >> 8) & ((1u64 << 40) - 1)
}

/// Extract flags from a packed address.
#[inline]
#[allow(dead_code)]
pub const fn addr_flags(addr: Addr) -> u8 {
    addr as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_unpack_roundtrip() {
        let seg_id: u16 = 0x1234;
        let offset: u64 = 0x9876543210;
        let flags: u8 = 0xAB;

        let addr = pack_addr(seg_id, offset, flags);
        assert_eq!(addr_seg(addr), seg_id);
        assert_eq!(addr_off(addr), offset);
        assert_eq!(addr_flags(addr), flags);
    }

    #[test]
    fn test_zero_values() {
        let addr = pack_addr(0, 0, 0);
        assert_eq!(addr, 0);
        assert_eq!(addr_seg(addr), 0);
        assert_eq!(addr_off(addr), 0);
        assert_eq!(addr_flags(addr), 0);
    }

    #[test]
    fn test_max_values() {
        let seg_id: u16 = u16::MAX;
        let offset: u64 = (1u64 << 40) - 1; // Max 40-bit value
        let flags: u8 = u8::MAX;

        let addr = pack_addr(seg_id, offset, flags);
        assert_eq!(addr_seg(addr), seg_id);
        assert_eq!(addr_off(addr), offset);
        assert_eq!(addr_flags(addr), flags);
    }
}
