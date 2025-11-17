use std::fs::File;
use std::io::Read;

mod crc {
    pub fn crc32c_inline(mut crc: u32, data: &[u8]) -> u32 {
        const POLY: u32 = 0x82F63B78;
        crc = !crc;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ POLY;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }
    
    pub fn crc32c_table(mut crc: u32, data: &[u8]) -> u32 {
        const POLY: u32 = 0x82F63B78;
        let mut table = [0u32; 256];
        for i in 0..256 {
            let mut c = i as u32;
            for _ in 0..8 {
                if c & 1 != 0 {
                    c = (c >> 1) ^ POLY;
                } else {
                    c >>= 1;
                }
            }
            table[i] = c;
        }
        
        crc = !crc;
        for &b in data {
            let idx = (crc ^ (b as u32)) & 0xFF;
            crc = (crc >> 8) ^ table[idx as usize];
        }
        !crc
    }
}

fn main() {
    let mut f = File::open("data/seg.00001.dat").unwrap();
    let mut hdr = [0u8; 12];
    f.read_exact(&mut hdr).unwrap();
    
    let rec_len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    let stored_crc = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    
    let mut body = vec![0u8; (rec_len - 12) as usize];
    f.read_exact(&mut body).unwrap();
    
    let computed_inline = crc::crc32c_inline(0, &body);
    let computed_table = crc::crc32c_table(0, &body);
    
    println!("Stored CRC:      0x{:08x}", stored_crc);
    println!("Computed inline: 0x{:08x} {}", computed_inline, if stored_crc == computed_inline {"✓"} else {"✗"});
    println!("Computed table:  0x{:08x} {}", computed_table, if stored_crc == computed_table {"✓"} else {"✗"});
}
