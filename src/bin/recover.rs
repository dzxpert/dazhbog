use std::{io, fs::{File, OpenOptions}, path::{Path, PathBuf}, os::unix::fs::FileExt};
use std::collections::HashMap;

const MAGIC: u32 = 0x4C4D4E31;

fn crc32c(seed: u32, data: &[u8]) -> u32 {
    let mut crc = !seed;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F63B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn crc32c_legacy(seed: u32, data: &[u8]) -> u32 {
    let mut crc = !seed;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB88320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[derive(Clone)]
struct Record {
    key: u128,
    ts_sec: u64,
    prev_addr: u64,
    len_bytes: u32,
    popularity: u32,
    name: String,
    data: Vec<u8>,
    flags: u8,
}

fn scan_segment_file(path: &Path) -> io::Result<Vec<(u64, Record)>> {
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    let mut records = Vec::new();
    let mut off = 0u64;
    
    println!("Scanning {} ({} bytes)", path.display(), len);
    
    while off + 12 < len {
        let mut hdr = [0u8; 12];
        if file.read_exact_at(&mut hdr, off).is_err() {
            break;
        }
        
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        if magic != MAGIC {
            break;
        }
        
        let rec_len = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as u64;
        if rec_len == 0 || off + rec_len > len {
            break;
        }
        
        let stored_crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        let body_len = (rec_len - 12) as usize;
        let mut body = vec![0u8; body_len];
        
        if file.read_exact_at(&mut body, off + 12).is_err() {
            off += rec_len;
            continue;
        }
        
        // Verify CRC
        let computed_crc = crc32c(0, &body);
        let crc_valid = if computed_crc == stored_crc {
            true
        } else {
            let computed_crc_legacy = crc32c_legacy(0, &body);
            computed_crc_legacy == stored_crc
        };
        
        if !crc_valid {
            println!("  Skipping corrupt record at offset {}", off);
            off += rec_len;
            continue;
        }
        
        // Parse record
        if body_len < 52 {
            off += rec_len;
            continue;
        }
        
        let p = &body[..];
        let lo = u64::from_le_bytes(p[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(p[8..16].try_into().unwrap());
        let key = ((hi as u128) << 64) | (lo as u128);
        let ts_sec = u64::from_le_bytes(p[16..24].try_into().unwrap());
        let prev_addr = u64::from_le_bytes(p[24..32].try_into().unwrap());
        let len_bytes = u32::from_le_bytes(p[32..36].try_into().unwrap());
        let popularity = u32::from_le_bytes(p[36..40].try_into().unwrap());
        let name_len = u16::from_le_bytes(p[40..42].try_into().unwrap()) as usize;
        let data_len = u32::from_le_bytes(p[42..46].try_into().unwrap()) as usize;
        let flags = p[46];
        
        let name_start = 52;
        if name_start + name_len + data_len > body_len {
            off += rec_len;
            continue;
        }
        
        let name = match std::str::from_utf8(&p[name_start..name_start + name_len]) {
            Ok(s) => s.to_string(),
            Err(_) => {
                off += rec_len;
                continue;
            }
        };
        
        let data_start = name_start + name_len;
        let data = p[data_start..data_start + data_len].to_vec();
        
        let rec = Record {
            key,
            ts_sec,
            prev_addr,
            len_bytes,
            popularity,
            name,
            data,
            flags,
        };
        
        records.push((off, rec));
        off += rec_len;
    }
    
    println!("  Found {} valid records", records.len());
    Ok(records)
}

fn write_record(file: &File, offset: u64, rec: &Record) -> io::Result<()> {
    let name_len = rec.name.len() as u16;
    let data_len = rec.data.len() as u32;
    let body_len: usize = 8+8+8+8+8+4+2+4+1+5 + (name_len as usize) + (data_len as usize);
    let total_len = 4 + 4 + 4 + body_len;
    
    let mut buf = Vec::with_capacity(total_len);
    let rec_len = total_len as u32;
    
    buf.extend_from_slice(&MAGIC.to_le_bytes());
    buf.extend_from_slice(&rec_len.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    
    buf.extend_from_slice(&(rec.key as u64).to_le_bytes());
    buf.extend_from_slice(&((rec.key >> 64) as u64).to_le_bytes());
    buf.extend_from_slice(&rec.ts_sec.to_le_bytes());
    buf.extend_from_slice(&rec.prev_addr.to_le_bytes());
    buf.extend_from_slice(&rec.len_bytes.to_le_bytes());
    buf.extend_from_slice(&rec.popularity.to_le_bytes());
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(&data_len.to_le_bytes());
    buf.push(rec.flags);
    buf.extend_from_slice(&[0u8; 5]);
    buf.extend_from_slice(rec.name.as_bytes());
    buf.extend_from_slice(&rec.data);
    
    let crc = crc32c(0, &buf[12..]);
    buf[8..12].copy_from_slice(&crc.to_le_bytes());
    
    file.write_all_at(&buf, offset)?;
    Ok(())
}

fn main() -> io::Result<()> {
    let data_dir = PathBuf::from("data");
    let backup_dir = PathBuf::from("data.backup");
    let temp_dir = PathBuf::from("data.recovered");
    
    if !data_dir.exists() {
        eprintln!("Error: data directory not found");
        std::process::exit(1);
    }
    
    println!("=== Dazhbog Segment Recovery Tool ===\n");
    
    // Scan all segment files
    let mut all_records: HashMap<u128, Vec<Record>> = HashMap::new();
    let mut total_valid = 0;
    let mut total_corrupt = 0;
    
    let mut entries: Vec<_> = std::fs::read_dir(&data_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("seg.")
                && e.file_name().to_string_lossy().ends_with(".dat")
        })
        .collect();
    
    entries.sort_by_key(|e| e.file_name());
    
    for entry in entries {
        let path = entry.path();
        match scan_segment_file(&path) {
            Ok(records) => {
                total_valid += records.len();
                for (_off, rec) in records {
                    all_records.entry(rec.key)
                        .or_insert_with(Vec::new)
                        .push(rec);
                }
            }
            Err(e) => {
                eprintln!("Error scanning {}: {}", path.display(), e);
                total_corrupt += 1;
            }
        }
    }
    
    println!("\n=== Scan Results ===");
    println!("Total valid records: {}", total_valid);
    println!("Unique keys: {}", all_records.len());
    println!("Failed files: {}", total_corrupt);
    
    // Keep only the latest version of each key
    let mut final_records: Vec<Record> = Vec::new();
    for (_key, mut versions) in all_records {
        versions.sort_by(|a, b| b.ts_sec.cmp(&a.ts_sec));
        if let Some(latest) = versions.into_iter().next() {
            if latest.flags & 0x01 == 0 {
                final_records.push(latest);
            }
        }
    }
    
    println!("Records to recover (after dedup): {}", final_records.len());
    
    if final_records.is_empty() {
        println!("\nNo records to recover!");
        return Ok(());
    }
    
    // Create temp directory
    std::fs::create_dir_all(&temp_dir)?;
    
    // Write recovered records to new segment
    println!("\n=== Writing recovered data ===");
    let seg_path = temp_dir.join("seg.00001.dat");
    let seg_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&seg_path)?;
    
    let mut offset = 0u64;
    for (i, rec) in final_records.iter().enumerate() {
        write_record(&seg_file, offset, rec)?;
        
        let name_len = rec.name.len() as u16;
        let data_len = rec.data.len() as u32;
        let body_len: usize = 8+8+8+8+8+4+2+4+1+5 + (name_len as usize) + (data_len as usize);
        let total_len = 4 + 4 + 4 + body_len;
        offset += total_len as u64;
        
        if (i + 1) % 1000 == 0 {
            println!("  Written {} records...", i + 1);
        }
    }
    
    seg_file.sync_all()?;
    println!("  Written {} records to {}", final_records.len(), seg_path.display());
    
    // Backup old segments
    println!("\n=== Creating backup ===");
    if backup_dir.exists() {
        std::fs::remove_dir_all(&backup_dir)?;
    }
    std::fs::rename(&data_dir, &backup_dir)?;
    println!("  Old segments backed up to {}", backup_dir.display());
    
    // Move recovered segments to data directory
    std::fs::rename(&temp_dir, &data_dir)?;
    println!("  Recovered segments moved to {}", data_dir.display());
    
    println!("\n=== Recovery Complete ===");
    println!("✓ Recovered {} unique records", final_records.len());
    println!("✓ Old segments backed up to: {}", backup_dir.display());
    println!("✓ New segments ready at: {}", data_dir.display());
    println!("\nYou can now restart the dazhbog server.");
    
    Ok(())
}
