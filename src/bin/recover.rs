use std::collections::HashMap;
use std::env;
use std::{io, path::PathBuf};

const MAGIC: u32 = 0x4C4D4E31;

/// Decode basenames from context index format.
/// Format: count:u8, then for each: len:u16_le, bytes
fn decode_basenames(mut b: &[u8]) -> Option<Vec<String>> {
    if b.is_empty() {
        return Some(Vec::new());
    }
    let count = b[0] as usize;
    b = &b[1..];

    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if b.len() < 2 {
            return None;
        }
        let len = u16::from_le_bytes([b[0], b[1]]) as usize;
        b = &b[2..];
        if b.len() < len {
            return None;
        }
        let s = std::str::from_utf8(&b[..len]).ok()?.to_string();
        b = &b[len..];
        out.push(s);
    }
    Some(out)
}

/// Pack segment ID, offset, and flags into a single 64-bit address.
const fn pack_addr(seg_id: u16, offset: u64, flags: u8) -> u64 {
    ((seg_id as u64) << 48) | ((offset & ((1u64 << 40) - 1)) << 8) | (flags as u64)
}

mod crc32c_impl {
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

fn scan_segment_tree(tree: &sled::Tree) -> io::Result<Vec<(u64, Record)>> {
    let mut records = Vec::new();
    println!(
        "Scanning tree {} ({} records)",
        String::from_utf8_lossy(&tree.name()),
        tree.len()
    );

    for item in tree.iter() {
        let (offset_bytes, record_bytes) = match item {
            Ok(i) => i,
            Err(e) => {
                eprintln!("  Error iterating tree: {}", e);
                continue;
            }
        };

        let off = u64::from_be_bytes(offset_bytes.as_ref().try_into().unwrap());

        if record_bytes.len() < 12 {
            continue;
        }
        let hdr: &[u8] = &record_bytes[0..12];

        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        if magic != MAGIC {
            eprintln!("  Skipping record at offset {} (bad magic)", off);
            continue;
        }

        let rec_len = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        if rec_len != record_bytes.len() {
            eprintln!("  Skipping record at offset {} (length mismatch)", off);
            continue;
        }

        let stored_crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        let body = &record_bytes[12..];

        // Verify CRC
        let computed_crc = crc32c_impl::crc32c(0, body);
        let crc_valid = if computed_crc == stored_crc {
            true
        } else {
            let computed_crc_legacy = crc32c_impl::crc32c_legacy(0, body);
            computed_crc_legacy == stored_crc
        };

        if !crc_valid {
            println!("  Skipping corrupt record at offset {}", off);
            continue;
        }

        // Parse record
        if body.len() < 52 {
            continue;
        }

        let p = body;
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
        if name_start + name_len + data_len > body.len() {
            continue;
        }

        let name = match std::str::from_utf8(&p[name_start..name_start + name_len]) {
            Ok(s) => s.to_string(),
            Err(_) => continue,
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
    }

    println!("  Found {} valid records", records.len());
    Ok(records)
}

fn write_record_to_tree(tree: &sled::Tree, offset: u64, rec: &Record) -> io::Result<usize> {
    let name_len = rec.name.len() as u16;
    let data_len = rec.data.len() as u32;
    let body_len: usize =
        8 + 8 + 8 + 8 + 4 + 4 + 2 + 4 + 1 + 5 + (name_len as usize) + (data_len as usize);
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

    let crc = crc32c_impl::crc32c(0, &buf[12..]);
    buf[8..12].copy_from_slice(&crc.to_le_bytes());

    tree.insert(offset.to_be_bytes(), buf.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(total_len)
}

fn print_usage() {
    eprintln!("Usage: recover [COMMAND] [OPTIONS]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  --rebuild-index [DATA_DIR]   Rebuild the key->addr index from segment data");
    eprintln!("  --rebuild-search [DATA_DIR]  Rebuild the full-text search index");
    eprintln!("  --rebuild-basenames [DATA_DIR]  Populate ctx.key_basenames from ctx.binary_meta");
    eprintln!("  --full-recover [DATA_DIR]    Full recovery with deduplication");
    eprintln!("  --list-trees [DATA_DIR]      List all sled trees and their sizes");
    eprintln!("  --help                       Show this help message");
    eprintln!();
    eprintln!("Default DATA_DIR is 'data/'");
}

fn list_trees(data_dir: &PathBuf) -> io::Result<()> {
    println!("=== Dazhbog Database Inspector ===\n");
    println!("Data directory: {}", data_dir.display());

    // Check segments_db
    let seg_db_dir = data_dir.join("segments_db");
    if seg_db_dir.exists() {
        println!("\n--- segments_db ---");
        let db = sled::open(&seg_db_dir)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open: {}", e)))?;
        for name in db.tree_names() {
            let name_str = String::from_utf8_lossy(&name);
            let tree = db
                .open_tree(&name)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {}", e)))?;
            println!("  {:30} {:>12} entries", name_str, tree.len());
        }
    }

    // Check index_db (contains main index + context trees)
    let index_db_dir = data_dir.join("index_db");
    if index_db_dir.exists() {
        println!("\n--- index_db ---");
        let db = sled::open(&index_db_dir)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open: {}", e)))?;
        for name in db.tree_names() {
            let name_str = String::from_utf8_lossy(&name);
            let tree = db
                .open_tree(&name)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {}", e)))?;
            println!("  {:30} {:>12} entries", name_str, tree.len());
        }
    }

    // Also check old-style "index" folder (before rename to index_db)
    let index_dir = data_dir.join("index");
    if index_dir.exists() {
        println!("\n--- index (legacy) ---");
        let db = sled::open(&index_dir)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open: {}", e)))?;
        for name in db.tree_names() {
            let name_str = String::from_utf8_lossy(&name);
            let tree = db
                .open_tree(&name)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {}", e)))?;
            println!("  {:30} {:>12} entries", name_str, tree.len());
        }
    }

    Ok(())
}

fn rebuild_index(data_dir: &PathBuf) -> io::Result<()> {
    let seg_db_dir = data_dir.join("segments_db");
    let index_db_dir = data_dir.join("index_db");

    if !seg_db_dir.exists() {
        eprintln!(
            "Error: {}/segments_db directory not found.",
            data_dir.display()
        );
        std::process::exit(1);
    }

    println!("=== Dazhbog Index Rebuild Tool ===\n");
    println!("Data directory: {}", data_dir.display());

    // Open the segments database (read-only scan)
    let seg_db = sled::open(&seg_db_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open segments: {}", e)))?;

    // Open/create the index database
    let index_db = sled::Config::default()
        .path(&index_db_dir)
        .cache_capacity(128 * 1024 * 1024)
        .open()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open index: {}", e)))?;

    let index_tree = index_db.open_tree("latest").map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("sled open latest tree: {}", e),
        )
    })?;

    // Clear the existing index
    println!("Clearing existing index...");
    index_tree
        .clear()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("clear index: {}", e)))?;

    // Get segment tree names
    let mut tree_names: Vec<_> = seg_db
        .tree_names()
        .into_iter()
        .map(|name| String::from_utf8_lossy(&name).to_string())
        .filter(|name| name.starts_with("seg."))
        .collect();
    tree_names.sort();

    println!("Found {} segment trees", tree_names.len());

    // Track latest record for each key (by timestamp)
    let mut latest_by_key: HashMap<u128, (u64, u64, u8)> = HashMap::new(); // key -> (ts, addr, flags)
    let mut total_records = 0u64;
    let mut corrupt_records = 0u64;

    for name in &tree_names {
        let seg_id: u16 = name[4..9].parse().unwrap_or(0);
        let tree = seg_db.open_tree(name).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("open tree {}: {}", name, e))
        })?;

        println!("Scanning {} ({} records)...", name, tree.len());

        for item in tree.iter() {
            let (offset_bytes, record_bytes) = match item {
                Ok(i) => i,
                Err(_) => continue,
            };

            let offset = u64::from_be_bytes(offset_bytes.as_ref().try_into().unwrap());

            if record_bytes.len() < 12 {
                corrupt_records += 1;
                continue;
            }

            let hdr: &[u8] = &record_bytes[0..12];
            let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
            if magic != MAGIC {
                corrupt_records += 1;
                continue;
            }

            let stored_crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
            let body = &record_bytes[12..];

            // Verify CRC
            let computed_crc = crc32c_impl::crc32c(0, body);
            let crc_valid = if computed_crc == stored_crc {
                true
            } else {
                let computed_crc_legacy = crc32c_impl::crc32c_legacy(0, body);
                computed_crc_legacy == stored_crc
            };

            if !crc_valid {
                corrupt_records += 1;
                continue;
            }

            if body.len() < 52 {
                corrupt_records += 1;
                continue;
            }

            // Parse key, timestamp, and flags
            let lo = u64::from_le_bytes(body[0..8].try_into().unwrap());
            let hi = u64::from_le_bytes(body[8..16].try_into().unwrap());
            let key = ((hi as u128) << 64) | (lo as u128);
            let ts_sec = u64::from_le_bytes(body[16..24].try_into().unwrap());
            let flags = body[46];

            let addr = pack_addr(seg_id, offset, flags);

            // Keep the latest version
            match latest_by_key.get(&key) {
                Some(&(existing_ts, _, _)) if existing_ts >= ts_sec => {}
                _ => {
                    latest_by_key.insert(key, (ts_sec, addr, flags));
                }
            }

            total_records += 1;
        }
    }

    println!("\n=== Scan Results ===");
    println!("Total valid records: {}", total_records);
    println!("Corrupt records skipped: {}", corrupt_records);
    println!("Unique keys: {}", latest_by_key.len());

    // Write index entries (skip deleted records)
    println!("\nWriting index entries...");
    let mut indexed = 0u64;
    let mut deleted = 0u64;

    for (key, (_ts, addr, flags)) in &latest_by_key {
        if flags & 0x01 == 0x01 {
            // Deleted record, don't index
            deleted += 1;
            continue;
        }

        index_tree
            .insert(key.to_le_bytes(), addr.to_le_bytes().as_slice())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("index insert: {}", e)))?;
        indexed += 1;

        if indexed % 10000 == 0 {
            print!("\r  Indexed {} entries...", indexed);
        }
    }

    index_db.flush()?;

    println!("\n\n=== Index Rebuild Complete ===");
    println!("✓ Indexed {} keys", indexed);
    println!("✓ Skipped {} deleted keys", deleted);
    println!("\nYou can now restart the dazhbog server.");

    Ok(())
}

/// Decode binary metadata from ctx.binary_meta format
fn decode_binary_meta_basename(b: &[u8]) -> Option<String> {
    // Format: md5[16] + first_seen_ts[8] + last_seen_ts[8] + obs_count[8] + basename_len[2] + basename + ...
    if b.len() < 16 + 8 + 8 + 8 + 2 {
        return None;
    }
    let mut offset = 16 + 8 + 8 + 8; // skip md5 + timestamps + obs_count
    let basename_len = u16::from_le_bytes([b[offset], b[offset + 1]]) as usize;
    offset += 2;
    if b.len() < offset + basename_len {
        return None;
    }
    std::str::from_utf8(&b[offset..offset + basename_len])
        .ok()
        .map(|s| s.to_string())
}

/// Decode key_bins to get list of MD5s for a key
fn decode_key_bins_md5s(b: &[u8]) -> Vec<[u8; 16]> {
    if b.is_empty() {
        return Vec::new();
    }
    let count = b[0] as usize;
    let mut out = Vec::with_capacity(count);
    let mut offset = 1;
    for _ in 0..count {
        if offset + 16 + 4 > b.len() {
            break;
        }
        let mut md5 = [0u8; 16];
        md5.copy_from_slice(&b[offset..offset + 16]);
        out.push(md5);
        offset += 16 + 4; // md5 + obs_count
    }
    out
}

/// Encode basenames for ctx.key_basenames
fn encode_basenames_for_key(names: &[String]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + names.len() * 18);
    v.push(names.len().min(255) as u8);
    for name in names.iter().take(16) {
        let b = name.as_bytes();
        let len = b.len().min(u16::MAX as usize) as u16;
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&b[..len as usize]);
    }
    v
}

fn rebuild_basenames(data_dir: &PathBuf) -> io::Result<()> {
    // Server uses "index" folder, not "index_db"
    let index_dir = data_dir.join("index");

    if !index_dir.exists() {
        eprintln!("Error: {}/index directory not found.", data_dir.display());
        std::process::exit(1);
    }

    println!("=== Dazhbog Basenames Rebuild Tool ===\n");
    println!("Data directory: {}", data_dir.display());

    let db = sled::open(&index_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open: {}", e)))?;

    // Open required trees
    let key_bins = db
        .open_tree("ctx.key_bins")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open ctx.key_bins: {}", e)))?;
    let binary_meta = db.open_tree("ctx.binary_meta").map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("open ctx.binary_meta: {}", e))
    })?;
    let key_basenames = db.open_tree("ctx.key_basenames").map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("open ctx.key_basenames: {}", e),
        )
    })?;

    println!("ctx.key_bins:      {} entries", key_bins.len());
    println!("ctx.binary_meta:   {} entries", binary_meta.len());
    println!(
        "ctx.key_basenames: {} entries (before)",
        key_basenames.len()
    );

    // Build md5 -> basename lookup from binary_meta
    println!("\nBuilding MD5 -> basename lookup...");
    let mut md5_to_basename: HashMap<[u8; 16], String> = HashMap::new();
    for item in binary_meta.iter() {
        let (md5_key, meta_val) = match item {
            Ok(i) => i,
            Err(_) => continue,
        };
        if md5_key.len() != 16 {
            continue;
        }
        if let Some(basename) = decode_binary_meta_basename(&meta_val) {
            if !basename.is_empty() {
                let mut md5 = [0u8; 16];
                md5.copy_from_slice(&md5_key);
                md5_to_basename.insert(md5, basename);
            }
        }
    }
    println!("  Found {} binaries with basenames", md5_to_basename.len());

    // Iterate key_bins and populate key_basenames
    println!("\nPopulating ctx.key_basenames...");
    let mut processed = 0u64;
    let mut populated = 0u64;

    for item in key_bins.iter() {
        let (key_bytes, bins_val) = match item {
            Ok(i) => i,
            Err(_) => continue,
        };

        // Decode the MD5 list for this key
        let md5s = decode_key_bins_md5s(&bins_val);

        // Look up basenames for each MD5
        let mut basenames: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for md5 in md5s {
            if let Some(basename) = md5_to_basename.get(&md5) {
                let lower = basename.to_lowercase();
                if seen.insert(lower) && basenames.len() < 16 {
                    basenames.push(basename.clone());
                }
            }
        }

        if !basenames.is_empty() {
            let encoded = encode_basenames_for_key(&basenames);
            key_basenames
                .insert(&key_bytes, encoded)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("insert: {}", e)))?;
            populated += 1;
        }

        processed += 1;
        if processed % 100000 == 0 {
            print!(
                "\r  Processed {} keys, {} populated...",
                processed, populated
            );
        }
    }

    db.flush()?;

    println!(
        "\r  Processed {} keys, {} populated    ",
        processed, populated
    );
    println!(
        "\nctx.key_basenames: {} entries (after)",
        key_basenames.len()
    );
    println!("\n=== Basenames Rebuild Complete ===");
    println!("You can now run --rebuild-search to update the search index.");

    Ok(())
}

fn rebuild_search(data_dir: &PathBuf) -> io::Result<()> {
    let seg_db_dir = data_dir.join("segments_db");
    let search_dir = data_dir.join("search_index");
    // Server uses "index" folder, not "index_db"
    let index_dir = data_dir.join("index");

    if !seg_db_dir.exists() {
        eprintln!(
            "Error: {}/segments_db directory not found.",
            data_dir.display()
        );
        std::process::exit(1);
    }

    println!("=== Dazhbog Search Index Rebuild Tool ===\n");
    println!("Data directory: {}", data_dir.display());

    // Open index database for context (binary names are stored in ctx.key_basenames tree)
    let ctx_basenames_tree: Option<sled::Tree> = if index_dir.exists() {
        println!("Found index database at {}", index_dir.display());
        let index_db = sled::open(&index_dir)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open index: {}", e)))?;
        // Context trees use "ctx." prefix in the index database
        match index_db.open_tree("ctx.key_basenames") {
            Ok(tree) => {
                println!("  Opened ctx.key_basenames tree ({} entries)", tree.len());
                if tree.is_empty() {
                    println!(
                        "  Warning: ctx.key_basenames is empty, run --rebuild-basenames first"
                    );
                    None
                } else {
                    Some(tree)
                }
            }
            Err(e) => {
                eprintln!("  Warning: could not open ctx.key_basenames: {}", e);
                None
            }
        }
    } else {
        println!("No index database found, binary names will be empty");
        None
    };

    // Open the segments database
    let seg_db = sled::open(&seg_db_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open segments: {}", e)))?;

    // Get segment tree names
    let mut tree_names: Vec<_> = seg_db
        .tree_names()
        .into_iter()
        .map(|name| String::from_utf8_lossy(&name).to_string())
        .filter(|name| name.starts_with("seg."))
        .collect();
    tree_names.sort();

    println!("Found {} segment trees", tree_names.len());

    // Collect latest record for each key
    let mut latest_by_key: HashMap<u128, (u64, String)> = HashMap::new(); // key -> (ts, name)
    let mut total_records = 0u64;

    for name in &tree_names {
        let tree = seg_db.open_tree(name).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("open tree {}: {}", name, e))
        })?;

        println!("Scanning {} ({} records)...", name, tree.len());

        for item in tree.iter() {
            let (offset_bytes, record_bytes) = match item {
                Ok(i) => i,
                Err(_) => continue,
            };

            if record_bytes.len() < 12 {
                continue;
            }

            let hdr: &[u8] = &record_bytes[0..12];
            let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
            if magic != MAGIC {
                continue;
            }

            let stored_crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
            let body = &record_bytes[12..];

            // Verify CRC
            let computed_crc = crc32c_impl::crc32c(0, body);
            let crc_valid = if computed_crc == stored_crc {
                true
            } else {
                let computed_crc_legacy = crc32c_impl::crc32c_legacy(0, body);
                computed_crc_legacy == stored_crc
            };

            if !crc_valid || body.len() < 52 {
                continue;
            }

            // Parse key, timestamp, flags, and name
            let lo = u64::from_le_bytes(body[0..8].try_into().unwrap());
            let hi = u64::from_le_bytes(body[8..16].try_into().unwrap());
            let key = ((hi as u128) << 64) | (lo as u128);
            let ts_sec = u64::from_le_bytes(body[16..24].try_into().unwrap());
            let flags = body[46];

            // Skip deleted records
            if flags & 0x01 == 0x01 {
                continue;
            }

            let name_len = u16::from_le_bytes(body[40..42].try_into().unwrap()) as usize;
            let name_start = 52;
            if name_start + name_len > body.len() {
                continue;
            }
            let name = match std::str::from_utf8(&body[name_start..name_start + name_len]) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };

            // Keep the latest version
            match latest_by_key.get(&key) {
                Some(&(existing_ts, _)) if existing_ts >= ts_sec => {}
                _ => {
                    latest_by_key.insert(key, (ts_sec, name));
                }
            }

            total_records += 1;
        }
    }

    println!("\n=== Scan Results ===");
    println!("Total valid records: {}", total_records);
    println!("Unique keys to index: {}", latest_by_key.len());

    // Delete and recreate search index
    if search_dir.exists() {
        println!("\nRemoving old search index...");
        std::fs::remove_dir_all(&search_dir)?;
    }
    std::fs::create_dir_all(&search_dir)?;

    // Use tantivy directly for indexing
    use tantivy::schema::{IndexRecordOption, Schema, TextFieldIndexing, TextOptions, STORED};
    use tantivy::tokenizer::{LowerCaser, NgramTokenizer, RawTokenizer, TextAnalyzer};
    use tantivy::{Index, IndexWriter};

    // Build schema (must match SearchIndex::build_schema)
    let mut builder = Schema::builder();
    let ngram_indexing = TextFieldIndexing::default()
        .set_tokenizer("edge_ngram")
        .set_index_option(IndexRecordOption::WithFreqsAndPositions);
    let text_options = TextOptions::default()
        .set_indexing_options(ngram_indexing.clone())
        .set_stored();
    let key_options = TextOptions::default().set_stored().set_indexing_options(
        TextFieldIndexing::default()
            .set_tokenizer("raw")
            .set_index_option(IndexRecordOption::Basic),
    );

    let key_hex = builder.add_text_field("key_hex", key_options);
    let func_name = builder.add_text_field("func_name", text_options.clone());
    let _binary_name = builder.add_text_field("binary_name", text_options);
    let ts = builder.add_u64_field("ts", STORED);
    let schema = builder.build();

    // Create index
    let index = Index::create_in_dir(&search_dir, schema)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("create index: {}", e)))?;

    // Register tokenizers
    let edge_ngram =
        TextAnalyzer::builder(NgramTokenizer::new(2, 12, true).expect("ngram tokenizer"))
            .filter(LowerCaser)
            .build();
    let raw = TextAnalyzer::builder(RawTokenizer::default()).build();
    index.tokenizers().register("edge_ngram", edge_ngram);
    index.tokenizers().register("raw", raw);

    // Create writer
    let mut writer: IndexWriter = index
        .writer(50_000_000)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("writer: {}", e)))?;

    println!("\nIndexing {} functions...", latest_by_key.len());
    let mut indexed = 0u64;
    let mut with_basenames = 0u64;

    for (k, (ts_val, name)) in latest_by_key.iter() {
        let key_hex_str = format!("{:032x}", k);
        let mut doc = tantivy::Document::new();
        doc.add_text(key_hex, &key_hex_str);
        doc.add_text(func_name, name);
        doc.add_u64(ts, *ts_val);

        // Look up binary names from context database
        if let Some(ref tree) = ctx_basenames_tree {
            let key_bytes = k.to_le_bytes();
            if let Ok(Some(val)) = tree.get(&key_bytes) {
                if let Some(basenames) = decode_basenames(&val) {
                    if !basenames.is_empty() {
                        // Join basenames with space for search indexing
                        let binary_names_str = basenames.join(" ");
                        doc.add_text(_binary_name, &binary_names_str);
                        with_basenames += 1;
                    }
                }
            }
        }

        writer
            .add_document(doc)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("add doc: {}", e)))?;

        indexed += 1;
        if indexed % 10000 == 0 {
            print!(
                "\r  Indexed {} functions ({} with binaries)...",
                indexed, with_basenames
            );
        }
    }

    println!(
        "\r  Indexed {} functions ({} with binaries)",
        indexed, with_basenames
    );
    println!("\nCommitting...");
    writer
        .commit()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("commit: {}", e)))?;

    println!("\n=== Search Index Rebuild Complete ===");
    println!("  Indexed {} functions", indexed);
    println!("  {} functions have binary names", with_basenames);
    println!("\nYou can now restart the dazhbog server.");

    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let command = args.get(1).map(|s| s.as_str());
    let data_path = args
        .get(2)
        .map(|s| PathBuf::from(s))
        .unwrap_or_else(|| PathBuf::from("data"));

    match command {
        Some("--help") | Some("-h") => {
            print_usage();
            return Ok(());
        }
        Some("--rebuild-index") => {
            return rebuild_index(&data_path);
        }
        Some("--rebuild-search") => {
            return rebuild_search(&data_path);
        }
        Some("--rebuild-basenames") => {
            return rebuild_basenames(&data_path);
        }
        Some("--list-trees") => {
            return list_trees(&data_path);
        }
        Some("--full-recover") | None => {
            // Continue with full recovery below
        }
        Some(other) => {
            eprintln!("Unknown command: {}", other);
            print_usage();
            std::process::exit(1);
        }
    }

    // Full recovery mode
    let data_dir = data_path;
    let seg_db_dir = data_dir.join("segments_db");
    let backup_dir = PathBuf::from("data.backup");
    let temp_dir = PathBuf::from("data.recovered");

    if !seg_db_dir.exists() {
        eprintln!("Error: {}/segments_db directory not found. This tool requires the new sled-based storage.", data_dir.display());
        eprintln!(
            "If you have old seg.*.dat files, run the main dazhbog server once to migrate them."
        );
        std::process::exit(1);
    }

    println!("=== Dazhbog Segment Recovery Tool (sled-based) ===\n");

    // Scan all segment trees in the sled database
    let mut all_records: HashMap<u128, Vec<Record>> = HashMap::new();
    let mut total_valid = 0;

    let db = sled::open(&seg_db_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open: {}", e)))?;

    let mut tree_names: Vec<_> = db
        .tree_names()
        .into_iter()
        .map(|name| String::from_utf8_lossy(&name).to_string())
        .filter(|name| name.starts_with("seg."))
        .collect();

    tree_names.sort();

    for name in tree_names {
        let tree = db
            .open_tree(&name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open_tree: {}", e)))?;

        match scan_segment_tree(&tree) {
            Ok(records) => {
                total_valid += records.len();
                for (_off, rec) in records {
                    all_records
                        .entry(rec.key)
                        .or_insert_with(Vec::new)
                        .push(rec);
                }
            }
            Err(e) => {
                eprintln!("Error scanning tree {}: {}", name, e);
            }
        }
    }

    println!("\n=== Scan Results ===");
    println!("Total valid records: {}", total_valid);
    println!("Unique keys: {}", all_records.len());

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

    // Create temp directory for new sled db
    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir)?;
    }
    std::fs::create_dir_all(&temp_dir)?;

    // Write recovered records to new segment db
    println!("\n=== Writing recovered data ===");
    let recovered_db = sled::open(&temp_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open temp db: {}", e)))?;
    let recovered_tree = recovered_db
        .open_tree("seg.00001")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open temp tree: {}", e)))?;

    let mut offset = 0u64;
    for (i, rec) in final_records.iter().enumerate() {
        let len = write_record_to_tree(&recovered_tree, offset, rec)?;
        offset += len as u64;

        if (i + 1) % 1000 == 0 {
            println!("  Written {} records...", i + 1);
        }
    }

    recovered_db.flush()?;
    println!(
        "  Written {} records to new database in {}",
        final_records.len(),
        temp_dir.display()
    );
    drop(recovered_db);

    // Backup old segments
    println!("\n=== Creating backup ===");
    if backup_dir.exists() {
        std::fs::remove_dir_all(&backup_dir)?;
    }
    std::fs::create_dir_all(&backup_dir)?;
    std::fs::rename(&seg_db_dir, backup_dir.join("segments_db"))?;
    println!(
        "  Old segment database backed up to {}",
        backup_dir.join("segments_db").display()
    );

    // Move recovered segments to data directory
    std::fs::rename(&temp_dir, &seg_db_dir)?;
    println!(
        "  Recovered segment database moved to {}",
        seg_db_dir.display()
    );

    println!("\n=== Recovery Complete ===");
    println!("✓ Recovered {} unique records", final_records.len());
    println!("✓ Old segments backed up to: {}", backup_dir.display());
    println!("✓ New segments ready at: {}", data_dir.display());
    println!("\nYou can now restart the dazhbog server.");

    Ok(())
}
