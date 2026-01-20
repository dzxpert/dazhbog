use std::{
    fs::OpenOptions,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use crate::common::addr::pack_addr;
use crate::engine::crc32c::{crc32c, crc32c_legacy};

pub type Addr = u64;

const MAGIC: u32 = 0x4C4D4E31;

fn offset_key(offset: u64) -> [u8; 8] {
    offset.to_be_bytes() // big-endian for lexicographic ordering
}

#[derive(Clone)]
pub struct Record {
    pub key: u128,
    pub ts_sec: u64,
    pub prev_addr: Addr,
    pub len_bytes: u32,
    pub popularity: u32,
    pub name: String,
    pub data: Vec<u8>,
    pub flags: u8,
}

pub struct SegmentWriter {
    tree: sled::Tree,
    id: u16,
    cap: u64,
    off: u64,
}

pub struct SegmentReader {
    tree: sled::Tree,
    pub id: u16,
}

pub struct OpenSegments {
    db: sled::Db,
    pub current: std::sync::Mutex<SegmentWriter>,
    pub readers: parking_lot::Mutex<Vec<SegmentReader>>,
    #[allow(dead_code)]
    pub use_mmap: bool,
    pub seg_bytes: u64,
    /// Cached storage bytes to avoid full scan on every call
    cached_storage_bytes: std::sync::atomic::AtomicU64,
    /// Metadata tree for persistent caching
    meta: sled::Tree,
}

impl SegmentWriter {
    fn open(db: &sled::Db, id: u16, cap: u64) -> io::Result<Self> {
        let tree_name = format!("seg.{:05}", id);
        let tree = db
            .open_tree(&tree_name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open_tree: {e}")))?;

        let off = if let Some(last) = tree
            .last()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled last: {e}")))?
        {
            let (key_bytes, val) = last;
            let offset = u64::from_be_bytes(key_bytes.as_ref().try_into().unwrap());
            offset + val.len() as u64
        } else {
            0
        };

        Ok(Self { tree, id, cap, off })
    }

    pub fn append(&mut self, rec: &Record) -> io::Result<Addr> {
        if rec.name.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "record.name too long (> u16::MAX)",
            ));
        }
        if rec.len_bytes as usize != rec.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "record.len_bytes mismatch with data length",
            ));
        }

        let name_len = rec.name.len() as u16;
        let data_len = rec.data.len() as u32;

        let body_len: usize =
            8 + 8 + 8 + 8 + 4 + 4 + 2 + 4 + 1 + 5 + (name_len as usize) + (data_len as usize);
        let total_len = 4 + 4 + 4 + body_len;

        if self.off + (total_len as u64) > self.cap {
            return Err(io::Error::new(io::ErrorKind::Other, "segment full"));
        }

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
        buf.extend_from_slice(&(name_len).to_le_bytes());
        buf.extend_from_slice(&(data_len).to_le_bytes());
        buf.push(rec.flags);
        buf.extend_from_slice(&[0u8; 5]);
        buf.extend_from_slice(rec.name.as_bytes());
        buf.extend_from_slice(&rec.data);

        let crc = crc32c(0, &buf[12..]);
        if self.off == 0 {
            eprintln!(
                "DEBUG: First write - CRC computed: 0x{:08x}, body_len: {}",
                crc,
                buf[12..].len()
            );
        }
        buf[8..12].copy_from_slice(&crc.to_le_bytes());

        let offset = self.off;
        self.tree
            .insert(offset_key(offset), buf.as_slice())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;
        self.off += buf.len() as u64;
        Ok(pack_addr(self.id, offset, rec.flags))
    }
}

impl Clone for SegmentReader {
    fn clone(&self) -> Self {
        Self {
            tree: self.tree.clone(),
            id: self.id,
        }
    }
}

impl SegmentReader {
    fn open(db: &sled::Db, id: u16) -> io::Result<Self> {
        let tree_name = format!("seg.{:05}", id);
        let tree = db
            .open_tree(&tree_name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open_tree: {e}")))?;
        Ok(Self { tree, id })
    }

    pub fn read_at(&self, offset: u64) -> io::Result<Record> {
        let data = self
            .tree
            .get(offset_key(offset))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled get: {e}")))?;
        let data =
            data.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "record not found"))?;

        if data.len() < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "record too short",
            ));
        }

        let hdr = &data[0..12];
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        if magic != MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
        }
        let _rec_len = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        let crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        let body = &data[12..];

        let crc2 = crc32c(0, body);
        if crc != crc2 {
            let crc2_legacy = crc32c_legacy(0, body);
            if crc != crc2_legacy {
                if offset < 500 {
                    eprintln!("DEBUG READ: offset={}, stored_crc=0x{:08x}, computed_crc=0x{:08x}, legacy_crc=0x{:08x}, body_len={}",
                              offset, crc, crc2, crc2_legacy, body.len());
                }
                return Err(io::Error::new(io::ErrorKind::InvalidData, "crc mismatch"));
            }
        }

        let lo = u64::from_le_bytes(body[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(body[8..16].try_into().unwrap());
        let key = ((hi as u128) << 64) | (lo as u128);
        let ts_sec = u64::from_le_bytes(body[16..24].try_into().unwrap());
        let prev_addr = u64::from_le_bytes(body[24..32].try_into().unwrap());
        let len_bytes = u32::from_le_bytes(body[32..36].try_into().unwrap());
        let popularity = u32::from_le_bytes(body[36..40].try_into().unwrap());
        let name_len = u16::from_le_bytes(body[40..42].try_into().unwrap()) as usize;
        let data_len = u32::from_le_bytes(body[42..46].try_into().unwrap()) as usize;
        let flags = body[46];
        let name_start = 52;
        let name = std::str::from_utf8(&body[name_start..name_start + name_len])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "utf8"))?
            .to_string();
        let data_start = name_start + name_len;
        let data = body[data_start..data_start + data_len].to_vec();

        let actual_len_bytes = if data_len != len_bytes as usize {
            data_len as u32
        } else {
            len_bytes
        };

        Ok(Record {
            key,
            ts_sec,
            prev_addr,
            len_bytes: actual_len_bytes,
            popularity,
            name,
            data,
            flags,
        })
    }
}

struct ProgressReporter {
    total_size: u64,
    processed_size: u64,
    last_progress: u8,
}

impl ProgressReporter {
    fn new(total_size: u64) -> Self {
        Self {
            total_size,
            processed_size: 0,
            last_progress: 0,
        }
    }

    fn update(&mut self, bytes: u64, operation: &str) {
        if self.total_size == 0 {
            return;
        }

        self.processed_size += bytes;
        let progress = ((self.processed_size as f64 / self.total_size as f64) * 100.0) as u8;
        if progress >= self.last_progress + 10 && progress <= 100 {
            log::info!("{}: {}%", operation, progress);
            self.last_progress = progress;
        }
    }
}

#[allow(dead_code)]
enum ScanAction {
    Continue,
    Break,
}

fn migrate_dat_files_to_sled(dat_files: &[PathBuf], db: &sled::Db, _dir: &Path) -> io::Result<()> {
    for path in dat_files {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid file name"))?;

        let mid = &file_name[4..9];
        let seg_id = mid.parse::<u16>().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("parse segment id: {e}"),
            )
        })?;

        log::info!("Migrating segment {} from {}", seg_id, file_name);

        let mut file = OpenOptions::new().read(true).open(path)?;
        let file_len = file.metadata()?.len();

        let tree_name = format!("seg.{:05}", seg_id);
        let tree = db
            .open_tree(&tree_name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open_tree: {e}")))?;

        let mut offset = 0u64;
        let mut record_count = 0u64;

        while offset + 12 < file_len {
            let mut hdr = [0u8; 12];
            if file.seek(SeekFrom::Start(offset)).is_err() {
                break;
            }
            if file.read_exact(&mut hdr).is_err() {
                break;
            }

            let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
            if magic != MAGIC {
                log::warn!("Skipping invalid record at offset {} (bad magic)", offset);
                break;
            }

            let rec_len = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as u64;
            if rec_len == 0 || offset + rec_len > file_len {
                break;
            }

            let mut record_data = vec![0u8; rec_len as usize];
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut record_data)?;

            tree.insert(offset_key(offset), record_data.as_slice())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;

            offset += rec_len;
            record_count += 1;
        }

        log::info!("Migrated {} records from segment {}", record_count, seg_id);

        let migrated_path = path.with_extension("dat.migrated");
        std::fs::rename(path, &migrated_path)?;
        log::info!(
            "Renamed {} to {}",
            file_name,
            migrated_path.file_name().unwrap().to_string_lossy()
        );
    }

    Ok(())
}

impl OpenSegments {
    fn total_segment_size(&self, readers: &[SegmentReader]) -> u64 {
        readers
            .iter()
            .map(|r| {
                r.tree
                    .iter()
                    .filter_map(|res| res.ok())
                    .map(|(_, v)| v.len() as u64)
                    .sum::<u64>()
            })
            .sum()
    }

    #[allow(dead_code)]
    fn scan_records<F>(&self, readers: &[SegmentReader], mut callback: F) -> io::Result<u64>
    where
        F: FnMut(&SegmentReader, u64, u64, u128, u8) -> io::Result<ScanAction>,
    {
        const MIN_STRUCTURED_SIZE: u64 = 12 + 16 + 8 + 8 + 4 + 4 + 2 + 4 + 1;
        let mut total_processed = 0u64;

        for r in readers.iter() {
            for item in r.tree.iter() {
                let (key_bytes, data) = item
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled iter: {e}")))?;

                let offset = u64::from_be_bytes(key_bytes.as_ref().try_into().unwrap());
                let rec_len = data.len() as u64;

                if rec_len < 12 {
                    log::warn!("Skipping short record at seg={}, offset={}", r.id, offset);
                    continue;
                }

                let hdr = &data[0..12];
                let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
                if magic != MAGIC {
                    log::warn!(
                        "Skipping record with bad magic at seg={}, offset={}",
                        r.id,
                        offset
                    );
                    continue;
                }

                if rec_len < MIN_STRUCTURED_SIZE {
                    log::warn!(
                        "Skipping malformed record at seg={}, offset={}: rec_len {} < minimum {}",
                        r.id,
                        offset,
                        rec_len,
                        MIN_STRUCTURED_SIZE
                    );
                    total_processed += rec_len;
                    continue;
                }

                let stored_crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
                let body = &data[12..];

                if body.len() < 16 + 8 + 8 + 8 + 4 + 4 + 2 + 4 + 1 {
                    log::warn!(
                        "Skipping record with short body at seg={}, offset={}",
                        r.id,
                        offset
                    );
                    total_processed += rec_len;
                    continue;
                }

                let keybuf = &body[0..16];
                let lo = u64::from_le_bytes(keybuf[0..8].try_into().unwrap());
                let hi = u64::from_le_bytes(keybuf[8..16].try_into().unwrap());
                let key = ((hi as u128) << 64) | (lo as u128);
                let flags = body[8 + 8 + 8 + 8 + 4 + 4 + 2 + 4];

                let computed_crc = crc32c(0, body);
                let crc_valid = if computed_crc == stored_crc {
                    true
                } else {
                    let computed_crc_legacy = crc32c_legacy(0, body);
                    computed_crc_legacy == stored_crc
                };

                if !crc_valid {
                    log::warn!("Skipping corrupt record at seg={}, offset={}, key={:032x}: CRC mismatch (stored={:#x}, computed={:#x})", r.id, offset, key, stored_crc, computed_crc);
                    total_processed += rec_len;
                    continue;
                }

                match callback(r, offset, rec_len, key, flags)? {
                    ScanAction::Continue => {}
                    ScanAction::Break => return Ok(total_processed),
                }

                total_processed += rec_len;
            }
        }

        Ok(total_processed)
    }

    pub fn open(dir: &Path, seg_bytes: u64, use_mmap: bool) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;

        let seg_db_dir = dir.join("segments_db");
        std::fs::create_dir_all(&seg_db_dir)?;

        let db = sled::Config::default()
            .path(&seg_db_dir)
            .cache_capacity(128 * 1024 * 1024)
            .flush_every_ms(Some(500))
            .open()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open: {e}")))?;

        let migration_marker = dir.join(".sled_migrated");
        let needs_migration = !migration_marker.exists();

        let mut dat_files = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("seg.") && name.ends_with(".dat") {
                    dat_files.push(entry.path());
                }
            }
        }

        if needs_migration && !dat_files.is_empty() {
            log::info!(
                "Migrating {} segment files to sled database...",
                dat_files.len()
            );
            migrate_dat_files_to_sled(&dat_files, &db, dir)?;
            std::fs::write(&migration_marker, b"migrated")?;
            log::info!("Migration complete");
        }

        let mut max_id = None;
        for name in db.tree_names() {
            let name_str = String::from_utf8_lossy(&name);
            if name_str.starts_with("seg.") {
                let mid = &name_str[4..9];
                if let Ok(id) = mid.parse::<u16>() {
                    max_id = Some(max_id.map_or(id, |m: u16| m.max(id)));
                }
            }
        }

        let id = max_id.unwrap_or(1u16);
        let writer = SegmentWriter::open(&db, id, seg_bytes)?;
        let mut readers = Vec::new();
        for sid in 1..=id {
            readers.push(SegmentReader::open(&db, sid)?);
        }

        // Open metadata tree for caching
        let meta = db
            .open_tree("__meta")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open __meta: {e}")))?;

        // Load cached storage bytes or compute if missing
        let cached_storage_bytes = if let Some(val) = meta
            .get(b"storage_bytes")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled get: {e}")))?
        {
            let bytes: [u8; 8] = val.as_ref().try_into().unwrap_or([0u8; 8]);
            std::sync::atomic::AtomicU64::new(u64::from_le_bytes(bytes))
        } else {
            // First time or cache missing - compute and store
            log::info!("Computing storage bytes (first startup or cache missing)...");
            let total: u64 = readers
                .iter()
                .map(|r| {
                    r.tree
                        .iter()
                        .filter_map(|res| res.ok())
                        .map(|(_, v)| v.len() as u64)
                        .sum::<u64>()
                })
                .sum();
            meta.insert(b"storage_bytes", &total.to_le_bytes())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;
            log::info!("Cached storage bytes: {} MB", total / 1_048_576);
            std::sync::atomic::AtomicU64::new(total)
        };

        Ok(Self {
            db,
            current: std::sync::Mutex::new(writer),
            readers: parking_lot::Mutex::new(readers),
            use_mmap,
            seg_bytes,
            cached_storage_bytes,
            meta,
        })
    }

    pub fn next_writer(&self) -> io::Result<()> {
        let mut w = self.current.lock().unwrap();
        let new_id =
            w.id.checked_add(1)
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "segment id overflow"))?;
        let nw = SegmentWriter::open(&self.db, new_id, self.seg_bytes)?;
        {
            let mut r = self.readers.lock();
            r.push(SegmentReader::open(&self.db, new_id)?);
        }
        *w = nw;
        Ok(())
    }

    pub fn get_reader(&self, seg_id: u16) -> Option<SegmentReader> {
        let rs = self.readers.lock();
        rs.iter().find(|r| r.id == seg_id).cloned()
    }

    pub fn append(&self, rec: &Record) -> io::Result<Addr> {
        let mut writer = self.current.lock().unwrap();
        let result = match writer.append(rec) {
            Ok(addr) => Ok(addr),
            Err(e)
                if e.kind() == io::ErrorKind::Other && e.to_string().contains("segment full") =>
            {
                drop(writer);
                self.next_writer()?;
                let mut writer = self.current.lock().unwrap();
                writer.append(rec)
            }
            Err(e) => Err(e),
        };

        // Update cached storage bytes on successful append
        if result.is_ok() {
            let name_len = rec.name.len() as u16;
            let data_len = rec.data.len() as u32;
            let body_len: u64 =
                8 + 8 + 8 + 8 + 4 + 4 + 2 + 4 + 1 + 5 + (name_len as u64) + (data_len as u64);
            let total_len = 4 + 4 + 4 + body_len;
            let new_total = self
                .cached_storage_bytes
                .fetch_add(total_len, std::sync::atomic::Ordering::Relaxed)
                + total_len;
            // Persist periodically (every ~10MB)
            if new_total % (10 * 1024 * 1024) < total_len {
                let _ = self.meta.insert(b"storage_bytes", &new_total.to_le_bytes());
            }
        }

        result
    }

    pub fn rebuild_index(&self, index: &crate::engine::index::ShardedIndex) -> io::Result<()> {
        let rs = self.readers.lock();
        let total_size = self.total_segment_size(&rs);

        if total_size > 0 {
            log::info!(
                "Loading segments: {:.2} MB total",
                total_size as f64 / 1_048_576.0
            );
        }

        let mut progress = ProgressReporter::new(total_size);
        let mut corrupt_count = 0u64;

        self.scan_records_with_corruption(&rs, |r, off, rec_len, key, flags, is_corrupt| {
            if is_corrupt {
                index.delete(key);
                corrupt_count += 1;
            } else {
                let addr = pack_addr(r.id, off, flags);
                if flags & 0x01 == 0x01 {
                    index.delete(key);
                } else {
                    if let Err(_) = index.upsert(key, addr) {
                        log::warn!("Index full during rebuild for key {:032x}", key);
                    }
                }
            }

            progress.update(rec_len, "Loading segments");
            Ok(ScanAction::Continue)
        })?;

        if total_size > 0 {
            if corrupt_count > 0 {
                log::info!(
                    "Segments loaded successfully ({} corrupt entries skipped)",
                    corrupt_count
                );
            } else {
                log::info!("Segments loaded successfully");
            }
        }

        Ok(())
    }

    /// Iterate over all records in all segment trees, invoking the callback for each decoded record.
    /// Corrupt or unreadable records are skipped.
    pub fn for_each_record<F>(&self, mut callback: F) -> io::Result<()>
    where
        F: FnMut(u16, u64, &Record) -> io::Result<()>,
    {
        let rs = self.readers.lock();
        for r in rs.iter() {
            for item in r.tree.iter() {
                let (key_bytes, _data) = match item {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let offset = u64::from_be_bytes(key_bytes.as_ref().try_into().unwrap());
                match r.read_at(offset) {
                    Ok(rec) => {
                        callback(r.id, offset, &rec)?;
                    }
                    Err(_) => continue,
                }
            }
        }
        Ok(())
    }

    fn scan_records_with_corruption<F>(
        &self,
        readers: &[SegmentReader],
        mut callback: F,
    ) -> io::Result<u64>
    where
        F: FnMut(&SegmentReader, u64, u64, u128, u8, bool) -> io::Result<ScanAction>,
    {
        const MIN_STRUCTURED_SIZE: u64 = 12 + 16 + 8 + 8 + 4 + 4 + 2 + 4 + 1;
        let mut total_processed = 0u64;

        for r in readers.iter() {
            for item in r.tree.iter() {
                let (key_bytes, data) = item
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled iter: {e}")))?;

                let offset = u64::from_be_bytes(key_bytes.as_ref().try_into().unwrap());
                let rec_len = data.len() as u64;

                if rec_len < 12 {
                    log::warn!("Skipping short record at seg={}, offset={}", r.id, offset);
                    continue;
                }

                let hdr = &data[0..12];
                let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
                if magic != MAGIC {
                    log::warn!(
                        "Skipping record with bad magic at seg={}, offset={}",
                        r.id,
                        offset
                    );
                    continue;
                }

                if rec_len < MIN_STRUCTURED_SIZE {
                    log::warn!(
                        "Skipping malformed record at seg={}, offset={}: rec_len {} < minimum {}",
                        r.id,
                        offset,
                        rec_len,
                        MIN_STRUCTURED_SIZE
                    );
                    total_processed += rec_len;
                    continue;
                }

                let stored_crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
                let body = &data[12..];

                if body.len() < 16 + 8 + 8 + 8 + 4 + 4 + 2 + 4 + 1 {
                    log::warn!(
                        "Skipping record with short body at seg={}, offset={}",
                        r.id,
                        offset
                    );
                    total_processed += rec_len;
                    continue;
                }

                let keybuf = &body[0..16];
                let lo = u64::from_le_bytes(keybuf[0..8].try_into().unwrap());
                let hi = u64::from_le_bytes(keybuf[8..16].try_into().unwrap());
                let key = ((hi as u128) << 64) | (lo as u128);
                let flags = body[8 + 8 + 8 + 8 + 4 + 4 + 2 + 4];

                let computed_crc = crc32c(0, body);
                let crc_valid = if computed_crc == stored_crc {
                    true
                } else {
                    let computed_crc_legacy = crc32c_legacy(0, body);
                    computed_crc_legacy == stored_crc
                };

                let is_corrupt = !crc_valid;
                if is_corrupt {
                    log::warn!("Corrupt record at seg={}, offset={}, key={:032x}: CRC mismatch (stored={:#x}, computed={:#x})", r.id, offset, key, stored_crc, computed_crc);
                }

                match callback(r, offset, rec_len, key, flags, is_corrupt)? {
                    ScanAction::Continue => {}
                    ScanAction::Break => return Ok(total_processed),
                }

                total_processed += rec_len;
            }
        }

        Ok(total_processed)
    }

    #[allow(dead_code)]
    pub fn deduplicate(&self) -> io::Result<(u64, u64, u64)> {
        use std::collections::HashMap;

        log::info!("Starting deduplication...");

        let rs = self.readers.lock();
        let total_size = self.total_segment_size(&rs);

        log::info!(
            "Scanning {:.2} MB for duplicates...",
            total_size as f64 / 1_048_576.0
        );

        let mut key_records: HashMap<u128, Vec<(Addr, u64, String, Vec<u8>, u64)>> = HashMap::new();
        let mut total_records = 0u64;
        let mut total_bytes = 0u64;
        let mut progress = ProgressReporter::new(total_size);

        self.scan_records(&rs, |r, off, rec_len, _key, flags| {
            if flags & 0x01 == 0 {
                if let Ok(rec) = r.read_at(off) {
                    let addr = pack_addr(r.id, off, rec.flags);
                    key_records
                        .entry(rec.key)
                        .or_insert_with(Vec::new)
                        .push((addr, rec.ts_sec, rec.name, rec.data, rec_len));
                    total_records += 1;
                    total_bytes += rec_len;
                }
            }

            progress.update(rec_len, "Scanning");
            Ok(ScanAction::Continue)
        })?;

        drop(rs);

        log::info!(
            "Found {} total records across {} unique keys",
            total_records,
            key_records.len()
        );

        let mut keep_addrs = std::collections::HashSet::new();
        let mut duplicates = 0u64;

        for (_key, records) in key_records.iter_mut() {
            if records.len() <= 1 {
                if let Some((addr, _, _, _, _)) = records.first() {
                    keep_addrs.insert(*addr);
                }
                continue;
            }

            records.sort_by(|a, b| b.1.cmp(&a.1));

            let mut seen = std::collections::HashSet::new();
            for (addr, _ts, name, data, _len) in records.iter() {
                let signature = (name.as_str(), data.as_slice());
                if seen.insert(signature) {
                    keep_addrs.insert(*addr);
                } else {
                    duplicates += 1;
                }
            }
        }

        let records_to_keep = keep_addrs.len() as u64;
        log::info!(
            "Keeping {} unique records, removing {} duplicates",
            records_to_keep,
            duplicates
        );

        if duplicates == 0 {
            log::info!("No duplicates found, skipping rewrite");
            return Ok((total_records, total_records, 0));
        }

        log::info!("Writing deduplicated segments...");

        let temp_dir = PathBuf::from(".dedup_temp");
        if temp_dir.exists() {
            std::fs::remove_dir_all(&temp_dir)?;
        }
        std::fs::create_dir_all(&temp_dir)?;

        let temp_db = sled::Config::default()
            .path(&temp_dir)
            .cache_capacity(128 * 1024 * 1024)
            .open()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open: {e}")))?;

        let mut new_writer = SegmentWriter::open(&temp_db, 1, self.seg_bytes)?;
        let mut written_records = 0u64;
        let mut written_bytes = 0u64;
        let mut write_progress = ProgressReporter::new(records_to_keep * 100);

        let rs = self.readers.lock();
        self.scan_records(&rs, |r, off, rec_len, _key, _flags| {
            let addr = pack_addr(r.id, off, 0);

            if keep_addrs.contains(&addr) {
                if let Ok(rec) = r.read_at(off) {
                    let new_rec = Record {
                        key: rec.key,
                        ts_sec: rec.ts_sec,
                        prev_addr: 0,
                        len_bytes: rec.len_bytes,
                        popularity: rec.popularity,
                        name: rec.name,
                        data: rec.data,
                        flags: rec.flags,
                    };
                    new_writer.append(&new_rec)?;
                    written_records += 1;
                    written_bytes += rec_len;
                    write_progress.update(100, "Writing");
                }
            }

            Ok(ScanAction::Continue)
        })?;
        drop(rs);
        drop(new_writer);
        drop(temp_db);

        log::info!("Replacing segments...");

        {
            let mut rs = self.readers.lock();
            rs.clear();
        }

        let seg_db_dir = PathBuf::from("data/segments_db");
        if seg_db_dir.exists() {
            std::fs::remove_dir_all(&seg_db_dir)?;
        }

        std::fs::rename(&temp_dir, &seg_db_dir)?;

        let new_db = sled::Config::default()
            .path(&seg_db_dir)
            .cache_capacity(128 * 1024 * 1024)
            .flush_every_ms(Some(500))
            .open()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open: {e}")))?;

        {
            let mut rs = self.readers.lock();
            rs.push(SegmentReader::open(&new_db, 1)?);
        }

        {
            let mut w = self.current.lock().unwrap();
            *w = SegmentWriter::open(&new_db, 1, self.seg_bytes)?;
        }

        log::warn!("Deduplication complete, but database reference not updated. Please restart the application.");

        let bytes_saved = total_bytes - written_bytes;
        log::info!(
            "Deduplication complete: {} -> {} records, saved {:.2} MB ({:.1}%)",
            total_records,
            written_records,
            bytes_saved as f64 / 1_048_576.0,
            (bytes_saved as f64 / total_bytes as f64) * 100.0
        );

        Ok((total_records, written_records, bytes_saved))
    }

    /// Get total storage bytes used by all segments (cached).
    pub fn get_storage_bytes(&self) -> u64 {
        self.cached_storage_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get total record count across all segments.
    pub fn get_record_count(&self) -> u64 {
        let rs = self.readers.lock();
        rs.iter().map(|r| r.tree.len() as u64).sum()
    }

    /// Get number of segments.
    pub fn get_segment_count(&self) -> u16 {
        let rs = self.readers.lock();
        rs.len() as u16
    }

    /// Get reference to the sled database.
    pub fn sled_db(&self) -> &sled::Db {
        &self.db
    }
}
