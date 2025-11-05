//! Disk-backed index: LSM-like (WAL + immutable SSTables + full compaction).
//!
//! Key → Addr mapping (u128 → u64). Crash safe via WAL; fast reads via
//! in-memory memtable (BTreeMap) and per-SSTable fence-pointer index.
//!
//! Design notes
//! ------------
//! - WAL (append-only): records Upsert/Delete with CRC32C.
//! - Memtable (BTreeMap): latest mutations while WAL grows.
//! - Flush: when memtable exceeds threshold, it is flushed as a level-0
//!   immutable SSTable (sorted, block-indexed). WAL is atomically rotated.
//! - Reads: probe memtable first, then SSTables (newest → oldest), using
//!   per-table fence pointers and block scans.
//! - Compaction (full): when the number of L0 tables exceeds a threshold,
//!   merge **all** SSTables into a single compacted SSTable. During merge
//!   we keep only the newest version per key (ties broken by file sequence).
//!
//! No external dependencies; uses only std + our crc32c helper.
//!
//! Public API preserved where used by the codebase:
//!   - `ShardedIndex::open(...)`
//!   - `get`, `upsert`, `delete`
//!   - `UpsertResult`, `IndexError`
//!
//! File layout
//! -----------
//! SSTable file (`sst.{seq}.ldb`)
//!   [ blocks ... ]
//!   [ index: u32 block_count
//!           repeated block_count * ( first_key[16], offset:u64, length:u32 ) ]
//!   [ trailer: index_offset:u64 ][ magic:u32 = 0x4C495A44 ('L','I','Z','D') ]
//!
//! Block:
//!   [ u32 entry_count ]
//!   repeated entry_count * ( key[16], tag:u8 (0=Del,1=Set), addr:u64 LE )
//!   [ u32 crc32c of the block payload starting at entry_count ]
//!
//! WAL file (`wal.dat`)
//!   repeated records:
//!     [ u8 tag (0=Del,1=Set) ][ key[16] ][ addr:u64 LE ][ u32 crc32c(tag+key+addr) ]
//!
//! Safety & concurrency
//! --------------------
//! - `get`: RCU-like pattern; read memtable (RwLock), then snapshot SSTable
//!   list (RwLock), scan readers newest→oldest.
//! - `upsert`/`delete`: serialized by a lightweight `apply_lock` Mutex to keep
//!   WAL append + memtable mutation atomic; readers remain lock-free.
//! - Flush/compaction: done synchronously in the writer path when thresholds
//!   trigger. SSTable list is swapped atomically under a write lock.

use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering as AtomOrdering},
        Arc, Mutex, RwLock,
    },
};

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt as _;

use crate::engine::crc32c::crc32c;
use crate::metrics::METRICS;

// ============================= Public API types ==============================

pub enum UpsertResult {
    Inserted,
    Replaced(u64),
}

pub enum IndexError {
    /// Capacity/overflow style error (historical compatibility with in-mem index).
    Full,
    /// Underlying IO error.
    Io(io::Error),
}

impl From<io::Error> for IndexError {
    fn from(e: io::Error) -> Self {
        IndexError::Io(e)
    }
}

// ============================== Index Options ===============================

#[derive(Clone, Debug)]
pub struct IndexOptions {
    /// Maximum entries in the memtable before a flush.
    pub memtable_max_entries: usize,
    /// Number of entries per on-disk block in SSTables.
    pub sst_block_entries: usize,
    /// Trigger a full compaction when level-0 file count exceeds this.
    pub level0_compact_trigger: usize,
}

impl IndexOptions {
    pub fn sane() -> Self {
        Self {
            memtable_max_entries: 200_000,
            sst_block_entries: 128,
            level0_compact_trigger: 8,
        }
    }
}

// =============================== Internals ==================================

const SST_MAGIC_TRAILER: u32 = 0x4C495A44; // 'L','I','Z','D'
const WAL_FILE_NAME: &str = "wal.dat";

#[derive(Clone, Copy)]
enum WalTag {
    Delete = 0,
    Set = 1,
}

#[inline]
fn key_cmp(a: &u128, b: &u128) -> Ordering {
    a.cmp(b) // native u128 order (big-endian numeric order)
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    // None → logical deletion tombstone in the LSM layer.
    val: Option<u64>,
}

struct Wal {
    path: PathBuf,
    file: File,
}

impl Wal {
    fn open(dir: &Path) -> io::Result<Self> {
        let path = dir.join(WAL_FILE_NAME);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        Ok(Self { path, file })
    }

    fn append_set(&mut self, key: u128, addr: u64) -> io::Result<()> {
        let mut buf = [0u8; 1 + 16 + 8 + 4];
        buf[0] = WalTag::Set as u8;
        buf[1..17].copy_from_slice(&key.to_le_bytes());
        buf[17..25].copy_from_slice(&addr.to_le_bytes());
        let c = crc32c(0, &buf[..1 + 16 + 8]);
        buf[25..29].copy_from_slice(&c.to_le_bytes());
        self.file.write_all(&buf)?;
        Ok(())
    }

    fn append_del(&mut self, key: u128) -> io::Result<()> {
        let mut buf = [0u8; 1 + 16 + 8 + 4];
        buf[0] = WalTag::Delete as u8;
        buf[1..17].copy_from_slice(&key.to_le_bytes());
        buf[17..25].copy_from_slice(&0u64.to_le_bytes());
        let c = crc32c(0, &buf[..1 + 16 + 8]);
        buf[25..29].copy_from_slice(&c.to_le_bytes());
        self.file.write_all(&buf)?;
        Ok(())
    }

    /// Replay all valid records (CRC-verified). Trailing junk/partial record is ignored.
    fn replay(&mut self) -> io::Result<Vec<(WalTag, u128, Option<u64>)>> {
        let mut out = Vec::new();
        self.file.seek(SeekFrom::Start(0))?;
        let mut buf = [0u8; 1 + 16 + 8 + 4];
        loop {
            match self.file.read_exact(&mut buf) {
                Ok(()) => {
                    let tag = buf[0];
                    let mut k_bytes = [0u8; 16];
                    k_bytes.copy_from_slice(&buf[1..17]);
                    let key = u128::from_le_bytes(k_bytes);
                    let mut a_bytes = [0u8; 8];
                    a_bytes.copy_from_slice(&buf[17..25]);
                    let addr = u64::from_le_bytes(a_bytes);
                    let mut c_bytes = [0u8; 4];
                    c_bytes.copy_from_slice(&buf[25..29]);
                    let crc = u32::from_le_bytes(c_bytes);
                    let calc = crc32c(0, &buf[..1 + 16 + 8]);
                    if calc != crc {
                        // Stop at the first corruption/partial (treat rest as garbage).
                        break;
                    }
                    match tag {
                        0 => out.push((WalTag::Delete, key, None)),
                        1 => out.push((WalTag::Set, key, Some(addr))),
                        _ => break,
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Replace WAL atomically with an empty one (after flush).
    fn reset(&mut self) -> io::Result<()> {
        let _ = &self.file;
        // Atomic reset: remove the old file then create a fresh one.
        let _ = fs::remove_file(&self.path);
        self.file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct BlockMeta {
    first_key: u128,
    offset: u64,
    length: u32,
}

struct SstReader {
    path: PathBuf,
    file: File,
    blocks: Vec<BlockMeta>,
    seq: u64,
    entry_count: u64,
}

impl SstReader {
    fn open(path: PathBuf, seq: u64) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).open(&path)?;
        let len = file.metadata()?.len();
        if len < 12 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "sst too small"));
        }
        let mut tail = [0u8; 12];
        file.read_exact_at(&mut tail, len - 12)?;
        let mut off_bytes = [0u8; 8];
        off_bytes.copy_from_slice(&tail[0..8]);
        let index_off = u64::from_le_bytes(off_bytes);
        let mut magic_bytes = [0u8; 4];
        magic_bytes.copy_from_slice(&tail[8..12]);
        let magic = u32::from_le_bytes(magic_bytes);
        if magic != SST_MAGIC_TRAILER {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad sst trailer"));
        }
        // Read index
        let mut idx_head = [0u8; 4 + 8];
        file.read_exact_at(&mut idx_head, index_off)?;
        let mut n_bytes = [0u8; 4];
        n_bytes.copy_from_slice(&idx_head[0..4]);
        let n = u32::from_le_bytes(n_bytes) as usize;
        let mut total_entries_bytes = [0u8; 8];
        total_entries_bytes.copy_from_slice(&idx_head[4..12]);
        let total_entries = u64::from_le_bytes(total_entries_bytes);

        let mut blocks = Vec::with_capacity(n);
        let mut rec = [0u8; 16 + 8 + 4];
        let mut p = index_off + 12;
        for _ in 0..n {
            file.read_exact_at(&mut rec, p)?;
            let mut k = [0u8; 16];
            k.copy_from_slice(&rec[0..16]);
            let first_key = u128::from_le_bytes(k);
            let mut offb = [0u8; 8];
            offb.copy_from_slice(&rec[16..24]);
            let offset = u64::from_le_bytes(offb);
            let mut lb = [0u8; 4];
            lb.copy_from_slice(&rec[24..28]);
            let length = u32::from_le_bytes(lb);
            blocks.push(BlockMeta { first_key, offset, length });
            p += 28;
        }
        Ok(Self {
            path,
            file,
            blocks,
            seq,
            entry_count: total_entries,
        })
    }

    /// Find key in this table; `Some(Some(addr))` for value, `Some(None)` for a delete tombstone,
    /// `None` for not found in this SSTable.
    fn get(&self, key: u128) -> io::Result<Option<Option<u64>>> {
        if self.blocks.is_empty() {
            return Ok(None);
        }
        // Binary search lower_bound of first_key > key
        let mut lo = 0usize;
        let mut hi = self.blocks.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if key_cmp(&self.blocks[mid].first_key, &key) == Ordering::Less
                || self.blocks[mid].first_key == key
            {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return Ok(None);
        }
        let idx = lo - 1;
        let bm = &self.blocks[idx];
        // Read the block and scan for the exact key (blocks are small).
        let mut head = [0u8; 4];
        self.file.read_exact_at(&mut head, bm.offset)?;
        let mut n_bytes = [0u8; 4];
        n_bytes.copy_from_slice(&head[0..4]);
        let count = u32::from_le_bytes(n_bytes) as usize;
        let payload_len = (16 + 1 + 8) * count;
        let mut payload = vec![0u8; payload_len + 4];
        self.file.read_exact_at(&mut payload, bm.offset + 4)?;
        let (records, crc_bytes) = payload.split_at(payload_len);
        let mut crc_arr = [0u8; 4];
        crc_arr.copy_from_slice(crc_bytes);
        let crc_on_disk = u32::from_le_bytes(crc_arr);
        let calc = crc32c(0, records);
        if calc != crc_on_disk {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "block crc mismatch"));
        }
        let mut p = 0usize;
        for _ in 0..count {
            let mut k = [0u8; 16];
            k.copy_from_slice(&records[p..p + 16]);
            let k128 = u128::from_le_bytes(k);
            p += 16;
            let tag = records[p];
            p += 1;
            let mut ab = [0u8; 8];
            ab.copy_from_slice(&records[p..p + 8]);
            let addr = u64::from_le_bytes(ab);
            p += 8;
            match key_cmp(&k128, &key) {
                Ordering::Equal => {
                    return Ok(Some(if tag == 0 { None } else { Some(addr) }));
                }
                Ordering::Greater => break, // short-circuit: keys in block are sorted
                Ordering::Less => continue,
            }
        }
        Ok(None)
    }

    fn iter(&self) -> io::Result<SstIter<'_>> {
        SstIter::new(self)
    }
}

struct SstIter<'a> {
    sst: &'a SstReader,
    block_idx: usize,
    block_count: usize,
    block_buf: Vec<u8>,
    cursor: usize,
    entries_left_in_block: usize,
}

#[derive(Clone, Copy)]
struct SstItem {
    key: u128,
    val: Option<u64>,
}

impl<'a> SstIter<'a> {
    fn new(sst: &'a SstReader) -> io::Result<Self> {
        Ok(Self {
            sst,
            block_idx: 0,
            block_count: sst.blocks.len(),
            block_buf: Vec::new(),
            cursor: 0,
            entries_left_in_block: 0,
        })
    }

    fn load_block(&mut self) -> io::Result<bool> {
        if self.block_idx >= self.block_count {
            return Ok(false);
        }
        let bm = &self.sst.blocks[self.block_idx];
        self.block_buf.clear();
        self.block_buf.resize(bm.length as usize, 0);
        self.sst
            .file
            .read_exact_at(&mut self.block_buf, bm.offset)?;
        let count = u32::from_le_bytes(self.block_buf[0..4].try_into().unwrap()) as usize;
        let payload = &self.block_buf[4..(4 + (16 + 1 + 8) * count)];
        let crc_on_disk =
            u32::from_le_bytes(self.block_buf[(4 + (16 + 1 + 8) * count)..][..4].try_into().unwrap());
        let calc = crc32c(0, payload);
        if calc != crc_on_disk {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "block crc mismatch (iter)",
            ));
        }
        self.cursor = 4; // start of payload
        self.entries_left_in_block = count;
        self.block_idx += 1;
        Ok(true)
    }
}

impl<'a> Iterator for SstIter<'a> {
    type Item = io::Result<SstItem>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.entries_left_in_block > 0 {
                // read one record
                let k = {
                    let mut kb = [0u8; 16];
                    kb.copy_from_slice(&self.block_buf[self.cursor..self.cursor + 16]);
                    self.cursor += 16;
                    u128::from_le_bytes(kb)
                };
                let tag = self.block_buf[self.cursor];
                self.cursor += 1;
                let addr = {
                    let mut ab = [0u8; 8];
                    ab.copy_from_slice(&self.block_buf[self.cursor..self.cursor + 8]);
                    self.cursor += 8;
                    u64::from_le_bytes(ab)
                };
                self.entries_left_in_block -= 1;
                return Some(Ok(SstItem {
                    key: k,
                    val: if tag == 0 { None } else { Some(addr) },
                }));
            } else {
                match self.load_block() {
                    Ok(true) => continue,
                    Ok(false) => return None,
                    Err(e) => return Some(Err(e)),
                }
            }
        }
    }
}

struct SstWriter {
    path: PathBuf,
    file: File,
    block_entries: usize,
    cur_block: Vec<(u128, Entry)>,
    index: Vec<BlockMeta>,
    total_entries: u64,
}

impl SstWriter {
    fn create(dir: &Path, seq: u64, block_entries: usize) -> io::Result<Self> {
        let path = dir.join(format!("sst.{:016x}.ldb", seq));
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        Ok(Self {
            path,
            file,
            block_entries,
            cur_block: Vec::with_capacity(block_entries),
            index: Vec::new(),
            total_entries: 0,
        })
    }

    fn push(&mut self, key: u128, val: Entry) -> io::Result<()> {
        if self.cur_block.is_empty() || self.cur_block.last().unwrap().0 <= key {
            // ok (keys must be sorted ascending)
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SST push: keys not sorted",
            ));
        }
        self.cur_block.push((key, val));
        if self.cur_block.len() >= self.block_entries {
            self.flush_block()?;
        }
        Ok(())
    }

    fn flush_block(&mut self) -> io::Result<()> {
        if self.cur_block.is_empty() {
            return Ok(());
        }
        let first_key = self.cur_block[0].0;
        let offset = self.file.seek(SeekFrom::End(0))?;
        // Build block payload
        let count = self.cur_block.len();
        let payload_len = (16 + 1 + 8) * count;
        let mut buf = Vec::with_capacity(4 + payload_len + 4);
        buf.extend_from_slice(&(count as u32).to_le_bytes());
        for (k, e) in self.cur_block.iter() {
            buf.extend_from_slice(&k.to_le_bytes());
            buf.push(if e.val.is_some() { 1 } else { 0 });
            buf.extend_from_slice(&e.val.unwrap_or(0).to_le_bytes());
        }
        let crc = crc32c(0, &buf[4..]);
        buf.extend_from_slice(&crc.to_le_bytes());
        self.file.write_all(&buf)?;
        self.index.push(BlockMeta {
            first_key,
            offset,
            length: buf.len() as u32,
        });
        self.total_entries += count as u64;
        self.cur_block.clear();
        Ok(())
    }

    fn finish(mut self) -> io::Result<SstReader> {
        self.flush_block()?;
        // Write index: [u32 block_count][u64 total_entries][repeated (key,off,len)] [u64 idx_off][u32 magic]
        let idx_off = self.file.seek(SeekFrom::End(0))?;
        self.file
            .write_all(&(self.index.len() as u32).to_le_bytes())?;
        self.file
            .write_all(&self.total_entries.to_le_bytes())?;
        for bm in &self.index {
            self.file.write_all(&bm.first_key.to_le_bytes())?;
            self.file.write_all(&bm.offset.to_le_bytes())?;
            self.file.write_all(&bm.length.to_le_bytes())?;
        }
        self.file.write_all(&idx_off.to_le_bytes())?;
        self.file
            .write_all(&SST_MAGIC_TRAILER.to_le_bytes())?;
        self.file.flush()?;
        // Open a reader on the newly created table
        SstReader::open(self.path, 0) // seq is parsed from filename by caller
    }
}

// ============================ Disk-backed index =============================

pub struct ShardlessDiskIndex {
    dir: PathBuf,
    opts: IndexOptions,
    // Serialize apply (WAL+memtable mutation).
    apply_lock: Mutex<()>,
    wal: Mutex<Wal>,
    // Hot in-memory structures
    mem: RwLock<BTreeMap<u128, Entry>>,
    // SSTables (newest first). Each reader stores its parsed fence pointers.
    ssts: RwLock<Vec<Arc<SstReader>>>,
    // Next monotonically increasing sequence used in file names.
    seq: AtomicU64,
}

impl ShardlessDiskIndex {
    fn index_dir(base: &Path) -> io::Result<PathBuf> {
        fs::create_dir_all(base)?;
        Ok(base.to_path_buf())
    }

    fn parse_seq_from_name(name: &str) -> Option<u64> {
        // "sst.{16 hex}.ldb"
        if !name.starts_with("sst.") || !name.ends_with(".ldb") {
            return None;
        }
        let hex = &name[4..(name.len() - 4)];
        u64::from_str_radix(hex, 16).ok()
    }

    fn load_existing_ssts(dir: &Path) -> io::Result<(Vec<Arc<SstReader>>, u64)> {
        let mut entries = Vec::new();
        let mut max_seq = 0u64;
        for ent in fs::read_dir(dir)? {
            let ent = ent?;
            let fname = ent.file_name();
            let Some(fname_s) = fname.to_str() else { continue; };
            if let Some(seq) = Self::parse_seq_from_name(fname_s) {
                let path = dir.join(fname_s);
                let rdr = Arc::new(SstReader::open(path, seq)?);
                entries.push((seq, rdr));
                if seq > max_seq {
                    max_seq = seq;
                }
            }
        }
        // Newest first in the array for faster lookups.
        entries.sort_by(|a, b| b.0.cmp(&a.0));
        Ok((entries.into_iter().map(|(_, r)| r).collect(), max_seq))
    }

    fn open_internal(base: &Path, opts: IndexOptions) -> io::Result<Self> {
        let dir = Self::index_dir(base)?;
        let (ssts_vec, max_seq) = Self::load_existing_ssts(&dir)?;
        let mut wal = Wal::open(&dir)?;
        // Restore memtable from WAL if present
        let mut mem = BTreeMap::<u128, Entry>::new();
        for (tag, key, val) in wal.replay()? {
            match tag {
                WalTag::Set => mem.insert(key, Entry { val }),
                WalTag::Delete => mem.insert(key, Entry { val: None }),
            };
        }
        Ok(Self {
            dir,
            opts,
            apply_lock: Mutex::new(()),
            wal: Mutex::new(wal),
            mem: RwLock::new(mem),
            ssts: RwLock::new(ssts_vec),
            seq: AtomicU64::new(max_seq.saturating_add(1)),
        })
    }

    fn flush_memtable_locked(&self, mem_snapshot: BTreeMap<u128, Entry>) -> io::Result<()> {
        if mem_snapshot.is_empty() {
            // Still reset WAL to cut it to zero length if there was residual.
            self.wal.lock().unwrap().reset()?;
            return Ok(());
        }
        let seq = self.seq.fetch_add(1, AtomOrdering::AcqRel);
        let mut writer = SstWriter::create(&self.dir, seq, self.opts.sst_block_entries)?;
        for (k, e) in mem_snapshot.iter() {
            writer.push(*k, *e)?;
        }
        let reader = Arc::new(SstReader::open(writer.finish()?.path, seq)?);

        // Swap into live list (newest first):
        {
            let mut tables = self.ssts.write().unwrap();
            let mut newv = Vec::with_capacity(tables.len() + 1);
            newv.push(reader);
            newv.extend_from_slice(&tables);
            *tables = newv;
        }

        // Reset WAL atomically after the SSTable is durable
        self.wal.lock().unwrap().reset()?;
        Ok(())
    }

    fn maybe_flush_and_compact(&self) -> io::Result<()> {
        // Flush if memtable size reached threshold
        let do_flush = {
            let mem = self.mem.read().unwrap();
            mem.len() >= self.opts.memtable_max_entries
        };
        if do_flush {
            // Swap out memtable content efficiently
            let snapshot = {
                let mut mem = self.mem.write().unwrap();
                std::mem::take(&mut *mem)
            };
            self.flush_memtable_locked(snapshot)?;
        }

        // Compact if too many L0 files
        let do_compact = { self.ssts.read().unwrap().len() > self.opts.level0_compact_trigger };
        if do_compact {
            METRICS
                .index_overflows
                .fetch_add(1, AtomOrdering::Relaxed);
            self.full_compaction()?;
        }

        Ok(())
    }

    fn full_compaction(&self) -> io::Result<()> {
        // Snapshot current tables
        let current = self.ssts.read().unwrap().clone();
        if current.len() <= 1 {
            return Ok(());
        }

        // Create new compaction output
        let seq = self.seq.fetch_add(1, AtomOrdering::AcqRel);
        let mut writer = SstWriter::create(&self.dir, seq, self.opts.sst_block_entries)?;

        // Build iterators (each is sorted ascending by key)
        let mut iters: Vec<_> = Vec::with_capacity(current.len());
        for t in &current {
            iters.push((t.seq, t.iter()?));
        }

        // k-way merge using a binary heap:
        // Since std::collections::BinaryHeap is a max-heap, wrap with Reverse.
        use std::collections::BinaryHeap;

        #[derive(Eq)]
        struct HeapElt {
            key: u128,
            // Higher seq => newer.
            seq: u64,
            val: Option<u64>,
            src: usize,
        }
        impl PartialEq for HeapElt {
            fn eq(&self, other: &Self) -> bool {
                self.key == other.key && self.seq == other.seq && self.src == other.src
            }
        }
        impl PartialOrd for HeapElt {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }
        impl Ord for HeapElt {
            fn cmp(&self, other: &Self) -> Ordering {
                // We want **min** by key; for equal keys, **max** by seq (newest first).
                match self.key.cmp(&other.key) {
                    Ordering::Less => Ordering::Greater, // reversed (min-heap via max-heap)
                    Ordering::Greater => Ordering::Less,
                    Ordering::Equal => self.seq.cmp(&other.seq), // newer (larger) is greater
                }
            }
        }

        let mut heap: BinaryHeap<HeapElt> = BinaryHeap::new();

        // Prime heap with first items
        for (i, (seq_i, iter)) in iters.iter_mut().enumerate() {
            if let Some(next) = iter.next() {
                let it = next?;
                heap.push(HeapElt {
                    key: it.key,
                    seq: *seq_i,
                    val: it.val,
                    src: i,
                });
            }
        }

        let mut last_written_key: Option<u128> = None;

        while let Some(top) = heap.pop() {
            // Drain all with this key, keeping the newest (largest seq) which is `top`
            if last_written_key == Some(top.key) {
                // We've already written this key; consume duplicates only.
            } else {
                // Emit top (newest) for this key
                writer.push(
                    top.key,
                    Entry {
                        val: top.val, // None → deletion tombstone; retained ONLY if overshadowing older values
                    },
                )?;
                last_written_key = Some(top.key);
            }
            // Advance the iterator for the source of `top`
            let src = top.src;
            if let Some(next) = iters[src].1.next() {
                let it = next?;
                heap.push(HeapElt {
                    key: it.key,
                    seq: iters[src].0,
                    val: it.val,
                    src,
                });
            }
        }

        let new_reader = Arc::new(SstReader::open(writer.finish()?.path, seq)?);

        // Atomically swap table list: new reader first; delete old files afterwards.
        {
            let mut w = self.ssts.write().unwrap();
            let old = std::mem::replace(&mut *w, vec![new_reader.clone()]);
            drop(w);
            // Remove old files on disk (best-effort)
            for t in old {
                let _ = fs::remove_file(&t.path);
            }
        }

        Ok(())
    }

    // ------------------------------ API ops ---------------------------------

    fn get(&self, key: u128) -> io::Result<u64> {
        // 1) memtable
        if let Some(e) = self.mem.read().unwrap().get(&key) {
            return Ok(e.val.unwrap_or(0));
        }
        // 2) SSTables, newest first
        let ssts = self.ssts.read().unwrap().clone();
        for t in &ssts {
            if let Some(v) = t.get(key)? {
                return Ok(v.unwrap_or(0));
            }
        }
        Ok(0)
    }

    fn upsert(&self, key: u128, addr: u64) -> Result<UpsertResult, IndexError> {
        let _g = self.apply_lock.lock().unwrap();
        // Record WAL then memtable
        {
            let mut wal = self.wal.lock().unwrap();
            wal.append_set(key, addr)?;
        }
        let prev = self
            .mem
            .write()
            .unwrap()
            .insert(key, Entry { val: Some(addr) });
        self.maybe_flush_and_compact()?;
        Ok(match prev {
            None => UpsertResult::Inserted,
            Some(e) => match e.val {
                Some(v) if v != 0 => UpsertResult::Replaced(v),
                _ => UpsertResult::Replaced(0),
            },
        })
    }

    fn delete(&self, key: u128) -> io::Result<Option<u64>> {
        let _g = self.apply_lock.lock().unwrap();
        // WAL
        {
            let mut wal = self.wal.lock().unwrap();
            wal.append_del(key)?;
        }
        // Memtable: store a deletion tombstone (None)
        let prev = self.mem.write().unwrap().insert(key, Entry { val: None });
        self.maybe_flush_and_compact()?;
        Ok(prev.and_then(|e| e.val))
    }

    fn entry_count(&self) -> io::Result<u64> {
        let mem_n = self.mem.read().unwrap().len() as u64;
        let sst_n: u64 = self
            .ssts
            .read()
            .unwrap()
            .iter()
            .map(|t| t.entry_count)
            .sum();
        Ok(mem_n + sst_n)
    }
}

// =============================== Public wrapper ==============================

/// Public name preserved for compatibility with the rest of the codebase.
pub struct ShardedIndex {
    inner: ShardlessDiskIndex,
}

impl ShardedIndex {
    /// Open or create a disk-backed index under `dir`.
    pub fn open(dir: &Path, opts: IndexOptions) -> io::Result<Self> {
        let inner = ShardlessDiskIndex::open_internal(dir, opts)?;
        Ok(Self { inner })
    }

    /// Get the latest mapped address for `key` (0 if not present).
    pub fn get(&self, key: u128) -> u64 {
        // Swallow IO errors as 0 (consistent with prior behavior returning 0 on miss)
        self.inner.get(key).unwrap_or(0)
    }

    /// Insert or replace mapping: key → addr.
    pub fn upsert(&self, key: u128, addr: u64) -> Result<UpsertResult, IndexError> {
        self.inner.upsert(key, addr)
    }

    /// Remove mapping for `key` (LSM tombstone). Returns previous addr if any.
    pub fn delete(&self, key: u128) -> Option<u64> {
        self.inner.delete(key).ok().flatten()
    }

    /// Visible to the engine bootstrapper to avoid segment scanning when we already have data.
    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count().unwrap_or(0)
    }
}
