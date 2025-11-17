//! Sled-backed index (u128 key → u64 address).
//!
//! This replaces the custom WAL/SSTable index with a robust embedded K/V store.
//! API surface is kept stable where used by the rest of the codebase.

use std::{io, path::Path};

#[derive(Clone, Debug)]
pub struct IndexOptions {
    pub memtable_max_entries: usize,
    pub sst_block_entries: usize,
    pub level0_compact_trigger: usize,
}
impl IndexOptions {
    pub fn sane() -> Self {
        Self { memtable_max_entries: 0, sst_block_entries: 0, level0_compact_trigger: 0 }
    }
}

pub enum UpsertResult {
    Inserted,
    Replaced(u64),
}

pub enum IndexError {
    Full,
    Io(io::Error),
}

impl From<io::Error> for IndexError {
    fn from(e: io::Error) -> Self { IndexError::Io(e) }
}

fn k128(k: u128) -> [u8; 16] { k.to_le_bytes() }

fn v64(v: u64) -> [u8; 8] { v.to_le_bytes() }

fn dec64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[0..8]);
    u64::from_le_bytes(a)
}

pub struct ShardedIndex {
    db: sled::Db,
    tree: sled::Tree,
}

impl ShardedIndex {
    pub fn open(dir: &Path, _opts: IndexOptions) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        // Proactively move legacy files (wal.dat/sst.*) aside to avoid confusion.
        migrate_legacy_index_files(dir)?;
        let db = sled::Config::default()
            .path(dir)
            .cache_capacity(64 * 1024 * 1024)
            .flush_every_ms(Some(500))
            .open()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open: {e}")))?;
        let tree = db.open_tree("latest").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open_tree: {e}")))?;
        Ok(Self { db, tree })
    }

    pub fn get(&self, key: u128) -> u64 {
        match self.tree.get(k128(key)) {
            Ok(Some(v)) if v.len() >= 8 => dec64(&v),
            _ => 0,
        }
    }

    pub fn upsert(&self, key: u128, addr: u64) -> Result<UpsertResult, IndexError> {
        let res = self.tree.fetch_and_update(k128(key), |prev| {
            match prev {
                None => Some(v64(addr).to_vec()),
                Some(_) => Some(v64(addr).to_vec()),
            }
        }).map_err(|e| IndexError::Io(io::Error::new(io::ErrorKind::Other, format!("sled upsert: {e}"))))?;
        Ok(match res {
            None => UpsertResult::Inserted,
            Some(p) if p.len() >= 8 => UpsertResult::Replaced(dec64(&p)),
            Some(_) => UpsertResult::Replaced(0),
        })
    }

    pub fn delete(&self, key: u128) -> Option<u64> {
        match self.tree.remove(k128(key)) {
            Ok(Some(p)) if p.len() >= 8 => Some(dec64(&p)),
            _ => None,
        }
    }

    pub fn entry_count(&self) -> u64 {
        self.tree.len() as u64
    }

    /// Iterate over all keys in the index
    pub fn iter_keys(&self) -> impl Iterator<Item = (u128, u64)> + '_ {
        self.tree.iter().filter_map(|res| {
            res.ok().and_then(|(k, v)| {
                if k.len() >= 16 && v.len() >= 8 {
                    let mut key_bytes = [0u8; 16];
                    key_bytes.copy_from_slice(&k[0..16]);
                    let key = u128::from_le_bytes(key_bytes);
                    let addr = dec64(&v);
                    Some((key, addr))
                } else {
                    None
                }
            })
        })
    }
}

fn migrate_legacy_index_files(dir: &Path) -> io::Result<()> {
    let mut found = false;
    for ent in std::fs::read_dir(dir)? {
        let ent = ent?;
        let name = ent.file_name();
        let Some(name) = name.to_str() else { continue; };
        if name == "wal.dat" || (name.starts_with("sst.") && name.ends_with(".ldb")) {
            found = true;
            break;
        }
    }
    if !found { return Ok(()); }
    let stamp = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
    let backup = dir.join(format!(".legacy_index_{}", stamp));
    std::fs::create_dir_all(&backup)?;
    for ent in std::fs::read_dir(dir)? {
        let ent = ent?;
        let name = ent.file_name();
        let Some(name) = name.to_str() else { continue; };
        if name == "wal.dat" || (name.starts_with("sst.") && name.ends_with(".ldb")) {
            std::fs::rename(ent.path(), backup.join(name))?;
        }
    }
    Ok(())
}
