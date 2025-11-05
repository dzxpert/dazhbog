    mod crc32c;
mod segment;
mod index;
mod spin;

pub use segment::{Record, OpenSegments};
pub use index::{ShardedIndex, UpsertResult, IndexError};

use crate::config::Engine;
use std::{io, path::PathBuf, sync::Arc};

#[derive(Clone)]
pub struct EngineRuntime {
    #[allow(dead_code)]
    pub dir: PathBuf,
    pub segments: Arc<OpenSegments>,
    pub index: Arc<ShardedIndex>,
    #[allow(dead_code)]
    pub cfg: Engine,
}

impl EngineRuntime {
    pub fn open(cfg: Engine) -> io::Result<Self> {
        std::fs::create_dir_all(&cfg.data_dir)?;
        let dir = PathBuf::from(&cfg.data_dir);
        let segments = Arc::new(OpenSegments::open(&dir, cfg.segment_bytes, cfg.use_mmap_reads)?);

        // Build index options from config and open disk-backed index under data_dir/index
        let index_dir = if let Some(ref override_dir) = cfg.index_dir {
            PathBuf::from(override_dir)
        } else {
            dir.join("index")
        };
        std::fs::create_dir_all(&index_dir)?;
        let idx_opts = crate::engine::index::IndexOptions {
            memtable_max_entries: cfg.index_memtable_max_entries,
            sst_block_entries: cfg.index_block_entries,
            level0_compact_trigger: cfg.index_level0_compact_trigger,
        };
        let index = Arc::new(ShardedIndex::open(&index_dir, idx_opts)?);

        // Recovery: scan segments and rebuild index **only if the index is empty**.
        if index.entry_count() == 0 {
            segments.rebuild_index(&index)?;
        }

        Ok(Self { dir, segments, index, cfg })
    }
}
