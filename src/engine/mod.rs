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

        let index_dir = if let Some(ref override_dir) = cfg.index_dir {
            PathBuf::from(override_dir)
        } else {
            dir.join("index")
        };
        std::fs::create_dir_all(&index_dir)?;
        // Sled-backed index; IndexOptions kept for API stability
        let idx_opts = crate::engine::index::IndexOptions::sane();
        let index = Arc::new(ShardedIndex::open(&index_dir, idx_opts)?);

        // Always rebuild index from segments if empty (or on first run).
        if index.entry_count() == 0 {
            segments.rebuild_index(&index)?;
        }

        Ok(Self { dir, segments, index, cfg })
    }
}
