mod context_index;
mod crc32c;
mod index;
pub mod search;
mod segment;

pub use context_index::ContextIndex;
pub use index::{migrate_legacy_index_files, IndexError, ShardedIndex, UpsertResult};
pub use search::{rebuild_from_engine, SearchDocument, SearchHit, SearchIndex};
pub use segment::{OpenSegments, Record};

use crate::config::{Engine, Scoring};
use std::{io, path::PathBuf, sync::Arc};

#[derive(Clone)]
pub struct EngineRuntime {
    #[allow(dead_code)]
    pub dir: PathBuf,
    pub segments: Arc<OpenSegments>,
    pub index: Arc<ShardedIndex>,
    pub ctx_index: Arc<ContextIndex>,
    pub search: Arc<SearchIndex>,
    #[allow(dead_code)]
    pub cfg: Engine,
    #[allow(dead_code)]
    pub scoring: Scoring,
}

impl EngineRuntime {
    pub fn open(cfg: Engine, scoring: Scoring) -> io::Result<Self> {
        std::fs::create_dir_all(&cfg.data_dir)?;
        let dir = PathBuf::from(&cfg.data_dir);
        let segments = Arc::new(OpenSegments::open(
            &dir,
            cfg.segment_bytes,
            cfg.use_mmap_reads,
        )?);

        let index_dir = if let Some(ref override_dir) = cfg.index_dir {
            PathBuf::from(override_dir)
        } else {
            dir.join("index")
        };
        std::fs::create_dir_all(&index_dir)?;

        migrate_legacy_index_files(&index_dir)?;

        let index_db = sled::Config::default()
            .path(&index_dir)
            .cache_capacity(64 * 1024 * 1024)
            .flush_every_ms(Some(500))
            .open()
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("sled open index db: {e}"))
            })?;

        let index = Arc::new(ShardedIndex::new(&index_db)?);

        if index.entry_count() == 0 {
            segments.rebuild_index(&index)?;
        }

        let ctx_index = Arc::new(ContextIndex::new(&index_db)?);
        let search_dir = dir.join("search_index");
        let search = Arc::new(SearchIndex::open(&search_dir)?);
        if search.is_empty()? {
            rebuild_from_engine(&search, &segments, &index, &ctx_index)?;
        }

        Ok(Self {
            dir,
            segments,
            index,
            ctx_index,
            search,
            cfg,
            scoring,
        })
    }
}
