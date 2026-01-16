//! Search index rebuild from engine data.

use super::index::SearchIndex;
use super::types::SearchDocument;
use crate::engine::{ContextIndex, OpenSegments, ShardedIndex};
use log::info;
use std::io;

/// Rebuild the search index from engine data.
pub fn rebuild_from_engine(
    search: &SearchIndex,
    segments: &OpenSegments,
    index: &ShardedIndex,
    ctx_index: &ContextIndex,
) -> io::Result<()> {
    use std::collections::HashMap;

    // Prefer walking live records directly; this avoids stale index offsets.
    let mut latest: HashMap<u128, (u64, String)> = HashMap::new();
    segments.for_each_record(|_seg_id, _off, rec| {
        if rec.flags & 0x01 != 0 {
            return Ok(());
        }
        let entry = latest
            .entry(rec.key)
            .or_insert((rec.ts_sec, rec.name.clone()));
        if rec.ts_sec >= entry.0 {
            *entry = (rec.ts_sec, rec.name.clone());
        }
        Ok(())
    })?;

    // If the sled index is empty we already collected records; otherwise ensure only keys still present remain.
    if index.entry_count() > 0 {
        latest.retain(|k, _| index.get(*k) != 0);
    }

    let mut docs = Vec::with_capacity(latest.len());
    for (key, (ts, name)) in latest.into_iter() {
        let basenames = ctx_index.resolve_basenames_for_key(key)?;
        docs.push(SearchDocument {
            key,
            func_name: name,
            binary_names: basenames,
            ts,
        });
    }

    info!("rebuilding full-text index for {} functions", docs.len());
    search.rebuild(docs)?;
    Ok(())
}
