//! Full-text search module for function metadata.
//!
//! This module provides:
//! - `SearchIndex` - Tantivy-based search index
//! - `SearchDocument` - Document structure for indexing
//! - `SearchHit` - Search result structure
//! - `rebuild_from_engine` - Rebuild index from engine data

mod index;
mod rebuild;
mod types;

pub use index::SearchIndex;
pub use rebuild::rebuild_from_engine;
pub use types::{SearchDocument, SearchHit};
