//! Search-related type definitions.

use serde::Serialize;

/// Document for search indexing.
#[derive(Debug, Clone)]
pub struct SearchDocument {
    pub key: u128,
    pub func_name: String,
    pub binary_names: Vec<String>,
    pub ts: u64,
}

/// Search result hit.
#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    pub key_hex: String,
    pub func_name: String,
    pub binary_names: Vec<String>,
    pub score: f32,
}
