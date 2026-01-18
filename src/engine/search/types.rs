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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub func_name_demangled: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    pub binary_names: Vec<String>,
    pub score: f32,
}

impl SearchHit {
    /// Create a new SearchHit with automatic demangling
    pub fn new(key_hex: String, func_name: String, binary_names: Vec<String>, score: f32) -> Self {
        let demangle_result = crate::common::demangle::demangle(&func_name);

        let (func_name_demangled, lang) = if demangle_result.demangled {
            (
                Some(demangle_result.name),
                demangle_result.lang.map(|s| s.to_string()),
            )
        } else {
            (None, None)
        };

        Self {
            key_hex,
            func_name,
            func_name_demangled,
            lang,
            binary_names,
            score,
        }
    }
}
