//! Search-related type definitions.

use serde::Serialize;

/// Document for search indexing.
#[derive(Debug, Clone)]
pub struct SearchDocument {
    pub key: u128,
    pub func_name: String,
    /// Pre-computed demangled name (empty string if not demangled)
    pub func_name_demangled: String,
    /// Detected language from demangling (empty string if not detected)
    pub lang: String,
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
    /// Create a new SearchHit with pre-computed demangled name
    pub fn new_with_demangled(
        key_hex: String,
        func_name: String,
        func_name_demangled: String,
        lang: String,
        binary_names: Vec<String>,
        score: f32,
    ) -> Self {
        let (func_name_demangled, lang) = if func_name_demangled.is_empty() {
            (None, None)
        } else {
            (
                Some(func_name_demangled),
                if lang.is_empty() { None } else { Some(lang) },
            )
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
