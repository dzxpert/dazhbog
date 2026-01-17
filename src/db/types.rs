//! Database type definitions.

/// Latest function metadata from the database.
#[derive(Debug, Clone)]
pub struct FuncLatest {
    pub popularity: u32,
    pub len_bytes: u32,
    pub name: String,
    pub data: Vec<u8>,
}

/// Context information for push operations.
#[derive(Clone, Debug)]
pub struct PushContext<'a> {
    pub md5: Option<[u8; 16]>,
    pub basename: Option<&'a str>,
    pub hostname: Option<&'a str>,
}

/// Owned version of PushContext for use in spawn_blocking.
#[derive(Clone, Debug)]
pub struct OwnedPushContext {
    pub md5: Option<[u8; 16]>,
    pub basename: Option<String>,
    pub hostname: Option<String>,
}

/// Context information for query operations.
#[derive(Clone)]
pub struct QueryContext<'a> {
    pub keys: &'a [u128],
    pub md5: Option<[u8; 16]>,
    pub basename: Option<&'a str>,
    #[allow(dead_code)]
    pub hostname: Option<&'a str>,
}
