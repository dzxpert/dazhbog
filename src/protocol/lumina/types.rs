//! Lumina protocol type definitions.

/// Hello message from client.
pub struct LuminaHello {
    pub protocol_version: u32,
    pub username: String,
    pub password: String,
}

/// Raw hello data for debug dumps.
pub struct LuminaHelloRaw {
    pub protocol_version: u32,
    pub license_data: Vec<u8>,
    pub id_bytes: [u8; 6],
    pub username: String,
    pub password: String,
}

/// Capability limits for protocol parsing.
#[derive(Clone, Copy, Debug)]
pub struct LuminaCaps {
    pub max_funcs: usize,
    pub max_name_bytes: usize,
    pub max_data_bytes: usize,
    pub max_cstr_bytes: usize,
    pub max_hash_bytes: usize,
}

impl Default for LuminaCaps {
    fn default() -> Self {
        Self {
            max_funcs: 524288,
            max_name_bytes: 65535,
            max_data_bytes: 8 * 1024 * 1024,
            max_cstr_bytes: 4096,
            max_hash_bytes: 64,
        }
    }
}

/// Function entry in PullMetadata request.
pub struct LuminaPullMetadataFunc {
    #[allow(dead_code)]
    pub unk0: u32,
    pub mb_hash: Vec<u8>,
}

/// PullMetadata request.
pub struct LuminaPullMetadata {
    #[allow(dead_code)]
    pub unk0: u32,
    #[allow(dead_code)]
    pub unk1: Vec<u32>,
    pub funcs: Vec<LuminaPullMetadataFunc>,
}

/// Function entry in PushMetadata request.
pub struct LuminaPushMetadataFunc {
    pub name: String,
    pub func_len: u32,
    pub func_data: Vec<u8>,
    #[allow(dead_code)]
    pub unk2: u32,
    pub hash: Vec<u8>,
}

/// PushMetadata request.
pub struct LuminaPushMetadata {
    #[allow(dead_code)]
    pub unk0: u32,
    #[allow(dead_code)]
    pub idb_path: String,
    pub file_path: String,
    pub md5: [u8; 16],
    pub hostname: String,
    pub funcs: Vec<LuminaPushMetadataFunc>,
    #[allow(dead_code)]
    pub unk1: Vec<u64>,
}

/// GetFuncHistories request.
pub struct LuminaGetFuncHistories {
    pub funcs: Vec<LuminaPullMetadataFunc>,
    #[allow(dead_code)]
    pub unk0: u32,
}
