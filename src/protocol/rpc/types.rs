//! RPC protocol type definitions.

/// Hello request from client.
#[derive(Debug)]
pub struct HelloReq {
    pub protocol_version: u32,
    pub username: String,
    #[allow(dead_code)]
    pub password: String,
}

/// Push item in a push request.
pub struct PushItem {
    pub key: u128,
    pub popularity: u32,
    pub len_bytes: u32,
    pub name: String,
    pub data: Vec<u8>,
}

/// Capability limits for push operations.
pub struct PushCaps {
    pub max_items: usize,
    pub max_name_bytes: usize,
    pub max_data_bytes: usize,
}
