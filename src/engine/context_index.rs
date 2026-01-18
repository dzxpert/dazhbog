use log::*;
use std::{io, path::Path};

#[derive(Clone, Debug)]
pub struct BinaryMeta {
    pub md5: [u8; 16],
    pub basename: String,
    pub hostname: String,
    pub first_seen_ts: u64,
    pub last_seen_ts: u64,
    pub obs_count: u64,
}

#[derive(Clone, Debug)]
pub struct KeyMd5Stats {
    pub obs_count: u32,
    pub last_ts_sec: u64,
    pub last_version_id: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct KeyMd5Entry {
    pub md5: [u8; 16],
    pub obs_count: u32,
}

#[derive(Clone, Debug)]
pub struct VersionStats {
    pub total_obs: u32,
    pub first_ts_sec: u64,
    pub last_ts_sec: u64,
    pub num_binaries: u32,
    pub top_md5s: Vec<KeyMd5Entry>,
}

pub struct ContextIndex {
    #[allow(dead_code)]
    db: sled::Db, // Keep db handle alive
    t_key_md5: sled::Tree,       // key||md5 -> KeyMd5Stats
    t_key_bins: sled::Tree,      // key -> Vec<KeyMd5Entry>
    t_version_stats: sled::Tree, // version_id -> VersionStats
    t_binary_meta: sled::Tree,   // md5 -> BinaryMeta
    t_key_basenames: sled::Tree, // key -> Vec<String>
}

const MAX_MD5_PER_KEY: usize = 16;
const MAX_MD5_PER_VERSION: usize = 16;
const MAX_BASENAMES_PER_KEY: usize = 16;

impl ContextIndex {
    /// Open existing context_db. Crashes if it doesn't exist.
    /// Use `recover --migrate-context` to create it from old data.
    pub fn open(dir: &Path) -> io::Result<Self> {
        let ctx_dir = dir.join("context_db");
        if !ctx_dir.exists() {
            error!("context_db not found at {}", ctx_dir.display());
            error!("Run `recover --migrate-context` to migrate from old index format");
            panic!(
                "FATAL: context_db not found at {}. Run `recover --migrate-context` first.",
                ctx_dir.display()
            );
        }
        Self::open_internal(&ctx_dir)
    }

    /// Open or create context_db (for recover tool).
    pub fn open_or_create(dir: &Path) -> io::Result<Self> {
        let ctx_dir = dir.join("context_db");
        std::fs::create_dir_all(&ctx_dir)?;
        Self::open_internal(&ctx_dir)
    }

    /// Open context_db directly at the given path (for recover tool migration).
    pub fn open_at_path(ctx_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(ctx_dir)?;
        Self::open_internal(ctx_dir)
    }

    fn open_internal(ctx_dir: &Path) -> io::Result<Self> {
        debug!("opening context index at {}", ctx_dir.display());
        let db = sled::Config::default()
            .path(ctx_dir)
            .cache_capacity(32 * 1024 * 1024)
            .flush_every_ms(Some(500))
            .open()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("sled open context_db: {e}"),
                )
            })?;

        let t_key_md5 = db
            .open_tree("key_md5")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")));
        let t_key_bins = db
            .open_tree("key_bins")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")));
        let t_version_stats = db
            .open_tree("version_stats")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")));
        let t_binary_meta = db
            .open_tree("binary_meta")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")));
        let t_key_basenames = db
            .open_tree("key_basenames")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")));
        info!("context index initialized successfully");
        Ok(Self {
            db,
            t_key_md5: t_key_md5?,
            t_key_bins: t_key_bins?,
            t_version_stats: t_version_stats?,
            t_binary_meta: t_binary_meta?,
            t_key_basenames: t_key_basenames?,
        })
    }

    pub fn approx_is_empty(&self) -> bool {
        self.t_key_md5.is_empty() && self.t_version_stats.is_empty()
    }

    pub fn record_binary_meta(
        &self,
        md5: [u8; 16],
        basename: &str,
        hostname: &str,
        ts_sec: u64,
    ) -> io::Result<()> {
        let clean_basename = sanitize_basename(basename);
        let key = md5;
        let val = self
            .t_binary_meta
            .get(key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled get: {e}")))?;
        let mut meta = if let Some(v) = val {
            decode_binary_meta(&v).unwrap_or(BinaryMeta {
                md5,
                basename: String::new(),
                hostname: String::new(),
                first_seen_ts: ts_sec,
                last_seen_ts: ts_sec,
                obs_count: 0,
            })
        } else {
            BinaryMeta {
                md5,
                basename: String::new(),
                hostname: String::new(),
                first_seen_ts: ts_sec,
                last_seen_ts: ts_sec,
                obs_count: 0,
            }
        };
        meta.last_seen_ts = meta.last_seen_ts.max(ts_sec);
        meta.obs_count = meta.obs_count.saturating_add(1);
        if meta.basename.is_empty() && !clean_basename.is_empty() {
            meta.basename = clean_basename;
        }
        if meta.hostname.is_empty() {
            meta.hostname = hostname.to_string();
        }
        let enc = encode_binary_meta(&meta);
        self.t_binary_meta
            .insert(key, enc)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;

        Ok(())
    }

    pub fn record_key_observation(
        &self,
        key: u128,
        md5: [u8; 16],
        version_id: Option<[u8; 32]>,
        ts_sec: u64,
        basename: Option<&str>,
    ) -> io::Result<()> {
        let mut key_bytes = [0u8; 32];
        key_bytes[0..16].copy_from_slice(&key.to_le_bytes());
        key_bytes[16..32].copy_from_slice(&md5);

        let now_stats = self
            .t_key_md5
            .get(&key_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled get: {e}")))?;
        let mut st = if let Some(v) = now_stats {
            decode_key_md5_stats(&v).unwrap_or(KeyMd5Stats {
                obs_count: 0,
                last_ts_sec: 0,
                last_version_id: [0u8; 32],
            })
        } else {
            KeyMd5Stats {
                obs_count: 0,
                last_ts_sec: 0,
                last_version_id: [0u8; 32],
            }
        };
        st.obs_count = st.obs_count.saturating_add(1);
        st.last_ts_sec = ts_sec;
        if let Some(vid) = version_id {
            st.last_version_id = vid;
        }
        let enc = encode_key_md5_stats(&st);
        self.t_key_md5
            .insert(&key_bytes, enc)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;

        // t_key_bins update
        let key_only = key.to_le_bytes();
        let bins_raw = self
            .t_key_bins
            .get(&key_only)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled get: {e}")))?;
        let mut bins = if let Some(v) = bins_raw {
            decode_key_bins(&v).unwrap_or_default()
        } else {
            Vec::<KeyMd5Entry>::new()
        };
        let mut found = false;
        for e in &mut bins {
            if e.md5 == md5 {
                e.obs_count = e.obs_count.saturating_add(1);
                found = true;
                break;
            }
        }
        if !found {
            bins.push(KeyMd5Entry { md5, obs_count: 1 });
        }
        bins.sort_by_key(|e| std::cmp::Reverse(e.obs_count));
        if bins.len() > MAX_MD5_PER_KEY {
            bins.truncate(MAX_MD5_PER_KEY);
        }
        let enc_bins = encode_key_bins(&bins);
        self.t_key_bins
            .insert(&key_only, enc_bins)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;

        if let Some(bn) = basename {
            self.record_basename_for_key(key, bn)?;
        }

        // version stats (if provided)
        if let Some(vid) = version_id {
            let cur = self
                .t_version_stats
                .get(&vid)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled get: {e}")))?;
            let mut vs = if let Some(v) = cur {
                decode_version_stats(&v).unwrap_or(VersionStats {
                    total_obs: 0,
                    first_ts_sec: ts_sec,
                    last_ts_sec: ts_sec,
                    num_binaries: 0,
                    top_md5s: Vec::new(),
                })
            } else {
                VersionStats {
                    total_obs: 0,
                    first_ts_sec: ts_sec,
                    last_ts_sec: ts_sec,
                    num_binaries: 0,
                    top_md5s: Vec::new(),
                }
            };
            vs.total_obs = vs.total_obs.saturating_add(1);
            if vs.first_ts_sec == 0 {
                vs.first_ts_sec = ts_sec;
            }
            vs.last_ts_sec = vs.last_ts_sec.max(ts_sec);
            let mut seen = false;
            for e in &mut vs.top_md5s {
                if e.md5 == md5 {
                    e.obs_count = e.obs_count.saturating_add(1);
                    seen = true;
                    break;
                }
            }
            if !seen {
                vs.top_md5s.push(KeyMd5Entry { md5, obs_count: 1 });
                if vs.num_binaries < u32::MAX {
                    vs.num_binaries += 1;
                }
            }
            vs.top_md5s.sort_by_key(|e| std::cmp::Reverse(e.obs_count));
            if vs.top_md5s.len() > MAX_MD5_PER_VERSION {
                vs.top_md5s.truncate(MAX_MD5_PER_VERSION);
            }
            let enc = encode_version_stats(&vs);
            self.t_version_stats
                .insert(&vid, enc)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;
        }

        Ok(())
    }

    pub fn get_md5_bins_for_key(&self, key: u128) -> io::Result<Vec<KeyMd5Entry>> {
        trace!("getting md5 bins for key: {}", key);
        let key_only = key.to_le_bytes();
        match self.t_key_bins.get(&key_only) {
            Ok(Some(v)) => Ok(decode_key_bins(&v).unwrap_or_default()),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sled get: {e}"),
            )),
        }
    }

    pub fn get_version_stats(&self, version_id: &[u8; 32]) -> io::Result<Option<VersionStats>> {
        trace!("getting version stats");
        match self.t_version_stats.get(version_id) {
            Ok(Some(v)) => Ok(decode_version_stats(&v)),
            Ok(None) => Ok(None),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sled get: {e}"),
            )),
        }
    }

    pub fn get_binary_meta(&self, md5: &[u8; 16]) -> io::Result<Option<BinaryMeta>> {
        trace!("getting binary meta");
        match self.t_binary_meta.get(md5) {
            Ok(Some(v)) => Ok(decode_binary_meta(&v)),
            Ok(None) => Ok(None),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sled get: {e}"),
            )),
        }
    }

    pub fn get_key_md5_stats(&self, key: u128, md5: &[u8; 16]) -> io::Result<Option<KeyMd5Stats>> {
        let mut k = [0u8; 32];
        k[0..16].copy_from_slice(&key.to_le_bytes());
        k[16..32].copy_from_slice(md5);
        match self.t_key_md5.get(&k) {
            Ok(Some(v)) => Ok(decode_key_md5_stats(&v)),
            Ok(None) => Ok(None),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sled get: {e}"),
            )),
        }
    }

    pub fn get_basenames_for_key(&self, key: u128) -> io::Result<Vec<String>> {
        let key_only = key.to_le_bytes();
        match self.t_key_basenames.get(&key_only) {
            Ok(Some(v)) => Ok(decode_basenames(&v).unwrap_or_default()),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sled get: {e}"),
            )),
        }
    }

    pub fn resolve_basenames_for_key(&self, key: u128) -> io::Result<Vec<String>> {
        // Sanitize all basenames to ensure only filenames are returned (no paths)
        // This protects against leaking usernames or directory structure from old data
        let mut names: Vec<String> = self
            .get_basenames_for_key(key)?
            .into_iter()
            .map(|b| sanitize_basename(&b))
            .filter(|b| !b.is_empty())
            .collect();
        let mut seen: std::collections::HashSet<String> =
            names.iter().map(|s| s.to_lowercase()).collect();

        if names.len() < MAX_BASENAMES_PER_KEY {
            let md5_list = self.get_md5_bins_for_key(key)?;
            for entry in md5_list.iter() {
                if let Ok(Some(meta)) = self.get_binary_meta(&entry.md5) {
                    let clean = sanitize_basename(&meta.basename);
                    if !clean.is_empty()
                        && seen.insert(clean.to_lowercase())
                        && names.len() < MAX_BASENAMES_PER_KEY
                    {
                        names.push(clean);
                    }
                }
            }
        }

        Ok(names)
    }

    fn record_basename_for_key(&self, key: u128, basename: &str) -> io::Result<()> {
        let clean = sanitize_basename(basename);
        if clean.is_empty() {
            return Ok(());
        }

        let key_only = key.to_le_bytes();
        let current = self
            .t_key_basenames
            .get(&key_only)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled get: {e}")))?;
        let mut basenames = if let Some(v) = current {
            decode_basenames(&v).unwrap_or_default()
        } else {
            Vec::new()
        };

        if !basenames
            .iter()
            .any(|b| b.eq_ignore_ascii_case(clean.as_str()))
        {
            basenames.insert(0, clean);
            if basenames.len() > MAX_BASENAMES_PER_KEY {
                basenames.truncate(MAX_BASENAMES_PER_KEY);
            }
            let enc = encode_basenames(&basenames);
            self.t_key_basenames
                .insert(&key_only, enc)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;
        }

        Ok(())
    }

    /// Get the count of unique binaries (md5s) observed.
    pub fn unique_binaries_count(&self) -> u64 {
        self.t_binary_meta.len() as u64
    }
}

// ----------------- encoding helpers -----------------

fn put_u16_le(v: u16, dst: &mut Vec<u8>) {
    dst.extend_from_slice(&v.to_le_bytes());
}
fn put_u32_le(v: u32, dst: &mut Vec<u8>) {
    dst.extend_from_slice(&v.to_le_bytes());
}
fn put_u64_le(v: u64, dst: &mut Vec<u8>) {
    dst.extend_from_slice(&v.to_le_bytes());
}
fn get_u16_le(src: &mut &[u8]) -> Option<u16> {
    if src.len() < 2 {
        return None;
    }
    let v = u16::from_le_bytes(src[0..2].try_into().ok()?);
    *src = &src[2..];
    Some(v)
}
fn get_u32_le(src: &mut &[u8]) -> Option<u32> {
    if src.len() < 4 {
        return None;
    }
    let v = u32::from_le_bytes(src[0..4].try_into().ok()?);
    *src = &src[4..];
    Some(v)
}
fn get_u64_le(src: &mut &[u8]) -> Option<u64> {
    if src.len() < 8 {
        return None;
    }
    let v = u64::from_le_bytes(src[0..8].try_into().ok()?);
    *src = &src[8..];
    Some(v)
}
fn get_bytes<'a>(src: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if src.len() < n {
        return None;
    }
    let out = &src[..n];
    *src = &src[n..];
    Some(out)
}

fn put_str(dst: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    put_u16_le(b.len() as u16, dst);
    dst.extend_from_slice(b);
}
fn get_str(src: &mut &[u8]) -> Option<String> {
    let n = get_u16_le(src)? as usize;
    let b = get_bytes(src, n)?;
    std::str::from_utf8(b).ok().map(|s| s.to_string())
}

fn encode_binary_meta(m: &BinaryMeta) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + m.basename.len() + m.hostname.len());
    v.extend_from_slice(&m.md5);
    put_u64_le(m.first_seen_ts, &mut v);
    put_u64_le(m.last_seen_ts, &mut v);
    put_u64_le(m.obs_count, &mut v);
    put_str(&mut v, &m.basename);
    put_str(&mut v, &m.hostname);
    v
}
fn decode_binary_meta(mut b: &[u8]) -> Option<BinaryMeta> {
    if b.len() < 16 {
        return None;
    }
    let mut md5 = [0u8; 16];
    md5.copy_from_slice(&b[..16]);
    b = &b[16..];
    Some(BinaryMeta {
        md5,
        first_seen_ts: get_u64_le(&mut b)?,
        last_seen_ts: get_u64_le(&mut b)?,
        obs_count: get_u64_le(&mut b)?,
        basename: get_str(&mut b)?,
        hostname: get_str(&mut b)?,
    })
}

fn encode_key_md5_stats(s: &KeyMd5Stats) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 8 + 32);
    put_u32_le(s.obs_count, &mut v);
    put_u64_le(s.last_ts_sec, &mut v);
    v.extend_from_slice(&s.last_version_id);
    v
}
fn decode_key_md5_stats(mut b: &[u8]) -> Option<KeyMd5Stats> {
    Some(KeyMd5Stats {
        obs_count: get_u32_le(&mut b)?,
        last_ts_sec: get_u64_le(&mut b)?,
        last_version_id: {
            let bytes = get_bytes(&mut b, 32)?;
            let mut a = [0u8; 32];
            a.copy_from_slice(bytes);
            a
        },
    })
}

fn encode_key_bins(vv: &[KeyMd5Entry]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + vv.len() * (16 + 4));
    v.push(vv.len() as u8);
    for e in vv.iter() {
        v.extend_from_slice(&e.md5);
        put_u32_le(e.obs_count, &mut v);
    }
    v
}
fn decode_key_bins(mut b: &[u8]) -> Option<Vec<KeyMd5Entry>> {
    let n = if b.is_empty() {
        0
    } else {
        let n = b[0] as usize;
        b = &b[1..];
        n
    };
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let md5 = {
            let s = get_bytes(&mut b, 16)?;
            let mut arr = [0u8; 16];
            arr.copy_from_slice(s);
            arr
        };
        let cnt = get_u32_le(&mut b)?;
        out.push(KeyMd5Entry {
            md5,
            obs_count: cnt,
        });
    }
    Some(out)
}

fn encode_version_stats(vs: &VersionStats) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 8 + 8 + 4 + 1 + vs.top_md5s.len() * (16 + 4));
    put_u32_le(vs.total_obs, &mut v);
    put_u64_le(vs.first_ts_sec, &mut v);
    put_u64_le(vs.last_ts_sec, &mut v);
    put_u32_le(vs.num_binaries, &mut v);
    v.push(vs.top_md5s.len() as u8);
    for e in &vs.top_md5s {
        v.extend_from_slice(&e.md5);
        put_u32_le(e.obs_count, &mut v);
    }
    v
}
fn decode_version_stats(mut b: &[u8]) -> Option<VersionStats> {
    let total_obs = get_u32_le(&mut b)?;
    let first_ts_sec = get_u64_le(&mut b)?;
    let last_ts_sec = get_u64_le(&mut b)?;
    let num_binaries = get_u32_le(&mut b)?;
    let n = if b.is_empty() {
        0
    } else {
        let n = b[0] as usize;
        b = &b[1..];
        n
    };
    let mut top_md5s = Vec::with_capacity(n);
    for _ in 0..n {
        let md5 = {
            let s = get_bytes(&mut b, 16)?;
            let mut a = [0u8; 16];
            a.copy_from_slice(s);
            a
        };
        let cnt = get_u32_le(&mut b)?;
        top_md5s.push(KeyMd5Entry {
            md5,
            obs_count: cnt,
        });
    }
    Some(VersionStats {
        total_obs,
        first_ts_sec,
        last_ts_sec,
        num_binaries,
        top_md5s,
    })
}

fn encode_basenames(names: &[String]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + names.len() * 18);
    v.push(names.len() as u8);
    for name in names {
        let b = name.as_bytes();
        let len = (b.len().min(u16::MAX as usize)) as u16;
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&b[..len as usize]);
    }
    v
}

fn decode_basenames(mut b: &[u8]) -> Option<Vec<String>> {
    if b.is_empty() {
        return Some(Vec::new());
    }
    let count = b[0] as usize;
    b = &b[1..];

    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let len = get_u16_le(&mut b)? as usize;
        let bytes = get_bytes(&mut b, len)?;
        let s = std::str::from_utf8(bytes).ok()?.to_string();
        out.push(s);
    }
    Some(out)
}

fn sanitize_basename(input: &str) -> String {
    let p = Path::new(input);
    let base = p
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(input)
        .trim()
        .to_string();
    if base.len() > 255 {
        base[..255].to_string()
    } else {
        base
    }
}
