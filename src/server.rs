use crate::{config::Config, db::Database, lumina, metrics::METRICS, rpc::*, util::hex_dump};
use log::*;
use std::{
    io,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;
use tokio::{net::TcpListener, time::timeout};

use std::sync::atomic::{AtomicUsize, Ordering};

struct Budget {
    limit: usize,
    used: AtomicUsize,
}

impl Budget {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            used: AtomicUsize::new(0),
        }
    }

    fn try_reserve(self: &Arc<Self>, n: usize) -> Option<BudgetGuard> {
        loop {
            let cur = self.used.load(Ordering::Relaxed);
            let new = cur.checked_add(n)?;
            if new > self.limit {
                return None;
            }
            if self
                .used
                .compare_exchange(cur, new, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(BudgetGuard {
                    b: Arc::clone(self),
                    n,
                });
            }
        }
    }

    fn release(&self, n: usize) {
        self.used.fetch_sub(n, Ordering::AcqRel);
    }
}

struct BudgetGuard {
    b: Arc<Budget>,
    n: usize,
}

impl Drop for BudgetGuard {
    fn drop(&mut self) {
        self.b.release(self.n);
    }
}

struct OwnedFrame {
    buf: Vec<u8>,
    _conn: BudgetGuard,
    _global: BudgetGuard,
}

impl OwnedFrame {
    fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

async fn read_multiproto_bounded<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
    is_legacy: Option<bool>,
    max_len_field: usize,
    conn_budget: &Arc<Budget>,
    global_budget: &Arc<Budget>,
) -> io::Result<OwnedFrame> {
    let mut head = [0u8; 5];

    r.read_exact(&mut head[..4]).await?;
    let len_field = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;

    if len_field > max_len_field {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }

    r.read_exact(&mut head[4..5]).await?;
    let typ = head[4];

    let is_legacy_final = if let Some(b) = is_legacy {
        b
    } else {
        typ == 0x0d
    };

    let to_read_payload = if is_legacy_final {
        len_field
    } else {
        if len_field == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid length"));
        }
        len_field - 1
    };

    let total_buf = 1usize
        .checked_add(to_read_payload)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "length overflow"))?;

    let g1 = conn_budget.clone().try_reserve(total_buf).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            "per-connection memory budget exceeded",
        )
    })?;

    let g2 = global_budget
        .clone()
        .try_reserve(total_buf)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "global memory budget exceeded"))?;

    let mut data = vec![0u8; total_buf];
    data[0] = typ;

    r.read_exact(&mut data[1..]).await?;

    Ok(OwnedFrame {
        buf: data,
        _conn: g1,
        _global: g2,
    })
}

async fn handle_client<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
    cfg: Arc<Config>,
    db: Arc<Database>,
    global_budget: Arc<Budget>,
) -> io::Result<()> {
    let conn_budget = Arc::new(Budget::new(cfg.limits.per_connection_inflight_bytes));

    let hello_frame = match timeout(
        Duration::from_millis(cfg.limits.hello_timeout_ms),
        read_multiproto_bounded(
            &mut stream,
            None,
            cfg.limits.max_hello_frame_bytes,
            &conn_budget,
            &global_budget,
        ),
    )
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            METRICS
                .timeouts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(());
        }
    };

    let hello_bytes = hello_frame.as_slice();
    debug!("Received hello message, {} bytes", hello_bytes.len());

    if log_enabled!(log::Level::Debug) {
        debug!("Hello frame hex dump:\n{}", hex_dump(hello_bytes, 256));
    }

    if hello_bytes.is_empty() {
        write_all(&mut stream, &encode_fail(0, "bad sequence")).await?;
        return Ok(());
    }

    let msg_type = hello_bytes[0];
    let payload = &hello_bytes[1..];

    const LUMINA_MSG_HELLO: u8 = 0x0d;
    let is_lumina = msg_type == LUMINA_MSG_HELLO;

    // Debug: dump hello message to file if enabled (only for Lumina protocol)
    if cfg.debug.dump_hello && is_lumina {
        if let Ok(raw) = lumina::parse_lumina_hello_raw(payload) {
            // Only dump if license is at least 128 bytes
            if raw.license_data.len() >= 128 {
                use std::io::Write;
                let hash = {
                    use std::collections::hash_map::DefaultHasher;
                    use std::hash::{Hash, Hasher};
                    let mut hasher = DefaultHasher::new();
                    raw.license_data.hash(&mut hasher);
                    hasher.finish()
                };
                let filename = format!("{:016x}.txt", hash);
                let path = std::path::Path::new(&cfg.debug.dump_hello_dir).join(&filename);
                if let Err(e) = std::fs::create_dir_all(&cfg.debug.dump_hello_dir) {
                    warn!("Failed to create dump directory: {}", e);
                } else if let Ok(mut f) = std::fs::File::create(&path) {
                    let id_hex = raw.id_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                    let content = format!(
                        "ID: {}\n\nLicense:\n\n{}\n\nCredentials: {} / {}\n",
                        id_hex,
                        String::from_utf8_lossy(&raw.license_data),
                        raw.username,
                        raw.password
                    );
                    if let Err(e) = f.write_all(content.as_bytes()) {
                        warn!("Failed to write hello dump: {}", e);
                    } else {
                        debug!("Dumped hello message to {:?}", path);
                    }
                }
            }
        }
    }

    let hello = if is_lumina {
        debug!("Detected Lumina Hello message (0x0d)");
        match lumina::parse_lumina_hello(payload) {
            Ok(v) => HelloReq {
                protocol_version: v.protocol_version,
                username: v.username,
                password: v.password,
            },
            Err(e) => {
                error!("Failed to parse Lumina Hello: {}", e);
                write_all(&mut stream, &encode_fail(0, "invalid hello")).await?;
                return Ok(());
            }
        }
    } else if msg_type == MSG_HELLO {
        debug!("Detected new Hello message (0x01)");
        match decode_hello(payload) {
            Ok(v) => v,
            Err(_) => {
                write_all(&mut stream, &encode_fail(0, "invalid hello")).await?;
                return Ok(());
            }
        }
    } else {
        error!("Unknown Hello message type: 0x{:02x}", msg_type);
        write_all(&mut stream, &encode_fail(0, "bad sequence")).await?;
        return Ok(());
    };

    debug!(
        "Hello request: protocol_version={}, username={}",
        hello.protocol_version, hello.username
    );

    if hello.protocol_version <= 4 {
        METRICS
            .lumina_v0_4
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    } else {
        METRICS
            .lumina_v5p
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    if hello.username != "guest" {
        if is_lumina {
            lumina::send_lumina_fail(
                &mut stream,
                1,
                &format!(
                    "{}: invalid username or password. Try logging in with `guest` instead.",
                    cfg.lumina.server_name
                ),
            )
            .await?;
        } else {
            write_all(
                &mut stream,
                &encode_fail(
                    1,
                    &format!(
                        "{}: invalid username or password. Try logging in with `guest` instead.",
                        cfg.lumina.server_name
                    ),
                ),
            )
            .await?;
        }
        return Ok(());
    }

    if is_lumina {
        if hello.protocol_version <= 4 {
            lumina::send_lumina_ok(&mut stream).await?;
        } else {
            let mut features = 0u32;
            if cfg.lumina.allow_deletes {
                features |= 0x02;
            }
            lumina::send_lumina_hello_result(&mut stream, features).await?;
        }
    } else {
        if hello.protocol_version <= 4 {
            write_all(&mut stream, &encode_ok()).await?;
        } else {
            let mut features = 0u32;
            if cfg.lumina.allow_deletes {
                features |= 0x02;
            }
            write_all(&mut stream, &encode_hello_ok(features)).await?;
        }
    }

    loop {
        let frame = if is_lumina {
            match timeout(
                Duration::from_millis(cfg.limits.command_timeout_ms),
                read_multiproto_bounded(
                    &mut stream,
                    Some(true),
                    cfg.limits.max_cmd_frame_bytes,
                    &conn_budget,
                    &global_budget,
                ),
            )
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Ok(Err(e)) => {
                    error!("read error: {}", e);
                    return Ok(());
                }
                Err(_) => {
                    METRICS
                        .timeouts
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    lumina::send_lumina_fail(
                        &mut stream,
                        0,
                        &format!("{} client idle for too long.\n", cfg.lumina.server_name),
                    )
                    .await
                    .ok();
                    return Ok(());
                }
            }
        } else {
            match timeout(
                Duration::from_millis(cfg.limits.command_timeout_ms),
                read_multiproto_bounded(
                    &mut stream,
                    Some(false),
                    cfg.limits.max_cmd_frame_bytes,
                    &conn_budget,
                    &global_budget,
                ),
            )
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Ok(Err(e)) => {
                    error!("read error: {}", e);
                    return Ok(());
                }
                Err(_) => {
                    METRICS
                        .timeouts
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    write_all(
                        &mut stream,
                        &encode_fail(
                            0,
                            &format!("{} client idle for too long.\n", cfg.lumina.server_name),
                        ),
                    )
                    .await
                    .ok();
                    return Ok(());
                }
            }
        };

        let frame_bytes = frame.as_slice();

        if frame_bytes.is_empty() {
            if is_lumina {
                lumina::send_lumina_fail(
                    &mut stream,
                    0,
                    &format!("{}: error: invalid data.\n", cfg.lumina.server_name),
                )
                .await?;
            } else {
                write_all(
                    &mut stream,
                    &encode_fail(
                        0,
                        &format!("{}: error: invalid data.\n", cfg.lumina.server_name),
                    ),
                )
                .await?;
            }
            continue;
        }

        let typ = frame_bytes[0];
        let pld = &frame_bytes[1..];

        debug!(
            "Incoming message: type=0x{:02x}, payload_size={}",
            typ,
            pld.len()
        );

        if is_lumina {
            debug!("Lumina command received: 0x{:02x}", typ);

            match typ {
                0x0e => {
                    // PullMetadata
                    let caps = lumina::LuminaCaps {
                        max_funcs: cfg.limits.max_pull_items,
                        max_name_bytes: cfg.limits.max_name_bytes,
                        max_data_bytes: cfg.limits.max_data_bytes,
                        max_cstr_bytes: cfg.limits.lumina_max_cstr_bytes,
                        max_hash_bytes: cfg.limits.lumina_max_hash_bytes,
                    };

                    let pull_msg = match lumina::parse_lumina_pull_metadata(pld, caps) {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Failed to parse Lumina PullMetadata: {}", e);
                            lumina::send_lumina_fail(&mut stream, 0, "invalid pull").await?;
                            continue;
                        }
                    };

                    // Collect keys in request order
                    let mut keys: Vec<u128> = Vec::with_capacity(pull_msg.funcs.len());
                    for func in &pull_msg.funcs {
                        if func.mb_hash.len() != 16 {
                            keys.push(0);
                        } else {
                            let key = u128::from_be_bytes([
                                func.mb_hash[0],
                                func.mb_hash[1],
                                func.mb_hash[2],
                                func.mb_hash[3],
                                func.mb_hash[4],
                                func.mb_hash[5],
                                func.mb_hash[6],
                                func.mb_hash[7],
                                func.mb_hash[8],
                                func.mb_hash[9],
                                func.mb_hash[10],
                                func.mb_hash[11],
                                func.mb_hash[12],
                                func.mb_hash[13],
                                func.mb_hash[14],
                                func.mb_hash[15],
                            ]);
                            keys.push(key);
                        }
                    }

                    let qctx = crate::db::QueryContext {
                        keys: &keys,
                        md5: None,
                        basename: None,
                        hostname: None,
                    };
                    let selected = match db.select_versions_for_batch(&qctx).await {
                        Ok(v) => v,
                        Err(e) => {
                            error!("scoring error: {}", e);
                            // Fallback to legacy latest-per-key
                            let mut v = Vec::with_capacity(keys.len());
                            for &k in &keys {
                                v.push(
                                    db.get_latest(k)
                                        .await
                                        .ok()
                                        .flatten()
                                        .map(|f| (f.popularity, f.len_bytes, f.name, f.data)),
                                );
                            }
                            v
                        }
                    };

                    let mut maybe_funcs: Vec<Option<(u32, u32, String, Vec<u8>)>> = selected;
                    let mut statuses: Vec<u32> = maybe_funcs
                        .iter()
                        .map(|o| if o.is_some() { 0 } else { 1 })
                        .collect();

                    METRICS
                        .queried_funcs
                        .fetch_add(keys.len() as u64, std::sync::atomic::Ordering::Relaxed);

                    // Upstream fetch for remaining misses
                    if !cfg.upstreams.is_empty() {
                        let mut missing_keys = Vec::new();
                        let mut missing_pos = Vec::new();
                        for (i, (&k, st)) in keys.iter().zip(statuses.iter()).enumerate() {
                            if k != 0 && *st == 1 {
                                missing_keys.push(k);
                                missing_pos.push(i);
                            }
                        }
                        if !missing_keys.is_empty() {
                            match crate::upstream::fetch_from_upstreams(
                                &cfg.upstreams,
                                &missing_keys,
                            )
                            .await
                            {
                                Ok(fetched) => {
                                    let mut new_inserts_owned: Vec<(
                                        u128,
                                        u32,
                                        u32,
                                        String,
                                        Vec<u8>,
                                    )> = Vec::new();
                                    for (j, item) in fetched.into_iter().enumerate() {
                                        let idx = missing_pos[j];
                                        if let Some((pop, len, name, data)) = item {
                                            statuses[idx] = 0;
                                            new_inserts_owned.push((
                                                missing_keys[j],
                                                pop,
                                                len,
                                                name.clone(),
                                                data.clone(),
                                            ));
                                            maybe_funcs[idx] = Some((pop, len, name, data));
                                        }
                                    }
                                    let new_inserts: Vec<(u128, u32, u32, &str, &[u8])> =
                                        new_inserts_owned
                                            .iter()
                                            .map(|(k, p, l, n, d)| {
                                                (*k, *p, *l, n.as_str(), d.as_slice())
                                            })
                                            .collect();
                                    if !new_inserts.is_empty() {
                                        match db.push(&new_inserts).await {
                                            Ok(st) => {
                                                let new_funcs =
                                                    st.iter().filter(|&&v| v == 1).count() as u64;
                                                let updated_funcs =
                                                    st.iter().filter(|&&v| v == 0).count() as u64;
                                                METRICS.pushes.fetch_add(
                                                    (new_funcs + updated_funcs) as u64,
                                                    std::sync::atomic::Ordering::Relaxed,
                                                );
                                                METRICS.new_funcs.fetch_add(
                                                    new_funcs,
                                                    std::sync::atomic::Ordering::Relaxed,
                                                );
                                            }
                                            Err(e) => {
                                                error!("db push after upstream: {}", e);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("upstream pull failed: {}", e);
                                }
                            }
                        }
                    }

                    let mut found_list = Vec::new();
                    for it in maybe_funcs.into_iter() {
                        if let Some(v) = it {
                            found_list.push(v);
                        }
                    }

                    METRICS.pulls.fetch_add(
                        found_list.len() as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    debug!(
                        "Lumina PULL response: {} found, {} not found",
                        found_list.len(),
                        statuses.iter().filter(|&&s| s == 1).count()
                    );
                    lumina::send_lumina_pull_result(&mut stream, &statuses, &found_list).await?;
                }
                0x10 => {
                    // PushMetadata
                    let caps = lumina::LuminaCaps {
                        max_funcs: cfg.limits.max_push_items,
                        max_name_bytes: cfg.limits.max_name_bytes,
                        max_data_bytes: cfg.limits.max_data_bytes,
                        max_cstr_bytes: cfg.limits.lumina_max_cstr_bytes,
                        max_hash_bytes: cfg.limits.lumina_max_hash_bytes,
                    };

                    let push_msg = match lumina::parse_lumina_push_metadata(pld, caps) {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Failed to parse Lumina PushMetadata: {}", e);
                            lumina::send_lumina_fail(&mut stream, 0, "invalid push").await?;
                            continue;
                        }
                    };

                    debug!("Lumina PUSH request: {} items", push_msg.funcs.len());

                    // Print push request metadata
                    println!("\n=== PUSH REQUEST ===");
                    println!("IDB Path:     {}", push_msg.idb_path);
                    println!("File Path:    {}", push_msg.file_path);
                    println!(
                        "MD5:          {}",
                        push_msg
                            .md5
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<String>()
                    );
                    println!("Functions:    {}", push_msg.funcs.len());
                    println!("===================\n");

                    let mut inlined: Vec<(u128, u32, u32, &str, &[u8])> =
                        Vec::with_capacity(push_msg.funcs.len());
                    for func in &push_msg.funcs {
                        if func.hash.len() != 16 {
                            error!("Invalid hash length: {}", func.hash.len());
                            continue;
                        }
                        let key = u128::from_be_bytes([
                            func.hash[0],
                            func.hash[1],
                            func.hash[2],
                            func.hash[3],
                            func.hash[4],
                            func.hash[5],
                            func.hash[6],
                            func.hash[7],
                            func.hash[8],
                            func.hash[9],
                            func.hash[10],
                            func.hash[11],
                            func.hash[12],
                            func.hash[13],
                            func.hash[14],
                            func.hash[15],
                        ]);
                        inlined.push((key, 0, func.func_len, &func.name, &func.func_data));
                    }

                    // Extract binary context
                    let basename = std::path::Path::new(&push_msg.file_path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("");
                    let ctx = crate::db::PushContext {
                        md5: Some(push_msg.md5),
                        basename: Some(basename),
                        hostname: Some(push_msg.hostname.as_str()),
                    };

                    match db.push_with_ctx(&inlined, &ctx).await {
                        Ok(status) => {
                            let new_funcs = status.iter().filter(|&&v| v == 1).count() as u64;
                            let updated_funcs = status.iter().filter(|&&v| v == 0).count() as u64;
                            let skipped_funcs = status.iter().filter(|&&v| v == 2).count() as u64;

                            METRICS.pushes.fetch_add(
                                (new_funcs + updated_funcs) as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            METRICS
                                .new_funcs
                                .fetch_add(new_funcs, std::sync::atomic::Ordering::Relaxed);

                            debug!(
                                "Lumina PUSH response: {} new, {} updated, {} unchanged",
                                new_funcs, updated_funcs, skipped_funcs
                            );

                            let lumina_status: Vec<u32> =
                                status.iter().map(|&s| if s == 2 { 0 } else { 1 }).collect();
                            lumina::send_lumina_push_result(&mut stream, &lumina_status).await?;
                        }
                        Err(e) => {
                            error!("db push: {}", e);
                            lumina::send_lumina_fail(
                                &mut stream,
                                0,
                                &format!(
                                    "{}: db error; please try again later",
                                    cfg.lumina.server_name
                                ),
                            )
                            .await?;
                        }
                    }
                }
                0x18 => {
                    // DelHistory
                    if !cfg.lumina.allow_deletes {
                        lumina::send_lumina_fail(
                            &mut stream,
                            2,
                            &format!(
                                "{}: Delete command is disabled on this server.",
                                cfg.lumina.server_name
                            ),
                        )
                        .await?;
                        continue;
                    }
                    debug!("Lumina DEL request (not fully implemented)");
                    lumina::send_lumina_del_result(&mut stream, 0).await?;
                }
                0x2f => {
                    // GetFuncHistories
                    let caps = lumina::LuminaCaps {
                        max_funcs: cfg.limits.max_hist_items,
                        max_name_bytes: cfg.limits.max_name_bytes,
                        max_data_bytes: cfg.limits.max_data_bytes,
                        max_cstr_bytes: cfg.limits.lumina_max_cstr_bytes,
                        max_hash_bytes: cfg.limits.lumina_max_hash_bytes,
                    };

                    let hist_msg = match lumina::parse_lumina_get_func_histories(pld, caps) {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Failed to parse Lumina GetFuncHistories: {}", e);
                            lumina::send_lumina_fail(&mut stream, 0, "invalid hist").await?;
                            continue;
                        }
                    };

                    debug!("Lumina HIST request: {} keys", hist_msg.funcs.len());

                    let limit = if cfg.lumina.get_history_limit == 0 {
                        0
                    } else {
                        cfg.lumina.get_history_limit
                    };
                    if limit == 0 {
                        lumina::send_lumina_fail(
                            &mut stream,
                            4,
                            &format!(
                                "{}: function histories are disabled on this server.",
                                cfg.lumina.server_name
                            ),
                        )
                        .await?;
                        continue;
                    }

                    let mut statuses = Vec::new();
                    let mut histories = Vec::new();

                    for func in &hist_msg.funcs {
                        if func.mb_hash.len() != 16 {
                            statuses.push(0);
                            continue;
                        }
                        let key = u128::from_be_bytes([
                            func.mb_hash[0],
                            func.mb_hash[1],
                            func.mb_hash[2],
                            func.mb_hash[3],
                            func.mb_hash[4],
                            func.mb_hash[5],
                            func.mb_hash[6],
                            func.mb_hash[7],
                            func.mb_hash[8],
                            func.mb_hash[9],
                            func.mb_hash[10],
                            func.mb_hash[11],
                            func.mb_hash[12],
                            func.mb_hash[13],
                            func.mb_hash[14],
                            func.mb_hash[15],
                        ]);

                        match db.get_history(key, limit).await {
                            Ok(hist) if !hist.is_empty() => {
                                statuses.push(1);
                                let hist_tuples: Vec<(u64, String, Vec<u8>)> = hist
                                    .into_iter()
                                    .map(|(ts, name, data)| (ts as u64, name, data))
                                    .collect();
                                histories.push(hist_tuples);
                            }
                            Ok(_) => {
                                statuses.push(0);
                            }
                            Err(e) => {
                                error!("db hist: {}", e);
                                lumina::send_lumina_fail(
                                    &mut stream,
                                    3,
                                    &format!("{}: db error", cfg.lumina.server_name),
                                )
                                .await?;
                                return Ok(());
                            }
                        }
                    }

                    debug!("Lumina HIST response: {} histories found", histories.len());
                    lumina::send_lumina_histories_result(&mut stream, &statuses, &histories)
                        .await?;
                }
                _ => {
                    warn!("Unknown Lumina command: 0x{:02x}", typ);
                    lumina::send_lumina_fail(
                        &mut stream,
                        0,
                        &format!("{}: Unknown command.", cfg.lumina.server_name),
                    )
                    .await?;
                    continue;
                }
            }
            continue;
        }

        let msg_start = Instant::now();

        match typ {
            MSG_PULL => {
                let keys = match decode_pull(pld, cfg.limits.max_pull_items) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("decode_pull: {:?}", e);
                        write_all(&mut stream, &encode_fail(0, "invalid pull")).await?;
                        continue;
                    }
                };

                debug!("PULL request: {} keys", keys.len());
                METRICS
                    .queried_funcs
                    .fetch_add(keys.len() as u64, std::sync::atomic::Ordering::Relaxed);

                let qctx = crate::db::QueryContext {
                    keys: &keys,
                    md5: None,
                    basename: None,
                    hostname: None,
                };
                let selected = match db.select_versions_for_batch(&qctx).await {
                    Ok(v) => v,
                    Err(e) => {
                        error!("scoring error: {}", e);
                        let mut v = Vec::with_capacity(keys.len());
                        for &k in &keys {
                            v.push(
                                db.get_latest(k)
                                    .await
                                    .ok()
                                    .flatten()
                                    .map(|f| (f.popularity, f.len_bytes, f.name, f.data)),
                            );
                        }
                        v
                    }
                };

                let mut maybe_funcs: Vec<Option<(u32, u32, String, Vec<u8>)>> = selected;
                let mut statuses: Vec<u32> = maybe_funcs
                    .iter()
                    .map(|o| if o.is_some() { 0 } else { 1 })
                    .collect();

                // Upstream fetch for misses
                if !cfg.upstreams.is_empty() {
                    let mut missing_keys = Vec::new();
                    let mut missing_pos = Vec::new();
                    for (i, (&k, st)) in keys.iter().zip(statuses.iter()).enumerate() {
                        if *st == 1 {
                            // Skip keys that are in the failure cache
                            if !db.failure_cache.is_failed(k) {
                                missing_keys.push(k);
                                missing_pos.push(i);
                            }
                        }
                    }
                    if !missing_keys.is_empty() {
                        debug!("Upstream fetch: {} keys (after filtering failure cache)", missing_keys.len());
                        match crate::upstream::fetch_from_upstreams(&cfg.upstreams, &missing_keys)
                            .await
                        {
                            Ok(fetched) => {
                                let mut new_inserts_owned: Vec<(u128, u32, u32, String, Vec<u8>)> =
                                    Vec::new();
                                for (j, item) in fetched.into_iter().enumerate() {
                                    let idx = missing_pos[j];
                                    let key = missing_keys[j];
                                    if let Some((pop, len, name, data)) = item {
                                        statuses[idx] = 0;
                                        new_inserts_owned.push((
                                            key,
                                            pop,
                                            len,
                                            name.clone(),
                                            data.clone(),
                                        ));
                                        maybe_funcs[idx] = Some((pop, len, name, data));
                                    } else {
                                        // Not found in upstream - add to failure cache
                                        db.failure_cache.insert(key);
                                    }
                                }
                                let new_inserts: Vec<(u128, u32, u32, &str, &[u8])> =
                                    new_inserts_owned
                                        .iter()
                                        .map(|(k, p, l, n, d)| {
                                            (*k, *p, *l, n.as_str(), d.as_slice())
                                        })
                                        .collect();
                                if !new_inserts_owned.is_empty() {
                                    match db.push(&new_inserts).await {
                                        Ok(st) => {
                                            let new_funcs =
                                                st.iter().filter(|&&v| v == 1).count() as u64;
                                            let updated_funcs =
                                                st.iter().filter(|&&v| v == 0).count() as u64;
                                            METRICS.pushes.fetch_add(
                                                (new_funcs + updated_funcs) as u64,
                                                std::sync::atomic::Ordering::Relaxed,
                                            );
                                            METRICS.new_funcs.fetch_add(
                                                new_funcs,
                                                std::sync::atomic::Ordering::Relaxed,
                                            );
                                        }
                                        Err(e) => {
                                            error!("db push after upstream: {}", e);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("upstream pull failed: {}", e);
                            }
                        }
                    }
                }

                let mut found = Vec::new();
                for it in maybe_funcs.into_iter() {
                    if let Some(v) = it {
                        found.push(v);
                    }
                }

                METRICS
                    .pulls
                    .fetch_add(found.len() as u64, std::sync::atomic::Ordering::Relaxed);
                debug!(
                    "PULL response: {} found, {} not found (took {:?})",
                    found.len(),
                    statuses.iter().filter(|&&s| s == 1).count(),
                    msg_start.elapsed()
                );
                write_all(&mut stream, &encode_pull_ok(&statuses, &found)).await?;
            }
            MSG_PUSH => {
                let caps = PushCaps {
                    max_items: cfg.limits.max_push_items,
                    max_name_bytes: cfg.limits.max_name_bytes,
                    max_data_bytes: cfg.limits.max_data_bytes,
                };

                let items = match decode_push(pld, &caps) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("decode_push: {:?}", e);
                        write_all(&mut stream, &encode_fail(0, "invalid push")).await?;
                        continue;
                    }
                };

                debug!("PUSH request: {} items", items.len());

                if log_enabled!(log::Level::Debug) {
                    for (i, item) in items.iter().enumerate().take(5) {
                        debug!(
                            "  Item[{}]: key=0x{:032x}, pop={}, len={}, name='{}'",
                            i, item.key, item.popularity, item.len_bytes, item.name
                        );
                        debug!("    Data hex dump:\n{}", hex_dump(&item.data, 128));
                    }
                    if items.len() > 5 {
                        debug!("  ... and {} more items", items.len() - 5);
                    }
                }

                let mut inlined: Vec<(u128, u32, u32, &str, &[u8])> =
                    Vec::with_capacity(items.len());
                for it in &items {
                    inlined.push((it.key, it.popularity, it.len_bytes, &it.name, &it.data));
                }

                let res = db.push(&inlined).await;

                match res {
                    Ok(status) => {
                        let new_funcs = status.iter().filter(|&&v| v == 1).count() as u64;
                        let updated_funcs = status.iter().filter(|&&v| v == 0).count() as u64;
                        let skipped_funcs = status.iter().filter(|&&v| v == 2).count() as u64;
                        METRICS.pushes.fetch_add(
                            (new_funcs + updated_funcs) as u64,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        METRICS
                            .new_funcs
                            .fetch_add(new_funcs, std::sync::atomic::Ordering::Relaxed);
                        
                        // Remove successfully pushed keys from failure cache
                        for it in &items {
                            db.failure_cache.remove(it.key);
                        }
                        
                        debug!(
                            "PUSH response: {} new, {} updated, {} unchanged (took {:?})",
                            new_funcs,
                            updated_funcs,
                            skipped_funcs,
                            msg_start.elapsed()
                        );
                        write_all(&mut stream, &encode_push_ok(&status)).await?;
                    }
                    Err(e) => {
                        error!("db push: {}", e);
                        write_all(
                            &mut stream,
                            &encode_fail(
                                0,
                                &format!(
                                    "{}: db error; please try again later..\n",
                                    cfg.lumina.server_name
                                ),
                            ),
                        )
                        .await?;
                    }
                }
            }
            MSG_DEL => {
                if !cfg.lumina.allow_deletes {
                    write_all(
                        &mut stream,
                        &encode_fail(
                            2,
                            &format!(
                                "{}: Delete command is disabled on this server.",
                                cfg.lumina.server_name
                            ),
                        ),
                    )
                    .await?;
                    continue;
                }

                let keys = match decode_del(pld, cfg.limits.max_del_items) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("decode_del: {:?}", e);
                        write_all(&mut stream, &encode_fail(0, "invalid del")).await?;
                        continue;
                    }
                };

                debug!("DEL request: {} keys", keys.len());

                match db.delete_keys(&keys).await {
                    Ok(n) => {
                        debug!(
                            "DEL response: {} keys deleted (took {:?})",
                            n,
                            msg_start.elapsed()
                        );
                        write_all(&mut stream, &encode_del_ok(n)).await?;
                    }
                    Err(e) => {
                        error!("db del: {}", e);
                        write_all(
                            &mut stream,
                            &encode_fail(
                                3,
                                &format!(
                                    "{}: db error, please try again later.",
                                    cfg.lumina.server_name
                                ),
                            ),
                        )
                        .await?;
                    }
                }
            }
            MSG_HIST => {
                let (limit_req, keys) = match decode_hist(pld, cfg.limits.max_hist_items) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("decode_hist: {:?}", e);
                        write_all(&mut stream, &encode_fail(0, "invalid hist")).await?;
                        continue;
                    }
                };

                debug!("HIST request: limit={}, {} keys", limit_req, keys.len());

                let limit = if cfg.lumina.get_history_limit == 0 {
                    0
                } else {
                    cfg.lumina.get_history_limit.min(limit_req)
                };
                if limit == 0 {
                    write_all(
                        &mut stream,
                        &encode_fail(
                            4,
                            &format!(
                                "{}: function histories are disabled on this server.",
                                cfg.lumina.server_name
                            ),
                        ),
                    )
                    .await?;
                    continue;
                }

                let mut statuses = Vec::with_capacity(keys.len());
                let mut logs = Vec::new();

                for k in keys {
                    match db.get_history(k, limit).await {
                        Ok(v) if !v.is_empty() => {
                            statuses.push(1);
                            logs.push(v);
                        }
                        Ok(_) => {
                            statuses.push(0);
                        }
                        Err(e) => {
                            error!("db hist: {}", e);
                            write_all(
                                &mut stream,
                                &encode_fail(
                                    3,
                                    &format!(
                                        "{}: db error, please try again later.",
                                        cfg.lumina.server_name
                                    ),
                                ),
                            )
                            .await?;
                            continue;
                        }
                    }
                }

                let found_histories = logs.len();
                debug!(
                    "HIST response: {} histories found (took {:?})",
                    found_histories,
                    msg_start.elapsed()
                );
                write_all(&mut stream, &encode_hist_ok(&statuses, &logs)).await?;
            }
            _ => {
                debug!(
                    "Unknown message type: 0x{:02x}, payload size: {} (took {:?})",
                    typ,
                    pld.len(),
                    msg_start.elapsed()
                );
                if log_enabled!(log::Level::Debug) && !pld.is_empty() {
                    debug!("Unknown message payload hex dump:\n{}", hex_dump(pld, 256));
                }
                write_all(
                    &mut stream,
                    &encode_fail(0, &format!("{}: invalid data.\n", cfg.lumina.server_name)),
                )
                .await?;
            }
        }
    }
}

#[inline]
fn looks_like_tls_client_hello(hdr6: &[u8]) -> bool {
    if hdr6.len() < 6 {
        return false;
    }
    if hdr6[0] != 0x16 {
        return false;
    }
    if hdr6[1] != 0x03 {
        return false;
    }
    if hdr6[2] > 0x04 {
        return false;
    }
    let len = u16::from_be_bytes([hdr6[3], hdr6[4]]) as usize;
    if len == 0 || len > (16 * 1024) {
        return false;
    }
    hdr6[5] == 0x01
}

pub async fn serve_binary_rpc(cfg: Arc<Config>, db: Arc<Database>) {
    let listener = TcpListener::bind(&cfg.lumina.bind_addr)
        .await
        .expect("bind failed");

    let global_budget = Arc::new(Budget::new(cfg.limits.global_inflight_bytes));

    let mut tls_acceptor = None;
    if cfg.lumina.use_tls {
        let tls = cfg.lumina.tls.as_ref().expect("tls config missing");
        let mut crt = std::fs::read(&tls.pkcs12_path).expect("read pkcs12 file");
        let pass = std::env::var(&tls.env_password_var).unwrap_or_default();
        let id = native_tls::Identity::from_pkcs12(&crt, &pass).expect("parse pkcs12");
        crt.iter_mut().for_each(|b| *b = 0);

        let mut builder = native_tls::TlsAcceptor::builder(id);

        if tls.min_protocol_sslv3 {
            builder.min_protocol_version(Some(native_tls::Protocol::Sslv3));
        }

        let acc = builder.build().expect("tls build");
        tls_acceptor = Some(tokio_native_tls::TlsAcceptor::from(acc));
    }

    info!(
        "binary RPC listening on {} secure={}",
        listener.local_addr().unwrap(),
        tls_acceptor.is_some()
    );

    loop {
        let (socket, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("accept: {}", e);
                continue;
            }
        };

        if METRICS
            .active_connections
            .load(std::sync::atomic::Ordering::Relaxed) as usize
            >= cfg.limits.max_active_conns
        {
            debug!("refusing connection {}; too many", addr);
            drop(socket);
            continue;
        }

        METRICS
            .active_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let cfg = cfg.clone();
        let db = db.clone();
        let acceptor = tls_acceptor.clone();
        let global_budget = global_budget.clone();

        tokio::spawn(async move {
            debug!("New connection from {}", addr);

            let res = if let Some(acc) = acceptor {
                let sniff_deadline = Duration::from_millis(cfg.limits.tls_handshake_timeout_ms);
                let is_tls = match tokio::time::timeout(sniff_deadline, async {
                    socket.readable().await.ok();
                    let mut hdr = [0u8; 6];
                    match socket.peek(&mut hdr).await {
                        Ok(n) if n >= 6 => looks_like_tls_client_hello(&hdr),
                        Ok(_) => false,
                        Err(_) => false,
                    }
                })
                .await
                {
                    Ok(v) => v,
                    Err(_) => false,
                };

                if is_tls {
                    debug!("{}: sniffed TLS ClientHello; upgrading connection", addr);
                    match tokio::time::timeout(
                        Duration::from_millis(cfg.limits.tls_handshake_timeout_ms),
                        acc.accept(socket),
                    )
                    .await
                    {
                        Ok(Ok(s)) => {
                            debug!("TLS handshake completed for {}", addr);
                            handle_client(s, cfg, db, global_budget).await
                        }
                        Ok(Err(e)) => {
                            debug!("tls accept {}: {}", addr, e);
                            Ok(())
                        }
                        Err(_) => {
                            debug!("tls handshake timeout {}", addr);
                            Ok(())
                        }
                    }
                } else {
                    debug!("{}: cleartext detected; proceeding without TLS", addr);
                    handle_client(socket, cfg, db, global_budget).await
                }
            } else {
                handle_client(socket, cfg, db, global_budget).await
            };

            if let Err(e) = res {
                debug!("connection {} ended: {}", addr, e);
            } else {
                debug!("connection {} closed cleanly", addr);
            }

            METRICS
                .active_connections
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
    }
}

#[cfg(test)]
mod sniff_tests {
    use super::looks_like_tls_client_hello;
    #[test]
    fn tls_header_positive_and_negative() {
        let good = [0x16, 0x03, 0x03, 0x00, 0x2a, 0x01];
        assert!(looks_like_tls_client_hello(&good));
        let clear = [0x00, 0x00, 0x00, 0x05, 0x01, 0xff];
        assert!(!looks_like_tls_client_hello(&clear));
    }
}
