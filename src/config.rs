use std::{fs, io};

#[derive(Clone, Debug)]
pub struct Limits {
    pub hello_timeout_ms: u64,
    pub command_timeout_ms: u64,
    pub tls_handshake_timeout_ms: u64,
    pub pull_timeout_ms: u64,
    pub push_timeout_ms: u64,
    pub max_active_conns: usize,
    pub max_hello_frame_bytes: usize,
    pub max_cmd_frame_bytes: usize,
    pub max_pull_items: usize,
    pub max_push_items: usize,
    pub max_del_items: usize,
    pub max_hist_items: usize,
    pub max_name_bytes: usize,
    pub max_data_bytes: usize,
    pub per_connection_inflight_bytes: usize,
    pub global_inflight_bytes: usize,
    pub lumina_max_cstr_bytes: usize,
    pub lumina_max_hash_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct TLS {
    pub pkcs12_path: String,
    pub env_password_var: String,
    pub min_protocol_sslv3: bool,
}

#[derive(Clone, Debug)]
pub struct Http {
    pub bind_addr: String,
}

#[derive(Clone, Debug)]
pub struct Engine {
    pub data_dir: String,
    pub segment_bytes: u64,
    pub shard_count: usize,
    pub index_capacity: usize,
    pub sync_interval_ms: u64,
    pub compaction_check_ms: u64,
    pub use_mmap_reads: bool,
    pub deduplicate_on_startup: bool,

    pub index_dir: Option<String>,
    pub index_memtable_max_entries: usize,
    pub index_block_entries: usize,
    pub index_level0_compact_trigger: usize,
}

#[derive(Clone, Debug)]
pub struct Debug {
    pub dump_hello: bool,
    pub dump_hello_dir: String,
}

#[derive(Clone, Debug)]
pub struct Lumina {
    pub bind_addr: String,
    pub server_name: String,
    pub allow_deletes: bool,
    pub get_history_limit: u32,
    pub use_tls: bool,
    pub tls: Option<TLS>,
}

// ---------------- Upstream configuration (optional) ----------------

#[derive(Clone, Debug)]
pub struct Upstream {
    pub enabled: bool,
    pub priority: u32,
    pub host: String,
    pub port: u16,
    pub use_tls: bool,
    pub insecure_no_verify: bool,
    pub hello_protocol_version: u32,
    pub license_path: Option<String>,
    pub timeout_ms: u64,
    pub batch_max: usize,
}

#[derive(Clone, Debug)]
pub struct Scoring {
    pub w_md5: f64,
    pub w_name: f64,
    pub w_coh: f64,
    pub w_stab: f64,
    pub w_rec: f64,
    pub w_pop_bin: f64,
    pub w_host: f64,
    pub w_origin: f64,
    pub max_versions_per_key: usize,
    pub max_md5_per_key: usize,
    pub max_md5_per_version: usize,
}

impl Default for Scoring {
    fn default() -> Self {
        Self {
            w_md5: 2.0,
            w_name: 1.0,
            w_coh: 2.0,
            w_stab: 0.5,
            w_rec: 0.5,
            w_pop_bin: 0.5,
            w_host: 0.25,
            w_origin: 0.25,
            max_versions_per_key: 16,
            max_md5_per_key: 16,
            max_md5_per_version: 16,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub limits: Limits,
    pub http: Option<Http>,
    pub engine: Engine,
    pub lumina: Lumina,
    pub upstreams: Vec<Upstream>,
    pub scoring: Scoring,
    pub debug: Debug,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            limits: Limits {
                hello_timeout_ms: 3000,
                command_timeout_ms: 15000,
                tls_handshake_timeout_ms: 5000,
                pull_timeout_ms: 15000,
                push_timeout_ms: 15000,
                max_active_conns: 2048,
                max_hello_frame_bytes: 16 * 1024 * 1024,
                max_cmd_frame_bytes: 256 * 1024 * 1024,
                max_pull_items: 524288,
                max_push_items: 524288,
                max_del_items: 524288,
                max_hist_items: 4096,
                max_name_bytes: 65535,
                max_data_bytes: 8 * 1024 * 1024,
                per_connection_inflight_bytes: 32 * 1024 * 1024,
                global_inflight_bytes: 512 * 1024 * 1024,
                lumina_max_cstr_bytes: 4096,
                lumina_max_hash_bytes: 64,
            },
            http: Some(Http {
                bind_addr: "127.0.0.1:8080".into(),
            }),
            engine: Engine {
                data_dir: "data".into(),
                segment_bytes: 1 << 30,
                shard_count: 64,
                index_capacity: 1 << 30,
                sync_interval_ms: 200,
                compaction_check_ms: 30000,
                use_mmap_reads: false,
                deduplicate_on_startup: false,
                index_dir: None,
                index_memtable_max_entries: 200_000,
                index_block_entries: 128,
                index_level0_compact_trigger: 8,
            },
            lumina: Lumina {
                bind_addr: "0.0.0.0:20667".into(),
                server_name: "dazhbog".into(),
                allow_deletes: false,
                get_history_limit: 0,
                use_tls: false,
                tls: None,
            },
            upstreams: Vec::new(),
            scoring: Scoring::default(),
            debug: Debug {
                dump_hello: false,
                dump_hello_dir: "debug_dumps".into(),
            },
        }
    }
}

impl Config {
    pub fn load(path: &str) -> io::Result<Self> {
        let s = fs::read_to_string(path)?;
        let mut cfg = Self::default();
        for (lineno, line) in s.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((lhs, rhs)) = line.split_once('=') else {
                continue;
            };
            let lhs = lhs.trim();
            let mut val = rhs.trim();
            if val.ends_with('#') {
                val = val.split('#').next().unwrap().trim();
            }
            let set = |section: &str, key: &str, val: &str, cfg: &mut Self| -> Result<(), String> {
                macro_rules! parse {
                    (s) => {
                        val.trim_matches('"').to_string()
                    };
                    (b) => {
                        match val {
                            "true" => true,
                            "false" => false,
                            _ => return Err(format!("bad bool {val}")),
                        }
                    };
                    (u) => {
                        val.parse::<u64>().map_err(|e| e.to_string())?
                    };
                    (usize_) => {
                        val.parse::<usize>().map_err(|e| e.to_string())?
                    };
                    (u32_) => {
                        val.parse::<u32>().map_err(|e| e.to_string())?
                    };
                    (u16_) => {
                        val.parse::<u16>().map_err(|e| e.to_string())?
                    };
                    (f64_) => {
                        val.parse::<f64>().map_err(|e| e.to_string())?
                    };
                }
                match (section, key) {
                    ("limits", "hello_timeout_ms") => cfg.limits.hello_timeout_ms = parse!(u),
                    ("limits", "command_timeout_ms") => cfg.limits.command_timeout_ms = parse!(u),
                    ("limits", "tls_handshake_timeout_ms") => {
                        cfg.limits.tls_handshake_timeout_ms = parse!(u)
                    }
                    ("limits", "pull_timeout_ms") => cfg.limits.pull_timeout_ms = parse!(u),
                    ("limits", "push_timeout_ms") => cfg.limits.push_timeout_ms = parse!(u),
                    ("limits", "max_active_conns") => cfg.limits.max_active_conns = parse!(usize_),
                    ("limits", "max_hello_frame_bytes") => {
                        cfg.limits.max_hello_frame_bytes = parse!(usize_)
                    }
                    ("limits", "max_cmd_frame_bytes") => {
                        cfg.limits.max_cmd_frame_bytes = parse!(usize_)
                    }
                    ("limits", "max_pull_items") => cfg.limits.max_pull_items = parse!(usize_),
                    ("limits", "max_push_items") => cfg.limits.max_push_items = parse!(usize_),
                    ("limits", "max_del_items") => cfg.limits.max_del_items = parse!(usize_),
                    ("limits", "max_hist_items") => cfg.limits.max_hist_items = parse!(usize_),
                    ("limits", "max_name_bytes") => cfg.limits.max_name_bytes = parse!(usize_),
                    ("limits", "max_data_bytes") => cfg.limits.max_data_bytes = parse!(usize_),
                    ("limits", "per_connection_inflight_bytes") => {
                        cfg.limits.per_connection_inflight_bytes = parse!(usize_)
                    }
                    ("limits", "global_inflight_bytes") => {
                        cfg.limits.global_inflight_bytes = parse!(usize_)
                    }
                    ("limits", "lumina_max_cstr_bytes") => {
                        cfg.limits.lumina_max_cstr_bytes = parse!(usize_)
                    }
                    ("limits", "lumina_max_hash_bytes") => {
                        cfg.limits.lumina_max_hash_bytes = parse!(usize_)
                    }

                    ("http", "bind_addr") => {
                        cfg.http
                            .get_or_insert_with(|| super::config::Http {
                                bind_addr: "".into(),
                            })
                            .bind_addr = parse!(s);
                    }

                    ("engine", "data_dir") => cfg.engine.data_dir = parse!(s),
                    ("engine", "segment_bytes") => cfg.engine.segment_bytes = parse!(u),
                    ("engine", "shard_count") => cfg.engine.shard_count = parse!(usize_),
                    ("engine", "index_capacity") => cfg.engine.index_capacity = parse!(usize_),
                    ("engine", "sync_interval_ms") => cfg.engine.sync_interval_ms = parse!(u),
                    ("engine", "compaction_check_ms") => cfg.engine.compaction_check_ms = parse!(u),
                    ("engine", "use_mmap_reads") => cfg.engine.use_mmap_reads = parse!(b),
                    ("engine", "deduplicate_on_startup") => {
                        cfg.engine.deduplicate_on_startup = parse!(b)
                    }

                    ("engine", "index_dir") => {
                        let v = parse!(s);
                        cfg.engine.index_dir = if v.is_empty() { None } else { Some(v) };
                    }
                    ("engine", "index_memtable_max_entries") => {
                        cfg.engine.index_memtable_max_entries = parse!(usize_)
                    }
                    ("engine", "index_block_entries") => {
                        cfg.engine.index_block_entries = parse!(usize_)
                    }
                    ("engine", "index_level0_compact_trigger") => {
                        cfg.engine.index_level0_compact_trigger = parse!(usize_)
                    }

                    ("lumina", "bind_addr") => cfg.lumina.bind_addr = parse!(s),
                    ("lumina", "server_name") => cfg.lumina.server_name = parse!(s),
                    ("lumina", "allow_deletes") => cfg.lumina.allow_deletes = parse!(b),
                    ("lumina", "get_history_limit") => cfg.lumina.get_history_limit = parse!(u32_),
                    ("lumina", "use_tls") => cfg.lumina.use_tls = parse!(b),

                    ("tls", "pkcs12_path") => {
                        cfg.lumina
                            .tls
                            .get_or_insert_with(|| super::config::TLS {
                                pkcs12_path: "".into(),
                                env_password_var: "PKCSPASSWD".into(),
                                min_protocol_sslv3: true,
                            })
                            .pkcs12_path = parse!(s);
                    }
                    ("tls", "env_password_var") => {
                        cfg.lumina
                            .tls
                            .get_or_insert_with(|| super::config::TLS {
                                pkcs12_path: "".into(),
                                env_password_var: "PKCSPASSWD".into(),
                                min_protocol_sslv3: true,
                            })
                            .env_password_var = parse!(s);
                    }
                    ("tls", "min_protocol_sslv3") => {
                        cfg.lumina
                            .tls
                            .get_or_insert_with(|| super::config::TLS {
                                pkcs12_path: "".into(),
                                env_password_var: "PKCSPASSWD".into(),
                                min_protocol_sslv3: true,
                            })
                            .min_protocol_sslv3 = parse!(b);
                    }

                    // ---------------- Upstream (optional) ----------------
                    ("upstream", key) if key.starts_with(|c: char| c.is_ascii_digit()) => {
                        let parts: Vec<&str> = key.splitn(2, '.').collect();
                        if parts.len() != 2 {
                            return Err(format!("invalid upstream key format: {}", key));
                        }
                        let idx = parts[0].parse::<usize>().map_err(|e| e.to_string())?;
                        let field = parts[1];

                        while cfg.upstreams.len() <= idx {
                            cfg.upstreams.push(Upstream {
                                enabled: false,
                                priority: cfg.upstreams.len() as u32,
                                host: String::new(),
                                port: 0,
                                use_tls: true,
                                insecure_no_verify: true,
                                hello_protocol_version: 6,
                                license_path: None,
                                timeout_ms: 8000,
                                batch_max: 1024,
                            });
                        }

                        match field {
                            "enabled" => cfg.upstreams[idx].enabled = parse!(b),
                            "priority" => cfg.upstreams[idx].priority = parse!(u32_),
                            "host" => cfg.upstreams[idx].host = parse!(s),
                            "port" => cfg.upstreams[idx].port = parse!(u16_),
                            "use_tls" => cfg.upstreams[idx].use_tls = parse!(b),
                            "insecure_no_verify" => {
                                cfg.upstreams[idx].insecure_no_verify = parse!(b)
                            }
                            "hello_protocol_version" => {
                                cfg.upstreams[idx].hello_protocol_version = parse!(u32_)
                            }
                            "license_path" => {
                                let v = parse!(s);
                                cfg.upstreams[idx].license_path =
                                    if v.is_empty() { None } else { Some(v) };
                            }
                            "timeout_ms" => cfg.upstreams[idx].timeout_ms = parse!(u),
                            "batch_max" => cfg.upstreams[idx].batch_max = parse!(usize_),
                            _ => return Err(format!("unknown upstream field: {}", field)),
                        }
                    }

                    // ---------------- Debug (optional) ----------------
                    ("debug", "dump_hello") => cfg.debug.dump_hello = parse!(b),
                    ("debug", "dump_hello_dir") => cfg.debug.dump_hello_dir = parse!(s),

                    // ---------------- Scoring (optional) ----------------
                    ("scoring", "w_md5") => cfg.scoring.w_md5 = parse!(f64_),
                    ("scoring", "w_name") => cfg.scoring.w_name = parse!(f64_),
                    ("scoring", "w_coh") => cfg.scoring.w_coh = parse!(f64_),
                    ("scoring", "w_stab") => cfg.scoring.w_stab = parse!(f64_),
                    ("scoring", "w_rec") => cfg.scoring.w_rec = parse!(f64_),
                    ("scoring", "w_pop_bin") => cfg.scoring.w_pop_bin = parse!(f64_),
                    ("scoring", "w_host") => cfg.scoring.w_host = parse!(f64_),
                    ("scoring", "w_origin") => cfg.scoring.w_origin = parse!(f64_),
                    ("scoring", "max_versions_per_key") => {
                        cfg.scoring.max_versions_per_key = parse!(usize_)
                    }
                    ("scoring", "max_md5_per_key") => cfg.scoring.max_md5_per_key = parse!(usize_),
                    ("scoring", "max_md5_per_version") => {
                        cfg.scoring.max_md5_per_version = parse!(usize_)
                    }

                    _ => return Err(format!("unknown key {section}.{key}")),
                }
                Ok(())
            };
            let (section, key) = if let Some((a, b)) = lhs.split_once('.') {
                (a.trim(), b.trim())
            } else {
                ("", lhs)
            };
            if section.is_empty() {
                continue;
            }
            set(section, key, val, &mut cfg).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("line {}: {}", lineno + 1, e),
                )
            })?;
        }
        Ok(cfg)
    }
}
