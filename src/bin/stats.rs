use std::io;
use std::path::PathBuf;

fn main() -> io::Result<()> {
    let data_dir = PathBuf::from("data");
    let index_dir = data_dir.join("index");

    if !index_dir.exists() {
        eprintln!("Error: data/index directory not found.");
        eprintln!("Run the main dazhbog server first to create the database.");
        std::process::exit(1);
    }

    println!("╔═════════════════════════════════════════════════════════════════════════════╗");
    println!("║           DAZHBOG DATABASE STATISTICS                                       ║");
    println!("╚═════════════════════════════════════════════════════════════════════════════╝");
    println!();

    // Open the index database
    let db = sled::open(&index_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open: {}", e)))?;

    // 1. Count unique functions (keys)
    let latest_tree = db.open_tree("latest")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open latest: {}", e)))?;
    let unique_functions = latest_tree.len();

    // 2. Count total versions
    let version_stats_tree = db.open_tree("ctx.version_stats")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open version_stats: {}", e)))?;
    let total_versions = version_stats_tree.len();

    // 3. Calculate averages
    let avg_versions = if unique_functions > 0 {
        total_versions as f64 / unique_functions as f64
    } else {
        0.0
    };

    // 4. Storage size estimation (approximate)
    let mut total_size_bytes = 0u64;
    for name in db.tree_names() {
        if let Ok(tree) = db.open_tree(&name) {
            for item in tree.iter() {
                if let Ok((k, v)) = item {
                    total_size_bytes += (k.len() + v.len()) as u64;
                }
            }
        }
    }

    // 5. Metrics (if persisted)
    let metrics_tree = db.open_tree("sys.metrics")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open metrics: {}", e)))?;

    println!("General Statistics:");
    println!("  Unique Functions:      {}", unique_functions);
    println!("  Total Versions:        {}", total_versions);
    println!("  Avg Versions/Func:     {:.2}", avg_versions);
    println!("  Index Size (approx):   {:.2} MB", total_size_bytes as f64 / 1_048_576.0);
    println!();

    if !metrics_tree.is_empty() {
        println!("Persisted Metrics:");
        for item in metrics_tree.iter() {
            if let Ok((k, v)) = item {
                let key = String::from_utf8_lossy(&k);
                if v.len() == 8 {
                    let val = u64::from_le_bytes(v.as_ref().try_into().unwrap());
                    println!("  {:<30} {}", key, val);
                }
            }
        }
        println!();
    }

    // 6. Top functions by popularity (if we scan segments, but that's slow.
    //    We can scan ctx.key_md5 for observation counts)
    let key_md5_tree = db.open_tree("ctx.key_md5")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open key_md5: {}", e)))?;

    if !key_md5_tree.is_empty() {
        println!("Scanning for top observed functions (sample)...");
        let mut top_obs = Vec::new();
        let mut scanned = 0;

        for item in key_md5_tree.iter() {
            if scanned > 10000 { break; } // Limit scan for speed
            if let Ok((_, v)) = item {
                // Decode KeyMd5Stats manually to avoid dependency on internal modules if possible,
                // or just copy the struct layout.
                // Layout: obs_count(u32), last_ts(u64), vid(32)
                if v.len() >= 4 {
                    let obs = u32::from_le_bytes(v[0..4].try_into().unwrap());
                    if obs > 1 {
                        top_obs.push(obs);
                    }
                }
            }
            scanned += 1;
        }
        top_obs.sort_unstable_by(|a, b| b.cmp(a));
        if !top_obs.is_empty() {
            println!("  Highest observation count (in sample): {}", top_obs[0]);
            println!("  Functions with >1 observations: {}", top_obs.len());
        }
    }

    Ok(())
}
