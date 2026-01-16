//! TCP server for binary RPC protocol.
//!
//! Handles connection acceptance, TLS negotiation, and dispatching
//! to the client handler.

use std::sync::Arc;
use std::time::Duration;

use log::*;
use tokio::net::TcpListener as TokioTcpListener;

use crate::api::metrics::METRICS;
use crate::config::Config;
use crate::db::Database;

use super::budget::Budget;
use super::handler::handle_client;
use super::protocol::looks_like_tls_client_hello;
use super::tls::build_tls_acceptor;

/// Start the binary RPC server.
///
/// Listens on the configured address and accepts connections.
/// Supports automatic TLS/cleartext detection when TLS is enabled.
pub async fn serve_binary_rpc(cfg: Arc<Config>, db: Arc<Database>) {
    let listener = TokioTcpListener::bind(&cfg.lumina.bind_addr)
        .await
        .expect("bind failed");

    let global_budget = Arc::new(Budget::new(cfg.limits.global_inflight_bytes));

    // Set up TLS acceptor if configured
    let tls_acceptor = if cfg.lumina.use_tls {
        let tls = cfg.lumina.tls.as_ref().expect("tls config missing");
        Some(build_tls_acceptor(tls))
    } else {
        None
    };

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

        // Check connection limit
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
                // TLS mode: sniff first bytes to detect TLS vs cleartext
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
                // No TLS: handle as cleartext
                handle_client(socket, cfg, db, global_budget).await
            };

            if let Err(e) = res {
                let msg = e.to_string();
                if msg.contains("TLS handshake detected") {
                    warn!("connection {} ended: {}", addr, msg);
                } else {
                    debug!("connection {} ended: {}", addr, msg);
                }
            } else {
                debug!("connection {} closed cleanly", addr);
            }

            METRICS
                .active_connections
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
    }
}
