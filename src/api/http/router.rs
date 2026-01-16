//! HTTP router and server setup.
//!
//! Supports both HTTP/1.1 and HTTP/2 on the same port using hyper-util's
//! auto connection builder for automatic protocol detection.

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{body::Incoming, header, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use log::*;
use std::{convert::Infallible, io, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener as TokioTcpListener;

use crate::config::Config;
use crate::db::Database;
use crate::net::tls::NegotiatedProtocol;

use super::handlers::{handle_search, json_response, metrics_snapshot};
use super::templates::HOME;
use crate::api::metrics::METRICS;

/// Route HTTP requests to appropriate handlers.
async fn router(
    db: Arc<Database>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();
    let method = req.method();

    let resp = match (method, path) {
        (&Method::GET, "/") => {
            let mut r = Response::new(Full::new(Bytes::from_static(HOME.as_bytes())));
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("text/html; charset=utf-8"),
            );
            r
        }
        (&Method::GET, "/api/search") => handle_search(db.clone(), req).await,
        (&Method::GET, "/api/metrics") => json_response(&metrics_snapshot(), StatusCode::OK),
        (&Method::GET, "/metrics") => {
            let s = METRICS.render_prometheus();
            let mut r = Response::new(Full::new(Bytes::from(s)));
            *r.status_mut() = StatusCode::OK;
            r
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("not found")))
            .unwrap(),
    };

    Ok(resp)
}

/// Handle an HTTP connection with automatic HTTP/1.1 and HTTP/2 detection.
///
/// This is the preferred handler that uses hyper-util's auto builder to
/// automatically detect and serve both HTTP/1.1 and HTTP/2 (h2c) connections.
/// For HTTP/2 over TLS (h2), the protocol should be negotiated via ALPN.
pub async fn handle_http_connection<S>(stream: S, db: Arc<Database>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    AutoBuilder::new(TokioExecutor::new())
        .serve_connection(io, service_fn(move |req| router(db.clone(), req)))
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("http error: {}", e)))
}

/// Handle an HTTP connection when we know the protocol from ALPN negotiation.
///
/// When TLS ALPN has negotiated the protocol, we can skip auto-detection and
/// use the appropriate HTTP/1.1 or HTTP/2 handler directly for efficiency.
pub async fn handle_http_connection_with_protocol<S>(
    stream: S,
    db: Arc<Database>,
    protocol: NegotiatedProtocol,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let svc = service_fn(move |req| router(db.clone(), req));

    match protocol {
        NegotiatedProtocol::H2 => {
            debug!("serving HTTP/2 connection (ALPN negotiated)");
            http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("http2 error: {}", e)))
        }
        NegotiatedProtocol::Http1 => {
            debug!("serving HTTP/1.1 connection (ALPN negotiated)");
            http1::Builder::new()
                .serve_connection(io, svc)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("http1 error: {}", e)))
        }
        NegotiatedProtocol::None => {
            // No ALPN, use auto-detection
            debug!("serving HTTP connection (auto-detection)");
            AutoBuilder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("http error: {}", e)))
        }
    }
}

/// Start the standalone HTTP server.
///
/// This server runs on a dedicated port and supports both HTTP/1.1 and HTTP/2 (h2c).
/// For HTTP/2 over TLS, use the main Lumina port with TLS and ALPN enabled.
pub async fn serve_http(cfg: Arc<Config>, db: Arc<Database>) {
    if let Some(http) = &cfg.http {
        let addr: std::net::SocketAddr = http.bind_addr.parse().expect("invalid http bind addr");
        let listener = TokioTcpListener::bind(&addr).await.expect("failed to bind");
        info!("http listening on {} (HTTP/1.1 + HTTP/2 h2c)", addr);
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    error!("accept error: {}", e);
                    continue;
                }
            };
            let db = db.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_http_connection(stream, db).await {
                    debug!("http connection error from {}: {}", peer, e);
                }
            });
        }
    }
}
