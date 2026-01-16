//! HTTP router and server setup.

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming, header, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::*;
use std::{convert::Infallible, sync::Arc};
use tokio::net::TcpListener as TokioTcpListener;

use crate::config::Config;
use crate::db::Database;

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

/// Start the HTTP server.
pub async fn serve_http(cfg: Arc<Config>, db: Arc<Database>) {
    if let Some(http) = &cfg.http {
        let addr: std::net::SocketAddr = http.bind_addr.parse().expect("invalid http bind addr");
        let listener = TokioTcpListener::bind(&addr).await.expect("failed to bind");
        info!("http listening on {}", addr);
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    error!("accept error: {}", e);
                    continue;
                }
            };
            let db = db.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                if let Err(e) = http1::Builder::new()
                    .serve_connection(io, service_fn(move |req| router(db.clone(), req)))
                    .await
                {
                    error!("http connection error: {}", e);
                }
            });
        }
    }
}
