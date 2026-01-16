//! TLS acceptor setup utilities.
//!
//! Supports both native-tls (PKCS#12) and rustls (PEM) for TLS termination.
//! Rustls is preferred when HTTP/2 support is needed as it provides ALPN.

use crate::config::TLS;
use log::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::Arc;

/// ALPN protocols for HTTP/2 and HTTP/1.1 negotiation.
/// Order matters: h2 is preferred over http/1.1.
pub const ALPN_PROTOCOLS: &[&[u8]] = &[b"h2", b"http/1.1"];

/// Build a native-tls acceptor from PKCS#12 configuration.
///
/// Loads the PKCS#12 certificate bundle and creates a TLS acceptor
/// with the configured settings. Does NOT support ALPN (HTTP/2 over TLS).
pub fn build_native_tls_acceptor(tls: &TLS) -> tokio_native_tls::TlsAcceptor {
    // Read certificate file
    let mut crt = std::fs::read(&tls.pkcs12_path).expect("read pkcs12 file");

    // Get password from environment variable
    let pass = std::env::var(&tls.env_password_var).unwrap_or_default();

    // Parse PKCS#12 identity
    let id = native_tls::Identity::from_pkcs12(&crt, &pass).expect("parse pkcs12");

    // Zero out certificate data for security
    crt.iter_mut().for_each(|b| *b = 0);

    // Build acceptor with optional settings
    let mut builder = native_tls::TlsAcceptor::builder(id);

    if tls.min_protocol_sslv3 {
        builder.min_protocol_version(Some(native_tls::Protocol::Sslv3));
    }

    let acc = builder.build().expect("tls build");
    tokio_native_tls::TlsAcceptor::from(acc)
}

/// Load certificates from a PEM file.
fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .filter_map(|cert| cert.ok())
        .collect();
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no certificates found in {}", path.display()),
        ));
    }
    Ok(certs)
}

/// Load private key from a PEM file.
fn load_private_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    // Try to load any type of private key (RSA, PKCS8, EC)
    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => {
                return Ok(PrivateKeyDer::Pkcs1(key));
            }
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
            Some(rustls_pemfile::Item::Sec1Key(key)) => {
                return Ok(PrivateKeyDer::Sec1(key));
            }
            Some(_) => continue, // Skip other items
            None => break,
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("no private key found in {}", path.display()),
    ))
}

/// Rustls TLS acceptor wrapper that exposes ALPN negotiation results.
#[derive(Clone)]
pub struct RustlsAcceptor {
    acceptor: tokio_rustls::TlsAcceptor,
}

impl RustlsAcceptor {
    /// Accept a TLS connection and return the stream with ALPN info.
    pub async fn accept<S>(&self, stream: S) -> io::Result<tokio_rustls::server::TlsStream<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        self.acceptor.accept(stream).await
    }
}

/// Build a rustls acceptor from PEM certificate and key files.
///
/// This acceptor supports ALPN for HTTP/2 negotiation over TLS.
/// Expects:
/// - `cert_path`: Path to PEM-encoded certificate chain
/// - `key_path`: Path to PEM-encoded private key
pub fn build_rustls_acceptor(cert_path: &str, key_path: &str) -> io::Result<RustlsAcceptor> {
    let certs = load_certs(Path::new(cert_path))?;
    let key = load_private_key(Path::new(key_path))?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    // Enable ALPN with h2 and http/1.1
    config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|p| p.to_vec()).collect();

    info!(
        "rustls acceptor configured with ALPN: {:?}",
        config
            .alpn_protocols
            .iter()
            .map(|p| String::from_utf8_lossy(p))
            .collect::<Vec<_>>()
    );

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    Ok(RustlsAcceptor { acceptor })
}

/// Negotiated application protocol from ALPN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiatedProtocol {
    /// HTTP/2 was negotiated
    H2,
    /// HTTP/1.1 was negotiated
    Http1,
    /// No ALPN negotiation occurred (fallback to detection)
    None,
}

impl NegotiatedProtocol {
    /// Determine the negotiated protocol from ALPN data.
    pub fn from_alpn(alpn: Option<&[u8]>) -> Self {
        match alpn {
            Some(b"h2") => NegotiatedProtocol::H2,
            Some(b"http/1.1") => NegotiatedProtocol::Http1,
            _ => NegotiatedProtocol::None,
        }
    }
}

/// TLS acceptor that can be either native-tls or rustls.
///
/// This allows gradual migration: existing PKCS#12 configs continue to work
/// with native-tls, while new PEM configs can use rustls with ALPN.
#[derive(Clone)]
pub enum TlsAcceptor {
    /// Native TLS acceptor (PKCS#12, no ALPN support)
    Native(tokio_native_tls::TlsAcceptor),
    /// Rustls acceptor (PEM, with ALPN support for HTTP/2)
    Rustls(RustlsAcceptor),
}

/// Build a TLS acceptor from configuration.
///
/// Automatically selects rustls (with ALPN) if PEM paths are provided,
/// otherwise falls back to native-tls with PKCS#12.
pub fn build_tls_acceptor(tls: &TLS) -> TlsAcceptor {
    // If PEM paths are provided, use rustls for ALPN support
    if let (Some(cert), Some(key)) = (&tls.cert_pem_path, &tls.key_pem_path) {
        info!("using rustls with ALPN support (HTTP/2 enabled)");
        match build_rustls_acceptor(cert, key) {
            Ok(acc) => return TlsAcceptor::Rustls(acc),
            Err(e) => {
                warn!(
                    "failed to build rustls acceptor: {}, falling back to native-tls",
                    e
                );
            }
        }
    }

    // Fall back to native-tls with PKCS#12
    if !tls.pkcs12_path.is_empty() {
        info!("using native-tls (no ALPN, HTTP/2 requires preface detection)");
        TlsAcceptor::Native(build_native_tls_acceptor(tls))
    } else {
        panic!("TLS enabled but no certificate paths configured");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negotiated_protocol() {
        assert_eq!(
            NegotiatedProtocol::from_alpn(Some(b"h2")),
            NegotiatedProtocol::H2
        );
        assert_eq!(
            NegotiatedProtocol::from_alpn(Some(b"http/1.1")),
            NegotiatedProtocol::Http1
        );
        assert_eq!(
            NegotiatedProtocol::from_alpn(None),
            NegotiatedProtocol::None
        );
        assert_eq!(
            NegotiatedProtocol::from_alpn(Some(b"unknown")),
            NegotiatedProtocol::None
        );
    }
}
