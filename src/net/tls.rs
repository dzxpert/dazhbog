//! TLS acceptor setup utilities.

use crate::config::TLS;

/// Build a TLS acceptor from configuration.
///
/// Loads the PKCS#12 certificate bundle and creates a TLS acceptor
/// with the configured settings.
pub fn build_tls_acceptor(tls: &TLS) -> tokio_native_tls::TlsAcceptor {
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
