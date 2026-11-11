//! TLS for connecting to the Hub (hard rule 11): when the Hub has a public certificate it is
//! verified against the system root certificates; when the Hub is self-signed it is verified
//! against the certificate fingerprint in the Hub configuration (reusing the transport adapter's
//! implementation).

use std::sync::Arc;

use nett_core::transport::CertFingerprint;
use tokio_rustls::TlsConnector;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("no trusted root certificates on this machine: {0}")]
    Roots(String),
    #[error("building the TLS client configuration: {0}")]
    Config(String),
}

pub fn connector(fingerprint: Option<[u8; 32]>) -> Result<TlsConnector, TlsError> {
    if let Some(f) = fingerprint {
        return nett_transport::client::connector(CertFingerprint(f))
            .map_err(|e| TlsError::Config(e.to_string()));
    }
    let mut roots = rustls::RootCertStore::empty();
    let found = rustls_native_certs::load_native_certs();
    for cert in found.certs {
        // Skip individual certificates that cannot be parsed and use the rest as usual
        roots.add(cert).ok();
    }
    if roots.is_empty() {
        return Err(TlsError::Roots(
            found
                .errors
                .first()
                .map_or_else(|| "none found".to_owned(), ToString::to_string),
        ));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}
