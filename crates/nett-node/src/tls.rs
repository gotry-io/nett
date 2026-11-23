//! TLS for connecting to the Hub and the website (hard rule 11): a public certificate is verified
//! by the operating system, as for any website (design/hub.md section 4); a self-signed Hub is
//! verified against the certificate fingerprint in the Hub configuration (reusing the TLS
//! transport's implementation).

use std::sync::Arc;

use nett_core::transport::CertFingerprint;
use rustls_platform_verifier::BuilderVerifierExt as _;
use tokio_rustls::TlsConnector;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("building the TLS client configuration: {0}")]
    Config(String),
}

pub fn connector(fingerprint: Option<[u8; 32]>) -> Result<TlsConnector, TlsError> {
    if let Some(f) = fingerprint {
        return nett_transport::client::connector(CertFingerprint(f))
            .map_err(|e| TlsError::Config(e.to_string()));
    }
    // The system checks the chain the server presents; loading every root certificate into this
    // process instead leaves several megabytes behind on macOS at each connection
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_platform_verifier()
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}
