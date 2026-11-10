//! 连接 Hub 的 TLS（硬性规则 11）：Hub 有公网证书时按系统的根证书校验；Hub 自签证书时按 Hub 配置中的证书指纹
//! 校验（复用传输适配进程的实现）。

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
        // 个别读不懂的证书跳过，其余照常用
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
