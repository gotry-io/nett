//! 没有反向代理时 Hub 自己终止 TLS（design/hub.md 第 8 节）：实验拓扑、自签证书的部署与测试。

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("reading {path}: {message}")]
    Read { path: String, message: String },
    #[error("building the TLS configuration: {0}")]
    Config(#[from] rustls::Error),
}

pub fn acceptor(cert: &Path, key: &Path) -> Result<tokio_rustls::TlsAcceptor, TlsError> {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let read = |path: &Path, e: &dyn std::fmt::Display| TlsError::Read {
        path: path.display().to_string(),
        message: e.to_string(),
    };
    let certs = CertificateDer::pem_file_iter(cert)
        .map_err(|e| read(cert, &e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| read(cert, &e))?;
    let key_der = PrivateKeyDer::from_pem_file(key).map_err(|e| read(key, &e))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key_der)?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// 没有反向代理时直接终止 TLS（design/hub.md 第 8 节）。握手失败的连接只记一条调试日志。
pub struct TlsListener {
    tcp: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl TlsListener {
    pub fn new(tcp: tokio::net::TcpListener, acceptor: tokio_rustls::TlsAcceptor) -> Self {
        Self { tcp, acceptor }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = match self.tcp.accept().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "accepting a connection");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                self.acceptor.accept(stream),
            )
            .await
            {
                Ok(Ok(tls)) => return (tls, addr),
                Ok(Err(e)) => tracing::debug!(%addr, error = %e, "TLS handshake failed"),
                Err(_) => tracing::debug!(%addr, "TLS handshake timed out"),
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}
