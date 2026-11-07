//! 到 TLS 中继的连接：按 IP 连接、不发送 SNI，证书按下发的指纹校验（硬性规则 11），只用 TLS 1.3。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use nett_core::transport::CertFingerprint;
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

/// 建立 TCP、TLS 与 WebSocket 连接的总时限。
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// 一个消息的上限：外层包最大约 1360 字节（design/mesh.md 第 4 节），留出余量。
pub const MAX_MESSAGE: usize = 2048;

pub type RelayStream = WebSocketStream<TlsStream<TcpStream>>;

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("connecting to the TLS relay at {0} timed out")]
    Timeout(SocketAddr),
    #[error("TCP connection to the TLS relay at {addr} failed: {source}")]
    Tcp {
        addr: SocketAddr,
        source: std::io::Error,
    },
    #[error(
        "TLS handshake with the relay at {addr} failed (certificate fingerprint mismatch or protocol error): {source}"
    )]
    Tls {
        addr: SocketAddr,
        source: std::io::Error,
    },
    #[error("WebSocket handshake with the relay at {addr} failed: {detail}")]
    WebSocket { addr: SocketAddr, detail: String },
    #[error("building the TLS client configuration: {0}")]
    Config(String),
}

/// 按指纹校验服务端证书；握手签名照常用证书中的公钥校验。
#[derive(Debug)]
struct PinnedCertificate {
    fingerprint: CertFingerprint,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let digest = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        if digest.as_ref() == self.fingerprint.0 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // 只协商 TLS 1.3
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// 只信任这一个指纹的 TLS 客户端。
pub fn connector(fingerprint: CertFingerprint) -> Result<TlsConnector, ConnectError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedCertificate {
        fingerprint,
        algorithms: provider.signature_verification_algorithms,
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ConnectError::Config(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// 连上 TLS 中继并完成 WebSocket 握手。
pub async fn connect(
    addr: SocketAddr,
    connector: &TlsConnector,
) -> Result<RelayStream, ConnectError> {
    let attempt = async {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|source| ConnectError::Tcp { addr, source })?;
        drop(tcp.set_nodelay(true));
        // 按 IP 连接：rustls 不为 IP 地址发送 SNI
        let tls = connector
            .connect(ServerName::IpAddress(addr.ip().into()), tcp)
            .await
            .map_err(|source| ConnectError::Tls { addr, source })?;
        let url = match addr {
            SocketAddr::V4(a) => format!("wss://{}/", a.ip()),
            SocketAddr::V6(a) => format!("wss://[{}]/", a.ip()),
        };
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE))
            .max_frame_size(Some(MAX_MESSAGE));
        let (ws, _) = tokio_tungstenite::client_async_with_config(url, tls, Some(config))
            .await
            .map_err(|e| ConnectError::WebSocket {
                addr,
                detail: e.to_string(),
            })?;
        Ok(ws)
    };
    tokio::time::timeout(CONNECT_TIMEOUT, attempt)
        .await
        .map_err(|_| ConnectError::Timeout(addr))?
}
