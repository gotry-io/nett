//! Connection to a TLS relay: connects by IP, sends no SNI, verifies the certificate by the pinned
//! fingerprint (hard rule 11), and uses TLS 1.3 only.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use nett_core::transport::CertFingerprint;
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

/// Overall time limit for establishing the TCP, TLS and WebSocket connections.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper limit of one message: outer packets are at most about 1360 bytes (design/mesh.md section
/// 4); leave some margin.
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

/// Verifies the server certificate by fingerprint; the handshake signature is still verified with
/// the public key in the certificate.
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
        // Negotiate only TLS 1.3
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

/// A TLS client that trusts only this one fingerprint.
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

/// Connects to the TLS relay and completes the WebSocket handshake; the TCP connection is bound to
/// `interface` when the mesh process names one (design/userspace.md section 6.2).
pub async fn connect(
    addr: SocketAddr,
    interface: Option<u32>,
    connector: &TlsConnector,
) -> Result<RelayStream, ConnectError> {
    let attempt = async {
        let tcp = tcp(addr, interface)
            .await
            .map_err(|source| ConnectError::Tcp { addr, source })?;
        drop(tcp.set_nodelay(true));
        // Connect by IP: rustls does not send SNI for an IP address
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

/// A TCP connection to `addr`, bound to `interface` when given.
async fn tcp(addr: SocketAddr, interface: Option<u32>) -> std::io::Result<TcpStream> {
    let Some(index) = interface else {
        return TcpStream::connect(addr).await;
    };
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    bind_to_interface(&socket, index, addr.is_ipv6())?;
    socket.connect(addr).await
}

#[cfg(target_os = "macos")]
fn bind_to_interface(socket: &TcpSocket, index: u32, v6: bool) -> std::io::Result<()> {
    use std::os::fd::AsFd as _;
    nett_mesh::macos::bind_to_interface(socket.as_fd(), index, v6)
}

/// Only the macOS mesh process names an interface.
#[cfg(not(target_os = "macos"))]
fn bind_to_interface(_socket: &TcpSocket, _index: u32, _v6: bool) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "binding a connection to an interface is only done on macOS",
    ))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// Index of the loopback interface, `lo0`, on macOS.
    const LOOPBACK: u32 = 1;

    /// A connection bound to an interface reaches what that interface reaches
    #[tokio::test]
    async fn a_bound_connection_reaches_its_interface() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let addr = listener.local_addr().expect("address");
        let accepted = tokio::spawn(async move { listener.accept().await.map(|(_, from)| from) });
        let stream = tcp(addr, Some(LOOPBACK)).await.expect("connected");
        assert_eq!(
            accepted.await.expect("task").expect("accepted"),
            stream.local_addr().expect("local")
        );
    }
}
