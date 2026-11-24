//! The relay's public TCP entry, which nett-relay runs (ADR 0032, design/mesh.md section 5.3): it
//! terminates TLS and WebSocket and hands each connection to the relay in the nett daemon. Every
//! connection gets a UDP socket of its own on the loopback address and sends to the relay's
//! hand-off port: each binary message becomes one datagram there, each datagram back one message,
//! and an empty datagram tells the relay the connection closed. The relay authenticates the member
//! from the first message; a connection that has heard nothing back within the time limit is
//! closed. The hand-off port is the one the daemon gives now, so a connection stays open across a
//! restart of the daemon, and the relay authenticates it again from its next probe.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::server::{AUTH_TIMEOUT, MAX_DATAGRAM, MAX_TLS_CONNECTIONS, MAX_UNAUTHENTICATED};
use nett_transport::queue;

/// Time limit for the TLS and WebSocket handshakes.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The TLS entry: the listening socket and the server configuration.
pub struct TlsIngress {
    pub listener: TcpListener,
    pub acceptor: TlsAcceptor,
}

/// Listens for the TLS entry on `addr`.
pub fn tls_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(1024)
}

/// The connections open, and those among them the relay has not answered yet.
#[derive(Default)]
struct Counts {
    open: AtomicUsize,
    waiting: AtomicUsize,
}

/// Counts one connection while it lives, and as waiting until the relay first answers it.
struct Counted {
    counts: Arc<Counts>,
    waiting: bool,
}

impl Counted {
    fn new(counts: Arc<Counts>) -> Self {
        counts.open.fetch_add(1, Ordering::AcqRel);
        counts.waiting.fetch_add(1, Ordering::AcqRel);
        Self {
            counts,
            waiting: true,
        }
    }

    fn answered(&mut self) {
        if std::mem::take(&mut self.waiting) {
            self.counts.waiting.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.answered();
        self.counts.open.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Accepts TLS connections until `shutdown` completes and hands each to the relay's hand-off port
/// on the loopback address, the one `handoff` holds at the time.
pub async fn serve(
    ingress: TlsIngress,
    handoff: Arc<AtomicU16>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let counts = Arc::new(Counts::default());
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            accepted = ingress.listener.accept() => {
                let Ok((stream, peer)) = accepted else { continue };
                if counts.open.load(Ordering::Acquire) >= MAX_TLS_CONNECTIONS
                    || counts.waiting.load(Ordering::Acquire) >= MAX_UNAUTHENTICATED
                {
                    tracing::debug!(%peer, "too many TLS connections; closing");
                    continue;
                }
                // Each message is one tunnel packet and goes out at once, as over UDP: Nagle's
                // algorithm would hold it until the previous one is acknowledged, and probes and
                // keepalives share the connection, so most requests through the relay would wait a
                // round trip more
                drop(stream.set_nodelay(true));
                let counted = Counted::new(counts.clone());
                tokio::spawn(connection(stream, ingress.acceptor.clone(), handoff.clone(), counted));
            }
        }
    }
}

/// One TLS connection: TLS and WebSocket handshakes, then messages both ways through a loopback
/// socket of its own. The relay's messages to it wait in a queue that keeps the newest
/// [`queue::SEND_QUEUE`] while the connection falls behind (design/mesh.md section 5.3).
async fn connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    handoff: Arc<AtomicU16>,
    mut counted: Counted,
) {
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_DATAGRAM))
        .max_frame_size(Some(MAX_DATAGRAM));
    let handshake = async {
        let tls = acceptor.accept(stream).await.ok()?;
        tokio_tungstenite::accept_async_with_config(tls, Some(config))
            .await
            .ok()
    };
    let Ok(Some(ws)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await else {
        return;
    };
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await else {
        return;
    };
    nett_mesh::sockbuf::enlarge_receive_buffer(&socket);
    let socket = Arc::new(socket);
    let relay =
        move || SocketAddr::new(Ipv4Addr::LOCALHOST.into(), handoff.load(Ordering::Acquire));
    let (tx, mut rx) = queue::queue();
    let reader = tokio::spawn({
        let socket = socket.clone();
        let relay = relay.clone();
        async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                // Only the relay's own port is heard; an ICMP error surfaces as a failed receive
                if let Ok((len, from)) = socket.recv_from(&mut buf).await
                    && from == relay()
                {
                    tx.push(buf[..len].to_vec());
                }
            }
        }
    });
    let deadline = tokio::time::sleep(AUTH_TIMEOUT);
    tokio::pin!(deadline);
    let mut answered = false;
    let (mut sink, mut source) = ws.split();
    loop {
        tokio::select! {
            incoming = source.next() => match incoming {
                // An empty message would read as a close to the relay
                Some(Ok(Message::Binary(data))) if !data.is_empty() && data.len() <= MAX_DATAGRAM => {
                    drop(socket.send_to(&data, relay()).await);
                }
                Some(Ok(Message::Binary(_))) => {}
                // Keepalives are answered automatically by the WebSocket library
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                _ => break,
            },
            outgoing = rx.recv() => match outgoing {
                Some(data) => {
                    if !answered {
                        answered = true;
                        counted.answered();
                    }
                    if sink.send(Message::binary(data)).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            // The relay answers only a connection that authenticated
            () = &mut deadline, if !answered => break,
        }
    }
    reader.abort();
    drop(sink.close().await);
    drop(socket.send_to(&[], relay()).await);
}

/// The server configuration for the relay's own certificate (design/mesh.md section 5.3): TLS 1.3
/// only, with ring as the crypto backend.
pub fn cert_acceptor(cert: &crate::cert::RelayCert) -> Result<TlsAcceptor, TlsSetupError> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsSetupError(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.cert.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_der().to_vec())),
        )
        .map_err(|e| TlsSetupError(e.to_string()))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[derive(Debug, thiserror::Error)]
#[error("building the TLS configuration: {0}")]
pub struct TlsSetupError(String);

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> (crate::cert::RelayCert, tempfile::TempDir) {
        let dir_tmp = tempfile::Builder::new()
            .prefix("nett-relay-entry-")
            .tempdir()
            .expect("temp dir");
        let cert =
            crate::cert::RelayCert::load_or_create(&dir_tmp.path().join("cert")).expect("cert");
        (cert, dir_tmp)
    }

    /// Each message on a TLS relay connection is one tunnel packet, so both ends send it at once
    /// instead of holding it until the one before is acknowledged (Nagle's algorithm): with probes
    /// and keepalives sharing the connection, that held most requests through the relay a round
    /// trip longer. Messages cross to the relay's hand-off port as datagrams and back, and a closed
    /// connection is announced with an empty datagram.
    #[test]
    fn both_ends_of_a_tls_relay_connection_send_each_packet_at_once() {
        let (cert, _dir) = entry();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let relay = UdpSocket::bind("127.0.0.1:0").await.expect("relay");
            let listener = tls_listener("127.0.0.1:0".parse().expect("addr")).expect("listener");
            let addr = listener.local_addr().expect("addr");
            let ingress = TlsIngress {
                listener,
                acceptor: cert_acceptor(&cert).expect("acceptor"),
            };
            let handoff = Arc::new(AtomicU16::new(relay.local_addr().expect("addr").port()));
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let server = tokio::spawn(serve(ingress, handoff, async {
                drop(stopped.await);
            }));
            let connector =
                nett_transport::client::connector(cert.fingerprint()).expect("connector");
            let mut ws = nett_transport::client::connect(addr, None, &connector)
                .await
                .expect("connected");
            assert!(
                ws.get_ref().get_ref().0.nodelay().expect("member end"),
                "the member holds small packets back"
            );

            let mut buf = [0u8; 64];
            ws.send(Message::binary(vec![0x90, 1, 2]))
                .await
                .expect("send");
            let (len, from) =
                tokio::time::timeout(Duration::from_secs(2), relay.recv_from(&mut buf))
                    .await
                    .expect("in time")
                    .expect("relay receives");
            assert_eq!(buf[..len], [0x90, 1, 2]);
            relay.send_to(&[0x91, 3], from).await.expect("reply");
            let back = tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .expect("in time")
                .expect("a message")
                .expect("ok");
            assert_eq!(back.into_data().as_ref(), [0x91, 3]);

            drop(ws.close(None).await);
            let (len, closed_from) =
                tokio::time::timeout(Duration::from_secs(2), relay.recv_from(&mut buf))
                    .await
                    .expect("in time")
                    .expect("relay receives");
            assert_eq!(
                (len, closed_from),
                (0, from),
                "closed with an empty datagram"
            );
            stop.send(()).expect("entry running");
            server.await.expect("task").expect("serve");
        });
    }
}
