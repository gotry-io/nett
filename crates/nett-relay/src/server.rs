//! The relay's receive/send loop (design/mesh.md sections 5.1-5.3): one single-threaded tokio task
//! owns the [`Relay`] and receives UDP packets and messages on TLS (WebSocket) connections, then
//! forwards or answers according to the result. Each TLS connection has its own task, which
//! exchanges messages with the main loop only over bounded channels; when a queue is full the
//! packet is dropped (WireGuard retransmits on its own) and the main loop never blocks.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt as _, StreamExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::relay::{AssignedMember, ConnId, Outcome, PeerAddr, Relay, RelayState};
use nett_trust::keys::X25519PublicKey;

const EXPIRE_INTERVAL: Duration = Duration::from_secs(1);
/// Outer packets are at most about 1360 bytes (design/mesh.md section 4); leave some margin.
const MAX_DATAGRAM: usize = 2048;
/// Interval for saving state (design/mesh.md section 5.2).
const SAVE_INTERVAL: Duration = Duration::from_secs(1);
/// Upper limit on TLS connections, and on those among them that are waiting for authentication.
const MAX_TLS_CONNECTIONS: usize = 1024;
const MAX_UNAUTHENTICATED: usize = 64;
/// Time limit for the TLS and WebSocket handshakes; how long after a connection is established an
/// authenticated probe must arrive (design/mesh.md section 5.3).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
/// Send queue of each TLS connection, and the queue of messages each connection hands to the main
/// loop.
const CONN_QUEUE: usize = 256;
const EVENT_QUEUE: usize = 4096;

/// Listens for the TLS entry point on `addr`.
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

/// The TLS entry point on the relay port.
pub struct TlsIngress {
    pub listener: TcpListener,
    pub acceptor: TlsAcceptor,
}

enum Event {
    Opened(ConnId, mpsc::Sender<Vec<u8>>),
    Packet(ConnId, Vec<u8>),
    Closed(ConnId),
}

struct Conn {
    tx: mpsc::Sender<Vec<u8>>,
    opened: Instant,
    authenticated: bool,
}

/// A changed assignment from the mesh process (design/mesh.md section 5.2).
#[derive(Debug, Clone)]
pub struct Assignment {
    pub members: Vec<AssignedMember>,
    pub connections: Vec<(X25519PublicKey, X25519PublicKey)>,
}

/// Bound on assignments waiting to be applied: the fetcher sends one only when it changed.
pub const ASSIGNMENT_QUEUE: usize = 4;

/// Runs until `shutdown` completes. `udp` is the dual-stack relay port. `state` is the file holding
/// the index table: restored at startup, and written once per second and again before exit, so
/// connections through the relay survive a restart. Assignments arriving on `updates` are applied in
/// place.
pub async fn serve(
    udp: UdpSocket,
    tls: Option<TlsIngress>,
    mut relay: Relay,
    state: Option<PathBuf>,
    mut updates: Option<mpsc::Receiver<Assignment>>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let granted = nett_mesh::sockbuf::enlarge_receive_buffer(&udp);
    tracing::debug!(bytes = ?granted, "relay receive buffer");
    if let Some(path) = &state {
        match load(path) {
            Ok(Some(saved)) => {
                relay.restore(&saved, Instant::now());
                let (_, sessions) = relay.table_sizes();
                tracing::info!(sessions, "relay state restored");
            }
            Ok(None) => {}
            // A corrupt state file only affects restoration: connections through the relay
            // handshake again per design/mesh.md section 8.4
            Err(error) => tracing::warn!(%error, "relay state not restored"),
        }
    }
    let (events_tx, mut events) = mpsc::channel(EVENT_QUEUE);
    let mut conns: HashMap<ConnId, Conn> = HashMap::new();
    let mut next_conn = 0u64;
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut tick = tokio::time::interval(EXPIRE_INTERVAL);
    let mut last_save = Instant::now();
    // Writing to disk can stall for a few hundred milliseconds when the disk is busy (for example
    // when ext4 commits its journal every 5 seconds), so it runs on a blocking thread and does not
    // hold up forwarding; only one save runs at a time: if the previous one has not finished, skip
    // it and save the latest state the next second
    let mut saving: Option<tokio::task::JoinHandle<()>> = None;
    let mut dropped: u64 = 0;
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            received = udp.recv_from(&mut buf) => {
                let (len, from) = received?;
                let from = PeerAddr::Udp(unmap(from));
                let packet = &buf[..len];
                let outcome = relay.handle(from, packet, Instant::now(), now_ms());
                dispatch(&udp, &conns, from, packet, outcome, &mut dropped);
            }
            Some(update) = next_update(&mut updates) => {
                match relay.reassign(&update.members, &update.connections) {
                    Ok(()) => tracing::info!(
                        members = update.members.len(),
                        links = update.connections.len(),
                        "relay assignment applied"
                    ),
                    Err(error) => tracing::warn!(%error, "relay assignment not applied; keeping the previous one"),
                }
            }
            accepted = accept(tls.as_ref()) => {
                let Ok((stream, peer)) = accepted else { continue };
                let unauthenticated = conns.values().filter(|c| !c.authenticated).count();
                if conns.len() >= MAX_TLS_CONNECTIONS || unauthenticated >= MAX_UNAUTHENTICATED {
                    tracing::debug!(%peer, "too many TLS connections; closing");
                    continue;
                }
                let Some(ingress) = tls.as_ref() else { continue };
                next_conn += 1;
                let id = ConnId(next_conn);
                tokio::spawn(connection(id, stream, ingress.acceptor.clone(), events_tx.clone()));
            }
            Some(event) = events.recv() => match event {
                Event::Opened(id, tx) => {
                    conns.insert(id, Conn { tx, opened: Instant::now(), authenticated: false });
                }
                Event::Packet(id, packet) => {
                    let Some(conn) = conns.get_mut(&id) else { continue };
                    if conn.authenticated {
                        let from = PeerAddr::Tls(id);
                        let outcome = relay.handle(from, &packet, Instant::now(), now_ms());
                        dispatch(&udp, &conns, from, &packet, outcome, &mut dropped);
                    } else if let Some(reply) = relay.authenticate(id, &packet, now_ms()) {
                        conn.authenticated = true;
                        tracing::info!(conn = id.0, "TLS connection authenticated");
                        drop(conn.tx.try_send(reply));
                    } else {
                        // The first message is not an authenticated probe: close the connection and
                        // send no reply
                        conns.remove(&id);
                    }
                }
                Event::Closed(id) => {
                    if conns.remove(&id).is_some_and(|c| c.authenticated) {
                        tracing::info!(conn = id.0, "TLS connection closed");
                    }
                    relay.closed(id);
                }
            },
            _ = tick.tick() => {
                let now = Instant::now();
                relay.expire(now);
                // A connection that has not authenticated in time: drop the sender, and the
                // connection task ends with it
                conns.retain(|_, c| c.authenticated || now.saturating_duration_since(c.opened) < AUTH_TIMEOUT);
                if let Some(path) = &state
                    && now.saturating_duration_since(last_save) >= SAVE_INTERVAL
                    && saving.as_ref().is_none_or(tokio::task::JoinHandle::is_finished)
                {
                    last_save = now;
                    saving = Some(save_in_background(path, relay.snapshot(now)));
                }
            }
        }
    }
    if let Some(path) = &state {
        if let Some(previous) = saving.take() {
            drop(previous.await);
        }
        drop(save_in_background(path, relay.snapshot(Instant::now())).await);
    }
    Ok(())
}

/// The next assignment; waits forever when there is no channel or it has closed.
async fn next_update(updates: &mut Option<mpsc::Receiver<Assignment>>) -> Option<Assignment> {
    match updates {
        Some(rx) => match rx.recv().await {
            Some(update) => Some(update),
            None => {
                *updates = None;
                std::future::pending().await
            }
        },
        None => std::future::pending().await,
    }
}

async fn accept(tls: Option<&TlsIngress>) -> std::io::Result<(TcpStream, SocketAddr)> {
    match tls {
        Some(ingress) => ingress.listener.accept().await,
        None => std::future::pending().await,
    }
}

/// The result of running [`Relay::handle`]. A send failure (for example the peer has no route yet
/// or the connection's queue is full) drops only that one packet.
fn dispatch(
    udp: &UdpSocket,
    conns: &HashMap<ConnId, Conn>,
    from: PeerAddr,
    packet: &[u8],
    outcome: Outcome,
    dropped: &mut u64,
) {
    let send = |to: PeerAddr, data: &[u8]| match to {
        PeerAddr::Udp(addr) => drop(udp.try_send_to(data, map_v6(addr))),
        PeerAddr::Tls(id) => {
            if let Some(conn) = conns.get(&id) {
                drop(conn.tx.try_send(data.to_vec()));
            }
        }
    };
    match outcome {
        Outcome::Forward(to) => send(to, packet),
        Outcome::ForwardEach(targets) => {
            for to in targets {
                send(to, packet);
            }
        }
        Outcome::Reply(reply) => send(from, &reply),
        Outcome::Drop(reason) => {
            *dropped += 1;
            tracing::debug!(?reason, ?from, dropped, "relay dropped a packet");
        }
    }
}

/// One TLS connection: TLS and WebSocket handshakes, after which each binary message is a WireGuard
/// packet or a relay probe.
async fn connection(
    id: ConnId,
    stream: TcpStream,
    acceptor: TlsAcceptor,
    events: mpsc::Sender<Event>,
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
    let (tx, mut rx) = mpsc::channel(CONN_QUEUE);
    if events.send(Event::Opened(id, tx)).await.is_err() {
        return;
    }
    let (mut sink, mut source) = ws.split();
    loop {
        tokio::select! {
            incoming = source.next() => match incoming {
                Some(Ok(Message::Binary(data))) => {
                    if data.len() <= MAX_DATAGRAM
                        && events.send(Event::Packet(id, data.to_vec())).await.is_err()
                    {
                        break;
                    }
                }
                // Keepalives are answered automatically by the WebSocket library
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                _ => break,
            },
            outgoing = rx.recv() => match outgoing {
                Some(data) => {
                    if sink.send(Message::binary(data)).await.is_err() {
                        break;
                    }
                }
                // The main loop no longer needs this connection (authentication failed or timed
                // out)
                None => break,
            },
        }
    }
    drop(sink.close().await);
    drop(events.send(Event::Closed(id)).await);
}

fn load(path: &Path) -> std::io::Result<Option<RelayState>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(std::io::Error::other),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn save_in_background(path: &Path, snapshot: RelayState) -> tokio::task::JoinHandle<()> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || save_or_warn(&path, &snapshot))
}

/// Write a temporary file first, then rename: what is read at restart is always a complete state.
fn save(path: &Path, snapshot: &RelayState) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let bytes = serde_json::to_vec(snapshot).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(&bytes)?;
    std::fs::rename(&tmp, path)
}

fn save_or_warn(path: &Path, snapshot: &RelayState) {
    if let Err(error) = save(path, snapshot) {
        tracing::warn!(%error, path = %path.display(), "saving relay state failed");
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn unmap(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

fn map_v6(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(a) => SocketAddr::new(IpAddr::V6(a.ip().to_ipv6_mapped()), a.port()),
        SocketAddr::V6(_) => addr,
    }
}

/// Builds the server configuration for the TLS entry point from PEM files: TLS 1.3 only, with ring
/// as the crypto backend.
pub fn tls_acceptor(cert: &Path, key: &Path) -> Result<TlsAcceptor, TlsSetupError> {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|e| TlsSetupError::Certificate(e.to_string()))?;
    // The error message does not contain private key material (hard rule 10)
    let key = PrivateKeyDer::from_pem_file(key).map_err(|_| TlsSetupError::Key)?;
    acceptor(chain, key)
}

/// The server configuration for the relay's own certificate (design/mesh.md section 5.3).
pub fn cert_acceptor(cert: &crate::cert::RelayCert) -> Result<TlsAcceptor, TlsSetupError> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    acceptor(
        vec![CertificateDer::from(cert.cert.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_der().to_vec())),
    )
}

fn acceptor(
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<TlsAcceptor, TlsSetupError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsSetupError::Config(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| TlsSetupError::Config(e.to_string()))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[derive(Debug, thiserror::Error)]
pub enum TlsSetupError {
    #[error("reading the TLS certificate chain: {0}")]
    Certificate(String),
    #[error("reading the TLS private key failed (file missing, unreadable, or not PEM)")]
    Key,
    #[error("building the TLS configuration: {0}")]
    Config(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::AssignedMember;
    use nett_mesh::probe::{KeyId, OuterProbe, OuterReply, ProbeKey, RELAY_PROBE};
    use nett_trust::keys::X25519PublicKey;

    /// When the state write stalls (a named pipe with no reader stands in for a busy disk here),
    /// the relay keeps answering and forwarding.
    #[test]
    fn a_stuck_state_write_does_not_hold_up_forwarding() {
        let dir = std::env::temp_dir().join(format!("nett-relay-save-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let state = dir.join("relay-state.json");
        // The temporary file written first when saving is a pipe: opening it for writing blocks
        // until someone reads
        let fifo = state.with_extension("tmp");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(made.success(), "mkfifo failed");

        let (a, b) = ([1; 32], [2; 32]);
        let member = |k: [u8; 32], address| AssignedMember {
            public_key: X25519PublicKey::from_bytes(k),
            address,
            token: [k[0]; 32],
        };
        let relay = Relay::new(
            &[
                member(a, Some("198.51.100.1:41820".parse().expect("addr"))),
                member(b, None),
            ],
            &[(
                X25519PublicKey::from_bytes(a),
                X25519PublicKey::from_bytes(b),
            )],
        )
        .expect("assignment");

        // The relay port is dual-stack: replies are sent to the IPv6-mapped address
        let socket = std::net::UdpSocket::bind("[::]:0").expect("relay socket");
        socket.set_nonblocking(true).expect("nonblocking");
        let relay_addr =
            SocketAddr::from(([127, 0, 0, 1], socket.local_addr().expect("addr").port()));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server_state = state.clone();
        // Runs on a single-threaded runtime, like `nett relay`
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async move {
                let udp = UdpSocket::from_std(socket).expect("tokio socket");
                serve(udp, None, relay, Some(server_state), None, async {
                    drop(stopped.await);
                })
                .await
            })
        });

        // The first save happens about 1 second after startup; after that it stays stuck on the
        // pipe
        std::thread::sleep(SAVE_INTERVAL + Duration::from_millis(1_500));
        let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("client socket");
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("timeout");
        let key = ProbeKey::from_token(&[2; 32]);
        let probe = OuterProbe {
            kind: RELAY_PROBE,
            key_id: KeyId::of(&b),
            seq: 1,
            sent_ms: now_ms(),
        };
        client
            .send_to(&probe.encode(&key), relay_addr)
            .expect("send probe");
        let mut buf = [0u8; MAX_DATAGRAM];
        let replied = client
            .recv_from(&mut buf)
            .map(|(len, _)| OuterReply::verify(&buf[..len], &key).is_some());

        // Release the stalled write so the save before the relay exits can finish
        let reader = std::thread::spawn(move || std::fs::read(&fifo));
        stop.send(()).expect("relay still running");
        server.join().expect("server thread").expect("serve");
        reader
            .join()
            .expect("reader thread")
            .expect("read the pipe");
        let saved = load(&state).expect("load");
        std::fs::remove_dir_all(&dir).expect("clean up");

        assert!(
            matches!(replied, Ok(true)),
            "relay did not answer while saving was stuck: {replied:?}"
        );
        assert!(saved.is_some(), "state saved on exit");
    }
}
