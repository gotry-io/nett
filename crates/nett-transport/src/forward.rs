//! Forwarding between loopback ports and TLS connections (design/mesh.md section 5.3).
//!
//! One task per TLS relay: it connects to the relay when the first packet arrives and stays
//! connected afterwards (keepalive every 25 seconds, i.e. a standby connection), and reconnects
//! when a packet arrives after a disconnect. The first message on a connection must be a relay
//! probe sent by the mesh process (the relay authenticates it from this); before then other packets
//! are held in a bounded queue.

use std::collections::VecDeque;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt as _, StreamExt as _};
use nett_core::transport::{RELAY_PROBE, RELAY_REPLY, TlsTarget, TransportConfig};
use nett_mesh::helper::HelperSource;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;

use crate::client::{self, MAX_MESSAGE};

/// WebSocket keepalive interval (design/mesh.md section 5.3).
pub const KEEPALIVE: Duration = Duration::from_secs(25);
/// After a failed or dropped connection, wait at least this long before reconnecting.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
/// Number of packets held before the connection is authenticated.
const MAX_HELD: usize = 64;
/// Send queue of each connection, and the queue of messages a connection hands to the forwarding
/// task.
const CONN_QUEUE: usize = 256;
const EVENT_QUEUE: usize = 256;
/// Interval for checking whether the configuration file, or the mesh process this runs in, has a
/// new configuration.
const CONFIG_POLL: Duration = Duration::from_secs(1);

#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("reading the transport config {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("transport config is not valid: {0}")]
    Invalid(String),
}

/// Where the configuration comes from (ADR 0013).
#[derive(Clone)]
pub enum ConfigSource {
    /// The helper socket of the mesh process (design/status.md section 3.1), asked every 5 seconds.
    Helper(PathBuf),
    /// The mesh process this forwarding runs in (macOS, design/mesh.md section 5.3), asked every
    /// second: each question is a message to its worker thread.
    Mesh(Arc<dyn HelperSource + Sync>),
    /// A local file written by the mesh process (lab builds), checked every second.
    File(PathBuf),
}

impl ConfigSource {
    fn interval(&self) -> Duration {
        match self {
            Self::Helper(_) => nett_mesh::helper::FETCH_INTERVAL,
            Self::Mesh(_) | Self::File(_) => CONFIG_POLL,
        }
    }

    /// The current configuration; `None` while there is none yet. An unreachable mesh process is not
    /// an error: the adapter keeps its configuration and asks again.
    async fn fetch(&self) -> Result<Option<TransportConfig>, ForwardError> {
        match self {
            Self::Helper(path) => {
                let owned = path.clone();
                let got =
                    tokio::task::spawn_blocking(move || nett_mesh::helper::fetch_transport(&owned))
                        .await
                        .map_err(|e| ForwardError::Invalid(e.to_string()))?;
                match got {
                    Ok(config) => Ok(config),
                    Err(error) => {
                        tracing::debug!(%error, "fetching the transport config");
                        Ok(None)
                    }
                }
            }
            // The worker thread answers within its query timeout; a busy one is asked again
            Self::Mesh(mesh) => {
                let mesh = Arc::clone(mesh);
                tokio::task::spawn_blocking(move || mesh.transport().flatten())
                    .await
                    .map_err(|e| ForwardError::Invalid(e.to_string()))
            }
            Self::File(path) => {
                let owned = path.clone();
                let read = tokio::task::spawn_blocking(move || std::fs::read(owned))
                    .await
                    .map_err(|e| ForwardError::Read {
                        path: path.display().to_string(),
                        source: std::io::Error::other(e),
                    })?;
                let bytes = match read {
                    Ok(bytes) => bytes,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(source) => {
                        return Err(ForwardError::Read {
                            path: path.display().to_string(),
                            source,
                        });
                    }
                };
                serde_json::from_slice(&bytes)
                    .map(Some)
                    .map_err(|e| ForwardError::Invalid(e.to_string()))
            }
        }
    }
}

/// Runs until `shutdown` completes. When there is no configuration yet it waits, and when the
/// configuration changes it rebuilds all forwarding tasks with the new one.
pub async fn run(
    source: ConfigSource,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ForwardError> {
    tokio::pin!(shutdown);
    let mut current: Option<(TransportConfig, Vec<JoinHandle<()>>)> = None;
    let mut poll = tokio::time::interval(source.interval());
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            _ = poll.tick() => {
                let Some(config) = source.fetch().await? else { continue };
                if current.as_ref().is_some_and(|(seen, _)| *seen == config) {
                    continue;
                }
                config.validate().map_err(|e| ForwardError::Invalid(e.to_string()))?;
                if let Some((_, tasks)) = current.take() {
                    for task in tasks {
                        task.abort();
                    }
                }
                let wireguard = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), config.wireguard_port);
                tracing::info!(targets = config.targets.len(), "transport config applied");
                let tasks = config
                    .targets
                    .iter()
                    .cloned()
                    .map(|t| tokio::spawn(target_or_log(t, wireguard, config.interface)))
                    .collect();
                current = Some((config, tasks));
            }
        }
    }
    if let Some((_, tasks)) = current {
        for task in tasks {
            task.abort();
        }
    }
    Ok(())
}

async fn target_or_log(target: TlsTarget, wireguard: SocketAddr, interface: Option<u32>) {
    let listen = target.listen;
    if let Err(error) = target_loop(target, wireguard, interface).await {
        tracing::error!(%listen, %error, "TLS transport for this relay stopped");
    }
}

enum Out {
    Data(Vec<u8>),
    Ping,
}

enum Event {
    Connected(mpsc::Sender<Out>),
    Message(Vec<u8>),
    Closed,
}

struct Link {
    tx: mpsc::Sender<Out>,
    /// A relay probe has already been sent on this connection.
    authenticated: bool,
}

async fn target_loop(
    target: TlsTarget,
    wireguard: SocketAddr,
    interface: Option<u32>,
) -> std::io::Result<()> {
    let udp = UdpSocket::bind(target.listen).await?;
    let connector = client::connector(target.fingerprint).map_err(std::io::Error::other)?;
    let (events_tx, mut events) = mpsc::channel(EVENT_QUEUE);
    let mut link: Option<Link> = None;
    let mut connecting = false;
    let mut next_attempt = Instant::now();
    let mut held: VecDeque<Vec<u8>> = VecDeque::new();
    // The mesh process port that sent the probe: relay replies go back to it
    let mut probe_source: Option<SocketAddr> = None;
    let mut buf = vec![0u8; MAX_MESSAGE];
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    loop {
        tokio::select! {
            received = udp.recv_from(&mut buf) => {
                let (len, from) = received?;
                // Forward only packets sent by this machine
                if !from.ip().is_loopback() || len == 0 {
                    continue;
                }
                let data = buf[..len].to_vec();
                let probe = data[0] == RELAY_PROBE;
                if probe {
                    probe_source = Some(from);
                }
                match link.as_mut() {
                    Some(l) if l.authenticated => drop(l.tx.try_send(Out::Data(data))),
                    Some(l) if probe => {
                        drop(l.tx.try_send(Out::Data(data)));
                        l.authenticated = true;
                        flush(l, &mut held);
                    }
                    _ => {
                        hold(&mut held, data);
                        if link.is_none() && !connecting && Instant::now() >= next_attempt {
                            connecting = true;
                            tokio::spawn(connection(
                                target.connect,
                                interface,
                                connector.clone(),
                                events_tx.clone(),
                            ));
                        }
                    }
                }
            }
            Some(event) = events.recv() => match event {
                Event::Connected(tx) => {
                    connecting = false;
                    let mut l = Link { tx, authenticated: false };
                    // The first message is a held probe; the rest follow in arrival order
                    if let Some(i) = held.iter().position(|d| d.first() == Some(&RELAY_PROBE))
                        && let Some(first) = held.remove(i)
                    {
                        drop(l.tx.try_send(Out::Data(first)));
                        l.authenticated = true;
                        flush(&l, &mut held);
                    }
                    link = Some(l);
                }
                Event::Message(data) => {
                    let to = if data.first() == Some(&RELAY_REPLY) { probe_source } else { Some(wireguard) };
                    if let Some(to) = to {
                        drop(udp.try_send_to(&data, to));
                    }
                }
                Event::Closed => {
                    connecting = false;
                    link = None;
                    next_attempt = Instant::now() + RECONNECT_DELAY;
                }
            },
            _ = keepalive.tick() => {
                if let Some(l) = &link {
                    drop(l.tx.try_send(Out::Ping));
                }
            }
        }
    }
}

fn hold(held: &mut VecDeque<Vec<u8>>, data: Vec<u8>) {
    if held.len() >= MAX_HELD {
        held.pop_front();
    }
    held.push_back(data);
}

fn flush(link: &Link, held: &mut VecDeque<Vec<u8>>) {
    for data in held.drain(..) {
        drop(link.tx.try_send(Out::Data(data)));
    }
}

/// One connection to a relay: after connecting, hands received binary messages to the forwarding
/// task, and writes the forwarding task's packets to the connection.
async fn connection(
    addr: SocketAddr,
    interface: Option<u32>,
    connector: TlsConnector,
    events: mpsc::Sender<Event>,
) {
    let ws = match client::connect(addr, interface, &connector).await {
        Ok(ws) => ws,
        Err(error) => {
            tracing::warn!(%error, "TLS relay connection failed");
            drop(events.send(Event::Closed).await);
            return;
        }
    };
    tracing::info!(relay = %addr, "TLS relay connected");
    let (tx, mut rx) = mpsc::channel(CONN_QUEUE);
    if events.send(Event::Connected(tx)).await.is_err() {
        return;
    }
    let (mut sink, mut source) = ws.split();
    loop {
        tokio::select! {
            incoming = source.next() => match incoming {
                Some(Ok(Message::Binary(data))) => {
                    if events.send(Event::Message(data.to_vec())).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                _ => break,
            },
            outgoing = rx.recv() => {
                let message = match outgoing {
                    Some(Out::Data(data)) => Message::binary(data),
                    Some(Out::Ping) => Message::Ping(Vec::new().into()),
                    None => break,
                };
                if sink.send(message).await.is_err() {
                    break;
                }
            }
        }
    }
    tracing::info!(relay = %addr, "TLS relay connection closed");
    drop(sink.close().await);
    drop(events.send(Event::Closed).await);
}

#[cfg(test)]
mod tests {
    use nett_core::transport::CertFingerprint;
    use nett_mesh::helper::RelayAssignment;

    use super::*;

    /// The mesh process answering for the forwarding that runs inside it.
    struct Mesh(TransportConfig);

    impl HelperSource for Mesh {
        fn relay(&self, _: Option<CertFingerprint>) -> Option<Option<RelayAssignment>> {
            Some(None)
        }

        fn transport(&self) -> Option<Option<TransportConfig>> {
            Some(Some(self.0.clone()))
        }
    }

    /// Inside the mesh process (macOS) the forwarding takes the mesh process's configuration: a
    /// packet sent to the loopback port it names makes it connect to that relay
    #[tokio::test]
    async fn forwarding_in_the_mesh_process_follows_its_configuration() {
        let relay = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("relay");
        let free = std::net::UdpSocket::bind("127.0.0.1:0").expect("free port");
        let listen = free.local_addr().expect("address");
        drop(free);
        let config = TransportConfig {
            wireguard_port: 51820,
            targets: vec![TlsTarget {
                listen,
                connect: relay.local_addr().expect("relay address"),
                fingerprint: CertFingerprint([0; 32]),
            }],
            interface: None,
        };
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let forwarding = tokio::spawn(run(
            ConfigSource::Mesh(Arc::new(Mesh(config))),
            async move {
                let _ = stopped.await;
            },
        ));
        let wireguard = UdpSocket::bind("127.0.0.1:0").await.expect("sender");
        let deadline = Instant::now() + Duration::from_secs(5);
        let connected = loop {
            assert!(
                Instant::now() < deadline,
                "the forwarding never connected to the relay"
            );
            wireguard
                .send_to(&[RELAY_PROBE, 1, 2, 3], listen)
                .await
                .expect("send");
            if let Ok(accepted) =
                tokio::time::timeout(Duration::from_millis(100), relay.accept()).await
            {
                break accepted;
            }
        };
        assert!(connected.expect("accepted").1.ip().is_loopback());
        drop(stop);
        forwarding.await.expect("task").expect("stopped cleanly");
    }
}
