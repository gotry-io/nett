//! Forwarding between loopback ports and TLS connections (design/mesh.md section 5.3).
//!
//! It runs in the nett daemon, which asks the mesh for its configuration (ADR 0013). One task per
//! TLS relay: it connects to the relay when the first packet arrives and stays connected afterwards
//! (keepalive every 25 seconds, i.e. a standby connection), and reconnects when a packet arrives
//! after a disconnect. The first message on a connection must be a relay probe sent by the mesh
//! (the relay authenticates it from this); before then other packets are held in a bounded queue.

use std::collections::VecDeque;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
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
use crate::queue::{self, SEND_QUEUE};

/// WebSocket keepalive interval (design/mesh.md section 5.3).
pub const KEEPALIVE: Duration = Duration::from_secs(25);
/// After a failed or dropped connection, wait at least this long before reconnecting.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
/// After a relay's loopback port failed, for example while another process still holds it, it is
/// opened again after a delay that starts here and doubles up to [`REOPEN_MAX`].
const REOPEN_DELAY: Duration = Duration::from_secs(1);
const REOPEN_MAX: Duration = Duration::from_secs(60);
/// Number of packets held before the connection is authenticated: they go to the connection's send
/// queue, which keeps as many.
const MAX_HELD: usize = SEND_QUEUE;
/// The queue of messages a connection hands to the forwarding task.
const EVENT_QUEUE: usize = 256;
/// Interval for asking the mesh whether it has a new configuration: each question is a message to
/// its worker thread.
const CONFIG_POLL: Duration = Duration::from_secs(1);

#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("asking the mesh for the transport config: {0}")]
    Invalid(String),
}

/// The current configuration; `None` while there is none yet. The worker thread answers within its
/// query timeout; a busy one is asked again.
async fn fetch(
    mesh: &Arc<dyn HelperSource + Sync>,
) -> Result<Option<TransportConfig>, ForwardError> {
    let mesh = Arc::clone(mesh);
    tokio::task::spawn_blocking(move || mesh.transport().flatten())
        .await
        .map_err(|e| ForwardError::Invalid(e.to_string()))
}

/// Runs until `shutdown` completes. When there is no configuration yet it waits, and when the
/// configuration changes it rebuilds all forwarding tasks with the new one.
pub async fn run(
    mesh: Arc<dyn HelperSource + Sync>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ForwardError> {
    tokio::pin!(shutdown);
    let mut current: Option<(TransportConfig, Vec<JoinHandle<()>>)> = None;
    let mut poll = tokio::time::interval(CONFIG_POLL);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            _ = poll.tick() => {
                let Some(config) = fetch(&mesh).await? else { continue };
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

/// Runs one relay's forwarding until the task is aborted with its configuration: a port that fails
/// is opened again, so the relay stays reachable once the cause goes away.
async fn target_or_log(target: TlsTarget, wireguard: SocketAddr, interface: Option<u32>) {
    let listen = target.listen;
    let mut delay = REOPEN_DELAY;
    loop {
        let started = Instant::now();
        if let Err(error) = target_loop(target.clone(), wireguard, interface).await {
            // A port that worked for a while starts over from the shortest delay
            if started.elapsed() > REOPEN_MAX {
                delay = REOPEN_DELAY;
            }
            tracing::warn!(%listen, %error, retry_in = ?delay, "TLS transport for this relay stopped");
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(REOPEN_MAX);
    }
}

enum Out {
    Data(Vec<u8>),
    Ping,
}

enum Event {
    Connected(queue::Sender<Out>),
    Message(Vec<u8>),
    Closed,
}

struct Link {
    tx: queue::Sender<Out>,
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
    // The mesh port that sent the probe: relay replies go back to it
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
                    Some(l) if l.authenticated => {
                        l.tx.push(Out::Data(data));
                    }
                    Some(l) if probe => {
                        l.tx.first(Out::Data(data));
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
                        l.tx.first(Out::Data(first));
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
                    l.tx.push(Out::Ping);
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
        link.tx.push(Out::Data(data));
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
    let (tx, mut rx) = queue::queue();
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

    /// The mesh answering for the forwarding that runs inside it.
    struct Mesh(TransportConfig);

    impl HelperSource for Mesh {
        fn relay(&self, _: Option<CertFingerprint>) -> Option<Option<RelayAssignment>> {
            Some(None)
        }

        fn transport(&self) -> Option<Option<TransportConfig>> {
            Some(Some(self.0.clone()))
        }
    }

    /// Inside the mesh (macOS) the forwarding takes the mesh's configuration: a
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
        let forwarding = tokio::spawn(run(Arc::new(Mesh(config)), async move {
            let _ = stopped.await;
        }));
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

    /// A loopback port another process still holds, as the separate adapter of an older version
    /// does during an upgrade, is opened once that process lets it go
    #[tokio::test]
    async fn a_port_held_by_another_process_is_opened_once_free() {
        let relay = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("relay");
        let holder = std::net::UdpSocket::bind("127.0.0.1:0").expect("holder");
        let listen = holder.local_addr().expect("address");
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
        let forwarding = tokio::spawn(run(Arc::new(Mesh(config)), async move {
            let _ = stopped.await;
        }));
        // The forwarding meets the held port first
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(holder);
        let wireguard = UdpSocket::bind("127.0.0.1:0").await.expect("sender");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                Instant::now() < deadline,
                "the port was not opened after it was let go"
            );
            wireguard
                .send_to(&[RELAY_PROBE, 1, 2, 3], listen)
                .await
                .expect("send");
            if tokio::time::timeout(Duration::from_millis(100), relay.accept())
                .await
                .is_ok()
            {
                break;
            }
        }
        drop(stop);
        forwarding.await.expect("task").expect("stopped cleanly");
    }
}
