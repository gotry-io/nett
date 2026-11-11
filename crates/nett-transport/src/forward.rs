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
use std::path::Path;
use std::time::{Duration, Instant};

use futures_util::{SinkExt as _, StreamExt as _};
use nett_core::transport::{RELAY_PROBE, RELAY_REPLY, TlsTarget, TransportConfig};
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
/// Interval for checking whether the configuration file has changed.
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

/// Runs until `shutdown` completes. The configuration file is written by the mesh process (ADR
/// 0013); when the file does not exist yet it waits, and when the content changes it rebuilds all
/// forwarding tasks with the new configuration.
pub async fn run(path: &Path, shutdown: impl Future<Output = ()>) -> Result<(), ForwardError> {
    tokio::pin!(shutdown);
    let mut current: Option<(Vec<u8>, Vec<JoinHandle<()>>)> = None;
    let mut poll = tokio::time::interval(CONFIG_POLL);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            _ = poll.tick() => {
                let owned = path.to_path_buf();
                let read = tokio::task::spawn_blocking(move || std::fs::read(owned))
                    .await
                    .map_err(|e| ForwardError::Read {
                        path: path.display().to_string(),
                        source: std::io::Error::other(e),
                    })?;
                let bytes = match read {
                    Ok(bytes) => bytes,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(source) => {
                        return Err(ForwardError::Read { path: path.display().to_string(), source });
                    }
                };
                if current.as_ref().is_some_and(|(seen, _)| *seen == bytes) {
                    continue;
                }
                let config: TransportConfig = serde_json::from_slice(&bytes)
                    .map_err(|e| ForwardError::Invalid(e.to_string()))?;
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
                    .into_iter()
                    .map(|t| tokio::spawn(target_or_log(t, wireguard)))
                    .collect();
                current = Some((bytes, tasks));
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

async fn target_or_log(target: TlsTarget, wireguard: SocketAddr) {
    let listen = target.listen;
    if let Err(error) = target_loop(target, wireguard).await {
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

async fn target_loop(target: TlsTarget, wireguard: SocketAddr) -> std::io::Result<()> {
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
async fn connection(addr: SocketAddr, connector: TlsConnector, events: mpsc::Sender<Event>) {
    let ws = match client::connect(addr, &connector).await {
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
