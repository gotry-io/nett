//! The relay's two sides (ADR 0032, design/mesh.md section 5.2): the relay in the nett daemon, which
//! asks the mesh in the same process for its assignment every second and applies changes in place,
//! and nett-relay, the relay's public TCP entry, which asks the daemon over the helper socket
//! (design/status.md section 3.1) for its ports. Neither depends on the daemon's connection to the
//! Hub.

use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use nett_core::transport::CertFingerprint;
use nett_mesh::config::ObfsPortDoc;
use nett_mesh::helper::{FETCH_INTERVAL, HelperSource, RelayAssignment, TlsEntry, fetch_tls_entry};
use tokio::sync::mpsc;

use crate::cert::{CertError, RelayCert};
use crate::entry::{TlsIngress, TlsSetupError, cert_acceptor, tls_listener};
use crate::relay::{AssignedMember, AssignmentError, Relay};
use crate::server::{ASSIGNMENT_QUEUE, Assignment, ObfsIngress, serve};

/// How often the relay in the daemon asks the mesh for its assignment, as the transports do.
const ASSIGNMENT_POLL: Duration = Duration::from_secs(1);
/// After the relay's ports could not be opened, how long before it tries again, doubling up to the
/// longest.
const RETRY_DELAY: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error(transparent)]
    Cert(#[from] CertError),
    #[error(transparent)]
    Tls(#[from] TlsSetupError),
    #[error("the relay assignment from the nett service is not valid: {0}")]
    Assignment(#[from] AssignmentError),
    #[error("the relay assignment's obfuscation padding is not valid: {0}")]
    Obfs(#[from] nett_mesh::obfs::ObfsError),
    #[error("binding {what} port {port}: {source}")]
    Bind {
        what: &'static str,
        port: u16,
        #[source]
        source: std::io::Error,
    },
    #[error("relay socket: {0}")]
    Io(#[from] std::io::Error),
}

/// The obfuscated port of an assignment, on every address (design/obfuscation.md section 2).
pub async fn obfs_ingress(doc: &ObfsPortDoc) -> Result<ObfsIngress, ServiceError> {
    let socket =
        tokio::net::UdpSocket::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), doc.port))
            .await
            .map_err(|source| ServiceError::Bind {
                what: "the obfuscated",
                port: doc.port,
                source,
            })?;
    let padding = nett_mesh::obfs::Padding::new(doc.padding.min, doc.padding.max)?;
    let key = nett_mesh::obfs::ObfsKey::from_bytes(doc.key.0);
    Ok(ObfsIngress {
        socket,
        obfuscator: nett_mesh::obfs::Obfuscator::new(&key, padding),
        rng: ring::rand::SystemRandom::new(),
    })
}

/// Runs the relay in the nett daemon until `shutdown` completes: while the mesh assigns this machine
/// a relay, it serves the assignment's ports, and a change of ports opens the new ones in place.
/// `state` is the file the bindings are saved to and restored from; `handoff` holds the loopback
/// port nett-relay hands TLS connections to, 0 while there is none. Ports that cannot be opened are
/// tried again with backoff, so the relay comes up once the cause goes away.
pub async fn run_in_daemon(
    mesh: Arc<dyn HelperSource + Sync>,
    state: PathBuf,
    handoff: Arc<AtomicU16>,
    shutdown: impl Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    let mut delay = RETRY_DELAY;
    loop {
        let Some(assignment) = wait_for_assignment(&mesh, &mut shutdown).await else {
            return;
        };
        let (relay, udp, handoff_socket, obfs) = match open(&assignment).await {
            Ok(opened) => opened,
            Err(error) => {
                tracing::warn!(%error, retry_in = ?delay, "the relay could not start");
                tokio::select! {
                    () = &mut shutdown => return,
                    () = tokio::time::sleep(delay) => {}
                }
                delay = (delay * 2).min(RETRY_MAX);
                continue;
            }
        };
        delay = RETRY_DELAY;
        let port = handoff_socket
            .as_ref()
            .and_then(|s| s.local_addr().ok())
            .map_or(0, |a| a.port());
        handoff.store(port, Ordering::Release);
        let (tx, rx) = mpsc::channel(ASSIGNMENT_QUEUE);
        let (reopen_tx, mut reopen) = mpsc::channel::<()>(1);
        let follower = tokio::spawn(follow(mesh.clone(), assignment, tx, reopen_tx));
        let mut stopped = false;
        let stop = async {
            tokio::select! {
                () = &mut shutdown => stopped = true,
                Some(()) = reopen.recv() => {}
            }
        };
        let served = serve(
            udp,
            handoff_socket,
            obfs,
            relay,
            Some(state.clone()),
            Some(rx),
            stop,
        )
        .await;
        follower.abort();
        handoff.store(0, Ordering::Release);
        if let Err(error) = served {
            tracing::warn!(%error, "the relay stopped; starting it again");
        }
        if stopped {
            return;
        }
    }
}

/// Waits until the mesh assigns a relay; `None` when `shutdown` completes first.
async fn wait_for_assignment(
    mesh: &Arc<dyn HelperSource + Sync>,
    shutdown: &mut std::pin::Pin<&mut impl Future<Output = ()>>,
) -> Option<RelayAssignment> {
    let mut poll = tokio::time::interval(ASSIGNMENT_POLL);
    loop {
        tokio::select! {
            () = shutdown.as_mut() => return None,
            _ = poll.tick() => {
                if let Some(Some(a)) = ask(mesh).await {
                    return Some(a);
                }
            }
        }
    }
}

/// The relay, and the sockets of its ports: the relay port, the hand-off port when it serves TLS,
/// and the obfuscated port when it offers one.
async fn open(
    assignment: &RelayAssignment,
) -> Result<
    (
        Relay,
        tokio::net::UdpSocket,
        Option<tokio::net::UdpSocket>,
        Option<ObfsIngress>,
    ),
    ServiceError,
> {
    let first = convert(assignment);
    let relay = Relay::new(&first.members, &first.connections)?;
    let port = assignment.port;
    let udp = tokio::net::UdpSocket::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port))
        .await
        .map_err(|source| ServiceError::Bind {
            what: "the UDP relay",
            port,
            source,
        })?;
    let handoff = match assignment.tls_port {
        Some(_) => {
            let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            nett_mesh::sockbuf::enlarge_receive_buffer(&socket);
            Some(socket)
        }
        None => None,
    };
    let obfs = match &assignment.obfs {
        Some(doc) => Some(obfs_ingress(doc).await?),
        None => None,
    };
    tracing::info!(
        udp = port,
        tls = ?assignment.tls_port,
        obfs = ?assignment.obfs.as_ref().map(|o| o.port),
        members = first.members.len(),
        links = first.connections.len(),
        "relay started"
    );
    Ok((relay, udp, handoff, obfs))
}

/// Asks the mesh again every second and passes on changed assignments; a change of ports, of the
/// obfuscation key or padding, or the end of the assignment, reopens the relay.
async fn follow(
    mesh: Arc<dyn HelperSource + Sync>,
    mut current: RelayAssignment,
    tx: mpsc::Sender<Assignment>,
    reopen: mpsc::Sender<()>,
) {
    let mut poll = tokio::time::interval(ASSIGNMENT_POLL);
    poll.tick().await;
    loop {
        poll.tick().await;
        let Some(next) = ask(&mesh).await else {
            continue;
        };
        let Some(next) = next else {
            tracing::info!("this machine no longer relays; the relay stops");
            let _ = reopen.try_send(());
            return;
        };
        if next == current {
            continue;
        }
        if (next.port, next.tls_port) != (current.port, current.tls_port)
            || next.obfs != current.obfs
        {
            tracing::info!(udp = next.port, tls = ?next.tls_port, obfs = ?next.obfs.as_ref().map(|o| o.port), "relay ports changed; opening the new ones");
            let _ = reopen.try_send(());
            return;
        }
        // Dropped when the queue is full: the next round sends the latest one again
        if tx.try_send(convert(&next)).is_ok() {
            current = next;
        }
    }
}

/// One question to the mesh's thread, on a blocking thread; `None` when it is busy.
async fn ask(mesh: &Arc<dyn HelperSource + Sync>) -> Option<Option<RelayAssignment>> {
    let mesh = mesh.clone();
    tokio::task::spawn_blocking(move || mesh.relay())
        .await
        .ok()
        .flatten()
}

/// How nett-relay ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// `shutdown` completed.
    Shutdown,
    /// The TLS port changed, or the relay no longer serves TLS: the service manager starts
    /// nett-relay again on the new port, or nett-node stops it.
    PortsChanged,
}

/// Runs nett-relay, the relay's TLS entry, until `shutdown` completes or its TLS port changes: it
/// listens on the relay's TLS port with `cert` and hands each connection to the relay in the
/// daemon (ADR 0032), at the hand-off port the daemon gives now.
pub async fn run_entry(
    helpers: PathBuf,
    cert: RelayCert,
    shutdown: impl Future<Output = ()>,
) -> Result<Ended, ServiceError> {
    let fingerprint = cert.fingerprint();
    tracing::info!(%fingerprint, "relay TLS certificate");
    tokio::pin!(shutdown);
    // Wait for the ports: the service may start before the mesh has its desired state, or before
    // the relay in the daemon has opened its hand-off port
    let entry = loop {
        if let Some(e) = fetch(&helpers, fingerprint).await {
            break e;
        }
        tokio::select! {
            () = &mut shutdown => return Ok(Ended::Shutdown),
            () = tokio::time::sleep(FETCH_INTERVAL) => {}
        }
    };
    let ingress = TlsIngress {
        listener: tls_listener(SocketAddr::new(
            Ipv6Addr::UNSPECIFIED.into(),
            entry.tls_port,
        ))
        .map_err(|source| ServiceError::Bind {
            what: "the TLS",
            port: entry.tls_port,
            source,
        })?,
        acceptor: cert_acceptor(&cert)?,
    };
    tracing::info!(
        tls = entry.tls_port,
        handoff = entry.handoff_port,
        "relay TLS entry started"
    );
    let handoff = Arc::new(AtomicU16::new(entry.handoff_port));
    let (changed_tx, mut changed) = mpsc::channel::<()>(1);
    let watcher = tokio::spawn(watch(
        helpers,
        fingerprint,
        entry.tls_port,
        handoff.clone(),
        changed_tx,
    ));
    let mut ended = Ended::Shutdown;
    let stop = async {
        tokio::select! {
            () = &mut shutdown => {}
            Some(()) = changed.recv() => ended = Ended::PortsChanged,
        }
    };
    let served = crate::entry::serve(ingress, handoff, stop).await;
    watcher.abort();
    served?;
    Ok(ended)
}

/// Asks the daemon again every 5 seconds, which also keeps the fingerprint reported, and follows its
/// hand-off port, which changes when the daemon restarts; a change of the TLS port, or the end of the
/// TLS entry, ends nett-relay.
async fn watch(
    helpers: PathBuf,
    fingerprint: CertFingerprint,
    tls_port: u16,
    handoff: Arc<AtomicU16>,
    changed: mpsc::Sender<()>,
) {
    let mut tick = tokio::time::interval(FETCH_INTERVAL);
    tick.tick().await;
    loop {
        tick.tick().await;
        match fetch_answer(&helpers, fingerprint).await {
            Some(Some(next)) if next.tls_port == tls_port => {
                if handoff.swap(next.handoff_port, Ordering::AcqRel) != next.handoff_port {
                    tracing::info!(
                        handoff = next.handoff_port,
                        "the relay's hand-off port changed"
                    );
                }
            }
            // The daemon is unreachable or busy, or restarting: keep serving what it gave
            None => {}
            Some(_) => {
                tracing::info!("the relay's TLS entry changed; restarting");
                let _ = changed.try_send(());
                return;
            }
        }
    }
}

/// The TLS entry's ports, when the daemon gives them.
async fn fetch(helpers: &Path, fingerprint: CertFingerprint) -> Option<TlsEntry> {
    fetch_answer(helpers, fingerprint).await.flatten()
}

/// One question over the helper socket, on a blocking thread: `None` when the daemon cannot be
/// reached, `Some(None)` when it gives no TLS entry right now.
async fn fetch_answer(helpers: &Path, fingerprint: CertFingerprint) -> Option<Option<TlsEntry>> {
    let path = helpers.to_owned();
    match tokio::task::spawn_blocking(move || fetch_tls_entry(&path, fingerprint)).await {
        Ok(Ok(entry)) => Some(entry),
        Ok(Err(error)) => {
            tracing::debug!(%error, "asking for the relay's TLS entry");
            None
        }
        Err(_) => None,
    }
}

fn convert(a: &RelayAssignment) -> Assignment {
    Assignment {
        members: a
            .members
            .iter()
            .map(|m| AssignedMember {
                public_key: m.public_key,
                address: m.address,
                token: m.token.0,
            })
            .collect(),
        connections: a.links.iter().map(|[x, y]| (*x, *y)).collect(),
    }
}
