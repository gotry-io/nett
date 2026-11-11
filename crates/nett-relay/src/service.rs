//! nett-relay as a service (design/mesh.md section 5.2): it creates its TLS certificate once, fetches its
//! assignment from the mesh process over the helper socket (design/status.md section 3.1) when it starts
//! and every 5 seconds, and applies changes in place. It does not depend on nett-node.

use std::future::Future;
use std::net::{Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use nett_core::transport::CertFingerprint;
use nett_mesh::helper::{FETCH_INTERVAL, RelayAssignment, fetch_relay};
use tokio::sync::mpsc;

use crate::cert::{CertError, RelayCert};
use crate::relay::{AssignedMember, AssignmentError, Relay};
use crate::server::{
    ASSIGNMENT_QUEUE, Assignment, TlsIngress, TlsSetupError, cert_acceptor, serve, tls_listener,
};

/// File holding the index table and bindings in the state directory.
pub const STATE_FILE: &str = "relay-state.json";

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error(transparent)]
    Cert(#[from] CertError),
    #[error(transparent)]
    Tls(#[from] TlsSetupError),
    #[error("the relay assignment from the mesh process is not valid: {0}")]
    Assignment(#[from] AssignmentError),
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

/// How the service ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// `shutdown` completed.
    Shutdown,
    /// The assignment changed its ports: the service manager starts the relay again on the new ones.
    PortsChanged,
}

/// Runs the relay until `shutdown` completes or the assignment changes its ports.
pub async fn run(
    helpers: PathBuf,
    state_dir: PathBuf,
    shutdown: impl Future<Output = ()>,
) -> Result<Ended, ServiceError> {
    let cert = RelayCert::load_or_create(&state_dir)?;
    let fingerprint = cert.fingerprint();
    tracing::info!(%fingerprint, "relay TLS certificate");
    tokio::pin!(shutdown);
    // Wait for an assignment: the service may start before the mesh process has its desired state
    let assignment = loop {
        if let Some(a) = fetch(&helpers, fingerprint).await {
            break a;
        }
        tokio::select! {
            () = &mut shutdown => return Ok(Ended::Shutdown),
            () = tokio::time::sleep(FETCH_INTERVAL) => {}
        }
    };
    let ports = (assignment.port, assignment.tls_port);
    let first = convert(&assignment);
    let relay = Relay::new(&first.members, &first.connections)?;
    let udp = tokio::net::UdpSocket::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), ports.0))
        .await
        .map_err(|source| ServiceError::Bind {
            what: "the UDP relay",
            port: ports.0,
            source,
        })?;
    let tls = match ports.1 {
        Some(port) => Some(TlsIngress {
            listener: tls_listener(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port)).map_err(
                |source| ServiceError::Bind {
                    what: "the TLS",
                    port,
                    source,
                },
            )?,
            acceptor: cert_acceptor(&cert)?,
        }),
        None => None,
    };
    tracing::info!(
        udp = ports.0,
        tls = ?ports.1,
        members = first.members.len(),
        links = first.connections.len(),
        "relay started"
    );
    let (tx, rx) = mpsc::channel(ASSIGNMENT_QUEUE);
    let (ports_changed_tx, mut ports_changed) = mpsc::channel::<()>(1);
    let fetcher = tokio::spawn(follow(
        helpers,
        fingerprint,
        assignment,
        tx,
        ports_changed_tx,
    ));
    let mut ended = Ended::Shutdown;
    let stop = async {
        tokio::select! {
            () = &mut shutdown => {}
            Some(()) = ports_changed.recv() => ended = Ended::PortsChanged,
        }
    };
    let served = serve(
        udp,
        tls,
        relay,
        Some(state_dir.join(STATE_FILE)),
        Some(rx),
        stop,
    )
    .await;
    fetcher.abort();
    served?;
    Ok(ended)
}

/// Asks the mesh process again every 5 seconds and passes on changed assignments; a change of ports
/// ends the relay so that it binds the new ones.
async fn follow(
    helpers: PathBuf,
    fingerprint: CertFingerprint,
    mut current: RelayAssignment,
    tx: mpsc::Sender<Assignment>,
    ports_changed: mpsc::Sender<()>,
) {
    let mut tick = tokio::time::interval(FETCH_INTERVAL);
    tick.tick().await;
    loop {
        tick.tick().await;
        let Some(next) = fetch(&helpers, fingerprint).await else {
            continue;
        };
        if next == current {
            continue;
        }
        if (next.port, next.tls_port) != (current.port, current.tls_port) {
            tracing::info!(udp = next.port, tls = ?next.tls_port, "relay ports changed; restarting");
            let _ = ports_changed.try_send(());
            return;
        }
        // Dropped when the queue is full: the next round sends the latest one again
        if tx.try_send(convert(&next)).is_ok() {
            current = next;
        }
    }
}

/// One fetch over the helper socket, on a blocking thread. `None` when the mesh process cannot be
/// reached or this machine is not a relay right now.
async fn fetch(helpers: &Path, fingerprint: CertFingerprint) -> Option<RelayAssignment> {
    let path = helpers.to_owned();
    match tokio::task::spawn_blocking(move || fetch_relay(&path, Some(fingerprint))).await {
        Ok(Ok(assignment)) => assignment,
        Ok(Err(error)) => {
            tracing::debug!(%error, "fetching the relay assignment");
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
