//! Served ports (design/mesh.md section 12.1, ADR 0028): TCP connections that reach this machine's
//! mesh addresses on a port its signed node policy serves are forwarded unchanged to the same port on
//! `127.0.0.1`, for services that listen only on loopback. The access rules have already decided who
//! may connect; this side makes sure that only connections that came through the mesh reach loopback.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use nett_core::prefix::IpPrefix;
use nett_trust::payload::ServedPort;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};

/// Forwarded connections at once on this machine, over all served ports; a new connection beyond it
/// is closed at once.
pub const MAX_CONNECTIONS: usize = 256;
/// Buffer in each direction of a forwarded connection.
const BUFFER: usize = 8 * 1024;
/// How long connecting to the service may take, as in Tailscale's `tailscale serve`.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// TCP keepalive on both sides: a connection whose peer has gone closes after the idle time plus
/// the lost probes, about 90 seconds; one whose peers are still there stays open however long it is
/// idle.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_PROBES: u32 = 3;
/// After accepting fails (out of file descriptors, for example), the wait before accepting again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The ports being forwarded, on the async runtime given at creation. Dropping it stops every port
/// and closes their connections.
pub struct Served {
    handle: Handle,
    permits: Arc<Semaphore>,
    ports: BTreeMap<ServedPort, Vec<JoinHandle<()>>>,
}

impl Served {
    pub fn new(handle: Handle) -> Self {
        Self {
            handle,
            permits: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            ports: BTreeMap::new(),
        }
    }

    /// The ports being forwarded now.
    pub fn ports(&self) -> impl Iterator<Item = ServedPort> + '_ {
        self.ports.keys().copied()
    }

    /// Starts forwarding `port` from `listeners`, bound to this machine's mesh addresses on the mesh
    /// interface. A connection whose peer is outside `mesh` (the mesh prefixes) is closed at once.
    pub fn start(
        &mut self,
        port: ServedPort,
        listeners: Vec<std::net::TcpListener>,
        mesh: &[IpPrefix],
    ) -> io::Result<()> {
        let _runtime = self.handle.enter();
        let listeners = listeners
            .into_iter()
            .map(|l| {
                l.set_nonblocking(true)?;
                TcpListener::from_std(l)
            })
            .collect::<io::Result<Vec<_>>>()?;
        let tasks = listeners
            .into_iter()
            .map(|listener| {
                self.handle.spawn(accept(
                    listener,
                    port.port,
                    mesh.to_vec(),
                    Arc::clone(&self.permits),
                ))
            })
            .collect();
        self.stop(port);
        self.ports.insert(port, tasks);
        Ok(())
    }

    /// Stops forwarding `port` and closes its connections.
    pub fn stop(&mut self, port: ServedPort) {
        for task in self.ports.remove(&port).into_iter().flatten() {
            task.abort();
        }
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        for task in self.ports.values().flatten() {
            task.abort();
        }
    }
}

/// Accepts connections on one listener. Its connections are tasks of its own set, so stopping the
/// listener closes them too.
async fn accept(listener: TcpListener, port: u16, mesh: Vec<IpPrefix>, permits: Arc<Semaphore>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    if !from_mesh(peer.ip(), &mesh) {
                        tracing::debug!(%peer, port, "closed a connection to a served port from outside the mesh");
                        continue;
                    }
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        tracing::warn!(%peer, port, limit = MAX_CONNECTIONS, "closed a connection to a served port: too many forwarded connections");
                        continue;
                    };
                    connections.spawn(async move {
                        forward(stream, peer, port).await;
                        drop(permit);
                    });
                }
                Err(error) => {
                    tracing::warn!(%error, port, "accepting on a served port");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

/// Whether a peer address belongs to the mesh. A host elsewhere can address a packet to the mesh
/// address through another interface; a forged mesh source cannot complete the handshake, since the
/// reply to it is routed into the mesh interface.
fn from_mesh(peer: IpAddr, mesh: &[IpPrefix]) -> bool {
    let peer = match peer {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(peer, IpAddr::V4),
        IpAddr::V4(_) => peer,
    };
    mesh.iter().any(|p| p.contains(peer))
}

/// Copies one connection to the service on `127.0.0.1` and back until either side closes it.
async fn forward(mut inbound: TcpStream, peer: SocketAddr, port: u16) {
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut outbound = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target)).await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            tracing::debug!(%peer, port, %error, "the served service did not take the connection");
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, port, "the served service did not answer within 10 seconds");
            return;
        }
    };
    for stream in [&inbound, &outbound] {
        // A proxy passes small writes on at once, as both ends would see them without it
        let _ = stream.set_nodelay(true);
        if let Err(error) = keepalive(stream) {
            tracing::debug!(%error, "setting TCP keepalive on a served connection");
        }
    }
    let _ =
        tokio::io::copy_bidirectional_with_sizes(&mut inbound, &mut outbound, BUFFER, BUFFER).await;
}

fn keepalive(stream: &TcpStream) -> io::Result<()> {
    use rustix::net::sockopt;
    sockopt::set_socket_keepalive(stream, true)?;
    sockopt::set_tcp_keepidle(stream, KEEPALIVE_IDLE)?;
    sockopt::set_tcp_keepintvl(stream, KEEPALIVE_INTERVAL)?;
    sockopt::set_tcp_keepcnt(stream, KEEPALIVE_PROBES)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn loopback_prefix() -> Vec<IpPrefix> {
        vec!["127.0.0.0/8".parse().expect("prefix")]
    }

    /// A service on loopback that answers each line with the line reversed, and the port it is on.
    async fn service() -> (u16, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("service");
        let port = listener.local_addr().expect("addr").port();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        let reply: Vec<u8> = buf[..n].iter().rev().copied().collect();
                        let _ = stream.write_all(&reply).await;
                    }
                });
            }
        });
        (port, task)
    }

    /// The forwarder's listener: on loopback in tests, standing in for the mesh address.
    fn front() -> (std::net::TcpListener, SocketAddr) {
        let listener = std::net::TcpListener::bind("127.0.0.2:0")
            .or_else(|_| std::net::TcpListener::bind("127.0.0.1:0"))
            .expect("front");
        let addr = listener.local_addr().expect("addr");
        (listener, addr)
    }

    async fn round_trip(front: SocketAddr) -> io::Result<Vec<u8>> {
        let mut client = TcpStream::connect(front).await?;
        client.write_all(b"abc").await?;
        let mut reply = [0u8; 3];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply))
            .await
            .map_err(|_| io::Error::other("no reply"))??;
        Ok(reply.to_vec())
    }

    #[tokio::test]
    async fn connections_from_the_mesh_reach_the_service_on_loopback() {
        let (port, _service) = service().await;
        let (listener, front) = front();
        let mut served = Served::new(Handle::current());
        // The service's port number is what the forwarder dials on 127.0.0.1
        served
            .start(ServedPort::tcp(port), vec![listener], &loopback_prefix())
            .expect("started");
        assert_eq!(round_trip(front).await.expect("forwarded"), b"cba");
        assert_eq!(served.ports().collect::<Vec<_>>(), [ServedPort::tcp(port)]);

        // Stopping the port closes its listener
        served.stop(ServedPort::tcp(port));
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(round_trip(front).await.is_err());
    }

    #[tokio::test]
    async fn peers_outside_the_mesh_prefixes_are_closed_at_once() {
        let (port, _service) = service().await;
        let (listener, front) = front();
        let mut served = Served::new(Handle::current());
        let elsewhere: Vec<IpPrefix> = vec!["100.88.0.0/16".parse().expect("prefix")];
        served
            .start(ServedPort::tcp(port), vec![listener], &elsewhere)
            .expect("started");
        assert!(round_trip(front).await.is_err());
    }

    #[tokio::test]
    async fn a_service_that_is_not_listening_closes_the_mesh_connection() {
        let free = std::net::TcpListener::bind("127.0.0.1:0").expect("free port");
        let port = free.local_addr().expect("addr").port();
        drop(free);
        let (listener, front) = front();
        let mut served = Served::new(Handle::current());
        served
            .start(ServedPort::tcp(port), vec![listener], &loopback_prefix())
            .expect("started");
        let mut client = TcpStream::connect(front).await.expect("accepted");
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "{read:?}");
    }

    #[test]
    fn mapped_ipv4_peers_are_checked_as_ipv4() {
        let mesh: Vec<IpPrefix> = vec![
            "100.88.0.0/16".parse().expect("v4"),
            "fd00:88::/48".parse().expect("v6"),
        ];
        let at = |s: &str| from_mesh(s.parse().expect("ip"), &mesh);
        assert!(at("100.88.0.2"));
        assert!(at("::ffff:100.88.0.2"));
        assert!(at("fd00:88::2"));
        assert!(!at("192.168.1.50"));
        assert!(!at("::ffff:192.168.1.50"));
        assert!(!at("127.0.0.1"));
    }
}
