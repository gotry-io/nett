//! The transports' loopback ports (design/mesh.md section 5.3), opened by the mesh before WireGuard
//! is pointed at them and taken by the transport that serves each, as NetBird binds its local proxy
//! before it points WireGuard at it (v0.83.2, `client/internal/peer/conn.go`). What WireGuard sends to
//! a port before its transport reads it waits in the port's receive buffer instead of being refused,
//! so the first handshake through a transport is not lost while the transport starts.

use std::collections::{BTreeSet, HashMap};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Mutex, PoisonError};

/// Ports held at once: the TLS and the obfuscated transports' loopback ports.
pub const MAX_PORTS: usize = 2 * nett_core::transport::MAX_TARGETS;

/// The loopback ports opened for the transports and not taken yet.
#[derive(Debug, Default)]
pub struct LoopbackPorts {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    /// The ports of the configuration last prepared.
    listed: BTreeSet<SocketAddr>,
    opened: HashMap<SocketAddr, UdpSocket>,
}

impl LoopbackPorts {
    /// Opens the ports in `listen` that the configuration before did not list, and lets go of those it
    /// no longer lists. A port that does not open now (another process holds it) is opened by its
    /// transport, which retries.
    pub fn prepare(&self, listen: &[SocketAddr]) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let next: BTreeSet<SocketAddr> = listen.iter().copied().take(MAX_PORTS).collect();
        inner.opened.retain(|addr, _| next.contains(addr));
        let new: Vec<SocketAddr> = next.difference(&inner.listed).copied().collect();
        for addr in new {
            match open(addr) {
                Ok(socket) => {
                    inner.opened.insert(addr, socket);
                }
                Err(error) => {
                    tracing::debug!(%addr, %error, "loopback port not opened ahead; its transport opens it");
                }
            }
        }
        inner.listed = next;
    }

    /// The ports of the configuration last prepared.
    #[cfg(test)]
    pub(crate) fn listed(&self) -> Vec<SocketAddr> {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.listed.iter().copied().collect()
    }

    /// The socket opened for `addr`, once.
    pub fn take(&self, addr: SocketAddr) -> Option<UdpSocket> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .opened
            .remove(&addr)
    }
}

fn open(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;
    crate::sockbuf::enlarge_receive_buffer(&socket);
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn free() -> SocketAddr {
        UdpSocket::bind("127.0.0.1:0")
            .and_then(|s| s.local_addr())
            .expect("a free port")
    }

    /// A new port is open before its transport takes it, and holds what arrives meanwhile; it is
    /// handed out once, a port no longer listed is let go, and a listed one is not opened again.
    #[test]
    fn a_new_port_is_open_before_its_transport_takes_it() {
        let ports = LoopbackPorts::default();
        let (a, b) = (free(), free());
        ports.prepare(&[a]);
        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
        sender.send_to(b"first handshake", a).expect("sent");
        let socket = ports.take(a).expect("opened ahead");
        assert!(ports.take(a).is_none(), "handed out once");
        socket.set_nonblocking(false).expect("blocking");
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("timeout");
        let mut buf = [0u8; 32];
        let (len, _) = socket.recv_from(&mut buf).expect("held until read");
        assert_eq!(&buf[..len], b"first handshake");

        // Listed already: not opened again, even though the transport holds it now
        ports.prepare(&[a, b]);
        assert!(ports.take(a).is_none());
        // No longer listed: let go, so the port is free
        ports.prepare(&[a]);
        assert!(ports.take(b).is_none());
        UdpSocket::bind(b).expect("free again");
        drop(socket);
    }

    /// A port another process holds does not stop the others from opening.
    #[test]
    fn a_port_held_elsewhere_is_left_to_its_transport() {
        let held = UdpSocket::bind("127.0.0.1:0").expect("held");
        let busy = held.local_addr().expect("addr");
        let ports = LoopbackPorts::default();
        let other = free();
        ports.prepare(&[busy, other]);
        assert!(ports.take(busy).is_none());
        assert!(ports.take(other).is_some());
    }
}
