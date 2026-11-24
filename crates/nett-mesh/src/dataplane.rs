//! Data plane interface: the WireGuard interface, peers, addresses and routes are implemented by each
//! platform's backend (ADR 0018).
//! The core logic operates on the data plane only through this interface; tests use a stand-in.

use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::time::SystemTime;

use nett_trust::keys::X25519PublicKey;

use crate::access::{EdgeSpec, FilterSpec, IngressSpec};
use crate::key::PrivateKey;
use nett_core::prefix::IpPrefix;

/// The MTU of `nett0` is fixed at 1280 (design/mesh.md section 4).
pub const MESH_MTU: u32 = 1280;

/// Name of the mesh interface.
pub const INTERFACE_NAME: &str = "nett0";

/// When a system-assigned port is one nett uses itself ([`crate::config::is_reserved_port`],
/// [`crate::config::is_loopback_port`]), the maximum number of reassignments.
const PORT_ATTEMPTS: usize = 8;

/// When the desired state carries no port, the system assigns the WireGuard port (design/mesh.md section
/// 5.5). `assign` obtains a port and the handle that holds it; when it lands on a port the mesh
/// uses itself (the Linux ephemeral port range includes them), it takes another. Handles that landed on
/// reserved ports are kept until a port is chosen and then released, so the system does not hand out the
/// same port again.
pub(crate) fn automatic_port<T>(
    mut assign: impl FnMut() -> Result<(T, u16), DataPlaneError>,
) -> Result<(T, u16), DataPlaneError> {
    let mut reserved = Vec::new();
    for _ in 0..=PORT_ATTEMPTS {
        let (handle, port) = assign()?;
        if !crate::config::is_reserved_port(port) && !crate::config::is_loopback_port(port) {
            return Ok((handle, port));
        }
        reserved.push((handle, port));
    }
    Err(DataPlaneError::Protocol {
        op: "pick a WireGuard port",
        detail: format!(
            "the system kept assigning ports nett uses itself: {:?}",
            reserved.iter().map(|(_, p)| p).collect::<Vec<_>>()
        ),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceSpec {
    pub name: String,
    /// WireGuard port. When empty, the interface's current port is kept; a newly created interface gets one
    /// from the system (design/mesh.md section 5.5).
    pub listen_port: Option<u16>,
    pub mtu: u32,
    /// This machine's mesh address, with the prefix length of the mesh prefixes: all traffic to the whole
    /// mesh prefixes enters this interface.
    pub addresses: Vec<InterfaceAddress>,
}

/// An address on the interface and its prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceAddress {
    pub addr: std::net::IpAddr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSpec {
    pub public_key: X25519PublicKey,
    pub allowed_ips: Vec<IpPrefix>,
    pub endpoint: Option<SocketAddr>,
    /// Persistent keepalive interval (seconds); set to 25 seconds for `dial-only` members to keep the NAT
    /// mapping alive.
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, thiserror::Error)]
pub enum DataPlaneError {
    #[error("{op}: {source}")]
    Os {
        op: &'static str,
        source: std::io::Error,
    },
    #[error("{op}: kernel rejected the request: {source}")]
    Kernel {
        op: &'static str,
        source: std::io::Error,
    },
    #[error("{op}: unexpected reply from the kernel: {detail}")]
    Protocol { op: &'static str, detail: String },
    #[error("interface {0} exists but is not a WireGuard interface")]
    NotWireGuard(String),
    #[error("{0} is not available on this platform")]
    Unsupported(&'static str),
    #[error("data plane thread: {0}")]
    Worker(&'static str),
}

/// Sends probes with the WireGuard port as the source port (design/mesh.md section 7.1): direct probes
/// and probes of UDP relays, going through WireGuard's own NAT mapping.
pub trait WgPortSend: Send {
    fn send(&self, to: SocketAddr, data: &[u8]) -> std::io::Result<()>;

    /// Sends wrapped from this machine's obfuscated port (design/obfuscation.md section 2), where
    /// the data plane has one.
    fn send_obfs(&self, _to: SocketAddr, _data: &[u8]) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "this data plane has no obfuscated port",
        ))
    }
}

/// Which of this machine's public UDP ports a probe message came in on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbePort {
    WireGuard,
    /// This machine's obfuscated port, opened by the data plane (design/obfuscation.md section 2).
    Obfs,
}

/// Copies of probe messages and cookie replies received on the WireGuard port, and probe messages
/// opened on the obfuscated port.
pub trait WgPortRecv: Send {
    /// A batch of (port, source address, UDP payload). Waits at most half a second and returns empty
    /// on timeout: the caller uses this to periodically check whether it should exit.
    fn recv(&mut self) -> std::io::Result<Vec<(ProbePort, SocketAddr, Vec<u8>)>>;
}

/// Probes on the WireGuard port: the sending end goes to the thread that hosts the engine, the
/// receiving end goes to the receive thread.
pub struct WgPortProbes {
    pub send: Box<dyn WgPortSend>,
    pub recv: Box<dyn WgPortRecv>,
}

/// Current state of a peer on the interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStat {
    pub public_key: X25519PublicKey,
    pub endpoint: Option<SocketAddr>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Time of the most recent completed handshake (wall clock). Empty when no handshake has completed since
    /// the peer was added, or since it was re-added by [`DataPlane::rehandshake`].
    pub last_handshake: Option<SystemTime>,
}

/// The public key and WireGuard port actually in use once the interface is ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceState {
    pub public_key: X25519PublicKey,
    pub listen_port: u16,
}

pub trait DataPlane: Send {
    /// Kernel or userspace WireGuard (shown in local status, design/status.md section 6).
    fn kind(&self) -> crate::status::DataPlaneKind;

    /// Creates or reuses the mesh interface, sets the private key, listen port, MTU and address, and enables
    /// it. Existing peers are kept unchanged: when the mesh restarts, connections in progress are
    /// not interrupted.
    fn ensure_interface(
        &mut self,
        spec: &InterfaceSpec,
        private_key: &PrivateKey,
    ) -> Result<InterfaceState, DataPlaneError>;

    /// Makes the peers on the interface exactly `peers`: adds missing ones, updates changed ones, removes
    /// extra ones. A peer with an empty `endpoint` keeps the kernel's current endpoint.
    fn sync_peers(&mut self, peers: &[PeerSpec]) -> Result<(), DataPlaneError>;

    /// Endpoint and byte counts of each peer.
    fn peer_stats(&mut self) -> Result<Vec<PeerStat>, DataPlaneError>;

    /// Changes only one peer's endpoint; the session is not affected (design/mesh.md section 4).
    fn set_endpoint(
        &mut self,
        public_key: &X25519PublicKey,
        endpoint: SocketAddr,
    ) -> Result<(), DataPlaneError>;

    /// Removes the peer and adds it back as `peer`: the next data packet triggers a new handshake, so the new
    /// relay establishes its index (design/mesh.md section 8.4).
    /// After that this peer's [`PeerStat::last_handshake`] is empty until the new handshake completes.
    fn rehandshake(&mut self, peer: &PeerSpec) -> Result<(), DataPlaneError>;

    /// Drops packets that enter the WireGuard port from these idle TLS loopback ports (design/mesh.md section
    /// 5.3), replacing the previous setting.
    fn guard_tls_ports(&mut self, wg_port: u16, idle: &[u16]) -> Result<(), DataPlaneError>;

    /// Installs the filter rules for inbound traffic on the mesh interface (design/mesh.md section 12),
    /// replacing the previous rules as a whole: the replacement either takes full effect or leaves things
    /// as they were, and there is never a moment without filtering.
    fn apply_filter(&mut self, filter: &FilterSpec) -> Result<(), DataPlaneError>;

    /// Sets or clears this machine's Edge source NAT and anti-spoofing rules (ADR 0015), replacing the
    /// previous setting as a whole.
    fn apply_edge(&mut self, edge: Option<&EdgeSpec>) -> Result<(), DataPlaneError>;

    /// Sets or clears the forwarding rules for this machine as a smart gateway (design/mesh.md section 10)
    /// and a mobile gateway (design/devices.md section 6), replacing the previous setting as a whole.
    /// Returns an error when forwarding is not enabled or the system drops it (the rules are installed
    /// as usual).
    fn apply_ingress(&mut self, ingress: Option<&IngressSpec>) -> Result<(), DataPlaneError>;

    /// Whether this machine forwards IPv6, where the data plane can tell: a mobile gateway that does not
    /// carries its devices' IPv4 traffic only.
    fn ipv6_forwarding(&self) -> Option<bool> {
        None
    }

    /// Makes the routes on the mesh interface exactly `routes`: the prefixes advertised by other members
    /// (design/mesh.md section 10).
    fn sync_routes(&mut self, routes: &[IpPrefix]) -> Result<(), DataPlaneError>;

    /// Opens sending and receiving of probes on the WireGuard port. Called once after the interface is
    /// ready.
    fn wg_port_probes(&mut self, listen_port: u16) -> Result<WgPortProbes, DataPlaneError>;

    /// A socket bound to this machine's mesh address that sends and receives only through the mesh interface
    /// (in-tunnel probes, design/mesh.md section 7).
    fn bind_tunnel(&self, addr: SocketAddr) -> std::io::Result<UdpSocket>;

    /// A TCP listener on this machine's mesh address that accepts only connections arriving through
    /// the mesh interface where the platform can tell (a port it serves, design/mesh.md section 12.1).
    fn listen_tunnel(&self, addr: SocketAddr) -> std::io::Result<TcpListener>;

    /// A dual-stack socket toward the underlying network (probes to TLS relays through the transport's
    /// loopback ports). On macOS it binds the physical interface carrying the default route and does not go
    /// through the proxy app's TUN (design/userspace.md section 6.2).
    fn bind_underlay(&self, port: u16) -> std::io::Result<UdpSocket>;

    /// Index of the interface the underlay sockets are bound to now; `None` where the routing table
    /// decides. The TLS transport binds its TLS connections to it (design/userspace.md section 6.2).
    fn underlay_interface(&self) -> Option<u32> {
        None
    }

    /// Whether the data plane wraps what it sends to peers' obfuscated ports on its WireGuard
    /// socket, and opens what comes back from them (design/userspace.md section 4.1); otherwise the
    /// obfuscated transport carries it through a loopback port (design/obfuscation.md section 2).
    fn inline_obfs(&self) -> bool {
        false
    }

    /// The names this machine's own DNS queries are answered from when they reach the data plane
    /// instead of the responder's socket (design/userspace.md section 4). Only the userspace data
    /// plane sees them; elsewhere they go to the responder over the loopback path.
    fn set_names(&mut self, _names: &crate::dns::NameTable) -> Result<(), DataPlaneError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{OBFS_LOOPBACK_BASE, TLS_LOOPBACK_BASE};
    use crate::probe::TUNNEL_PROBE_PORT;

    #[test]
    fn automatic_port_skips_the_ports_nett_uses_itself() {
        let mut ports = vec![
            TUNNEL_PROBE_PORT,
            TLS_LOOPBACK_BASE,
            OBFS_LOOPBACK_BASE,
            50_000,
        ]
        .into_iter();
        let mut calls = 0;
        let got = automatic_port(|| {
            calls += 1;
            Ok(((), ports.next().expect("port")))
        });
        assert_eq!(got.expect("picked").1, 50_000);
        assert_eq!(calls, 4);

        let mut calls = 0;
        let stuck = automatic_port(|| {
            calls += 1;
            Ok(((), TUNNEL_PROBE_PORT))
        });
        assert!(matches!(stuck, Err(DataPlaneError::Protocol { .. })));
        assert_eq!(calls, PORT_ATTEMPTS + 1);
    }
}
