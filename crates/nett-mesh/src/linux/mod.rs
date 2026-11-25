//! Linux data plane: kernel WireGuard, with the interface, peers and addresses configured through netlink
//! (design/mesh.md section 4).
//! Requires `CAP_NET_ADMIN`.

mod filter;
mod hostfw;
mod netlink;
mod nft;
mod rtnl;
mod sys;
pub mod tun;
mod wg;
mod wgport;

use std::collections::BTreeMap;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsFd;

use nett_trust::keys::X25519PublicKey;
use rustix::net::netlink::GENERIC;

use self::netlink::{NlError, Socket};

/// What the kernel answers for a generic netlink family it does not have.
const ENOENT: i32 = 2;
use self::wg::PeerChange;
use self::wgport::WgPort;
use crate::access::{EdgeSpec, FilterSpec, IngressSpec};
use crate::dataplane::{
    DataPlane, DataPlaneError, INTERFACE_NAME, InterfaceSpec, InterfaceState, PeerSpec, PeerStat,
    UdpPort, WgPortProbes, WgPortRecv, WgPortSend, automatic_port,
};
use crate::key::PrivateKey;
use nett_core::prefix::IpPrefix;

/// System clock, synchronized while the maximum error the kernel reports
/// ([`sys::max_clock_error`]) is below its limit. `STA_UNSYNC` is not read: systemd-timesyncd sets it
/// to keep the kernel from writing a real-time clock that runs in local time, as systemd's own check
/// ignores it.
pub struct SystemClock;

impl crate::clock::Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        crate::clock::system_now_ms()
    }

    fn trusted(&self) -> bool {
        sys::max_clock_error().is_ok_and(|e| crate::clock::synchronized(e, false))
    }
}

/// Effective user ID of the peer process of a Unix socket (design/status.md section 3).
pub(crate) fn peer_uid(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<u32> {
    sys::peer_cred(fd).map(|(_, uid)| uid)
}

/// Process ID (0 outside this PID namespace) and effective user ID of a Unix socket's peer.
pub(crate) fn peer_cred(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<(u32, u32)> {
    sys::peer_cred(fd)
}

/// Tears down what the mesh leaves in the system (`nett leave`, design/auth.md section 8.3): the
/// mesh normally keeps the interface on exit, so connections are not interrupted during a
/// restart (design/mesh.md section 4). Delete the interface first, and delete the filter rules once
/// there is no traffic; if deleting the interface fails, the filter rules stay, keeping deny (hard rule
/// 6). The mesh must be stopped first.
pub fn teardown() -> Result<(), DataPlaneError> {
    let mut route = Socket::open(None).map_err(kernel("open rtnetlink socket"))?;
    rtnl::del_link(&mut route, INTERFACE_NAME).map_err(kernel("delete the mesh interface"))?;
    if nftables()? {
        for table in nft::tables() {
            nft::delete_table(table).map_err(kernel("delete an nftables table"))?;
        }
        hostfw::remove().map_err(kernel("remove nett's rule from the system's FORWARD chain"))?;
    }
    Ok(())
}

/// The forwarding rules of a smart gateway and a mobile gateway on the mesh interface, for the
/// kernel data plane and the userspace one alike (design/userspace.md section 4.2); an error when
/// the system does not forward or drops what it would.
pub(crate) fn apply_ingress(ingress: Option<&IngressSpec>) -> Result<(), DataPlaneError> {
    filter::install_ingress(ingress).map_err(kernel("install forwarding rules"))?;
    let carry = ingress.is_some_and(IngressSpec::carries_devices);
    let blocked = hostfw::reconcile(carry).map_err(kernel(
        "accept device traffic in the system's FORWARD chain",
    ))?;
    if ingress.is_none() {
        return Ok(());
    }
    // Forwarding is decided by this network namespace's settings (in a container, enable it with Compose
    // sysctls); the mesh only checks and does not modify
    let path = "/proc/sys/net/ipv4/ip_forward";
    if !forwarding(path)? {
        let what = if carry {
            "carries devices"
        } else {
            "advertises routes"
        };
        return Err(DataPlaneError::Protocol {
            op: "forward traffic",
            detail: format!("{path} is 0: this node {what} but does not forward"),
        });
    }
    if carry && !blocked.is_empty() {
        return Err(DataPlaneError::Protocol {
            op: "forward device traffic",
            detail: format!(
                "{} drops forwarded traffic by default, so devices cannot reach other machines \
                 through this gateway; accept traffic from nett0 to nett0 there",
                blocked.join(", ")
            ),
        });
    }
    Ok(())
}

pub(crate) fn ipv6_forwarding() -> Option<bool> {
    forwarding("/proc/sys/net/ipv6/conf/all/forwarding").ok()
}

/// Whether this machine holds nett's nftables tables (design/userspace.md section 4.2).
pub(crate) fn nftables() -> Result<bool, DataPlaneError> {
    has_nft_tables(KernelWireGuard::open().map(drop))
}

/// Whether this machine can hold nett's nftables tables, from whether kernel WireGuard opens: a kernel
/// without WireGuard (Synology DSM, old kernels) has the userspace data plane filter in the mesh, and
/// may have no nftables at all, and then does not even answer a request.
fn has_nft_tables(kernel: Result<(), DataPlaneError>) -> Result<bool, DataPlaneError> {
    match kernel {
        Ok(()) => Ok(true),
        Err(DataPlaneError::Unsupported(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

pub struct KernelWireGuard {
    route: Socket,
    generic: Socket,
    family: u16,
    ifindex: Option<u32>,
}

/// A kernel without the WireGuard family, and no module to load for it, has no kernel WireGuard: the
/// userspace data plane takes over (design/dsm.md section 5). Anything else is an error.
fn family_error(e: NlError) -> DataPlaneError {
    if e.errno() == Some(ENOENT) {
        DataPlaneError::Unsupported("kernel WireGuard")
    } else {
        kernel("resolve the wireguard netlink family")(e)
    }
}

/// Whether a forwarding setting in `/proc/sys` is on.
fn forwarding(path: &str) -> Result<bool, DataPlaneError> {
    std::fs::read_to_string(path)
        .map(|v| v.trim() == "1")
        .map_err(|source| DataPlaneError::Os {
            op: "read a forwarding setting",
            source,
        })
}

fn kernel(op: &'static str) -> impl FnOnce(NlError) -> DataPlaneError {
    move |e| match e {
        NlError::Io(source) => DataPlaneError::Os { op, source },
        NlError::Kernel(source) => DataPlaneError::Kernel { op, source },
        NlError::Malformed(detail) => DataPlaneError::Protocol {
            op,
            detail: detail.to_owned(),
        },
        NlError::Interrupted => DataPlaneError::Protocol {
            op,
            detail: "dump interrupted twice".to_owned(),
        },
    }
}

/// When the state changes during a dump the kernel marks it interrupted; retry once.
fn retry_interrupted<T>(mut f: impl FnMut() -> Result<T, NlError>) -> Result<T, NlError> {
    match f() {
        Err(NlError::Interrupted) => f(),
        other => other,
    }
}

impl KernelWireGuard {
    pub fn open() -> Result<Self, DataPlaneError> {
        let route = Socket::open(None).map_err(kernel("open rtnetlink socket"))?;
        let mut generic =
            Socket::open(Some(GENERIC)).map_err(kernel("open generic netlink socket"))?;
        let family = wg::resolve_family(&mut generic).map_err(family_error)?;
        Ok(Self {
            route,
            generic,
            family,
            ifindex: None,
        })
    }
}

/// Makes the addresses on the interface exactly the addresses in `spec`.
fn sync_addresses(
    route: &mut Socket,
    index: u32,
    spec: &InterfaceSpec,
) -> Result<(), DataPlaneError> {
    let current = retry_interrupted(|| rtnl::get_addresses(route, index))
        .map_err(kernel("list interface addresses"))?;
    let wanted: Vec<_> = spec
        .addresses
        .iter()
        .map(|a| (a.addr, a.prefix_len))
        .collect();
    for (addr, len) in &current {
        if !wanted.contains(&(*addr, *len)) {
            rtnl::del_address(route, index, *addr, *len)
                .map_err(kernel("remove interface address"))?;
        }
    }
    for (addr, len) in &wanted {
        if !current.contains(&(*addr, *len)) {
            rtnl::add_address(route, index, *addr, *len)
                .map_err(kernel("add interface address"))?;
        }
    }
    Ok(())
}

/// Makes the routes on the interface exactly `routes` ([`DataPlane::sync_routes`]).
fn sync_routes(
    route: &mut Socket,
    index: Option<u32>,
    routes: &[IpPrefix],
) -> Result<(), DataPlaneError> {
    let Some(index) = index else {
        return Err(DataPlaneError::Protocol {
            op: "sync routes",
            detail: "interface is not set up".to_owned(),
        });
    };
    let current = retry_interrupted(|| rtnl::get_routes(route, index))
        .map_err(kernel("list routes on the mesh interface"))?;
    for r in current.iter().filter(|r| !routes.contains(r)) {
        rtnl::del_route(route, index, *r)
            .map_err(kernel("remove a route from the mesh interface"))?;
    }
    for r in routes.iter().filter(|r| !current.contains(r)) {
        rtnl::add_route(route, index, *r).map_err(kernel("add a route to the mesh interface"))?;
    }
    Ok(())
}

impl DataPlane for KernelWireGuard {
    fn kind(&self) -> crate::status::DataPlaneKind {
        crate::status::DataPlaneKind::Kernel
    }

    fn ensure_interface(
        &mut self,
        spec: &InterfaceSpec,
        private_key: &PrivateKey,
    ) -> Result<InterfaceState, DataPlaneError> {
        rtnl::create_wireguard(&mut self.route, &spec.name)
            .map_err(kernel("create wireguard interface"))?;
        let link = rtnl::get_link(&mut self.route, &spec.name)
            .map_err(kernel("look up interface"))?
            .ok_or_else(|| DataPlaneError::Protocol {
                op: "look up interface",
                detail: format!("{} vanished after creation", spec.name),
            })?;
        if link.kind.as_deref() != Some("wireguard") {
            return Err(DataPlaneError::NotWireGuard(spec.name.clone()));
        }
        wg::set_device(
            &mut self.generic,
            self.family,
            link.index,
            private_key.as_bytes(),
            spec.listen_port,
        )
        .map_err(kernel("set wireguard private key and port"))?;
        rtnl::set_mtu_up(&mut self.route, link.index, spec.mtu)
            .map_err(kernel("set interface mtu and up"))?;
        sync_addresses(&mut self.route, link.index, spec)?;
        let read = |generic: &mut Socket| {
            retry_interrupted(|| wg::get_device(generic, self.family, link.index))
                .map_err(kernel("read wireguard device"))
        };
        let device = match spec.listen_port {
            Some(_) => read(&mut self.generic)?,
            // A newly created interface is assigned a port by the kernel when enabled; if it lands on a reserved
            // port, let the kernel reassign
            None => {
                let mut first = true;
                let generic = &mut self.generic;
                automatic_port(|| {
                    if !std::mem::take(&mut first) {
                        wg::set_device(
                            generic,
                            self.family,
                            link.index,
                            private_key.as_bytes(),
                            Some(0),
                        )
                        .map_err(kernel("reassign the wireguard port"))?;
                    }
                    let device = read(generic)?;
                    let port = device.listen_port;
                    Ok((device, port))
                })?
                .0
            }
        };
        self.ifindex = Some(link.index);
        let public_key = device.public_key.ok_or(DataPlaneError::Protocol {
            op: "read wireguard device",
            detail: "no public key after setting the private key".to_owned(),
        })?;
        Ok(InterfaceState {
            public_key,
            listen_port: device.listen_port,
        })
    }

    fn sync_peers(&mut self, peers: &[PeerSpec]) -> Result<(), DataPlaneError> {
        let Some(ifindex) = self.ifindex else {
            return Err(DataPlaneError::Protocol {
                op: "sync peers",
                detail: "interface is not set up".to_owned(),
            });
        };
        let device = retry_interrupted(|| wg::get_device(&mut self.generic, self.family, ifindex))
            .map_err(kernel("read wireguard peers"))?;
        let current: BTreeMap<_, _> = device.peers.iter().map(|p| (p.public_key, p)).collect();

        // Delete extra peers first, then add and update: a new peer's AllowedIPs does not overlap with a peer
        // about to be deleted
        let mut changes: Vec<PeerChange> = current
            .keys()
            .filter(|key| !peers.iter().any(|p| p.public_key == **key))
            .map(|key| PeerChange::Remove(*key))
            .collect();
        for peer in peers {
            let keepalive = peer.persistent_keepalive.unwrap_or(0);
            let up_to_date = current.get(&peer.public_key).is_some_and(|cur| {
                let mut have = cur.allowed_ips.clone();
                let mut want = peer.allowed_ips.clone();
                have.sort();
                want.sort();
                have == want
                    && cur.keepalive == keepalive
                    && peer.endpoint.is_none_or(|e| cur.endpoint == Some(e))
            });
            if !up_to_date {
                changes.push(PeerChange::Upsert {
                    public_key: peer.public_key,
                    endpoint: peer.endpoint,
                    keepalive,
                    allowed_ips: peer.allowed_ips.clone(),
                });
            }
        }
        if changes.is_empty() {
            return Ok(());
        }
        wg::apply_peers(&mut self.generic, self.family, ifindex, &changes)
            .map_err(kernel("update wireguard peers"))
    }

    fn peer_stats(&mut self) -> Result<Vec<PeerStat>, DataPlaneError> {
        let ifindex = self.ifindex.ok_or_else(|| DataPlaneError::Protocol {
            op: "read peer state",
            detail: "interface is not set up".to_owned(),
        })?;
        let device = retry_interrupted(|| wg::get_device(&mut self.generic, self.family, ifindex))
            .map_err(kernel("read wireguard peers"))?;
        Ok(device
            .peers
            .into_iter()
            .map(|p| PeerStat {
                public_key: p.public_key,
                endpoint: p.endpoint,
                // A machine that offers an obfuscated port runs the userspace data plane
                port: UdpPort::WireGuard,
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
                last_handshake: p.last_handshake,
            })
            .collect())
    }

    fn set_endpoint(
        &mut self,
        public_key: &X25519PublicKey,
        endpoint: std::net::SocketAddr,
    ) -> Result<(), DataPlaneError> {
        let ifindex = self.ifindex.ok_or_else(|| DataPlaneError::Protocol {
            op: "set endpoint",
            detail: "interface is not set up".to_owned(),
        })?;
        let change = PeerChange::Endpoint {
            public_key: *public_key,
            endpoint,
        };
        wg::apply_peers(&mut self.generic, self.family, ifindex, &[change])
            .map_err(kernel("set peer endpoint"))
    }

    fn guard_tls_ports(&mut self, wg_port: u16, idle: &[u16]) -> Result<(), DataPlaneError> {
        nft::set_tls_guard(wg_port, idle).map_err(kernel("guard idle TLS ports"))
    }

    fn apply_filter(&mut self, filter: &FilterSpec) -> Result<(), DataPlaneError> {
        filter::install_access(filter).map_err(kernel("install access rules"))
    }

    fn apply_edge(&mut self, edge: Option<&EdgeSpec>) -> Result<(), DataPlaneError> {
        filter::install_edge(edge).map_err(kernel("install edge address rules"))
    }

    fn apply_ingress(&mut self, ingress: Option<&IngressSpec>) -> Result<(), DataPlaneError> {
        apply_ingress(ingress)
    }

    fn ipv6_forwarding(&self) -> Option<bool> {
        ipv6_forwarding()
    }

    fn sync_routes(&mut self, routes: &[IpPrefix]) -> Result<(), DataPlaneError> {
        sync_routes(&mut self.route, self.ifindex, routes)
    }

    fn rehandshake(&mut self, peer: &PeerSpec) -> Result<(), DataPlaneError> {
        let ifindex = self.ifindex.ok_or_else(|| DataPlaneError::Protocol {
            op: "re-handshake",
            detail: "interface is not set up".to_owned(),
        })?;
        // Deleting a peer clears its session; after adding it back with the new endpoint, the next data packet
        // triggers a handshake through the new path
        let changes = [
            PeerChange::Remove(peer.public_key),
            PeerChange::Upsert {
                public_key: peer.public_key,
                endpoint: peer.endpoint,
                keepalive: peer.persistent_keepalive.unwrap_or(0),
                allowed_ips: peer.allowed_ips.clone(),
            },
        ];
        wg::apply_peers(&mut self.generic, self.family, ifindex, &changes)
            .map_err(kernel("re-handshake peer"))
    }

    fn wg_port_probes(&mut self, listen_port: u16) -> Result<WgPortProbes, DataPlaneError> {
        let os = |op| move |source| DataPlaneError::Os { op, source };
        let send = WgPort::open(listen_port)
            .map_err(os("open raw sockets for probes from the WireGuard port"))?;
        // The log group is the WireGuard port number: one per mesh on the same host
        nft::install_probe_copy(listen_port, listen_port).map_err(kernel(
            "install the nftables rules that copy probes on the WireGuard port",
        ))?;
        let log = nft::ProbeLog::bind(listen_port, listen_port)
            .map_err(kernel("subscribe to copied probes"))?;
        Ok(WgPortProbes {
            send: Box::new(send),
            recv: Box::new(log),
        })
    }

    fn bind_tunnel(&self, addr: SocketAddr) -> std::io::Result<UdpSocket> {
        let socket = UdpSocket::bind(addr)?;
        // Send and receive only on nett0: packets to the mesh address on other interfaces are not handed to this
        // socket
        sys::bind_to_device(socket.as_fd(), INTERFACE_NAME)?;
        Ok(socket)
    }

    fn listen_tunnel(&self, addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
        let listener = std::net::TcpListener::bind(addr)?;
        // Connections to the mesh address that arrive on other interfaces never reach the listener:
        // Linux would otherwise accept them (weak host model)
        sys::bind_to_device(listener.as_fd(), INTERFACE_NAME)?;
        Ok(listener)
    }

    fn bind_underlay(&self, port: u16) -> std::io::Result<UdpSocket> {
        crate::userspace::dual_stack_udp(port)
    }
}

impl WgPortSend for WgPort {
    fn send(&self, to: SocketAddr, data: &[u8]) -> std::io::Result<()> {
        WgPort::send(self, to, data)
    }
}

impl WgPortRecv for nft::ProbeLog {
    fn recv(&mut self) -> std::io::Result<Vec<(UdpPort, SocketAddr, Vec<u8>)>> {
        let probes = nft::ProbeLog::recv(self).map_err(std::io::Error::other)?;
        Ok(probes
            .into_iter()
            .map(|(from, data)| (UdpPort::WireGuard, from, data))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kernel_without_the_wireguard_family_means_userspace() {
        let missing = NlError::Kernel(std::io::Error::from_raw_os_error(ENOENT));
        assert!(matches!(
            family_error(missing),
            DataPlaneError::Unsupported("kernel WireGuard")
        ));
        // Anything else, for example missing privileges, stays an error rather than falling back
        let denied = NlError::Kernel(std::io::Error::from_raw_os_error(1));
        assert!(matches!(
            family_error(denied),
            DataPlaneError::Kernel { .. }
        ));
    }

    /// Uninstalling on Synology DSM waited for an answer about nftables its kernel never gives, and
    /// failed: where kernel WireGuard is missing, nett never made any nftables table
    #[test]
    fn teardown_leaves_nftables_alone_without_kernel_wireguard() {
        assert!(
            !has_nft_tables(Err(DataPlaneError::Unsupported("kernel WireGuard"))).expect("decided")
        );
        assert!(has_nft_tables(Ok(())).expect("decided"));
        let denied = DataPlaneError::Kernel {
            op: "resolve the wireguard netlink family",
            source: std::io::Error::from_raw_os_error(1),
        };
        assert!(has_nft_tables(Err(denied)).is_err());
    }
}
