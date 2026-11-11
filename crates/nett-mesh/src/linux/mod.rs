//! Linux data plane: kernel WireGuard, with the interface, peers and addresses configured through netlink
//! (design/mesh.md section 4).
//! Requires `CAP_NET_ADMIN`.

mod filter;
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
use self::wg::PeerChange;
use self::wgport::WgPort;
use crate::access::{EdgeSpec, FilterSpec, IngressSpec};
use crate::dataplane::{
    DataPlane, DataPlaneError, DirectProbes, DirectRecv, DirectSend, INTERFACE_NAME, InterfaceSpec,
    InterfaceState, PeerSpec, PeerStat, automatic_port,
};
use crate::key::PrivateKey;
use nett_core::prefix::IpPrefix;

/// System clock; the error is the maximum error reported by the kernel ([`sys::max_clock_error`]).
pub struct SystemClock;

impl crate::clock::Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        crate::clock::system_now_ms()
    }

    fn trusted(&self) -> bool {
        sys::max_clock_error().is_ok_and(|e| e <= crate::clock::MAX_TRUSTED_ERROR)
    }
}

/// Tears down what the mesh process leaves in the system (`nett leave`, design/auth.md section 8.3): the
/// mesh process normally keeps the interface on exit, so connections are not interrupted during a
/// restart (design/mesh.md section 4). Delete the interface first, and delete the filter rules once
/// there is no traffic; if deleting the interface fails, the filter rules stay, keeping deny (hard rule
/// 6). The mesh process must be stopped first.
pub fn teardown() -> Result<(), DataPlaneError> {
    let mut route = Socket::open(None).map_err(kernel("open rtnetlink socket"))?;
    rtnl::del_link(&mut route, INTERFACE_NAME).map_err(kernel("delete the mesh interface"))?;
    for table in nft::tables() {
        nft::delete_table(table).map_err(kernel("delete an nftables table"))?;
    }
    Ok(())
}

pub struct KernelWireGuard {
    route: Socket,
    generic: Socket,
    family: u16,
    ifindex: Option<u32>,
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
        let family = wg::resolve_family(&mut generic).map_err(kernel(
            "resolve the wireguard netlink family (is the wireguard module available?)",
        ))?;
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
        filter::install_ingress(ingress).map_err(kernel("install forwarding rules"))?;
        if ingress.is_none() {
            return Ok(());
        }
        // Forwarding is decided by this network namespace's settings (in a container, enable it with Compose
        // sysctls); the mesh process only checks and does not modify
        let path = "/proc/sys/net/ipv4/ip_forward";
        let on = std::fs::read_to_string(path)
            .map_err(|source| DataPlaneError::Os {
                op: "read the IPv4 forwarding setting",
                source,
            })?
            .trim()
            == "1";
        if on {
            Ok(())
        } else {
            Err(DataPlaneError::Protocol {
                op: "forward to advertised routes",
                detail: format!("{path} is 0: this node advertises routes but does not forward"),
            })
        }
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

    fn direct_probes(&mut self, listen_port: u16) -> Result<DirectProbes, DataPlaneError> {
        let os = |op| move |source| DataPlaneError::Os { op, source };
        let send = WgPort::open(listen_port).map_err(os("open raw sockets for direct probes"))?;
        // The log group is the WireGuard port number: one per mesh process on the same host
        nft::install_probe_copy(listen_port, listen_port)
            .map_err(kernel("install the nftables rules that copy direct probes"))?;
        let log = nft::ProbeLog::bind(listen_port, listen_port)
            .map_err(kernel("subscribe to copied direct probes"))?;
        Ok(DirectProbes {
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

    fn bind_underlay(&self, port: u16) -> std::io::Result<UdpSocket> {
        crate::userspace::dual_stack_udp(port)
    }
}

impl DirectSend for WgPort {
    fn send(&self, to: SocketAddr, data: &[u8]) -> std::io::Result<()> {
        WgPort::send(self, to, data)
    }
}

impl DirectRecv for nft::ProbeLog {
    fn recv(&mut self) -> std::io::Result<Vec<(SocketAddr, Vec<u8>)>> {
        nft::ProbeLog::recv(self).map_err(std::io::Error::other)
    }
}
