//! Userspace data plane (design/userspace.md): the WireGuard session, peer selection and source
//! validation, in-process filtering, and demultiplexing on the WireGuard port are all done in the mesh
//! process, and the platform backend provides only the TUN and interface configuration. Shared by
//! macOS, DSM and Linux with old kernels.

pub mod filter;
pub mod packet;
pub mod plane;
pub mod session;
#[cfg(unix)]
mod worker;

#[cfg(unix)]
pub use self::dataplane::{Platform, Tun, UserspaceDataPlane, dual_stack_udp};

#[cfg(unix)]
mod dataplane {
    use std::io;
    use std::net::{IpAddr, SocketAddr, UdpSocket};
    use std::os::fd::AsFd;

    use nett_core::prefix::IpPrefix;
    use nett_trust::keys::X25519PublicKey;

    use super::plane::Plane;
    use super::session::Gotatun;
    use super::worker::{Command, ProbeQueue, ProbeSender, Worker};
    use crate::access::{EdgeSpec, FilterSpec, IngressSpec};
    use crate::dataplane::{
        DataPlane, DataPlaneError, DirectProbes, InterfaceSpec, InterfaceState, PeerSpec, PeerStat,
        automatic_port,
    };
    use crate::key::PrivateKey;

    /// The mesh interface's TUN: each send or receive carries one IP packet.
    pub trait Tun: AsFd + Send + 'static {
        /// Reads an IP packet without blocking; returns `WouldBlock` when there is none.
        fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
        fn send(&self, packet: &[u8]) -> io::Result<()>;
    }

    /// Platform backend: TUN, interface addresses, routes and sockets (design/userspace.md section 6).
    pub trait Platform: Send + 'static {
        type Tun: Tun;
        /// Creates the mesh interface, configures the address and MTU and brings it up.
        fn create(&mut self, spec: &InterfaceSpec) -> Result<Self::Tun, DataPlaneError>;
        /// Changes the address and MTU of an existing mesh interface.
        fn configure(&mut self, spec: &InterfaceSpec) -> Result<(), DataPlaneError>;
        /// A dual-stack socket toward the underlying network: the WireGuard port and probes to relays
        /// ([`DataPlane::bind_underlay`]).
        fn bind_underlay(&self, port: u16) -> io::Result<UdpSocket>;
        /// A socket bound to this machine's mesh address that sends and receives only through the mesh
        /// interface.
        fn bind_tunnel(&self, addr: SocketAddr) -> io::Result<UdpSocket>;
        /// Makes the routes on the mesh interface exactly `routes`.
        fn sync_routes(&mut self, routes: &[IpPrefix]) -> Result<(), DataPlaneError>;
    }

    struct Running {
        worker: Worker,
        spec: InterfaceSpec,
        public_key: X25519PublicKey,
        socket: UdpSocket,
        /// The port the WireGuard socket is actually bound to.
        listen_port: u16,
        probes: Option<ProbeQueue>,
    }

    /// The userspace [`DataPlane`]: sessions and filtering are in the data plane thread, and the platform
    /// backend is responsible only for the TUN and interface configuration.
    pub struct UserspaceDataPlane<P> {
        platform: P,
        running: Option<Running>,
    }

    impl<P: Platform> UserspaceDataPlane<P> {
        pub fn new(platform: P) -> Self {
            Self {
                platform,
                running: None,
            }
        }

        /// Local address of the WireGuard port (after the interface is ready).
        pub fn wireguard_addr(&self) -> Option<SocketAddr> {
            self.running.as_ref()?.socket.local_addr().ok()
        }

        /// Binds the WireGuard port; when no port is given the system assigns one ([`automatic_port`]).
        fn bind_wireguard(&self, port: Option<u16>) -> Result<(UdpSocket, u16), DataPlaneError> {
            let bind = |port| {
                let os = |source| DataPlaneError::Os {
                    op: "bind the WireGuard port",
                    source,
                };
                let socket = self.platform.bind_underlay(port).map_err(os)?;
                let bound = socket.local_addr().map_err(os)?.port();
                Ok((socket, bound))
            };
            match port {
                Some(port) => bind(port),
                None => automatic_port(|| bind(0)),
            }
        }

        fn worker(&self) -> Result<&Worker, DataPlaneError> {
            self.running
                .as_ref()
                .map(|r| &r.worker)
                .ok_or(DataPlaneError::Worker("the interface is not up yet"))
        }
    }

    /// The socket on the WireGuard port: a dual-stack socket on the IPv6 wildcard address, sending and
    /// receiving both IPv4 (mapped addresses) and IPv6.
    pub fn dual_stack_udp(port: u16) -> io::Result<UdpSocket> {
        use rustix::io::{FdFlags, fcntl_setfd};
        use rustix::net::{AddressFamily, SocketType, bind, socket, sockopt::set_ipv6_v6only};
        // macOS has no SOCK_CLOEXEC: set it after creation
        let fd = socket(AddressFamily::INET6, SocketType::DGRAM, None)?;
        fcntl_setfd(&fd, FdFlags::CLOEXEC)?;
        // Explicitly turn off "IPv6 only": some systems enable it by default
        set_ipv6_v6only(&fd, false)?;
        bind(
            &fd,
            &std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, port, 0, 0),
        )?;
        Ok(UdpSocket::from(fd))
    }

    fn local(spec: &InterfaceSpec) -> Vec<IpAddr> {
        spec.addresses.iter().map(|a| a.addr).collect()
    }

    fn unknown(op: &'static str) -> impl FnOnce(super::plane::UnknownPeer) -> DataPlaneError {
        move |_| DataPlaneError::Protocol {
            op,
            detail: "no such peer".to_owned(),
        }
    }

    impl<P: Platform> DataPlane for UserspaceDataPlane<P> {
        fn kind(&self) -> crate::status::DataPlaneKind {
            crate::status::DataPlaneKind::Userspace
        }

        fn ensure_interface(
            &mut self,
            spec: &InterfaceSpec,
            private_key: &PrivateKey,
        ) -> Result<InterfaceState, DataPlaneError> {
            if let Some(running) = &mut self.running {
                let state = InterfaceState {
                    public_key: running.public_key,
                    listen_port: running.listen_port,
                };
                if running.spec == *spec {
                    return Ok(state);
                }
                // With no port given, keep the current port
                if spec.listen_port.is_some_and(|p| p != running.listen_port)
                    || running.spec.name != spec.name
                {
                    return Err(DataPlaneError::Unsupported(
                        "changing the WireGuard port or interface name without a restart",
                    ));
                }
                self.platform.configure(spec)?;
                let addrs = local(spec);
                running.worker.call(|r| Command::SetLocal(addrs, r))?;
                running.spec = spec.clone();
                return Ok(state);
            }
            let tun = self.platform.create(spec)?;
            let (socket, listen_port) = self.bind_wireguard(spec.listen_port)?;
            let mut plane = Plane::new(Gotatun::new(private_key));
            plane.set_local(local(spec));
            let os = |op| move |source| DataPlaneError::Os { op, source };
            let worker_socket = socket
                .try_clone()
                .map_err(os("share the WireGuard socket"))?;
            let (worker, probes) = Worker::spawn(plane, tun, worker_socket)
                .map_err(os("start the data plane thread"))?;
            let public_key = private_key.public_key();
            self.running = Some(Running {
                worker,
                spec: spec.clone(),
                public_key,
                socket,
                listen_port,
                probes: Some(probes),
            });
            Ok(InterfaceState {
                public_key,
                listen_port,
            })
        }

        fn sync_peers(&mut self, peers: &[PeerSpec]) -> Result<(), DataPlaneError> {
            let peers = peers.to_vec();
            self.worker()?.call(|r| Command::SyncPeers(peers, r))
        }

        fn peer_stats(&mut self) -> Result<Vec<PeerStat>, DataPlaneError> {
            self.worker()?.call(Command::Stats)
        }

        fn set_endpoint(
            &mut self,
            public_key: &X25519PublicKey,
            endpoint: SocketAddr,
        ) -> Result<(), DataPlaneError> {
            let key = *public_key;
            self.worker()?
                .call(|r| Command::SetEndpoint(key, endpoint, r))?
                .map_err(unknown("set endpoint"))
        }

        fn rehandshake(&mut self, peer: &PeerSpec) -> Result<(), DataPlaneError> {
            let peer = peer.clone();
            self.worker()?
                .call(|r| Command::Rehandshake(peer, r))?
                .map_err(unknown("re-handshake peer"))
        }

        fn guard_tls_ports(&mut self, _wg_port: u16, idle: &[u16]) -> Result<(), DataPlaneError> {
            let idle = idle.to_vec();
            self.worker()?.call(|r| Command::GuardTlsPorts(idle, r))
        }

        fn apply_filter(&mut self, filter: &FilterSpec) -> Result<(), DataPlaneError> {
            let filter = filter.clone();
            self.worker()?.call(|r| Command::Filter(filter, r))
        }

        fn set_names(&mut self, names: &crate::dns::NameTable) -> Result<(), DataPlaneError> {
            let names = names.clone();
            self.worker()?.call(|r| Command::SetNames(names, r))
        }

        fn apply_edge(&mut self, edge: Option<&EdgeSpec>) -> Result<(), DataPlaneError> {
            match edge {
                None => Ok(()),
                Some(_) => Err(DataPlaneError::Unsupported(
                    "Edge source address translation",
                )),
            }
        }

        fn apply_ingress(&mut self, ingress: Option<&IngressSpec>) -> Result<(), DataPlaneError> {
            match ingress {
                None => Ok(()),
                Some(_) => Err(DataPlaneError::Unsupported(
                    "forwarding to advertised routes",
                )),
            }
        }

        fn sync_routes(&mut self, routes: &[IpPrefix]) -> Result<(), DataPlaneError> {
            self.platform.sync_routes(routes)
        }

        fn direct_probes(&mut self, _listen_port: u16) -> Result<DirectProbes, DataPlaneError> {
            let running = self
                .running
                .as_mut()
                .ok_or(DataPlaneError::Worker("the interface is not up yet"))?;
            let recv = running
                .probes
                .take()
                .ok_or(DataPlaneError::Worker("direct probes are already open"))?;
            let socket = running
                .socket
                .try_clone()
                .map_err(|source| DataPlaneError::Os {
                    op: "share the WireGuard socket",
                    source,
                })?;
            Ok(DirectProbes {
                send: Box::new(ProbeSender { socket }),
                recv: Box::new(recv),
            })
        }

        fn bind_tunnel(&self, addr: SocketAddr) -> io::Result<UdpSocket> {
            self.platform.bind_tunnel(addr)
        }

        fn bind_underlay(&self, port: u16) -> io::Result<UdpSocket> {
            self.platform.bind_underlay(port)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::os::unix::net::UnixDatagram;
        use std::time::{Duration, Instant};

        use super::*;
        use crate::access::{FilterRule, Match};
        use crate::dataplane::{InterfaceAddress, MESH_MTU};
        use crate::probe::{DIRECT_PROBE, OUTER_LEN};
        use crate::userspace::packet::build;

        struct FakeTun(UnixDatagram);

        impl AsFd for FakeTun {
            fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
                self.0.as_fd()
            }
        }

        impl Tun for FakeTun {
            fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
                self.0.recv(buf)
            }
            fn send(&self, packet: &[u8]) -> io::Result<()> {
                self.0.send(packet).map(drop)
            }
        }

        /// The TUN is a pair of Unix sockets with the test holding the other end; the WireGuard port is on the
        /// loopback address.
        #[derive(Default)]
        struct Fake {
            host: Option<UnixDatagram>,
        }

        impl Platform for Fake {
            type Tun = FakeTun;
            fn create(&mut self, _spec: &InterfaceSpec) -> Result<FakeTun, DataPlaneError> {
                let (tun, host) = UnixDatagram::pair().expect("pair");
                tun.set_nonblocking(true).expect("nonblocking");
                host.set_read_timeout(Some(Duration::from_millis(100)))
                    .expect("timeout");
                self.host = Some(host);
                Ok(FakeTun(tun))
            }
            fn configure(&mut self, _spec: &InterfaceSpec) -> Result<(), DataPlaneError> {
                Ok(())
            }
            fn bind_underlay(&self, _port: u16) -> io::Result<UdpSocket> {
                UdpSocket::bind("127.0.0.1:0")
            }
            fn bind_tunnel(&self, _addr: SocketAddr) -> io::Result<UdpSocket> {
                Err(io::Error::other("not used"))
            }
            fn sync_routes(&mut self, _routes: &[IpPrefix]) -> Result<(), DataPlaneError> {
                Ok(())
            }
        }

        struct Node {
            plane: UserspaceDataPlane<Fake>,
            host: UnixDatagram,
            key: X25519PublicKey,
            mesh: IpAddr,
            at: SocketAddr,
        }

        fn node(mesh: &str) -> Node {
            let private = PrivateKey::generate().expect("key");
            let mesh: IpAddr = mesh.parse().expect("ip");
            let mut plane = UserspaceDataPlane::new(Fake::default());
            let mut spec = InterfaceSpec {
                name: "nett0".into(),
                listen_port: None,
                mtu: MESH_MTU,
                addresses: vec![InterfaceAddress {
                    addr: mesh,
                    prefix_len: 16,
                }],
            };
            let state = plane.ensure_interface(&spec, &private).expect("interface");
            assert_eq!(state.public_key, private.public_key());
            let at = plane.wireguard_addr().expect("bound");
            // No port: the system assigns one, and the actual bound port is reported
            assert_eq!(state.listen_port, at.port());
            // The same interface description once more: keep as is
            assert_eq!(
                plane.ensure_interface(&spec, &private).expect("again"),
                state
            );
            // The desired state names the current port: keep it; changing to another port requires a restart
            spec.listen_port = Some(state.listen_port);
            assert_eq!(
                plane.ensure_interface(&spec, &private).expect("same port"),
                state
            );
            spec.listen_port = Some(state.listen_port.wrapping_add(1));
            assert!(matches!(
                plane.ensure_interface(&spec, &private),
                Err(DataPlaneError::Unsupported(_))
            ));
            let host = plane.platform.host.take().expect("tun host side");
            Node {
                plane,
                host,
                key: state.public_key,
                mesh,
                at,
            }
        }

        fn peer(of: &Node) -> PeerSpec {
            PeerSpec {
                public_key: of.key,
                allowed_ips: vec![IpPrefix::host(of.mesh)],
                endpoint: Some(of.at),
                persistent_keepalive: None,
            }
        }

        fn allow_from(n: &Node) -> FilterSpec {
            FilterSpec {
                rules: vec![FilterRule {
                    matches: vec![Match::Source(IpPrefix::host(n.mesh))],
                    accept: true,
                }],
            }
        }

        /// Waits for the `host` end to receive a packet, for at most `deadline`.
        fn expect_packet(host: &UnixDatagram, deadline: Duration) -> Option<Vec<u8>> {
            let start = Instant::now();
            let mut buf = vec![0u8; 2048];
            while start.elapsed() < deadline {
                if let Ok(n) = host.recv(&mut buf) {
                    return Some(buf[..n].to_vec());
                }
            }
            None
        }

        #[test]
        fn two_planes_handshake_and_exchange_over_loopback() {
            let (mut a, mut b) = (node("100.88.0.1"), node("100.88.0.2"));
            a.plane.sync_peers(&[peer(&b)]).expect("peers");
            b.plane.sync_peers(&[peer(&a)]).expect("peers");
            b.plane.apply_filter(&allow_from(&a)).expect("filter");

            let packet = build::udp(a.mesh, 4000, b.mesh, 53);
            a.host.send(&packet).expect("into a's tun");
            let got = expect_packet(&b.host, Duration::from_secs(5)).expect("at b's tun");
            assert_eq!(got, packet);

            // Return direction: a has no rule, but this is a return packet of a UDP flow it initiated
            let reply = build::udp(b.mesh, 53, a.mesh, 4000);
            b.host.send(&reply).expect("into b's tun");
            assert_eq!(expect_packet(&a.host, Duration::from_secs(5)), Some(reply));

            let stats = a.plane.peer_stats().expect("stats");
            assert_eq!(stats[0].endpoint, Some(b.at));
            assert!(stats[0].last_handshake.is_some());

            // After the rules are narrowed, b no longer accepts a's new flows
            b.plane
                .apply_filter(&FilterSpec::deny_all())
                .expect("filter");
            a.host
                .send(&build::udp(a.mesh, 4001, b.mesh, 53))
                .expect("into a's tun");
            assert_eq!(expect_packet(&b.host, Duration::from_millis(500)), None);
        }

        #[test]
        fn direct_probes_share_the_wireguard_port() {
            let (mut a, mut b) = (node("100.88.0.1"), node("100.88.0.2"));
            let probes_a = a.plane.direct_probes(0).expect("probes");
            let mut probes_b = b.plane.direct_probes(0).expect("probes");
            assert!(b.plane.direct_probes(0).is_err(), "opened once");
            let probe = vec![DIRECT_PROBE; OUTER_LEN];
            probes_a.send.send(b.at, &probe).expect("send");
            let got = probes_b.recv.recv().expect("recv");
            // The source port is a's WireGuard port
            assert_eq!(got, [(a.at, probe)]);
        }

        #[test]
        fn edge_and_forwarding_are_refused_and_unknown_peers_reported() {
            let mut a = node("100.88.0.1");
            let b = node("100.88.0.2");
            assert!(matches!(
                a.plane.apply_ingress(Some(&IngressSpec {
                    edge_sources: vec![]
                })),
                Err(DataPlaneError::Unsupported(_))
            ));
            assert!(a.plane.apply_edge(None).is_ok());
            assert!(a.plane.set_endpoint(&b.key, b.at).is_err());
            let mut fresh = UserspaceDataPlane::new(Fake::default());
            assert!(matches!(
                fresh.sync_peers(&[]),
                Err(DataPlaneError::Worker(_))
            ));
        }
    }
}
