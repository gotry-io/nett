//! 用户态数据面（design/userspace.md）：WireGuard 会话、选择对端与来源校验、进程内过滤、WireGuard 端口上
//! 的分流都在组网进程中完成，平台后端只提供 TUN 和接口配置。macOS、DSM 与旧内核的 Linux 共用。

pub mod filter;
pub mod packet;
pub mod plane;
pub mod session;
#[cfg(unix)]
mod worker;

#[cfg(unix)]
pub use self::dataplane::{Platform, Tun, UserspaceDataPlane};

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
        DataPlane, DataPlaneError, DirectProbes, InterfaceSpec, PeerSpec, PeerStat,
    };
    use crate::key::PrivateKey;

    /// 组网接口的 TUN：每次收发一个 IP 包。
    pub trait Tun: AsFd + Send + 'static {
        /// 非阻塞地读一个 IP 包；没有时返回 `WouldBlock`。
        fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
        fn send(&self, packet: &[u8]) -> io::Result<()>;
    }

    /// 平台后端：TUN、接口地址、路由与套接字（design/userspace.md 第 6 节）。
    pub trait Platform: Send + 'static {
        type Tun: Tun;
        /// 创建组网接口，配置地址和 MTU 并启用。
        fn create(&mut self, spec: &InterfaceSpec) -> Result<Self::Tun, DataPlaneError>;
        /// 修改已有组网接口的地址和 MTU。
        fn configure(&mut self, spec: &InterfaceSpec) -> Result<(), DataPlaneError>;
        /// WireGuard 端口的套接字。
        fn bind_wireguard(&mut self, port: u16) -> Result<UdpSocket, DataPlaneError>;
        /// 绑定到本机组网地址、只收发经组网接口的套接字。
        fn bind_tunnel(&self, addr: SocketAddr) -> io::Result<UdpSocket>;
        /// 让组网接口上的路由恰好是 `routes`。
        fn sync_routes(&mut self, routes: &[IpPrefix]) -> Result<(), DataPlaneError>;
    }

    struct Running {
        worker: Worker,
        spec: InterfaceSpec,
        public_key: X25519PublicKey,
        socket: UdpSocket,
        probes: Option<ProbeQueue>,
    }

    /// 用户态的 [`DataPlane`]：会话与过滤在数据面线程中，平台后端只负责 TUN 和接口配置。
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

        /// WireGuard 端口的本地地址（接口就绪之后）。
        pub fn wireguard_addr(&self) -> Option<SocketAddr> {
            self.running.as_ref()?.socket.local_addr().ok()
        }

        fn worker(&self) -> Result<&Worker, DataPlaneError> {
            self.running
                .as_ref()
                .map(|r| &r.worker)
                .ok_or(DataPlaneError::Worker("the interface is not up yet"))
        }
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
        fn ensure_interface(
            &mut self,
            spec: &InterfaceSpec,
            private_key: &PrivateKey,
        ) -> Result<X25519PublicKey, DataPlaneError> {
            if let Some(running) = &mut self.running {
                if running.spec == *spec {
                    return Ok(running.public_key);
                }
                if running.spec.listen_port != spec.listen_port || running.spec.name != spec.name {
                    return Err(DataPlaneError::Unsupported(
                        "changing the WireGuard port or interface name without a restart",
                    ));
                }
                self.platform.configure(spec)?;
                let addrs = local(spec);
                running.worker.call(|r| Command::SetLocal(addrs, r))?;
                running.spec = spec.clone();
                return Ok(running.public_key);
            }
            let tun = self.platform.create(spec)?;
            let socket = self.platform.bind_wireguard(spec.listen_port)?;
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
                probes: Some(probes),
            });
            Ok(public_key)
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

        /// TUN 是一对 Unix 套接字，测试持有另一端；WireGuard 端口在回环地址上。
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
            fn bind_wireguard(&mut self, _port: u16) -> Result<UdpSocket, DataPlaneError> {
                Ok(UdpSocket::bind("127.0.0.1:0").expect("bind"))
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
            let spec = InterfaceSpec {
                name: "nett0".into(),
                listen_port: 0,
                mtu: MESH_MTU,
                addresses: vec![InterfaceAddress {
                    addr: mesh,
                    prefix_len: 16,
                }],
            };
            let key = plane.ensure_interface(&spec, &private).expect("interface");
            assert_eq!(key, private.public_key());
            // 同一份接口描述再来一次：沿用
            plane.ensure_interface(&spec, &private).expect("again");
            let host = plane.platform.host.take().expect("tun host side");
            let at = plane.wireguard_addr().expect("bound");
            Node {
                plane,
                host,
                key,
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

        /// 等 `host` 端收到一个包，最多 `deadline`。
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

            // 回包方向：a 没有规则，但这是它发起的 UDP 流的回包
            let reply = build::udp(b.mesh, 53, a.mesh, 4000);
            b.host.send(&reply).expect("into b's tun");
            assert_eq!(expect_packet(&a.host, Duration::from_secs(5)), Some(reply));

            let stats = a.plane.peer_stats().expect("stats");
            assert_eq!(stats[0].endpoint, Some(b.at));
            assert!(stats[0].last_handshake.is_some());

            // 规则收窄后，b 不再接受 a 的新流
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
            // 来源端口就是 a 的 WireGuard 端口
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
