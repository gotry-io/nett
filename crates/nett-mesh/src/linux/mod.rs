//! Linux 数据面：内核 WireGuard，经 netlink 配置接口、对端和地址（design/mesh.md 第 4 节）。
//! 需要 `CAP_NET_ADMIN`。

mod filter;
mod netlink;
mod nft;
mod rtnl;
pub mod runtime;
mod sys;
mod wg;
mod wgport;

use std::collections::BTreeMap;

use nett_trust::keys::X25519PublicKey;
use rustix::net::netlink::GENERIC;

use self::netlink::{NlError, Socket};
use self::wg::PeerChange;
use crate::access::{EdgeSpec, FilterSpec, IngressSpec};
use crate::dataplane::{DataPlane, DataPlaneError, InterfaceSpec, PeerSpec, PeerStat};
use crate::key::PrivateKey;
use nett_core::prefix::IpPrefix;

/// 系统时钟；误差以内核报告的最大误差为准（[`sys::max_clock_error`]）。
pub struct SystemClock;

impl crate::clock::Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        crate::clock::system_now_ms()
    }

    fn trusted(&self) -> bool {
        sys::max_clock_error().is_ok_and(|e| e <= crate::clock::MAX_TRUSTED_ERROR)
    }
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

/// dump 期间状态变化时内核标记中断，重试一次。
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

    fn sync_addresses(&mut self, index: u32, spec: &InterfaceSpec) -> Result<(), DataPlaneError> {
        let current = retry_interrupted(|| rtnl::get_addresses(&mut self.route, index))
            .map_err(kernel("list interface addresses"))?;
        let wanted: Vec<_> = spec
            .addresses
            .iter()
            .map(|a| (a.addr, a.prefix_len))
            .collect();
        for (addr, len) in &current {
            if !wanted.contains(&(*addr, *len)) {
                rtnl::del_address(&mut self.route, index, *addr, *len)
                    .map_err(kernel("remove interface address"))?;
            }
        }
        for (addr, len) in &wanted {
            if !current.contains(&(*addr, *len)) {
                rtnl::add_address(&mut self.route, index, *addr, *len)
                    .map_err(kernel("add interface address"))?;
            }
        }
        Ok(())
    }
}

impl DataPlane for KernelWireGuard {
    fn ensure_interface(
        &mut self,
        spec: &InterfaceSpec,
        private_key: &PrivateKey,
    ) -> Result<X25519PublicKey, DataPlaneError> {
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
        self.sync_addresses(link.index, spec)?;
        let device =
            retry_interrupted(|| wg::get_device(&mut self.generic, self.family, link.index))
                .map_err(kernel("read wireguard device"))?;
        self.ifindex = Some(link.index);
        device.public_key.ok_or(DataPlaneError::Protocol {
            op: "read wireguard device",
            detail: "no public key after setting the private key".to_owned(),
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

        // 先删除多余的对端，再新增和更新：新对端的 AllowedIPs 不会与即将删除的对端重叠
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
        // 转发由这个网络命名空间的设置决定（容器中用 Compose 的 sysctls 开启）；组网进程只检查，不修改
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
        let Some(index) = self.ifindex else {
            return Err(DataPlaneError::Protocol {
                op: "sync routes",
                detail: "interface is not set up".to_owned(),
            });
        };
        let current = retry_interrupted(|| rtnl::get_routes(&mut self.route, index))
            .map_err(kernel("list routes on the mesh interface"))?;
        for route in current.iter().filter(|r| !routes.contains(r)) {
            rtnl::del_route(&mut self.route, index, *route)
                .map_err(kernel("remove a route from the mesh interface"))?;
        }
        for route in routes.iter().filter(|r| !current.contains(r)) {
            rtnl::add_route(&mut self.route, index, *route)
                .map_err(kernel("add a route to the mesh interface"))?;
        }
        Ok(())
    }

    fn rehandshake(&mut self, peer: &PeerSpec) -> Result<(), DataPlaneError> {
        let ifindex = self.ifindex.ok_or_else(|| DataPlaneError::Protocol {
            op: "re-handshake",
            detail: "interface is not set up".to_owned(),
        })?;
        // 删除对端会清掉它的会话；按新 endpoint 加回后，下一个数据包触发经新路径的握手
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
}
