//! 用户态数据面的核心（design/userspace.md 第 4 节）：不做 I/O。数据面线程把 WireGuard 端口和 TUN 收到的包
//! 交给它，按它返回的 [`Action`] 收发；控制命令也在同一个线程里执行，状态不加锁。
//!
//! 入方向：分流 → 解密 → 校验内层包 → 来源必须在该对端的 `AllowedIPs` 内 → 目标必须是本机 → 过滤 → TUN。
//! 出方向：TUN → 按目的地址最长前缀匹配对端 → 记录连接 → 加密 → 对端当前的 endpoint。任何一步不通过就丢弃，
//! 不作响应。

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Instant, SystemTime};

use nett_core::prefix::IpPrefix;
use nett_trust::keys::X25519PublicKey;

use super::filter::Filter;
use super::packet;
use super::session::{Output, Sessions};
use crate::access::FilterSpec;
use crate::dataplane::{PeerSpec, PeerStat};
use crate::probe::{DIRECT_PROBE, DIRECT_REPLY, OUTER_LEN, WG_COOKIE_LEN, WG_COOKIE_REPLY};

/// 数据面要执行的动作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// 从 WireGuard 端口发出。
    Udp { to: SocketAddr, datagram: Vec<u8> },
    /// 写入 TUN，交给本机协议栈。
    Tun(Vec<u8>),
    /// 交给引擎（[`crate::prober::Incoming::Direct`]）：直连探测消息，以及 cookie 应答的副本。
    Probe { from: SocketAddr, data: Vec<u8> },
}

#[derive(Debug)]
struct Peer {
    key: X25519PublicKey,
    allowed: Vec<IpPrefix>,
    endpoint: Option<SocketAddr>,
    keepalive: Option<u16>,
    rx_bytes: u64,
    tx_bytes: u64,
}

impl Peer {
    fn new(spec: &PeerSpec) -> Self {
        Self {
            key: spec.public_key,
            allowed: spec.allowed_ips.clone(),
            endpoint: spec.endpoint,
            keepalive: spec.persistent_keepalive,
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("no peer with this public key")]
pub struct UnknownPeer;

pub struct Plane<S> {
    sessions: S,
    peers: Vec<Peer>,
    filter: Filter,
    /// 本机的组网地址：只有发往它们的包写入 TUN。
    local: Vec<IpAddr>,
    /// 闲置的 TLS 回环端口：从它们进来的包丢弃（design/mesh.md 第 5.3 节）。
    guarded: BTreeSet<u16>,
}

impl<S: Sessions> Plane<S> {
    pub fn new(sessions: S) -> Self {
        Self {
            sessions,
            peers: Vec::new(),
            filter: Filter::default(),
            local: Vec::new(),
            guarded: BTreeSet::new(),
        }
    }

    pub fn set_local(&mut self, local: Vec<IpAddr>) {
        self.filter.set_local(local.clone());
        self.local = local;
    }

    pub fn set_filter(&mut self, filter: FilterSpec) {
        self.filter.set_rules(filter);
    }

    pub fn guard_tls_ports(&mut self, idle: &[u16]) {
        self.guarded = idle.iter().copied().collect();
    }

    /// 让对端恰好是 `peers`。`endpoint` 为空的已有对端保留当前的 endpoint；已有会话保持不变。
    pub fn sync_peers(&mut self, peers: &[PeerSpec]) {
        let mut next = Vec::with_capacity(peers.len());
        for spec in peers {
            let mut peer = match self.peers.iter().position(|p| p.key == spec.public_key) {
                Some(i) => self.peers.swap_remove(i),
                None => Peer::new(spec),
            };
            peer.allowed.clone_from(&spec.allowed_ips);
            peer.keepalive = spec.persistent_keepalive;
            if spec.endpoint.is_some() {
                peer.endpoint = spec.endpoint;
            }
            next.push(peer);
        }
        self.peers = next;
        let keys: Vec<_> = self.peers.iter().map(|p| (p.key, p.keepalive)).collect();
        self.sessions.sync(&keys);
    }

    pub fn set_endpoint(
        &mut self,
        key: &X25519PublicKey,
        endpoint: SocketAddr,
    ) -> Result<(), UnknownPeer> {
        let peer = self
            .peers
            .iter_mut()
            .find(|p| p.key == *key)
            .ok_or(UnknownPeer)?;
        peer.endpoint = Some(endpoint);
        Ok(())
    }

    /// 与内核上"删除对端再加回"相同：会话和计数清零，下一个包触发新的握手。
    pub fn rehandshake(&mut self, spec: &PeerSpec) -> Result<(), UnknownPeer> {
        let peer = self
            .peers
            .iter_mut()
            .find(|p| p.key == spec.public_key)
            .ok_or(UnknownPeer)?;
        *peer = Peer::new(spec);
        self.sessions.reset(&spec.public_key);
        Ok(())
    }

    pub fn stats(&self, now: SystemTime) -> Vec<PeerStat> {
        self.peers
            .iter()
            .map(|p| PeerStat {
                public_key: p.key,
                endpoint: p.endpoint,
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
                last_handshake: self
                    .sessions
                    .since_handshake(&p.key)
                    .and_then(|d| now.checked_sub(d)),
            })
            .collect()
    }

    /// WireGuard 端口收到的一个包。
    pub fn from_udp(
        &mut self,
        from: SocketAddr,
        datagram: &[u8],
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        if from.ip().is_loopback() && self.guarded.contains(&from.port()) {
            return;
        }
        match datagram.first() {
            Some(1..=4) => {}
            Some(&kind) if (DIRECT_PROBE..=DIRECT_REPLY).contains(&kind) => {
                if datagram.len() == OUTER_LEN {
                    out.push(Action::Probe {
                        from,
                        data: datagram.to_vec(),
                    });
                }
                return;
            }
            _ => return,
        }
        if datagram[0] == WG_COOKIE_REPLY && datagram.len() == WG_COOKIE_LEN {
            out.push(Action::Probe {
                from,
                data: datagram.to_vec(),
            });
        }
        let mut outputs = Vec::new();
        self.sessions.receive(from, datagram, &mut outputs);
        let mut authenticated = None;
        for o in outputs {
            match o {
                Output::Authenticated { peer, from } => {
                    if let Some(p) = self.peer_mut(&peer) {
                        p.endpoint = Some(from);
                        p.rx_bytes += datagram.len() as u64;
                        authenticated = Some(peer);
                    }
                }
                Output::SendTo { to, datagram } => {
                    if let Some(p) = authenticated.and_then(|k| self.peer_mut(&k)) {
                        p.tx_bytes += datagram.len() as u64;
                    }
                    out.push(Action::Udp { to, datagram });
                }
                Output::SendToPeer { peer, datagram } => self.send_to_peer(&peer, datagram, out),
                Output::Deliver { peer, packet } => self.deliver(&peer, packet, now, out),
            }
        }
    }

    /// TUN 读出的一个包：本机发往组网的流量。
    pub fn from_tun(&mut self, packet: &[u8], now: Instant, out: &mut Vec<Action>) {
        let Some(ip) = packet::parse(packet) else {
            return;
        };
        let Some(key) = self.route(ip.dst) else {
            return;
        };
        self.filter.outbound(&ip, now);
        let mut outputs = Vec::new();
        self.sessions.send(&key, &packet[..ip.len], &mut outputs);
        self.apply(outputs, now, out);
    }

    /// 推进会话定时器，清理过期的连接。每 [`super::session::TIMER_TICK`] 调用一次。
    pub fn tick(&mut self, now: Instant, out: &mut Vec<Action>) {
        let mut outputs = Vec::new();
        self.sessions.tick(&mut outputs);
        self.apply(outputs, now, out);
        self.filter.expire(now);
    }

    fn apply(&mut self, outputs: Vec<Output>, now: Instant, out: &mut Vec<Action>) {
        for o in outputs {
            match o {
                Output::SendToPeer { peer, datagram } => self.send_to_peer(&peer, datagram, out),
                Output::SendTo { to, datagram } => out.push(Action::Udp { to, datagram }),
                Output::Deliver { peer, packet } => self.deliver(&peer, packet, now, out),
                Output::Authenticated { .. } => {}
            }
        }
    }

    fn peer_mut(&mut self, key: &X25519PublicKey) -> Option<&mut Peer> {
        self.peers.iter_mut().find(|p| p.key == *key)
    }

    /// 对端还没有 endpoint 时（`dial-only` 对端等它先连过来）丢弃。
    fn send_to_peer(&mut self, key: &X25519PublicKey, datagram: Vec<u8>, out: &mut Vec<Action>) {
        let Some(peer) = self.peer_mut(key) else {
            return;
        };
        let Some(to) = peer.endpoint else {
            return;
        };
        peer.tx_bytes += datagram.len() as u64;
        out.push(Action::Udp { to, datagram });
    }

    /// 最长前缀匹配：对端的 `AllowedIPs` 中包含 `dst` 的最长网段。
    fn route(&self, dst: IpAddr) -> Option<X25519PublicKey> {
        self.peers
            .iter()
            .flat_map(|p| p.allowed.iter().map(move |a| (a, p.key)))
            .filter(|(a, _)| a.contains(dst))
            .max_by_key(|(a, _)| a.prefix_len())
            .map(|(_, key)| key)
    }

    fn deliver(
        &mut self,
        key: &X25519PublicKey,
        mut packet: Vec<u8>,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let Some(ip) = packet::parse(&packet) else {
            return;
        };
        let Some(peer) = self.peers.iter().find(|p| p.key == *key) else {
            return;
        };
        // 来源地址由 WireGuard 的公钥保证：只接受这个对端被允许使用的地址
        if !peer.allowed.iter().any(|a| a.contains(ip.src)) {
            return;
        }
        if !self.local.contains(&ip.dst) {
            return;
        }
        if !self.filter.inbound(&ip, now) {
            return;
        }
        packet.truncate(ip.len);
        out.push(Action::Tun(packet));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{FilterRule, Match};
    use crate::key::PrivateKey;
    use crate::userspace::packet::build;
    use crate::userspace::session::Gotatun;

    const SYN: u8 = 0x02;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect(s)
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().expect(s)
    }

    struct Node {
        plane: Plane<Gotatun>,
        key: X25519PublicKey,
        mesh: IpAddr,
        at: SocketAddr,
    }

    fn node(mesh: &str, at: &str) -> Node {
        let private = PrivateKey::generate().expect("key");
        let mut plane = Plane::new(Gotatun::new(&private));
        plane.set_local(vec![ip(mesh)]);
        Node {
            plane,
            key: private.public_key(),
            mesh: ip(mesh),
            at: sa(at),
        }
    }

    fn spec(of: &Node, endpoint: Option<SocketAddr>) -> PeerSpec {
        PeerSpec {
            public_key: of.key,
            allowed_ips: vec![IpPrefix::host(of.mesh)],
            endpoint,
            persistent_keepalive: None,
        }
    }

    /// a 与 b 互为对端；b 放行所有来自 a 的连接时 `open`。
    fn pair(open: bool) -> (Node, Node) {
        let mut a = node("100.88.0.1", "198.51.100.1:41820");
        let mut b = node("100.88.0.2", "198.51.100.2:41820");
        a.plane.sync_peers(&[spec(&b, Some(b.at))]);
        b.plane.sync_peers(&[spec(&a, None)]);
        if open {
            b.plane.set_filter(FilterSpec {
                rules: vec![FilterRule {
                    matches: vec![Match::Source(IpPrefix::host(a.mesh))],
                    accept: true,
                }],
            });
        }
        (a, b)
    }

    /// 在 a、b 之间来回投递发往对方的 UDP 包，直到没有新的；返回两边写入 TUN 的包。
    fn exchange(a: &mut Node, b: &mut Node, from_a: Vec<Action>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let now = Instant::now();
        let (mut tun_a, mut tun_b) = (Vec::new(), Vec::new());
        let mut pending: Vec<(bool, Action)> = from_a.into_iter().map(|x| (true, x)).collect();
        let mut rounds = 0;
        while let Some((by_a, action)) = pending.pop() {
            rounds += 1;
            assert!(rounds < 100, "packets keep bouncing");
            let (sender, receiver, tun) = if by_a {
                (&*a, &mut *b, &mut tun_b)
            } else {
                (&*b, &mut *a, &mut tun_a)
            };
            if let Action::Udp { to, datagram } = action {
                assert_eq!(to, receiver.at);
                let mut out = Vec::new();
                receiver.plane.from_udp(sender.at, &datagram, now, &mut out);
                for o in out {
                    match o {
                        Action::Tun(p) => tun.push(p),
                        other => pending.push((!by_a, other)),
                    }
                }
            }
        }
        (tun_a, tun_b)
    }

    fn send(n: &mut Node, packet: &[u8]) -> Vec<Action> {
        let mut out = Vec::new();
        n.plane.from_tun(packet, Instant::now(), &mut out);
        out
    }

    #[test]
    fn packets_cross_after_the_handshake_and_learn_the_endpoint() {
        let (mut a, mut b) = pair(true);
        let syn = build::tcp(a.mesh, 40000, b.mesh, 22, SYN);
        let out = send(&mut a, &syn);
        let (_, at_b) = exchange(&mut a, &mut b, out);
        assert_eq!(at_b, [syn]);
        // b 从认证通过的包学到 a 的 endpoint
        let stat = &b.plane.stats(SystemTime::now())[0];
        assert_eq!(stat.endpoint, Some(a.at));
        assert!(stat.last_handshake.is_some() && stat.rx_bytes > 0 && stat.tx_bytes > 0);

        // 回包方向：b 的 TCP 应答（带 ACK）在 a 上直接放行，即使 a 没有任何规则
        let reply = build::tcp(b.mesh, 22, a.mesh, 40000, SYN | 0x10);
        let out = send(&mut b, &reply);
        let (_, at_a) = exchange(&mut b, &mut a, out);
        assert_eq!(at_a, [reply]);
    }

    #[test]
    fn denied_spoofed_and_misaddressed_packets_are_dropped() {
        let (mut a, mut b) = pair(false);
        // 没有规则：新建连接拒绝
        let packet = build::tcp(a.mesh, 1, b.mesh, 22, SYN);
        let out = send(&mut a, &packet);
        assert!(exchange(&mut a, &mut b, out).1.is_empty());

        let (mut a, mut b) = pair(true);
        // a 伪造来源：b 只接受 a 被允许使用的地址
        let forged = build::udp(ip("100.88.0.9"), 1, b.mesh, 53);
        let out = send_raw(&mut a, &b, &forged);
        assert!(exchange(&mut a, &mut b, out).1.is_empty());
        // 目标不是 b 的地址
        let elsewhere = build::udp(a.mesh, 1, ip("100.88.0.7"), 53);
        let out = send_raw(&mut a, &b, &elsewhere);
        assert!(exchange(&mut a, &mut b, out).1.is_empty());
        // 对照：同一条会话上的正常包能到
        let ok = build::udp(a.mesh, 1, b.mesh, 53);
        let out = send(&mut a, &ok);
        assert_eq!(exchange(&mut a, &mut b, out).1, [ok]);
    }

    /// 不经过 a 的选路和过滤，直接用 a 与 b 的会话加密一个包：模拟一个被攻破的成员。
    fn send_raw(a: &mut Node, b: &Node, packet: &[u8]) -> Vec<Action> {
        let mut outputs = Vec::new();
        a.plane.sessions.send(&b.key, packet, &mut outputs);
        let mut out = Vec::new();
        a.plane.apply(outputs, Instant::now(), &mut out);
        out
    }

    #[test]
    fn padding_is_stripped_before_the_tun() {
        let (mut a, mut b) = pair(true);
        // 长度不是 16 的倍数：会话层补齐，写入 TUN 前去掉
        let odd = build::echo(a.mesh, b.mesh, true, 1);
        assert_ne!(odd.len() % 16, 0);
        let out = send(&mut a, &odd);
        assert_eq!(exchange(&mut a, &mut b, out).1, [odd]);
    }

    #[test]
    fn probes_and_cookie_copies_go_to_the_engine() {
        let (_, mut b) = pair(true);
        let from = sa("203.0.113.5:41820");
        let now = Instant::now();
        let mut out = Vec::new();
        let mut probe = vec![DIRECT_PROBE; OUTER_LEN];
        b.plane.from_udp(from, &probe, now, &mut out);
        probe.truncate(OUTER_LEN - 1);
        b.plane.from_udp(from, &probe, now, &mut out);
        b.plane.from_udp(from, &[0x80; OUTER_LEN], now, &mut out);
        b.plane.from_udp(from, &[], now, &mut out);
        let mut cookie = vec![0u8; WG_COOKIE_LEN];
        cookie[0] = WG_COOKIE_REPLY;
        b.plane.from_udp(from, &cookie, now, &mut out);
        assert_eq!(
            out,
            [
                Action::Probe {
                    from,
                    data: vec![DIRECT_PROBE; OUTER_LEN]
                },
                Action::Probe { from, data: cookie }
            ]
        );
    }

    #[test]
    fn idle_tls_ports_are_dropped() {
        let (mut a, mut b) = pair(true);
        let packet = build::udp(a.mesh, 1, b.mesh, 53);
        let out = send(&mut a, &packet);
        let Some(Action::Udp { datagram, .. }) = out.first().cloned() else {
            panic!("handshake initiation");
        };
        b.plane.guard_tls_ports(&[50000]);
        let mut at_b = Vec::new();
        b.plane
            .from_udp(sa("127.0.0.1:50000"), &datagram, Instant::now(), &mut at_b);
        assert!(at_b.is_empty());
        b.plane
            .from_udp(sa("127.0.0.1:50001"), &datagram, Instant::now(), &mut at_b);
        assert!(!at_b.is_empty(), "other loopback ports are used by TLS");
    }

    #[test]
    fn sync_keeps_learned_endpoints_and_rehandshake_resets() {
        let (mut a, mut b) = pair(true);
        let packet = build::udp(a.mesh, 1, b.mesh, 53);
        let out = send(&mut a, &packet);
        exchange(&mut a, &mut b, out);
        b.plane.sync_peers(&[spec(&a, None)]);
        let stat = b.plane.stats(SystemTime::now()).remove(0);
        assert_eq!(stat.endpoint, Some(a.at));
        assert!(stat.last_handshake.is_some());

        b.plane.rehandshake(&spec(&a, None)).expect("known peer");
        let stat = b.plane.stats(SystemTime::now()).remove(0);
        assert_eq!(
            (stat.endpoint, stat.last_handshake, stat.rx_bytes),
            (None, None, 0)
        );
        let unknown = node("100.88.0.5", "198.51.100.5:41820");
        assert_eq!(b.plane.rehandshake(&spec(&unknown, None)), Err(UnknownPeer));
        assert_eq!(
            b.plane.set_endpoint(&unknown.key, unknown.at),
            Err(UnknownPeer)
        );

        b.plane.sync_peers(&[]);
        assert!(b.plane.stats(SystemTime::now()).is_empty());
    }

    #[test]
    fn longest_prefix_selects_the_peer() {
        let (mut a, b) = pair(true);
        let c = node("100.88.0.3", "198.51.100.3:41820");
        let mut wide = spec(&b, Some(b.at));
        wide.allowed_ips
            .push("192.0.2.0/24".parse().expect("prefix"));
        let mut narrow = spec(&c, Some(c.at));
        narrow
            .allowed_ips
            .push("192.0.2.10/32".parse().expect("prefix"));
        a.plane.sync_peers(&[wide, narrow]);
        let to =
            |a: &mut Node, dst: &str| match send(a, &build::udp(a.mesh, 1, ip(dst), 53)).first() {
                Some(Action::Udp { to, .. }) => Some(*to),
                _ => None,
            };
        assert_eq!(to(&mut a, "192.0.2.10"), Some(c.at));
        assert_eq!(to(&mut a, "192.0.2.11"), Some(b.at));
        assert_eq!(to(&mut a, "198.18.0.1"), None);
    }
}
