//! 探测与选路的运行时状态（design/mesh.md 第 7、8 节）：为每个对端维护候选路径，收发探测消息，
//! 产出要发送的包和要执行的切换。不碰套接字和数据面，由 [`crate::engine`] 执行，测试中可以直接驱动。

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use nett_core::id::NodeId;
use nett_trust::admission::Member;
use nett_trust::keys::X25519PublicKey;

use crate::config::{Candidate, PeerPathConfig, Reachability};
use crate::key::PrivateKey;
use crate::path::{Action, PathKind, PathStats, PeerPaths, Route, SwitchReason};
use crate::probe::{
    self, DIRECT_PROBE, DIRECT_REPLY, KeyId, OuterProbe, OuterReply, ProbeKey, RELAY_PROBE,
    RelayReport, TUNNEL_PROBE_PORT,
};

/// 发出的探测等待应答的上限，过后从对照表中删除（各状态机自己判定丢失）。
const OUTSTANDING_TTL: Duration = Duration::from_secs(2);
/// 对照表的上限。
const MAX_OUTSTANDING: usize = 4096;
/// 跟随方测量中继的间隔：只为向决定方提供"中继 → 本机"这一段。
const RELAY_MONITOR_INTERVAL: Duration = Duration::from_secs(5);
/// 有流量的判定窗口（design/mesh.md 第 7 节）。
pub const ACTIVE_WINDOW: Duration = Duration::from_secs(30);

/// 要发出的包。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outgoing {
    /// 经 `nett0` 发往对端组网地址上的探测端口。
    Tunnel { to: SocketAddr, data: Vec<u8> },
    /// 从组网进程自己的端口发往中继。
    Relay { to: SocketAddr, data: Vec<u8> },
    /// 从 WireGuard 端口发出（第 7.1 节）。
    Direct { to: SocketAddr, data: Vec<u8> },
}

/// 收到的包从哪里来。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Incoming {
    /// 组网地址上的探测端口。
    Tunnel,
    /// 组网进程发往中继的套接字。
    Relay,
    /// WireGuard 端口上的副本。
    Direct,
}

/// 要对数据面执行的切换。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Switch {
    pub peer: NodeId,
    pub public_key: X25519PublicKey,
    pub to: Route,
    pub rehandshake: bool,
    pub reason: SwitchReason,
}

enum CandidateMeta {
    Direct,
    Relay { relay: KeyId, key: ProbeKey },
}

struct Peer {
    public_key: X25519PublicKey,
    mesh_addrs: [IpAddr; 2],
    direct_key: Option<ProbeKey>,
    routes: Vec<(Route, PathKind)>,
    meta: Vec<CandidateMeta>,
    /// 只有决定方才有选路状态。
    paths: Option<PeerPaths>,
    reports: HashMap<KeyId, (Duration, f64)>,
    last_activity: Option<Instant>,
}

#[derive(Debug, Clone, Copy)]
enum Pending {
    Tunnel { local: u32 },
    Candidate { index: usize, local: u32 },
    Monitor { relay: KeyId },
}

pub struct Prober {
    own_key_id: KeyId,
    peers: BTreeMap<NodeId, Peer>,
    by_mesh_addr: HashMap<IpAddr, NodeId>,
    by_key_id: HashMap<KeyId, NodeId>,
    /// 线上的序号 → 哪个对端的哪个探测。各状态机的序号各自独立，这里换成全局唯一的序号。
    outstanding: HashMap<u32, (NodeId, Pending, Instant)>,
    wire_seq: u32,
    /// 本机到各中继的测量，随隧道内应答带给对端。
    relay_stats: HashMap<KeyId, PathStats>,
    /// 跟随方要测的中继：编号 → (地址, 令牌)。
    monitored: HashMap<KeyId, (SocketAddr, ProbeKey, Option<Instant>)>,
}

/// 由谁决定这一对的路径（design/mesh.md 第 8.3 节）：`dial-only` 对 `public` 时 `dial-only` 一方决定，
/// 否则成员 ID 较小的一方决定。双方都是 `dial-only` 时的两端一起切换在 G3 实现。
pub fn is_decider(
    own: &NodeId,
    own_reach: Reachability,
    peer: &NodeId,
    peer_reach: Reachability,
) -> bool {
    match (own_reach, peer_reach) {
        (Reachability::DialOnly, Reachability::Public) => true,
        (Reachability::Public, Reachability::DialOnly) => false,
        _ => own < peer,
    }
}

fn routes(candidates: &[Candidate]) -> (Vec<(Route, PathKind)>, Vec<CandidateMeta>) {
    candidates
        .iter()
        .map(|c| match c {
            Candidate::Direct { endpoint } => (
                (Route::Direct(*endpoint), PathKind::Direct),
                CandidateMeta::Direct,
            ),
            Candidate::Relay {
                relay,
                endpoint,
                token,
            } => {
                let id = KeyId::of(relay.as_str().as_bytes());
                (
                    (
                        Route::Relay {
                            relay: id,
                            endpoint: *endpoint,
                        },
                        PathKind::Relay,
                    ),
                    CandidateMeta::Relay {
                        relay: id,
                        key: ProbeKey::from_token(&token.0),
                    },
                )
            }
        })
        .unzip()
}

impl Prober {
    pub fn new(own_public_key: &X25519PublicKey) -> Self {
        Self {
            own_key_id: KeyId::of(own_public_key.as_bytes()),
            peers: BTreeMap::new(),
            by_mesh_addr: HashMap::new(),
            by_key_id: HashMap::new(),
            outstanding: HashMap::new(),
            wire_seq: 0,
            relay_stats: HashMap::new(),
            monitored: HashMap::new(),
        }
    }

    /// 按已准入的成员和期望状态中的候选路径更新。候选列表没有变化的对端保留选路状态。
    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &mut self,
        own_id: &NodeId,
        own_reach: Reachability,
        private_key: &PrivateKey,
        members: &BTreeMap<NodeId, Member>,
        paths: &BTreeMap<NodeId, PeerPathConfig>,
    ) {
        let mut next = BTreeMap::new();
        self.monitored.clear();
        for (id, member) in members.iter().filter(|(id, _)| *id != own_id) {
            let config = paths.get(id);
            let candidates = config.map(|c| c.candidates.as_slice()).unwrap_or_default();
            let (routes, meta) = routes(candidates);
            let decider = config.is_some_and(|c| is_decider(own_id, own_reach, id, c.reachability));
            let previous = self
                .peers
                .remove(id)
                .filter(|p| p.routes == routes && p.public_key == member.mesh_public_key);
            let paths = match previous.as_ref().and_then(|p| p.paths.clone()) {
                Some(p) if decider => Some(p),
                _ if decider => PeerPaths::new(routes.clone()),
                _ => None,
            };
            for m in &meta {
                if let CandidateMeta::Relay { relay, key } = m {
                    let endpoint = routes
                        .iter()
                        .find_map(|(r, _)| match r {
                            Route::Relay {
                                relay: rid,
                                endpoint,
                            } if rid == relay => Some(*endpoint),
                            _ => None,
                        })
                        .unwrap_or(probe::UNSPECIFIED);
                    self.monitored
                        .entry(*relay)
                        .or_insert_with(|| (endpoint, key.clone(), None));
                }
            }
            next.insert(
                id.clone(),
                Peer {
                    public_key: member.mesh_public_key,
                    mesh_addrs: [
                        IpAddr::V4(member.addresses.ipv4),
                        IpAddr::V6(member.addresses.ipv6),
                    ],
                    direct_key: ProbeKey::direct(private_key, &member.mesh_public_key),
                    routes,
                    meta,
                    paths,
                    reports: previous
                        .as_ref()
                        .map(|p| p.reports.clone())
                        .unwrap_or_default(),
                    last_activity: previous.and_then(|p| p.last_activity),
                },
            );
        }
        self.peers = next;
        self.by_mesh_addr = self
            .peers
            .iter()
            .flat_map(|(id, p)| p.mesh_addrs.iter().map(move |a| (*a, id.clone())))
            .collect();
        self.by_key_id = self
            .peers
            .iter()
            .map(|(id, p)| (KeyId::of(p.public_key.as_bytes()), id.clone()))
            .collect();
    }

    /// 当前路径的 endpoint：决定方取选路状态，跟随方取第一条候选（之后由 WireGuard 的漫游跟随）。
    pub fn endpoint(&self, peer: &NodeId) -> Option<SocketAddr> {
        let p = self.peers.get(peer)?;
        match &p.paths {
            Some(paths) => Some(paths.current().endpoint()),
            None => p.routes.first().map(|(r, _)| r.endpoint()),
        }
    }

    /// 决定方期望的 endpoint，用于纠正被漫游改掉的 endpoint（第 8.3 节）。跟随方返回 `None`。
    pub fn desired_endpoint(&self, peer: &NodeId) -> Option<SocketAddr> {
        self.peers
            .get(peer)?
            .paths
            .as_ref()
            .map(|p| p.current().endpoint())
    }

    /// 记录对端最近有流量。
    pub fn mark_active(&mut self, peer: &NodeId, now: Instant) {
        if let Some(p) = self.peers.get_mut(peer) {
            p.last_activity = Some(now);
        }
    }

    pub fn peer_ids(&self) -> impl Iterator<Item = (&NodeId, &X25519PublicKey)> {
        self.peers.iter().map(|(id, p)| (id, &p.public_key))
    }

    fn next_wire_seq(&mut self) -> u32 {
        self.wire_seq = self.wire_seq.wrapping_add(1);
        self.wire_seq
    }

    fn remember(&mut self, peer: &NodeId, pending: Pending, now: Instant) -> Option<u32> {
        if self.outstanding.len() >= MAX_OUTSTANDING {
            return None;
        }
        let seq = self.next_wire_seq();
        self.outstanding.insert(seq, (peer.clone(), pending, now));
        Some(seq)
    }

    pub fn tick(&mut self, now: Instant, now_ms: u64) -> (Vec<Outgoing>, Vec<Switch>) {
        let mut out = Vec::new();
        let mut switches = Vec::new();

        // 过期的对照项：中继测量记为丢失，其余由各状态机自己判定
        let expired: Vec<u32> = self
            .outstanding
            .iter()
            .filter(|(_, (_, _, at))| now.saturating_duration_since(*at) >= OUTSTANDING_TTL)
            .map(|(seq, _)| *seq)
            .collect();
        for seq in expired {
            if let Some((_, Pending::Monitor { relay }, _)) = self.outstanding.remove(&seq) {
                self.relay_stats.entry(relay).or_default().record_loss();
            }
        }

        let ids: Vec<NodeId> = self.peers.keys().cloned().collect();
        for id in ids {
            let Some(peer) = self.peers.get_mut(&id) else {
                continue;
            };
            let active = peer
                .last_activity
                .is_some_and(|t| now.saturating_duration_since(t) < ACTIVE_WINDOW);
            let Some(paths) = peer.paths.as_mut() else {
                continue;
            };
            let actions = paths.tick(now, active);
            for action in actions {
                match action {
                    Action::TunnelProbe { seq } => {
                        let to = SocketAddr::new(self.peers[&id].mesh_addrs[0], TUNNEL_PROBE_PORT);
                        if let Some(wire) = self.remember(&id, Pending::Tunnel { local: seq }, now)
                        {
                            out.push(Outgoing::Tunnel {
                                to,
                                data: probe::encode_tunnel_probe(wire).to_vec(),
                            });
                        }
                    }
                    Action::CandidateProbe { index, route, seq } => {
                        let Some(wire) =
                            self.remember(&id, Pending::Candidate { index, local: seq }, now)
                        else {
                            continue;
                        };
                        let peer = &self.peers[&id];
                        match (&peer.meta[index], route) {
                            (CandidateMeta::Direct, Route::Direct(to)) => {
                                if let Some(key) = &peer.direct_key {
                                    let probe = OuterProbe {
                                        kind: DIRECT_PROBE,
                                        key_id: self.own_key_id,
                                        seq: wire,
                                        sent_ms: now_ms,
                                    };
                                    out.push(Outgoing::Direct {
                                        to,
                                        data: probe.encode(key).to_vec(),
                                    });
                                }
                            }
                            (CandidateMeta::Relay { key, .. }, Route::Relay { endpoint, .. }) => {
                                let probe = OuterProbe {
                                    kind: RELAY_PROBE,
                                    key_id: self.own_key_id,
                                    seq: wire,
                                    sent_ms: now_ms,
                                };
                                out.push(Outgoing::Relay {
                                    to: endpoint,
                                    data: probe.encode(key).to_vec(),
                                });
                            }
                            _ => {}
                        }
                    }
                    Action::Switch {
                        to,
                        rehandshake,
                        reason,
                    } => switches.push(Switch {
                        peer: id.clone(),
                        public_key: self.peers[&id].public_key,
                        to,
                        rehandshake,
                        reason,
                    }),
                }
            }
        }

        // 跟随方也测中继，供对端估算经中继路径的另一段
        let due: Vec<KeyId> = self
            .monitored
            .iter()
            .filter(|(_, (_, _, last))| {
                last.is_none_or(|t| now.saturating_duration_since(t) >= RELAY_MONITOR_INTERVAL)
            })
            .map(|(id, _)| *id)
            .collect();
        let any_peer = self.peers.keys().next().cloned();
        for relay in due {
            let Some(owner) = any_peer.clone() else { break };
            let Some(wire) = self.remember(&owner, Pending::Monitor { relay }, now) else {
                break;
            };
            if let Some((endpoint, key, last)) = self.monitored.get_mut(&relay) {
                *last = Some(now);
                let probe = OuterProbe {
                    kind: RELAY_PROBE,
                    key_id: self.own_key_id,
                    seq: wire,
                    sent_ms: now_ms,
                };
                out.push(Outgoing::Relay {
                    to: *endpoint,
                    data: probe.encode(key).to_vec(),
                });
            }
        }
        (out, switches)
    }

    /// 处理收到的包，返回要发出的应答。认证不过或格式不对的包不作任何响应。
    pub fn on_packet(
        &mut self,
        kind: Incoming,
        from: SocketAddr,
        data: &[u8],
        at: Instant,
        now_ms: u64,
    ) -> Vec<Outgoing> {
        match (kind, data.first().copied()) {
            (Incoming::Tunnel, Some(probe::TUNNEL_PROBE)) => {
                // 只应答来自已准入成员组网地址的探测；来源已由 WireGuard 按 AllowedIPs 认证
                let (Some(seq), true) = (
                    probe::decode_tunnel_probe(data),
                    self.by_mesh_addr.contains_key(&from.ip()),
                ) else {
                    return vec![];
                };
                vec![Outgoing::Tunnel {
                    to: from,
                    data: probe::encode_tunnel_reply(seq, &self.relay_reports()),
                }]
            }
            (Incoming::Tunnel, Some(probe::TUNNEL_REPLY)) => {
                let Some((wire, reports)) = probe::decode_tunnel_reply(data) else {
                    return vec![];
                };
                let Some(sender) = self.by_mesh_addr.get(&from.ip()).cloned() else {
                    return vec![];
                };
                if let Some(peer) = self.peers.get_mut(&sender) {
                    for r in reports {
                        peer.reports.insert(
                            r.relay,
                            (
                                Duration::from_millis(u64::from(r.rtt_ms)),
                                f64::from(r.loss_permille) / 1000.0,
                            ),
                        );
                    }
                }
                if let Some((owner, Pending::Tunnel { local }, _)) = self.outstanding.remove(&wire)
                    && owner == sender
                    && let Some(paths) = self.peers.get_mut(&owner).and_then(|p| p.paths.as_mut())
                {
                    paths.on_tunnel_reply(local, at);
                }
                vec![]
            }
            (Incoming::Direct, Some(DIRECT_PROBE)) => {
                let Some(head) = OuterProbe::peek(data) else {
                    return vec![];
                };
                let Some(key) = self
                    .by_key_id
                    .get(&head.key_id)
                    .and_then(|id| self.peers[id].direct_key.as_ref())
                else {
                    return vec![];
                };
                let Some(probe) = OuterProbe::verify(data, key, now_ms) else {
                    return vec![];
                };
                let reply = probe.reply(self.own_key_id, from).encode(key);
                vec![Outgoing::Direct {
                    to: from,
                    data: reply.to_vec(),
                }]
            }
            (Incoming::Direct, Some(DIRECT_REPLY)) => {
                let Some(key_id) = OuterReply::peek(data) else {
                    return vec![];
                };
                let Some(id) = self.by_key_id.get(&key_id).cloned() else {
                    return vec![];
                };
                let Some(reply) = self.peers[&id]
                    .direct_key
                    .as_ref()
                    .and_then(|k| OuterReply::verify(data, k))
                else {
                    return vec![];
                };
                if let Some((owner, Pending::Candidate { index, local }, _)) =
                    self.outstanding.remove(&reply.seq)
                    && owner == id
                    && let Some(paths) = self.peers.get_mut(&owner).and_then(|p| p.paths.as_mut())
                {
                    paths.on_candidate_reply(index, local, at, None);
                }
                vec![]
            }
            (Incoming::Relay, Some(probe::RELAY_REPLY)) => {
                self.on_relay_reply(data, at);
                vec![]
            }
            _ => vec![],
        }
    }

    fn on_relay_reply(&mut self, data: &[u8], at: Instant) {
        // 应答中的编号是本机的；按序号找回是哪个探测，再用那个中继的令牌认证
        let Some(head) = OuterReply::peek(data) else {
            return;
        };
        if head != self.own_key_id || data.len() < 16 {
            return;
        }
        let seq = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let Some((owner, pending, sent)) = self.outstanding.get(&seq).cloned() else {
            return;
        };
        let (relay, key) = match pending {
            Pending::Monitor { relay } => match self.monitored.get(&relay) {
                Some((_, key, _)) => (relay, key),
                None => return,
            },
            Pending::Candidate { index, .. } => {
                match self.peers.get(&owner).and_then(|p| p.meta.get(index)) {
                    Some(CandidateMeta::Relay { relay, key }) => (*relay, key),
                    _ => return,
                }
            }
            Pending::Tunnel { .. } => return,
        };
        if OuterReply::verify(data, key).is_none() {
            return;
        }
        self.outstanding.remove(&seq);
        let rtt = at.saturating_duration_since(sent);
        self.relay_stats.entry(relay).or_default().record_reply(rtt);
        if let Pending::Candidate { index, local } = pending
            && let Some(peer) = self.peers.get_mut(&owner)
        {
            let extra = peer.reports.get(&relay).copied();
            if let Some(paths) = peer.paths.as_mut() {
                paths.on_candidate_reply(index, local, at, extra);
            }
        }
    }

    fn relay_reports(&self) -> Vec<RelayReport> {
        self.relay_stats
            .iter()
            .filter_map(|(relay, stats)| {
                let rtt = stats.rtt_ms()?;
                Some(RelayReport {
                    relay: *relay,
                    rtt_ms: rtt.round().clamp(0.0, f64::from(u16::MAX)) as u16,
                    loss_permille: (stats.loss_rate() * 1000.0).round() as u16,
                })
            })
            .take(probe::MAX_RELAY_REPORTS)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Candidate, ProbeToken};
    use crate::probe::{OuterProbe, OuterReply, RELAY_REPLY};
    use crate::testutil::{Mesh, node_id};
    use nett_trust::admission::admit;
    use nett_trust::anchors::TrustAnchors;
    use nett_trust::revocation::Revocations;
    use x25519_dalek::{PublicKey, StaticSecret};

    const TOKEN_A: [u8; 32] = [0xa1; 32];
    const TOKEN_B: [u8; 32] = [0xb2; 32];

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("addr")
    }

    struct Node {
        id: NodeId,
        prober: Prober,
        wg: SocketAddr,
        mesh: SocketAddr,
    }

    /// A（dial-only，决定方）经直连或中继 R 到 B（public）；模拟网络按链路的通断投递真实编码的消息。
    struct Net {
        a: Node,
        b: Node,
        relay: SocketAddr,
        direct_up: bool,
        relay_up: bool,
        now: Instant,
        switches: Vec<(Instant, Switch)>,
    }

    fn keypair(n: u8) -> (PrivateKey, X25519PublicKey) {
        let public = PublicKey::from(&StaticSecret::from([n; 32]));
        (
            PrivateKey::from_bytes([n; 32]),
            X25519PublicKey::from_bytes(public.to_bytes()),
        )
    }

    impl Net {
        fn new() -> Self {
            let mesh = Mesh::new(&[1, 2]);
            let (a_priv, a_pub) = keypair(1);
            let (b_priv, b_pub) = keypair(2);
            let anchors =
                TrustAnchors::from_doc(&mesh.desired(1, vec![]).trust_anchors).expect("anchors");
            let members: BTreeMap<NodeId, Member> = [(1, a_pub), (2, b_pub)]
                .into_iter()
                .map(|(n, key)| {
                    let m = admit(
                        &mesh.material_for(mesh.policy(n, 1), key),
                        &anchors,
                        &Revocations::default(),
                    )
                    .expect("admitted");
                    (m.node_id.clone(), m)
                })
                .collect();
            let relay_id = node_id(9);
            let relay = addr("198.51.100.9:41900");
            let paths = |peer: u8,
                         reach: Reachability,
                         token: [u8; 32],
                         direct: &str|
             -> BTreeMap<NodeId, PeerPathConfig> {
                [(
                    node_id(peer),
                    PeerPathConfig {
                        reachability: reach,
                        candidates: vec![
                            Candidate::Direct {
                                endpoint: addr(direct),
                            },
                            Candidate::Relay {
                                relay: relay_id.clone(),
                                endpoint: relay,
                                token: ProbeToken(token),
                            },
                        ],
                    },
                )]
                .into()
            };
            let mut a = Node {
                id: node_id(1),
                prober: Prober::new(&a_pub),
                wg: addr("203.0.113.1:41820"),
                mesh: addr("100.88.0.1:41821"),
            };
            let mut b = Node {
                id: node_id(2),
                prober: Prober::new(&b_pub),
                wg: addr("198.51.100.2:41820"),
                mesh: addr("100.88.0.2:41821"),
            };
            a.prober.update(
                &a.id,
                Reachability::DialOnly,
                &a_priv,
                &members,
                &paths(2, Reachability::Public, TOKEN_A, "198.51.100.2:41820"),
            );
            b.prober.update(
                &b.id,
                Reachability::Public,
                &b_priv,
                &members,
                &paths(1, Reachability::DialOnly, TOKEN_B, "203.0.113.1:41820"),
            );
            for node in [&mut a, &mut b] {
                let peer = if node.id == node_id(1) {
                    node_id(2)
                } else {
                    node_id(1)
                };
                node.prober.mark_active(&peer, Instant::now());
            }
            Self {
                a,
                b,
                relay,
                direct_up: true,
                relay_up: true,
                now: Instant::now(),
                switches: Vec::new(),
            }
        }

        /// 模拟中继：令牌认证后应答。
        fn relay_reply(&self, data: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
            let head = OuterProbe::peek(data)?;
            for token in [TOKEN_A, TOKEN_B] {
                let key = ProbeKey::from_token(&token);
                if let Some(p) = OuterProbe::verify(data, &key, 0) {
                    let reply = OuterReply {
                        kind: RELAY_REPLY,
                        key_id: head.key_id,
                        seq: p.seq,
                        sent_ms: p.sent_ms,
                        observed: from,
                    };
                    return Some(reply.encode(&key).to_vec());
                }
            }
            None
        }

        fn current_up(&self) -> bool {
            match self.a.prober.desired_endpoint(&self.b.id) {
                Some(e) if e == self.relay => self.relay_up,
                _ => self.direct_up,
            }
        }

        /// 投递一个节点发出的包；对方的应答立即投递回来（往返时间视为 0，由 tick 的粒度决定）。
        fn deliver(&mut self, from_a: bool, out: Outgoing) {
            let up = self.current_up();
            let (src, dst) = if from_a {
                (&mut self.a, &mut self.b)
            } else {
                (&mut self.b, &mut self.a)
            };
            let now = self.now;
            match out {
                Outgoing::Tunnel { data, .. } if up => {
                    for reply in dst
                        .prober
                        .on_packet(Incoming::Tunnel, src.mesh, &data, now, 0)
                    {
                        if let Outgoing::Tunnel { data, .. } = reply {
                            src.prober
                                .on_packet(Incoming::Tunnel, dst.mesh, &data, now, 0);
                        }
                    }
                }
                Outgoing::Direct { data, .. } if self.direct_up => {
                    for reply in dst
                        .prober
                        .on_packet(Incoming::Direct, src.wg, &data, now, 0)
                    {
                        if let Outgoing::Direct { data, .. } = reply {
                            src.prober
                                .on_packet(Incoming::Direct, dst.wg, &data, now, 0);
                        }
                    }
                }
                Outgoing::Relay { data, .. } if self.relay_up => {
                    let wg = src.wg;
                    if let Some(reply) = self.relay_reply(&data, wg) {
                        let src = if from_a { &mut self.a } else { &mut self.b };
                        src.prober
                            .on_packet(Incoming::Relay, self.relay, &reply, now, 0);
                    }
                }
                _ => {}
            }
        }

        fn run(&mut self, d: Duration) {
            let end = self.now + d;
            while self.now < end {
                self.now += Duration::from_millis(100);
                let (a_out, a_switches) = self.a.prober.tick(self.now, 0);
                let (b_out, b_switches) = self.b.prober.tick(self.now, 0);
                assert!(b_switches.is_empty(), "the follower never switches");
                self.switches
                    .extend(a_switches.into_iter().map(|s| (self.now, s)));
                for o in a_out {
                    self.deliver(true, o);
                }
                for o in b_out {
                    self.deliver(false, o);
                }
            }
        }
    }

    #[test]
    fn dial_only_member_decides() {
        let (a, b) = (node_id(1), node_id(2));
        assert!(is_decider(
            &a,
            Reachability::DialOnly,
            &b,
            Reachability::Public
        ));
        assert!(!is_decider(
            &b,
            Reachability::Public,
            &a,
            Reachability::DialOnly
        ));
        assert!(is_decider(
            &a,
            Reachability::Public,
            &b,
            Reachability::Public
        ));
        assert!(!is_decider(
            &b,
            Reachability::Public,
            &a,
            Reachability::Public
        ));
    }

    #[test]
    fn fails_over_to_the_relay_and_comes_back() {
        let mut net = Net::new();
        net.run(Duration::from_secs(10));
        assert!(net.switches.is_empty());
        // 跟随方的中继测量随隧道内应答带给了决定方
        assert!(
            net.a.prober.peers[&net.b.id]
                .reports
                .contains_key(&KeyId::of(node_id(9).as_str().as_bytes()))
        );

        let broke = net.now;
        net.direct_up = false;
        net.run(Duration::from_secs(5));
        let (at, s) = net.switches.first().expect("switched to the relay");
        assert_eq!(s.to.endpoint(), net.relay);
        assert!(s.rehandshake);
        assert!(at.saturating_duration_since(broke) <= Duration::from_millis(3600));

        let restored = net.now;
        net.direct_up = true;
        net.run(Duration::from_secs(25));
        let (at, s) = net.switches.last().expect("switched back");
        assert_eq!(s.to.endpoint(), addr("198.51.100.2:41820"));
        assert_eq!(s.reason, SwitchReason::BetterType);
        assert!(at.saturating_duration_since(restored) <= Duration::from_millis(3600));
    }

    #[test]
    fn ignores_unauthenticated_and_foreign_probes() {
        let mut net = Net::new();
        let now = net.now;
        // 不是成员组网地址发来的隧道内探测
        let probe = probe::encode_tunnel_probe(1);
        assert!(
            net.b
                .prober
                .on_packet(Incoming::Tunnel, addr("100.88.0.77:5000"), &probe, now, 0)
                .is_empty()
        );
        // 用错误密钥算校验码的直连探测
        let forged = OuterProbe {
            kind: DIRECT_PROBE,
            key_id: net.a.prober.own_key_id,
            seq: 1,
            sent_ms: 0,
        }
        .encode(&ProbeKey::from_token(&[0; 32]));
        assert!(
            net.b
                .prober
                .on_packet(Incoming::Direct, net.a.wg, &forged, now, 0)
                .is_empty()
        );
        // 任意字节
        assert!(
            net.b
                .prober
                .on_packet(Incoming::Direct, net.a.wg, &[0x82; 64], now, 0)
                .is_empty()
        );
    }
}
