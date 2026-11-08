//! 探测与选路的运行时状态（design/mesh.md 第 7、8 节）：为每个对端维护候选路径，收发探测消息，
//! 产出要发送的包和要执行的切换；双方都是 `dial-only` 时协调两端一起切换（第 8.4 节）。不碰套接字和
//! 数据面，由 [`crate::engine`] 执行，测试中可以直接驱动。

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use nett_core::id::NodeId;
use nett_trust::admission::Member;
use nett_trust::keys::X25519PublicKey;

use crate::config::{Candidate, PeerPathConfig, ProbeToken, Reachability};
use crate::event::Event;
use crate::key::PrivateKey;
use crate::path::{Action, PathKind, PathStats, PeerPaths, Role, Route, SwitchReason};
use crate::probe::{
    self, DIRECT_PROBE, DIRECT_REPLY, KeyId, OuterProbe, OuterReply, PUNCH_ACK, PUNCH_PROPOSAL,
    ProbeKey, PunchMessage, RELAY_PROBE, RelayReport, SWITCH_ACK, SWITCH_PROPOSAL, SwitchMessage,
    SwitchTarget, TUNNEL_PROBE_PORT,
};
use crate::punch::{Observations, Punch, PunchEvent};

/// 发出的探测等待应答的上限，过后从对照表中删除（各状态机自己判定丢失）。
const OUTSTANDING_TTL: Duration = Duration::from_secs(2);
/// 对照表的上限。
const MAX_OUTSTANDING: usize = 4096;
/// 跟随方测量中继的间隔：只为向决定方提供"中继 → 本机"这一段。
const RELAY_MONITOR_INTERVAL: Duration = Duration::from_secs(5);
/// 有流量的判定窗口（design/mesh.md 第 7 节）。
pub const ACTIVE_WINDOW: Duration = Duration::from_secs(30);
/// 切换提议的重发间隔与次数：约 2 秒收不到确认，决定方照常切换，之后中断就进入轮换（第 8.4 节）。
const PROPOSAL_RETRY: Duration = Duration::from_millis(300);
const PROPOSAL_TRIES: u32 = 7;
/// 跟随方发出确认之后等这么久再切换：确认要经当前的会话发出，切换会删除这个会话。
const ACK_GRACE: Duration = Duration::from_millis(100);
/// 轮换的时间片（第 8.4 节）。
const ROTATION_SLOT_MS: u64 = 15_000;
/// 时钟不可信时随机重试的间隔范围。
const RANDOM_RETRY_MIN: Duration = Duration::from_secs(5);
const RANDOM_RETRY_MAX: Duration = Duration::from_secs(15);

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
    /// `tls`：经传输适配进程的 TLS 传输；测量不计入本机到这个中继的 UDP 测量。
    Relay {
        relay: KeyId,
        key: ProbeKey,
        tls: bool,
    },
}

struct Peer {
    public_key: X25519PublicKey,
    mesh_addrs: [IpAddr; 2],
    direct_key: Option<ProbeKey>,
    /// 前 `configured` 条来自期望状态，之后是打通的直连。
    routes: Vec<(Route, PathKind)>,
    meta: Vec<CandidateMeta>,
    configured: usize,
    /// 决定方，以及双方都是 `dial-only` 时的两端，才有选路状态。
    paths: Option<PeerPaths>,
    /// 双方都是 `dial-only` 时两端一起切换的状态。
    together: Option<Together>,
    /// 双方都是 `dial-only`、配置了打洞候选时的打洞状态（design/mesh.md 第 6.1 节）。
    punch: Option<Punch>,
    reports: HashMap<KeyId, (Duration, f64)>,
    last_activity: Option<Instant>,
}

/// 两端一起切换（design/mesh.md 第 8.4 节）。
#[derive(Debug, Clone, Default)]
struct Together {
    /// 决定方：等待确认的提议。
    proposal: Option<Proposal>,
    /// 跟随方：最近一次接受的提议轮次，更早的轮次直接丢弃。
    accepted_round: u32,
    /// 跟随方：已经确认、等待执行的切换（目标候选、执行时刻）。
    accepted: Option<(usize, Instant)>,
    /// 当前路径中断，正在轮换。
    rotation: Option<Rotation>,
}

#[derive(Debug, Clone)]
struct Proposal {
    round: u32,
    target: SwitchTarget,
    index: usize,
    reason: SwitchReason,
    next_send: Instant,
    sent: u32,
}

#[derive(Debug, Clone, Default)]
struct Rotation {
    /// 时钟可信：最近一次重新握手所在的时间片。
    slot: Option<u64>,
    /// 时钟不可信：下一次随机重试的时刻。
    next_random: Option<Instant>,
}

#[derive(Debug, Clone, Copy)]
enum Pending {
    Tunnel {
        local: u32,
    },
    Candidate {
        index: usize,
        local: u32,
    },
    Monitor {
        relay: KeyId,
    },
    /// 打洞探测。
    Punch,
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
    /// 最近一次切换提议的轮次。
    round: u32,
    /// 收到确认后要执行的切换，在下一次 [`Prober::tick`] 交出。
    ready: Vec<Switch>,
    /// 本机时钟误差在 2 秒以内：轮换按时间片，否则按随机间隔（第 8.4 节）。
    clock_trusted: bool,
    /// `public` 节点告诉本机的映射地址（design/mesh.md 第 6.1 节）。
    observations: Observations,
    /// 交给调用方上报的事件。
    events: Vec<Event>,
}

/// 这一端在这一对中的角色（design/mesh.md 第 8.3、8.4 节）；`None` 表示经漫游跟随的一方。
pub fn role(
    own: &NodeId,
    own_reach: Reachability,
    peer: &NodeId,
    peer_reach: Reachability,
) -> Option<Role> {
    let decider = is_decider(own, own_reach, peer, peer_reach);
    match (own_reach, peer_reach, decider) {
        (Reachability::DialOnly, Reachability::DialOnly, true) => Some(Role::DecideTogether),
        (Reachability::DialOnly, Reachability::DialOnly, false) => Some(Role::FollowTogether),
        (_, _, true) => Some(Role::Decide),
        (_, _, false) => None,
    }
}

/// 由谁决定这一对的路径（design/mesh.md 第 8.3 节）：`dial-only` 对 `public` 时 `dial-only` 一方决定，
/// 否则成员 ID 较小的一方决定。
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

/// 候选在 WireGuard 中的 endpoint 与测量用的信息。TLS 候选的 endpoint 是传输适配进程的回环端口，
/// 由 `tls` 给出；没有分到端口的 TLS 候选不用。
fn routes(
    candidates: &[Candidate],
    tls: &BTreeMap<NodeId, SocketAddr>,
) -> (Vec<(Route, PathKind)>, Vec<CandidateMeta>) {
    candidates
        .iter()
        .filter_map(|c| match c {
            Candidate::Direct { endpoint } => Some((
                (Route::Direct(*endpoint), PathKind::Direct),
                CandidateMeta::Direct,
            )),
            Candidate::Relay {
                relay,
                endpoint,
                token,
            } => Some(relay_route(relay, *endpoint, token, false)),
            Candidate::RelayTls { relay, token, .. } => {
                Some(relay_route(relay, *tls.get(relay)?, token, true))
            }
            // 打洞的地址在打洞时交换，打通之后才成为一条候选
            Candidate::Punch => None,
        })
        .unzip()
}

fn relay_route(
    relay: &NodeId,
    endpoint: SocketAddr,
    token: &ProbeToken,
    tls: bool,
) -> ((Route, PathKind), CandidateMeta) {
    let id = KeyId::of(relay.as_str().as_bytes());
    let kind = if tls {
        PathKind::RelayTls
    } else {
        PathKind::Relay
    };
    (
        (
            Route::Relay {
                relay: id,
                endpoint,
            },
            kind,
        ),
        CandidateMeta::Relay {
            relay: id,
            key: ProbeKey::from_token(&token.0),
            tls,
        },
    )
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
            round: 0,
            ready: Vec::new(),
            clock_trusted: false,
            observations: Observations::default(),
            events: Vec::new(),
        }
    }

    /// 取走要上报的事件。
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// 有对端在高频探测刚切走的更优路径（design/mesh.md 第 7 节），或在等待重新握手完成（第 8.4 节）。
    pub fn needs_fine_ticks(&self, now: Instant) -> bool {
        self.peers.values().any(|p| {
            p.paths
                .as_ref()
                .is_some_and(|paths| paths.needs_fine_ticks(now))
        })
    }

    /// 有对端重新握手之后等待确认的期限已到：调用方先读取 WireGuard 的握手状态，再推进。
    pub fn handshake_due(&self, now: Instant) -> bool {
        self.peers.values().any(|p| {
            p.paths
                .as_ref()
                .is_some_and(|paths| paths.handshake_due(now))
        })
    }

    /// WireGuard 端口上来了一个 cookie 应答（只读副本）：交给当前路径就是 `from`、隧道还没建立的对端
    /// （design/mesh.md 第 8.4 节）。cookie 应答本身无法验证，作用只是推迟一次故障切换。
    fn on_cookie_reply(&mut self, from: SocketAddr, at: Instant) {
        for peer in self.peers.values_mut() {
            if let Some(paths) = peer.paths.as_mut()
                && paths.current().endpoint() == from
                && !paths.tunnel_established()
            {
                paths.on_cookie(at);
            }
        }
    }

    /// WireGuard 报告这个对端加入（或重新握手时重新加入）以来完成过握手。
    pub fn on_handshake(&mut self, id: &NodeId) {
        if let Some(paths) = self.peers.get_mut(id).and_then(|p| p.paths.as_mut()) {
            paths.on_handshake();
        }
    }

    /// 本机时钟误差是否在 2 秒以内（design/mesh.md 第 8.4 节），由运行时定期更新。
    pub fn set_clock_trusted(&mut self, trusted: bool) {
        self.clock_trusted = trusted;
    }

    /// 按已准入的成员和期望状态中的候选路径更新。候选列表没有变化的对端保留选路状态。`tls` 是各 TLS
    /// 中继在传输适配进程上的回环端口（[`crate::config::DesiredMesh::tls_endpoints`]）。
    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &mut self,
        own_id: &NodeId,
        own_reach: Reachability,
        private_key: &PrivateKey,
        members: &BTreeMap<NodeId, Member>,
        paths: &BTreeMap<NodeId, PeerPathConfig>,
        tls: &BTreeMap<NodeId, SocketAddr>,
    ) {
        let mut next = BTreeMap::new();
        self.monitored.clear();
        for (id, member) in members.iter().filter(|(id, _)| *id != own_id) {
            let config = paths.get(id);
            let candidates = config.map(|c| c.candidates.as_slice()).unwrap_or_default();
            let (mut routes, mut meta) = routes(candidates, tls);
            let configured = routes.len();
            let role = config.and_then(|c| role(own_id, own_reach, id, c.reachability));
            let punch_wanted =
                role.is_some_and(Role::together) && candidates.contains(&Candidate::Punch);
            let previous = self.peers.remove(id).filter(|p| {
                p.routes[..p.configured] == routes[..] && p.public_key == member.mesh_public_key
            });
            let kept = previous
                .as_ref()
                .and_then(|p| p.paths.as_ref().map(|paths| (paths, &p.together, &p.punch)))
                .filter(|(paths, _, _)| Some(paths.role()) == role);
            // 保留选路状态时，打通的直连也留下
            if kept.is_some()
                && let Some(prev) = &previous
            {
                for extra in &prev.routes[prev.configured..] {
                    routes.push(*extra);
                    meta.push(CandidateMeta::Direct);
                }
            }
            let punch = match kept {
                Some((_, _, punch)) if punch_wanted => {
                    punch.clone().or_else(|| Some(Punch::new(Instant::now())))
                }
                _ if punch_wanted => Some(Punch::new(Instant::now())),
                _ => None,
            };
            let (paths, together) = match (kept, role) {
                (Some((paths, together, _)), _) => (Some(paths.clone()), together.clone()),
                (None, Some(role)) => (
                    PeerPaths::new(routes.clone(), role),
                    role.together().then(Together::default),
                ),
                (None, None) => (None, None),
            };
            for m in &meta {
                // 跟随方只测 UDP 中继：测量供对端估算经中继路径的另一段
                if let CandidateMeta::Relay {
                    relay,
                    key,
                    tls: false,
                } = m
                {
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
                    configured,
                    paths,
                    together,
                    punch,
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

    /// 当前路径的 endpoint：有选路状态时取选路状态，否则取第一条候选（之后由 WireGuard 的漫游跟随）。
    pub fn endpoint(&self, peer: &NodeId) -> Option<SocketAddr> {
        let p = self.peers.get(peer)?;
        match &p.paths {
            Some(paths) => Some(paths.current().endpoint()),
            None => p.routes.first().map(|(r, _)| r.endpoint()),
        }
    }

    /// 期望的 endpoint，用于纠正被漫游改掉的 endpoint（第 8.3 节）。经漫游跟随的一方返回 `None`。
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
        let mut switches = std::mem::take(&mut self.ready);

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
            // 轮换中总是探测隧道：本端的探测收到应答就是双向确认
            let active = peer
                .last_activity
                .is_some_and(|t| now.saturating_duration_since(t) < ACTIVE_WINDOW)
                || peer.together.as_ref().is_some_and(|t| t.rotation.is_some());
            let Some(paths) = peer.paths.as_mut() else {
                continue;
            };
            let mut actions = paths.tick(now, active);
            actions.extend(self.coordinate(&id, now, now_ms));
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
                    Action::Propose { index, reason } => {
                        let round = self.next_round(now_ms);
                        if let Some(switch) = self.propose(&id, index, reason, round, now) {
                            switches.push(switch);
                        }
                    }
                    Action::Lost => self.start_rotation(&id),
                }
            }
            // 新的提议立即发出，等待中的按间隔重发
            out.extend(self.send_proposal(&id, now));
            out.extend(self.punch_tick(&id, now, now_ms));
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

    fn next_round(&mut self, now_ms: u64) -> u32 {
        // 以 Unix 秒为下限：重启之后的轮次也大于重启之前的，跟随方不会当作过期
        let secs = u32::try_from(now_ms / 1000).unwrap_or(u32::MAX);
        self.round = self.round.wrapping_add(1).max(secs);
        self.round
    }

    /// 决定方要切到第 `index` 个候选：目标是中继或打通的直连时开始提议；其他直连直接切换。
    fn propose(
        &mut self,
        id: &NodeId,
        index: usize,
        reason: SwitchReason,
        round: u32,
        now: Instant,
    ) -> Option<Switch> {
        let peer = self.peers.get_mut(id)?;
        let paths = peer.paths.as_mut()?;
        let together = peer.together.as_mut()?;
        let target = match peer.routes.get(index) {
            Some((Route::Relay { relay, .. }, _)) => Some(SwitchTarget::Relay(*relay)),
            Some((Route::Direct(_), _)) if paths.punched_index() == Some(index) => {
                Some(SwitchTarget::Punched)
            }
            _ => None,
        };
        match target {
            Some(target) => {
                together.proposal = Some(Proposal {
                    round,
                    target,
                    index,
                    reason,
                    next_send: now,
                    sent: 0,
                });
                None
            }
            None => {
                paths.set_hold(false);
                let action = paths.adopt(index, reason, now)?;
                switch_of(id, peer.public_key, action)
            }
        }
    }

    /// 发出（或重发）等待确认的提议；重发次数用完仍没有确认，决定方照常切换（第 8.4 节）。
    fn send_proposal(&mut self, id: &NodeId, now: Instant) -> Vec<Outgoing> {
        let Some(peer) = self.peers.get_mut(id) else {
            return vec![];
        };
        let to = SocketAddr::new(peer.mesh_addrs[0], TUNNEL_PROBE_PORT);
        let (Some(paths), Some(together)) = (peer.paths.as_mut(), peer.together.as_mut()) else {
            return vec![];
        };
        let Some(p) = together.proposal.as_mut() else {
            return vec![];
        };
        if now < p.next_send {
            return vec![];
        }
        if p.sent >= PROPOSAL_TRIES {
            let (index, reason) = (p.index, p.reason);
            together.proposal = None;
            paths.set_hold(false);
            if let Some(switch) = paths
                .adopt(index, reason, now)
                .and_then(|a| switch_of(id, peer.public_key, a))
            {
                self.ready.push(switch);
            }
            return vec![];
        }
        p.sent += 1;
        p.next_send = now + PROPOSAL_RETRY;
        let message = SwitchMessage {
            kind: SWITCH_PROPOSAL,
            round: p.round,
            target: p.target,
        };
        vec![Outgoing::Tunnel {
            to,
            data: message.encode().to_vec(),
        }]
    }

    fn start_rotation(&mut self, id: &NodeId) {
        let Some(together) = self.peers.get_mut(id).and_then(|p| p.together.as_mut()) else {
            return;
        };
        if together.rotation.is_none() {
            together.proposal = None;
            together.accepted = None;
            together.rotation = Some(Rotation::default());
        }
    }

    /// 两端一起切换的推进：跟随方执行已确认的提议；轮换中按时间片（或随机间隔）重新握手，本端的隧道内
    /// 探测收到应答就停在当前中继（第 8.4 节）。
    fn coordinate(&mut self, id: &NodeId, now: Instant, now_ms: u64) -> Vec<Action> {
        let trusted = self.clock_trusted;
        let Some(peer) = self.peers.get_mut(id) else {
            return vec![];
        };
        let (Some(paths), Some(together)) = (peer.paths.as_mut(), peer.together.as_mut()) else {
            return vec![];
        };
        if let Some((index, due)) = together.accepted
            && now >= due
        {
            together.accepted = None;
            together.rotation = None;
            paths.set_hold(false);
            return paths
                .adopt(index, SwitchReason::Proposed, now)
                .into_iter()
                .collect();
        }
        let Some(rotation) = together.rotation.as_mut() else {
            return vec![];
        };
        // 已经重新握手过，本端的隧道内探测收到了应答：双向都通，停在这个中继
        if (rotation.slot.is_some() || rotation.next_random.is_some()) && paths.tunnel_established()
        {
            together.rotation = None;
            paths.set_hold(false);
            return vec![];
        }
        paths.set_hold(true);
        let relays = paths.relays_in_order();
        if relays.is_empty() {
            return vec![];
        }
        let n = relays.len() as u64;
        let target = if trusted {
            let slot = now_ms / ROTATION_SLOT_MS;
            if rotation.slot == Some(slot) {
                return vec![];
            }
            rotation.slot = Some(slot);
            rotation.next_random = None;
            relays[usize::try_from(slot % n).unwrap_or(0)]
        } else {
            if rotation.next_random.is_some_and(|t| now < t) {
                return vec![];
            }
            rotation.slot = None;
            let span = RANDOM_RETRY_MAX - RANDOM_RETRY_MIN;
            let wait =
                RANDOM_RETRY_MIN + span.mul_f64(f64::from(random_u32()) / f64::from(u32::MAX));
            rotation.next_random = Some(now + wait);
            relays[usize::try_from(u64::from(random_u32()) % n).unwrap_or(0)]
        };
        paths
            .adopt(target, SwitchReason::Rotation, now)
            .into_iter()
            .collect()
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
            (Incoming::Tunnel, Some(PUNCH_PROPOSAL | PUNCH_ACK)) => {
                let Some(message) = PunchMessage::decode(data) else {
                    return vec![];
                };
                let Some(sender) = self.by_mesh_addr.get(&from.ip()).cloned() else {
                    return vec![];
                };
                self.on_punch_message(&sender, from, message, at)
            }
            (Incoming::Tunnel, Some(SWITCH_PROPOSAL | SWITCH_ACK)) => {
                let Some(message) = SwitchMessage::decode(data) else {
                    return vec![];
                };
                let Some(sender) = self.by_mesh_addr.get(&from.ip()).cloned() else {
                    return vec![];
                };
                self.on_switch_message(&sender, from, message, at)
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
                // 打洞期间：对方到本机这个方向通了（design/mesh.md 第 6.1 节）
                if let Some(peer) = self
                    .by_key_id
                    .get(&head.key_id)
                    .and_then(|id| self.peers.get_mut(id))
                    && let (Some(punch), Some(paths)) = (peer.punch.as_mut(), peer.paths.as_ref())
                {
                    punch.on_probe_from(from, paths.role() == Role::FollowTogether);
                }
                vec![Outgoing::Direct {
                    to: from,
                    data: reply.to_vec(),
                }]
            }
            (Incoming::Direct, Some(probe::WG_COOKIE_REPLY))
                if data.len() == probe::WG_COOKIE_LEN =>
            {
                self.on_cookie_reply(from, at);
                vec![]
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
                match self.outstanding.remove(&reply.seq) {
                    Some((owner, Pending::Candidate { index, local }, _)) if owner == id => {
                        // 对方看到的来源就是本机 WireGuard 端口的映射地址（design/mesh.md 第 6.1 节）
                        self.observations.record(from.ip(), reply.observed, at);
                        if let Some(paths) =
                            self.peers.get_mut(&owner).and_then(|p| p.paths.as_mut())
                        {
                            paths.on_candidate_reply(index, local, at, None);
                        }
                    }
                    Some((owner, Pending::Punch, _)) if owner == id => {
                        if let Some(punch) =
                            self.peers.get_mut(&owner).and_then(|p| p.punch.as_mut())
                        {
                            punch.on_reply_from(from, at);
                        }
                    }
                    _ => {}
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

    /// 切换提议与确认（第 8.4 节）。来源已由 WireGuard 按 AllowedIPs 认证；只接受这一对中对方角色的消息，
    /// 过期轮次和不在候选中的中继直接丢弃。
    fn on_switch_message(
        &mut self,
        sender: &NodeId,
        from: SocketAddr,
        message: SwitchMessage,
        at: Instant,
    ) -> Vec<Outgoing> {
        let Some(peer) = self.peers.get_mut(sender) else {
            return vec![];
        };
        let public_key = peer.public_key;
        let (Some(paths), Some(together)) = (peer.paths.as_mut(), peer.together.as_mut()) else {
            return vec![];
        };
        match (message.kind, paths.role()) {
            (SWITCH_PROPOSAL, Role::FollowTogether) => {
                let index = match message.target {
                    SwitchTarget::Relay(relay) => paths.relay_index(relay),
                    SwitchTarget::Punched => paths.punched_index(),
                };
                let Some(index) = index else {
                    return vec![];
                };
                if message.round < together.accepted_round {
                    return vec![];
                }
                if message.round > together.accepted_round {
                    together.accepted_round = message.round;
                    together.accepted = Some((index, at + ACK_GRACE));
                }
                // 同一轮次的重发：上一份确认丢了，再确认一次
                let ack = SwitchMessage {
                    kind: SWITCH_ACK,
                    ..message
                };
                vec![Outgoing::Tunnel {
                    to: from,
                    data: ack.encode().to_vec(),
                }]
            }
            (SWITCH_ACK, Role::DecideTogether) => {
                let Some(p) = together
                    .proposal
                    .take_if(|p| p.round == message.round && p.target == message.target)
                else {
                    return vec![];
                };
                paths.set_hold(false);
                if let Some(switch) = paths
                    .adopt(p.index, p.reason, at)
                    .and_then(|a| switch_of(sender, public_key, a))
                {
                    self.ready.push(switch);
                }
                vec![]
            }
            _ => vec![],
        }
    }

    /// 打洞提议与确认（design/mesh.md 第 6.1 节）。来源已由 WireGuard 认证；只接受这一对中对方角色的消息。
    fn on_punch_message(
        &mut self,
        sender: &NodeId,
        from: SocketAddr,
        message: PunchMessage,
        at: Instant,
    ) -> Vec<Outgoing> {
        let own = self.observations.own(at);
        let Some(peer) = self.peers.get_mut(sender) else {
            return vec![];
        };
        let (Some(paths), Some(punch)) = (peer.paths.as_ref(), peer.punch.as_mut()) else {
            return vec![];
        };
        match (message.kind, paths.role()) {
            (PUNCH_PROPOSAL, Role::FollowTogether) => punch
                .on_proposal(&message, &own, at)
                .map(|ack| Outgoing::Tunnel {
                    to: from,
                    data: ack.encode().to_vec(),
                })
                .into_iter()
                .collect(),
            (PUNCH_ACK, Role::DecideTogether) => {
                punch.on_ack(&message, &own, at);
                vec![]
            }
            _ => vec![],
        }
    }

    /// 打洞的推进：决定方在适合时提议；打洞期间每 200 毫秒从 WireGuard 端口向对方的地址发探测；打通的
    /// 地址作为一条直连候选加入选路状态（design/mesh.md 第 6.1 节）。
    fn punch_tick(&mut self, id: &NodeId, now: Instant, now_ms: u64) -> Vec<Outgoing> {
        let own = self.observations.own(now);
        let next_round = self
            .round
            .wrapping_add(1)
            .max(u32::try_from(now_ms / 1000).unwrap_or(u32::MAX));
        let mut round_used = false;
        let Some(peer) = self.peers.get_mut(id) else {
            return vec![];
        };
        let to = SocketAddr::new(peer.mesh_addrs[0], TUNNEL_PROBE_PORT);
        let (Some(paths), Some(punch), Some(together)) = (
            peer.paths.as_mut(),
            peer.punch.as_mut(),
            peer.together.as_ref(),
        ) else {
            return vec![];
        };
        let mut out = Vec::new();
        if paths.role() == Role::DecideTogether {
            let eligible = paths.tunnel_established()
                && paths.current_kind().via_relay()
                && together.proposal.is_none()
                && together.rotation.is_none();
            if let Some(proposal) = punch.decider_tick(now, eligible, &own, || {
                round_used = true;
                next_round
            }) {
                out.push(Outgoing::Tunnel {
                    to,
                    data: proposal.encode().to_vec(),
                });
            }
        }
        let targets = punch.probe_targets(now);
        if let Some(addr) = punch.punched() {
            let index = paths.set_punched(addr);
            let route = (Route::Direct(addr), PathKind::Direct);
            if index < peer.routes.len() {
                peer.routes[index] = route;
            } else {
                peer.routes.push(route);
                peer.meta.push(CandidateMeta::Direct);
            }
        }
        let events = punch.take_events();
        let key = peer.direct_key.clone();
        if round_used {
            self.round = next_round;
        }
        for event in events {
            self.events.push(match event {
                PunchEvent::Started {
                    round,
                    own,
                    peer,
                    targets,
                } => Event::PunchStarted {
                    node_id: id.clone(),
                    round,
                    nat: own,
                    peer_nat: peer,
                    targets,
                },
                PunchEvent::Succeeded { address } => Event::PunchSucceeded {
                    node_id: id.clone(),
                    address,
                },
                PunchEvent::Failed { reason } => Event::PunchFailed {
                    node_id: id.clone(),
                    reason: reason.to_owned(),
                },
            });
        }
        let Some(key) = key else {
            return out;
        };
        for target in targets {
            let Some(wire) = self.remember(id, Pending::Punch, now) else {
                break;
            };
            let probe = OuterProbe {
                kind: DIRECT_PROBE,
                key_id: self.own_key_id,
                seq: wire,
                sent_ms: now_ms,
            };
            out.push(Outgoing::Direct {
                to: target,
                data: probe.encode(&key).to_vec(),
            });
        }
        out
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
        let (relay, key, tls) = match pending {
            Pending::Monitor { relay } => match self.monitored.get(&relay) {
                Some((_, key, _)) => (relay, key, false),
                None => return,
            },
            Pending::Candidate { index, .. } => {
                match self.peers.get(&owner).and_then(|p| p.meta.get(index)) {
                    Some(CandidateMeta::Relay { relay, key, tls }) => (*relay, key, *tls),
                    _ => return,
                }
            }
            Pending::Tunnel { .. } | Pending::Punch => return,
        };
        if OuterReply::verify(data, key).is_none() {
            return;
        }
        self.outstanding.remove(&seq);
        let rtt = at.saturating_duration_since(sent);
        // 随隧道内应答带给对端的是本机到中继的 UDP 测量
        if !tls {
            self.relay_stats.entry(relay).or_default().record_reply(rtt);
        }
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

fn switch_of(peer: &NodeId, public_key: X25519PublicKey, action: Action) -> Option<Switch> {
    match action {
        Action::Switch {
            to,
            rehandshake,
            reason,
        } => Some(Switch {
            peer: peer.clone(),
            public_key,
            to,
            rehandshake,
            reason,
        }),
        _ => None,
    }
}

/// 随机重试用的随机数：只用于错开两端的重试，不承担安全作用。
fn random_u32() -> u32 {
    use ring::rand::SecureRandom as _;
    let mut b = [0u8; 4];
    match ring::rand::SystemRandom::new().fill(&mut b) {
        Ok(()) => u32::from_be_bytes(b),
        Err(_) => 0,
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
                &BTreeMap::new(),
            );
            b.prober.update(
                &b.id,
                Reachability::Public,
                &b_priv,
                &members,
                &paths(1, Reachability::DialOnly, TOKEN_B, "203.0.113.1:41820"),
                &BTreeMap::new(),
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
        // 切走后的 15 秒内高频探测；模拟每 100 毫秒推进一次
        let took = at.saturating_duration_since(restored);
        assert!(took <= Duration::from_millis(300), "took {took:?}");
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

    /// A、B 都是 `dial-only`（A 的 ID 较小，是决定方），经中继 R1、R2；隧道只在两端的 endpoint 指向同一个
    /// 可用的中继时连通。两端的候选列表顺序不同。
    struct Pair {
        a: Node,
        b: Node,
        relays: [SocketAddr; 2],
        relay_up: [bool; 2],
        /// 经这个中继时每隔几个隧道内的探测（或提议）丢一个，应答不丢。
        lossy: Option<(usize, u32)>,
        sent: u32,
        now: Instant,
        now_ms: u64,
        switches: Vec<(Instant, bool, Switch)>,
        /// 两端各在一个端口受限的锥形 NAT 之后：映射地址固定；只有本机先向对方的地址发过包，对方的包
        /// 才进得来。
        mapped: [SocketAddr; 2],
        opened: [std::collections::HashSet<SocketAddr>; 2],
        direct_sent: [usize; 2],
    }

    impl Pair {
        fn new() -> Self {
            Self::build(false)
        }

        /// 配置了打洞候选；两端都从两个 `public` 节点得知了自己的映射地址（`symmetric` 时两个观察者看到的
        /// 端口不同）。
        fn with_punch(symmetric: bool) -> Self {
            let mut pair = Self::build(true);
            let now = pair.now;
            for (i, node) in [&mut pair.a, &mut pair.b].into_iter().enumerate() {
                let m = pair.mapped[i];
                let r1: IpAddr = "198.51.100.9".parse().expect("ip");
                let r2: IpAddr = "198.51.100.10".parse().expect("ip");
                node.prober.observations.record(r1, m, now);
                let other = if symmetric {
                    SocketAddr::new(m.ip(), m.port() + 1)
                } else {
                    m
                };
                node.prober.observations.record(r2, other, now);
            }
            pair
        }

        fn build(punch: bool) -> Self {
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
            let relays = [addr("198.51.100.9:41900"), addr("198.51.100.10:41900")];
            let relay = |i: usize, token: [u8; 32]| Candidate::Relay {
                relay: node_id(9 + u8::try_from(i).expect("small")),
                endpoint: relays[i],
                token: ProbeToken(token),
            };
            let paths =
                |peer: u8, candidates: Vec<Candidate>| -> BTreeMap<NodeId, PeerPathConfig> {
                    [(
                        node_id(peer),
                        PeerPathConfig {
                            reachability: Reachability::DialOnly,
                            candidates,
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
                wg: addr("192.0.2.2:41820"),
                mesh: addr("100.88.0.2:41821"),
            };
            a.prober.update(
                &a.id,
                Reachability::DialOnly,
                &a_priv,
                &members,
                &paths(2, {
                    let mut c = vec![relay(0, TOKEN_A), relay(1, TOKEN_A)];
                    c.extend(punch.then_some(Candidate::Punch));
                    c
                }),
                &BTreeMap::new(),
            );
            b.prober.update(
                &b.id,
                Reachability::DialOnly,
                &b_priv,
                &members,
                &paths(1, {
                    let mut c = vec![relay(1, TOKEN_B), relay(0, TOKEN_B)];
                    c.extend(punch.then_some(Candidate::Punch));
                    c
                }),
                &BTreeMap::new(),
            );
            let now = Instant::now();
            for (node, peer) in [(&mut a, node_id(2)), (&mut b, node_id(1))] {
                node.prober.mark_active(&peer, now);
                node.prober.set_clock_trusted(true);
            }
            Self {
                a,
                b,
                relays,
                relay_up: [true, true],
                lossy: None,
                sent: 0,
                now,
                // 时间片边界之后 1 秒
                now_ms: 1_800_000_001_000 - 1_800_000_001_000 % ROTATION_SLOT_MS + 1_000,
                switches: Vec::new(),
                mapped: [addr("198.51.100.201:41820"), addr("198.51.100.202:41820")],
                opened: Default::default(),
                direct_sent: [0, 0],
            }
        }

        fn endpoints(&self) -> (Option<SocketAddr>, Option<SocketAddr>) {
            (
                self.a.prober.desired_endpoint(&self.b.id),
                self.b.prober.desired_endpoint(&self.a.id),
            )
        }

        fn tunnel_up(&mut self, lossy: bool) -> bool {
            let (a, b) = self.endpoints();
            // 打通的直连：两端都指向对方的映射地址
            if a == Some(self.mapped[1]) && b == Some(self.mapped[0]) {
                return true;
            }
            let shared = a.filter(|_| a == b);
            let Some(i) = self.relays.iter().position(|r| Some(*r) == shared) else {
                return false;
            };
            let dropping = match self.lossy {
                Some((relay, every)) if lossy && relay == i => {
                    self.sent += 1;
                    self.sent.is_multiple_of(every)
                }
                _ => false,
            };
            self.relay_up[i] && !dropping
        }

        fn deliver(&mut self, from_a: bool, out: Outgoing) {
            let (now, now_ms) = (self.now, self.now_ms);
            match out {
                Outgoing::Tunnel { data, .. } => {
                    if !self.tunnel_up(true) {
                        return;
                    }
                    let (src, dst) = if from_a {
                        (&mut self.a, &mut self.b)
                    } else {
                        (&mut self.b, &mut self.a)
                    };
                    let replies =
                        dst.prober
                            .on_packet(Incoming::Tunnel, src.mesh, &data, now, now_ms);
                    let dst_mesh = dst.mesh;
                    for reply in replies {
                        if let Outgoing::Tunnel { data, .. } = reply
                            && self.tunnel_up(false)
                        {
                            let src = if from_a { &mut self.a } else { &mut self.b };
                            src.prober
                                .on_packet(Incoming::Tunnel, dst_mesh, &data, now, now_ms);
                        }
                    }
                }
                Outgoing::Relay { to, data } => {
                    let Some(i) = self.relays.iter().position(|r| *r == to) else {
                        return;
                    };
                    if !self.relay_up[i] {
                        return;
                    }
                    let src = if from_a { &mut self.a } else { &mut self.b };
                    for token in [TOKEN_A, TOKEN_B] {
                        let key = ProbeKey::from_token(&token);
                        if let Some(p) = OuterProbe::verify(&data, &key, now_ms) {
                            let reply = OuterReply {
                                kind: RELAY_REPLY,
                                key_id: p.key_id,
                                seq: p.seq,
                                sent_ms: p.sent_ms,
                                observed: src.wg,
                            };
                            src.prober.on_packet(
                                Incoming::Relay,
                                to,
                                &reply.encode(&key),
                                now,
                                now_ms,
                            );
                        }
                    }
                }
                Outgoing::Direct { to, data } => {
                    let (src, dst) = if from_a { (0, 1) } else { (1, 0) };
                    self.direct_sent[src] += 1;
                    // 发出即在本机的 NAT 上打开到这个地址的映射
                    self.opened[src].insert(to);
                    if to != self.mapped[dst] || !self.opened[dst].contains(&self.mapped[src]) {
                        return;
                    }
                    let from = self.mapped[src];
                    let (sender, receiver) = if from_a {
                        (&mut self.a, &mut self.b)
                    } else {
                        (&mut self.b, &mut self.a)
                    };
                    let replies =
                        receiver
                            .prober
                            .on_packet(Incoming::Direct, from, &data, now, now_ms);
                    for reply in replies {
                        if let Outgoing::Direct { to, data } = reply
                            && to == from
                            && self.opened[src].contains(&self.mapped[dst])
                        {
                            sender.prober.on_packet(
                                Incoming::Direct,
                                self.mapped[dst],
                                &data,
                                now,
                                now_ms,
                            );
                        }
                    }
                }
            }
        }

        fn run(&mut self, d: Duration) {
            let end = self.now + d;
            while self.now < end {
                self.now += Duration::from_millis(100);
                self.now_ms += 100;
                let (a_out, a_sw) = self.a.prober.tick(self.now, self.now_ms);
                let (b_out, b_sw) = self.b.prober.tick(self.now, self.now_ms);
                let now = self.now;
                self.switches
                    .extend(a_sw.into_iter().map(|s| (now, true, s)));
                self.switches
                    .extend(b_sw.into_iter().map(|s| (now, false, s)));
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
    fn dial_only_pair_starts_on_the_same_relay() {
        let mut pair = Pair::new();
        let (a, b) = pair.endpoints();
        assert_eq!(a, b);
        assert!(a.is_some());
        pair.run(Duration::from_secs(10));
        assert!(pair.switches.is_empty(), "{:?}", pair.switches);
    }

    #[test]
    fn dial_only_pair_switches_together_after_the_ack() {
        let mut pair = Pair::new();
        pair.run(Duration::from_secs(10));
        let (start, _) = pair.endpoints();
        // 当前中继严重丢包但仍能传递一部分：决定方经隧道提议，对端确认后两端一起切换
        let current = pair
            .relays
            .iter()
            .position(|r| Some(*r) == start)
            .expect("on a relay");
        pair.lossy = Some((current, 2));
        pair.run(Duration::from_secs(20));
        let (a, b) = pair.endpoints();
        assert_eq!(a, b);
        assert_ne!(a, start, "{:?}", pair.switches);
        let reasons: Vec<(bool, SwitchReason, bool)> = pair
            .switches
            .iter()
            .map(|(_, from_a, s)| (*from_a, s.reason, s.rehandshake))
            .collect();
        // 丢包明显时同类更优路径 5 秒即切换，可能先于判为故障
        assert!(
            reasons.contains(&(true, SwitchReason::HighLoss, true))
                || reasons.contains(&(true, SwitchReason::BetterScore, true)),
            "{reasons:?}"
        );
        assert!(
            reasons.contains(&(false, SwitchReason::Proposed, true)),
            "{reasons:?}"
        );
        // 两端切换的时刻相差不超过半秒
        let at = |side: bool| {
            pair.switches
                .iter()
                .find(|(_, from_a, _)| *from_a == side)
                .map(|(t, _, _)| *t)
                .expect("switched")
        };
        let gap = at(true).max(at(false)) - at(true).min(at(false));
        assert!(gap <= Duration::from_millis(500), "gap {gap:?}");
    }

    #[test]
    fn dial_only_pair_meets_by_time_slot_after_an_outage() {
        let mut pair = Pair::new();
        pair.run(Duration::from_secs(10));
        let (start, _) = pair.endpoints();
        let failed = pair
            .relays
            .iter()
            .position(|r| Some(*r) == start)
            .expect("on a relay");
        pair.relay_up[failed] = false;
        let down = pair.now;
        pair.run(Duration::from_secs(45));
        let (a, b) = pair.endpoints();
        assert_eq!(a, b);
        assert_ne!(a, start);
        // 双方都按时间片轮换；在另一个中继上确认后停下，不再轮换
        let rotations: Vec<(Instant, bool)> = pair
            .switches
            .iter()
            .filter(|(_, _, s)| s.reason == SwitchReason::Rotation)
            .map(|(t, side, _)| (*t, *side))
            .collect();
        assert!(rotations.iter().any(|(_, a)| *a) && rotations.iter().any(|(_, a)| !*a));
        let last = rotations.last().expect("rotated").0;
        assert!(
            last.saturating_duration_since(down) <= Duration::from_secs(20),
            "{rotations:?}"
        );
        let before = pair.switches.len();
        pair.run(Duration::from_secs(60));
        assert_eq!(pair.switches.len(), before);
    }

    #[test]
    fn switch_messages_need_the_right_role_round_and_relay() {
        let mut pair = Pair::new();
        let (now, now_ms) = (pair.now, pair.now_ms);
        let relay = KeyId::of(node_id(10).as_str().as_bytes());
        let proposal = |round: u32, relay: KeyId| {
            SwitchMessage {
                kind: SWITCH_PROPOSAL,
                round,
                target: SwitchTarget::Relay(relay),
            }
            .encode()
        };
        // 跟随方确认决定方的提议
        let acks = pair.b.prober.on_packet(
            Incoming::Tunnel,
            pair.a.mesh,
            &proposal(5, relay),
            now,
            now_ms,
        );
        assert_eq!(acks.len(), 1);
        // 过期的轮次、不在候选中的中继、来自跟随方的提议：都不应答
        let stale = pair.b.prober.on_packet(
            Incoming::Tunnel,
            pair.a.mesh,
            &proposal(4, relay),
            now,
            now_ms,
        );
        let unknown = pair.b.prober.on_packet(
            Incoming::Tunnel,
            pair.a.mesh,
            &proposal(6, KeyId([7; 8])),
            now,
            now_ms,
        );
        let wrong_role = pair.a.prober.on_packet(
            Incoming::Tunnel,
            pair.b.mesh,
            &proposal(9, relay),
            now,
            now_ms,
        );
        assert!(stale.is_empty() && unknown.is_empty() && wrong_role.is_empty());
        // 不是成员组网地址发来的
        let foreign = pair.b.prober.on_packet(
            Incoming::Tunnel,
            addr("100.88.0.77:41821"),
            &proposal(10, relay),
            now,
            now_ms,
        );
        assert!(foreign.is_empty());
    }

    #[test]
    fn untrusted_clock_retries_at_random_intervals() {
        let mut pair = Pair::new();
        pair.run(Duration::from_secs(10));
        for node in [&mut pair.a, &mut pair.b] {
            node.prober.set_clock_trusted(false);
        }
        pair.relay_up = [false, false];
        pair.run(Duration::from_secs(120));
        let attempts: Vec<Instant> = pair
            .switches
            .iter()
            .filter(|(_, from_a, s)| *from_a && s.reason == SwitchReason::Rotation)
            .map(|(t, _, _)| *t)
            .collect();
        assert!(attempts.len() >= 7, "{attempts:?}");
        for w in attempts.windows(2) {
            let gap = w[1].saturating_duration_since(w[0]);
            assert!(
                gap >= RANDOM_RETRY_MIN && gap <= RANDOM_RETRY_MAX + Duration::from_millis(100),
                "gap {gap:?}"
            );
        }
    }

    #[test]
    fn dial_only_pair_punches_through_cone_nats_and_switches_together() {
        let mut pair = Pair::with_punch(false);
        pair.run(Duration::from_secs(15));
        let (a, b) = pair.endpoints();
        assert_eq!(
            (a, b),
            (Some(pair.mapped[1]), Some(pair.mapped[0])),
            "{:?}",
            pair.switches
        );
        let reasons: Vec<(bool, SwitchReason, bool)> = pair
            .switches
            .iter()
            .map(|(_, from_a, s)| (*from_a, s.reason, s.rehandshake))
            .collect();
        // 决定方择优切过去，跟随方按提议切换；直连不需要重新握手
        assert!(
            reasons.contains(&(true, SwitchReason::BetterType, false)),
            "{reasons:?}"
        );
        assert!(
            reasons.contains(&(false, SwitchReason::Proposed, false)),
            "{reasons:?}"
        );
        let events = pair.a.prober.take_events();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::PunchStarted { .. })),
            "{events:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::PunchSucceeded { .. })),
            "{events:?}"
        );
        // 之后停在直连上
        let before = pair.switches.len();
        pair.run(Duration::from_secs(60));
        assert_eq!(pair.switches.len(), before);
    }

    #[test]
    fn both_symmetric_do_not_punch() {
        let mut pair = Pair::with_punch(true);
        pair.run(Duration::from_secs(20));
        assert!(pair.switches.is_empty(), "{:?}", pair.switches);
        assert_eq!(pair.direct_sent, [0, 0], "no punch probes");
        let events = pair.a.prober.take_events();
        assert!(
            events.iter().any(|e| matches!(e, Event::PunchFailed { reason, .. } if reason == "both behind symmetric NAT")),
            "{events:?}"
        );
    }
}
