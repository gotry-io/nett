//! 把已准入的成员落到数据面：本机的组网接口，以及每个其他成员一个 WireGuard 对端；按选路的结果
//! 切换对端的 endpoint，并纠正被 WireGuard 漫游改掉的 endpoint（design/mesh.md 第 4、8 节）。
//!
//! 数据面操作失败时保持现状，在下一份期望状态或下一次检查时重试（"拿不准时，连接保持现状"）。访问控制是
//! 例外：先安装过滤规则再添加对端，安装失败时拒绝（硬性规则 6）。

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_core::transport::TransportConfig;
use nett_trust::admission::Member;
use nett_trust::encoding::Timestamp;
use nett_trust::keys::X25519PublicKey;

use crate::access::{AccessRules, EdgeSpec, FilterSpec, IngressSpec};
use crate::config::{DesiredMesh, Reachability};
use crate::dataplane::{
    DataPlane, INTERFACE_NAME, InterfaceAddress, InterfaceSpec, MESH_MTU, PeerSpec,
};
use crate::event::{Event, EventSink};
use crate::key::PrivateKey;
use crate::members::MemberSet;
use crate::path::{CandidateState, PathKind, Role, Route};
use crate::probe::{KeyId, NatType};
use crate::prober::{ACTIVE_WINDOW, Incoming, Outgoing, Prober};
use crate::routes::Routes;
use crate::status::{
    self, CandidateStateDoc, CandidateStatus, ConfigStatus, NatKind, NatStatus, NodeRef,
    NodeStatus, PathKindDoc, PathStatus, PeerRole, PeerState, PeerStatus, StatusDoc,
};
use nett_core::prefix::IpPrefix;

/// `dial-only` 成员对每个对端的持久保活间隔（秒），维持 NAT 映射（design/mesh.md 第 4 节）。
pub const DIAL_ONLY_KEEPALIVE_SECS: u16 = 25;
/// 读取各对端状态（流量、endpoint）的间隔：endpoint 被漫游改掉后在这个时间内纠正（第 8.3 节）。
const STATS_INTERVAL: Duration = Duration::from_millis(100);

/// 已经就绪的组网接口。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// 最近一次成功应用的接口配置。
    pub spec: InterfaceSpec,
    /// WireGuard 实际监听的端口：期望状态不带端口时由系统分配（design/mesh.md 第 5.5 节）。
    pub listen_port: u16,
}

pub struct Engine<D> {
    node_id: NodeId,
    private_key: PrivateKey,
    dataplane: D,
    members: MemberSet,
    interface: Option<Interface>,
    /// 最近一次交给传输适配进程的配置。
    transport: Option<TransportConfig>,
    reachability: Reachability,
    prober: Option<Prober>,
    /// 已经配置到数据面的对端：经漫游跟随的一方只在新增对端时设置 endpoint，之后交给 WireGuard 的漫游。
    configured: HashSet<X25519PublicKey>,
    traffic: HashMap<X25519PublicKey, Traffic>,
    /// 最近一次重新握手执行的时刻（Unix 毫秒）：WireGuard 报告的握手时间不早于它，才是这次握手完成
    /// （第 8.4 节）。决定与执行之间读到的仍是旧对端的握手时间。
    rehandshaked_at: HashMap<X25519PublicKey, u64>,
    last_stats: Option<Instant>,
    clock_trusted: bool,
    /// TLS 中继在传输适配进程上的回环端点，以及最近一次设置的闲置端口（design/mesh.md 第 5.3 节）。
    tls_endpoints: BTreeSet<SocketAddr>,
    tls_guarded: Option<Vec<u16>>,
    access: AccessRules,
    routes: Routes,
    /// 已经安装到数据面的过滤规则、Edge 设置、智能入口的转发规则与其他成员网段的路由。
    filter: Option<FilterSpec>,
    edge: Option<Option<EdgeSpec>>,
    ingress: Option<Option<IngressSpec>>,
    installed_routes: Option<Vec<IpPrefix>>,
    /// 最近一次接受的期望状态中的节点名，以及接受的时刻（本机状态，design/status.md 第 5、6 节）。
    names: BTreeMap<NodeId, NodeName>,
    applied_at: Option<Instant>,
    /// TLS 中继在传输适配进程上的回环端口 → 中继的 TLS 地址：本机状态中显示后者。
    tls_relays: BTreeMap<SocketAddr, SocketAddr>,
}

/// 从数据面读到的一个对端的流量，以及收发字节数最近一次变化的时刻。
#[derive(Debug, Clone, Default)]
struct Traffic {
    rx_bytes: u64,
    tx_bytes: u64,
    last_rx: Option<Instant>,
    last_tx: Option<Instant>,
    endpoint: Option<SocketAddr>,
    last_handshake: Option<SystemTime>,
}

impl<D: DataPlane> Engine<D> {
    pub fn new(node_id: NodeId, private_key: PrivateKey, dataplane: D) -> Self {
        Self {
            node_id,
            private_key,
            dataplane,
            members: MemberSet::default(),
            interface: None,
            transport: None,
            reachability: Reachability::Public,
            prober: None,
            configured: HashSet::new(),
            traffic: HashMap::new(),
            rehandshaked_at: HashMap::new(),
            last_stats: None,
            clock_trusted: false,
            tls_endpoints: BTreeSet::new(),
            tls_guarded: None,
            access: AccessRules::default(),
            routes: Routes::default(),
            filter: None,
            edge: None,
            ingress: None,
            installed_routes: None,
            names: BTreeMap::new(),
            applied_at: None,
            tls_relays: BTreeMap::new(),
        }
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// 最近一次接受的期望状态中的节点名。
    pub fn names(&self) -> &BTreeMap<NodeId, NodeName> {
        &self.names
    }

    pub fn members(&self) -> &MemberSet {
        &self.members
    }

    /// 运行时经数据面打开探测用的套接字（[`DataPlane::direct_probes`]、[`DataPlane::bind_tunnel`]）。
    pub fn dataplane_mut(&mut self) -> &mut D {
        &mut self.dataplane
    }

    /// 组网接口已经就绪（探测套接字可以绑定到组网地址上）。
    pub fn interface(&self) -> Option<&Interface> {
        self.interface.as_ref()
    }

    pub fn apply(&mut self, desired: &DesiredMesh, events: &mut impl EventSink) {
        if desired.node_id != self.node_id {
            events.emit(Event::ConfigRejected {
                reason: format!(
                    "desired state is for {}, this node is {}",
                    desired.node_id, self.node_id
                ),
            });
            return;
        }
        self.names = desired.names.clone();
        self.applied_at = Some(Instant::now());
        self.tls_relays = desired
            .tls_targets()
            .iter()
            .map(|t| (t.listen, t.connect))
            .collect();
        self.members.apply(desired, events);
        self.routes.apply(desired, self.members.members(), events);

        let Some(me) = self.members.get(&self.node_id) else {
            events.emit(Event::SelfNotAdmitted {
                node_id: self.node_id.clone(),
            });
            // 本机已被撤销：不再与任何对端通信
            if self.interface.is_some() {
                self.sync_peers(Vec::new(), events);
                self.sync_routes(Vec::new(), events);
            }
            self.prober = None;
            return;
        };

        let spec = interface_spec(me, desired);
        if self.interface.as_ref().map(|i| &i.spec) != Some(&spec) {
            match self.dataplane.ensure_interface(&spec, &self.private_key) {
                Ok(state) if state.public_key == me.mesh_public_key => {
                    if self.interface.as_ref().map(|i| i.listen_port) != Some(state.listen_port) {
                        events.emit(Event::InterfaceReady {
                            listen_port: state.listen_port,
                        });
                    }
                    self.interface = Some(Interface {
                        spec,
                        listen_port: state.listen_port,
                    });
                }
                Ok(state) => {
                    events.emit(Event::DataPlaneFailed {
                        reason: format!(
                            "interface public key {} does not match this node's admitted mesh key {}",
                            state.public_key, me.mesh_public_key
                        ),
                    });
                    return;
                }
                Err(e) => {
                    events.emit(Event::DataPlaneFailed {
                        reason: e.to_string(),
                    });
                    return;
                }
            }
        }

        let own_key = me.mesh_public_key;
        let edge = EdgeSpec::of(me);
        self.update_transport(desired, events);
        if !self.apply_access(desired, edge, events) {
            // 访问控制装不上：不与任何对端通信
            self.sync_peers(Vec::new(), events);
            return;
        }
        self.apply_ingress(events);

        self.reachability = desired.reachability;
        let trusted = self.clock_trusted;
        let prober = self.prober.get_or_insert_with(|| {
            let mut prober = Prober::new(&own_key);
            prober.set_clock_trusted(trusted);
            prober
        });
        prober.update(
            &self.node_id,
            desired.reachability,
            &self.private_key,
            self.members.members(),
            &desired.paths,
            desired.tls_endpoints(),
        );
        self.tls_endpoints = desired.tls_endpoints().values().copied().collect();
        let peers: Vec<PeerSpec> = self
            .members
            .members()
            .values()
            .filter(|m| m.node_id != self.node_id)
            .map(|m| {
                // 有选路状态的一方总是写入期望的 endpoint；经漫游跟随的一方只在新增对端时写入
                let endpoint = prober.desired_endpoint(&m.node_id).or_else(|| {
                    (!self.configured.contains(&m.mesh_public_key))
                        .then(|| prober.endpoint(&m.node_id))
                        .flatten()
                });
                peer_spec(
                    m,
                    self.routes.of(&m.node_id),
                    desired.reachability,
                    endpoint,
                )
            })
            .collect();
        self.sync_peers(peers, events);
        let others: Vec<IpPrefix> = self.routes.of_others(&self.node_id).collect();
        self.sync_routes(others, events);
        self.guard_idle_tls(events);
    }

    /// 本机宣告了网段时，安装智能入口的转发规则（design/mesh.md 第 10 节）。失败时下一份期望状态重试。
    fn apply_ingress(&mut self, events: &mut impl EventSink) {
        let ingress = IngressSpec::of(self.routes.of(&self.node_id), self.members.members());
        if self.ingress.as_ref() == Some(&ingress) {
            return;
        }
        match self.dataplane.apply_ingress(ingress.as_ref()) {
            Ok(()) => self.ingress = Some(ingress),
            Err(e) => {
                self.ingress = None;
                events.emit(Event::DataPlaneFailed {
                    reason: e.to_string(),
                });
            }
        }
    }

    /// 其他成员宣告的网段：在组网接口上加路由。失败时下一份期望状态重试。
    fn sync_routes(&mut self, routes: Vec<IpPrefix>, events: &mut impl EventSink) {
        if self.installed_routes.as_ref() == Some(&routes) {
            return;
        }
        match self.dataplane.sync_routes(&routes) {
            Ok(()) => self.installed_routes = Some(routes),
            Err(e) => {
                self.installed_routes = None;
                events.emit(Event::DataPlaneFailed {
                    reason: e.to_string(),
                });
            }
        }
    }

    /// 验证规则集，安装本机的过滤规则和 Edge 设置（design/mesh.md 第 12 节，ADR 0015）。规则无法展开或
    /// 安装失败时改装拒绝全部新建入方向连接的规则；连它也装不上、或 Edge 设置失败时返回 `false`，调用方
    /// 不添加任何对端。
    fn apply_access(
        &mut self,
        desired: &DesiredMesh,
        edge: Option<EdgeSpec>,
        events: &mut impl EventSink,
    ) -> bool {
        self.access.apply(desired, events);
        if self.edge.as_ref() != Some(&edge) {
            match self.dataplane.apply_edge(edge.as_ref()) {
                Ok(()) => self.edge = Some(edge),
                Err(e) => {
                    self.edge = None;
                    events.emit(Event::DataPlaneFailed {
                        reason: e.to_string(),
                    });
                    return false;
                }
            }
        }
        let filter = self
            .access
            .filter(&self.node_id, self.members.members())
            .unwrap_or_else(|e| {
                events.emit(Event::AccessRulesRejected {
                    reason: e.to_string(),
                });
                FilterSpec::deny_all()
            });
        if self.filter.as_ref() == Some(&filter) {
            return true;
        }
        match self.dataplane.apply_filter(&filter) {
            Ok(()) => {
                self.filter = Some(filter);
                return true;
            }
            Err(e) => events.emit(Event::DataPlaneFailed {
                reason: e.to_string(),
            }),
        }
        let deny = FilterSpec::deny_all();
        match self.dataplane.apply_filter(&deny) {
            Ok(()) => {
                self.filter = Some(deny);
                true
            }
            Err(e) => {
                self.filter = None;
                events.emit(Event::DataPlaneFailed {
                    reason: e.to_string(),
                });
                false
            }
        }
    }

    /// 传输适配进程的配置（design/mesh.md 第 5.3 节）：TLS 目标与 WireGuard 的实际端口，变化时交出。在配置
    /// 对端之前调用：WireGuard 发往回环端口的包到达时，传输适配进程已经在监听。
    fn update_transport(&mut self, desired: &DesiredMesh, events: &mut impl EventSink) {
        let Some(interface) = &self.interface else {
            return;
        };
        let config = desired.transport(interface.listen_port);
        if self.transport.as_ref() != Some(&config) {
            events.emit(Event::TransportConfigChanged {
                config: config.clone(),
            });
            self.transport = Some(config);
        }
    }

    /// 没有对端在用的 TLS 回环端口：丢弃从它们进入 WireGuard 端口的包（design/mesh.md 第 5.3 节）。
    /// 在执行切换之前调用：切到 TLS 的端口先放开，切走的端口再挡住。设置失败时下一次推进重试。
    fn guard_idle_tls(&mut self, events: &mut impl EventSink) {
        let (Some(prober), Some(interface)) = (self.prober.as_ref(), self.interface.as_ref())
        else {
            return;
        };
        let in_use: BTreeSet<SocketAddr> = prober
            .peer_ids()
            .filter_map(|(id, _)| prober.endpoint(id))
            .collect();
        let idle: Vec<u16> = self
            .tls_endpoints
            .difference(&in_use)
            .map(SocketAddr::port)
            .collect();
        if self.tls_guarded.as_ref() == Some(&idle)
            || (self.tls_guarded.is_none() && self.tls_endpoints.is_empty())
        {
            return;
        }
        match self.dataplane.guard_tls_ports(interface.listen_port, &idle) {
            Ok(()) => self.tls_guarded = Some(idle),
            Err(e) => {
                self.tls_guarded = None;
                events.emit(Event::DataPlaneFailed {
                    reason: e.to_string(),
                });
            }
        }
    }

    fn sync_peers(&mut self, peers: Vec<PeerSpec>, events: &mut impl EventSink) {
        match self.dataplane.sync_peers(&peers) {
            Ok(()) => {
                events.emit(Event::PeersApplied { peers: peers.len() });
                self.configured = peers.iter().map(|p| p.public_key).collect();
            }
            Err(e) => events.emit(Event::DataPlaneFailed {
                reason: e.to_string(),
            }),
        }
    }

    /// 有对端在高频探测刚因故障切走的更优路径（design/mesh.md 第 7 节），或在等待重新握手完成
    /// （第 8.4 节）：运行时要推进得比 [`crate::path::FAST_RECOVERY_INTERVAL`] 更密。
    pub fn needs_fine_ticks(&self, now: Instant) -> bool {
        self.prober
            .as_ref()
            .is_some_and(|p| p.needs_fine_ticks(now))
    }

    /// 本机时钟误差是否在 2 秒以内（design/mesh.md 第 8.4 节），由运行时定期更新。
    pub fn set_clock_trusted(&mut self, trusted: bool) {
        self.clock_trusted = trusted;
        if let Some(prober) = self.prober.as_mut() {
            prober.set_clock_trusted(trusted);
        }
    }

    /// 定期调用（约 100 毫秒一次）：读取对端状态、纠正 endpoint、推进选路，返回要发出的探测。
    pub fn tick(
        &mut self,
        now: Instant,
        now_ms: u64,
        events: &mut impl EventSink,
    ) -> Vec<Outgoing> {
        if self.interface.is_none() {
            return Vec::new();
        }
        // 重新握手的确认到期时也读一次：按刚读到的握手状态决定是否再握手
        let handshake_due = self.prober.as_ref().is_some_and(|p| p.handshake_due(now));
        if handshake_due
            || self
                .last_stats
                .is_none_or(|t| now.saturating_duration_since(t) >= STATS_INTERVAL)
        {
            self.last_stats = Some(now);
            self.check_peers(now, events);
        }
        let Some(prober) = self.prober.as_mut() else {
            return Vec::new();
        };
        let (out, switches) = prober.tick(now, now_ms);
        for event in prober.take_events() {
            events.emit(event);
        }
        self.guard_idle_tls(events);
        for switch in switches {
            let result = if switch.rehandshake {
                match self.members.get(&switch.peer) {
                    Some(member) => {
                        let spec = peer_spec(
                            member,
                            self.routes.of(&switch.peer),
                            self.reachability,
                            Some(switch.to.endpoint()),
                        );
                        let result = self.dataplane.rehandshake(&spec);
                        if result.is_ok() {
                            self.rehandshaked_at.insert(switch.public_key, now_ms);
                        }
                        result
                    }
                    None => continue,
                }
            } else {
                self.dataplane
                    .set_endpoint(&switch.public_key, switch.to.endpoint())
            };
            match result {
                Ok(()) => events.emit(Event::PathSwitched {
                    node_id: switch.peer,
                    to: route_label(&switch.to),
                    reason: switch.reason,
                    rehandshake: switch.rehandshake,
                }),
                Err(e) => events.emit(Event::DataPlaneFailed {
                    reason: e.to_string(),
                }),
            }
        }
        out
    }

    /// 读取各对端的流量与 endpoint：有流量的对端按第 7 节的频率探测；决定方发现 endpoint 被漫游
    /// 改掉就改回（第 8.3 节）。
    fn check_peers(&mut self, now: Instant, events: &mut impl EventSink) {
        let Some(prober) = self.prober.as_mut() else {
            return;
        };
        let stats = match self.dataplane.peer_stats() {
            Ok(stats) => stats,
            Err(e) => {
                events.emit(Event::DataPlaneFailed {
                    reason: e.to_string(),
                });
                return;
            }
        };
        let by_key: HashMap<X25519PublicKey, NodeId> = prober
            .peer_ids()
            .map(|(id, key)| (*key, id.clone()))
            .collect();
        self.rehandshaked_at
            .retain(|key, _| stats.iter().any(|s| s.public_key == *key));
        self.traffic
            .retain(|key, _| stats.iter().any(|s| s.public_key == *key));
        for stat in stats {
            let Some(id) = by_key.get(&stat.public_key) else {
                continue;
            };
            let bytes = (stat.rx_bytes, stat.tx_bytes);
            let before = self
                .traffic
                .get(&stat.public_key)
                .map(|t| (t.rx_bytes, t.tx_bytes));
            let traffic = self.traffic.entry(stat.public_key).or_default();
            if before.is_some_and(|(rx, _)| rx != stat.rx_bytes) {
                traffic.last_rx = Some(now);
            }
            if before.is_some_and(|(_, tx)| tx != stat.tx_bytes) {
                traffic.last_tx = Some(now);
            }
            traffic.rx_bytes = stat.rx_bytes;
            traffic.tx_bytes = stat.tx_bytes;
            traffic.endpoint = stat.endpoint;
            traffic.last_handshake = stat.last_handshake;
            if before != Some(bytes) {
                prober.mark_active(id, now);
            }
            if before.is_some_and(|(rx, _)| rx != stat.rx_bytes) {
                prober.on_receive(id, now);
            }
            if handshake_since(
                stat.last_handshake,
                self.rehandshaked_at.get(&stat.public_key).copied(),
            ) {
                prober.on_handshake(id);
            }
            let Some(want) = prober.desired_endpoint(id) else {
                continue;
            };
            if stat.endpoint != Some(want) {
                match self.dataplane.set_endpoint(&stat.public_key, want) {
                    Ok(()) => events.emit(Event::EndpointCorrected {
                        node_id: id.clone(),
                        from: stat.endpoint,
                        to: want,
                    }),
                    Err(e) => events.emit(Event::DataPlaneFailed {
                        reason: e.to_string(),
                    }),
                }
            }
        }
    }

    /// 本机状态的快照（design/status.md 第 6 节）。`now` 与 `wall` 是同一时刻。问题、最近的事件和切换的
    /// 时间与原因由 [`crate::status::Recorder::fill`] 填入。
    pub fn status(&self, now: Instant, wall: SystemTime, started_at: Timestamp) -> StatusDoc {
        let relays: HashMap<KeyId, &NodeId> = self
            .members
            .members()
            .keys()
            .map(|id| (KeyId::of(id.as_str().as_bytes()), id))
            .collect();
        let node_ref = |key: &KeyId| {
            relays.get(key).map(|id| NodeRef {
                id: (*id).clone(),
                name: self.names.get(*id).cloned(),
            })
        };
        let path_status = |route: Route, kind: PathKind, punched: bool| PathStatus {
            kind: kind_doc(kind),
            relay: match &route {
                Route::Relay { relay, .. } => node_ref(relay),
                Route::Direct(_) => None,
            },
            endpoint: Some(self.shown_endpoint(&route, kind)),
            punched,
            since: None,
            reason: None,
        };
        let me = self.members.get(&self.node_id);
        let node = NodeStatus {
            id: self.node_id.clone(),
            name: self.names.get(&self.node_id).cloned(),
            admitted: me.is_some(),
            mesh: me.map(mesh_addrs).unwrap_or_default(),
            edge: me.map(edge_addrs).unwrap_or_default(),
            routes: self.routes.of(&self.node_id).to_vec(),
            reachability: self.reachability,
            dataplane: self.dataplane.kind(),
            listen_port: self.interface.as_ref().map(|i| i.listen_port),
            nat: self
                .prober
                .as_ref()
                .filter(|_| self.reachability == Reachability::DialOnly)
                .map(|p| {
                    let own = p.own_nat(now);
                    NatStatus {
                        kind: match own.nat {
                            NatType::Cone => NatKind::Cone,
                            NatType::Symmetric => NatKind::Symmetric,
                            NatType::Unknown => NatKind::Unknown,
                        },
                        ipv4: own.v4.map(SocketAddr::V4),
                        ipv6: own.v6.map(SocketAddr::V6),
                    }
                }),
            clock_trusted: self.clock_trusted,
            started_at,
        };
        let recent = |t: Option<Instant>| {
            t.is_some_and(|t| now.saturating_duration_since(t) < ACTIVE_WINDOW)
        };
        let peers = self
            .members
            .members()
            .values()
            .filter(|m| m.node_id != self.node_id)
            .map(|m| {
                let view = self
                    .prober
                    .as_ref()
                    .and_then(|p| p.peer_view(&m.node_id, now));
                let traffic = self.traffic.get(&m.mesh_public_key);
                let last_rx = traffic.and_then(|t| t.last_rx);
                let ever_received = last_rx.is_some()
                    || traffic.is_some_and(|t| t.rx_bytes > 0 || t.last_handshake.is_some());
                let linked = view.as_ref().is_some_and(|v| v.linked);
                let state = if recent(last_rx) {
                    PeerState::Connected
                } else if !linked {
                    PeerState::NoPath
                } else if recent(traffic.and_then(|t| t.last_tx)) {
                    if ever_received {
                        PeerState::Unreachable
                    } else {
                        PeerState::Connecting
                    }
                } else {
                    PeerState::Idle
                };
                let role = linked.then(|| match view.as_ref().and_then(|v| v.role) {
                    Some(Role::Decide | Role::DecideTogether) => PeerRole::Decider,
                    Some(Role::FollowTogether) | None => PeerRole::Follower,
                });
                let candidates = view.as_ref().map(|v| &v.candidates[..]).unwrap_or_default();
                let path = match candidates
                    .iter()
                    .find(|c| c.state == CandidateState::Current)
                {
                    Some(c) => Some(path_status(c.route, c.kind, c.punched)),
                    // 经漫游跟随：WireGuard 当前的 endpoint 是本机候选中的哪一条，不在其中时是直连
                    None => traffic.and_then(|t| t.endpoint).map(|endpoint| {
                        let (route, kind) = view
                            .as_ref()
                            .and_then(|v| v.routes.iter().find(|(r, _)| r.endpoint() == endpoint))
                            .copied()
                            .unwrap_or((Route::Direct(endpoint), PathKind::Direct));
                        path_status(route, kind, false)
                    }),
                };
                let tunnel = view.as_ref().and_then(|v| v.tunnel);
                PeerStatus {
                    id: m.node_id.clone(),
                    name: self.names.get(&m.node_id).cloned(),
                    mesh: mesh_addrs(m),
                    edge: edge_addrs(m),
                    routes: self.routes.of(&m.node_id).to_vec(),
                    state,
                    role,
                    path,
                    rtt_ms: tunnel.and_then(|t| t.rtt_ms),
                    loss: tunnel.and_then(|t| t.loss),
                    jitter_ms: tunnel.and_then(|t| t.rtt_ms.map(|_| t.jitter_ms)),
                    last_handshake: traffic
                        .and_then(|t| t.last_handshake)
                        .map(status::timestamp),
                    last_received: last_rx.map(|t| status::wall_time(now, wall, t)),
                    rx_bytes: traffic.map_or(0, |t| t.rx_bytes),
                    tx_bytes: traffic.map_or(0, |t| t.tx_bytes),
                    candidates: candidates
                        .iter()
                        .map(|c| CandidateStatus {
                            kind: kind_doc(c.kind),
                            relay: match &c.route {
                                Route::Relay { relay, .. } => node_ref(relay),
                                Route::Direct(_) => None,
                            },
                            endpoint: self.shown_endpoint(&c.route, c.kind),
                            punched: c.punched,
                            rtt_ms: c.rtt_ms,
                            loss: c.loss,
                            state: match c.state {
                                CandidateState::Current => CandidateStateDoc::Current,
                                CandidateState::Ok => CandidateStateDoc::Ok,
                                CandidateState::Failing => CandidateStateDoc::Failing,
                                CandidateState::Untested => CandidateStateDoc::Untested,
                            },
                        })
                        .collect(),
                }
            })
            .collect();
        StatusDoc {
            v: status::VERSION,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            node,
            config: ConfigStatus {
                applied_at: self.applied_at.map(|t| status::wall_time(now, wall, t)),
                access_rules_version: self.access.version(),
            },
            peers,
            problems: Vec::new(),
            events: Vec::new(),
        }
    }

    /// 本机状态中显示的地址：TLS 中继显示它的 TLS 地址，而不是传输适配进程的回环端口。
    fn shown_endpoint(&self, route: &Route, kind: PathKind) -> SocketAddr {
        let endpoint = route.endpoint();
        match kind {
            PathKind::RelayTls => self.tls_relays.get(&endpoint).copied().unwrap_or(endpoint),
            _ => endpoint,
        }
    }

    /// 处理收到的探测消息，返回要发出的应答。
    pub fn on_packet(
        &mut self,
        kind: Incoming,
        from: SocketAddr,
        data: &[u8],
        at: Instant,
        now_ms: u64,
    ) -> Vec<Outgoing> {
        match self.prober.as_mut() {
            Some(prober) => prober.on_packet(kind, from, data, at, now_ms),
            None => Vec::new(),
        }
    }
}

fn kind_doc(kind: PathKind) -> PathKindDoc {
    match kind {
        PathKind::Lan => PathKindDoc::Lan,
        PathKind::Direct => PathKindDoc::Direct,
        PathKind::Relay => PathKindDoc::Relay,
        PathKind::RelayTls => PathKindDoc::RelayTls,
    }
}

fn mesh_addrs(m: &Member) -> Vec<IpAddr> {
    vec![IpAddr::V4(m.addresses.ipv4), IpAddr::V6(m.addresses.ipv6)]
}

fn edge_addrs(m: &Member) -> Vec<IpAddr> {
    m.edge
        .iter()
        .flat_map(|e| [IpAddr::V4(e.addresses.ipv4), IpAddr::V6(e.addresses.ipv6)])
        .collect()
}

fn route_label(route: &Route) -> String {
    match route {
        Route::Direct(e) => format!("direct {e}"),
        Route::Relay { endpoint, .. } => format!("relay {endpoint}"),
    }
}

fn interface_spec(me: &Member, desired: &DesiredMesh) -> InterfaceSpec {
    InterfaceSpec {
        name: INTERFACE_NAME.to_owned(),
        listen_port: desired.listen_port,
        mtu: MESH_MTU,
        addresses: vec![
            InterfaceAddress {
                addr: IpAddr::V4(me.addresses.ipv4),
                prefix_len: desired.prefixes.ipv4.prefix_len(),
            },
            InterfaceAddress {
                addr: IpAddr::V6(me.addresses.ipv6),
                prefix_len: desired.prefixes.ipv6.prefix_len(),
            },
        ],
    }
}

/// 最近一次重新握手（`rehandshaked_ms`，Unix 毫秒）之后完成过握手。没有重新握手过就无从确认；
/// 早于重新握手的握手时间是旧对端的（决定与执行之间读到的状态）。
fn handshake_since(last_handshake: Option<SystemTime>, rehandshaked_ms: Option<u64>) -> bool {
    let done_ms = last_handshake.map(|t| {
        t.duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    });
    matches!((done_ms, rehandshaked_ms), (Some(done), Some(at)) if done >= at)
}

fn peer_spec(
    member: &Member,
    routes: &[IpPrefix],
    own: Reachability,
    endpoint: Option<SocketAddr>,
) -> PeerSpec {
    // 组网地址，有 `edge` 角色时的 Edge 专用地址，以及它宣告的网段（design/mesh.md 第 4 节）
    let edge = member.edge.iter().map(|e| e.addresses);
    PeerSpec {
        public_key: member.mesh_public_key,
        allowed_ips: std::iter::once(member.addresses)
            .chain(edge)
            .flat_map(|a| [IpAddr::V4(a.ipv4), IpAddr::V6(a.ipv6)])
            .map(IpPrefix::host)
            .chain(routes.iter().copied())
            .collect(),
        endpoint,
        persistent_keepalive: (own == Reachability::DialOnly).then_some(DIAL_ONLY_KEEPALIVE_SECS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::VecSink;
    use crate::testutil::{FAKE_AUTO_PORT, FakeDataPlane, Mesh, mesh_key, node_id, validated};
    use nett_trust::revocation::Revocation;

    fn engine(me: u8) -> Engine<FakeDataPlane> {
        Engine::new(
            node_id(me),
            PrivateKey::from_bytes([me; 32]),
            FakeDataPlane::new(mesh_key(me)),
        )
    }

    fn peer_keys(e: &Engine<FakeDataPlane>) -> Vec<u8> {
        e.dataplane
            .peers
            .as_ref()
            .expect("peers applied")
            .iter()
            .map(|p| p.public_key.as_bytes()[0])
            .collect()
    }

    fn rejected(events: &VecSink) -> Vec<Option<NodeId>> {
        events
            .0
            .iter()
            .filter_map(|e| match e {
                Event::MemberRejected { node_id, .. } => Some(node_id.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn configures_interface_and_admitted_peers() {
        let mesh = Mesh::new(&[1, 2, 3]);
        let mut e = engine(1);
        let mut events = VecSink::default();
        let doc = mesh.desired(
            1,
            vec![
                mesh.material(1, 1),
                mesh.material(2, 1),
                mesh.material(3, 1),
            ],
        );
        e.apply(&validated(doc), &mut events);

        let iface = &e.dataplane.interfaces[0];
        assert_eq!(iface.name, "nett0");
        assert_eq!(iface.mtu, 1280);
        assert_eq!(iface.addresses[0].addr.to_string(), "100.88.0.1");
        assert_eq!(iface.addresses[0].prefix_len, 16);
        assert_eq!(iface.addresses[1].prefix_len, 48);

        let peers = e.dataplane.peers.as_ref().expect("peers");
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].public_key, mesh_key(2));
        assert_eq!(
            peers[0].endpoint,
            Some("192.0.2.2:41820".parse().expect("addr"))
        );
        assert_eq!(
            peers[0]
                .allowed_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["100.88.0.2/32", "fd00:88::2/128"]
        );
        assert_eq!(
            peers[0].persistent_keepalive,
            Some(DIAL_ONLY_KEEPALIVE_SECS)
        );
        assert!(events.0.contains(&Event::PeersApplied { peers: 2 }));
    }

    #[test]
    fn without_a_port_the_assigned_one_is_reported_and_handed_to_the_transport() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        let mut doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        doc.listen_port = None;
        let mut events = VecSink::default();
        e.apply(&validated(doc.clone()), &mut events);
        assert_eq!(e.dataplane.interfaces[0].listen_port, None);
        assert_eq!(e.interface().map(|i| i.listen_port), Some(FAKE_AUTO_PORT));
        assert!(events.0.contains(&Event::InterfaceReady {
            listen_port: FAKE_AUTO_PORT
        }));
        // 传输适配进程拿到的是实际的端口，而且在配置对端之前
        let at = |pred: &dyn Fn(&Event) -> bool| events.0.iter().position(pred);
        let transport = at(
            &|e| matches!(e, Event::TransportConfigChanged { config } if config.wireguard_port == FAKE_AUTO_PORT),
        );
        let peers = at(&|e| matches!(e, Event::PeersApplied { .. }));
        assert!(transport.expect("transport config") < peers.expect("peers"));
        // 没有变化时不再报告
        let mut again = VecSink::default();
        e.apply(&validated(doc), &mut again);
        assert!(!again.0.iter().any(|e| matches!(
            e,
            Event::InterfaceReady { .. } | Event::TransportConfigChanged { .. }
        )));
    }

    #[test]
    fn access_rules_are_installed_before_peers() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        let doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        e.apply(&validated(doc.clone()), &mut VecSink::default());
        assert_eq!(
            e.dataplane.calls,
            [
                "apply_edge",
                "apply_filter",
                "apply_ingress",
                "sync_peers",
                "sync_routes"
            ]
        );
        // 成员 2 发往本机隧道内探测端口的包放行（IPv4、IPv6），没有别的规则
        assert_eq!(e.dataplane.filter.as_ref().map(|f| f.rules.len()), Some(2));
        assert_eq!(e.dataplane.edge, None);
        // 没有变化时不重装
        e.apply(&validated(doc), &mut VecSink::default());
        assert_eq!(
            e.dataplane.calls,
            [
                "apply_edge",
                "apply_filter",
                "apply_ingress",
                "sync_peers",
                "sync_routes",
                "sync_peers"
            ]
        );
    }

    #[test]
    fn failed_filter_falls_back_to_denying_new_inbound_connections() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        e.dataplane.fail_filter = Some(false);
        let mut events = VecSink::default();
        let doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        e.apply(&validated(doc), &mut events);
        assert_eq!(e.dataplane.filter, Some(FilterSpec::deny_all()));
        assert_eq!(peer_keys(&e), [2]);
        assert!(
            events
                .0
                .iter()
                .any(|ev| matches!(ev, Event::DataPlaneFailed { .. }))
        );
    }

    #[test]
    fn no_peers_when_no_filter_can_be_installed() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        e.dataplane.fail_filter = Some(true);
        let doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        e.apply(&validated(doc), &mut VecSink::default());
        assert_eq!(e.dataplane.filter, None);
        assert_eq!(e.dataplane.peers, Some(vec![]));
    }

    #[test]
    fn edge_addresses_are_routed_to_the_edge_node_and_rewritten_there() {
        let mesh = Mesh::new(&[1, 2]);
        let members = vec![mesh.edge_material(1, 1), mesh.material(2, 1)];
        let mut edge_node = engine(1);
        edge_node.apply(
            &validated(mesh.desired(1, members.clone())),
            &mut VecSink::default(),
        );
        let edge = edge_node.dataplane.edge.as_ref().expect("edge rules");
        assert_eq!(edge.addresses.ipv4.to_string(), "100.88.1.1");
        assert_eq!(edge.containers[0].to_string(), "172.17.0.0/16");

        let mut other = engine(2);
        other.apply(
            &validated(mesh.desired(2, members)),
            &mut VecSink::default(),
        );
        assert_eq!(other.dataplane.edge, None);
        let peers = other.dataplane.peers.as_ref().expect("peers");
        assert_eq!(
            peers[0]
                .allowed_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            [
                "100.88.0.1/32",
                "fd00:88::1/128",
                "100.88.1.1/32",
                "fd00:88::1:1/128"
            ]
        );
        // 来源是 Edge 专用地址、又没有规则放行时拒绝：只有隧道内探测放行，而它们的来源是组网地址
        let edge_source: IpPrefix = "100.88.1.1/32".parse().expect("prefix");
        let filter = other.dataplane.filter.as_ref().expect("filter");
        assert!(!filter.rules.iter().any(|r| {
            r.accept
                && r.matches
                    .iter()
                    .any(|m| matches!(m, crate::access::Match::Source(s) if s.covers(&edge_source)))
        }));
    }

    #[test]
    fn advertised_routes_reach_peers_routes_filter_and_forwarding() {
        let mesh = Mesh::new(&[1, 2, 3]);
        let members = vec![
            mesh.edge_material(1, 1),
            mesh.router_material(2, 1),
            mesh.material(3, 1),
        ];
        let with_routes = |me: u8| {
            let mut d = mesh.desired(me, members.clone());
            d.advertised_routes = vec![mesh.sign(&mesh.routes_doc(2, 1, &["192.0.2.10/32"]))];
            validated(d)
        };
        let route: IpPrefix = "192.0.2.10/32".parse().expect("prefix");
        // 其他成员：对端的 AllowedIPs 和组网接口上的路由都有这个网段
        let mut edge = engine(1);
        edge.apply(&with_routes(1), &mut VecSink::default());
        let peer2 = edge
            .dataplane
            .peers
            .as_ref()
            .and_then(|p| p.iter().find(|p| p.public_key == mesh_key(2)).cloned())
            .expect("peer 2");
        assert!(peer2.allowed_ips.contains(&route));
        assert_eq!(edge.dataplane.routes, [route]);
        assert_eq!(edge.dataplane.ingress, None);

        // 智能入口本身：转发 Edge 的流量，宣告的网段没有规则时拒绝，自己的网段不加路由
        let mut router = engine(2);
        router.apply(&with_routes(2), &mut VecSink::default());
        let ingress = router.dataplane.ingress.as_ref().expect("ingress");
        assert!(
            ingress
                .edge_sources
                .contains(&"100.88.1.1".parse().expect("ip"))
        );
        assert!(router.dataplane.routes.is_empty());
        let filter = router.dataplane.filter.as_ref().expect("filter");
        assert!(!filter.rules.iter().any(|r| {
            r.accept
                && r.matches
                    .iter()
                    .any(|m| matches!(m, crate::access::Match::Destination(d) if d.covers(&route)))
        }));
    }

    #[test]
    fn unchanged_state_does_not_touch_the_interface_again() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        let doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        e.apply(&validated(doc.clone()), &mut VecSink::default());
        e.apply(&validated(doc), &mut VecSink::default());
        assert_eq!(e.dataplane.interfaces.len(), 1);
    }

    #[test]
    fn invalid_members_are_not_configured() {
        let mesh = Mesh::new(&[1, 2, 3, 4, 5]);
        let mut e = engine(1);
        let mut events = VecSink::default();

        // 3：准入证明中的组网公钥与签名不符；4：地址在组网网段之外；5：节点策略没有 mesh 模块
        let mut bad_proof = mesh.material(3, 1);
        bad_proof.proof.signature[0] ^= 1;
        let mut outside = mesh.policy(4, 1);
        outside.addresses.mesh.ipv4 = "100.99.0.4".parse().expect("ipv4");
        let mut no_mesh = mesh.policy(5, 1);
        no_mesh.modules.clear();
        let members = vec![
            mesh.material(1, 1),
            mesh.material(2, 1),
            bad_proof,
            mesh.material_for(outside, mesh_key(4)),
            mesh.material_for(no_mesh, mesh_key(5)),
        ];
        e.apply(&validated(mesh.desired(1, members)), &mut events);

        assert_eq!(peer_keys(&e), [2]);
        assert_eq!(
            rejected(&events),
            [Some(node_id(3)), Some(node_id(5)), Some(node_id(4))]
        );
    }

    #[test]
    fn revocation_is_permanent_and_absence_is_not_revocation() {
        let mesh = Mesh::new(&[1, 2, 3]);
        let mut e = engine(1);
        let all = vec![
            mesh.material(1, 1),
            mesh.material(2, 1),
            mesh.material(3, 1),
        ];
        e.apply(&validated(mesh.desired(1, all)), &mut VecSink::default());
        assert_eq!(peer_keys(&e), [2, 3]);

        // 快照中缺少 3：不删除
        let without_3 = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        e.apply(&validated(without_3), &mut VecSink::default());
        assert_eq!(peer_keys(&e), [2, 3]);

        // 撤销 3：删除；之后更高版本的签名材料也不能恢复
        let mut revoke = mesh.desired(1, vec![]);
        revoke.revocations = vec![Revocation::Node {
            node_id: node_id(3),
        }];
        let mut events = VecSink::default();
        e.apply(&validated(revoke), &mut events);
        assert!(events.0.contains(&Event::MemberRemoved {
            node_id: node_id(3)
        }));
        assert_eq!(peer_keys(&e), [2]);

        let mut events = VecSink::default();
        e.apply(
            &validated(mesh.desired(1, vec![mesh.material(3, 9)])),
            &mut events,
        );
        assert_eq!(peer_keys(&e), [2]);
        assert_eq!(rejected(&events), [Some(node_id(3))]);
    }

    #[test]
    fn versions_only_move_forward() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        e.apply(
            &validated(mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 2)])),
            &mut VecSink::default(),
        );
        let mut older = mesh.policy(2, 1);
        older.addresses.mesh.ipv4 = "100.88.0.42".parse().expect("ipv4");
        let mut events = VecSink::default();
        e.apply(
            &validated(mesh.desired(1, vec![mesh.material_for(older, mesh_key(2))])),
            &mut events,
        );
        assert_eq!(rejected(&events), [Some(node_id(2))]);
        let peers = e.dataplane.peers.as_ref().expect("peers");
        assert_eq!(peers[0].allowed_ips[0].to_string(), "100.88.0.2/32");

        // 同一份期望状态中带着同一节点的两个版本：采用高的，低的被拒绝
        let mut e = engine(1);
        let mut events = VecSink::default();
        let both = vec![
            mesh.material(1, 1),
            mesh.material(2, 1),
            mesh.material(2, 3),
        ];
        e.apply(&validated(mesh.desired(1, both)), &mut events);
        assert_eq!(
            e.members().get(&node_id(2)).map(|m| m.policy_version),
            Some(3)
        );
        assert_eq!(rejected(&events), [Some(node_id(2))]);
    }

    #[test]
    fn conflicting_addresses_and_keys_keep_the_existing_member() {
        let mesh = Mesh::new(&[1, 2, 3, 4]);
        let mut e = engine(1);
        let mut same_addr = mesh.policy(3, 1);
        same_addr.addresses.mesh.ipv6 = "fd00:88::2".parse().expect("ipv6");
        let members = vec![
            mesh.material(1, 1),
            mesh.material(2, 1),
            mesh.material_for(same_addr, mesh_key(3)),
            mesh.material_for(mesh.policy(4, 1), mesh_key(2)),
        ];
        let mut events = VecSink::default();
        e.apply(&validated(mesh.desired(1, members)), &mut events);
        assert_eq!(peer_keys(&e), [2]);
        assert_eq!(rejected(&events), [Some(node_id(3)), Some(node_id(4))]);
    }

    #[test]
    fn interface_key_must_match_own_admission() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = Engine::new(
            node_id(1),
            PrivateKey::from_bytes([1; 32]),
            FakeDataPlane::new(mesh_key(9)),
        );
        let mut events = VecSink::default();
        e.apply(
            &validated(mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)])),
            &mut events,
        );
        assert!(e.dataplane.peers.is_none());
        assert!(matches!(
            events.0.last(),
            Some(Event::DataPlaneFailed { .. })
        ));
    }

    #[test]
    fn self_revoked_clears_peers() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        e.apply(
            &validated(mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)])),
            &mut VecSink::default(),
        );
        let mut revoke = mesh.desired(1, vec![]);
        revoke.revocations = vec![Revocation::Node {
            node_id: node_id(1),
        }];
        let mut events = VecSink::default();
        e.apply(&validated(revoke), &mut events);
        assert!(events.0.contains(&Event::SelfNotAdmitted {
            node_id: node_id(1)
        }));
        assert_eq!(peer_keys(&e), Vec::<u8>::new());
    }

    #[test]
    fn rejects_state_for_another_node() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        let mut events = VecSink::default();
        e.apply(&validated(mesh.desired(2, vec![])), &mut events);
        assert!(matches!(events.0[..], [Event::ConfigRejected { .. }]));
        assert!(e.dataplane.interfaces.is_empty());
    }

    #[test]
    fn only_a_handshake_after_the_rehandshake_confirms_it() {
        let at = |ms: u64| Some(UNIX_EPOCH + Duration::from_millis(ms));
        // 重新加入之后还没有握手
        assert!(!handshake_since(None, Some(1_000)));
        // 决定之后、执行之前读到的旧对端的握手
        assert!(!handshake_since(at(900), Some(1_000)));
        assert!(!handshake_since(at(900), None));
        assert!(handshake_since(at(1_000), Some(1_000)));
        assert!(handshake_since(at(1_030), Some(1_000)));
    }

    #[test]
    fn guards_tls_ports_nobody_uses() {
        use crate::config::{Candidate, PathDoc, ProbeToken};
        use nett_core::transport::CertFingerprint;
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        let mut events = VecSink::default();
        let mut doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        let tls = Candidate::RelayTls {
            relay: node_id(9),
            address: "198.51.100.9:443".parse().expect("addr"),
            fingerprint: CertFingerprint([1; 32]),
            token: ProbeToken([9; 32]),
        };
        let direct = Candidate::Direct {
            endpoint: "192.0.2.2:41820".parse().expect("addr"),
        };
        // 当前路径是直连：TLS 端口闲置，挡住
        doc.paths = vec![PathDoc {
            peer: node_id(2),
            peer_reachability: Reachability::Public,
            candidates: vec![direct.clone(), tls.clone()],
        }];
        e.apply(&validated(doc.clone()), &mut events);
        assert_eq!(
            e.dataplane.tls_guards,
            vec![vec![crate::config::TLS_LOOPBACK_BASE]]
        );
        // 只剩 TLS 候选：它就是当前路径，放开
        doc.paths[0].candidates = vec![tls];
        e.apply(&validated(doc.clone()), &mut events);
        assert_eq!(e.dataplane.tls_guards.last(), Some(&vec![]));
        // 没有 TLS 候选的节点不设置
        let mut plain = engine(1);
        doc.paths[0].candidates = vec![direct];
        plain.apply(&validated(doc), &mut events);
        assert!(plain.dataplane.tls_guards.is_empty());
    }

    /// 本机状态的快照（design/status.md 第 6 节）：节点名、对端状态随流量变化、TLS 中继显示真实地址、
    /// 回复中没有私钥与探测令牌。
    #[test]
    fn status_reports_peers_paths_and_no_secrets() {
        use crate::config::{Candidate, PathDoc, ProbeToken};
        use crate::status::{PathKindDoc, PeerRole, PeerState};
        use base64::Engine as _;
        use nett_core::transport::CertFingerprint;

        let mesh = Mesh::new(&[1, 2, 3, 4]);
        let mut e = engine(1);
        let mut events = VecSink::default();
        let mut doc = mesh.desired(1, (1..=4).map(|n| mesh.material(n, 1)).collect());
        let token = ProbeToken([9; 32]);
        doc.paths = vec![
            PathDoc {
                peer: node_id(2),
                peer_reachability: Reachability::Public,
                candidates: vec![
                    Candidate::RelayTls {
                        relay: node_id(3),
                        address: "198.51.100.3:443".parse().expect("addr"),
                        fingerprint: CertFingerprint([1; 32]),
                        token: token.clone(),
                    },
                    Candidate::Direct {
                        endpoint: "192.0.2.2:41820".parse().expect("addr"),
                    },
                ],
            },
            PathDoc {
                peer: node_id(3),
                peer_reachability: Reachability::Public,
                candidates: vec![Candidate::Direct {
                    endpoint: "192.0.2.3:41820".parse().expect("addr"),
                }],
            },
        ];
        // 节点 4 没有路径
        e.apply(&validated(doc), &mut events);
        let t0 = Instant::now();
        let wall = SystemTime::now();
        e.tick(t0, 0, &mut events);

        let st = e.status(t0, wall, Timestamp::now());
        assert_eq!(st.node.name.as_ref().map(NodeName::as_str), Some("node-1"));
        assert!(st.node.admitted);
        assert_eq!(st.node.mesh[0].to_string(), "100.88.0.1");
        assert_eq!(st.node.listen_port, Some(41820));
        let peer = |st: &StatusDoc, n: u8| {
            st.peers
                .iter()
                .find(|p| p.id == node_id(n))
                .cloned()
                .expect("peer")
        };
        assert_eq!(st.peers.len(), 3);
        // 还没有流量：有路径的对端无从判断，没有路径的写明
        assert_eq!(peer(&st, 2).state, PeerState::Idle);
        assert_eq!(peer(&st, 4).state, PeerState::NoPath);
        assert_eq!(peer(&st, 4).role, None);
        // 本机是 dial-only：对 public 对端决定路径；TLS 中继显示它的 TLS 地址和名字
        let p2 = peer(&st, 2);
        assert_eq!(p2.role, Some(PeerRole::Decider));
        let path = p2.path.expect("path");
        assert_eq!(path.kind, PathKindDoc::RelayTls);
        assert_eq!(
            path.endpoint,
            Some("198.51.100.3:443".parse().expect("addr"))
        );
        assert_eq!(
            path.relay.and_then(|r| r.name).map(|n| n.to_string()),
            Some("node-3".to_owned())
        );
        assert_eq!(p2.candidates.len(), 2);

        // 两个方向都有包：连通；只发不收、从未收到过：正在连接
        e.dataplane.traffic.insert(mesh_key(2), (100, 100));
        e.dataplane.traffic.insert(mesh_key(3), (0, 100));
        let t1 = t0 + Duration::from_secs(1);
        e.tick(t1, 1_000, &mut events);
        let st = e.status(t1, wall, Timestamp::now());
        assert_eq!(peer(&st, 2).state, PeerState::Connected);
        assert_eq!(peer(&st, 2).rx_bytes, 100);
        assert_eq!(peer(&st, 3).state, PeerState::Connecting);

        // 之后只发不收超过 30 秒：不通
        let t2 = t1 + Duration::from_secs(31);
        e.dataplane.traffic.insert(mesh_key(2), (100, 200));
        e.tick(t2, 32_000, &mut events);
        assert_eq!(
            e.status(t2, wall, Timestamp::now()).peers[0].state,
            PeerState::Unreachable
        );
        // 两个方向都没有包超过 30 秒：空闲
        let t3 = t2 + Duration::from_secs(31);
        e.tick(t3, 63_000, &mut events);
        assert_eq!(
            peer(&e.status(t3, wall, Timestamp::now()), 2).state,
            PeerState::Idle
        );

        let json = serde_json::to_string(&e.status(t3, wall, Timestamp::now())).expect("json");
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        for secret in [b64.encode([9u8; 32]), b64.encode([1u8; 32])] {
            assert!(!json.contains(&secret), "status leaks {secret}");
        }
    }

    /// 本机是 public、对端是 dial-only：本机跟随，路径按 WireGuard 当前的 endpoint 判断，没有测量。
    #[test]
    fn a_follower_reports_the_endpoint_without_measurements() {
        use crate::config::PathDoc;
        use crate::status::{PathKindDoc, PeerRole};
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        let mut events = VecSink::default();
        let mut doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        doc.reachability = Reachability::Public;
        doc.paths = vec![PathDoc {
            peer: node_id(2),
            peer_reachability: Reachability::DialOnly,
            candidates: vec![],
        }];
        e.apply(&validated(doc), &mut events);
        // 对端连进来以后，WireGuard 记下它的地址
        let roamed: SocketAddr = "203.0.113.7:53557".parse().expect("addr");
        e.dataplane.peers.as_mut().expect("peers")[0].endpoint = Some(roamed);
        let now = Instant::now();
        e.tick(now, 0, &mut events);
        let st = e.status(now, SystemTime::now(), Timestamp::now());
        let p = &st.peers[0];
        assert_eq!(p.role, Some(PeerRole::Follower));
        assert_eq!(p.rtt_ms, None);
        assert!(p.candidates.is_empty());
        let path = p.path.as_ref().expect("path");
        assert_eq!(
            (path.kind, path.endpoint),
            (PathKindDoc::Direct, Some(roamed))
        );
        assert!(st.node.nat.is_none());
    }
}
