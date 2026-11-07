//! 把已准入的成员落到数据面：本机的组网接口，以及每个其他成员一个 WireGuard 对端；按选路的结果
//! 切换对端的 endpoint，并纠正被 WireGuard 漫游改掉的 endpoint（design/mesh.md 第 4、8 节）。
//!
//! 数据面操作失败时保持现状，在下一份期望状态或下一次检查时重试（"拿不准时，连接保持现状"）。

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nett_core::id::NodeId;
use nett_trust::admission::Member;
use nett_trust::keys::X25519PublicKey;

use crate::config::{DesiredMesh, Reachability};
use crate::dataplane::{
    DataPlane, INTERFACE_NAME, InterfaceAddress, InterfaceSpec, MESH_MTU, PeerSpec,
};
use crate::event::{Event, EventSink};
use crate::key::PrivateKey;
use crate::members::MemberSet;
use crate::path::Route;
use crate::prefix::IpPrefix;
use crate::prober::{Incoming, Outgoing, Prober};

/// `dial-only` 成员对每个对端的持久保活间隔（秒），维持 NAT 映射（design/mesh.md 第 4 节）。
pub const DIAL_ONLY_KEEPALIVE_SECS: u16 = 25;
/// 读取各对端状态（流量、endpoint）的间隔：endpoint 被漫游改掉后在这个时间内纠正（第 8.3 节）。
const STATS_INTERVAL: Duration = Duration::from_millis(100);

pub struct Engine<D> {
    node_id: NodeId,
    private_key: PrivateKey,
    dataplane: D,
    members: MemberSet,
    /// 最近一次成功应用的接口配置。
    interface: Option<InterfaceSpec>,
    reachability: Reachability,
    prober: Option<Prober>,
    /// 已经配置到数据面的对端：经漫游跟随的一方只在新增对端时设置 endpoint，之后交给 WireGuard 的漫游。
    configured: HashSet<X25519PublicKey>,
    bytes: HashMap<X25519PublicKey, (u64, u64)>,
    /// 最近一次重新握手执行的时刻（Unix 毫秒）：WireGuard 报告的握手时间不早于它，才是这次握手完成
    /// （第 8.4 节）。决定与执行之间读到的仍是旧对端的握手时间。
    rehandshaked_at: HashMap<X25519PublicKey, u64>,
    last_stats: Option<Instant>,
    clock_trusted: bool,
    /// TLS 中继在传输适配进程上的回环端点，以及最近一次设置的闲置端口（design/mesh.md 第 5.3 节）。
    tls_endpoints: BTreeSet<SocketAddr>,
    tls_guarded: Option<Vec<u16>>,
}

impl<D: DataPlane> Engine<D> {
    pub fn new(node_id: NodeId, private_key: PrivateKey, dataplane: D) -> Self {
        Self {
            node_id,
            private_key,
            dataplane,
            members: MemberSet::default(),
            interface: None,
            reachability: Reachability::Public,
            prober: None,
            configured: HashSet::new(),
            bytes: HashMap::new(),
            rehandshaked_at: HashMap::new(),
            last_stats: None,
            clock_trusted: false,
            tls_endpoints: BTreeSet::new(),
            tls_guarded: None,
        }
    }

    pub fn members(&self) -> &MemberSet {
        &self.members
    }

    /// 组网接口已经就绪（探测套接字可以绑定到组网地址上）。
    pub fn interface(&self) -> Option<&InterfaceSpec> {
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
        self.members.apply(desired, events);

        let Some(me) = self.members.get(&self.node_id) else {
            events.emit(Event::SelfNotAdmitted {
                node_id: self.node_id.clone(),
            });
            // 本机已被撤销：不再与任何对端通信
            if self.interface.is_some() {
                self.sync_peers(Vec::new(), events);
            }
            self.prober = None;
            return;
        };

        let spec = interface_spec(me, desired);
        if self.interface.as_ref() != Some(&spec) {
            match self.dataplane.ensure_interface(&spec, &self.private_key) {
                Ok(public_key) if public_key == me.mesh_public_key => self.interface = Some(spec),
                Ok(public_key) => {
                    events.emit(Event::DataPlaneFailed {
                        reason: format!(
                            "interface public key {public_key} does not match this node's admitted mesh key {}",
                            me.mesh_public_key
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

        self.reachability = desired.reachability;
        let own_key = me.mesh_public_key;
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
                peer_spec(m, desired.reachability, endpoint)
            })
            .collect();
        self.sync_peers(peers, events);
        self.guard_idle_tls(events);
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
                        let spec = peer_spec(member, self.reachability, Some(switch.to.endpoint()));
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
        for stat in stats {
            let Some(id) = by_key.get(&stat.public_key) else {
                continue;
            };
            let bytes = (stat.rx_bytes, stat.tx_bytes);
            if self.bytes.insert(stat.public_key, bytes) != Some(bytes) {
                prober.mark_active(id, now);
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

fn peer_spec(member: &Member, own: Reachability, endpoint: Option<SocketAddr>) -> PeerSpec {
    PeerSpec {
        public_key: member.mesh_public_key,
        allowed_ips: vec![
            IpPrefix::host(IpAddr::V4(member.addresses.ipv4)),
            IpPrefix::host(IpAddr::V6(member.addresses.ipv6)),
        ],
        endpoint,
        persistent_keepalive: (own == Reachability::DialOnly).then_some(DIAL_ONLY_KEEPALIVE_SECS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::VecSink;
    use crate::testutil::{FakeDataPlane, Mesh, mesh_key, node_id, validated};
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
}
