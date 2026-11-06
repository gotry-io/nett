//! 把已准入的成员落到数据面：本机的组网接口，以及每个其他成员一个 WireGuard 对端。
//!
//! 数据面操作失败时保持现状，在下一份期望状态到来时重试（"拿不准时，连接保持现状"）。

use std::net::IpAddr;

use nett_core::id::NodeId;
use nett_trust::admission::Member;

use crate::config::{Candidate, DesiredMesh, Reachability};
use crate::dataplane::{
    DataPlane, INTERFACE_NAME, InterfaceAddress, InterfaceSpec, MESH_MTU, PeerSpec,
};
use crate::event::{Event, EventSink};
use crate::key::PrivateKey;
use crate::members::MemberSet;
use crate::prefix::IpPrefix;

/// `dial-only` 成员对每个对端的持久保活间隔（秒），维持 NAT 映射（design/mesh.md 第 4 节）。
pub const DIAL_ONLY_KEEPALIVE_SECS: u16 = 25;

pub struct Engine<D> {
    node_id: NodeId,
    private_key: PrivateKey,
    dataplane: D,
    members: MemberSet,
    /// 最近一次成功应用的接口配置。
    interface: Option<InterfaceSpec>,
}

impl<D: DataPlane> Engine<D> {
    pub fn new(node_id: NodeId, private_key: PrivateKey, dataplane: D) -> Self {
        Self {
            node_id,
            private_key,
            dataplane,
            members: MemberSet::default(),
            interface: None,
        }
    }

    pub fn members(&self) -> &MemberSet {
        &self.members
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
                self.sync_peers(&[], events);
            }
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

        let peers: Vec<PeerSpec> = self
            .members
            .members()
            .values()
            .filter(|m| m.node_id != self.node_id)
            .map(|m| peer_spec(m, desired))
            .collect();
        self.sync_peers(&peers, events);
    }

    fn sync_peers(&mut self, peers: &[PeerSpec], events: &mut impl EventSink) {
        match self.dataplane.sync_peers(peers) {
            Ok(()) => events.emit(Event::PeersApplied { peers: peers.len() }),
            Err(e) => events.emit(Event::DataPlaneFailed {
                reason: e.to_string(),
            }),
        }
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

fn peer_spec(member: &Member, desired: &DesiredMesh) -> PeerSpec {
    let endpoint = desired
        .paths
        .get(&member.node_id)
        .and_then(|candidates| candidates.first())
        .map(|candidate| match candidate {
            Candidate::Direct { endpoint } => *endpoint,
        });
    PeerSpec {
        public_key: member.mesh_public_key,
        allowed_ips: vec![
            IpPrefix::host(IpAddr::V4(member.addresses.ipv4)),
            IpPrefix::host(IpAddr::V6(member.addresses.ipv6)),
        ],
        endpoint,
        persistent_keepalive: (desired.reachability == Reachability::DialOnly)
            .then_some(DIAL_ONLY_KEEPALIVE_SECS),
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
}
