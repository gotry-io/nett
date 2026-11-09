//! 智能入口宣告的网段（design/mesh.md 第 10 节）：验证签名，只接受有 `subnet_router` 角色的成员的宣告，
//! 版本号只增不减；网段不能与组网网段或其他成员宣告的网段重叠（WireGuard 不允许对端的 `AllowedIPs`
//! 重叠）。成员被移除、或它的节点策略不再有 `subnet_router` 角色时，它宣告的网段随之作废。

use std::collections::BTreeMap;

use nett_core::id::NodeId;
use nett_core::prefix::IpPrefix;
use nett_trust::admission::Member;
use nett_trust::encoding::Sha256Digest;
use nett_trust::payload::Role;

use crate::config::DesiredMesh;
use crate::event::{Event, EventSink};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Applied {
    version: u64,
    hash: Sha256Digest,
    routes: Vec<IpPrefix>,
}

/// 各成员已生效的宣告。期望状态中缺少某个成员的宣告不视为撤销。
#[derive(Debug, Default)]
pub struct Routes {
    applied: BTreeMap<NodeId, Applied>,
}

impl Routes {
    /// 某个成员宣告的网段。
    pub fn of(&self, node: &NodeId) -> &[IpPrefix] {
        self.applied.get(node).map_or(&[], |a| a.routes.as_slice())
    }

    pub fn version(&self, node: &NodeId) -> Option<u64> {
        self.applied.get(node).map(|a| a.version)
    }

    /// 应用期望状态中的宣告；`members` 是已准入的成员。
    pub fn apply(
        &mut self,
        desired: &DesiredMesh,
        members: &BTreeMap<NodeId, Member>,
        events: &mut impl EventSink,
    ) {
        self.applied.retain(|node, _| {
            members
                .get(node)
                .is_some_and(|m| m.roles.contains(&Role::SubnetRouter))
        });
        for signed in &desired.advertised_routes {
            let verified = match signed.verify(&desired.anchors) {
                Ok(v) => v,
                Err(e) => {
                    events.emit(Event::RoutesRejected {
                        node_id: None,
                        reason: format!("signature: {e}"),
                    });
                    continue;
                }
            };
            for (hash, routes) in verified.payload.advertised_routes() {
                let reject = |reason: String| Event::RoutesRejected {
                    node_id: Some(routes.node_id.clone()),
                    reason,
                };
                let Some(member) = members.get(&routes.node_id) else {
                    events.emit(reject("not an admitted member".into()));
                    continue;
                };
                if !member.roles.contains(&Role::SubnetRouter) {
                    events.emit(reject("the node policy has no subnet_router role".into()));
                    continue;
                }
                if let Some(applied) = self.applied.get(&routes.node_id) {
                    if applied.version == routes.version && applied.hash == *hash {
                        continue;
                    }
                    if routes.version <= applied.version {
                        events.emit(reject(format!(
                            "version {} is not newer than the applied version {}",
                            routes.version, applied.version
                        )));
                        continue;
                    }
                }
                let mesh = [desired.prefixes.ipv4, desired.prefixes.ipv6];
                if let Some(r) = routes
                    .routes
                    .iter()
                    .find(|r| mesh.iter().any(|m| overlaps(m, r)))
                {
                    events.emit(reject(format!("{r} overlaps the mesh prefixes")));
                    continue;
                }
                let taken = self
                    .applied
                    .iter()
                    .filter(|(node, _)| **node != routes.node_id)
                    .find_map(|(node, a)| {
                        routes
                            .routes
                            .iter()
                            .find(|r| a.routes.iter().any(|o| overlaps(o, r)))
                            .map(|r| (node.clone(), *r))
                    });
                if let Some((other, r)) = taken {
                    events.emit(reject(format!("{r} overlaps a route of {other}")));
                    continue;
                }
                events.emit(Event::RoutesApplied {
                    node_id: routes.node_id.clone(),
                    version: routes.version,
                });
                self.applied.insert(
                    routes.node_id.clone(),
                    Applied {
                        version: routes.version,
                        hash: *hash,
                        routes: routes.routes.clone(),
                    },
                );
            }
        }
    }

    /// 本机之外的成员宣告的网段：本机经组网接口到达它们。
    pub fn of_others<'a>(&'a self, own: &'a NodeId) -> impl Iterator<Item = IpPrefix> + 'a {
        self.applied
            .iter()
            .filter(move |(node, _)| *node != own)
            .flat_map(|(_, a)| a.routes.iter().copied())
    }
}

fn overlaps(a: &IpPrefix, b: &IpPrefix) -> bool {
    a.covers(b) || b.covers(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::VecSink;
    use crate::members::MemberSet;
    use crate::testutil::{Mesh, node_id, validated};

    fn p(s: &str) -> IpPrefix {
        s.parse().expect(s)
    }

    fn applied(mesh: &Mesh, docs: Vec<nett_trust::signed::SignedPayload>) -> (Routes, Vec<Event>) {
        let mut d = mesh.desired(
            1,
            vec![
                mesh.material(1, 1),
                mesh.router_material(2, 1),
                mesh.router_material(3, 1),
            ],
        );
        d.advertised_routes = docs;
        let desired = validated(d);
        let mut members = MemberSet::default();
        members.apply(&desired, &mut VecSink::default());
        let mut routes = Routes::default();
        let mut events = VecSink::default();
        routes.apply(&desired, members.members(), &mut events);
        (routes, events.0)
    }

    #[test]
    fn accepts_routes_of_subnet_routers_only() {
        let mesh = Mesh::new(&[1, 2, 3]);
        let (routes, events) = applied(
            &mesh,
            vec![
                mesh.sign(&mesh.routes_doc(2, 1, &["192.0.2.10/32"])),
                mesh.sign(&mesh.routes_doc(1, 1, &["198.51.100.0/24"])),
            ],
        );
        assert_eq!(routes.of(&node_id(2)), [p("192.0.2.10/32")]);
        assert!(
            routes.of(&node_id(1)).is_empty(),
            "node 1 is not a subnet router"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::RoutesRejected { .. }))
        );
        assert_eq!(
            routes.of_others(&node_id(1)).collect::<Vec<_>>(),
            [p("192.0.2.10/32")]
        );
        assert!(routes.of_others(&node_id(2)).next().is_none());
    }

    #[test]
    fn routes_lapse_when_the_role_is_dropped() {
        let mesh = Mesh::new(&[1, 2]);
        let mut d = mesh.desired(1, vec![mesh.material(1, 1), mesh.router_material(2, 1)]);
        d.advertised_routes = vec![mesh.sign(&mesh.routes_doc(2, 1, &["192.0.2.10/32"]))];
        let mut members = MemberSet::default();
        let mut routes = Routes::default();
        let desired = validated(d.clone());
        members.apply(&desired, &mut VecSink::default());
        routes.apply(&desired, members.members(), &mut VecSink::default());
        assert_eq!(routes.of(&node_id(2)).len(), 1);
        // 新版本的节点策略去掉了 subnet_router 角色
        d.members = vec![mesh.material(1, 1), mesh.material(2, 2)];
        let desired = validated(d);
        members.apply(&desired, &mut VecSink::default());
        routes.apply(&desired, members.members(), &mut VecSink::default());
        assert!(routes.of(&node_id(2)).is_empty());
    }

    #[test]
    fn rejects_overlaps_forgeries_and_old_versions() {
        let mesh = Mesh::new(&[1, 2, 3]);
        let stranger = Mesh::new(&[2]);
        let (routes, events) = applied(
            &mesh,
            vec![
                mesh.sign(&mesh.routes_doc(2, 2, &["192.0.2.0/24"])),
                // 与 2 的网段重叠
                mesh.sign(&mesh.routes_doc(3, 1, &["192.0.2.10/32"])),
                // 与组网网段重叠
                mesh.sign(&mesh.routes_doc(3, 1, &["100.88.5.0/24"])),
                // 不是信任锚签的
                stranger.sign(&mesh.routes_doc(3, 1, &["203.0.113.0/24"])),
                // 低于已生效的版本
                mesh.sign(&mesh.routes_doc(2, 1, &["198.51.100.0/24"])),
            ],
        );
        assert_eq!(routes.of(&node_id(2)), [p("192.0.2.0/24")]);
        assert!(routes.of(&node_id(3)).is_empty());
        let rejected = events
            .iter()
            .filter(|e| matches!(e, Event::RoutesRejected { .. }))
            .count();
        assert_eq!(rejected, 4, "{events:?}");
    }
}
