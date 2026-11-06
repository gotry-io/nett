//! 成员集合：只为能验证签名链条的对端配置 WireGuard（design/mesh.md 第 4.1 节，ADR 0014）。
//!
//! - 先应用撤销记录，再应用新的准入材料；撤销永久生效（design/auth.md 第 10.4 节）；
//! - 成员只因撤销记录删除，期望状态中缺少某个成员不视为撤销；
//! - 版本号只增不减，与已生效材料相同的视为幂等；
//! - 验证失败的成员不配置，已生效的旧版本保持不变，并上报事件。

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use nett_core::id::NodeId;
use nett_trust::admission::{AppliedMembers, Member, VersionCheck, admit};
use nett_trust::revocation::{Revocation, Revocations};

use crate::config::DesiredMesh;
use crate::event::{Event, EventSink};

#[derive(Debug, Default)]
pub struct MemberSet {
    revocations: Revocations,
    applied: AppliedMembers,
    members: BTreeMap<NodeId, Member>,
}

impl MemberSet {
    pub fn members(&self) -> &BTreeMap<NodeId, Member> {
        &self.members
    }

    pub fn get(&self, node_id: &NodeId) -> Option<&Member> {
        self.members.get(node_id)
    }

    /// 应用一份期望状态中的撤销记录和准入材料。
    pub fn apply(&mut self, desired: &DesiredMesh, events: &mut impl EventSink) {
        for revocation in &desired.revocations {
            self.revocations.apply(revocation);
            let Revocation::Node { node_id } = revocation;
            self.applied.remove(node_id);
            if self.members.remove(node_id).is_some() {
                events.emit(Event::MemberRemoved {
                    node_id: node_id.clone(),
                });
            }
        }

        // 同一份期望状态中同一个节点有多份材料时，版本高的先处理，低的随后按"低于已生效版本"拒绝
        let mut admitted = Vec::new();
        for material in &desired.members {
            match admit(material, &desired.anchors, &self.revocations) {
                Ok(member) => admitted.push(member),
                Err(e) => events.emit(Event::MemberRejected {
                    node_id: e.node_id().cloned(),
                    reason: e.to_string(),
                }),
            }
        }
        admitted
            .sort_by(|a, b| (&a.node_id, b.policy_version).cmp(&(&b.node_id, a.policy_version)));

        for member in admitted {
            let reject = |reason: String| Event::MemberRejected {
                node_id: Some(member.node_id.clone()),
                reason,
            };
            let addresses = [
                IpAddr::V4(member.addresses.ipv4),
                IpAddr::V6(member.addresses.ipv6),
            ];
            let in_prefixes = desired.prefixes.ipv4.contains(addresses[0])
                && desired.prefixes.ipv6.contains(addresses[1]);
            if !in_prefixes {
                events.emit(reject("mesh address is outside the mesh prefixes".into()));
                continue;
            }
            match self.applied.check(&member) {
                Ok(VersionCheck::Unchanged) => continue,
                Ok(VersionCheck::Newer) => {}
                Err(e) => {
                    events.emit(reject(e.to_string()));
                    continue;
                }
            }
            // 地址或组网公钥与另一个成员冲突时，已有的成员优先：WireGuard 不允许对端的 AllowedIPs 重叠
            if let Some(other) = self.conflict(&member) {
                events.emit(reject(format!(
                    "mesh address or public key already belongs to {other}"
                )));
                continue;
            }
            self.applied.record(&member);
            events.emit(Event::MemberAdmitted {
                node_id: member.node_id.clone(),
                policy_version: member.policy_version,
            });
            self.members.insert(member.node_id.clone(), member);
        }
    }

    fn conflict(&self, member: &Member) -> Option<&NodeId> {
        let taken: BTreeSet<_> = [
            IpAddr::V4(member.addresses.ipv4),
            IpAddr::V6(member.addresses.ipv6),
        ]
        .into();
        self.members
            .values()
            .filter(|other| other.node_id != member.node_id)
            .find(|other| {
                other.mesh_public_key == member.mesh_public_key
                    || taken.contains(&IpAddr::V4(other.addresses.ipv4))
                    || taken.contains(&IpAddr::V6(other.addresses.ipv6))
            })
            .map(|other| &other.node_id)
    }
}
