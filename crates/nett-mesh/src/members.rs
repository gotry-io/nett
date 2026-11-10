//! 成员集合：只为能验证签名链条的对端配置 WireGuard（design/mesh.md 第 4.1 节，ADR 0014）。
//!
//! - 先应用撤销记录，再应用新的准入材料；撤销永久生效（design/auth.md 第 10.4 节）；
//! - 成员只因撤销记录删除，期望状态中缺少某个成员不视为撤销；
//! - 版本号只增不减，与已生效材料相同的视为幂等；重启之后以信任存储中的版本为基准（design/mesh.md
//!   第 4.2 节）；
//! - 本机节点策略的新版本检查过期时间（design/auth.md 第 10.2 节检查 6）；
//! - 验证失败的成员不配置，已生效的旧版本保持不变，并上报事件。

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use nett_core::id::NodeId;
use nett_trust::admission::{AppliedMembers, AppliedRecord, Member, VersionCheck, admit};
use nett_trust::encoding::Timestamp;
use nett_trust::revocation::{Revocation, Revocations};

use crate::config::DesiredMesh;
use crate::event::{Event, EventSink};

#[derive(Debug, Default)]
pub struct MemberSet {
    revocations: Revocations,
    applied: AppliedMembers,
    /// 本机此前接受过的版本（信任存储）：低于它的、同版本不同内容的材料都不接受。
    floor: BTreeMap<NodeId, AppliedRecord>,
    members: BTreeMap<NodeId, Member>,
}

/// 本机节点策略的检查：本机的节点 ID，以及检查过期时间用的当前时间。信任存储刚建立时（第一份期望状态）
/// 不检查过期时间，`now` 为 `None`。
pub struct OwnPolicy<'a> {
    pub node_id: &'a NodeId,
    pub now: Option<Timestamp>,
}

impl MemberSet {
    pub fn members(&self) -> &BTreeMap<NodeId, Member> {
        &self.members
    }

    pub fn get(&self, node_id: &NodeId) -> Option<&Member> {
        self.members.get(node_id)
    }

    /// 从信任存储恢复撤销记录和各成员此前接受过的版本。
    pub fn restore(&mut self, revoked: &BTreeSet<NodeId>, floor: &BTreeMap<NodeId, AppliedRecord>) {
        for node_id in revoked {
            self.revocations.apply(&Revocation::Node {
                node_id: node_id.clone(),
            });
        }
        self.floor = floor.clone();
    }

    pub fn revoked(&self) -> &BTreeSet<NodeId> {
        self.revocations.nodes()
    }

    /// 保存进信任存储的版本：此前接受过的，加上这次生效的（只会更高）。
    pub fn saved_versions(&self) -> BTreeMap<NodeId, AppliedRecord> {
        let mut out = self.floor.clone();
        out.extend(
            self.applied
                .records()
                .iter()
                .map(|(id, r)| (id.clone(), *r)),
        );
        out
    }

    /// 应用一份期望状态中的撤销记录和准入材料。
    pub fn apply(
        &mut self,
        desired: &DesiredMesh,
        own: &OwnPolicy<'_>,
        events: &mut impl EventSink,
    ) {
        for revocation in &desired.revocations {
            self.revocations.apply(revocation);
            let Revocation::Node { node_id } = revocation;
            self.applied.remove(node_id);
            self.floor.remove(node_id);
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
            let in_prefixes = addresses(&member).iter().all(|a| match a {
                IpAddr::V4(_) => desired.prefixes.ipv4.contains(*a),
                IpAddr::V6(_) => desired.prefixes.ipv6.contains(*a),
            });
            if !in_prefixes {
                events.emit(reject(
                    "mesh or edge address is outside the mesh prefixes".into(),
                ));
                continue;
            }
            let seen_before = match self.floor.get(&member.node_id).map(|f| f.compare(&member)) {
                Some(Err(e)) => {
                    events.emit(reject(e.to_string()));
                    continue;
                }
                Some(Ok(VersionCheck::Unchanged)) => true,
                Some(Ok(VersionCheck::Newer)) | None => false,
            };
            match self.applied.check(&member) {
                Ok(VersionCheck::Unchanged) => continue,
                Ok(VersionCheck::Newer) => {}
                Err(e) => {
                    events.emit(reject(e.to_string()));
                    continue;
                }
            }
            if member.node_id == *own.node_id
                && !seen_before
                && let Some(now) = own.now
                && member.policy_expires_at <= now
            {
                events.emit(reject(format!(
                    "this node's policy version {} expired at {}; sign a new one",
                    member.policy_version, member.policy_expires_at
                )));
                continue;
            }
            // 地址或组网公钥与另一个成员冲突时，已有的成员优先：WireGuard 不允许对端的 AllowedIPs 重叠
            if let Some(other) = self.conflict(&member) {
                events.emit(reject(format!(
                    "mesh or edge address, or public key, already belongs to {other}"
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
        let taken: BTreeSet<_> = addresses(member).into_iter().collect();
        self.members
            .values()
            .filter(|other| other.node_id != member.node_id)
            .find(|other| {
                other.mesh_public_key == member.mesh_public_key
                    || addresses(other).iter().any(|a| taken.contains(a))
            })
            .map(|other| &other.node_id)
    }
}

/// 成员占用的全部地址：组网地址，以及有 `edge` 角色时的 Edge 专用地址。
fn addresses(member: &Member) -> Vec<IpAddr> {
    std::iter::once(member.addresses)
        .chain(member.edge.iter().map(|e| e.addresses))
        .flat_map(|a| [IpAddr::V4(a.ipv4), IpAddr::V6(a.ipv6)])
        .collect()
}
