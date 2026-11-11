//! 在 Hub 一侧发生的事（design/hub.md 第 4 节）：机器入网时交来的准入材料、机器自行退出、Hub 得知的公网
//! 地址。Hub 把它们用到自己保存的站点副本和每一次推送上，签名工具取回之后用到站点目录中：两边用的是这同一
//! 份逻辑，结果相同。准入材料在这里按站点的信任锚完整验证，Hub 交来的内容是不可信的输入（硬性规则 13）。

use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_trust::admission::{AdmissionMaterial, admit};
use nett_trust::anchors::TrustAnchors;
use nett_trust::revocation::{Revocation, Revocations};
use serde::{Deserialize, Serialize};

use crate::SiteError;
use crate::sign::enrolled_input;
use crate::state::{Learned, NodeKeys, SignedPolicy, State};

/// `GET /api/v1/site/updates` 的回复。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Updates {
    /// 经 Hub 入网的机器的准入材料：站点签的初始节点策略加上机器签的准入证明。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enrolled: Vec<AdmissionMaterial>,
    /// 自行退出（`nett leave`）的机器。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub left: Vec<NodeId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub learned: Vec<LearnedFor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearnedFor {
    pub node_id: NodeId,
    pub learned: Learned,
}

/// 用到站点上的事，按机器名。
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    pub joined: Vec<NodeName>,
    pub left: Vec<NodeName>,
    pub learned: Vec<NodeName>,
}

impl Updates {
    /// 用到站点状态上。已经用过的（机器已经记下这份准入材料、已经移除、地址相同）跳过，不在站点中的机器
    /// 也跳过。失败时站点状态不变。
    pub fn apply(&self, state: &mut State) -> Result<Applied, SiteError> {
        let mut next = state.clone();
        let mut applied = Applied::default();
        // 撤销先于授权（硬性规则 4）
        for node in &self.left {
            if let Some(name) = next.name_of(node).cloned() {
                next.remove(&name)?;
                applied.left.push(name);
            }
        }
        for material in &self.enrolled {
            if let Some(name) = record_enrollment(&mut next, material)? {
                applied.joined.push(name);
            }
        }
        for l in &self.learned {
            let Some(name) = next.name_of(&l.node_id).cloned() else {
                continue;
            };
            let m = next.machine_mut(&name)?;
            if m.learned != l.learned {
                m.learned = l.learned;
                applied.learned.push(name);
            }
        }
        next.check()?;
        *state = next;
        Ok(applied)
    }
}

/// 记下一台机器经 Hub 入网时交来的准入材料（design/hub.md 第 6 节）：材料要能用站点的信任锚验证，机器要在
/// 站点中、还没有公钥。返回记下的机器名；这台机器已经记下同样的公钥、或已不在站点中时返回 `None`。
pub fn record_enrollment(
    state: &mut State,
    material: &AdmissionMaterial,
) -> Result<Option<NodeName>, SiteError> {
    let trusted = TrustAnchors::from_doc(&state.trust_anchors)
        .map_err(|e| SiteError::invalid(format!("the site's trust anchors: {e}")))?;
    let mut revocations = Revocations::default();
    for r in &state.revoked {
        revocations.apply(&Revocation::Node {
            node_id: r.node_id.clone(),
        });
    }
    let member = match admit(material, &trusted, &revocations) {
        Ok(member) => member,
        // 机器入网之后又被移除了
        Err(e) if e.node_id().is_some_and(|n| revocations.is_node_revoked(n)) => return Ok(None),
        Err(e) => return Err(SiteError::invalid(format!("admission material: {e}"))),
    };
    let Some(name) = state.name_of(&member.node_id).cloned() else {
        return Ok(None);
    };
    let keys = NodeKeys {
        mesh: member.mesh_public_key,
        identity: member.identity_public_key,
    };
    let m = state.machine_mut(&name)?;
    if m.keys == Some(keys) {
        return Ok(None);
    }
    if m.keys.is_some() {
        return Err(SiteError::invalid(format!(
            "`{name}` is already a member with other keys"
        )));
    }
    m.keys = Some(keys);
    m.policy = Some(SignedPolicy {
        version: member.policy_version,
        input: enrolled_input(keys, &member)?,
        material: material.clone(),
    });
    m.enrollment = None;
    state.check()?;
    Ok(Some(name))
}
