//! 撤销记录（design/auth.md 第 10.4 节）。撤销只会让权限更小，不需要签名；节点永久保存。

use std::collections::BTreeSet;

use nett_core::id::NodeId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Revocation {
    /// 身份撤销：移除节点。按节点 ID 永久生效，任何版本的签名产物都不能恢复。
    Node { node_id: NodeId },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Revocations {
    nodes: BTreeSet<NodeId>,
}

impl Revocations {
    pub fn apply(&mut self, revocation: &Revocation) {
        match revocation {
            Revocation::Node { node_id } => {
                self.nodes.insert(node_id.clone());
            }
        }
    }

    pub fn is_node_revoked(&self, node_id: &NodeId) -> bool {
        self.nodes.contains(node_id)
    }

    /// 被撤销的节点，保存在本机的信任存储中（design/mesh.md 第 4.2 节）。
    pub fn nodes(&self) -> &BTreeSet<NodeId> {
        &self.nodes
    }
}
