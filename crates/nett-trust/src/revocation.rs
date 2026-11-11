//! Revocations (design/auth.md section 10.4). A revocation can only make privileges smaller and
//! needs no signature; nodes keep them permanently.

use std::collections::BTreeSet;

use nett_core::id::NodeId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Revocation {
    /// Identity revocation: removes a node. It takes effect permanently by node ID, and no version
    /// of a signed artifact can restore it.
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

    /// Revoked nodes, kept in the local trust store (design/mesh.md section 4.2).
    pub fn nodes(&self) -> &BTreeSet<NodeId> {
        &self.nodes
    }
}
