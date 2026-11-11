//! What happens on the Hub side (design/hub.md section 4): admission material delivered when a
//! machine joins, machines leaving on their own, and public addresses learned by the Hub. The Hub
//! applies them to its own copy of the site and to every push; the signing tool fetches them and
//! applies them to the site directory: both sides use this same logic and get the same result.
//! Admission material is fully verified here against the site's trust anchor; what the Hub delivers
//! is untrusted input (hard rule 13).

use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_trust::admission::{AdmissionMaterial, admit};
use nett_trust::anchors::TrustAnchors;
use nett_trust::revocation::{Revocation, Revocations};
use serde::{Deserialize, Serialize};

use crate::SiteError;
use crate::sign::enrolled_input;
use crate::state::{Learned, NodeKeys, SignedPolicy, State};

/// Response of `GET /api/v1/site/updates`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Updates {
    /// Admission material of machines that joined through the Hub: the initial node policy signed
    /// by the site plus the admission proof signed by the machine.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enrolled: Vec<AdmissionMaterial>,
    /// Machines that left on their own (`nett leave`).
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

/// Events applied to a site, by machine name.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    pub joined: Vec<NodeName>,
    pub left: Vec<NodeName>,
    pub learned: Vec<NodeName>,
}

impl Updates {
    /// Applies them to the site state. Ones already applied (the machine already recorded this
    /// admission material, was already removed, or the address is the same) are skipped, and so are
    /// machines not in the site. On failure the site state is unchanged.
    pub fn apply(&self, state: &mut State) -> Result<Applied, SiteError> {
        let mut next = state.clone();
        let mut applied = Applied::default();
        // Revocation comes before authorization (hard rule 4)
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
                m.learned = l.learned.clone();
                applied.learned.push(name);
            }
        }
        next.check()?;
        *state = next;
        Ok(applied)
    }
}

/// Records the admission material delivered when a machine joins through the Hub (design/hub.md
/// section 6): the material must verify against the site's trust anchor, and the machine must be in
/// the site and not yet have a public key. Returns the recorded machine name; returns `None` when
/// the machine already recorded the same public key or is no longer in the site.
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
        // The machine was removed after it joined
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
