//! Member set: configures WireGuard only for peers whose signature chain can be verified
//! (design/mesh.md section 4.1, ADR 0014).
//!
//! - Revocations are applied first, then new admission material; revocation is permanent
//!   (design/auth.md section 10.4);
//! - Members are removed only by revocation; a member missing from the desired state is not treated as
//!   revoked;
//! - Versions only increase; material identical to what is in effect is idempotent; after a restart,
//!   the version in the trust store is the baseline (design/mesh.md section 4.2);
//! - The new version of this machine's node policy has its expiry checked (design/auth.md section 10.2,
//!   check 6);
//! - A member that fails verification is not configured, the older version in effect stays unchanged,
//!   and an event is reported.

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
    /// Versions previously accepted by this machine (trust store): material lower than it, or with the same
    /// version but different content, is not accepted.
    floor: BTreeMap<NodeId, AppliedRecord>,
    members: BTreeMap<NodeId, Member>,
}

/// Check for this machine's node policy: this machine's node ID, and the current time used for the expiry
/// check. Right after the trust store is created (the first desired state) the expiry is not checked and
/// `now` is `None`.
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

    /// Restores revocations and the previously accepted versions of each member from the trust store.
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

    /// Versions saved into the trust store: those previously accepted, plus those that took effect this
    /// time (only ever higher).
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

    /// Applies the revocations and admission material in a desired state.
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

        // When one desired state has several pieces of material for the same node, the higher version is
        // handled first and the lower is then rejected as "lower than the version in effect"
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
            // When the address or mesh public key conflicts with another member, the existing member takes
            // precedence: WireGuard does not allow peers' AllowedIPs to overlap
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

/// All addresses a member occupies: the mesh address, plus the Edge address when it has the `edge` role.
fn addresses(member: &Member) -> Vec<IpAddr> {
    std::iter::once(member.addresses)
        .chain(member.edge.iter().map(|e| e.addresses))
        .flat_map(|a| [IpAddr::V4(a.ipv4), IpAddr::V6(a.ipv6)])
        .collect()
}
