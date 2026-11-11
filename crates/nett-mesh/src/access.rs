//! Access control (design/mesh.md section 12) and the Edge address (ADR 0015): verifies the signed access
//! rule set and computes the filter rules this machine enforces and the Edge's source NAT. The form of
//! the rules is platform-independent; each platform's backend installs them (ADR 0018).

use std::collections::BTreeMap;
use std::net::IpAddr;

use nett_core::id::NodeId;
use nett_core::prefix::IpPrefix;
use nett_trust::admission::Member;
use nett_trust::anchors::TrustAnchors;
use nett_trust::encoding::Sha256Digest;
use nett_trust::payload::{AccessRuleSet, MeshAddresses, PortRange, Protocol, RuleAction};
use nett_trust::signed::SignedPayload;

use crate::config::DesiredMesh;
use crate::event::{Event, EventSink};
use crate::probe::TUNNEL_PROBE_PORT;
use crate::store::{FloorError, VersionRecord};

/// Maximum number of filter rules after expansion (hard rule 14): source x destination x port range of
/// each rule in the rule set, plus control traffic between members. When exceeded, the whole set is
/// treated as deny.
pub const MAX_FILTER_RULES: usize = 4096;

/// A match condition. The source and destination prefixes together determine the address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    Source(IpPrefix),
    Destination(IpPrefix),
    /// Protocol and destination port range.
    Port(PortRange),
}

/// A filter rule: allows or rejects when all conditions are met; with no conditions it matches all packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterRule {
    pub matches: Vec<Match>,
    pub accept: bool,
}

/// Filter rules for new connections entering this machine from the mesh interface (established
/// connections and related packets are allowed directly): matched in order, the first matching rule
/// decides allow or reject; when none match, reject (ADR 0023). Enforced by the data plane backend.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilterSpec {
    pub rules: Vec<FilterRule>,
}

impl FilterSpec {
    /// Rejects all new inbound connections (with no rules this is the same as reject): used when the rules
    /// cannot be expanded or fail to install (hard rule 6).
    pub fn deny_all() -> Self {
        Self::default()
    }
}

/// Traffic this machine forwards as a smart gateway (design/mesh.md section 10, ADR 0016): for
/// connections coming in from the mesh interface and forwarded out, only those whose source is an Edge
/// address are allowed, and the source is replaced with this machine's address on the outgoing
/// interface; forwarding from other sources is dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressSpec {
    pub edge_sources: Vec<IpAddr>,
}

impl IngressSpec {
    /// Forwards only when this machine advertises prefixes.
    pub fn of(own_routes: &[IpPrefix], members: &BTreeMap<NodeId, Member>) -> Option<Self> {
        (!own_routes.is_empty()).then(|| Self {
            edge_sources: members
                .values()
                .filter_map(|m| m.edge.as_ref())
                .flat_map(|e| mesh_addrs(&e.addresses))
                .collect(),
        })
    }
}

/// This machine's Edge: for traffic sent to the mesh interface whose source is in `containers`, the
/// source address is replaced with the Edge address; packets from other sources that use the Edge
/// address are dropped (ADR 0015).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeSpec {
    pub containers: Vec<IpPrefix>,
    pub addresses: MeshAddresses,
}

impl EdgeSpec {
    pub fn of(member: &Member) -> Option<Self> {
        member.edge.as_ref().map(|edge| Self {
            containers: edge.containers.clone(),
            addresses: edge.addresses,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccessError {
    #[error("access rule set: signature: {0}")]
    Signature(String),
    #[error("access rule set: the signed payload carries no access rule set")]
    Missing,
    #[error("access rule set: {0}")]
    Floor(FloorError),
    #[error("access rule set: version {got} is not newer than the applied version {applied}")]
    Version { got: u64, applied: u64 },
    #[error("access rules expand to more than {MAX_FILTER_RULES} filter rules")]
    TooManyRules,
}

#[derive(Debug, Clone)]
struct Applied {
    version: u64,
    hash: Sha256Digest,
    rules: AccessRuleSet,
}

/// The access rule set in effect. Versions only increase; after a restart the version in the trust store
/// is the baseline (design/mesh.md section 4.2); when the desired state has no rule set, the one in
/// effect is kept.
#[derive(Debug, Default)]
pub struct AccessRules {
    applied: Option<Applied>,
    /// Versions previously accepted by this machine.
    floor: Option<VersionRecord>,
}

impl AccessRules {
    pub fn version(&self) -> Option<u64> {
        self.applied.as_ref().map(|a| a.version)
    }

    pub fn restore(&mut self, floor: Option<VersionRecord>) {
        self.floor = floor;
    }

    /// Versions saved into the trust store.
    pub fn saved_version(&self) -> Option<VersionRecord> {
        self.applied
            .as_ref()
            .map(|a| VersionRecord {
                version: a.version,
                hash: a.hash,
            })
            .or(self.floor)
    }

    /// Applies the rule set in the desired state. On verification failure the rule set in effect is kept and
    /// an event is reported.
    pub fn apply(&mut self, desired: &DesiredMesh, events: &mut impl EventSink) {
        let Some(signed) = &desired.access_rules else {
            return;
        };
        match self.check(signed, &desired.anchors) {
            Ok(Some(applied)) => {
                events.emit(Event::AccessRulesApplied {
                    version: applied.version,
                });
                self.applied = Some(applied);
            }
            Ok(None) => {}
            Err(e) => events.emit(Event::AccessRulesRejected {
                reason: e.to_string(),
            }),
        }
    }

    /// Verifies the signature and version; returns `None` when identical to what is in effect (idempotent).
    fn check(
        &self,
        signed: &SignedPayload,
        anchors: &TrustAnchors,
    ) -> Result<Option<Applied>, AccessError> {
        let verified = signed
            .verify(anchors)
            .map_err(|e| AccessError::Signature(e.to_string()))?;
        let (hash, rules) = verified
            .payload
            .access_rule_set()
            .ok_or(AccessError::Missing)?;
        if let Some(floor) = &self.floor {
            floor
                .admits(rules.version, hash)
                .map_err(AccessError::Floor)?;
        }
        if let Some(applied) = &self.applied {
            if applied.version == rules.version && applied.hash == *hash {
                return Ok(None);
            }
            if rules.version <= applied.version {
                return Err(AccessError::Version {
                    got: rules.version,
                    applied: applied.version,
                });
            }
        }
        Ok(Some(Applied {
            version: rules.version,
            hash: *hash,
            rules: rules.clone(),
        }))
    }

    /// This machine's filter rules (design/mesh.md section 12):
    /// 1. Packets from members to the in-tunnel probe port of this machine are allowed: the mesh's own
    ///    measurement is not affected by access rules;
    /// 2. The rules in the rule set, expanded in order.
    ///
    /// All other new connections are rejected (ADR 0023), including those from the Edge address to prefixes
    /// advertised by this machine.
    pub fn filter(
        &self,
        own: &NodeId,
        members: &BTreeMap<NodeId, Member>,
    ) -> Result<FilterSpec, AccessError> {
        let mut rules = Vec::new();
        let own_addrs = members.get(own).map(|m| mesh_addrs(&m.addresses));
        if let Some(own_addrs) = own_addrs {
            for member in members.values().filter(|m| &m.node_id != own) {
                for (from, to) in mesh_addrs(&member.addresses).into_iter().zip(own_addrs) {
                    rules.push(FilterRule {
                        matches: vec![
                            Match::Source(IpPrefix::host(from)),
                            Match::Destination(IpPrefix::host(to)),
                            Match::Port(PortRange {
                                protocol: Protocol::Udp,
                                first: TUNNEL_PROBE_PORT,
                                last: TUNNEL_PROBE_PORT,
                            }),
                        ],
                        accept: true,
                    });
                }
            }
        }
        for rule in self.applied.iter().flat_map(|a| &a.rules.rules) {
            let accept = rule.action == RuleAction::Allow;
            for from in &rule.from {
                for to in rule.to.iter().filter(|t| t.is_ipv4() == from.is_ipv4()) {
                    let base = [Match::Source(*from), Match::Destination(*to)];
                    if rule.ports.is_empty() {
                        rules.push(FilterRule {
                            matches: base.to_vec(),
                            accept,
                        });
                    }
                    for port in &rule.ports {
                        let mut matches = base.to_vec();
                        matches.push(Match::Port(*port));
                        rules.push(FilterRule { matches, accept });
                    }
                    if rules.len() > MAX_FILTER_RULES {
                        return Err(AccessError::TooManyRules);
                    }
                }
            }
        }
        if rules.len() > MAX_FILTER_RULES {
            return Err(AccessError::TooManyRules);
        }
        Ok(FilterSpec { rules })
    }
}

fn mesh_addrs(addresses: &MeshAddresses) -> [IpAddr; 2] {
    [IpAddr::V4(addresses.ipv4), IpAddr::V6(addresses.ipv6)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::VecSink;
    use crate::testutil::{Mesh, no_expiry, node_id, validated};
    use nett_trust::payload::{AccessRule, Artifact, PayloadDoc};

    fn p(s: &str) -> IpPrefix {
        s.parse().expect(s)
    }

    fn rule_set(version: u64, rules: Vec<AccessRule>) -> PayloadDoc {
        PayloadDoc::EnrollmentPolicy {
            v: 1,
            artifacts: vec![Artifact::AccessRuleSet(AccessRuleSet { version, rules })],
            expires_at: "2026-11-06T10:00:00Z".parse().expect("time"),
        }
    }

    fn allow_8686(from: &str, to: &str) -> AccessRule {
        AccessRule {
            action: RuleAction::Allow,
            from: vec![p(from)],
            to: vec![p(to)],
            ports: vec![PortRange {
                protocol: Protocol::Tcp,
                first: 8686,
                last: 8686,
            }],
        }
    }

    /// Members 1, 2, 3, where 1 has an Edge; returns the member table as seen by 2.
    fn members(mesh: &Mesh) -> BTreeMap<NodeId, Member> {
        let desired = validated(mesh.desired(
            2,
            vec![
                mesh.edge_material(1, 1),
                mesh.material(2, 1),
                mesh.material(3, 1),
            ],
        ));
        let mut set = crate::members::MemberSet::default();
        set.apply(&desired, &no_expiry(&desired), &mut VecSink::default());
        set.members().clone()
    }

    #[test]
    fn verifies_signature_and_keeps_versions_increasing() {
        let mesh = Mesh::new(&[1, 2]);
        let mut access = AccessRules::default();
        let mut events = VecSink::default();
        let with = |doc: PayloadDoc| {
            let mut d = mesh.desired(2, vec![mesh.material(1, 1), mesh.material(2, 1)]);
            d.access_rules = Some(mesh.sign(&doc));
            validated(d)
        };
        access.apply(&with(rule_set(2, vec![])), &mut events);
        assert_eq!(access.version(), Some(2));
        // Identical rule sets are idempotent; the same version with different content, or a lower version, is
        // rejected and the one in effect stays unchanged
        access.apply(&with(rule_set(2, vec![])), &mut events);
        access.apply(
            &with(rule_set(
                2,
                vec![allow_8686("100.88.0.1/32", "100.88.0.2/32")],
            )),
            &mut events,
        );
        access.apply(&with(rule_set(1, vec![])), &mut events);
        // not signed by a trust anchor
        let mut forged = mesh.desired(2, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        forged.access_rules = Some(Mesh::new(&[1]).sign(&rule_set(9, vec![])));
        access.apply(&validated(forged), &mut events);
        assert_eq!(access.version(), Some(2));
        let rejected = events
            .0
            .iter()
            .filter(|e| matches!(e, Event::AccessRulesRejected { .. }))
            .count();
        assert_eq!(rejected, 3, "{:?}", events.0);
        assert_eq!(
            events
                .0
                .iter()
                .filter(|e| matches!(e, Event::AccessRulesApplied { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn filter_puts_control_rules_before_the_rule_set() {
        let mesh = Mesh::new(&[1, 2, 3]);
        let members = members(&mesh);
        let mut access = AccessRules::default();
        let mut d = mesh.desired(
            2,
            vec![
                mesh.edge_material(1, 1),
                mesh.material(2, 1),
                mesh.material(3, 1),
            ],
        );
        d.access_rules = Some(mesh.sign(&rule_set(
            1,
            vec![
                allow_8686("100.88.1.1/32", "100.88.0.2/32"),
                AccessRule {
                    action: RuleAction::Deny,
                    from: vec![p("100.88.0.3/32"), p("fd00:88::3/128")],
                    to: vec![p("100.88.0.2/32")],
                    ports: vec![],
                },
            ],
        )));
        access.apply(&validated(d), &mut VecSink::default());
        let spec = access.filter(&node_id(2), &members).expect("filter");
        let r = &spec.rules;
        // In-tunnel probes of members 1 and 3 (one each for IPv4 and IPv6) come first; after them only the rule
        // set, and anything no rule matches is rejected
        assert_eq!(r.len(), 4 + 1 + 1, "{r:?}");
        assert!(r[..4].iter().all(|x| x.accept
            && x.matches.contains(&Match::Port(PortRange {
                protocol: Protocol::Udp,
                first: TUNNEL_PROBE_PORT,
                last: TUNNEL_PROBE_PORT
            }))));
        assert_eq!(
            r[4],
            FilterRule {
                matches: vec![
                    Match::Source(p("100.88.1.1/32")),
                    Match::Destination(p("100.88.0.2/32")),
                    Match::Port(PortRange {
                        protocol: Protocol::Tcp,
                        first: 8686,
                        last: 8686
                    }),
                ],
                accept: true,
            }
        );
        // An IPv6 source does not combine with an IPv4 destination
        assert_eq!(
            r[5],
            FilterRule {
                matches: vec![
                    Match::Source(p("100.88.0.3/32")),
                    Match::Destination(p("100.88.0.2/32"))
                ],
                accept: false,
            }
        );
    }

    #[test]
    fn too_many_rules_fail_closed() {
        let mesh = Mesh::new(&[1, 2]);
        let mut access = AccessRules::default();
        let many: Vec<IpPrefix> = (0..65u32)
            .map(|i| IpPrefix::host(IpAddr::V4(std::net::Ipv4Addr::from(0x6458_0100 + i))))
            .collect();
        let rule = AccessRule {
            action: RuleAction::Allow,
            from: many.clone(),
            to: many,
            ports: vec![],
        };
        let mut d = mesh.desired(2, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        d.access_rules = Some(mesh.sign(&rule_set(1, vec![rule])));
        access.apply(&validated(d), &mut VecSink::default());
        let members = {
            let mut set = crate::members::MemberSet::default();
            let desired =
                validated(mesh.desired(2, vec![mesh.material(1, 1), mesh.material(2, 1)]));
            set.apply(&desired, &no_expiry(&desired), &mut VecSink::default());
            set.members().clone()
        };
        assert_eq!(
            access.filter(&node_id(2), &members),
            Err(AccessError::TooManyRules)
        );
    }

    #[test]
    fn a_restored_version_rejects_older_rule_sets() {
        let mesh = Mesh::new(&[1, 2]);
        let mut first = AccessRules::default();
        let mut d = mesh.desired(2, vec![]);
        d.access_rules = Some(mesh.sign(&rule_set(2, vec![])));
        first.apply(&validated(d), &mut VecSink::default());
        assert_eq!(first.version(), Some(2));
        // After a restart: the version in the trust store is the baseline
        let mut restarted = AccessRules::default();
        restarted.restore(first.saved_version());
        let mut d = mesh.desired(2, vec![]);
        d.access_rules = Some(mesh.sign(&rule_set(1, vec![])));
        let mut events = VecSink::default();
        restarted.apply(&validated(d.clone()), &mut events);
        assert!(matches!(events.0[..], [Event::AccessRulesRejected { .. }]));
        assert_eq!(restarted.version(), None);
        // The same version with the same content takes effect as usual
        d.access_rules = Some(mesh.sign(&rule_set(2, vec![])));
        restarted.apply(&validated(d), &mut VecSink::default());
        assert_eq!(restarted.version(), Some(2));
    }
}
