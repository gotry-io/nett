//! 访问控制（design/mesh.md 第 12 节）与 Edge 专用地址（ADR 0015）：验证签名的访问规则集，算出本机要执行
//! 的过滤规则和 Edge 的源地址转换。规则的形式与平台无关，由各平台的后端安装（ADR 0018）。

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

/// 展开后的过滤规则最多的条数（硬性规则 14）：规则集中每条规则的来源 × 目标 × 端口范围，加上成员之间的
/// 控制流量。超过时整体按拒绝处理。
pub const MAX_FILTER_RULES: usize = 4096;

/// 一个匹配条件。来源和目标网段同时决定了地址族。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    Source(IpPrefix),
    Destination(IpPrefix),
    /// 协议与目的端口范围。
    Port(PortRange),
}

/// 一条过滤规则：全部条件都满足时放行或拒绝；没有条件时匹配所有包。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterRule {
    pub matches: Vec<Match>,
    pub accept: bool,
}

/// 本机从组网接口进入、新建连接的过滤规则（已建立的连接和与它相关的包直接放行）：按顺序匹配，第一条
/// 匹配的规则决定放行或拒绝；都不匹配时拒绝（ADR 0023），由数据面的后端执行。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilterSpec {
    pub rules: Vec<FilterRule>,
}

impl FilterSpec {
    /// 拒绝所有新建的入方向连接（没有规则时即是拒绝）：规则无法展开或安装失败时使用（硬性规则 6）。
    pub fn deny_all() -> Self {
        Self::default()
    }
}

/// 本机作为智能入口转发的流量（design/mesh.md 第 10 节，ADR 0016）：从组网接口进来、转发出去的连接，只放行
/// 来源是 Edge 专用地址的，来源换成本机在出接口上的地址；其他来源的转发丢弃。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressSpec {
    pub edge_sources: Vec<IpAddr>,
}

impl IngressSpec {
    /// 本机宣告了网段时才转发。
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

/// 本机的 Edge：发往组网接口、来源在 `containers` 中的流量，源地址换成 Edge 专用地址；其他来源使用
/// Edge 专用地址的包丢弃（ADR 0015）。
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

/// 已生效的访问规则集。版本号只增不减，重启之后以信任存储中的版本为基准（design/mesh.md 第 4.2 节）；
/// 期望状态中没有规则集时保持已生效的那一份。
#[derive(Debug, Default)]
pub struct AccessRules {
    applied: Option<Applied>,
    /// 本机此前接受过的版本。
    floor: Option<VersionRecord>,
}

impl AccessRules {
    pub fn version(&self) -> Option<u64> {
        self.applied.as_ref().map(|a| a.version)
    }

    pub fn restore(&mut self, floor: Option<VersionRecord>) {
        self.floor = floor;
    }

    /// 保存进信任存储的版本。
    pub fn saved_version(&self) -> Option<VersionRecord> {
        self.applied
            .as_ref()
            .map(|a| VersionRecord {
                version: a.version,
                hash: a.hash,
            })
            .or(self.floor)
    }

    /// 应用期望状态中的规则集。验证失败时保持已生效的规则集，并上报事件。
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

    /// 验证签名与版本；与已生效的完全相同时返回 `None`（幂等）。
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

    /// 本机的过滤规则（design/mesh.md 第 12 节）：
    /// 1. 成员发往本机隧道内探测端口的包放行：组网自己的测量不受访问规则影响；
    /// 2. 规则集中的规则，按顺序展开。
    ///
    /// 其他新建连接都拒绝（ADR 0023），包括来自 Edge 专用地址的、发往本机宣告的网段的。
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

    /// 成员 1、2、3，其中 1 有 Edge；返回 2 看到的成员表。
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
        // 相同的规则集幂等；版本相同而内容不同、版本更低都被拒绝，已生效的保持不变
        access.apply(&with(rule_set(2, vec![])), &mut events);
        access.apply(
            &with(rule_set(
                2,
                vec![allow_8686("100.88.0.1/32", "100.88.0.2/32")],
            )),
            &mut events,
        );
        access.apply(&with(rule_set(1, vec![])), &mut events);
        // 不是信任锚签的
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
        // 成员 1、3 的隧道内探测（IPv4、IPv6 各一条）在最前；其后只有规则集，没有规则匹配的都拒绝
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
        // IPv6 的来源与 IPv4 的目标不组合
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
        // 重启之后：信任存储中的版本是基准
        let mut restarted = AccessRules::default();
        restarted.restore(first.saved_version());
        let mut d = mesh.desired(2, vec![]);
        d.access_rules = Some(mesh.sign(&rule_set(1, vec![])));
        let mut events = VecSink::default();
        restarted.apply(&validated(d.clone()), &mut events);
        assert!(matches!(events.0[..], [Event::AccessRulesRejected { .. }]));
        assert_eq!(restarted.version(), None);
        // 同一个版本、同样的内容照常生效
        d.access_rules = Some(mesh.sign(&rule_set(2, vec![])));
        restarted.apply(&validated(d), &mut VecSink::default());
        assert_eq!(restarted.version(), Some(2));
    }
}
