//! 签名（design/site.md 第 7 节）：内容变化的产物版本加一并重新签名，不变的沿用原来的签名；已签的节点策略
//! 离过期不到 7 天的，换一个新版本重签。收窄同样以更高的版本签名：节点按版本只增不减拒绝旧的版本
//! （design/mesh.md 第 4.2 节），重发旧的签名产物恢复不了被收窄的权限。
//!
//! 输入的哈希与这个工具接手的站点相同（节点策略输入的字段与顺序、访问规则的展开方式都没有变），已有的
//! 站点换过来之后不需要重签。

use nett_core::id::NodeId;
use nett_core::prefix::IpPrefix;
use nett_trust::admission::Member;
use nett_trust::admission::{AdmissionMaterial, AdmissionProofDoc, AdmissionProofKind};
use nett_trust::encoding::{Sha256Digest, Timestamp};
use nett_trust::keys::{Ed25519PublicKey, X25519PublicKey};
use nett_trust::payload::{
    AccessRule, AccessRuleSet, AdvertisedRoutes, Artifact, EdgeSources, MeshAddresses, Module,
    NodeAddresses, NodePolicy, Payload, PayloadDoc, Role, RuleAction,
};
use nett_trust::signed::SignedPayload;
use nett_trust::signing::{EnrollmentKeyPair, RecoveryKeyPair};
use serde::Serialize;

use crate::SiteError;
use crate::state::{Machine, NodeKeys, Part, SignedPolicy, SignedVersion, State};

/// 签名载荷的过期时间：生成之后 30 天（design/local-signing.md 第 5 节）。
pub const PAYLOAD_VALIDITY_SECS: i64 = 30 * 24 * 3600;
/// 已签的节点策略离过期不到这么久时换一个新版本重签。
pub const RESIGN_BEFORE_SECS: i64 = 7 * 24 * 3600;

/// 生成节点策略和准入证明的输入；它的哈希不变时沿用原来的签名。
#[derive(Serialize)]
struct PolicyInput {
    mesh_key: X25519PublicKey,
    identity_key: X25519PublicKey,
    roles: Vec<Role>,
    edge_sources: Option<EdgeSources>,
    mesh: MeshAddresses,
    edge: Option<MeshAddresses>,
}

/// 等待经 Hub 入网的机器的节点策略输入（design/hub.md 第 6 节）：公钥要等入网时由机器交来，策略中写的是
/// 入网公钥。
#[derive(Serialize)]
struct PendingInput {
    enrollment_key: Ed25519PublicKey,
    roles: Vec<Role>,
    edge_sources: Option<EdgeSources>,
    mesh: MeshAddresses,
    edge: Option<MeshAddresses>,
}

/// 签名站点中变化了的产物。`force` 中的机器即使没有变化、也没有接近过期，也换一个新版本重签节点策略
/// （`nett site invite`：拷过去之前已经过期的那一份）。
pub fn sign(
    state: &mut State,
    recovery: &RecoveryKeyPair,
    now: Timestamp,
    force: &[NodeId],
) -> Result<(), SiteError> {
    if recovery.doc() != state.trust_anchors.recovery_key {
        return Err(SiteError::invalid(
            "recovery.pk8 does not match the trust anchors of this site",
        ));
    }
    let expires_at = Timestamp::from_unix_seconds(now.unix_seconds() + PAYLOAD_VALIDITY_SECS);
    for m in state.machines.values_mut() {
        if let Some(input) = policy_input(m) {
            let hash = hash_of(&input)?;
            let keep = m.policy.as_ref().is_some_and(|p| {
                p.input == hash
                    && !force.contains(&m.node_id)
                    && !expiring(&p.material, now, RESIGN_BEFORE_SECS)
            });
            if !keep {
                let version = m.policy.as_ref().map_or(1, |p| p.version + 1);
                m.policy = Some(SignedPolicy {
                    version,
                    input: hash,
                    material: sign_node(recovery, &m.node_id, version, input, expires_at)?,
                });
            }
        } else if let Some(e) = &m.enrollment {
            // 等待入网：策略中写入网公钥，准入证明由机器入网时签（design/hub.md 第 6 节）
            let input = PendingInput {
                enrollment_key: e.public_key,
                roles: roles(m),
                edge_sources: m.edge.as_ref().map(|e| EdgeSources {
                    containers: e.containers.clone(),
                }),
                mesh: m.mesh,
                edge: m.edge.as_ref().map(|e| e.addresses),
            };
            let hash = hash_of(&input)?;
            let keep = e.policy.as_ref().is_some_and(|p| {
                p.input == hash && !expiring_payload(&p.signed, now, RESIGN_BEFORE_SECS)
            });
            if !keep {
                let version = e.policy.as_ref().map_or(1, |p| p.version + 1);
                let signed = recovery
                    .sign(node_policy_payload(
                        &m.node_id,
                        version,
                        input.roles,
                        input.edge_sources,
                        input.mesh,
                        input.edge,
                        input.enrollment_key,
                        expires_at,
                    )?)
                    .map_err(SiteError::sign)?;
                if let Some(e) = &mut m.enrollment {
                    e.policy = Some(SignedVersion {
                        version,
                        input: hash,
                        signed,
                    });
                }
            }
        }
        m.routes_signed = sign_routes(
            recovery,
            &m.node_id,
            &m.routes,
            m.routes_signed.take(),
            &mut m.routes_version,
            expires_at,
        )?;
    }

    let rules = expand_rules(state)?;
    let input = hash_of(&rules)?;
    let changed = state.access_rules.as_ref().is_none_or(|r| r.input != input);
    if changed && !(rules.is_empty() && state.access_rules.is_none()) {
        let version = state.access_rules.as_ref().map_or(1, |r| r.version + 1);
        let payload = PayloadDoc::EnrollmentPolicy {
            v: 1,
            artifacts: vec![Artifact::AccessRuleSet(AccessRuleSet { version, rules })],
            expires_at,
        }
        .to_canonical()
        .map_err(SiteError::sign)?;
        state.access_rules = Some(SignedVersion {
            version,
            input,
            signed: recovery.sign(payload).map_err(SiteError::sign)?,
        });
    }
    Ok(())
}

fn policy_input(m: &Machine) -> Option<PolicyInput> {
    let keys = m.keys?;
    Some(PolicyInput {
        mesh_key: keys.mesh,
        identity_key: keys.identity,
        roles: roles(m),
        edge_sources: m.edge.as_ref().map(|e| EdgeSources {
            containers: e.containers.clone(),
        }),
        mesh: m.mesh,
        edge: m.edge.as_ref().map(|e| e.addresses),
    })
}

/// 签名会换新版本的产物：输入变了的节点策略、宣告网段与访问规则集。迁移已有的站点之后据此确认不需要重签。
pub fn outdated(state: &State) -> Result<Vec<String>, SiteError> {
    let mut out = Vec::new();
    for (name, m) in &state.machines {
        if let (Some(input), Some(p)) = (policy_input(m), &m.policy)
            && hash_of(&input)? != p.input
        {
            out.push(format!("{name}: node policy"));
        }
        if !m.routes.is_empty()
            && m.routes_signed.as_ref().map(|r| r.input) != Some(hash_of(&m.routes.as_slice())?)
        {
            out.push(format!("{name}: advertised routes"));
        }
    }
    if state.access_rules.as_ref().map(|r| r.input) != Some(hash_of(&expand_rules(state)?)?)
        && !(state.rules.is_empty() && state.access_rules.is_none())
    {
        out.push("access rules".to_owned());
    }
    Ok(out)
}

/// 节点策略中的角色：有 Edge 时 `edge`，有宣告的网段时 `subnet_router`。
fn roles(m: &Machine) -> Vec<Role> {
    m.edge
        .iter()
        .map(|_| Role::Edge)
        .chain((!m.routes.is_empty()).then_some(Role::SubnetRouter))
        .collect()
}

fn hash_of(value: &impl Serialize) -> Result<Sha256Digest, SiteError> {
    let json = serde_json::to_string(value).map_err(|e| SiteError::invalid(e.to_string()))?;
    Ok(Sha256Digest::of(json.as_bytes()))
}

/// 经 Hub 入网的机器交来准入证明之后，它的节点策略输入的哈希：与签名工具自己签的机器用同一种输入，
/// 内容取自验证过的准入材料。之后站点没有变化时沿用这份材料。
pub(crate) fn enrolled_input(keys: NodeKeys, member: &Member) -> Result<Sha256Digest, SiteError> {
    hash_of(&PolicyInput {
        mesh_key: keys.mesh,
        identity_key: keys.identity,
        roles: member.roles.clone(),
        edge_sources: member.edge.as_ref().map(|e| EdgeSources {
            containers: e.containers.clone(),
        }),
        mesh: member.addresses,
        edge: member.edge.as_ref().map(|e| e.addresses),
    })
}

/// 节点策略的载荷。
#[allow(clippy::too_many_arguments)]
fn node_policy_payload(
    node_id: &NodeId,
    version: u64,
    roles: Vec<Role>,
    edge_sources: Option<EdgeSources>,
    mesh: MeshAddresses,
    edge: Option<MeshAddresses>,
    enrollment_public_key: Ed25519PublicKey,
    expires_at: Timestamp,
) -> Result<Vec<u8>, SiteError> {
    PayloadDoc::EnrollmentPolicy {
        v: 1,
        artifacts: vec![Artifact::NodePolicy(NodePolicy {
            node_id: node_id.clone(),
            policy_version: version,
            modules: vec![Module::Mesh],
            roles,
            edge: edge_sources,
            addresses: NodeAddresses { mesh, edge },
            enrollment_public_key,
        })],
        expires_at,
    }
    .to_canonical()
    .map_err(SiteError::sign)
}

/// 用恢复密钥签节点策略，用一把只用这一次的入网密钥签准入证明（design/local-signing.md 第 3 节）。
fn sign_node(
    recovery: &RecoveryKeyPair,
    node_id: &NodeId,
    version: u64,
    input: PolicyInput,
    expires_at: Timestamp,
) -> Result<AdmissionMaterial, SiteError> {
    let enrollment = EnrollmentKeyPair::generate().map_err(SiteError::sign)?;
    let payload = node_policy_payload(
        node_id,
        version,
        input.roles,
        input.edge_sources,
        input.mesh,
        input.edge,
        enrollment.public_key(),
        expires_at,
    )?;
    Ok(AdmissionMaterial {
        policy: recovery.sign(payload).map_err(SiteError::sign)?,
        proof: enrollment
            .sign_proof(&AdmissionProofDoc {
                v: 1,
                kind: AdmissionProofKind::AdmissionProof,
                node_id: node_id.clone(),
                identity_public_key: input.identity_key,
                mesh_public_key: input.mesh_key,
            })
            .map_err(SiteError::sign)?,
    })
}

/// 已签的节点策略在 `within` 秒内过期（或读不出过期时间）。
pub fn expiring(material: &AdmissionMaterial, now: Timestamp, within: i64) -> bool {
    expiring_payload(&material.policy, now, within)
}

fn expiring_payload(signed: &SignedPayload, now: Timestamp, within: i64) -> bool {
    Payload::parse(&signed.payload).map_or(true, |p| {
        p.expires_at().unix_seconds() < now.unix_seconds() + within
    })
}

/// 宣告的网段：变了就换一个新版本重签；没有网段时不签（节点策略同时去掉 `subnet_router` 角色，成员随之
/// 作废它已生效的宣告）。
fn sign_routes(
    recovery: &RecoveryKeyPair,
    node_id: &NodeId,
    routes: &[IpPrefix],
    old: Option<SignedVersion>,
    last_version: &mut u64,
    expires_at: Timestamp,
) -> Result<Option<SignedVersion>, SiteError> {
    *last_version = (*last_version).max(old.as_ref().map_or(0, |o| o.version));
    if routes.is_empty() {
        return Ok(None);
    }
    let input = hash_of(&routes)?;
    if let Some(old) = old.as_ref().filter(|o| o.input == input) {
        return Ok(Some(old.clone()));
    }
    let version = *last_version + 1;
    *last_version = version;
    let payload = PayloadDoc::EnrollmentPolicy {
        v: 1,
        artifacts: vec![Artifact::AdvertisedRoutes(AdvertisedRoutes {
            node_id: node_id.clone(),
            version,
            routes: routes.to_vec(),
        })],
        expires_at,
    }
    .to_canonical()
    .map_err(SiteError::sign)?;
    Ok(Some(SignedVersion {
        version,
        input,
        signed: recovery.sign(payload).map_err(SiteError::sign)?,
    }))
}

/// 访问规则展开成网段（design/mesh.md 第 12 节），按编号排列：机器是它的组网地址，`<机器>.edge` 是它的
/// Edge 专用地址，`<机器>.routes` 是它宣告的网段。
pub fn expand_rules(state: &State) -> Result<Vec<AccessRule>, SiteError> {
    let host =
        |a: MeshAddresses| vec![IpPrefix::host(a.ipv4.into()), IpPrefix::host(a.ipv6.into())];
    let prefixes = |s: &crate::state::Selector| -> Result<Vec<IpPrefix>, SiteError> {
        let m = state.by_id(&s.node).ok_or_else(|| {
            SiteError::invalid(format!(
                "a rule names node {}, which is not in the site",
                s.node
            ))
        })?;
        Ok(match s.part {
            Part::Mesh => host(m.mesh),
            Part::Edge => host(
                m.edge
                    .as_ref()
                    .ok_or_else(|| SiteError::invalid("a rule names an Edge that does not exist"))?
                    .addresses,
            ),
            Part::Routes => m.routes.clone(),
        })
    };
    let mut rules = Vec::new();
    for rule in state.rules.values() {
        let mut from = Vec::new();
        for s in &rule.from {
            from.extend(prefixes(s)?);
        }
        let mut to = Vec::new();
        for s in &rule.to {
            to.extend(prefixes(s)?);
        }
        rules.push(AccessRule {
            action: RuleAction::Allow,
            from,
            to,
            ports: rule.ports.clone(),
        });
    }
    Ok(rules)
}
