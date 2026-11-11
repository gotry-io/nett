//! Signing (design/site.md section 7): an artifact whose content changed gets its version
//! incremented and is re-signed; an unchanged one keeps its signature; a signed node policy less
//! than 7 days from expiry is re-signed with a new version. Narrowing is also signed with a higher
//! version: nodes reject older versions because versions only increase (design/mesh.md section
//! 4.2), so replaying an old signed artifact cannot restore a narrowed permission.
//!
//! The hash of the inputs equals that of the sites this tool took over (the fields and order of the
//! node policy inputs and the way access rules are expanded are unchanged), so an existing site
//! does not need to be re-signed after switching over.

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

/// Expiry time of a signed payload: 30 days after generation (design/local-signing.md section 5).
pub const PAYLOAD_VALIDITY_SECS: i64 = 30 * 24 * 3600;
/// A signed node policy closer to expiry than this is re-signed with a new version.
pub const RESIGN_BEFORE_SECS: i64 = 7 * 24 * 3600;

/// Inputs that generate the node policy and admission proof; when their hash is unchanged, the
/// existing signature is reused.
#[derive(Serialize)]
struct PolicyInput {
    mesh_key: X25519PublicKey,
    identity_key: X25519PublicKey,
    roles: Vec<Role>,
    edge_sources: Option<EdgeSources>,
    mesh: MeshAddresses,
    edge: Option<MeshAddresses>,
}

/// Node policy inputs of a machine waiting to join through the Hub (design/hub.md section 6): the
/// public key is handed over by the machine when it joins, and the policy carries the enrollment
/// public key.
#[derive(Serialize)]
struct PendingInput {
    enrollment_key: Ed25519PublicKey,
    roles: Vec<Role>,
    edge_sources: Option<EdgeSources>,
    mesh: MeshAddresses,
    edge: Option<MeshAddresses>,
}

/// Signs the artifacts in the site that changed. Machines in `force` get a new version of the node
/// policy even if nothing changed and expiry is not near (`nett site invite`: the copy that had
/// already expired before it was copied over).
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
            // Waiting to join: the policy carries the enrollment public key, and the admission
            // proof is signed by the machine when it joins (design/hub.md section 6)
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

/// Artifacts whose signing would change the version: node policies whose inputs changed, advertised
/// routes and the access rule set. After migrating an existing site, this confirms no re-signing is
/// needed.
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

/// Roles in the node policy: `edge` when there is an Edge, `subnet_router` when there are
/// advertised routes.
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

/// Hash of the node policy inputs after a machine that joined through the Hub delivers its
/// admission proof: uses the same kind of inputs as machines signed by the signing tool itself,
/// with content taken from the verified admission material. Afterwards, when the site has no
/// changes, this material is reused.
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

/// Payload of the node policy.
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

/// Signs the node policy with the recovery key and the admission proof with an enrollment key used
/// only once (design/local-signing.md section 3).
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

/// The signed node policy expires within `within` seconds (or its expiry time cannot be read).
pub fn expiring(material: &AdmissionMaterial, now: Timestamp, within: i64) -> bool {
    expiring_payload(&material.policy, now, within)
}

fn expiring_payload(signed: &SignedPayload, now: Timestamp, within: i64) -> bool {
    Payload::parse(&signed.payload).map_or(true, |p| {
        p.expires_at().unix_seconds() < now.unix_seconds() + within
    })
}

/// Advertised routes: re-signed with a new version when changed; not signed when there are no
/// routes (the node policy drops the `subnet_router` role at the same time, and members invalidate
/// the advertisement that had taken effect).
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

/// Access rules expanded into prefixes (design/mesh.md section 12), ordered by number: a machine is
/// its mesh address, `<machine>.edge` is its Edge address, and `<machine>.routes` is the routes it
/// advertises.
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
