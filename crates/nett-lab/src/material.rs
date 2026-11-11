//! Generates lab material: keys, signed node policies, admission proofs, and each node's desired
//! state (design/prototype.md section 4).
//!
//! In lab runs these keys are generated centrally by `nett-lab` and used only for lab runs. The
//! mesh process verifies every item as usual and does not skip checks because the source is a local
//! file.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, ensure};
use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_core::prefix::IpPrefix;
use nett_core::transport::CertFingerprint;
use nett_mesh::config::{
    Candidate, DesiredMeshDoc, MeshPrefixes, PathDoc, ProbeToken, Reachability,
};
use nett_relay::lab::{MemberDoc, RelayConfig, TlsDoc};
use nett_trust::admission::{
    AdmissionMaterial, AdmissionProof, AdmissionProofDoc, AdmissionProofKind,
};
use nett_trust::anchors::TrustAnchorsDoc;
use nett_trust::encoding::Timestamp;
use nett_trust::keys::X25519PublicKey;
use nett_trust::payload::{
    AccessRule, AccessRuleSet, AdvertisedRoutes, Artifact, EdgeSources, MeshAddresses, Module,
    NodeAddresses, NodePolicy, PayloadDoc, Role, RuleAction,
};
use nett_trust::revocation::Revocation;
use nett_trust::signed::SignedPayload;
use nett_trust::signing::{EnrollmentKeyPair, RecoveryKeyPair};
use serde::Serialize;

use crate::cmd;
use crate::net::Underlay;
use crate::topology::{Topology, parse_ports};

/// Addresses used when generating the configuration: lab A takes them from this machine's network
/// plan ([`Underlay`]), lab B from the real addresses written in the topology ([`Topology`],
/// design/prototype.md section 5.2).
pub trait Addresses {
    /// The node's public IPv4 address; `dial-only` nodes have none.
    fn public_ipv4(&self, name: &str) -> Option<Ipv4Addr>;
    /// The node's global IPv6 address.
    fn ipv6(&self, name: &str) -> Option<Ipv6Addr>;
}

impl Addresses for Underlay {
    fn public_ipv4(&self, name: &str) -> Option<Ipv4Addr> {
        Underlay::public_ipv4(self, name)
    }

    fn ipv6(&self, name: &str) -> Option<Ipv6Addr> {
        self.node(name)?.ipv6
    }
}

impl Addresses for Topology {
    fn public_ipv4(&self, name: &str) -> Option<Ipv4Addr> {
        let node = self.node(name)?;
        (node.reachability == nett_mesh::config::Reachability::Public)
            .then_some(node.ipv4)
            .flatten()
    }

    fn ipv6(&self, name: &str) -> Option<Ipv6Addr> {
        self.node(name)?.ipv6
    }
}

/// WireGuard port of `public` nodes (the default in design/mesh.md section 5.5).
pub const LISTEN_PORT: u16 = 41820;
/// Relay port of nett-relay in lab runs.
pub const RELAY_PORT: u16 = 41900;
/// TLS entry of nett-relay (design/mesh.md section 5.3).
pub const RELAY_TLS_PORT: u16 = 443;

/// Candidates `relay:<relay>` and `relay-tls:<relay>`: the relay's name, and whether it goes
/// through TLS.
pub fn relay_of(candidate: &str) -> Option<(&str, bool)> {
    candidate
        .strip_prefix("relay:")
        .map(|r| (r, false))
        .or_else(|| candidate.strip_prefix("relay-tls:").map(|r| (r, true)))
}

/// Node information recorded in the lab material, for scenario checks.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct LabNode {
    pub name: String,
    pub node_id: NodeId,
    pub mesh_public_key: X25519PublicKey,
    pub mesh_ipv4: Ipv4Addr,
    pub mesh_ipv6: Ipv6Addr,
    /// Edge address (IPv4) of a node running Edge.
    #[serde(default)]
    pub edge_ipv4: Option<Ipv4Addr>,
    pub dir: PathBuf,
    /// Has a candidate through TLS: needs a transport adapter.
    #[serde(default)]
    pub tls: bool,
    /// Userspace data plane: there is no kernel WireGuard interface, so `wg show` cannot read it.
    #[serde(default)]
    pub userspace: bool,
}

/// Negative case of scenario 14 (design/prototype.md section 4, item 5), added to the first node's
/// desired state.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct Negative {
    pub case: String,
    /// The node expected to be rejected; empty when the format is so broken that the node ID cannot
    /// be read.
    pub node_id: Option<NodeId>,
}

pub struct Generated {
    pub nodes: Vec<LabNode>,
    pub negatives: Vec<Negative>,
    /// The first node's desired state (the negative cases are all added here); rewritten in the
    /// scenario and reloaded with `SIGHUP`.
    pub first_desired: DesiredMeshDoc,
    pub materials: BTreeMap<String, AdmissionMaterial>,
    pub lower_version_of_second: Option<AdmissionMaterial>,
}

fn lab_node_id(index: u32) -> NodeId {
    // Lab IDs are fixed and reproducible: an all-digit ULID is also a valid canonical form
    format!("node_{index:026}")
        .parse()
        .expect("digits are valid Crockford base32")
}

/// Mesh address of node `i`: the `i`-th address in the mesh prefixes.
fn mesh_addresses(topo: &Topology, index: u8) -> anyhow::Result<MeshAddresses> {
    let (std::net::IpAddr::V4(v4), std::net::IpAddr::V6(v6)) =
        (topo.mesh.ipv4.addr(), topo.mesh.ipv6.addr())
    else {
        anyhow::bail!("mesh ranges must be one IPv4 and one IPv6 prefix");
    };
    Ok(MeshAddresses {
        ipv4: Ipv4Addr::from(u32::from(v4) + u32::from(index)),
        ipv6: Ipv6Addr::from(u128::from(v6) + u128::from(index)),
    })
}

/// Edge address of a node running Edge: the 256th (IPv4) or 65536th (IPv6) after the mesh address,
/// for example `100.88.1.<index>`, `fd00:88::1:<index>`.
fn edge_addresses(topo: &Topology, index: u8) -> anyhow::Result<MeshAddresses> {
    let mesh = mesh_addresses(topo, index)?;
    let edge = MeshAddresses {
        ipv4: Ipv4Addr::from(u32::from(mesh.ipv4) + 256),
        ipv6: Ipv6Addr::from(u128::from(mesh.ipv6) + 0x1_0000),
    };
    ensure!(
        topo.mesh.ipv4.contains(edge.ipv4.into()) && topo.mesh.ipv6.contains(edge.ipv6.into()),
        "the mesh ranges are too small for edge addresses"
    );
    Ok(edge)
}

fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", path.display()))
}

fn write_json(path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
    let text = serde_json::to_vec_pretty(value).context("serializing")?;
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
}

/// WireGuard key pair: `wg genkey` / `wg pubkey`.
fn wireguard_keypair() -> anyhow::Result<(String, X25519PublicKey)> {
    let private = cmd::run("wg", ["genkey"])?;
    let public = cmd::run_with_input(
        "wg",
        ["pubkey"],
        Some(private.as_bytes()),
        cmd::COMMAND_TIMEOUT,
    )?;
    let public = public.trim();
    let bytes: [u8; 32] = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(public)
            .ok()
            .and_then(|b| b.try_into().ok())
            .context("wg pubkey output")?
    };
    Ok((private, X25519PublicKey::from_bytes(bytes)))
}

struct Signer<'a> {
    recovery: &'a RecoveryKeyPair,
}

impl Signer<'_> {
    fn material(
        &self,
        policy: &NodePolicy,
        enrollment: &EnrollmentKeyPair,
        mesh_key: X25519PublicKey,
    ) -> anyhow::Result<AdmissionMaterial> {
        let payload = PayloadDoc::EnrollmentPolicy {
            v: 1,
            artifacts: vec![Artifact::NodePolicy(policy.clone())],
            // Admission verification does not check the expiry time; approvals in lab runs are all
            // treated as long expired, which covers exactly this
            expires_at: Timestamp::from_unix_seconds(0),
        }
        .to_canonical()?;
        Ok(AdmissionMaterial {
            policy: self.recovery.sign(payload)?,
            proof: enrollment.sign_proof(&AdmissionProofDoc {
                v: 1,
                kind: AdmissionProofKind::AdmissionProof,
                node_id: policy.node_id.clone(),
                // There is no nett-node in lab runs; the identity public key only needs to be a
                // valid X25519 public key
                identity_public_key: mesh_key,
                mesh_public_key: mesh_key,
            })?,
        })
    }

    /// The routes a node advertises (auth.md section 10.5).
    fn routes(&self, node_id: &NodeId, routes: &[IpPrefix]) -> anyhow::Result<SignedPayload> {
        let payload = PayloadDoc::EnrollmentPolicy {
            v: 1,
            artifacts: vec![Artifact::AdvertisedRoutes(AdvertisedRoutes {
                node_id: node_id.clone(),
                version: 1,
                routes: routes.to_vec(),
            })],
            expires_at: Timestamp::from_unix_seconds(0),
        }
        .to_canonical()?;
        Ok(self.recovery.sign(payload)?)
    }

    /// The `[[allow]]` entries in the topology expand into one signed access rule set
    /// (design/mesh.md section 12); empty when there are no rules.
    fn access_rules(
        &self,
        topo: &Topology,
        nodes: &[LabNode],
        edges: &BTreeMap<String, MeshAddresses>,
    ) -> anyhow::Result<Option<SignedPayload>> {
        if topo.allows.is_empty() {
            return Ok(None);
        }
        let prefixes = |selector: &str| -> anyhow::Result<Vec<IpPrefix>> {
            if let Some(name) = selector.strip_suffix(".routes") {
                return Ok(topo.node(name).context("node")?.routes.clone());
            }
            let addrs = match selector.strip_suffix(".edge") {
                Some(name) => *edges.get(name).context("edge node")?,
                None => {
                    let n = nodes.iter().find(|n| n.name == selector).context("node")?;
                    MeshAddresses {
                        ipv4: n.mesh_ipv4,
                        ipv6: n.mesh_ipv6,
                    }
                }
            };
            Ok([addrs.ipv4.into(), addrs.ipv6.into()]
                .into_iter()
                .map(IpPrefix::host)
                .collect())
        };
        let mut rules = Vec::new();
        for allow in &topo.allows {
            let mut from = Vec::new();
            for s in &allow.from {
                from.extend(prefixes(s)?);
            }
            let mut to = Vec::new();
            for s in &allow.to {
                to.extend(prefixes(s)?);
            }
            rules.push(AccessRule {
                action: RuleAction::Allow,
                from,
                to,
                ports: allow
                    .ports
                    .iter()
                    .map(|p| parse_ports(p))
                    .collect::<anyhow::Result<_>>()?,
            });
        }
        let payload = PayloadDoc::EnrollmentPolicy {
            v: 1,
            artifacts: vec![Artifact::AccessRuleSet(AccessRuleSet { version: 1, rules })],
            expires_at: Timestamp::from_unix_seconds(0),
        }
        .to_canonical()?;
        Ok(Some(self.recovery.sign(payload)?))
    }
}

/// Node policy; `edge` is the Edge address and the prefix of the container Edge runs in, and when
/// present the `edge` role is added.
fn policy(
    node_id: NodeId,
    version: u64,
    addresses: MeshAddresses,
    roles: &[String],
    edge: Option<(MeshAddresses, &[IpPrefix])>,
    enrollment: &EnrollmentKeyPair,
) -> NodePolicy {
    let mut roles: Vec<Role> = roles
        .iter()
        .filter_map(|r| match r.as_str() {
            "relay" => Some(Role::Relay),
            "subnet_router" => Some(Role::SubnetRouter),
            _ => None,
        })
        .collect();
    if edge.is_some() {
        roles.push(Role::Edge);
    }
    NodePolicy {
        node_id,
        policy_version: version,
        modules: vec![Module::Mesh],
        roles,
        edge: edge.map(|(_, containers)| EdgeSources {
            containers: containers.to_vec(),
        }),
        addresses: NodeAddresses {
            mesh: addresses,
            edge: edge.map(|(a, _)| a),
        },
        enrollment_public_key: enrollment.public_key(),
    }
}

pub fn generate(
    topo: &Topology,
    addresses: &dyn Addresses,
    out: &Path,
    negatives: bool,
) -> anyhow::Result<Generated> {
    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    let recovery = RecoveryKeyPair::generate()?;
    write_private(&out.join("recovery.pk8"), recovery.pkcs8())?;
    let signer = Signer {
        recovery: &recovery,
    };
    let anchors = TrustAnchorsDoc {
        v: 1,
        version: 1,
        rp_id: "hub.example.com".into(),
        origin: "https://hub.example.com".into(),
        passkeys: vec![],
        recovery_key: recovery.doc(),
    };

    let mut nodes = Vec::new();
    let mut materials = BTreeMap::new();
    let mut edges = BTreeMap::new();
    let mut routes = Vec::new();
    let mut lower_version_of_second = None;
    for (i, node) in topo.nodes.iter().enumerate() {
        let index = u8::try_from(i + 1).context("too many nodes")?;
        let dir = out.join(&node.name);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let (private, public) = wireguard_keypair()?;
        write_private(&dir.join("mesh.key"), private.as_bytes())?;
        let enrollment = EnrollmentKeyPair::generate()?;
        let addresses = mesh_addresses(topo, index)?;
        let edge = node
            .edge
            .as_ref()
            .map(|_| edge_addresses(topo, index))
            .transpose()?;
        if let Some(edge) = edge {
            edges.insert(node.name.clone(), edge);
        }
        let node_id = lab_node_id(u32::from(index));
        // With negative cases, the second node uses version 2, and a version 1 material is attached
        // as the "below the version in effect" negative case
        let version = if negatives && i == 1 { 2 } else { 1 };
        let edge_policy = edge.zip(node.edge.as_ref().map(|e| e.containers.as_slice()));
        // A node advertising routes carries the subnet_router role (design/mesh.md section 10)
        let mut roles = node.roles.clone();
        if !node.routes.is_empty() {
            roles.push("subnet_router".to_owned());
            routes.push(signer.routes(&node_id, &node.routes)?);
        }
        let p = policy(
            node_id.clone(),
            version,
            addresses,
            &roles,
            edge_policy,
            &enrollment,
        );
        materials.insert(node.name.clone(), signer.material(&p, &enrollment, public)?);
        if negatives && i == 1 {
            let older = policy(
                node_id.clone(),
                1,
                addresses,
                &roles,
                edge_policy,
                &enrollment,
            );
            lower_version_of_second = Some(signer.material(&older, &enrollment, public)?);
        }
        // Only dial-only members use the TLS transport (design/mesh.md section 5.3)
        let tls = node.reachability == nett_mesh::config::Reachability::DialOnly
            && topo.links.iter().any(|l| {
                l.peers.contains(&node.name)
                    && l.candidates
                        .iter()
                        .any(|c| relay_of(c).is_some_and(|(_, t)| t))
            });
        nodes.push(LabNode {
            name: node.name.clone(),
            node_id,
            mesh_public_key: public,
            mesh_ipv4: addresses.ipv4,
            mesh_ipv6: addresses.ipv6,
            edge_ipv4: edge.map(|e| e.ipv4),
            dir,
            tls,
            userspace: node.userspace,
        });
    }

    let (extra_members, revocations, negative_list) = if negatives {
        ensure!(
            nodes.len() >= 2,
            "admission negatives need at least two nodes"
        );
        let (members, revocations, mut list) = negative_examples(topo, &signer)?;
        list.push(Negative {
            case: "lower-version".into(),
            node_id: Some(nodes[1].node_id.clone()),
        });
        let mut members = members;
        members.extend(lower_version_of_second.clone());
        (members, revocations, list)
    } else {
        (vec![], vec![], vec![])
    };

    // One probe token per (member, relay) (design/mesh.md section 5.2)
    let mut tokens: BTreeMap<(String, String), [u8; 32]> = BTreeMap::new();
    for link in &topo.links {
        for (relay, _) in link.candidates.iter().filter_map(|c| relay_of(c)) {
            for member in &link.peers {
                tokens
                    .entry((member.clone(), relay.to_owned()))
                    .or_insert_with(random_token);
            }
        }
    }
    // Relays with a TLS entry: self-signed certificate, with the fingerprint delivered along with
    // the candidate (design/mesh.md section 5.3)
    let mut fingerprints: BTreeMap<String, CertFingerprint> = BTreeMap::new();
    for (relay, _) in topo
        .links
        .iter()
        .flat_map(|l| &l.candidates)
        .filter_map(|c| relay_of(c))
        .filter(|(_, tls)| *tls)
    {
        if fingerprints.contains_key(relay) {
            continue;
        }
        let dir = nodes
            .iter()
            .find(|n| n.name == relay)
            .context("relay node")?
            .dir
            .clone();
        let ip = addresses.public_ipv4(relay).context("relay address")?;
        fingerprints.insert(relay.to_owned(), self_signed(ip, &dir)?);
    }
    write_relay_configs(topo, addresses, &nodes, &tokens, &fingerprints)?;

    let access_rules = signer.access_rules(topo, &nodes, &edges)?;
    let names: BTreeMap<NodeId, NodeName> = nodes
        .iter()
        .map(|n| Ok((n.node_id.clone(), n.name.parse()?)))
        .collect::<anyhow::Result<_>>()?;
    let mut first_desired = None;
    for (i, node) in topo.nodes.iter().enumerate() {
        let mut members: Vec<AdmissionMaterial> = materials.values().cloned().collect();
        let mut node_revocations = vec![];
        if i == 0 {
            members.extend(extra_members.iter().cloned());
            node_revocations = revocations.clone();
        }
        let paths = topo
            .links
            .iter()
            .filter_map(|link| {
                let other = if link.peers[0] == node.name {
                    &link.peers[1]
                } else if link.peers[1] == node.name {
                    &link.peers[0]
                } else {
                    return None;
                };
                let peer = nodes.iter().find(|n| &n.name == other)?;
                let candidates = link
                    .candidates
                    .iter()
                    .filter_map(|c| match relay_of(c) {
                        // Via relay: the relay port is on the relay node's public address
                        Some((relay, false)) => Some(Candidate::Relay {
                            relay: nodes.iter().find(|n| n.name == relay)?.node_id.clone(),
                            endpoint: SocketAddr::new(
                                addresses.public_ipv4(relay)?.into(),
                                RELAY_PORT,
                            ),
                            token: ProbeToken(tokens[&(node.name.clone(), relay.to_owned())]),
                        }),
                        // TLS transport via relay: TLS entry and certificate fingerprint; the token
                        // is the same as for the UDP relay
                        Some((relay, true)) => Some(Candidate::RelayTls {
                            relay: nodes.iter().find(|n| n.name == relay)?.node_id.clone(),
                            address: SocketAddr::new(
                                addresses.public_ipv4(relay)?.into(),
                                RELAY_TLS_PORT,
                            ),
                            fingerprint: *fingerprints.get(relay)?,
                            token: ProbeToken(tokens[&(node.name.clone(), relay.to_owned())]),
                        }),
                        None if c == "punch" => Some(Candidate::Punch),
                        // Direct candidate: when the peer is on the "public network" it is its
                        // public address; `direct6` is its IPv6 address. Only points to public
                        // nodes: the port of a dial-only node is assigned by the system, and it
                        // connects in by itself
                        None if c == "direct6" => {
                            let public = topo.node(other)?.reachability == Reachability::Public;
                            public.then_some(Candidate::Direct {
                                endpoint: SocketAddr::new(
                                    addresses.ipv6(other)?.into(),
                                    LISTEN_PORT,
                                ),
                            })
                        }
                        None => Some(Candidate::Direct {
                            endpoint: SocketAddr::new(
                                addresses.public_ipv4(other)?.into(),
                                LISTEN_PORT,
                            ),
                        }),
                    })
                    .collect();
                Some(PathDoc {
                    peer: peer.node_id.clone(),
                    peer_reachability: topo.node(other)?.reachability,
                    candidates,
                })
            })
            .collect();
        let doc = DesiredMeshDoc {
            node_id: nodes[i].node_id.clone(),
            reachability: node.reachability,
            // Same as the site tool: public nodes use a fixed port, dial-only nodes are assigned by
            // the system (design/mesh.md section 5.5)
            listen_port: (node.reachability == Reachability::Public).then_some(LISTEN_PORT),
            prefixes: MeshPrefixes {
                ipv4: topo.mesh.ipv4,
                ipv6: topo.mesh.ipv6,
            },
            trust_anchors: anchors.clone(),
            members,
            revocations: node_revocations,
            paths,
            access_rules: access_rules.clone(),
            advertised_routes: routes.clone(),
            names: names.clone(),
            // Lab relays are separate processes with their own assignment file
            relay: None,
        };
        write_json(&nodes[i].dir.join("desired.json"), &doc)?;
        if i == 0 {
            first_desired = Some(doc);
        }
    }
    write_json(&out.join("nodes.json"), &nodes)?;
    write_json(&out.join("negatives.json"), &negative_list)?;
    Ok(Generated {
        nodes,
        negatives: negative_list,
        first_desired: first_desired.context("topology has no nodes")?,
        materials,
        lower_version_of_second,
    })
}

/// Negative cases: wrong signature, unknown trust anchor, missing admission proof, admission proof
/// that does not match the mesh public key, node ID that has been revoked. Each negative case is a
/// member that exists only in the desired state, using a later address in the mesh prefixes.
fn negative_examples(
    topo: &Topology,
    signer: &Signer<'_>,
) -> anyhow::Result<(Vec<AdmissionMaterial>, Vec<Revocation>, Vec<Negative>)> {
    let mut members = Vec::new();
    let mut list = Vec::new();
    let mut revocations = Vec::new();
    let cases = [
        "bad-signature",
        "unknown-anchor",
        "missing-proof",
        "proof-mismatch",
        "revoked",
    ];
    for (k, case) in cases.iter().enumerate() {
        let index = 200 + u8::try_from(k).context("case index")?;
        let node_id = lab_node_id(u32::from(index));
        let enrollment = EnrollmentKeyPair::generate()?;
        let mesh_key = X25519PublicKey::from_bytes([index; 32]);
        let p = policy(
            node_id.clone(),
            1,
            mesh_addresses(topo, index)?,
            &[],
            None,
            &enrollment,
        );
        let mut material = signer.material(&p, &enrollment, mesh_key)?;
        let mut expected = Some(node_id.clone());
        match *case {
            "bad-signature" => {
                if let nett_trust::signed::PayloadSignature::Recovery { signature } =
                    &mut material.policy.signature
                {
                    signature[10] ^= 0x01;
                }
            }
            "unknown-anchor" => {
                let stranger = RecoveryKeyPair::generate()?;
                material.policy = stranger.sign(material.policy.payload.clone())?;
            }
            "missing-proof" => {
                material.proof = AdmissionProof {
                    payload: vec![],
                    signature: [0; 64],
                };
                expected = None;
            }
            "proof-mismatch" => {
                // After the admission proof is signed, swap the mesh public key in it
                let original = mesh_key.to_string();
                let replaced = X25519PublicKey::from_bytes([index ^ 0xff; 32]).to_string();
                let text =
                    String::from_utf8(material.proof.payload.clone()).context("proof utf-8")?;
                material.proof.payload = text.replace(&original, &replaced).into_bytes();
            }
            "revoked" => revocations.push(Revocation::Node {
                node_id: node_id.clone(),
            }),
            _ => unreachable!("listed above"),
        }
        members.push(material);
        list.push(Negative {
            case: (*case).to_owned(),
            node_id: expected,
        });
    }
    Ok((members, revocations, list))
}

fn random_token() -> [u8; 32] {
    let mut token = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut token)
        .expect("the system random source works");
    token
}

/// One relay assignment per relay node: the mesh public keys of both ends of the connections
/// through it, the address of the `public` end, and each member's token.
fn write_relay_configs(
    topo: &Topology,
    addresses: &dyn Addresses,
    nodes: &[LabNode],
    tokens: &BTreeMap<(String, String), [u8; 32]>,
    fingerprints: &BTreeMap<String, CertFingerprint>,
) -> anyhow::Result<()> {
    let key_of = |name: &str| {
        nodes
            .iter()
            .find(|n| n.name == name)
            .map(|n| n.mesh_public_key)
    };
    for relay in topo
        .nodes
        .iter()
        .filter(|n| n.roles.iter().any(|r| r == "relay"))
    {
        let mut members = Vec::new();
        let mut connections = Vec::new();
        for link in topo.links.iter().filter(|l| {
            l.candidates
                .iter()
                .any(|c| relay_of(c).is_some_and(|(r, _)| r == relay.name))
        }) {
            for member in &link.peers {
                if members
                    .iter()
                    .any(|m: &MemberDoc| Some(m.public_key) == key_of(member))
                {
                    continue;
                }
                members.push(MemberDoc {
                    public_key: key_of(member).context("member key")?,
                    address: addresses
                        .public_ipv4(member)
                        .map(|ip| SocketAddr::new(ip.into(), LISTEN_PORT)),
                    token: tokens[&(member.clone(), relay.name.clone())],
                });
            }
            connections.push([
                key_of(&link.peers[0]).context("member key")?,
                key_of(&link.peers[1]).context("member key")?,
            ]);
        }
        let dir = nodes
            .iter()
            .find(|n| n.name == relay.name)
            .context("relay node")?
            .dir
            .clone();
        let tls = fingerprints.contains_key(&relay.name).then(|| TlsDoc {
            listen: SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), RELAY_TLS_PORT),
            cert: dir.join(TLS_CERT),
            key: dir.join(TLS_KEY),
        });
        let config = RelayConfig {
            listen: SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), RELAY_PORT),
            tls,
            members,
            connections,
        };
        write_json(&dir.join("relay.json"), &config)?;
    }
    Ok(())
}

const TLS_CERT: &str = "tls-cert.pem";
const TLS_KEY: &str = "tls-key.pem";

/// Self-signed certificate of the relay (used only in lab runs; in a real deployment the relay node
/// generates it itself, and the private key never leaves the node). Returns the DER of the leaf
/// certificate
/// SHA-256.
pub(crate) fn self_signed(ip: Ipv4Addr, dir: &Path) -> anyhow::Result<CertFingerprint> {
    let (cert, key) = (dir.join(TLS_CERT), dir.join(TLS_KEY));
    cmd::run(
        "openssl",
        [
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "7",
            "-subj",
            "/CN=nett-lab-relay",
            "-addext",
            &format!("subjectAltName=IP:{ip}"),
            "-keyout",
            &key.to_string_lossy(),
            "-out",
            &cert.to_string_lossy(),
        ],
    )?;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {}", key.display()))?;
    let pem =
        std::fs::read_to_string(&cert).with_context(|| format!("reading {}", cert.display()))?;
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .collect();
    use base64::Engine as _;
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .ok()
        .context("certificate PEM is not base64")?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &der);
    let mut fp = [0u8; 32];
    fp.copy_from_slice(digest.as_ref());
    Ok(CertFingerprint(fp))
}

/// Public key text used by the WireGuard tools (standard base64).
pub fn wg_text(key: &X25519PublicKey) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(key.as_bytes())
}

/// Reads a WireGuard public key text back from a file (to check the output of `wg show`).
pub fn key_from_wg_text(text: &str) -> anyhow::Result<X25519PublicKey> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .ok()
        .context("not a base64 WireGuard key")?;
    let bytes: [u8; 32] = bytes.try_into().ok().context("key length")?;
    Ok(X25519PublicKey::from_bytes(bytes))
}

/// Lab B (design/prototype.md section 5.2): generates each node's configuration from the real
/// addresses written in the topology and distributes it to the respective machines to run. Every
/// node needs an SSH host name, and `public` nodes need a public address; the relay's TLS entry is
/// not generated here (the certificate path in the configuration is a path on the local machine).
pub fn generate_remote(topo: &Topology, out: &Path) -> anyhow::Result<Generated> {
    for node in &topo.nodes {
        ensure!(
            node.ssh.is_some() && node.behind.is_none(),
            "node `{}` needs `ssh` and no `behind` in a real-machine topology",
            node.name
        );
        ensure!(
            node.reachability != nett_mesh::config::Reachability::Public
                || node.ipv4.is_some()
                || node.ipv6.is_some(),
            "public node `{}` needs `ipv4` or `ipv6`",
            node.name
        );
    }
    ensure!(
        topo.links
            .iter()
            .flat_map(|l| &l.candidates)
            .all(|c| !relay_of(c).is_some_and(|(_, tls)| tls)),
        "real-machine topologies do not support `relay-tls:` candidates yet"
    );
    generate(topo, topo, out, false)
}
