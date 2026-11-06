//! 生成实验材料：钥匙、签名的节点策略、准入证明、各节点的期望状态（design/prototype.md 第 4 节）。
//!
//! 实验中这些钥匙由 `nett-lab` 集中生成，只用于实验。组网进程照常逐项验证，不因为来源是本地文件而跳过检查。

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, ensure};
use nett_core::id::NodeId;
use nett_mesh::config::{Candidate, DesiredMeshDoc, MeshPrefixes, PathDoc, ProbeToken};
use nett_relay::lab::{MemberDoc, RelayConfig};
use nett_trust::admission::{
    AdmissionMaterial, AdmissionProof, AdmissionProofDoc, AdmissionProofKind,
};
use nett_trust::anchors::TrustAnchorsDoc;
use nett_trust::encoding::Timestamp;
use nett_trust::keys::X25519PublicKey;
use nett_trust::payload::{
    Artifact, MeshAddresses, Module, NodeAddresses, NodePolicy, PayloadDoc, Role,
};
use nett_trust::revocation::Revocation;
use nett_trust::signing::{EnrollmentKeyPair, RecoveryKeyPair};
use serde::Serialize;

use crate::cmd;
use crate::net::Underlay;
use crate::topology::Topology;

/// 组网进程的 WireGuard 端口（design/mesh.md 第 4 节的默认值）。
pub const LISTEN_PORT: u16 = 41820;
/// 实验中 nett-relay 的中继端口。
pub const RELAY_PORT: u16 = 41900;

/// 实验材料中记录的节点信息，供场景检查使用。
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct LabNode {
    pub name: String,
    pub node_id: NodeId,
    pub mesh_public_key: X25519PublicKey,
    pub mesh_ipv4: Ipv4Addr,
    pub mesh_ipv6: Ipv6Addr,
    pub dir: PathBuf,
}

/// 场景 14 的反例（design/prototype.md 第 4 节第 5 项），加入第一个节点的期望状态。
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct Negative {
    pub case: String,
    /// 期望被拒绝的节点；格式错误到读不出节点 ID 时为空。
    pub node_id: Option<NodeId>,
}

pub struct Generated {
    pub nodes: Vec<LabNode>,
    pub negatives: Vec<Negative>,
    /// 第一个节点的期望状态（反例都加在这里），场景中改写后用 `SIGHUP` 重新加载。
    pub first_desired: DesiredMeshDoc,
    pub materials: BTreeMap<String, AdmissionMaterial>,
    pub lower_version_of_second: Option<AdmissionMaterial>,
}

fn lab_node_id(index: u32) -> NodeId {
    // 实验用的 ID 固定可复现：全为数字的 ULID 也是合法的规范形式
    format!("node_{index:026}")
        .parse()
        .expect("digits are valid Crockford base32")
}

/// 节点 `i` 的组网地址：组网网段中的第 `i` 个地址。
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

fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", path.display()))
}

fn write_json(path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
    let text = serde_json::to_vec_pretty(value).context("serializing")?;
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
}

/// WireGuard 钥匙对：`wg genkey` / `wg pubkey`。
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
            // 准入验证不检查过期时间；实验中的批准一律视为早已过期，正好覆盖这一点
            expires_at: Timestamp::from_unix_seconds(0),
        }
        .to_canonical()?;
        Ok(AdmissionMaterial {
            policy: self.recovery.sign(payload)?,
            proof: enrollment.sign_proof(&AdmissionProofDoc {
                v: 1,
                kind: AdmissionProofKind::AdmissionProof,
                node_id: policy.node_id.clone(),
                // 实验中没有 nett-node，身份公钥只需要是一个合法的 X25519 公钥
                identity_public_key: mesh_key,
                mesh_public_key: mesh_key,
            })?,
        })
    }
}

fn policy(
    node_id: NodeId,
    version: u64,
    addresses: MeshAddresses,
    roles: &[String],
    enrollment: &EnrollmentKeyPair,
) -> NodePolicy {
    NodePolicy {
        node_id,
        policy_version: version,
        modules: vec![Module::Mesh],
        roles: roles
            .iter()
            .filter(|r| *r == "relay")
            .map(|_| Role::Relay)
            .collect(),
        addresses: NodeAddresses { mesh: addresses },
        enrollment_public_key: enrollment.public_key(),
    }
}

pub fn generate(
    topo: &Topology,
    underlay: &Underlay,
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
    let mut lower_version_of_second = None;
    for (i, node) in topo.nodes.iter().enumerate() {
        let index = u8::try_from(i + 1).context("too many nodes")?;
        let dir = out.join(&node.name);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let (private, public) = wireguard_keypair()?;
        write_private(&dir.join("mesh.key"), private.as_bytes())?;
        let enrollment = EnrollmentKeyPair::generate()?;
        let addresses = mesh_addresses(topo, index)?;
        let node_id = lab_node_id(u32::from(index));
        // 有反例时第二个节点用版本 2，同时附上一份版本 1 的材料作为"低于已生效版本"的反例
        let version = if negatives && i == 1 { 2 } else { 1 };
        let p = policy(
            node_id.clone(),
            version,
            addresses,
            &node.roles,
            &enrollment,
        );
        materials.insert(node.name.clone(), signer.material(&p, &enrollment, public)?);
        if negatives && i == 1 {
            let older = policy(node_id.clone(), 1, addresses, &node.roles, &enrollment);
            lower_version_of_second = Some(signer.material(&older, &enrollment, public)?);
        }
        nodes.push(LabNode {
            name: node.name.clone(),
            node_id,
            mesh_public_key: public,
            mesh_ipv4: addresses.ipv4,
            mesh_ipv6: addresses.ipv6,
            dir,
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

    // 每个（成员，中继）一个探测令牌（design/mesh.md 第 5.2 节）
    let mut tokens: BTreeMap<(String, String), [u8; 32]> = BTreeMap::new();
    for link in &topo.links {
        for relay in link
            .candidates
            .iter()
            .filter_map(|c| c.strip_prefix("relay:"))
        {
            for member in &link.peers {
                tokens
                    .entry((member.clone(), relay.to_owned()))
                    .or_insert_with(random_token);
            }
        }
    }
    write_relay_configs(topo, underlay, &nodes, &tokens)?;

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
                    .filter_map(|c| match c.strip_prefix("relay:") {
                        // 经中继：中继端口在中继节点的公网地址上
                        Some(relay) => Some(Candidate::Relay {
                            relay: nodes.iter().find(|n| n.name == relay)?.node_id.clone(),
                            endpoint: SocketAddr::new(
                                underlay.public_ipv4(relay)?.into(),
                                RELAY_PORT,
                            ),
                            token: ProbeToken(tokens[&(node.name.clone(), relay.to_owned())]),
                        }),
                        // 直连候选：对端在"公网"上时就是它的公网地址；`direct6` 为它的 IPv6 地址
                        None if c == "direct6" => Some(Candidate::Direct {
                            endpoint: SocketAddr::new(
                                underlay.node(other)?.ipv6?.into(),
                                LISTEN_PORT,
                            ),
                        }),
                        None => Some(Candidate::Direct {
                            endpoint: SocketAddr::new(
                                underlay.public_ipv4(other)?.into(),
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
            listen_port: LISTEN_PORT,
            prefixes: MeshPrefixes {
                ipv4: topo.mesh.ipv4,
                ipv6: topo.mesh.ipv6,
            },
            trust_anchors: anchors.clone(),
            members,
            revocations: node_revocations,
            paths,
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

/// 反例：签名错误、信任锚不认识、缺少准入证明、准入证明与组网公钥不符、节点 ID 已被撤销。
/// 每个反例是一个只存在于期望状态中的成员，使用组网网段中靠后的地址。
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
                // 准入证明签名之后换掉其中的组网公钥
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

/// 每个中继节点一份中继分配：经它的连接两端的组网公钥、`public` 一端的地址、各成员的令牌。
fn write_relay_configs(
    topo: &Topology,
    underlay: &Underlay,
    nodes: &[LabNode],
    tokens: &BTreeMap<(String, String), [u8; 32]>,
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
                .any(|c| c.strip_prefix("relay:") == Some(relay.name.as_str()))
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
                    address: underlay
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
        let config = RelayConfig {
            listen: SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), RELAY_PORT),
            members,
            connections,
        };
        let dir = nodes
            .iter()
            .find(|n| n.name == relay.name)
            .context("relay node")?
            .dir
            .clone();
        write_json(&dir.join("relay.json"), &config)?;
    }
    Ok(())
}

/// WireGuard 工具使用的公钥文本（标准 base64）。
pub fn wg_text(key: &X25519PublicKey) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(key.as_bytes())
}

/// 从文件读回 WireGuard 公钥文本（用于核对 `wg show` 的输出）。
pub fn key_from_wg_text(text: &str) -> anyhow::Result<X25519PublicKey> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .ok()
        .context("not a base64 WireGuard key")?;
    let bytes: [u8; 32] = bytes.try_into().ok().context("key length")?;
    Ok(X25519PublicKey::from_bytes(bytes))
}
