//! 生成实验材料：钥匙、签名的节点策略、准入证明、各节点的期望状态（design/prototype.md 第 4 节）。
//!
//! 实验中这些钥匙由 `nett-lab` 集中生成，只用于实验。组网进程照常逐项验证，不因为来源是本地文件而跳过检查。

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, ensure};
use nett_core::id::NodeId;
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

/// 生成配置时用到的地址：实验 A 取自本机的网络规划（[`Underlay`]），实验 B 取自拓扑中写明的真实
/// 地址（[`Topology`]，design/prototype.md 第 5.2 节）。
pub trait Addresses {
    /// 节点的公网 IPv4 地址；`dial-only` 的节点没有。
    fn public_ipv4(&self, name: &str) -> Option<Ipv4Addr>;
    /// 节点的全局 IPv6 地址。
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

/// `public` 节点的 WireGuard 端口（design/mesh.md 第 5.5 节的默认值）。
pub const LISTEN_PORT: u16 = 41820;
/// 实验中 nett-relay 的中继端口。
pub const RELAY_PORT: u16 = 41900;
/// nett-relay 的 TLS 入口（design/mesh.md 第 5.3 节）。
pub const RELAY_TLS_PORT: u16 = 443;

/// 候选 `relay:<中继>` 与 `relay-tls:<中继>`：中继的名称，以及是否经 TLS。
pub fn relay_of(candidate: &str) -> Option<(&str, bool)> {
    candidate
        .strip_prefix("relay:")
        .map(|r| (r, false))
        .or_else(|| candidate.strip_prefix("relay-tls:").map(|r| (r, true)))
}

/// 实验材料中记录的节点信息，供场景检查使用。
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct LabNode {
    pub name: String,
    pub node_id: NodeId,
    pub mesh_public_key: X25519PublicKey,
    pub mesh_ipv4: Ipv4Addr,
    pub mesh_ipv6: Ipv6Addr,
    /// 运行 Edge 的节点的 Edge 专用地址（IPv4）。
    #[serde(default)]
    pub edge_ipv4: Option<Ipv4Addr>,
    pub dir: PathBuf,
    /// 有经 TLS 的候选：需要传输适配进程。
    #[serde(default)]
    pub tls: bool,
    /// 用户态数据面：没有内核 WireGuard 接口，`wg show` 读不到它。
    #[serde(default)]
    pub userspace: bool,
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

/// 运行 Edge 的节点的 Edge 专用地址：组网地址之后第 256 个（IPv4）、第 65536 个（IPv6），
/// 例如 `100.88.1.<序号>`、`fd00:88::1:<序号>`。
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

    /// 一个节点宣告的网段（auth.md 第 10.5 节）。
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

    /// 拓扑中的 `[[allow]]` 展开成一份签名的访问规则集（design/mesh.md 第 12 节）；没有规则时为空。
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

/// 节点策略；`edge` 是 Edge 专用地址与 Edge 所在容器的网段，有它时加上 `edge` 角色。
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
        // 有反例时第二个节点用版本 2，同时附上一份版本 1 的材料作为"低于已生效版本"的反例
        let version = if negatives && i == 1 { 2 } else { 1 };
        let edge_policy = edge.zip(node.edge.as_ref().map(|e| e.containers.as_slice()));
        // 宣告网段的节点带 subnet_router 角色（design/mesh.md 第 10 节）
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
        // 只有 dial-only 成员经 TLS 传输（design/mesh.md 第 5.3 节）
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

    // 每个（成员，中继）一个探测令牌（design/mesh.md 第 5.2 节）
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
    // 有 TLS 入口的中继：自签证书，指纹随候选下发（design/mesh.md 第 5.3 节）
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
                        // 经中继：中继端口在中继节点的公网地址上
                        Some((relay, false)) => Some(Candidate::Relay {
                            relay: nodes.iter().find(|n| n.name == relay)?.node_id.clone(),
                            endpoint: SocketAddr::new(
                                addresses.public_ipv4(relay)?.into(),
                                RELAY_PORT,
                            ),
                            token: ProbeToken(tokens[&(node.name.clone(), relay.to_owned())]),
                        }),
                        // 经中继的 TLS 传输：TLS 入口与证书指纹，令牌与 UDP 中继相同
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
                        // 直连候选：对端在"公网"上时就是它的公网地址；`direct6` 为它的 IPv6 地址。
                        // 只指向 public 节点：dial-only 节点的端口由系统分配，由它主动连过来
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
            // 与站点工具相同：public 节点用固定端口，dial-only 节点由系统分配（design/mesh.md 第 5.5 节）
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

/// 中继的自签证书（只用于实验；正式部署中由中继节点自己生成，私钥不离开节点）。返回叶证书 DER 的
/// SHA-256。
fn self_signed(ip: Ipv4Addr, dir: &Path) -> anyhow::Result<CertFingerprint> {
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

/// 实验 B（design/prototype.md 第 5.2 节）：按拓扑中写明的真实地址生成各节点的配置，分发到各自的机器上
/// 运行。每个节点都要有 SSH 主机名，`public` 节点要有公网地址；中继的 TLS 入口不在这里生成（配置中
/// 的证书路径是本机路径）。
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
