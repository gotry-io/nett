//! 站点状态（design/site.md 第 8 节）：机器、权限、访问规则，以及已签的产物与它们的版本。没有私钥：
//! 恢复密钥在站点目录中另存一个文件，只在签名时读取。

use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_core::prefix::IpPrefix;
use nett_mesh::config::{MAX_MEMBERS, MeshPrefixes, Reachability, is_reserved_port};
use nett_trust::admission::AdmissionMaterial;
use nett_trust::anchors::TrustAnchorsDoc;
use nett_trust::encoding::Sha256Digest;
use nett_trust::keys::X25519PublicKey;
use nett_trust::payload::{MeshAddresses, PortRange};
use nett_trust::signed::SignedPayload;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::SiteError;

/// 站点状态的格式版本。
pub const FORMAT_V1: u32 = 1;
/// `public` 机器默认的 WireGuard 端口。
pub const DEFAULT_LISTEN_PORT: u16 = 41820;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub v: u32,
    pub trust_anchors: TrustAnchorsDoc,
    /// 组网网段：建立站点时确定，之后不能改。
    pub prefixes: MeshPrefixes,
    /// `public` 机器默认的 WireGuard 端口。
    pub listen_port: u16,
    /// 下一个分配的地址是组网网段中的第几个。地址不回收（design/mesh.md 第 3 节）。
    pub next_host: u32,
    /// 下一条规则的编号。编号不复用（design/site.md 第 5.1 节）。
    pub next_rule: u32,
    #[serde(default)]
    pub machines: BTreeMap<NodeName, Machine>,
    #[serde(default)]
    pub rules: BTreeMap<RuleId, Rule>,
    /// 移除的机器：撤销永久生效，地址不再分配。
    #[serde(default)]
    pub revoked: Vec<Revoked>,
    /// 签名的访问规则集。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_rules: Option<SignedVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Machine {
    pub node_id: NodeId,
    pub reachability: Reachability,
    /// `public` 机器的公网地址。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<Ipv6Addr>,
    /// `public` 机器自己的 WireGuard 端口；没有时用站点默认的端口。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// 机器的公钥：不接 Hub 时由 `add --keys` 写明。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<NodeKeys>,
    /// 组网地址。
    pub mesh: MeshAddresses,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge: Option<Edge>,
    /// 宣告的网段。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<IpPrefix>,
    /// 签名的节点策略与准入证明。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<SignedPolicy>,
    /// 签名的宣告网段。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes_signed: Option<SignedVersion>,
}

impl Machine {
    /// `public` 机器的 WireGuard 端口。
    pub fn listen_port(&self, default: u16) -> Option<u16> {
        (self.reachability == Reachability::Public).then(|| self.port.unwrap_or(default))
    }
}

/// 机器上 `nett keys`（或 `sudo nett install`）打印的一行：组网公钥与身份公钥。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeKeys {
    pub mesh: X25519PublicKey,
    pub identity: X25519PublicKey,
}

impl FromStr for NodeKeys {
    type Err = SiteError;

    fn from_str(s: &str) -> Result<Self, SiteError> {
        let mut parts = s.split_whitespace();
        let (Some(mesh), Some(identity), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(SiteError::invalid(
                "--keys takes the two public keys printed by `nett keys` or `sudo nett install`, \
                 separated by a space",
            ));
        };
        let key = |k: &str| {
            k.parse::<X25519PublicKey>()
                .map_err(|e| SiteError::invalid(format!("--keys: {e}")))
        };
        Ok(Self {
            mesh: key(mesh)?,
            identity: key(identity)?,
        })
    }
}

/// 机器上的 Edge：Edge 所在容器的地址，以及分配给它的 Edge 专用地址（ADR 0015）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub containers: Vec<IpPrefix>,
    pub addresses: MeshAddresses,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicy {
    pub version: u64,
    /// 生成节点策略和准入证明的输入的哈希：不变时沿用原来的签名。
    pub input: Sha256Digest,
    pub material: AdmissionMaterial,
}

/// 一份带版本号的签名产物：版本、输入的哈希与签名的载荷。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedVersion {
    pub version: u64,
    pub input: Sha256Digest,
    pub signed: SignedPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revoked {
    pub name: NodeName,
    pub node_id: NodeId,
}

/// 一条访问规则：只有放行（design/site.md 第 5.1 节）。两边按机器 ID 记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub from: Vec<Selector>,
    pub to: Vec<Selector>,
    /// 不写时为全部端口。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Part {
    /// 机器的组网地址。
    Mesh,
    /// 机器的 Edge 专用地址。
    Edge,
    /// 机器宣告的网段。
    Routes,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    pub node: NodeId,
    pub part: Part,
}

/// 规则的编号：`r1`、`r2`……
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(pub u32);

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r{}", self.0)
    }
}

impl FromStr for RuleId {
    type Err = SiteError;

    fn from_str(s: &str) -> Result<Self, SiteError> {
        s.strip_prefix('r')
            .and_then(|n| n.parse().ok())
            .map(Self)
            .ok_or_else(|| SiteError::invalid(format!("`{s}` is not a rule ID such as r3")))
    }
}

impl Serialize for RuleId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for RuleId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl State {
    pub fn new(trust_anchors: TrustAnchorsDoc, prefixes: MeshPrefixes) -> Self {
        Self {
            v: FORMAT_V1,
            trust_anchors,
            prefixes,
            listen_port: DEFAULT_LISTEN_PORT,
            next_host: 1,
            next_rule: 1,
            machines: BTreeMap::new(),
            rules: BTreeMap::new(),
            revoked: Vec::new(),
            access_rules: None,
        }
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, SiteError> {
        let state: Self = serde_json::from_slice(bytes)
            .map_err(|e| SiteError::invalid(format!("state.json: {e}")))?;
        if state.v != FORMAT_V1 {
            return Err(SiteError::invalid(format!(
                "state.json: unsupported format version {}",
                state.v
            )));
        }
        state.check()?;
        Ok(state)
    }

    pub fn machine(&self, name: &NodeName) -> Result<&Machine, SiteError> {
        self.machines
            .get(name)
            .ok_or_else(|| SiteError::invalid(format!("there is no machine `{name}`")))
    }

    pub fn machine_mut(&mut self, name: &NodeName) -> Result<&mut Machine, SiteError> {
        self.machines
            .get_mut(name)
            .ok_or_else(|| SiteError::invalid(format!("there is no machine `{name}`")))
    }

    /// 节点 ID 对应的机器名。
    pub fn name_of(&self, node: &NodeId) -> Option<&NodeName> {
        self.machines
            .iter()
            .find(|(_, m)| m.node_id == *node)
            .map(|(name, _)| name)
    }

    pub fn by_id(&self, node: &NodeId) -> Option<&Machine> {
        self.machines.values().find(|m| m.node_id == *node)
    }

    /// 选择器的文本形式：`mac`、`edge-vps.edge`、`mac-app.routes`。
    pub fn selector_text(&self, s: &Selector) -> String {
        let name = self
            .name_of(&s.node)
            .map_or_else(|| s.node.to_string(), ToString::to_string);
        match s.part {
            Part::Mesh => name,
            Part::Edge => format!("{name}.edge"),
            Part::Routes => format!("{name}.routes"),
        }
    }

    /// 站点内部的一致性：每条修改命令之后、读出站点状态之后检查（design/site.md 第 7 节）。
    pub fn check(&self) -> Result<(), SiteError> {
        if self.machines.len() > MAX_MEMBERS {
            return Err(SiteError::invalid(format!(
                "a site holds at most {MAX_MEMBERS} machines"
            )));
        }
        for (name, m) in &self.machines {
            match m.reachability {
                Reachability::Public if m.ipv4.is_none() && m.ipv6.is_none() => {
                    return Err(SiteError::invalid(format!(
                        "public machine `{name}` needs --ipv4 or --ipv6: other members dial it there"
                    )));
                }
                Reachability::DialOnly
                    if m.ipv4.is_some() || m.ipv6.is_some() || m.port.is_some() =>
                {
                    return Err(SiteError::invalid(format!(
                        "dial-only machine `{name}` takes no public address or port: nobody dials it, \
                         and the system picks its WireGuard port; a machine others connect to is --public"
                    )));
                }
                _ => {}
            }
            if let Some(port) = m.listen_port(self.listen_port)
                && (port == 0 || is_reserved_port(port))
            {
                return Err(SiteError::invalid(format!(
                    "machine `{name}`: WireGuard port {port} is 0 or one nett itself uses on the host; \
                     pick another with --port"
                )));
            }
            if let Some(edge) = &m.edge
                && edge.containers.is_empty()
            {
                return Err(SiteError::invalid(format!(
                    "machine `{name}`: an Edge needs the address of its container"
                )));
            }
            let overlaps = |a: &IpPrefix, b: &IpPrefix| a.covers(b) || b.covers(a);
            for route in &m.routes {
                if overlaps(route, &self.prefixes.ipv4) || overlaps(route, &self.prefixes.ipv6) {
                    return Err(SiteError::invalid(format!(
                        "machine `{name}`: route {route} overlaps the mesh prefixes"
                    )));
                }
                if let Some((other, _)) = self.machines.iter().find(|(o, other)| {
                    *o != name && other.routes.iter().any(|r| overlaps(r, route))
                }) {
                    return Err(SiteError::invalid(format!(
                        "machine `{name}`: route {route} overlaps a route of `{other}`"
                    )));
                }
            }
        }
        // 公网地址加端口是其他成员连它的地方，两台机器不能相同
        let mut endpoints = BTreeMap::new();
        for (name, m) in &self.machines {
            let Some(port) = m.listen_port(self.listen_port) else {
                continue;
            };
            for ip in [
                m.ipv4.map(std::net::IpAddr::V4),
                m.ipv6.map(std::net::IpAddr::V6),
            ]
            .into_iter()
            .flatten()
            {
                if let Some(other) = endpoints.insert((ip, port), name) {
                    return Err(SiteError::invalid(format!(
                        "`{other}` and `{name}` both listen on {ip} port {port}; give one of them \
                         another --port"
                    )));
                }
            }
        }
        for (id, rule) in &self.rules {
            if rule.from.is_empty() || rule.to.is_empty() {
                return Err(SiteError::invalid(format!("rule {id} has an empty side")));
            }
            for s in rule.from.iter().chain(&rule.to) {
                let Some(m) = self.by_id(&s.node) else {
                    return Err(SiteError::invalid(format!(
                        "rule {id} names node {}, which is not in the site",
                        s.node
                    )));
                };
                let ok = match s.part {
                    Part::Mesh => true,
                    Part::Edge => m.edge.is_some(),
                    Part::Routes => !m.routes.is_empty(),
                };
                if !ok {
                    return Err(SiteError::invalid(format!(
                        "rule {id} names {}, which does not exist",
                        self.selector_text(s)
                    )));
                }
            }
        }
        Ok(())
    }
}
