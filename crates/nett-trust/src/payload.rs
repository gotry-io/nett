//! 签名载荷与其中的产物（design/auth.md 第 10.1、10.5 节）。

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::canonical::{CanonicalError, parse_canonical, to_canonical};
use crate::encoding::{Sha256Digest, Timestamp};
use crate::keys::Ed25519PublicKey;
use nett_core::id::{ChangeId, NodeId};
use nett_core::prefix::IpPrefix;
use serde::{Deserialize, Serialize};

/// 载荷格式的版本。
pub const PAYLOAD_V1: u64 = 1;

/// 一份访问规则集最多的规则数，以及每条规则中网段和端口范围的上限（硬性规则 14）。
pub const MAX_ACCESS_RULES: usize = 1024;
pub const MAX_RULE_PREFIXES: usize = 256;
pub const MAX_RULE_PORTS: usize = 64;
/// Edge 所在容器的网段数的上限。
pub const MAX_EDGE_CONTAINERS: usize = 16;
/// 一个节点宣告的网段数的上限。
pub const MAX_ADVERTISED_ROUTES: usize = 64;

/// 签名载荷的文档形式。控制台（以及实验工具）按它生成，验证方按它解析。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PayloadDoc {
    ChangeApproval {
        v: u64,
        change_id: ChangeId,
        plan_hash: Sha256Digest,
        artifacts: Vec<Artifact>,
        expires_at: Timestamp,
    },
    EnrollmentPolicy {
        v: u64,
        artifacts: Vec<Artifact>,
        expires_at: Timestamp,
    },
}

/// 需要下发给节点、由节点独立验证的产物。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Artifact {
    NodePolicy(NodePolicy),
    AccessRuleSet(AccessRuleSet),
    AdvertisedRoutes(AdvertisedRoutes),
}

/// 节点策略，字段与 `node-policies` 资源一致（design/api-resources.md 第 5.2 节）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodePolicy {
    pub node_id: NodeId,
    pub policy_version: u64,
    pub modules: Vec<Module>,
    pub roles: Vec<Role>,
    /// 有 `edge` 角色时，怎样识别 Edge 发出的流量（ADR 0015）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge: Option<EdgeSources>,
    pub addresses: NodeAddresses,
    pub enrollment_public_key: Ed25519PublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Module {
    Mesh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Relay,
    Edge,
    /// 智能入口：宣告网段并转发（design/mesh.md 第 10 节）。
    SubnetRouter,
}

/// Edge 发出的流量从哪里来：Edge 所在容器的网段。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeSources {
    pub containers: Vec<IpPrefix>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAddresses {
    pub mesh: MeshAddresses,
    /// Edge 专用地址，只在有 `edge` 角色时出现。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge: Option<MeshAddresses>,
}

/// 一个智能入口宣告的网段（design/mesh.md 第 10 节），版本号只增不减。只有节点策略中有 `subnet_router`
/// 角色的节点，它的宣告才被接受。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvertisedRoutes {
    pub node_id: NodeId,
    pub version: u64,
    pub routes: Vec<IpPrefix>,
}

/// 访问规则集（design/mesh.md 第 12 节）：选择器展开后的网段和端口，按数组顺序匹配。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRuleSet {
    pub version: u64,
    pub rules: Vec<AccessRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRule {
    pub action: RuleAction,
    pub from: Vec<IpPrefix>,
    pub to: Vec<IpPrefix>,
    /// 为空表示所有协议和端口。
    pub ports: Vec<PortRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortRange {
    pub protocol: Protocol,
    pub first: u16,
    pub last: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshAddresses {
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    #[error("payload: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("payload: invalid document: {0}")]
    Document(String),
    #[error("payload: unsupported format version {0}")]
    Format(u64),
    #[error("payload: fields are not in their single canonical text form")]
    NonCanonicalFields,
    #[error("payload: node policy for {0} lists a module or role twice")]
    DuplicateEntry(NodeId),
    #[error("payload: node policy for {0} has a mesh address that is not a unicast address")]
    Address(NodeId),
    #[error("payload: carries more than one node policy for {0}")]
    DuplicatePolicy(NodeId),
    #[error(
        "payload: node policy for {0} must have the edge role, the edge sources and the edge \
         addresses together, with unicast edge addresses that differ from the mesh addresses"
    )]
    Edge(NodeId),
    #[error("payload: access rule set: {0}")]
    AccessRules(&'static str),
    #[error("payload: carries more than one access rule set")]
    DuplicateRuleSet,
    #[error("payload: advertised routes of {0}: {1}")]
    Routes(NodeId, &'static str),
    #[error("payload: carries more than one set of advertised routes for {0}")]
    DuplicateRoutes(NodeId),
}

/// 已解析、已校验格式的签名载荷（签名由 [`crate::signed`] 验证）。
#[derive(Debug, Clone)]
pub struct Payload {
    doc: PayloadDoc,
    hash: Sha256Digest,
    artifact_hashes: Vec<Sha256Digest>,
}

impl Payload {
    /// 从签名覆盖的字节解析。字节必须是规范形式；不认识的字段、种类和产物整份拒绝。
    pub fn parse(bytes: &[u8]) -> Result<Self, PayloadError> {
        let value = parse_canonical(bytes)?;
        let doc =
            PayloadDoc::deserialize(&value).map_err(|e| PayloadError::Document(e.to_string()))?;
        // 序列化回去必须得到同一份文档：地址、键等字段因此只有一种文本形式
        let round_trip =
            serde_json::to_value(&doc).map_err(|e| PayloadError::Document(e.to_string()))?;
        if round_trip != value {
            return Err(PayloadError::NonCanonicalFields);
        }
        let artifacts = doc.artifacts();
        let version = match &doc {
            PayloadDoc::ChangeApproval { v, .. } | PayloadDoc::EnrollmentPolicy { v, .. } => *v,
        };
        if version != PAYLOAD_V1 {
            return Err(PayloadError::Format(version));
        }
        let mut artifact_hashes = Vec::with_capacity(artifacts.len());
        for (i, artifact) in artifacts.iter().enumerate() {
            match artifact {
                Artifact::NodePolicy(policy) => {
                    policy.validate()?;
                    let duplicate = artifacts[..i].iter().any(|other| {
                        matches!(other, Artifact::NodePolicy(o) if o.node_id == policy.node_id)
                    });
                    if duplicate {
                        return Err(PayloadError::DuplicatePolicy(policy.node_id.clone()));
                    }
                }
                Artifact::AccessRuleSet(rules) => {
                    rules.validate()?;
                    if artifacts[..i]
                        .iter()
                        .any(|other| matches!(other, Artifact::AccessRuleSet(_)))
                    {
                        return Err(PayloadError::DuplicateRuleSet);
                    }
                }
                Artifact::AdvertisedRoutes(routes) => {
                    routes.validate()?;
                    let duplicate = artifacts[..i].iter().any(|other| {
                        matches!(other, Artifact::AdvertisedRoutes(o) if o.node_id == routes.node_id)
                    });
                    if duplicate {
                        return Err(PayloadError::DuplicateRoutes(routes.node_id.clone()));
                    }
                }
            }
            artifact_hashes.push(artifact_hash(artifact)?);
        }
        Ok(Self {
            doc,
            hash: Sha256Digest::of(bytes),
            artifact_hashes,
        })
    }

    pub fn doc(&self) -> &PayloadDoc {
        &self.doc
    }

    /// 载荷字节的 SHA-256，即 WebAuthn 的 challenge。
    pub fn hash(&self) -> &Sha256Digest {
        &self.hash
    }

    pub fn expires_at(&self) -> Timestamp {
        match &self.doc {
            PayloadDoc::ChangeApproval { expires_at, .. }
            | PayloadDoc::EnrollmentPolicy { expires_at, .. } => *expires_at,
        }
    }

    /// 载荷中的产物及其哈希（产物对象规范形式的 SHA-256）。
    pub fn artifacts(&self) -> impl Iterator<Item = (&Sha256Digest, &Artifact)> {
        self.artifact_hashes.iter().zip(self.doc.artifacts())
    }

    pub fn node_policy(&self, node_id: &NodeId) -> Option<(&Sha256Digest, &NodePolicy)> {
        self.artifacts()
            .find_map(|(hash, artifact)| match artifact {
                Artifact::NodePolicy(policy) if policy.node_id == *node_id => Some((hash, policy)),
                _ => None,
            })
    }

    pub fn access_rule_set(&self) -> Option<(&Sha256Digest, &AccessRuleSet)> {
        self.artifacts()
            .find_map(|(hash, artifact)| match artifact {
                Artifact::AccessRuleSet(rules) => Some((hash, rules)),
                _ => None,
            })
    }

    /// 载荷中的全部宣告网段产物。
    pub fn advertised_routes(&self) -> impl Iterator<Item = (&Sha256Digest, &AdvertisedRoutes)> {
        self.artifacts()
            .filter_map(|(hash, artifact)| match artifact {
                Artifact::AdvertisedRoutes(routes) => Some((hash, routes)),
                _ => None,
            })
    }
}

impl PayloadDoc {
    pub fn artifacts(&self) -> &[Artifact] {
        match self {
            PayloadDoc::ChangeApproval { artifacts, .. }
            | PayloadDoc::EnrollmentPolicy { artifacts, .. } => artifacts,
        }
    }

    /// 规范形式的字节，即要签名的内容。
    pub fn to_canonical(&self) -> Result<Vec<u8>, PayloadError> {
        let value =
            serde_json::to_value(self).map_err(|e| PayloadError::Document(e.to_string()))?;
        Ok(to_canonical(&value)?)
    }
}

impl NodePolicy {
    fn validate(&self) -> Result<(), PayloadError> {
        if has_duplicates(&self.modules) || has_duplicates(&self.roles) {
            return Err(PayloadError::DuplicateEntry(self.node_id.clone()));
        }
        if !self.addresses.mesh.is_unicast() {
            return Err(PayloadError::Address(self.node_id.clone()));
        }
        let edge_ok = match (self.has_role(Role::Edge), &self.edge, &self.addresses.edge) {
            (false, None, None) => true,
            (true, Some(sources), Some(edge)) => {
                !sources.containers.is_empty()
                    && sources.containers.len() <= MAX_EDGE_CONTAINERS
                    && edge.is_unicast()
                    && edge.ipv4 != self.addresses.mesh.ipv4
                    && edge.ipv6 != self.addresses.mesh.ipv6
            }
            _ => false,
        };
        if edge_ok {
            Ok(())
        } else {
            Err(PayloadError::Edge(self.node_id.clone()))
        }
    }

    pub fn has_module(&self, module: Module) -> bool {
        self.modules.contains(&module)
    }

    pub fn has_role(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }
}

impl MeshAddresses {
    fn is_unicast(&self) -> bool {
        let Self { ipv4, ipv6 } = *self;
        let ipv4_ok = !(ipv4.is_unspecified()
            || ipv4.is_loopback()
            || ipv4.is_multicast()
            || ipv4.is_broadcast());
        let ipv6_ok = !(ipv6.is_unspecified() || ipv6.is_loopback() || ipv6.is_multicast());
        ipv4_ok && ipv6_ok
    }
}

impl AdvertisedRoutes {
    fn validate(&self) -> Result<(), PayloadError> {
        let err = |why| Err(PayloadError::Routes(self.node_id.clone(), why));
        if self.version == 0 {
            return err("the version starts at 1");
        }
        if self.routes.is_empty() || self.routes.len() > MAX_ADVERTISED_ROUTES {
            return err("needs between 1 and 64 prefixes");
        }
        for route in &self.routes {
            // 默认路由会把对端的全部流量引进组网；回环、组播、链路本地地址不是可以宣告的网段
            let special = match route.addr() {
                std::net::IpAddr::V4(a) => {
                    a.is_loopback() || a.is_multicast() || a.is_link_local() || a.is_unspecified()
                }
                std::net::IpAddr::V6(a) => {
                    a.is_loopback()
                        || a.is_multicast()
                        || a.is_unspecified()
                        || (a.segments()[0] & 0xffc0) == 0xfe80
                }
            };
            if route.prefix_len() == 0 || special {
                return err(
                    "a default route, loopback, multicast or link-local prefix cannot be advertised",
                );
            }
        }
        Ok(())
    }
}

impl AccessRuleSet {
    fn validate(&self) -> Result<(), PayloadError> {
        let err = PayloadError::AccessRules;
        if self.version == 0 {
            return Err(err("the version starts at 1"));
        }
        if self.rules.len() > MAX_ACCESS_RULES {
            return Err(err("too many rules"));
        }
        for rule in &self.rules {
            if rule.from.is_empty() || rule.to.is_empty() {
                return Err(err("a rule needs at least one source and one destination"));
            }
            if rule.from.len() > MAX_RULE_PREFIXES || rule.to.len() > MAX_RULE_PREFIXES {
                return Err(err("a rule lists too many prefixes"));
            }
            if rule.ports.len() > MAX_RULE_PORTS {
                return Err(err("a rule lists too many port ranges"));
            }
            if rule.ports.iter().any(|p| p.first == 0 || p.first > p.last) {
                return Err(err("a port range must satisfy 1 <= first <= last"));
            }
        }
        Ok(())
    }
}

fn has_duplicates<T: Ord + Copy>(items: &[T]) -> bool {
    let mut sorted = items.to_vec();
    sorted.sort_unstable();
    sorted.windows(2).any(|w| w[0] == w[1])
}

/// 产物哈希：产物对象规范形式的 SHA-256（design/auth.md 第 10.5 节）。
pub fn artifact_hash(artifact: &Artifact) -> Result<Sha256Digest, PayloadError> {
    let value =
        serde_json::to_value(artifact).map_err(|e| PayloadError::Document(e.to_string()))?;
    Ok(Sha256Digest::of(&to_canonical(&value)?))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::{Value, json};

    pub(crate) const NODE_A: &str = "node_01J9Z3K8Q2T7V4X6Y8A0B2C4D6";

    pub(crate) fn policy_value() -> Value {
        json!({
            "kind": "node_policy",
            "node_id": NODE_A,
            "policy_version": 1,
            "modules": ["mesh"],
            "roles": ["relay"],
            "addresses": { "mesh": { "ipv4": "100.88.0.2", "ipv6": "fd00:88::2" } },
            "enrollment_public_key": crate::encoding::encode_b64(&[9u8; 32]),
        })
    }

    fn payload_value(artifacts: Vec<Value>) -> Value {
        json!({ "v": 1, "kind": "enrollment_policy", "artifacts": artifacts, "expires_at": "2026-11-06T10:00:00Z" })
    }

    fn bytes(v: &Value) -> Vec<u8> {
        to_canonical(v).expect("canonical")
    }

    #[test]
    fn parses_an_enrollment_policy() {
        let p = Payload::parse(&bytes(&payload_value(vec![policy_value()]))).expect("valid");
        let node: NodeId = NODE_A.parse().expect("id");
        let (hash, policy) = p.node_policy(&node).expect("policy present");
        assert_eq!(*hash, Sha256Digest::of(&bytes(&policy_value())));
        assert!(policy.has_module(Module::Mesh));
        assert_eq!(policy.addresses.mesh.ipv4, Ipv4Addr::new(100, 88, 0, 2));
    }

    #[test]
    fn rejects_unknown_fields_kinds_and_artifacts() {
        let mut extra = payload_value(vec![policy_value()]);
        extra["note"] = json!("x");
        let mut extra_in_policy = policy_value();
        extra_in_policy["note"] = json!("x");
        let mut unknown_role = policy_value();
        unknown_role["roles"] = json!(["gateway"]);
        let mut unknown_kind = payload_value(vec![policy_value()]);
        unknown_kind["kind"] = json!("trust_update");
        for v in [
            extra,
            payload_value(vec![extra_in_policy]),
            payload_value(vec![unknown_role]),
            payload_value(vec![json!({"kind": "device_credential", "version": 1})]),
            unknown_kind,
        ] {
            assert!(Payload::parse(&bytes(&v)).is_err(), "{v}");
        }
    }

    #[test]
    fn rejects_non_canonical_addresses() {
        let mut v = policy_value();
        v["addresses"]["mesh"]["ipv6"] = json!("fd00:88:0::2");
        assert_eq!(
            Payload::parse(&bytes(&payload_value(vec![v]))).err(),
            Some(PayloadError::NonCanonicalFields)
        );
    }

    #[test]
    fn rejects_duplicates_and_bad_addresses() {
        let mut dup_module = policy_value();
        dup_module["modules"] = json!(["mesh", "mesh"]);
        let mut loopback = policy_value();
        loopback["addresses"]["mesh"]["ipv4"] = json!("127.0.0.1");
        for (v, want) in [
            (payload_value(vec![dup_module]), "DuplicateEntry"),
            (payload_value(vec![loopback]), "Address"),
            (
                payload_value(vec![policy_value(), policy_value()]),
                "DuplicatePolicy",
            ),
        ] {
            let err = Payload::parse(&bytes(&v)).expect_err(want);
            assert!(format!("{err:?}").starts_with(want), "{err:?}");
        }
    }

    #[test]
    fn rejects_other_format_versions() {
        let mut v = payload_value(vec![policy_value()]);
        v["v"] = json!(2);
        assert_eq!(
            Payload::parse(&bytes(&v)).err(),
            Some(PayloadError::Format(2))
        );
    }

    fn edge_policy_value() -> Value {
        let mut v = policy_value();
        v["roles"] = json!(["relay", "edge"]);
        v["edge"] = json!({ "containers": ["172.17.0.0/16"] });
        v["addresses"]["edge"] = json!({ "ipv4": "100.88.1.2", "ipv6": "fd00:88::1:2" });
        v
    }

    pub(crate) fn rule_set_value() -> Value {
        json!({
            "kind": "access_rule_set",
            "version": 3,
            "rules": [
                { "action": "allow", "from": ["100.88.1.2/32", "fd00:88::1:2/128"],
                  "to": ["100.88.0.9/32"], "ports": [{ "protocol": "tcp", "first": 8686, "last": 8686 }] },
                { "action": "deny", "from": ["100.88.0.0/16"], "to": ["100.88.0.9/32"], "ports": [] },
            ],
        })
    }

    #[test]
    fn parses_an_edge_policy() {
        let p = Payload::parse(&bytes(&payload_value(vec![edge_policy_value()]))).expect("valid");
        let node: NodeId = NODE_A.parse().expect("id");
        let (_, policy) = p.node_policy(&node).expect("policy present");
        assert!(policy.has_role(Role::Edge));
        assert_eq!(
            policy.edge.as_ref().map(|e| e.containers.clone()),
            Some(vec!["172.17.0.0/16".parse().expect("prefix")])
        );
        assert_eq!(
            policy.addresses.edge.map(|a| a.ipv4),
            Some(Ipv4Addr::new(100, 88, 1, 2))
        );
    }

    #[test]
    fn rejects_inconsistent_edge_policies() {
        let mut role_only = policy_value();
        role_only["roles"] = json!(["edge"]);
        let mut sources_only = edge_policy_value();
        sources_only["roles"] = json!(["relay"]);
        let mut no_addresses = edge_policy_value();
        no_addresses["addresses"] =
            json!({ "mesh": { "ipv4": "100.88.0.2", "ipv6": "fd00:88::2" } });
        let mut same_as_mesh = edge_policy_value();
        same_as_mesh["addresses"]["edge"]["ipv4"] = json!("100.88.0.2");
        let mut no_containers = edge_policy_value();
        no_containers["edge"]["containers"] = json!([]);
        let mut loopback = edge_policy_value();
        loopback["addresses"]["edge"]["ipv6"] = json!("::1");
        for v in [
            role_only,
            sources_only,
            no_addresses,
            same_as_mesh,
            no_containers,
            loopback,
        ] {
            let err = Payload::parse(&bytes(&payload_value(vec![v.clone()]))).expect_err("edge");
            assert!(matches!(err, PayloadError::Edge(_)), "{v}: {err:?}");
        }
    }

    #[test]
    fn parses_an_access_rule_set() {
        let v = payload_value(vec![policy_value(), rule_set_value()]);
        let p = Payload::parse(&bytes(&v)).expect("valid");
        let (hash, rules) = p.access_rule_set().expect("rule set present");
        assert_eq!(*hash, Sha256Digest::of(&bytes(&rule_set_value())));
        assert_eq!(rules.version, 3);
        assert_eq!(rules.rules[0].action, RuleAction::Allow);
        assert_eq!(
            rules.rules[0].ports,
            vec![PortRange {
                protocol: Protocol::Tcp,
                first: 8686,
                last: 8686
            }]
        );
        assert!(rules.rules[1].ports.is_empty());
        assert_eq!(p.doc().to_canonical().expect("canonical"), bytes(&v));
    }

    #[test]
    fn rejects_bad_access_rule_sets() {
        let with = |f: &dyn Fn(&mut Value)| {
            let mut v = rule_set_value();
            f(&mut v);
            payload_value(vec![v])
        };
        for (v, want) in [
            (with(&|v| v["version"] = json!(0)), "AccessRules"),
            (with(&|v| v["rules"][0]["from"] = json!([])), "AccessRules"),
            (
                with(&|v| v["rules"][0]["ports"][0]["first"] = json!(0)),
                "AccessRules",
            ),
            (
                with(&|v| v["rules"][0]["ports"][0]["last"] = json!(80)),
                "AccessRules",
            ),
            (
                with(&|v| v["rules"][0]["ports"][0]["protocol"] = json!("icmp")),
                "Document",
            ),
            (
                with(&|v| v["rules"][0]["to"] = json!(["100.88.0.9/16"])),
                "Document",
            ),
            (
                with(&|v| v["rules"][0]["action"] = json!("reject")),
                "Document",
            ),
            (
                payload_value(vec![rule_set_value(), rule_set_value()]),
                "DuplicateRuleSet",
            ),
        ] {
            let err = Payload::parse(&bytes(&v)).expect_err(want);
            assert!(format!("{err:?}").starts_with(want), "{v}: {err:?}");
        }
    }

    #[test]
    fn parses_and_validates_advertised_routes() {
        let routes = json!({ "kind": "advertised_routes", "node_id": NODE_A, "version": 2, "routes": ["192.0.2.10/32", "198.51.100.0/24"] });
        let p = Payload::parse(&bytes(&payload_value(vec![routes.clone()]))).expect("valid");
        let (_, r) = p.advertised_routes().next().expect("routes");
        assert_eq!(r.version, 2);
        assert_eq!(r.routes.len(), 2);
        let mut role = policy_value();
        role["roles"] = json!(["subnet_router"]);
        assert!(Payload::parse(&bytes(&payload_value(vec![role]))).is_ok());
        let with = |f: &dyn Fn(&mut Value)| {
            let mut v = routes.clone();
            f(&mut v);
            payload_value(vec![v])
        };
        for (v, want) in [
            (with(&|v| v["version"] = json!(0)), "Routes"),
            (with(&|v| v["routes"] = json!([])), "Routes"),
            (with(&|v| v["routes"] = json!(["0.0.0.0/0"])), "Routes"),
            (with(&|v| v["routes"] = json!(["127.0.0.0/8"])), "Routes"),
            (with(&|v| v["routes"] = json!(["fe80::/64"])), "Routes"),
            (with(&|v| v["routes"] = json!(["224.0.0.0/4"])), "Routes"),
            (
                payload_value(vec![routes.clone(), routes.clone()]),
                "DuplicateRoutes",
            ),
        ] {
            let err = Payload::parse(&bytes(&v)).expect_err(want);
            assert!(format!("{err:?}").starts_with(want), "{v}: {err:?}");
        }
    }

    #[test]
    fn doc_round_trips_through_canonical_bytes() {
        let p = Payload::parse(&bytes(&payload_value(vec![policy_value()]))).expect("valid");
        let again = p.doc().to_canonical().expect("canonical");
        assert_eq!(again, bytes(&payload_value(vec![policy_value()])));
    }
}
