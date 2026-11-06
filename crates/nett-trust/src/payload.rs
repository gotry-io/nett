//! 签名载荷与其中的产物（design/auth.md 第 10.1、10.5 节）。

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::canonical::{CanonicalError, parse_canonical, to_canonical};
use crate::encoding::{Sha256Digest, Timestamp};
use crate::keys::Ed25519PublicKey;
use nett_core::id::{ChangeId, NodeId};
use serde::{Deserialize, Serialize};

/// 载荷格式的版本。
pub const PAYLOAD_V1: u64 = 1;

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
}

/// 节点策略，字段与 `node-policies` 资源一致（design/api-resources.md 第 5.2 节）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodePolicy {
    pub node_id: NodeId,
    pub policy_version: u64,
    pub modules: Vec<Module>,
    pub roles: Vec<Role>,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAddresses {
    pub mesh: MeshAddresses,
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
            let Artifact::NodePolicy(policy) = artifact;
            policy.validate()?;
            let duplicate = artifacts[..i].iter().any(|other| {
                let Artifact::NodePolicy(other) = other;
                other.node_id == policy.node_id
            });
            if duplicate {
                return Err(PayloadError::DuplicatePolicy(policy.node_id.clone()));
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
        self.artifacts().find_map(|(hash, artifact)| {
            let Artifact::NodePolicy(policy) = artifact;
            (policy.node_id == *node_id).then_some((hash, policy))
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
        let MeshAddresses { ipv4, ipv6 } = self.addresses.mesh;
        let ipv4_ok = !(ipv4.is_unspecified()
            || ipv4.is_loopback()
            || ipv4.is_multicast()
            || ipv4.is_broadcast());
        let ipv6_ok = !(ipv6.is_unspecified() || ipv6.is_loopback() || ipv6.is_multicast());
        if ipv4_ok && ipv6_ok {
            Ok(())
        } else {
            Err(PayloadError::Address(self.node_id.clone()))
        }
    }

    pub fn has_module(&self, module: Module) -> bool {
        self.modules.contains(&module)
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
            payload_value(vec![json!({"kind": "access_rule_set", "version": 1})]),
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

    #[test]
    fn doc_round_trips_through_canonical_bytes() {
        let p = Payload::parse(&bytes(&payload_value(vec![policy_value()]))).expect("valid");
        let again = p.doc().to_canonical().expect("canonical");
        assert_eq!(again, bytes(&payload_value(vec![policy_value()])));
    }
}
