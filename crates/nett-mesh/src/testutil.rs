//! 测试用的期望状态与替身数据面。

use std::collections::BTreeMap;

use nett_core::id::NodeId;
use nett_trust::admission::{AdmissionMaterial, AdmissionProofDoc, AdmissionProofKind};
use nett_trust::anchors::TrustAnchorsDoc;
use nett_trust::encoding::Timestamp;
use nett_trust::keys::X25519PublicKey;
use nett_trust::payload::{
    Artifact, MeshAddresses, Module, NodeAddresses, NodePolicy, PayloadDoc, Role,
};
use nett_trust::signing::{EnrollmentKeyPair, RecoveryKeyPair};

use crate::config::{Candidate, DesiredMesh, DesiredMeshDoc, MeshPrefixes, PathDoc, Reachability};
use crate::dataplane::{DataPlane, DataPlaneError, InterfaceSpec, PeerSpec, PeerStat};
use crate::key::PrivateKey;

pub fn node_id(n: u8) -> NodeId {
    format!("node_01J9Z3K8Q2T7V4X6Y8A0B2C4{n:02}")
        .parse()
        .expect("valid node id")
}

pub fn mesh_key(n: u8) -> X25519PublicKey {
    X25519PublicKey::from_bytes([n; 32])
}

/// 一组节点的签名材料。节点 `n` 的组网地址为 `100.88.0.n` 与 `fd00:88::n`。
pub struct Mesh {
    pub recovery: RecoveryKeyPair,
    pub enrollment: BTreeMap<u8, EnrollmentKeyPair>,
}

impl Mesh {
    pub fn new(nodes: &[u8]) -> Self {
        Self {
            recovery: RecoveryKeyPair::generate().expect("recovery key"),
            enrollment: nodes
                .iter()
                .map(|n| (*n, EnrollmentKeyPair::generate().expect("enrollment key")))
                .collect(),
        }
    }

    pub fn policy(&self, n: u8, version: u64) -> NodePolicy {
        NodePolicy {
            node_id: node_id(n),
            policy_version: version,
            modules: vec![Module::Mesh],
            roles: vec![Role::Relay],
            addresses: NodeAddresses {
                mesh: MeshAddresses {
                    ipv4: format!("100.88.0.{n}").parse().expect("ipv4"),
                    ipv6: format!("fd00:88::{n:x}").parse().expect("ipv6"),
                },
            },
            enrollment_public_key: self.enrollment[&n].public_key(),
        }
    }

    pub fn material_for(&self, policy: NodePolicy, mesh: X25519PublicKey) -> AdmissionMaterial {
        let n = self
            .enrollment
            .iter()
            .find(|(n, _)| node_id(**n) == policy.node_id)
            .map(|(n, _)| *n)
            .expect("known node");
        let payload = PayloadDoc::EnrollmentPolicy {
            v: 1,
            artifacts: vec![Artifact::NodePolicy(policy.clone())],
            expires_at: Timestamp::from_unix_seconds(0),
        }
        .to_canonical()
        .expect("canonical");
        AdmissionMaterial {
            policy: self.recovery.sign(payload).expect("sign"),
            proof: self.enrollment[&n]
                .sign_proof(&AdmissionProofDoc {
                    v: 1,
                    kind: AdmissionProofKind::AdmissionProof,
                    node_id: policy.node_id,
                    identity_public_key: X25519PublicKey::from_bytes([0xee; 32]),
                    mesh_public_key: mesh,
                })
                .expect("proof"),
        }
    }

    pub fn material(&self, n: u8, version: u64) -> AdmissionMaterial {
        self.material_for(self.policy(n, version), mesh_key(n))
    }

    pub fn desired(&self, me: u8, members: Vec<AdmissionMaterial>) -> DesiredMeshDoc {
        DesiredMeshDoc {
            node_id: node_id(me),
            reachability: Reachability::DialOnly,
            listen_port: 41820,
            prefixes: MeshPrefixes {
                ipv4: "100.88.0.0/16".parse().expect("prefix"),
                ipv6: "fd00:88::/48".parse().expect("prefix"),
            },
            trust_anchors: TrustAnchorsDoc {
                v: 1,
                version: 1,
                rp_id: "hub.example.com".into(),
                origin: "https://hub.example.com".into(),
                passkeys: vec![],
                recovery_key: self.recovery.doc(),
            },
            members,
            revocations: vec![],
            paths: self
                .enrollment
                .keys()
                .filter(|n| **n != me)
                .map(|n| PathDoc {
                    peer: node_id(*n),
                    peer_reachability: Reachability::Public,
                    candidates: vec![Candidate::Direct {
                        endpoint: format!("192.0.2.{n}:41820").parse().expect("endpoint"),
                    }],
                })
                .collect(),
        }
    }
}

pub fn validated(doc: DesiredMeshDoc) -> DesiredMesh {
    DesiredMesh::from_doc(doc).expect("valid desired state")
}

/// 替身数据面：记录调用，`ensure_interface` 返回预设的公钥（相当于内核由私钥算出的公钥）。
pub struct FakeDataPlane {
    pub public_key: X25519PublicKey,
    pub interfaces: Vec<InterfaceSpec>,
    pub peers: Option<Vec<PeerSpec>>,
    pub fail_peers: bool,
    pub rehandshakes: Vec<PeerSpec>,
    /// 每次设置的闲置 TLS 端口。
    pub tls_guards: Vec<Vec<u16>>,
}

impl FakeDataPlane {
    pub fn new(public_key: X25519PublicKey) -> Self {
        Self {
            public_key,
            interfaces: vec![],
            peers: None,
            fail_peers: false,
            rehandshakes: Vec::new(),
            tls_guards: Vec::new(),
        }
    }
}

impl DataPlane for FakeDataPlane {
    fn ensure_interface(
        &mut self,
        spec: &InterfaceSpec,
        _private_key: &PrivateKey,
    ) -> Result<X25519PublicKey, DataPlaneError> {
        self.interfaces.push(spec.clone());
        Ok(self.public_key)
    }

    fn sync_peers(&mut self, peers: &[PeerSpec]) -> Result<(), DataPlaneError> {
        if self.fail_peers {
            return Err(DataPlaneError::Protocol {
                op: "sync peers",
                detail: "injected failure".into(),
            });
        }
        self.peers = Some(peers.to_vec());
        Ok(())
    }

    fn peer_stats(&mut self) -> Result<Vec<PeerStat>, DataPlaneError> {
        Ok(self
            .peers
            .iter()
            .flatten()
            .map(|p| PeerStat {
                public_key: p.public_key,
                endpoint: p.endpoint,
                rx_bytes: 0,
                tx_bytes: 0,
                last_handshake: None,
            })
            .collect())
    }

    fn set_endpoint(
        &mut self,
        public_key: &X25519PublicKey,
        endpoint: std::net::SocketAddr,
    ) -> Result<(), DataPlaneError> {
        for p in self.peers.iter_mut().flatten() {
            if p.public_key == *public_key {
                p.endpoint = Some(endpoint);
            }
        }
        Ok(())
    }

    fn rehandshake(&mut self, peer: &PeerSpec) -> Result<(), DataPlaneError> {
        self.rehandshakes.push(peer.clone());
        self.set_endpoint(
            &peer.public_key,
            peer.endpoint.unwrap_or(crate::probe::UNSPECIFIED),
        )
    }

    fn guard_tls_ports(&mut self, _wg_port: u16, idle: &[u16]) -> Result<(), DataPlaneError> {
        self.tls_guards.push(idle.to_vec());
        Ok(())
    }
}
