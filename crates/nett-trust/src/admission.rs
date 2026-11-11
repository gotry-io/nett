//! Mesh admission: trust anchors → signed node policy containing the mesh module → admission proof
//! (design/mesh.md section 4.1, ADR 0014).

use std::collections::BTreeMap;

use nett_core::id::NodeId;
use nett_core::prefix::IpPrefix;
use serde::{Deserialize, Serialize};

use crate::anchors::TrustAnchors;
use crate::canonical::{CanonicalError, parse_canonical, to_canonical};
use crate::encoding::{Sha256Digest, Timestamp, b64, b64_fixed};
use crate::keys::X25519PublicKey;
use crate::payload::{MeshAddresses, Module, Role};
use crate::revocation::Revocations;
use crate::signed::{SignatureError, SignedPayload, Signer};

/// Version of the admission proof payload format.
pub const PROOF_V1: u64 = 1;

/// The admission proof payload: the enrollment private key's signature over the node ID, identity
/// public key and mesh public key (design/auth.md sections 8.2, 10.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionProofDoc {
    pub v: u64,
    pub kind: AdmissionProofKind,
    pub node_id: NodeId,
    pub identity_public_key: X25519PublicKey,
    pub mesh_public_key: X25519PublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionProofKind {
    AdmissionProof,
}

impl AdmissionProofDoc {
    pub fn to_canonical(&self) -> Result<Vec<u8>, CanonicalError> {
        let value =
            serde_json::to_value(self).map_err(|e| CanonicalError::Syntax(e.to_string()))?;
        to_canonical(&value)
    }
}

/// The transport form of an admission proof: the payload bytes and an Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionProof {
    #[serde(with = "b64")]
    pub payload: Vec<u8>,
    #[serde(with = "b64_fixed")]
    pub signature: [u8; 64],
}

/// One member's admission material: the signed node policy plus the admission proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionMaterial {
    pub policy: SignedPayload,
    pub proof: AdmissionProof,
}

/// A member that passed admission verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub node_id: NodeId,
    pub policy_version: u64,
    pub mesh_public_key: X25519PublicKey,
    pub identity_public_key: X25519PublicKey,
    pub addresses: MeshAddresses,
    pub roles: Vec<Role>,
    /// With the `edge` role, the Edge address and the origin of Edge traffic (ADR 0015).
    pub edge: Option<EdgeMember>,
    pub signer: Signer,
    /// Hash of the node policy artifact.
    pub policy_hash: Sha256Digest,
    /// Hash of the admission proof payload.
    pub proof_hash: Sha256Digest,
    /// Expiry time of the node policy payload: checked only when this machine first accepts its own
    /// policy (design/auth.md section 10.2 check 6).
    pub policy_expires_at: Timestamp,
}

/// A member's Edge: the Edge address, and from which container prefixes Edge traffic comes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeMember {
    pub addresses: MeshAddresses,
    pub containers: Vec<IpPrefix>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    #[error("admission proof: {0}")]
    ProofFormat(#[from] CanonicalError),
    #[error("admission proof: invalid document: {0}")]
    ProofDocument(String),
    #[error("admission proof: unsupported format version {0}")]
    ProofVersion(u64),
    #[error("node {0} is revoked")]
    Revoked(NodeId),
    #[error("node policy for {node_id}: {source}")]
    Policy {
        node_id: NodeId,
        source: SignatureError,
    },
    #[error("signed payload carries no node policy for {0}")]
    NoPolicy(NodeId),
    #[error("node policy for {0} does not enable the mesh module")]
    NotMeshMember(NodeId),
    #[error("admission proof for {0} is not signed by the enrollment key in its node policy")]
    BadProof(NodeId),
}

impl AdmissionError {
    /// The rejected node; empty when the format is so wrong that the node ID cannot be read.
    pub fn node_id(&self) -> Option<&NodeId> {
        match self {
            Self::ProofFormat(_) | Self::ProofDocument(_) | Self::ProofVersion(_) => None,
            Self::Revoked(id)
            | Self::Policy { node_id: id, .. }
            | Self::NoPolicy(id)
            | Self::NotMeshMember(id)
            | Self::BadProof(id) => Some(id),
        }
    }
}

/// Verifies one member's admission material. What is verified is the signature chain and
/// revocations; the expiry of the approval is not checked (design/auth.md section 10.2 check 6);
/// the version number is checked by [`AppliedMembers`].
pub fn admit(
    material: &AdmissionMaterial,
    anchors: &TrustAnchors,
    revocations: &Revocations,
) -> Result<Member, AdmissionError> {
    let proof_value = parse_canonical(&material.proof.payload)?;
    let proof = AdmissionProofDoc::deserialize(&proof_value)
        .map_err(|e| AdmissionError::ProofDocument(e.to_string()))?;
    if proof.v != PROOF_V1 {
        return Err(AdmissionError::ProofVersion(proof.v));
    }
    let node_id = proof.node_id;
    if revocations.is_node_revoked(&node_id) {
        return Err(AdmissionError::Revoked(node_id));
    }

    let verified = material
        .policy
        .verify(anchors)
        .map_err(|source| AdmissionError::Policy {
            node_id: node_id.clone(),
            source,
        })?;
    let Some((policy_hash, policy)) = verified.payload.node_policy(&node_id) else {
        return Err(AdmissionError::NoPolicy(node_id));
    };
    if !policy.has_module(Module::Mesh) {
        return Err(AdmissionError::NotMeshMember(node_id));
    }
    if !policy
        .enrollment_public_key
        .verify(&material.proof.payload, &material.proof.signature)
    {
        return Err(AdmissionError::BadProof(node_id));
    }

    Ok(Member {
        policy_version: policy.policy_version,
        mesh_public_key: proof.mesh_public_key,
        identity_public_key: proof.identity_public_key,
        addresses: policy.addresses.mesh,
        roles: policy.roles.clone(),
        // Payload parsing has already confirmed that the role, origin and address either all appear
        // or all are absent
        edge: policy
            .addresses
            .edge
            .zip(policy.edge.as_ref())
            .map(|(addresses, sources)| EdgeMember {
                addresses,
                containers: sources.containers.clone(),
            }),
        signer: verified.signer,
        policy_hash: *policy_hash,
        proof_hash: Sha256Digest::of(&material.proof.payload),
        policy_expires_at: verified.payload.expires_at(),
        node_id,
    })
}

/// Member versions already in effect. Version numbers only increase; material identical to the
/// version in effect is treated as idempotent (design/auth.md section 10.2 check 7).
#[derive(Debug, Clone, Default)]
pub struct AppliedMembers {
    by_node: BTreeMap<NodeId, AppliedRecord>,
}

/// A member's material in effect: the version and the hashes of the two payloads. The mesh process
/// keeps it in the local trust store, and after a restart uses it to reject older versions
/// (design/mesh.md section 4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedRecord {
    pub policy_version: u64,
    pub policy_hash: Sha256Digest,
    pub proof_hash: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionCheck {
    /// A new member, or a higher version.
    Newer,
    /// Identical to the material in effect.
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VersionError {
    #[error("node {node_id}: policy version {offered} is lower than applied version {applied}")]
    Older {
        node_id: NodeId,
        applied: u64,
        offered: u64,
    },
    #[error(
        "node {node_id}: policy version {version} differs from the applied material of the same version"
    )]
    Conflict { node_id: NodeId, version: u64 },
}

impl AppliedMembers {
    pub fn check(&self, member: &Member) -> Result<VersionCheck, VersionError> {
        match self.by_node.get(&member.node_id) {
            Some(applied) => applied.compare(member),
            None => Ok(VersionCheck::Newer),
        }
    }

    /// Records a member that passed [`Self::check`].
    pub fn record(&mut self, member: &Member) {
        self.by_node
            .insert(member.node_id.clone(), AppliedRecord::of(member));
    }

    pub fn records(&self) -> &BTreeMap<NodeId, AppliedRecord> {
        &self.by_node
    }

    /// Versions in effect; revoked members are removed by the caller.
    pub fn remove(&mut self, node_id: &NodeId) {
        self.by_node.remove(node_id);
    }
}

impl AppliedRecord {
    pub fn of(member: &Member) -> Self {
        Self {
            policy_version: member.policy_version,
            policy_hash: member.policy_hash,
            proof_hash: member.proof_hash,
        }
    }

    /// Compares with this material in effect: a higher version is [`VersionCheck::Newer`],
    /// identical is
    /// [`VersionCheck::Unchanged`], and a lower version, or the same version with different content, is
    /// an error.
    pub fn compare(&self, member: &Member) -> Result<VersionCheck, VersionError> {
        let offered = Self::of(member);
        if offered.policy_version > self.policy_version {
            Ok(VersionCheck::Newer)
        } else if offered == *self {
            Ok(VersionCheck::Unchanged)
        } else if offered.policy_version < self.policy_version {
            Err(VersionError::Older {
                node_id: member.node_id.clone(),
                applied: self.policy_version,
                offered: offered.policy_version,
            })
        } else {
            Err(VersionError::Conflict {
                node_id: member.node_id.clone(),
                version: offered.policy_version,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchors::TrustAnchorsDoc;
    use crate::encoding::Timestamp;
    use crate::keys::Algorithm;
    use crate::payload::{Artifact, MeshAddresses, NodeAddresses, NodePolicy, PayloadDoc, Role};
    use crate::revocation::Revocation;
    use crate::signing::{EnrollmentKeyPair, PasskeyKeyPair, RecoveryKeyPair};

    const RP_ID: &str = "hub.example.com";
    const ORIGIN: &str = "https://hub.example.com";
    const UP_UV: u8 = 0x05;
    const NODE_A: &str = "node_01J9Z3K8Q2T7V4X6Y8A0B2C4D6";
    const NODE_B: &str = "node_01J9Z3K8Q2T7V4X6Y8A0B2C4D7";
    const PK_ES: &str = "pk_01J9Z3K8Q2T7V4X6Y8A0B2C4D6";
    const PK_ED: &str = "pk_01J9Z3K8Q2T7V4X6Y8A0B2C4D7";

    struct Fixture {
        recovery: RecoveryKeyPair,
        passkey_es: PasskeyKeyPair,
        passkey_ed: PasskeyKeyPair,
        anchors: TrustAnchors,
        enrollment: EnrollmentKeyPair,
    }

    fn id<T: std::str::FromStr>(s: &str) -> T
    where
        T::Err: std::fmt::Debug,
    {
        s.parse().expect("valid id")
    }

    fn fixture() -> Fixture {
        let recovery = RecoveryKeyPair::generate().expect("recovery key");
        let passkey_es = PasskeyKeyPair::generate(id(PK_ES), Algorithm::Es256).expect("passkey");
        let passkey_ed = PasskeyKeyPair::generate(id(PK_ED), Algorithm::EdDsa).expect("passkey");
        let anchors = TrustAnchors::from_doc(&TrustAnchorsDoc {
            v: 1,
            version: 1,
            rp_id: RP_ID.into(),
            origin: ORIGIN.into(),
            passkeys: vec![passkey_es.doc(), passkey_ed.doc()],
            recovery_key: recovery.doc(),
        })
        .expect("anchors");
        let enrollment = EnrollmentKeyPair::generate().expect("enrollment key");
        Fixture {
            recovery,
            passkey_es,
            passkey_ed,
            anchors,
            enrollment,
        }
    }

    fn policy(node: &str, version: u64, enrollment: &EnrollmentKeyPair) -> NodePolicy {
        NodePolicy {
            node_id: id(node),
            policy_version: version,
            modules: vec![Module::Mesh],
            roles: vec![Role::Relay],
            edge: None,
            addresses: NodeAddresses {
                mesh: MeshAddresses {
                    ipv4: "100.88.0.2".parse().expect("ipv4"),
                    ipv6: "fd00:88::2".parse().expect("ipv6"),
                },
                edge: None,
            },
            enrollment_public_key: enrollment.public_key(),
        }
    }

    fn payload(policies: Vec<NodePolicy>) -> Vec<u8> {
        PayloadDoc::EnrollmentPolicy {
            v: 1,
            artifacts: policies.into_iter().map(Artifact::NodePolicy).collect(),
            // Admission verification does not check expiry: an approval that expired long ago is
            // still valid
            expires_at: Timestamp::from_unix_seconds(0),
        }
        .to_canonical()
        .expect("canonical")
    }

    fn proof(node: &str, mesh_key: u8, enrollment: &EnrollmentKeyPair) -> AdmissionProof {
        enrollment
            .sign_proof(&AdmissionProofDoc {
                v: 1,
                kind: AdmissionProofKind::AdmissionProof,
                node_id: id(node),
                identity_public_key: X25519PublicKey::from_bytes([1; 32]),
                mesh_public_key: X25519PublicKey::from_bytes([mesh_key; 32]),
            })
            .expect("proof")
    }

    fn material(f: &Fixture, version: u64) -> AdmissionMaterial {
        AdmissionMaterial {
            policy: f
                .recovery
                .sign(payload(vec![policy(NODE_A, version, &f.enrollment)]))
                .expect("sign"),
            proof: proof(NODE_A, 2, &f.enrollment),
        }
    }

    fn admit_ok(f: &Fixture, m: &AdmissionMaterial) -> Member {
        admit(m, &f.anchors, &Revocations::default()).expect("admitted")
    }

    #[test]
    fn admits_with_each_signer() {
        let f = fixture();
        let by_recovery = material(&f, 1);
        let member = admit_ok(&f, &by_recovery);
        assert_eq!(member.node_id, id::<NodeId>(NODE_A));
        assert_eq!(member.mesh_public_key, X25519PublicKey::from_bytes([2; 32]));
        assert_eq!(member.signer, Signer::RecoveryKey);

        for (passkey, pk_id) in [(&f.passkey_es, PK_ES), (&f.passkey_ed, PK_ED)] {
            let m = AdmissionMaterial {
                policy: passkey
                    .sign(by_recovery.policy.payload.clone(), RP_ID, ORIGIN, UP_UV)
                    .expect("sign"),
                proof: by_recovery.proof.clone(),
            };
            assert_eq!(admit_ok(&f, &m).signer, Signer::Passkey(id(pk_id)));
        }
    }

    fn policy_error(f: &Fixture, m: &AdmissionMaterial) -> SignatureError {
        match admit(m, &f.anchors, &Revocations::default()) {
            Err(AdmissionError::Policy { source, .. }) => source,
            other => panic!("expected a policy error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_tampered_payload_and_foreign_anchor() {
        let f = fixture();
        let mut tampered = material(&f, 1);
        let at = tampered.policy.payload.len() - 3;
        tampered.policy.payload[at] ^= 1;
        assert_eq!(policy_error(&f, &tampered), SignatureError::BadSignature);

        let other = RecoveryKeyPair::generate().expect("key");
        let foreign = AdmissionMaterial {
            policy: other
                .sign(payload(vec![policy(NODE_A, 1, &f.enrollment)]))
                .expect("sign"),
            proof: proof(NODE_A, 2, &f.enrollment),
        };
        assert_eq!(policy_error(&f, &foreign), SignatureError::BadSignature);
    }

    #[test]
    fn rejects_bad_webauthn_assertions() {
        let f = fixture();
        let bytes = payload(vec![policy(NODE_A, 1, &f.enrollment)]);
        let stranger =
            PasskeyKeyPair::generate(id("pk_01J9Z3K8Q2T7V4X6Y8A0B2C4D8"), Algorithm::Es256)
                .expect("passkey");
        let cases = [
            (
                stranger.sign(bytes.clone(), RP_ID, ORIGIN, UP_UV),
                "unknown passkey",
            ),
            (
                f.passkey_es.sign(bytes.clone(), RP_ID, ORIGIN, 0x01),
                "no UV",
            ),
            (
                f.passkey_es.sign(bytes.clone(), RP_ID, ORIGIN, 0x04),
                "no UP",
            ),
            (
                f.passkey_es
                    .sign(bytes.clone(), "example.com", ORIGIN, UP_UV),
                "rp id",
            ),
            (
                f.passkey_es
                    .sign(bytes.clone(), RP_ID, "https://evil.example.com", UP_UV),
                "origin",
            ),
        ];
        for (signed, what) in cases {
            let m = AdmissionMaterial {
                policy: signed.expect("sign"),
                proof: proof(NODE_A, 2, &f.enrollment),
            };
            assert!(
                matches!(
                    policy_error(&f, &m),
                    SignatureError::UnknownPasskey(_) | SignatureError::WebAuthn(_)
                ),
                "{what}"
            );
        }

        // The assertion was generated for another payload: the challenge does not match
        let mut swapped = f
            .passkey_es
            .sign(bytes, RP_ID, ORIGIN, UP_UV)
            .expect("sign");
        swapped.payload = payload(vec![policy(NODE_A, 2, &f.enrollment)]);
        let m = AdmissionMaterial {
            policy: swapped,
            proof: proof(NODE_A, 2, &f.enrollment),
        };
        assert_eq!(
            policy_error(&f, &m),
            SignatureError::WebAuthn("challenge is not the payload hash")
        );
    }

    #[test]
    fn rejects_bad_or_missing_proof() {
        let f = fixture();
        let mut m = material(&f, 1);

        // The admission proof is signed by another enrollment private key
        m.proof = proof(NODE_A, 2, &EnrollmentKeyPair::generate().expect("key"));
        assert_eq!(
            admit(&m, &f.anchors, &Revocations::default()),
            Err(AdmissionError::BadProof(id(NODE_A)))
        );

        // The mesh public key in the admission proof is replaced: the signature no longer holds
        let mut swapped = proof(NODE_A, 2, &f.enrollment);
        let original = X25519PublicKey::from_bytes([2; 32]).to_string();
        let replaced = X25519PublicKey::from_bytes([3; 32]).to_string();
        swapped.payload = String::from_utf8(swapped.payload)
            .expect("utf-8")
            .replace(&original, &replaced)
            .into_bytes();
        m.proof = swapped;
        assert_eq!(
            admit(&m, &f.anchors, &Revocations::default()),
            Err(AdmissionError::BadProof(id(NODE_A)))
        );

        // The admission proof belongs to a node other than the one in the payload
        m.proof = proof(NODE_B, 2, &f.enrollment);
        assert_eq!(
            admit(&m, &f.anchors, &Revocations::default()),
            Err(AdmissionError::NoPolicy(id(NODE_B)))
        );
    }

    #[test]
    fn rejects_revoked_and_non_mesh_nodes() {
        let f = fixture();
        let m = material(&f, 1);
        let mut revocations = Revocations::default();
        revocations.apply(&Revocation::Node {
            node_id: id(NODE_A),
        });
        assert_eq!(
            admit(&m, &f.anchors, &revocations),
            Err(AdmissionError::Revoked(id(NODE_A)))
        );

        let mut no_mesh = policy(NODE_A, 1, &f.enrollment);
        no_mesh.modules.clear();
        let m = AdmissionMaterial {
            policy: f.recovery.sign(payload(vec![no_mesh])).expect("sign"),
            proof: proof(NODE_A, 2, &f.enrollment),
        };
        assert_eq!(
            admit(&m, &f.anchors, &Revocations::default()),
            Err(AdmissionError::NotMeshMember(id(NODE_A)))
        );
    }

    #[test]
    fn versions_only_move_forward() {
        let f = fixture();
        let v1 = admit_ok(&f, &material(&f, 1));
        let v2 = admit_ok(&f, &material(&f, 2));
        let mut applied = AppliedMembers::default();
        assert_eq!(applied.check(&v2), Ok(VersionCheck::Newer));
        applied.record(&v2);

        // Resending the same material (for example a full snapshot) is idempotent, even with a
        // different signature: what is compared is the artifact and the admission proof
        let v2_again = admit_ok(&f, &material(&f, 2));
        assert_eq!(applied.check(&v2_again), Ok(VersionCheck::Unchanged));
        assert!(matches!(
            applied.check(&v1),
            Err(VersionError::Older {
                applied: 2,
                offered: 1,
                ..
            })
        ));

        // Same version, different content
        let mut other = policy(NODE_A, 2, &f.enrollment);
        other.roles.clear();
        let conflicting = admit_ok(
            &f,
            &AdmissionMaterial {
                policy: f.recovery.sign(payload(vec![other])).expect("sign"),
                proof: proof(NODE_A, 2, &f.enrollment),
            },
        );
        assert!(matches!(
            applied.check(&conflicting),
            Err(VersionError::Conflict { version: 2, .. })
        ));
    }
}
