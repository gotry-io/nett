//! Desired state and stand-in data plane for tests.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use nett_core::id::NodeId;
use nett_trust::admission::{AdmissionMaterial, AdmissionProofDoc, AdmissionProofKind};
use nett_trust::anchors::TrustAnchorsDoc;
use nett_trust::encoding::Timestamp;
use nett_trust::keys::X25519PublicKey;
use nett_trust::payload::{
    Artifact, EdgeSources, MeshAddresses, Module, NodeAddresses, NodePolicy, PayloadDoc, Role,
};
use nett_trust::signed::SignedPayload;
use nett_trust::signing::{EnrollmentKeyPair, RecoveryKeyPair};

use crate::access::{EdgeSpec, FilterSpec, IngressSpec};
use crate::config::{Candidate, DesiredMesh, DesiredMeshDoc, MeshPrefixes, PathDoc, Reachability};
use crate::dataplane::{
    DataPlane, DataPlaneError, DirectProbes, InterfaceSpec, InterfaceState, PeerSpec, PeerStat,
};
use crate::key::PrivateKey;
use nett_core::prefix::IpPrefix;

pub fn node_id(n: u8) -> NodeId {
    format!("node_01J9Z3K8Q2T7V4X6Y8A0B2C4{n:02}")
        .parse()
        .expect("valid node id")
}

/// Expiry time of test material: 2100-01-01.
pub const FAR_FUTURE: Timestamp = Timestamp::from_unix_seconds(4_102_444_800);

pub fn mesh_key(n: u8) -> X25519PublicKey {
    X25519PublicKey::from_bytes([n; 32])
}

/// Signed material for a set of nodes. The mesh address of node `n` is `100.88.0.n` and `fd00:88::n`.
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
            edge: None,
            addresses: NodeAddresses {
                mesh: MeshAddresses {
                    ipv4: format!("100.88.0.{n}").parse().expect("ipv4"),
                    ipv6: format!("fd00:88::{n:x}").parse().expect("ipv6"),
                },
                edge: None,
            },
            enrollment_public_key: self.enrollment[&n].public_key(),
        }
    }

    pub fn material_for(&self, policy: NodePolicy, mesh: X25519PublicKey) -> AdmissionMaterial {
        self.material_expiring(policy, mesh, FAR_FUTURE)
    }

    /// Admission material whose node policy payload expires at `expires_at`.
    pub fn material_expiring(
        &self,
        policy: NodePolicy,
        mesh: X25519PublicKey,
        expires_at: Timestamp,
    ) -> AdmissionMaterial {
        let n = self
            .enrollment
            .iter()
            .find(|(n, _)| node_id(**n) == policy.node_id)
            .map(|(n, _)| *n)
            .expect("known node");
        let payload = PayloadDoc::EnrollmentPolicy {
            v: 1,
            artifacts: vec![Artifact::NodePolicy(policy.clone())],
            expires_at,
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

    /// A node with the `edge` role: the Edge address is `100.88.1.n` and `fd00:88::1:n`, and the Edge
    /// containers are in `172.17.0.0/16`.
    pub fn edge_policy(&self, n: u8, version: u64) -> NodePolicy {
        let mut policy = self.policy(n, version);
        policy.roles.push(Role::Edge);
        policy.edge = Some(EdgeSources {
            containers: vec!["172.17.0.0/16".parse().expect("prefix")],
        });
        policy.addresses.edge = Some(MeshAddresses {
            ipv4: format!("100.88.1.{n}").parse().expect("ipv4"),
            ipv6: format!("fd00:88::1:{n:x}").parse().expect("ipv6"),
        });
        policy
    }

    pub fn edge_material(&self, n: u8, version: u64) -> AdmissionMaterial {
        self.material_for(self.edge_policy(n, version), mesh_key(n))
    }

    /// A node with the `subnet_router` role (smart gateway).
    pub fn router_material(&self, n: u8, version: u64) -> AdmissionMaterial {
        let mut policy = self.policy(n, version);
        policy.roles.push(Role::SubnetRouter);
        self.material_for(policy, mesh_key(n))
    }

    /// The payload of the prefixes advertised by node `n`.
    pub fn routes_doc(&self, n: u8, version: u64, routes: &[&str]) -> PayloadDoc {
        PayloadDoc::EnrollmentPolicy {
            v: 1,
            artifacts: vec![Artifact::AdvertisedRoutes(
                nett_trust::payload::AdvertisedRoutes {
                    node_id: node_id(n),
                    version,
                    routes: routes.iter().map(|r| r.parse().expect("prefix")).collect(),
                },
            )],
            expires_at: Timestamp::from_unix_seconds(0),
        }
    }

    /// Signs a payload with this set of nodes' recovery key.
    pub fn sign(&self, doc: &PayloadDoc) -> SignedPayload {
        self.recovery
            .sign(doc.to_canonical().expect("canonical"))
            .expect("sign")
    }

    pub fn desired(&self, me: u8, members: Vec<AdmissionMaterial>) -> DesiredMeshDoc {
        DesiredMeshDoc {
            node_id: node_id(me),
            reachability: Reachability::DialOnly,
            listen_port: Some(41820),
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
            access_rules: None,
            advertised_routes: vec![],
            names: self
                .enrollment
                .keys()
                .map(|n| (node_id(*n), format!("node-{n}").parse().expect("name")))
                .collect(),
            relay: None,
        }
    }
}

pub fn validated(doc: DesiredMeshDoc) -> DesiredMesh {
    DesiredMesh::from_doc(doc).expect("valid desired state")
}

/// When applying members, the expiry of this machine's node policy is not checked (equivalent to a newly
/// created trust store).
pub fn no_expiry(desired: &DesiredMesh) -> crate::members::OwnPolicy<'_> {
    crate::members::OwnPolicy {
        node_id: &desired.node_id,
        now: None,
    }
}

/// The port the stand-in data plane "assigns" when the desired state carries no port.
pub const FAKE_AUTO_PORT: u16 = 50_000;

/// Stand-in data plane: records calls, and `ensure_interface` returns a preset public key (equivalent to
/// the public key the kernel derives from the private key).
pub struct FakeDataPlane {
    pub public_key: X25519PublicKey,
    pub interfaces: Vec<InterfaceSpec>,
    /// The interface's current WireGuard port: kept when no port is given, and [`FAKE_AUTO_PORT`] the first
    /// time.
    pub listen_port: Option<u16>,
    pub peers: Option<Vec<PeerSpec>>,
    pub fail_peers: bool,
    pub rehandshakes: Vec<PeerSpec>,
    /// The idle TLS ports set on each call.
    pub tls_guards: Vec<Vec<u16>>,
    /// The filter rules and Edge settings currently installed.
    pub filter: Option<FilterSpec>,
    pub edge: Option<EdgeSpec>,
    pub ingress: Option<IngressSpec>,
    pub routes: Vec<IpPrefix>,
    /// Installing filter rules fails: `Some(true)` makes all installs fail, `Some(false)` lets only the
    /// deny-all rules install.
    pub fail_filter: Option<bool>,
    /// Data plane calls recorded in order, used to check "install filter rules first, then add peers".
    pub calls: Vec<&'static str>,
    /// Byte counts and most recent handshake of each peer, which `peer_stats` reports (0 and empty when
    /// absent).
    pub traffic: std::collections::HashMap<X25519PublicKey, (u64, u64)>,
    pub handshakes: std::collections::HashMap<X25519PublicKey, std::time::SystemTime>,
}

impl FakeDataPlane {
    pub fn new(public_key: X25519PublicKey) -> Self {
        Self {
            public_key,
            interfaces: vec![],
            listen_port: None,
            peers: None,
            fail_peers: false,
            rehandshakes: Vec::new(),
            tls_guards: Vec::new(),
            filter: None,
            edge: None,
            ingress: None,
            routes: Vec::new(),
            fail_filter: None,
            calls: Vec::new(),
            traffic: std::collections::HashMap::new(),
            handshakes: std::collections::HashMap::new(),
        }
    }
}

impl DataPlane for FakeDataPlane {
    fn kind(&self) -> crate::status::DataPlaneKind {
        crate::status::DataPlaneKind::Kernel
    }

    fn ensure_interface(
        &mut self,
        spec: &InterfaceSpec,
        _private_key: &PrivateKey,
    ) -> Result<InterfaceState, DataPlaneError> {
        self.interfaces.push(spec.clone());
        let listen_port = spec
            .listen_port
            .or(self.listen_port)
            .unwrap_or(FAKE_AUTO_PORT);
        self.listen_port = Some(listen_port);
        Ok(InterfaceState {
            public_key: self.public_key,
            listen_port,
        })
    }

    fn sync_peers(&mut self, peers: &[PeerSpec]) -> Result<(), DataPlaneError> {
        if self.fail_peers {
            return Err(DataPlaneError::Protocol {
                op: "sync peers",
                detail: "injected failure".into(),
            });
        }
        self.calls.push("sync_peers");
        self.peers = Some(peers.to_vec());
        Ok(())
    }

    fn peer_stats(&mut self) -> Result<Vec<PeerStat>, DataPlaneError> {
        Ok(self
            .peers
            .iter()
            .flatten()
            .map(|p| {
                let (rx_bytes, tx_bytes) =
                    self.traffic.get(&p.public_key).copied().unwrap_or((0, 0));
                PeerStat {
                    public_key: p.public_key,
                    endpoint: p.endpoint,
                    rx_bytes,
                    tx_bytes,
                    last_handshake: self.handshakes.get(&p.public_key).copied(),
                }
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

    fn apply_filter(&mut self, filter: &FilterSpec) -> Result<(), DataPlaneError> {
        self.calls.push("apply_filter");
        let fails = match self.fail_filter {
            Some(all) => all || *filter != FilterSpec::deny_all(),
            None => false,
        };
        if fails {
            return Err(DataPlaneError::Protocol {
                op: "apply filter",
                detail: "injected failure".into(),
            });
        }
        self.filter = Some(filter.clone());
        Ok(())
    }

    fn apply_edge(&mut self, edge: Option<&EdgeSpec>) -> Result<(), DataPlaneError> {
        self.calls.push("apply_edge");
        self.edge = edge.cloned();
        Ok(())
    }

    fn apply_ingress(&mut self, ingress: Option<&IngressSpec>) -> Result<(), DataPlaneError> {
        self.calls.push("apply_ingress");
        self.ingress = ingress.cloned();
        Ok(())
    }

    fn sync_routes(&mut self, routes: &[IpPrefix]) -> Result<(), DataPlaneError> {
        self.calls.push("sync_routes");
        self.routes = routes.to_vec();
        Ok(())
    }

    fn direct_probes(&mut self, _listen_port: u16) -> Result<DirectProbes, DataPlaneError> {
        Err(DataPlaneError::Unsupported(
            "direct probes in the fake data plane",
        ))
    }

    fn bind_tunnel(&self, _addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
        Err(std::io::Error::other(
            "no tunnel sockets in the fake data plane",
        ))
    }

    fn bind_underlay(&self, _port: u16) -> std::io::Result<std::net::UdpSocket> {
        Err(std::io::Error::other(
            "no underlay sockets in the fake data plane",
        ))
    }
}
