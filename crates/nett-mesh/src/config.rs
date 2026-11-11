//! Desired state of the mesh process: the parts of the desired state's `trust` and `mesh` partitions that
//! the mesh process uses (design/protocol.md section 6).
//!
//! Sources only deliver documents ([`crate::source`]); validation happens once here at the boundary, and
//! only validated types are passed on afterwards.
//! Signed artifacts are only parsed for format here; signatures and admission are verified item by item by
//! [`crate::members`] and are never skipped because of the source.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_core::transport::{CertFingerprint, MAX_TARGETS, TlsTarget, TransportConfig};
use nett_trust::admission::AdmissionMaterial;
use nett_trust::anchors::{AnchorsError, TrustAnchors, TrustAnchorsDoc};
use nett_trust::revocation::Revocation;
use nett_trust::signed::SignedPayload;
use serde::{Deserialize, Serialize};

use nett_core::prefix::IpPrefix;

use crate::probe::TUNNEL_PROBE_PORT;

/// Document form of the desired state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredMeshDoc {
    pub node_id: NodeId,
    pub reachability: Reachability,
    /// WireGuard port. Required for `public` nodes; for `dial-only` nodes the system assigns one when it is
    /// absent (design/mesh.md section 5.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    pub prefixes: MeshPrefixes,
    pub trust_anchors: TrustAnchorsDoc,
    pub members: Vec<AdmissionMaterial>,
    pub revocations: Vec<Revocation>,
    pub paths: Vec<PathDoc>,
    /// Signed access rule set (design/mesh.md section 12); when absent, matching uses the default values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_rules: Option<SignedPayload>,
    /// Prefixes advertised by smart gateways, each a signed payload (design/mesh.md section 10).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advertised_routes: Vec<SignedPayload>,
    /// Node name, not signed, used only for display (design/status.md section 5).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub names: BTreeMap<NodeId, NodeName>,
    /// The relay this machine runs, with the links assigned to it (design/mesh.md section 5.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayDoc>,
}

/// Relay assignment in the desired state (design/mesh.md section 5.2). Members are named by node ID;
/// the mesh process resolves them to mesh public keys from the verified admission material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayDoc {
    /// UDP relay port.
    pub port: u16,
    /// TCP port of the TLS transport; absent when the relay serves UDP only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_port: Option<u16>,
    pub members: Vec<RelayMemberDoc>,
    /// Pairs of members the relay forwards between.
    pub links: Vec<[NodeId; 2]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayMemberDoc {
    pub node: NodeId,
    /// WireGuard address of a `public` member, bound before its first handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<SocketAddr>,
    /// Probe token between this member and the relay.
    pub token: ProbeToken,
}

/// Network reachability of a node (design/architecture.md section 6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reachability {
    Public,
    DialOnly,
}

/// Mesh prefixes (design/mesh.md section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshPrefixes {
    pub ipv4: IpPrefix,
    pub ipv6: IpPrefix,
}

/// Candidate paths to one peer, equivalent to the result of the Hub's computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathDoc {
    pub peer: NodeId,
    /// Reachability of the peer: determines which side decides the path for this pair (design/mesh.md
    /// section 8.3).
    pub peer_reachability: Reachability,
    /// Ordered as given by the Hub; the initial path is the first one.
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Candidate {
    /// Direct public path: the address of the peer's WireGuard port.
    Direct { endpoint: SocketAddr },
    /// Via a relay: the relay's node ID, the address of the relay port, and the probe token between this
    /// machine and this relay (design/mesh.md section 5.2).
    Relay {
        relay: NodeId,
        endpoint: SocketAddr,
        token: ProbeToken,
    },
    /// TLS transport via a relay (design/mesh.md section 5.3): the relay's TLS address and certificate
    /// fingerprint; the token is the same as for the UDP relay and authenticates the first probe on the
    /// WebSocket connection. The endpoint in WireGuard is the transport adapter's loopback port.
    RelayTls {
        relay: NodeId,
        address: SocketAddr,
        fingerprint: CertFingerprint,
        token: ProbeToken,
    },
    /// LAN direct path (design/mesh.md section 6): the peer's LAN address and WireGuard port, composed by
    /// the Hub when both are on the same LAN.
    Lan { endpoint: SocketAddr },
    /// Try hole punching for a direct path (design/mesh.md section 6.1): both sides are `dial-only`. The
    /// addresses are exchanged during hole punching, not here.
    Punch,
}

/// The transport adapter's loopback ports start here and are allocated in order of the relays' node IDs
/// (ADR 0013: allocated by the mesh process).
pub const TLS_LOOPBACK_BASE: u16 = 41830;
const TLS_LOOPBACK_LAST: u16 = TLS_LOOPBACK_BASE + MAX_TARGETS as u16 - 1;

/// Size limit of each file in the desired state file and the trust store (design/mesh.md section 17).
pub const MAX_DESIRED_BYTES: u64 = 4 << 20;
/// Upper limit on the number of members (and paths, node names, advertised prefixes) in one desired state.
pub const MAX_MEMBERS: usize = 256;
/// Upper limit on the number of revocations: revocations are kept permanently, and each re-enrolled node
/// leaves one.
pub const MAX_REVOCATIONS: usize = 4096;
/// Upper limit on the links assigned to one relay.
pub const MAX_RELAY_LINKS: usize = 8192;

/// Reads a regular file of at most `max` bytes; `Ok(None)` when it does not exist.
pub fn read_bounded(path: &Path, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(std::io::Error::other(format!(
            "{} is larger than {max} bytes",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

/// Ports the mesh process and the transport adapter use locally: the probe port on the mesh address and
/// the loopback ports of TLS relays. The WireGuard socket binds all local addresses; when it uses one of
/// them, the party that binds later fails (design/site.md section 4).
pub fn is_reserved_port(port: u16) -> bool {
    port == TUNNEL_PROBE_PORT || (TLS_LOOPBACK_BASE..=TLS_LOOPBACK_LAST).contains(&port)
}

/// Probe token between a member and a relay. `Debug` does not print the contents (hard rule 10).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProbeToken(#[serde(with = "nett_trust::encoding::b64_fixed")] pub [u8; 32]);

impl std::fmt::Debug for ProbeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProbeToken(<redacted>)")
    }
}

/// Path configuration of one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPathConfig {
    pub reachability: Reachability,
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("desired state is not valid: {0}")]
    Document(String),
    #[error(transparent)]
    Anchors(#[from] AnchorsError),
    #[error("listen port must not be 0; leave it out to have the system pick one")]
    ListenPort,
    #[error("a public node needs a listen port: other members dial it")]
    PublicWithoutPort,
    #[error(
        "listen port {0} is one nett itself uses on this host: {TUNNEL_PROBE_PORT} for probes on mesh \
         addresses and {TLS_LOOPBACK_BASE}-{last} for TLS relays on loopback; pick another WireGuard port",
        last = TLS_LOOPBACK_LAST
    )]
    ListenPortInUse(u16),
    #[error("mesh prefix {0} is not a private-use range of a sensible size")]
    Prefix(IpPrefix),
    #[error("paths list peer {0} more than once")]
    DuplicatePath(NodeId),
    #[error("TLS relay {0} is listed with different addresses or fingerprints")]
    TlsTargetConflict(NodeId),
    #[error("paths list more than {MAX_TARGETS} TLS relays")]
    TooManyTlsRelays,
    #[error("desired state lists more than {max} {what}")]
    TooMany { what: &'static str, max: usize },
    #[error("relay: {0}")]
    Relay(String),
}

/// Validated desired state.
#[derive(Debug, Clone)]
pub struct DesiredMesh {
    pub node_id: NodeId,
    pub reachability: Reachability,
    pub listen_port: Option<u16>,
    pub prefixes: MeshPrefixes,
    pub anchors: TrustAnchors,
    /// Document form of the trust anchor list: compared with the trust anchors pinned on this machine
    /// (design/mesh.md section 4.2).
    pub trust_anchors: TrustAnchorsDoc,
    pub members: Vec<AdmissionMaterial>,
    pub revocations: Vec<Revocation>,
    pub paths: BTreeMap<NodeId, PeerPathConfig>,
    pub access_rules: Option<SignedPayload>,
    pub advertised_routes: Vec<SignedPayload>,
    pub names: BTreeMap<NodeId, NodeName>,
    pub relay: Option<RelayDoc>,
    /// TLS targets of the transport adapter, coming from the same place as [`DesiredMesh::tls_endpoints`].
    tls_targets: Vec<TlsTarget>,
    tls_endpoints: BTreeMap<NodeId, SocketAddr>,
    /// The document before validation: saved into the trust store after the whole is accepted, and used when
    /// the desired state file is rejected at startup.
    doc: DesiredMeshDoc,
}

impl DesiredMesh {
    pub fn doc(&self) -> &DesiredMeshDoc {
        &self.doc
    }

    /// The endpoint in WireGuard of each TLS relay: the loopback port the transport adapter opens for it.
    pub fn tls_endpoints(&self) -> &BTreeMap<NodeId, SocketAddr> {
        &self.tls_endpoints
    }

    /// TLS targets of the transport adapter: loopback port and the relay's TLS address.
    pub fn tls_targets(&self) -> &[TlsTarget] {
        &self.tls_targets
    }

    /// Configuration handed to the transport adapter: the WireGuard port is the port the interface actually
    /// listens on (possibly assigned by the system).
    pub fn transport(&self, wireguard_port: u16) -> TransportConfig {
        TransportConfig {
            wireguard_port,
            targets: self.tls_targets.clone(),
        }
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, ConfigError> {
        let doc: DesiredMeshDoc =
            serde_json::from_slice(bytes).map_err(|e| ConfigError::Document(e.to_string()))?;
        Self::from_doc(doc)
    }

    pub fn from_doc(doc: DesiredMeshDoc) -> Result<Self, ConfigError> {
        for (what, len, max) in [
            ("members", doc.members.len(), MAX_MEMBERS),
            ("revocations", doc.revocations.len(), MAX_REVOCATIONS),
            ("paths", doc.paths.len(), MAX_MEMBERS),
            ("names", doc.names.len(), MAX_MEMBERS),
            (
                "advertised routes",
                doc.advertised_routes.len(),
                MAX_MEMBERS,
            ),
        ] {
            if len > max {
                return Err(ConfigError::TooMany { what, max });
            }
        }
        let source = doc.clone();
        match doc.listen_port {
            Some(0) => return Err(ConfigError::ListenPort),
            Some(port) if is_reserved_port(port) => {
                return Err(ConfigError::ListenPortInUse(port));
            }
            None if doc.reachability == Reachability::Public => {
                return Err(ConfigError::PublicWithoutPort);
            }
            _ => {}
        }
        for prefix in [doc.prefixes.ipv4, doc.prefixes.ipv6] {
            if !is_sensible_mesh_prefix(&prefix) {
                return Err(ConfigError::Prefix(prefix));
            }
        }
        let mut tls: BTreeMap<NodeId, (SocketAddr, CertFingerprint)> = BTreeMap::new();
        for c in doc.paths.iter().flat_map(|p| &p.candidates) {
            if let Candidate::RelayTls {
                relay,
                address,
                fingerprint,
                ..
            } = c
                && tls
                    .insert(relay.clone(), (*address, *fingerprint))
                    .is_some_and(|prev| prev != (*address, *fingerprint))
            {
                return Err(ConfigError::TlsTargetConflict(relay.clone()));
            }
        }
        if tls.len() > MAX_TARGETS {
            return Err(ConfigError::TooManyTlsRelays);
        }
        let mut tls_endpoints = BTreeMap::new();
        let mut targets = Vec::new();
        for (port, (relay, (connect, fingerprint))) in (TLS_LOOPBACK_BASE..).zip(tls) {
            let listen = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
            tls_endpoints.insert(relay, listen);
            targets.push(TlsTarget {
                listen,
                connect,
                fingerprint,
            });
        }
        if let Some(relay) = &doc.relay {
            check_relay(relay)?;
        }
        let mut paths = BTreeMap::new();
        for path in doc.paths {
            let config = PeerPathConfig {
                reachability: path.peer_reachability,
                candidates: path.candidates,
            };
            if paths.insert(path.peer.clone(), config).is_some() {
                return Err(ConfigError::DuplicatePath(path.peer));
            }
        }
        Ok(Self {
            node_id: doc.node_id,
            reachability: doc.reachability,
            listen_port: doc.listen_port,
            prefixes: doc.prefixes,
            anchors: TrustAnchors::from_doc(&doc.trust_anchors)?,
            trust_anchors: doc.trust_anchors,
            members: doc.members,
            revocations: doc.revocations,
            paths,
            access_rules: doc.access_rules,
            advertised_routes: doc.advertised_routes,
            names: doc.names,
            relay: doc.relay,
            tls_targets: targets,
            tls_endpoints,
            doc: source,
        })
    }
}

/// The relay section is consistent: ports in range, members listed once, links between listed members.
fn check_relay(relay: &RelayDoc) -> Result<(), ConfigError> {
    if relay.port == 0 || relay.tls_port == Some(0) {
        return Err(ConfigError::Relay("ports must not be 0".into()));
    }
    if relay.members.len() > MAX_MEMBERS {
        return Err(ConfigError::TooMany {
            what: "relay members",
            max: MAX_MEMBERS,
        });
    }
    if relay.links.len() > MAX_RELAY_LINKS {
        return Err(ConfigError::TooMany {
            what: "relay links",
            max: MAX_RELAY_LINKS,
        });
    }
    let mut members = std::collections::BTreeSet::new();
    for m in &relay.members {
        if !members.insert(&m.node) {
            return Err(ConfigError::Relay(format!(
                "member {} is listed twice",
                m.node
            )));
        }
    }
    for [a, b] in &relay.links {
        if a == b {
            return Err(ConfigError::Relay(format!("link of {a} with itself")));
        }
        if let Some(missing) = [a, b].into_iter().find(|n| !members.contains(n)) {
            return Err(ConfigError::Relay(format!(
                "a link names {missing}, which is not among the relay's members"
            )));
        }
    }
    Ok(())
}

/// Mesh prefixes may only come from private address ranges and must be of reasonable size: all traffic to
/// the mesh prefixes enters `nett0`, and an oversized prefix (for example `0.0.0.0/0`) would swallow the
/// machine's other traffic (including traffic to the Hub).
fn is_sensible_mesh_prefix(prefix: &IpPrefix) -> bool {
    let private: &[(&str, u8)] = if prefix.is_ipv4() {
        &[
            ("10.0.0.0/8", 30),
            ("172.16.0.0/12", 30),
            ("192.168.0.0/16", 30),
            ("100.64.0.0/10", 30),
        ]
    } else {
        // ULA; Hub generates a /48 at initialization
        &[("fc00::/7", 120)]
    };
    private.iter().any(|(range, max_len)| {
        let range: IpPrefix = range.parse().expect("built-in prefix is valid");
        range.covers(prefix)
            && prefix.prefix_len() <= *max_len
            && prefix.prefix_len() >= min_len(prefix.addr())
    })
}

fn min_len(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 8 } else { 48 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Mesh, node_id};

    #[test]
    fn counts_and_sizes_are_bounded() {
        let mesh = Mesh::new(&[1]);
        let mut doc = mesh.desired(1, vec![]);
        doc.revocations = vec![
            Revocation::Node {
                node_id: node_id(9)
            };
            MAX_REVOCATIONS + 1
        ];
        assert_eq!(
            DesiredMesh::from_doc(doc).err(),
            Some(ConfigError::TooMany {
                what: "revocations",
                max: MAX_REVOCATIONS
            })
        );

        let dir = std::env::temp_dir().join(format!("nett-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("desired.json");
        std::fs::write(&file, [b' '; 11]).expect("written");
        assert!(read_bounded(&file, 10).is_err());
        assert_eq!(
            read_bounded(&file, 11)
                .expect("small enough")
                .map(|b| b.len()),
            Some(11)
        );
        assert_eq!(
            read_bounded(&dir.join("missing"), 10).expect("no error"),
            None
        );
        assert!(read_bounded(&dir, 10).is_err());
        std::fs::remove_dir_all(&dir).expect("cleaned up");
    }

    #[test]
    fn mesh_prefixes_must_be_private_and_sized() {
        for (s, ok) in [
            ("100.88.0.0/16", true),
            ("10.0.0.0/8", true),
            ("100.0.0.0/8", false),
            ("0.0.0.0/0", false),
            ("8.8.0.0/16", false),
            ("100.88.0.0/31", false),
            ("fd00:88::/48", true),
            ("fd00::/8", false),
            ("2001:db8::/48", false),
        ] {
            let p: IpPrefix = s.parse().expect(s);
            assert_eq!(is_sensible_mesh_prefix(&p), ok, "{s}");
        }
    }

    #[test]
    fn listen_port_avoids_the_ports_nett_uses_itself() {
        use crate::testutil::Mesh;
        let mesh = Mesh::new(&[1]);
        let with_port = |reachability, port| {
            let mut doc = mesh.desired(1, vec![]);
            doc.reachability = reachability;
            doc.listen_port = port;
            DesiredMesh::from_doc(doc).map(|d| d.listen_port)
        };
        for reachability in [Reachability::Public, Reachability::DialOnly] {
            assert_eq!(
                with_port(reachability, Some(0)).err(),
                Some(ConfigError::ListenPort)
            );
            for port in [TUNNEL_PROBE_PORT, TLS_LOOPBACK_BASE, TLS_LOOPBACK_LAST] {
                assert_eq!(
                    with_port(reachability, Some(port)).err(),
                    Some(ConfigError::ListenPortInUse(port))
                );
            }
            for port in [41820, 41822, TLS_LOOPBACK_BASE - 1, TLS_LOOPBACK_LAST + 1] {
                assert_eq!(with_port(reachability, Some(port)), Ok(Some(port)));
            }
        }
        // No port: dial-only gets one from the system, public does not (others connect to it by port)
        assert_eq!(with_port(Reachability::DialOnly, None), Ok(None));
        assert_eq!(
            with_port(Reachability::Public, None).err(),
            Some(ConfigError::PublicWithoutPort)
        );
    }

    #[test]
    fn tls_relays_get_loopback_ports_in_relay_order() {
        use crate::testutil::{Mesh, node_id};
        let tls = |relay: u8, fp: u8| Candidate::RelayTls {
            relay: node_id(relay),
            address: format!("198.51.100.{relay}:443").parse().expect("addr"),
            fingerprint: CertFingerprint([fp; 32]),
            token: ProbeToken([relay; 32]),
        };
        let mesh = Mesh::new(&[1]);
        let mut doc = mesh.desired(1, vec![]);
        doc.paths = vec![
            PathDoc {
                peer: node_id(2),
                peer_reachability: Reachability::Public,
                candidates: vec![tls(9, 1), tls(8, 2)],
            },
            PathDoc {
                peer: node_id(3),
                peer_reachability: Reachability::Public,
                candidates: vec![tls(9, 1)],
            },
        ];
        let desired = DesiredMesh::from_doc(doc.clone()).expect("valid");
        let port = |relay: u8| desired.tls_endpoints()[&node_id(relay)].port();
        assert_eq!(
            (port(8), port(9)),
            (TLS_LOOPBACK_BASE, TLS_LOOPBACK_BASE + 1)
        );
        let transport = desired.transport(51000);
        assert_eq!(transport.targets.len(), 2);
        assert_eq!(transport.wireguard_port, 51000);
        assert_eq!(transport.validate(), Ok(()));
        // The same relay was given two different fingerprints
        doc.paths[1].candidates = vec![tls(9, 7)];
        assert!(matches!(
            DesiredMesh::from_doc(doc),
            Err(ConfigError::TlsTargetConflict(_))
        ));
    }
}
