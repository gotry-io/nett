//! Composes each machine's desired state from the site (design/site.md section 6, design/hub.md
//! section 4): written as files when the signing tool is not linked to a Hub; when linked, the Hub
//! composes it with the same logic.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_core::transport::CertFingerprint;
use nett_mesh::config::{
    Candidate, DesiredMesh, DesiredMeshDoc, PathDoc, ProbeToken, Reachability, RelayDoc,
    RelayMemberDoc,
};
use nett_trust::revocation::Revocation;

use crate::SiteError;
use crate::state::{Machine, RelayKey, RelayRole, State};

/// Most candidate paths of one connection (design/mesh.md section 6).
pub const MAX_CANDIDATES: usize = 6;

/// A pair of machines that need a connection, sorted by node ID.
pub type Pair = (NodeId, NodeId);

/// Which machines get connections: every pair involved in an access rule, plus every `dial-only`
/// member with all `public` members (to determine NAT type and mapped address, and as redundancy on
/// failure, design/mesh.md section 6.1, architecture.md section 12.3).
pub fn connections(state: &State) -> BTreeSet<Pair> {
    let mut pairs = BTreeSet::new();
    let mut add = |a: &NodeId, b: &NodeId| {
        if a != b {
            pairs.insert(if a < b {
                (a.clone(), b.clone())
            } else {
                (b.clone(), a.clone())
            });
        }
    };
    for rule in state.rules.values() {
        for f in &rule.from {
            for t in &rule.to {
                add(&f.node, &t.node);
            }
        }
    }
    let public: Vec<&Machine> = state
        .machines
        .values()
        .filter(|m| m.reachability == Reachability::Public)
        .collect();
    for d in state
        .machines
        .values()
        .filter(|m| m.reachability == Reachability::DialOnly)
    {
        for p in &public {
            add(&d.node_id, &p.node_id);
        }
    }
    pairs
}

/// Candidate paths from this machine to a peer (design/site.md section 6): the direct ones first,
/// then the paths through relays.
pub fn candidates(state: &State, me: &Machine, peer: &Machine) -> Vec<Candidate> {
    let mut out = direct(state, me, peer);
    let Some(key) = &state.relay_key else {
        return out;
    };
    for path in relay_paths(state, me, peer) {
        let token = token(key, &path.relay.node_id, &me.node_id);
        let relay = path.relay.node_id.clone();
        out.push(match path.tls {
            None => Candidate::Relay {
                relay,
                endpoint: SocketAddr::new(path.ip, path.port),
                token,
            },
            Some(fingerprint) => Candidate::RelayTls {
                relay,
                address: SocketAddr::new(path.ip, path.port),
                fingerprint,
                token,
            },
        });
    }
    out
}

/// One path of a connection through a relay.
#[derive(Debug, Clone, Copy)]
pub struct RelayPath<'a> {
    pub relay: &'a Machine,
    pub ip: IpAddr,
    pub port: u16,
    /// TLS with this certificate fingerprint; UDP when absent.
    pub tls: Option<CertFingerprint>,
}

/// The paths of the connection between `a` and `b` through relays (design/site.md section 6):
/// every relay other than the two ends that has joined and has a public address, in the order of
/// their node IDs, first over UDP and then over TLS, while the connection has room for candidates.
/// The result is the same for both ends.
pub fn relay_paths<'a>(state: &'a State, a: &Machine, b: &Machine) -> Vec<RelayPath<'a>> {
    if a.policy.is_none() || b.policy.is_none() {
        return Vec::new();
    }
    let room =
        MAX_CANDIDATES.saturating_sub(direct(state, a, b).len().max(direct(state, b, a).len()));
    let mut relays: Vec<(&Machine, IpAddr, RelayRole)> = state
        .machines
        .values()
        .filter(|r| r.node_id != a.node_id && r.node_id != b.node_id && r.policy.is_some())
        .filter_map(|r| {
            let role = r.relay?;
            let ip = r
                .public_ipv4()
                .map(IpAddr::V4)
                .or_else(|| r.public_ipv6().map(IpAddr::V6))?;
            Some((r, ip, role))
        })
        .collect();
    relays.sort_by(|x, y| x.0.node_id.cmp(&y.0.node_id));
    let udp = relays.iter().map(|(r, ip, role)| RelayPath {
        relay: r,
        ip: *ip,
        port: role.port,
        tls: None,
    });
    let tls = relays.iter().filter_map(|(r, ip, role)| {
        Some(RelayPath {
            relay: r,
            ip: *ip,
            port: role.tls_port?,
            tls: Some(r.relay_fingerprint()?),
        })
    });
    udp.chain(tls).take(room).collect()
}

/// The probe token between a member and a relay (design/mesh.md section 5.2): HMAC-SHA256 of the
/// two node IDs under the site's relay key, so the site and the Hub derive the same token.
fn token(key: &RelayKey, relay: &NodeId, member: &NodeId) -> ProbeToken {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key.0);
    let mut ctx = ring::hmac::Context::with_key(&key);
    ctx.update(b"nett relay token v1");
    ctx.update(relay.as_str().as_bytes());
    ctx.update(&[0]);
    ctx.update(member.as_str().as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.sign().as_ref());
    ProbeToken(out)
}

/// The relay section of a machine that runs a relay: the connections that list it, and their ends
/// (design/mesh.md section 5.2).
fn relay_doc(state: &State, me: &Machine) -> Option<RelayDoc> {
    let role = me.relay?;
    let key = state.relay_key.as_ref()?;
    let mut links = Vec::new();
    let mut ends = BTreeSet::new();
    for (a, b) in connections(state) {
        let (Some(ma), Some(mb)) = (state.by_id(&a), state.by_id(&b)) else {
            continue;
        };
        if relay_paths(state, ma, mb)
            .iter()
            .any(|p| p.relay.node_id == me.node_id)
        {
            ends.insert(a.clone());
            ends.insert(b.clone());
            links.push([a, b]);
        }
    }
    let members = ends
        .into_iter()
        .filter_map(|id| {
            let m = state.by_id(&id)?;
            let address = m.listen_port(state.listen_port).and_then(|port| {
                m.public_ipv4()
                    .map(IpAddr::V4)
                    .or_else(|| m.public_ipv6().map(IpAddr::V6))
                    .map(|ip| SocketAddr::new(ip, port))
            });
            Some(RelayMemberDoc {
                token: token(key, &me.node_id, &id),
                node: id,
                address,
            })
        })
        .collect();
    Some(RelayDoc {
        port: role.port,
        tls_port: role.tls_port,
        members,
        links,
    })
}

/// Direct candidate paths from this machine to a peer (design/mesh.md section 6): when the peer is
/// `public`, connect directly to its public address (the one given, or the one the Hub learned; one
/// each for IPv4 and IPv6 when both exist); when both ends are `dial-only`, hole punching; when
/// this machine is `public` and the peer is `dial-only`, there is none and the peer connects in
/// (WireGuard roaming).
fn direct(state: &State, me: &Machine, peer: &Machine) -> Vec<Candidate> {
    match (me.reachability, peer.reachability) {
        (_, Reachability::Public) => {
            let port = peer
                .listen_port(state.listen_port)
                .unwrap_or(state.listen_port);
            [
                peer.public_ipv4().map(IpAddr::V4),
                peer.public_ipv6().map(IpAddr::V6),
            ]
            .into_iter()
            .flatten()
            .map(|ip| Candidate::Direct {
                endpoint: SocketAddr::new(ip, port),
            })
            .collect()
        }
        (Reachability::DialOnly, Reachability::DialOnly) => vec![Candidate::Punch],
        (Reachability::Public, Reachability::DialOnly) => Vec::new(),
    }
}

/// A machine's desired state. Returns `None` when the machine has no signed node policy yet (before
/// it joins through the Hub).
pub fn desired(state: &State, name: &NodeName) -> Result<Option<DesiredMeshDoc>, SiteError> {
    let me = state.machine(name)?;
    if me.policy.is_none() {
        return Ok(None);
    }
    let paths: Vec<PathDoc> = connections(state)
        .into_iter()
        .filter_map(|(a, b)| {
            let other = if a == me.node_id {
                b
            } else if b == me.node_id {
                a
            } else {
                return None;
            };
            let peer = state.by_id(&other)?;
            Some(PathDoc {
                peer: other,
                peer_reachability: peer.reachability,
                candidates: candidates(state, me, peer),
            })
        })
        .collect();
    let names: BTreeMap<NodeId, NodeName> = state
        .machines
        .iter()
        .map(|(n, m)| (m.node_id.clone(), n.clone()))
        .collect();
    let doc = DesiredMeshDoc {
        node_id: me.node_id.clone(),
        reachability: me.reachability,
        listen_port: me.listen_port(state.listen_port),
        prefixes: state.prefixes,
        trust_anchors: state.trust_anchors.clone(),
        members: state
            .machines
            .values()
            .filter_map(|m| m.policy.as_ref().map(|p| p.material.clone()))
            .collect(),
        revocations: state
            .revoked
            .iter()
            .map(|r| Revocation::Node {
                node_id: r.node_id.clone(),
            })
            .collect(),
        paths,
        access_rules: state.access_rules.as_ref().map(|r| r.signed.clone()),
        advertised_routes: state
            .machines
            .values()
            .filter_map(|m| m.routes_signed.as_ref().map(|r| r.signed.clone()))
            .collect(),
        names,
        relay: relay_doc(state, me),
    };
    // The generated desired state must be accepted by the mesh process
    DesiredMesh::from_doc(doc.clone()).map_err(|e| {
        SiteError::invalid(format!("machine `{name}`: generated desired state: {e}"))
    })?;
    Ok(Some(doc))
}
