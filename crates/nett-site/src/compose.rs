//! Composes each machine's desired state from the site (design/site.md section 6, design/hub.md
//! section 4): written as files when the signing tool is not linked to a Hub; when linked, the Hub
//! composes it with the same logic.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_mesh::config::{Candidate, DesiredMesh, DesiredMeshDoc, PathDoc, Reachability};
use nett_trust::revocation::Revocation;

use crate::SiteError;
use crate::state::{Machine, State};

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

/// Candidate paths from this machine to a peer (design/mesh.md section 6): when the peer is
/// `public`, connect directly to its public address (the one given, or the one the Hub learned; one
/// each for IPv4 and IPv6 when both exist); when both ends are `dial-only`, hole punching; when
/// this machine is `public` and the peer is `dial-only`, there is no candidate and the peer
/// connects in (WireGuard roaming).
pub fn candidates(state: &State, me: &Machine, peer: &Machine) -> Vec<Candidate> {
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
    };
    // The generated desired state must be accepted by the mesh process
    DesiredMesh::from_doc(doc.clone()).map_err(|e| {
        SiteError::invalid(format!("machine `{name}`: generated desired state: {e}"))
    })?;
    Ok(Some(doc))
}
