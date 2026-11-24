//! Composes each machine's desired state from the site (design/site.md section 6, design/hub.md
//! section 4): written as files when the signing tool is not linked to a Hub; when linked, the Hub
//! composes it with the same logic.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_core::transport::CertFingerprint;
use nett_mesh::config::{
    Candidate, DesiredMesh, DesiredMeshDoc, DeviceDoc, ObfsPortDoc, ObfsSecret, PathDoc,
    ProbeToken, Reachability, RelayDoc, RelayMemberDoc,
};
use nett_mesh::prober::is_decider;
use nett_trust::revocation::Revocation;

use crate::SiteError;
use crate::state::{Machine, RelayKey, RelayRole, Selector, State};

/// Most candidate paths of one connection besides its LAN direct paths (design/mesh.md section 6).
pub const MAX_CANDIDATES: usize = 6;

/// A pair of machines that need a connection, sorted by node ID.
pub type Pair = (NodeId, NodeId);

/// Which machines get connections: every pair involved in an access rule, a device counting as its
/// gateway, plus every `dial-only` member with all `public` members (to determine NAT type and mapped
/// address, and as redundancy on failure, design/mesh.md section 6.1, architecture.md section 12.3).
/// A gateway that carries devices reaching every machine connects to every machine
/// (design/devices.md section 7).
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
    let node = |s: &Selector| match s {
        Selector::Machine(m) => Some(m.node.clone()),
        Selector::Device(d) => state
            .device_by_id(&d.device)
            .map(|(_, d)| d.gateway.clone()),
    };
    for rule in state.rules.values() {
        for f in rule.from.iter().filter_map(node) {
            for t in rule.to.iter().filter_map(node) {
                add(&f, &t);
            }
        }
    }
    for d in state.devices.values().filter(|d| !d.limited) {
        for m in state.machines.values() {
            add(&d.gateway, &m.node_id);
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

/// Candidate paths from this machine to a peer (design/site.md section 6): the LAN paths, then
/// obfuscated UDP to the peer's own obfuscated port, so the first handshake is already obfuscated
/// (design/obfuscation.md section 5), then the public direct ones, then the paths through relays
/// other than this machine's own.
pub fn candidates(state: &State, me: &Machine, peer: &Machine) -> Vec<Candidate> {
    let mut out = lan(state, me, peer);
    out.extend(direct(state, me, peer));
    let Some(key) = &state.relay_key else {
        return out;
    };
    for path in relay_paths(state, me, peer)
        .into_iter()
        .filter(|p| p.relay.node_id != me.node_id)
    {
        let token = token(key, &path.relay.node_id, &me.node_id);
        let relay = path.relay.node_id.clone();
        let address = SocketAddr::new(path.ip, path.port);
        out.push(match path.via {
            RelayVia::Udp => Candidate::Relay {
                relay,
                endpoint: address,
                token,
            },
            RelayVia::Obfs(padding) => Candidate::RelayObfs {
                key: obfs_key(key, ObfsPortOf::Relay, &path.relay.node_id),
                relay,
                address,
                padding,
                token,
            },
            RelayVia::Tls(fingerprint) => Candidate::RelayTls {
                relay,
                address,
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
    pub via: RelayVia,
}

/// How a relay path reaches the relay: its UDP relay port, its obfuscated port with the site's
/// padding range, or TLS with its certificate fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayVia {
    Udp,
    Obfs(nett_mesh::config::ObfsPadding),
    Tls(CertFingerprint),
}

impl RelayVia {
    pub fn label(self) -> &'static str {
        match self {
            RelayVia::Udp => "udp",
            RelayVia::Obfs(_) => "obfs",
            RelayVia::Tls(_) => "tls",
        }
    }
}

/// The paths of the connection between `a` and `b` through relays (design/site.md section 6,
/// design/obfuscation.md section 5): the relay on one end when the other end decides the path, over
/// obfuscated UDP, UDP and then TLS, then every relay other than the two ends that has joined and
/// has a public address, in the order of their node IDs, first over obfuscated UDP, then UDP, then
/// TLS, while the connection has room for candidates; a TLS path stays among them when any relay
/// serves TLS. The result is the same for both ends.
pub fn relay_paths<'a>(state: &'a State, a: &Machine, b: &Machine) -> Vec<RelayPath<'a>> {
    if a.policy.is_none() || b.policy.is_none() {
        return Vec::new();
    }
    // The LAN direct paths come in addition to the limit (design/mesh.md section 6)
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
    // The relay hands the packets to WireGuard on its own machine, so the two stay connected when
    // only the relay's port or only TCP passes between them (design/mesh.md section 5.1); only the
    // deciding end can use it
    let own = [(a, b), (b, a)].into_iter().flat_map(|(host, other)| {
        let decides = is_decider(
            &other.node_id,
            other.reachability,
            &host.node_id,
            host.reachability,
        );
        let relay = state
            .by_id(&host.node_id)
            .filter(|_| decides)
            .and_then(|r| {
                let ip = r
                    .public_ipv4()
                    .map(IpAddr::V4)
                    .or_else(|| r.public_ipv6().map(IpAddr::V6))?;
                Some((r, ip, r.relay?))
            });
        let ways: Vec<RelayPath> = relay
            .into_iter()
            .flat_map(|(r, ip, role)| {
                [
                    obfs_path(state, r, ip, role),
                    udp_path(r, ip, role),
                    tls_path(r, ip, role),
                ]
            })
            .flatten()
            .collect();
        ways
    });
    let udp = relays
        .iter()
        .filter_map(|(r, ip, role)| udp_path(r, *ip, *role));
    let obfs = relays
        .iter()
        .filter_map(|(r, ip, role)| obfs_path(state, r, *ip, *role));
    let tls = relays
        .iter()
        .filter_map(|(r, ip, role)| tls_path(r, *ip, *role));
    let all: Vec<RelayPath> = own.chain(obfs).chain(udp).chain(tls).collect();
    let is_tls = |p: &RelayPath| matches!(p.via, RelayVia::Tls(_));
    let mut chosen: Vec<RelayPath> = all.iter().take(room).copied().collect();
    // TLS is what still passes where all UDP is dropped, so the limit does not cut every TLS path
    if room > 0
        && !chosen.iter().any(is_tls)
        && let Some(tls) = all.iter().find(|p| is_tls(p))
    {
        chosen.pop();
        chosen.push(*tls);
    }
    chosen
}

fn udp_path<'a>(r: &'a Machine, ip: IpAddr, role: RelayRole) -> Option<RelayPath<'a>> {
    Some(RelayPath {
        relay: r,
        ip,
        port: role.port,
        via: RelayVia::Udp,
    })
}

fn obfs_path<'a>(
    state: &State,
    r: &'a Machine,
    ip: IpAddr,
    role: RelayRole,
) -> Option<RelayPath<'a>> {
    Some(RelayPath {
        relay: r,
        ip,
        port: role.obfs_port?,
        via: RelayVia::Obfs(state.obfs_padding?),
    })
}

fn tls_path<'a>(r: &'a Machine, ip: IpAddr, role: RelayRole) -> Option<RelayPath<'a>> {
    Some(RelayPath {
        relay: r,
        ip,
        port: role.tls_port?,
        via: RelayVia::Tls(r.relay_fingerprint()?),
    })
}

/// Whose obfuscated port a key is for: a relay's or a machine's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfsPortOf {
    Relay,
    Machine,
}

/// An obfuscated port's key (design/obfuscation.md section 4): HMAC-SHA256 of a label and the node ID
/// of the machine it is on under the site's relay key, so the site and the Hub derive the same key,
/// and the two ports of a relay's machine have different ones.
pub fn obfs_key(key: &RelayKey, of: ObfsPortOf, node: &NodeId) -> ObfsSecret {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key.0);
    let mut ctx = ring::hmac::Context::with_key(&key);
    ctx.update(match of {
        ObfsPortOf::Relay => b"nett obfuscation v1".as_slice(),
        ObfsPortOf::Machine => b"nett machine obfuscation v1".as_slice(),
    });
    ctx.update(&[0]);
    ctx.update(node.as_str().as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.sign().as_ref());
    ObfsSecret(out)
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
    let obfs = role
        .obfs_port
        .zip(state.obfs_padding)
        .map(|(port, padding)| ObfsPortDoc {
            port,
            key: obfs_key(key, ObfsPortOf::Relay, &me.node_id),
            padding,
        });
    Some(RelayDoc {
        port: role.port,
        tls_port: role.tls_port,
        members,
        links,
        obfs,
    })
}

/// The machine's own obfuscated port, with its key and the site's padding range (ADR 0031).
fn own_obfs(state: &State, me: &Machine) -> Option<ObfsPortDoc> {
    Some(ObfsPortDoc {
        port: me.obfs_port?,
        key: obfs_key(state.relay_key.as_ref()?, ObfsPortOf::Machine, &me.node_id),
        padding: state.obfs_padding?,
    })
}

/// The LAN direct paths to a peer (design/mesh.md section 6): one for each LAN address the peer
/// reported, at its WireGuard port, IPv4 first, whatever network the two are on: probes decide
/// which ones work, as Tailscale tries every interface address of a peer. An address this machine
/// has itself leads back to it and is left out.
fn lan(state: &State, me: &Machine, peer: &Machine) -> Vec<Candidate> {
    let Some(port) = peer
        .listen_port(state.listen_port)
        .or(peer.learned.listen_port)
    else {
        return Vec::new();
    };
    let mut ips: Vec<IpAddr> = peer
        .learned
        .lan
        .iter()
        .map(|theirs| theirs.addr)
        .filter(|ip| !me.learned.lan.iter().any(|mine| mine.addr == *ip))
        .collect();
    ips.sort_by_key(|ip| !ip.is_ipv4());
    ips.dedup();
    ips.into_iter()
        .take(nett_mesh::lan::MAX_LAN_ADDRESSES)
        .map(|ip| Candidate::Lan {
            endpoint: SocketAddr::new(ip, port),
        })
        .collect()
}

/// The direct paths that count toward the limit: obfuscated UDP to the peer's own obfuscated port
/// for the end that decides the path, then the public direct ones.
fn direct(state: &State, me: &Machine, peer: &Machine) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = direct_obfs(state, me, peer).into_iter().collect();
    out.extend(public(state, me, peer));
    out
}

/// Obfuscated UDP to the peer's own obfuscated port (design/obfuscation.md section 5), for the end
/// that decides the path (mesh.md section 8.3): at its public IPv4 address, or IPv6 without one.
fn direct_obfs(state: &State, me: &Machine, peer: &Machine) -> Option<Candidate> {
    let port = peer.obfs_port?;
    if !is_decider(
        &me.node_id,
        me.reachability,
        &peer.node_id,
        peer.reachability,
    ) {
        return None;
    }
    let ip = peer
        .public_ipv4()
        .map(IpAddr::V4)
        .or_else(|| peer.public_ipv6().map(IpAddr::V6))?;
    Some(Candidate::DirectObfs {
        endpoint: SocketAddr::new(ip, port),
        key: obfs_key(
            state.relay_key.as_ref()?,
            ObfsPortOf::Machine,
            &peer.node_id,
        ),
        padding: state.obfs_padding?,
    })
}

/// Direct candidate paths from this machine to a peer (design/mesh.md section 6): the LAN direct
/// paths first; when the peer is `public`, connect directly to its public address (the one given, or
/// the one the Hub learned; one each for IPv4 and IPv6 when both exist); when both ends are
/// `dial-only`, hole punching; when this machine is `public` and the peer is `dial-only`, nothing
/// more, and the peer connects in (WireGuard roaming).
fn public(state: &State, me: &Machine, peer: &Machine) -> Vec<Candidate> {
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
            .chain(
                state
                    .revoked_credentials
                    .iter()
                    .map(|r| Revocation::DeviceCredential {
                        credential_id: r.credential_id.clone(),
                    }),
            )
            .collect(),
        paths,
        access_rules: state.access_rules.as_ref().map(|r| r.signed.clone()),
        advertised_routes: state
            .machines
            .values()
            .filter_map(|m| m.routes_signed.as_ref().map(|r| r.signed.clone()))
            .collect(),
        devices: state
            .devices
            .iter()
            .filter_map(|(name, d)| {
                Some(DeviceDoc {
                    credential: d.credential.signed.clone()?,
                    gateway: d.gateway.clone(),
                    name: Some(name.clone()),
                })
            })
            .collect(),
        names,
        relay: relay_doc(state, me),
        obfs: own_obfs(state, me),
    };
    // The generated desired state must be accepted by the mesh
    DesiredMesh::from_doc(doc.clone()).map_err(|e| {
        SiteError::invalid(format!("machine `{name}`: generated desired state: {e}"))
    })?;
    Ok(Some(doc))
}
