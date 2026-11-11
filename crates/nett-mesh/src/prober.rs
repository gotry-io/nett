//! Runtime state of probing and path selection (design/mesh.md sections 7 and 8): maintains candidate
//! paths for each peer, sends and receives probe messages, and produces the packets to send and the
//! switches to perform; when both sides are `dial-only`, coordinates a two-ended switchover (section
//! 8.4). It does not touch sockets or the data plane; [`crate::engine`] performs those, and tests can
//! drive it directly.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use nett_core::id::NodeId;
use nett_trust::admission::Member;
use nett_trust::keys::X25519PublicKey;

use crate::config::{Candidate, PeerPathConfig, ProbeToken, Reachability};
use crate::event::Event;
use crate::key::PrivateKey;
use crate::path::{
    Action, CandidateView, LATE_HORIZON, PathKind, PathStats, PeerPaths, Role, Route, SwitchReason,
};
use crate::probe::{
    self, DIRECT_PROBE, DIRECT_REPLY, KeyId, OuterProbe, OuterReply, PUNCH_ACK, PUNCH_PROPOSAL,
    ProbeKey, PunchMessage, RELAY_PROBE, RelayReport, SWITCH_ACK, SWITCH_PROPOSAL, SwitchMessage,
    SwitchTarget, TUNNEL_PROBE_PORT,
};
use crate::punch::{Observations, Punch, PunchEvent};

/// Upper limit on how long a sent probe waits for a reply; after that it is removed from the lookup table
/// (each state machine decides loss itself). In-tunnel probes are kept for [`LATE_HORIZON`]: late
/// replies that queued for a few seconds must also be handed to the path selection state machine
/// (design/mesh.md section 7).
const OUTSTANDING_TTL: Duration = Duration::from_secs(2);
/// Upper limit of the lookup table: fewer than 20 in-tunnel probes within 10 seconds for each peer with
/// traffic, plus probes of candidates and relays.
const MAX_OUTSTANDING: usize = 4096;
/// Interval at which the follower measures relays: only to provide the decider with the "relay -> this
/// machine" leg.
const RELAY_MONITOR_INTERVAL: Duration = Duration::from_secs(5);
/// Window for judging whether there is traffic (design/mesh.md section 7).
pub const ACTIVE_WINDOW: Duration = Duration::from_secs(30);
/// Resend interval and count of switch proposals: if no confirmation arrives in about 2 seconds, the
/// decider switches as usual, and a later outage enters rotation (section 8.4).
const PROPOSAL_RETRY: Duration = Duration::from_millis(300);
const PROPOSAL_TRIES: u32 = 7;
/// Through the Hub (design/mesh.md section 8.4): the decider resends its proposal every second, 3 times,
/// and then rotates by time slot; the follower waits this long for a proposal before it rotates.
const HUB_PROPOSAL_RETRY: Duration = Duration::from_secs(1);
const HUB_PROPOSAL_TRIES: u32 = 3;
const HUB_WAIT: Duration = Duration::from_secs(4);
/// How long the follower waits after sending the confirmation before switching: the confirmation is sent
/// through the current session, and switching deletes that session.
const ACK_GRACE: Duration = Duration::from_millis(100);
/// Time slice of the rotation (section 8.4).
const ROTATION_SLOT_MS: u64 = 15_000;
/// Range of the random retry interval when the clock is not trusted.
const RANDOM_RETRY_MIN: Duration = Duration::from_secs(5);
const RANDOM_RETRY_MAX: Duration = Duration::from_secs(15);

/// Packets to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outgoing {
    /// Sent through `nett0` to the probe port on the peer's mesh address.
    Tunnel { to: SocketAddr, data: Vec<u8> },
    /// Sent from the mesh process's own port to the relay.
    Relay { to: SocketAddr, data: Vec<u8> },
    /// Sent from the WireGuard port (section 7.1).
    Direct { to: SocketAddr, data: Vec<u8> },
    /// Handed to nett-node, which relays it through the Hub to the peer's nett-node (section 8.4).
    Hub { peer: NodeId, data: Vec<u8> },
}

/// Where a received packet came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Incoming {
    /// The probe port on the mesh address.
    Tunnel,
    /// The socket the mesh process uses to send to relays.
    Relay,
    /// The copy on the WireGuard port.
    Direct,
}

/// How a peer's path selection state appears in local status (design/status.md section 6).
#[derive(Debug, Clone)]
pub struct PeerView {
    pub linked: bool,
    /// Role when path selection state exists; `None` means following through roaming (design/mesh.md section
    /// 8.3).
    pub role: Option<Role>,
    /// Candidate paths (including the punched direct path): the follower uses these to tell which path
    /// WireGuard's current endpoint is.
    pub routes: Vec<(Route, PathKind)>,
    /// Measurements of each candidate when path selection state exists, including the current path.
    pub candidates: Vec<CandidateView>,
    /// Measurement of in-tunnel probes on the current path when path selection state exists.
    pub tunnel: Option<TunnelView>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TunnelView {
    pub rtt_ms: Option<f64>,
    pub loss: Option<f64>,
    pub jitter_ms: f64,
}

/// The switch to perform on the data plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Switch {
    pub peer: NodeId,
    pub public_key: X25519PublicKey,
    pub to: Route,
    pub rehandshake: bool,
    pub reason: SwitchReason,
}

enum CandidateMeta {
    Direct,
    /// `tls`: TLS transport via the transport adapter; the measurement is not counted as this machine's UDP
    /// measurement to this relay.
    Relay {
        relay: KeyId,
        key: ProbeKey,
        tls: bool,
    },
}

struct Peer {
    /// The desired state has a path to it (the site description has a `link` for this pair).
    linked: bool,
    public_key: X25519PublicKey,
    mesh_addrs: [IpAddr; 2],
    direct_key: Option<ProbeKey>,
    /// Key of the switch messages relayed through the Hub.
    switch_key: Option<ProbeKey>,
    /// The first `configured` come from the desired state, followed by punched direct paths.
    routes: Vec<(Route, PathKind)>,
    meta: Vec<CandidateMeta>,
    configured: usize,
    /// Only the decider, and both ends when both sides are `dial-only`, have path selection state.
    paths: Option<PeerPaths>,
    /// State of the two-ended switchover when both sides are `dial-only`.
    together: Option<Together>,
    /// Hole punching state when both sides are `dial-only` and hole punching candidates are configured
    /// (design/mesh.md section 6.1).
    punch: Option<Punch>,
    reports: HashMap<KeyId, (Duration, f64)>,
    last_activity: Option<Instant>,
}

/// Two-ended switchover (design/mesh.md section 8.4).
#[derive(Debug, Clone, Default)]
struct Together {
    /// Decider: the proposal awaiting confirmation.
    proposal: Option<Proposal>,
    /// Follower: the proposal round most recently accepted; earlier rounds are dropped directly.
    accepted_round: u32,
    /// Follower: the switch that has been confirmed and is waiting to be executed (target candidate,
    /// execution time).
    accepted: Option<(usize, Instant)>,
    /// The current path is broken and rotation is in progress.
    rotation: Option<Rotation>,
    /// Follower: the current path is broken and the Hub is up; until then it waits for the decider's
    /// proposal through the Hub before it rotates.
    hub_wait: Option<Instant>,
}

#[derive(Debug, Clone)]
struct Proposal {
    round: u32,
    target: SwitchTarget,
    index: usize,
    reason: SwitchReason,
    next_send: Instant,
    sent: u32,
    /// Sent through the Hub because the current path is broken; otherwise through the tunnel.
    via_hub: bool,
}

#[derive(Debug, Clone, Default)]
struct Rotation {
    /// Clock trusted: the time slice in which the most recent re-handshake took place.
    slot: Option<u64>,
    /// Clock not trusted: the time of the next random retry.
    next_random: Option<Instant>,
}

#[derive(Debug, Clone, Copy)]
enum Pending {
    Tunnel {
        local: u32,
    },
    Candidate {
        index: usize,
        local: u32,
    },
    /// A probe of a relay outside path selection: over UDP it measures the relay for the peer, over TLS it
    /// keeps the standby connection authenticated.
    Monitor {
        relay: KeyId,
        tls: bool,
    },
    /// Hole punching probe.
    Punch,
}

pub struct Prober {
    own_key_id: KeyId,
    peers: BTreeMap<NodeId, Peer>,
    by_mesh_addr: HashMap<IpAddr, NodeId>,
    by_key_id: HashMap<KeyId, NodeId>,
    /// Sequence number on the wire -> which probe of which peer. Each state machine's sequence numbers are
    /// independent, and here they are mapped to globally unique sequence numbers.
    outstanding: HashMap<u32, (NodeId, Pending, Instant)>,
    wire_seq: u32,
    /// This machine's measurements to each relay, carried to the peer with in-tunnel replies.
    relay_stats: HashMap<KeyId, PathStats>,
    /// Relays probed outside path selection: (number, over TLS) -> (address, token, last probe). Over UDP
    /// the follower measures each relay, for the peer to estimate the other leg of the relay path; over TLS
    /// the follower of a pair of `dial-only` members keeps its standby connection authenticated, since it
    /// may have to move there together with the decider (design/mesh.md sections 5.3 and 8.4).
    monitored: HashMap<(KeyId, bool), (SocketAddr, ProbeKey, Option<Instant>)>,
    /// The round of the most recent switch proposal.
    round: u32,
    /// The switch to perform after a confirmation is received, handed out at the next [`Prober::tick`].
    ready: Vec<Switch>,
    /// The local clock error is within 2 seconds: rotation uses time slices; otherwise random intervals
    /// (section 8.4).
    clock_trusted: bool,
    /// nett-node reports its Hub session up: switch proposals can go through the Hub (section 8.4).
    hub: bool,
    /// The mapped address that `public` nodes report to this machine (design/mesh.md section 6.1).
    observations: Observations,
    /// Events to be reported by the caller.
    events: Vec<Event>,
}

/// The role of this side in this pair (design/mesh.md sections 8.3 and 8.4); `None` means the side that
/// follows through roaming.
pub fn role(
    own: &NodeId,
    own_reach: Reachability,
    peer: &NodeId,
    peer_reach: Reachability,
) -> Option<Role> {
    let decider = is_decider(own, own_reach, peer, peer_reach);
    match (own_reach, peer_reach, decider) {
        (Reachability::DialOnly, Reachability::DialOnly, true) => Some(Role::DecideTogether),
        (Reachability::DialOnly, Reachability::DialOnly, false) => Some(Role::FollowTogether),
        (_, _, true) => Some(Role::Decide),
        (_, _, false) => None,
    }
}

/// Who decides the path of this pair (design/mesh.md section 8.3): when `dial-only` meets `public`, the
/// `dial-only` side decides; otherwise the side with the smaller member ID decides.
pub fn is_decider(
    own: &NodeId,
    own_reach: Reachability,
    peer: &NodeId,
    peer_reach: Reachability,
) -> bool {
    match (own_reach, peer_reach) {
        (Reachability::DialOnly, Reachability::Public) => true,
        (Reachability::Public, Reachability::DialOnly) => false,
        _ => own < peer,
    }
}

/// A candidate's endpoint in WireGuard and the information used for measurement. The endpoint of a TLS
/// candidate is the transport adapter's loopback port, given by `tls`; a TLS candidate that was not
/// assigned a port is not used.
fn routes(
    candidates: &[Candidate],
    tls: &BTreeMap<NodeId, SocketAddr>,
) -> (Vec<(Route, PathKind)>, Vec<CandidateMeta>) {
    candidates
        .iter()
        .filter_map(|c| match c {
            Candidate::Direct { endpoint } => Some((
                (Route::Direct(*endpoint), PathKind::Direct),
                CandidateMeta::Direct,
            )),
            Candidate::Relay {
                relay,
                endpoint,
                token,
            } => Some(relay_route(relay, *endpoint, token, false)),
            Candidate::RelayTls { relay, token, .. } => {
                Some(relay_route(relay, *tls.get(relay)?, token, true))
            }
            // The address for hole punching is exchanged during hole punching, and becomes a candidate only after
            // the punch succeeds
            Candidate::Punch => None,
        })
        .unzip()
}

fn relay_route(
    relay: &NodeId,
    endpoint: SocketAddr,
    token: &ProbeToken,
    tls: bool,
) -> ((Route, PathKind), CandidateMeta) {
    let id = KeyId::of(relay.as_str().as_bytes());
    let kind = if tls {
        PathKind::RelayTls
    } else {
        PathKind::Relay
    };
    (
        (
            Route::Relay {
                relay: id,
                endpoint,
            },
            kind,
        ),
        CandidateMeta::Relay {
            relay: id,
            key: ProbeKey::from_token(&token.0),
            tls,
        },
    )
}

impl Prober {
    pub fn new(own_public_key: &X25519PublicKey) -> Self {
        Self {
            own_key_id: KeyId::of(own_public_key.as_bytes()),
            peers: BTreeMap::new(),
            by_mesh_addr: HashMap::new(),
            by_key_id: HashMap::new(),
            outstanding: HashMap::new(),
            wire_seq: 0,
            relay_stats: HashMap::new(),
            monitored: HashMap::new(),
            round: 0,
            ready: Vec::new(),
            clock_trusted: false,
            hub: false,
            observations: Observations::default(),
            events: Vec::new(),
        }
    }

    /// Takes the events to report.
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// A peer is probing at high frequency the better path it just switched away from (design/mesh.md
    /// section 7), or is waiting for a re-handshake to complete (section 8.4).
    pub fn needs_fine_ticks(&self, now: Instant) -> bool {
        self.peers.values().any(|p| {
            p.paths
                .as_ref()
                .is_some_and(|paths| paths.needs_fine_ticks(now))
        })
    }

    /// A peer's deadline for waiting for confirmation after a re-handshake has arrived: the caller first
    /// reads WireGuard's handshake state, then advances.
    pub fn handshake_due(&self, now: Instant) -> bool {
        self.peers.values().any(|p| {
            p.paths
                .as_ref()
                .is_some_and(|paths| paths.handshake_due(now))
        })
    }

    /// A cookie reply arrived on the WireGuard port (read-only copy): handed to the peer whose current path
    /// is `from` and whose tunnel is not yet established (design/mesh.md section 8.4). The cookie reply
    /// itself cannot be verified; its only effect is to postpone one failure switch.
    fn on_cookie_reply(&mut self, from: SocketAddr, at: Instant) {
        for peer in self.peers.values_mut() {
            if let Some(paths) = peer.paths.as_mut()
                && paths.current().endpoint() == from
                && !paths.tunnel_established()
            {
                paths.on_cookie(at);
            }
        }
    }

    /// WireGuard reports that this peer has completed a handshake since it joined (or re-joined on a
    /// re-handshake).
    pub fn on_handshake(&mut self, id: &NodeId) {
        if let Some(paths) = self.peers.get_mut(id).and_then(|p| p.paths.as_mut()) {
            paths.on_handshake();
        }
    }

    /// Whether the local clock error is within 2 seconds (design/mesh.md section 8.4), updated periodically
    /// by the runtime.
    pub fn set_clock_trusted(&mut self, trusted: bool) {
        self.clock_trusted = trusted;
    }

    /// Updates from the admitted members and the candidate paths in the desired state. Peers whose candidate
    /// list has not changed keep their path selection state. `tls` is the loopback port of each TLS relay
    /// on the transport adapter ([`crate::config::DesiredMesh::tls_endpoints`]).
    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &mut self,
        own_id: &NodeId,
        own_reach: Reachability,
        private_key: &PrivateKey,
        members: &BTreeMap<NodeId, Member>,
        paths: &BTreeMap<NodeId, PeerPathConfig>,
        tls: &BTreeMap<NodeId, SocketAddr>,
    ) {
        let mut next = BTreeMap::new();
        self.monitored.clear();
        for (id, member) in members.iter().filter(|(id, _)| *id != own_id) {
            let config = paths.get(id);
            let candidates = config.map(|c| c.candidates.as_slice()).unwrap_or_default();
            let (mut routes, mut meta) = routes(candidates, tls);
            let configured = routes.len();
            let role = config.and_then(|c| role(own_id, own_reach, id, c.reachability));
            let punch_wanted =
                role.is_some_and(Role::together) && candidates.contains(&Candidate::Punch);
            let previous = self.peers.remove(id).filter(|p| {
                p.routes[..p.configured] == routes[..] && p.public_key == member.mesh_public_key
            });
            let kept = previous
                .as_ref()
                .and_then(|p| p.paths.as_ref().map(|paths| (paths, &p.together, &p.punch)))
                .filter(|(paths, _, _)| Some(paths.role()) == role);
            // When path selection state is kept, the punched direct path is kept too
            if kept.is_some()
                && let Some(prev) = &previous
            {
                for extra in &prev.routes[prev.configured..] {
                    routes.push(*extra);
                    meta.push(CandidateMeta::Direct);
                }
            }
            let punch = match kept {
                Some((_, _, punch)) if punch_wanted => {
                    punch.clone().or_else(|| Some(Punch::new(Instant::now())))
                }
                _ if punch_wanted => Some(Punch::new(Instant::now())),
                _ => None,
            };
            let (paths, together) = match (kept, role) {
                (Some((paths, together, _)), _) => (Some(paths.clone()), together.clone()),
                (None, Some(role)) => (
                    PeerPaths::new(routes.clone(), role),
                    role.together().then(Together::default),
                ),
                (None, None) => (None, None),
            };
            let follows_together = role == Some(Role::FollowTogether);
            for (m, (route, _)) in meta.iter().zip(&routes) {
                let (CandidateMeta::Relay { relay, key, tls }, Route::Relay { endpoint, .. }) =
                    (m, route)
                else {
                    continue;
                };
                if *tls && !follows_together {
                    continue;
                }
                self.monitored
                    .entry((*relay, *tls))
                    .or_insert_with(|| (*endpoint, key.clone(), None));
            }
            next.insert(
                id.clone(),
                Peer {
                    linked: config.is_some(),
                    public_key: member.mesh_public_key,
                    mesh_addrs: [
                        IpAddr::V4(member.addresses.ipv4),
                        IpAddr::V6(member.addresses.ipv6),
                    ],
                    direct_key: ProbeKey::direct(private_key, &member.mesh_public_key),
                    switch_key: ProbeKey::path_switch(private_key, &member.mesh_public_key),
                    routes,
                    meta,
                    configured,
                    paths,
                    together,
                    punch,
                    reports: previous
                        .as_ref()
                        .map(|p| p.reports.clone())
                        .unwrap_or_default(),
                    last_activity: previous.and_then(|p| p.last_activity),
                },
            );
        }
        self.peers = next;
        self.by_mesh_addr = self
            .peers
            .iter()
            .flat_map(|(id, p)| p.mesh_addrs.iter().map(move |a| (*a, id.clone())))
            .collect();
        self.by_key_id = self
            .peers
            .iter()
            .map(|(id, p)| (KeyId::of(p.public_key.as_bytes()), id.clone()))
            .collect();
    }

    /// Endpoint of the current path: with path selection state it is taken from it, otherwise from the first
    /// candidate (afterwards WireGuard's roaming follows).
    pub fn endpoint(&self, peer: &NodeId) -> Option<SocketAddr> {
        let p = self.peers.get(peer)?;
        match &p.paths {
            Some(paths) => Some(paths.current().endpoint()),
            None => p.routes.first().map(|(r, _)| r.endpoint()),
        }
    }

    /// The intended endpoint, used to correct an endpoint changed by roaming (section 8.3). The side that
    /// follows through roaming returns `None`.
    pub fn desired_endpoint(&self, peer: &NodeId) -> Option<SocketAddr> {
        self.peers
            .get(peer)?
            .paths
            .as_ref()
            .map(|p| p.current().endpoint())
    }

    /// Records that the peer recently had traffic.
    pub fn mark_active(&mut self, peer: &NodeId, now: Instant) {
        if let Some(p) = self.peers.get_mut(peer) {
            p.last_activity = Some(now);
        }
    }

    /// WireGuard's received byte count for this peer changed: the peer's packets are still arriving
    /// (design/mesh.md section 8.2).
    pub fn on_receive(&mut self, peer: &NodeId, now: Instant) {
        if let Some(paths) = self.peers.get_mut(peer).and_then(|p| p.paths.as_mut()) {
            paths.on_receive(now);
        }
    }

    /// Path selection state of a peer (design/status.md section 6).
    pub fn peer_view(&self, peer: &NodeId, now: Instant) -> Option<PeerView> {
        let p = self.peers.get(peer)?;
        Some(PeerView {
            linked: p.linked,
            role: p.paths.as_ref().map(PeerPaths::role),
            routes: p.routes.clone(),
            candidates: p
                .paths
                .as_ref()
                .map(|paths| paths.candidate_views(now))
                .unwrap_or_default(),
            tunnel: p.paths.as_ref().map(|paths| {
                let t = paths.tunnel_stats();
                TunnelView {
                    rtt_ms: t.rtt_ms(),
                    loss: t.measured_loss(),
                    jitter_ms: t.jitter_ms(),
                }
            }),
        })
    }

    /// This machine's NAT type and mapped addresses (design/mesh.md section 6.1).
    pub fn own_nat(&self, now: Instant) -> crate::punch::OwnInfo {
        self.observations.own(now)
    }

    pub fn peer_ids(&self) -> impl Iterator<Item = (&NodeId, &X25519PublicKey)> {
        self.peers.iter().map(|(id, p)| (id, &p.public_key))
    }

    fn next_wire_seq(&mut self) -> u32 {
        self.wire_seq = self.wire_seq.wrapping_add(1);
        self.wire_seq
    }

    fn remember(&mut self, peer: &NodeId, pending: Pending, now: Instant) -> Option<u32> {
        if self.outstanding.len() >= MAX_OUTSTANDING {
            return None;
        }
        let seq = self.next_wire_seq();
        self.outstanding.insert(seq, (peer.clone(), pending, now));
        Some(seq)
    }

    pub fn tick(&mut self, now: Instant, now_ms: u64) -> (Vec<Outgoing>, Vec<Switch>) {
        let mut out = Vec::new();
        let mut switches = std::mem::take(&mut self.ready);

        // Expired lookup entries: relay measurements are recorded as lost, and the rest are decided by each
        // state machine itself
        let expired: Vec<u32> = self
            .outstanding
            .iter()
            .filter(|(_, (_, pending, at))| {
                let ttl = match pending {
                    Pending::Tunnel { .. } => LATE_HORIZON,
                    _ => OUTSTANDING_TTL,
                };
                now.saturating_duration_since(*at) >= ttl
            })
            .map(|(seq, _)| *seq)
            .collect();
        for seq in expired {
            if let Some((_, Pending::Monitor { relay, tls: false }, _)) =
                self.outstanding.remove(&seq)
            {
                self.relay_stats.entry(relay).or_default().record_loss();
            }
        }

        let ids: Vec<NodeId> = self.peers.keys().cloned().collect();
        for id in ids {
            let Some(peer) = self.peers.get_mut(&id) else {
                continue;
            };
            // During rotation always probe the tunnel: a reply to this end's probe is a two-way confirmation
            let active = peer
                .last_activity
                .is_some_and(|t| now.saturating_duration_since(t) < ACTIVE_WINDOW)
                || peer.together.as_ref().is_some_and(|t| t.rotation.is_some());
            let Some(paths) = peer.paths.as_mut() else {
                continue;
            };
            let mut actions = paths.tick(now, active);
            actions.extend(self.coordinate(&id, now, now_ms));
            for action in actions {
                match action {
                    Action::TunnelProbe { seq } => {
                        let to = SocketAddr::new(self.peers[&id].mesh_addrs[0], TUNNEL_PROBE_PORT);
                        if let Some(wire) = self.remember(&id, Pending::Tunnel { local: seq }, now)
                        {
                            out.push(Outgoing::Tunnel {
                                to,
                                data: probe::encode_tunnel_probe(wire).to_vec(),
                            });
                        }
                    }
                    Action::CandidateProbe { index, route, seq } => {
                        let Some(wire) =
                            self.remember(&id, Pending::Candidate { index, local: seq }, now)
                        else {
                            continue;
                        };
                        let peer = &self.peers[&id];
                        match (&peer.meta[index], route) {
                            (CandidateMeta::Direct, Route::Direct(to)) => {
                                if let Some(key) = &peer.direct_key {
                                    let probe = OuterProbe {
                                        kind: DIRECT_PROBE,
                                        key_id: self.own_key_id,
                                        seq: wire,
                                        sent_ms: now_ms,
                                    };
                                    out.push(Outgoing::Direct {
                                        to,
                                        data: probe.encode(key).to_vec(),
                                    });
                                }
                            }
                            (CandidateMeta::Relay { key, .. }, Route::Relay { endpoint, .. }) => {
                                let probe = OuterProbe {
                                    kind: RELAY_PROBE,
                                    key_id: self.own_key_id,
                                    seq: wire,
                                    sent_ms: now_ms,
                                };
                                out.push(Outgoing::Relay {
                                    to: endpoint,
                                    data: probe.encode(key).to_vec(),
                                });
                            }
                            _ => {}
                        }
                    }
                    Action::Switch {
                        to,
                        rehandshake,
                        reason,
                    } => switches.push(Switch {
                        peer: id.clone(),
                        public_key: self.peers[&id].public_key,
                        to,
                        rehandshake,
                        reason,
                    }),
                    Action::Propose { index, reason } => {
                        let round = self.next_round(now_ms);
                        if let Some(switch) = self.propose(&id, index, reason, round, now) {
                            switches.push(switch);
                        }
                    }
                    Action::Lost => self.lost(&id, now, now_ms),
                }
            }
            // A new proposal is sent immediately; those already waiting are resent at intervals
            out.extend(self.send_proposal(&id, now, now_ms));
            out.extend(self.punch_tick(&id, now, now_ms));
        }

        // The follower also measures relays, for the peer to estimate the other leg of the relay path, and
        // keeps its TLS standby connections authenticated
        let due: Vec<(KeyId, bool)> = self
            .monitored
            .iter()
            .filter(|(_, (_, _, last))| {
                last.is_none_or(|t| now.saturating_duration_since(t) >= RELAY_MONITOR_INTERVAL)
            })
            .map(|(id, _)| *id)
            .collect();
        let any_peer = self.peers.keys().next().cloned();
        for (relay, tls) in due {
            let Some(owner) = any_peer.clone() else { break };
            let Some(wire) = self.remember(&owner, Pending::Monitor { relay, tls }, now) else {
                break;
            };
            if let Some((endpoint, key, last)) = self.monitored.get_mut(&(relay, tls)) {
                *last = Some(now);
                let probe = OuterProbe {
                    kind: RELAY_PROBE,
                    key_id: self.own_key_id,
                    seq: wire,
                    sent_ms: now_ms,
                };
                out.push(Outgoing::Relay {
                    to: *endpoint,
                    data: probe.encode(key).to_vec(),
                });
            }
        }
        (out, switches)
    }

    fn next_round(&mut self, now_ms: u64) -> u32 {
        // Use Unix seconds as the lower bound: rounds after a restart are also greater than those before it, so
        // the follower does not treat them as stale
        let secs = u32::try_from(now_ms / 1000).unwrap_or(u32::MAX);
        self.round = self.round.wrapping_add(1).max(secs);
        self.round
    }

    /// The decider is to switch to candidate `index`: when the target is a relay or a punched direct path,
    /// proposing begins; other direct paths are switched directly.
    fn propose(
        &mut self,
        id: &NodeId,
        index: usize,
        reason: SwitchReason,
        round: u32,
        now: Instant,
    ) -> Option<Switch> {
        let peer = self.peers.get_mut(id)?;
        let paths = peer.paths.as_mut()?;
        let together = peer.together.as_mut()?;
        let target = match peer.routes.get(index) {
            Some((Route::Relay { relay, .. }, _)) => Some(SwitchTarget::Relay(*relay)),
            Some((Route::Direct(_), _)) if paths.punched_index() == Some(index) => {
                Some(SwitchTarget::Punched)
            }
            _ => None,
        };
        match target {
            Some(target) => {
                together.proposal = Some(Proposal {
                    round,
                    target,
                    index,
                    reason,
                    next_send: now,
                    sent: 0,
                    via_hub: false,
                });
                None
            }
            None => {
                paths.set_hold(false);
                let action = paths.adopt(index, reason, now)?;
                switch_of(id, peer.public_key, action)
            }
        }
    }

    /// nett-node reports whether its Hub session is up (design/status.md section 4.2).
    pub fn set_hub(&mut self, up: bool) {
        self.hub = up;
    }

    /// Both sides `dial-only` and the current path is broken (section 8.4): with the Hub up, the decider
    /// proposes the best other relay through it and the follower waits for that proposal; otherwise both
    /// rotate by time slot. A recovery already under way continues.
    fn lost(&mut self, id: &NodeId, now: Instant, now_ms: u64) {
        let round = self.next_round(now_ms);
        let hub = self.hub;
        let Some(peer) = self.peers.get_mut(id) else {
            return;
        };
        let (Some(paths), Some(together)) = (peer.paths.as_mut(), peer.together.as_mut()) else {
            return;
        };
        if together.rotation.is_some() || together.proposal.is_some() || together.hub_wait.is_some()
        {
            return;
        }
        if hub && peer.switch_key.is_some() {
            match paths.role() {
                Role::DecideTogether => {
                    if let Some(index) = paths.best_other_relay(now)
                        && let Some((Route::Relay { relay, .. }, _)) = peer.routes.get(index)
                    {
                        paths.set_hold(true);
                        together.proposal = Some(Proposal {
                            round,
                            target: SwitchTarget::Relay(*relay),
                            index,
                            reason: SwitchReason::Unreachable,
                            next_send: now,
                            sent: 0,
                            via_hub: true,
                        });
                        return;
                    }
                }
                Role::FollowTogether => {
                    paths.set_hold(true);
                    together.hub_wait = Some(now + HUB_WAIT);
                    return;
                }
                Role::Decide => {}
            }
        }
        self.start_rotation(id);
    }

    /// Sends (or resends) the proposal awaiting confirmation. Through the tunnel, when the resends are used
    /// up with still no confirmation, the decider switches as usual; through the Hub, it rotates by time
    /// slot (section 8.4).
    fn send_proposal(&mut self, id: &NodeId, now: Instant, now_ms: u64) -> Vec<Outgoing> {
        let Some(peer) = self.peers.get_mut(id) else {
            return vec![];
        };
        let to = SocketAddr::new(peer.mesh_addrs[0], TUNNEL_PROBE_PORT);
        let (Some(paths), Some(together)) = (peer.paths.as_mut(), peer.together.as_mut()) else {
            return vec![];
        };
        let Some(p) = together.proposal.as_mut() else {
            return vec![];
        };
        if now < p.next_send {
            return vec![];
        }
        if p.via_hub {
            let Some(key) = &peer.switch_key else {
                return vec![];
            };
            if p.sent >= HUB_PROPOSAL_TRIES {
                together.proposal = None;
                together.rotation = Some(Rotation::default());
                return vec![];
            }
            p.sent += 1;
            p.next_send = now + HUB_PROPOSAL_RETRY;
            let message = SwitchMessage {
                kind: SWITCH_PROPOSAL,
                round: p.round,
                target: p.target,
            };
            return vec![Outgoing::Hub {
                peer: id.clone(),
                data: message.seal(now_ms, key).to_vec(),
            }];
        }
        if p.sent >= PROPOSAL_TRIES {
            let (index, reason) = (p.index, p.reason);
            together.proposal = None;
            paths.set_hold(false);
            if let Some(switch) = paths
                .adopt(index, reason, now)
                .and_then(|a| switch_of(id, peer.public_key, a))
            {
                self.ready.push(switch);
            }
            return vec![];
        }
        p.sent += 1;
        p.next_send = now + PROPOSAL_RETRY;
        let message = SwitchMessage {
            kind: SWITCH_PROPOSAL,
            round: p.round,
            target: p.target,
        };
        vec![Outgoing::Tunnel {
            to,
            data: message.encode().to_vec(),
        }]
    }

    fn start_rotation(&mut self, id: &NodeId) {
        let Some(together) = self.peers.get_mut(id).and_then(|p| p.together.as_mut()) else {
            return;
        };
        if together.rotation.is_none() {
            together.proposal = None;
            together.accepted = None;
            together.rotation = Some(Rotation::default());
        }
    }

    /// Advancing the two-ended switchover: the follower executes the confirmed proposal; during rotation it
    /// re-handshakes by time slice (or random interval), and stops at the current relay once this end's
    /// in-tunnel probe gets a reply (section 8.4).
    fn coordinate(&mut self, id: &NodeId, now: Instant, now_ms: u64) -> Vec<Action> {
        let trusted = self.clock_trusted;
        let hub = self.hub;
        let Some(peer) = self.peers.get_mut(id) else {
            return vec![];
        };
        let (Some(paths), Some(together)) = (peer.paths.as_mut(), peer.together.as_mut()) else {
            return vec![];
        };
        if let Some((index, due)) = together.accepted
            && now >= due
        {
            together.accepted = None;
            together.rotation = None;
            together.hub_wait = None;
            paths.set_hold(false);
            return paths
                .adopt(index, SwitchReason::Proposed, now)
                .into_iter()
                .collect();
        }
        // The follower waits for the decider's proposal through the Hub, and rotates when none comes in
        // time or the Hub goes down
        if let Some(deadline) = together.hub_wait {
            if together.accepted.is_some() || (now < deadline && hub) {
                return vec![];
            }
            together.hub_wait = None;
            together.rotation = Some(Rotation::default());
        }
        let Some(rotation) = together.rotation.as_mut() else {
            return vec![];
        };
        // Already re-handshaked, and this end's in-tunnel probe got a reply: both directions work, stay on this
        // relay
        if (rotation.slot.is_some() || rotation.next_random.is_some()) && paths.tunnel_established()
        {
            together.rotation = None;
            paths.set_hold(false);
            return vec![];
        }
        paths.set_hold(true);
        let relays = paths.relays_in_order();
        if relays.is_empty() {
            return vec![];
        }
        let n = relays.len() as u64;
        let target = if trusted {
            let slot = now_ms / ROTATION_SLOT_MS;
            if rotation.slot == Some(slot) {
                return vec![];
            }
            rotation.slot = Some(slot);
            rotation.next_random = None;
            relays[usize::try_from(slot % n).unwrap_or(0)]
        } else {
            if rotation.next_random.is_some_and(|t| now < t) {
                return vec![];
            }
            rotation.slot = None;
            let span = RANDOM_RETRY_MAX - RANDOM_RETRY_MIN;
            let wait =
                RANDOM_RETRY_MIN + span.mul_f64(f64::from(random_u32()) / f64::from(u32::MAX));
            rotation.next_random = Some(now + wait);
            relays[usize::try_from(u64::from(random_u32()) % n).unwrap_or(0)]
        };
        paths
            .adopt(target, SwitchReason::Rotation, now)
            .into_iter()
            .collect()
    }

    /// Handles a received packet and returns the reply to send. Packets that fail authentication or have a
    /// bad format get no response at all.
    pub fn on_packet(
        &mut self,
        kind: Incoming,
        from: SocketAddr,
        data: &[u8],
        at: Instant,
        now_ms: u64,
    ) -> Vec<Outgoing> {
        match (kind, data.first().copied()) {
            (Incoming::Tunnel, Some(probe::TUNNEL_PROBE)) => {
                // Reply only to probes from the mesh address of an admitted member; the source has already been
                // authenticated by WireGuard through AllowedIPs
                let (Some(seq), true) = (
                    probe::decode_tunnel_probe(data),
                    self.by_mesh_addr.contains_key(&from.ip()),
                ) else {
                    return vec![];
                };
                vec![Outgoing::Tunnel {
                    to: from,
                    data: probe::encode_tunnel_reply(seq, &self.relay_reports()),
                }]
            }
            (Incoming::Tunnel, Some(probe::TUNNEL_REPLY)) => {
                let Some((wire, reports)) = probe::decode_tunnel_reply(data) else {
                    return vec![];
                };
                let Some(sender) = self.by_mesh_addr.get(&from.ip()).cloned() else {
                    return vec![];
                };
                if let Some(peer) = self.peers.get_mut(&sender) {
                    for r in reports {
                        peer.reports.insert(
                            r.relay,
                            (
                                Duration::from_millis(u64::from(r.rtt_ms)),
                                f64::from(r.loss_permille) / 1000.0,
                            ),
                        );
                    }
                }
                if let Some((owner, Pending::Tunnel { local }, _)) = self.outstanding.remove(&wire)
                    && owner == sender
                    && let Some(paths) = self.peers.get_mut(&owner).and_then(|p| p.paths.as_mut())
                {
                    paths.on_tunnel_reply(local, at);
                }
                vec![]
            }
            (Incoming::Tunnel, Some(PUNCH_PROPOSAL | PUNCH_ACK)) => {
                let Some(message) = PunchMessage::decode(data) else {
                    return vec![];
                };
                let Some(sender) = self.by_mesh_addr.get(&from.ip()).cloned() else {
                    return vec![];
                };
                self.on_punch_message(&sender, from, message, at)
            }
            (Incoming::Tunnel, Some(SWITCH_PROPOSAL | SWITCH_ACK)) => {
                let Some(message) = SwitchMessage::decode(data) else {
                    return vec![];
                };
                let Some(sender) = self.by_mesh_addr.get(&from.ip()).cloned() else {
                    return vec![];
                };
                self.on_switch_message(&sender, from, message, at)
            }
            (Incoming::Direct, Some(DIRECT_PROBE)) => {
                let Some(head) = OuterProbe::peek(data) else {
                    return vec![];
                };
                let Some(key) = self
                    .by_key_id
                    .get(&head.key_id)
                    .and_then(|id| self.peers[id].direct_key.as_ref())
                else {
                    return vec![];
                };
                let Some(probe) = OuterProbe::verify(data, key, now_ms) else {
                    return vec![];
                };
                let reply = probe.reply(self.own_key_id, from).encode(key);
                // During hole punching: the direction from the other side to this machine works (design/mesh.md
                // section 6.1)
                if let Some(peer) = self
                    .by_key_id
                    .get(&head.key_id)
                    .and_then(|id| self.peers.get_mut(id))
                    && let (Some(punch), Some(paths)) = (peer.punch.as_mut(), peer.paths.as_ref())
                {
                    punch.on_probe_from(from, paths.role() == Role::FollowTogether);
                }
                vec![Outgoing::Direct {
                    to: from,
                    data: reply.to_vec(),
                }]
            }
            (Incoming::Direct, Some(probe::WG_COOKIE_REPLY))
                if data.len() == probe::WG_COOKIE_LEN =>
            {
                self.on_cookie_reply(from, at);
                vec![]
            }
            (Incoming::Direct, Some(DIRECT_REPLY)) => {
                let Some(key_id) = OuterReply::peek(data) else {
                    return vec![];
                };
                let Some(id) = self.by_key_id.get(&key_id).cloned() else {
                    return vec![];
                };
                let Some(reply) = self.peers[&id]
                    .direct_key
                    .as_ref()
                    .and_then(|k| OuterReply::verify(data, k))
                else {
                    return vec![];
                };
                match self.outstanding.remove(&reply.seq) {
                    Some((owner, Pending::Candidate { index, local }, _)) if owner == id => {
                        // The source the other side sees is the mapped address of this machine's WireGuard port (design/mesh.md
                        // section 6.1)
                        self.observations.record(from.ip(), reply.observed, at);
                        if let Some(paths) =
                            self.peers.get_mut(&owner).and_then(|p| p.paths.as_mut())
                        {
                            paths.on_candidate_reply(index, local, at, None);
                        }
                    }
                    Some((owner, Pending::Punch, _)) if owner == id => {
                        if let Some(punch) =
                            self.peers.get_mut(&owner).and_then(|p| p.punch.as_mut())
                        {
                            punch.on_reply_from(from, at);
                        }
                    }
                    _ => {}
                }
                vec![]
            }
            (Incoming::Relay, Some(probe::RELAY_REPLY)) => {
                self.on_relay_reply(data, at);
                vec![]
            }
            _ => vec![],
        }
    }

    /// Switch proposals and confirmations (section 8.4). The source has already been authenticated by
    /// WireGuard through AllowedIPs; only messages from the other side's role in this pair are accepted,
    /// and stale rounds and relays not among the candidates are dropped directly.
    fn on_switch_message(
        &mut self,
        sender: &NodeId,
        from: SocketAddr,
        message: SwitchMessage,
        at: Instant,
    ) -> Vec<Outgoing> {
        self.on_switch(sender, message, at)
            .map(|ack| Outgoing::Tunnel {
                to: from,
                data: ack.encode().to_vec(),
            })
            .into_iter()
            .collect()
    }

    /// A switch proposal or confirmation relayed through the Hub (section 8.4): it must authenticate with
    /// the key only the two members can derive, and the confirmation goes back the same way.
    pub fn on_hub_message(
        &mut self,
        sender: &NodeId,
        data: &[u8],
        at: Instant,
        now_ms: u64,
    ) -> Vec<Outgoing> {
        let Some(key) = self.peers.get(sender).and_then(|p| p.switch_key.clone()) else {
            return vec![];
        };
        let Some(message) = SwitchMessage::open(data, &key, now_ms) else {
            return vec![];
        };
        self.on_switch(sender, message, at)
            .map(|ack| Outgoing::Hub {
                peer: sender.clone(),
                data: ack.seal(now_ms, &key).to_vec(),
            })
            .into_iter()
            .collect()
    }

    /// Handles a switch proposal or confirmation, wherever it came from; returns the confirmation to send
    /// back.
    fn on_switch(
        &mut self,
        sender: &NodeId,
        message: SwitchMessage,
        at: Instant,
    ) -> Option<SwitchMessage> {
        let peer = self.peers.get_mut(sender)?;
        let public_key = peer.public_key;
        let (Some(paths), Some(together)) = (peer.paths.as_mut(), peer.together.as_mut()) else {
            return None;
        };
        match (message.kind, paths.role()) {
            (SWITCH_PROPOSAL, Role::FollowTogether) => {
                let index = match message.target {
                    SwitchTarget::Relay(relay) => paths.relay_index(relay),
                    SwitchTarget::Punched => paths.punched_index(),
                }?;
                if message.round < together.accepted_round {
                    return None;
                }
                if message.round > together.accepted_round {
                    together.accepted_round = message.round;
                    together.accepted = Some((index, at + ACK_GRACE));
                }
                // A resend of the same round: the previous confirmation was lost, so confirm once more
                Some(SwitchMessage {
                    kind: SWITCH_ACK,
                    ..message
                })
            }
            (SWITCH_ACK, Role::DecideTogether) => {
                let p = together
                    .proposal
                    .take_if(|p| p.round == message.round && p.target == message.target)?;
                together.rotation = None;
                paths.set_hold(false);
                if let Some(switch) = paths
                    .adopt(p.index, p.reason, at)
                    .and_then(|a| switch_of(sender, public_key, a))
                {
                    self.ready.push(switch);
                }
                None
            }
            _ => None,
        }
    }

    /// Hole punching proposals and confirmations (design/mesh.md section 6.1). The source has been
    /// authenticated by WireGuard; only messages from the other side's role in this pair are accepted.
    fn on_punch_message(
        &mut self,
        sender: &NodeId,
        from: SocketAddr,
        message: PunchMessage,
        at: Instant,
    ) -> Vec<Outgoing> {
        let own = self.observations.own(at);
        let Some(peer) = self.peers.get_mut(sender) else {
            return vec![];
        };
        let (Some(paths), Some(punch)) = (peer.paths.as_ref(), peer.punch.as_mut()) else {
            return vec![];
        };
        match (message.kind, paths.role()) {
            (PUNCH_PROPOSAL, Role::FollowTogether) => punch
                .on_proposal(&message, &own, at)
                .map(|ack| Outgoing::Tunnel {
                    to: from,
                    data: ack.encode().to_vec(),
                })
                .into_iter()
                .collect(),
            (PUNCH_ACK, Role::DecideTogether) => {
                punch.on_ack(&message, &own, at);
                vec![]
            }
            _ => vec![],
        }
    }

    /// Advancing hole punching: the decider proposes when appropriate; during punching, probes are sent every
    /// 200 ms from the WireGuard port to the other side's addresses; the punched address is added to path
    /// selection state as a direct candidate (design/mesh.md section 6.1).
    fn punch_tick(&mut self, id: &NodeId, now: Instant, now_ms: u64) -> Vec<Outgoing> {
        let own = self.observations.own(now);
        let next_round = self
            .round
            .wrapping_add(1)
            .max(u32::try_from(now_ms / 1000).unwrap_or(u32::MAX));
        let mut round_used = false;
        let Some(peer) = self.peers.get_mut(id) else {
            return vec![];
        };
        let to = SocketAddr::new(peer.mesh_addrs[0], TUNNEL_PROBE_PORT);
        let (Some(paths), Some(punch), Some(together)) = (
            peer.paths.as_mut(),
            peer.punch.as_mut(),
            peer.together.as_ref(),
        ) else {
            return vec![];
        };
        let mut out = Vec::new();
        if paths.role() == Role::DecideTogether {
            let eligible = paths.tunnel_established()
                && paths.current_kind().via_relay()
                && together.proposal.is_none()
                && together.rotation.is_none();
            if let Some(proposal) = punch.decider_tick(now, eligible, &own, || {
                round_used = true;
                next_round
            }) {
                out.push(Outgoing::Tunnel {
                    to,
                    data: proposal.encode().to_vec(),
                });
            }
        }
        let targets = punch.probe_targets(now);
        if let Some(addr) = punch.punched() {
            let index = paths.set_punched(addr);
            let route = (Route::Direct(addr), PathKind::Direct);
            if index < peer.routes.len() {
                peer.routes[index] = route;
            } else {
                peer.routes.push(route);
                peer.meta.push(CandidateMeta::Direct);
            }
        }
        let events = punch.take_events();
        let key = peer.direct_key.clone();
        if round_used {
            self.round = next_round;
        }
        for event in events {
            self.events.push(match event {
                PunchEvent::Started {
                    round,
                    own,
                    peer,
                    targets,
                } => Event::PunchStarted {
                    node_id: id.clone(),
                    round,
                    nat: own,
                    peer_nat: peer,
                    targets,
                },
                PunchEvent::Succeeded { address } => Event::PunchSucceeded {
                    node_id: id.clone(),
                    address,
                },
                PunchEvent::Failed { reason } => Event::PunchFailed {
                    node_id: id.clone(),
                    reason: reason.to_owned(),
                },
            });
        }
        let Some(key) = key else {
            return out;
        };
        for target in targets {
            let Some(wire) = self.remember(id, Pending::Punch, now) else {
                break;
            };
            let probe = OuterProbe {
                kind: DIRECT_PROBE,
                key_id: self.own_key_id,
                seq: wire,
                sent_ms: now_ms,
            };
            out.push(Outgoing::Direct {
                to: target,
                data: probe.encode(&key).to_vec(),
            });
        }
        out
    }

    fn on_relay_reply(&mut self, data: &[u8], at: Instant) {
        // The number in the reply is this machine's; look up which probe it was by sequence number, then
        // authenticate with that relay's token
        let Some(head) = OuterReply::peek(data) else {
            return;
        };
        if head != self.own_key_id || data.len() < 16 {
            return;
        }
        let seq = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let Some((owner, pending, sent)) = self.outstanding.get(&seq).cloned() else {
            return;
        };
        let (relay, key, tls) = match pending {
            Pending::Monitor { relay, tls } => match self.monitored.get(&(relay, tls)) {
                Some((_, key, _)) => (relay, key, tls),
                None => return,
            },
            Pending::Candidate { index, .. } => {
                match self.peers.get(&owner).and_then(|p| p.meta.get(index)) {
                    Some(CandidateMeta::Relay { relay, key, tls }) => (*relay, key, *tls),
                    _ => return,
                }
            }
            Pending::Tunnel { .. } | Pending::Punch => return,
        };
        if OuterReply::verify(data, key).is_none() {
            return;
        }
        self.outstanding.remove(&seq);
        let rtt = at.saturating_duration_since(sent);
        // What is carried to the peer with the in-tunnel reply is this machine's UDP measurement to the relay
        if !tls {
            self.relay_stats.entry(relay).or_default().record_reply(rtt);
        }
        if let Pending::Candidate { index, local } = pending
            && let Some(peer) = self.peers.get_mut(&owner)
        {
            let extra = peer.reports.get(&relay).copied();
            if let Some(paths) = peer.paths.as_mut() {
                paths.on_candidate_reply(index, local, at, extra);
            }
        }
    }

    fn relay_reports(&self) -> Vec<RelayReport> {
        self.relay_stats
            .iter()
            .filter_map(|(relay, stats)| {
                let rtt = stats.rtt_ms()?;
                Some(RelayReport {
                    relay: *relay,
                    rtt_ms: rtt.round().clamp(0.0, f64::from(u16::MAX)) as u16,
                    loss_permille: (stats.loss_rate() * 1000.0).round() as u16,
                })
            })
            .take(probe::MAX_RELAY_REPORTS)
            .collect()
    }
}

fn switch_of(peer: &NodeId, public_key: X25519PublicKey, action: Action) -> Option<Switch> {
    match action {
        Action::Switch {
            to,
            rehandshake,
            reason,
        } => Some(Switch {
            peer: peer.clone(),
            public_key,
            to,
            rehandshake,
            reason,
        }),
        _ => None,
    }
}

/// Random number for random retries: used only to stagger the two ends' retries, with no security role.
fn random_u32() -> u32 {
    use ring::rand::SecureRandom as _;
    let mut b = [0u8; 4];
    match ring::rand::SystemRandom::new().fill(&mut b) {
        Ok(()) => u32::from_be_bytes(b),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Candidate, ProbeToken};
    use crate::probe::{OuterProbe, OuterReply, RELAY_REPLY};
    use crate::testutil::{Mesh, node_id};
    use nett_trust::admission::admit;
    use nett_trust::anchors::TrustAnchors;
    use nett_trust::revocation::Revocations;
    use x25519_dalek::{PublicKey, StaticSecret};

    const TOKEN_A: [u8; 32] = [0xa1; 32];
    const TOKEN_B: [u8; 32] = [0xb2; 32];

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("addr")
    }

    struct Node {
        id: NodeId,
        prober: Prober,
        wg: SocketAddr,
        mesh: SocketAddr,
    }

    /// A (dial-only, decider) reaches B (public) via direct or relay R; the simulated network delivers
    /// really encoded messages according to whether each link is up.
    struct Net {
        a: Node,
        b: Node,
        relay: SocketAddr,
        direct_up: bool,
        relay_up: bool,
        /// In-tunnel packets from B to A are additionally queued this long (B's uplink is filled, the queue is
        /// deep).
        tunnel_queue: Duration,
        /// In-tunnel replies in the queue: (delivery time, content).
        queued: Vec<(Instant, Vec<u8>)>,
        now: Instant,
        switches: Vec<(Instant, Switch)>,
    }

    fn keypair(n: u8) -> (PrivateKey, X25519PublicKey) {
        let public = PublicKey::from(&StaticSecret::from([n; 32]));
        (
            PrivateKey::from_bytes([n; 32]),
            X25519PublicKey::from_bytes(public.to_bytes()),
        )
    }

    impl Net {
        fn new() -> Self {
            let mesh = Mesh::new(&[1, 2]);
            let (a_priv, a_pub) = keypair(1);
            let (b_priv, b_pub) = keypair(2);
            let anchors =
                TrustAnchors::from_doc(&mesh.desired(1, vec![]).trust_anchors).expect("anchors");
            let members: BTreeMap<NodeId, Member> = [(1, a_pub), (2, b_pub)]
                .into_iter()
                .map(|(n, key)| {
                    let m = admit(
                        &mesh.material_for(mesh.policy(n, 1), key),
                        &anchors,
                        &Revocations::default(),
                    )
                    .expect("admitted");
                    (m.node_id.clone(), m)
                })
                .collect();
            let relay_id = node_id(9);
            let relay = addr("198.51.100.9:41900");
            let paths = |peer: u8,
                         reach: Reachability,
                         token: [u8; 32],
                         direct: &str|
             -> BTreeMap<NodeId, PeerPathConfig> {
                [(
                    node_id(peer),
                    PeerPathConfig {
                        reachability: reach,
                        candidates: vec![
                            Candidate::Direct {
                                endpoint: addr(direct),
                            },
                            Candidate::Relay {
                                relay: relay_id.clone(),
                                endpoint: relay,
                                token: ProbeToken(token),
                            },
                        ],
                    },
                )]
                .into()
            };
            let mut a = Node {
                id: node_id(1),
                prober: Prober::new(&a_pub),
                wg: addr("203.0.113.1:41820"),
                mesh: addr("100.88.0.1:41821"),
            };
            let mut b = Node {
                id: node_id(2),
                prober: Prober::new(&b_pub),
                wg: addr("198.51.100.2:41820"),
                mesh: addr("100.88.0.2:41821"),
            };
            a.prober.update(
                &a.id,
                Reachability::DialOnly,
                &a_priv,
                &members,
                &paths(2, Reachability::Public, TOKEN_A, "198.51.100.2:41820"),
                &BTreeMap::new(),
            );
            b.prober.update(
                &b.id,
                Reachability::Public,
                &b_priv,
                &members,
                &paths(1, Reachability::DialOnly, TOKEN_B, "203.0.113.1:41820"),
                &BTreeMap::new(),
            );
            for node in [&mut a, &mut b] {
                let peer = if node.id == node_id(1) {
                    node_id(2)
                } else {
                    node_id(1)
                };
                node.prober.mark_active(&peer, Instant::now());
            }
            Self {
                a,
                b,
                relay,
                direct_up: true,
                relay_up: true,
                tunnel_queue: Duration::ZERO,
                queued: Vec::new(),
                now: Instant::now(),
                switches: Vec::new(),
            }
        }

        /// Simulated relay: replies after token authentication.
        fn relay_reply(&self, data: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
            let head = OuterProbe::peek(data)?;
            for token in [TOKEN_A, TOKEN_B] {
                let key = ProbeKey::from_token(&token);
                if let Some(p) = OuterProbe::verify(data, &key, 0) {
                    let reply = OuterReply {
                        kind: RELAY_REPLY,
                        key_id: head.key_id,
                        seq: p.seq,
                        sent_ms: p.sent_ms,
                        observed: from,
                    };
                    return Some(reply.encode(&key).to_vec());
                }
            }
            None
        }

        fn current_up(&self) -> bool {
            match self.a.prober.desired_endpoint(&self.b.id) {
                Some(e) if e == self.relay => self.relay_up,
                _ => self.direct_up,
            }
        }

        /// Delivers a packet sent by a node; the other side's reply is delivered back immediately (the
        /// round-trip time is treated as 0, determined by the granularity of tick).
        fn deliver(&mut self, from_a: bool, out: Outgoing) {
            let up = self.current_up();
            let (src, dst) = if from_a {
                (&mut self.a, &mut self.b)
            } else {
                (&mut self.b, &mut self.a)
            };
            let now = self.now;
            match out {
                Outgoing::Tunnel { data, .. } if up => {
                    for reply in dst
                        .prober
                        .on_packet(Incoming::Tunnel, src.mesh, &data, now, 0)
                    {
                        if let Outgoing::Tunnel { data, .. } = reply {
                            if from_a && !self.tunnel_queue.is_zero() {
                                self.queued.push((now + self.tunnel_queue, data));
                            } else {
                                src.prober
                                    .on_packet(Incoming::Tunnel, dst.mesh, &data, now, 0);
                            }
                        }
                    }
                }
                Outgoing::Direct { data, .. } if self.direct_up => {
                    for reply in dst
                        .prober
                        .on_packet(Incoming::Direct, src.wg, &data, now, 0)
                    {
                        if let Outgoing::Direct { data, .. } = reply {
                            src.prober
                                .on_packet(Incoming::Direct, dst.wg, &data, now, 0);
                        }
                    }
                }
                Outgoing::Relay { data, .. } if self.relay_up => {
                    let wg = src.wg;
                    if let Some(reply) = self.relay_reply(&data, wg) {
                        let src = if from_a { &mut self.a } else { &mut self.b };
                        src.prober
                            .on_packet(Incoming::Relay, self.relay, &reply, now, 0);
                    }
                }
                _ => {}
            }
        }

        fn run(&mut self, d: Duration) {
            let end = self.now + d;
            while self.now < end {
                self.now += Duration::from_millis(100);
                let now = self.now;
                let (due, rest) = std::mem::take(&mut self.queued)
                    .into_iter()
                    .partition::<Vec<_>, _>(|(at, _)| *at <= now);
                self.queued = rest;
                for (at, data) in due {
                    self.a
                        .prober
                        .on_packet(Incoming::Tunnel, self.b.mesh, &data, at, 0);
                }
                // With traffic: while the current path works, B's packets keep arriving
                if self.current_up() {
                    let b = self.b.id.clone();
                    self.a.prober.on_receive(&b, now);
                }
                let (a_out, a_switches) = self.a.prober.tick(self.now, 0);
                let (b_out, b_switches) = self.b.prober.tick(self.now, 0);
                assert!(b_switches.is_empty(), "the follower never switches");
                self.switches
                    .extend(a_switches.into_iter().map(|s| (self.now, s)));
                for o in a_out {
                    self.deliver(true, o);
                }
                for o in b_out {
                    self.deliver(false, o);
                }
            }
        }
    }

    #[test]
    fn dial_only_member_decides() {
        let (a, b) = (node_id(1), node_id(2));
        assert!(is_decider(
            &a,
            Reachability::DialOnly,
            &b,
            Reachability::Public
        ));
        assert!(!is_decider(
            &b,
            Reachability::Public,
            &a,
            Reachability::DialOnly
        ));
        assert!(is_decider(
            &a,
            Reachability::Public,
            &b,
            Reachability::Public
        ));
        assert!(!is_decider(
            &b,
            Reachability::Public,
            &a,
            Reachability::Public
        ));
    }

    #[test]
    fn fails_over_to_the_relay_and_comes_back() {
        let mut net = Net::new();
        net.run(Duration::from_secs(10));
        assert!(net.switches.is_empty());
        // The follower's relay measurement was carried to the decider with the in-tunnel reply
        assert!(
            net.a.prober.peers[&net.b.id]
                .reports
                .contains_key(&KeyId::of(node_id(9).as_str().as_bytes()))
        );

        let broke = net.now;
        net.direct_up = false;
        net.run(Duration::from_secs(5));
        let (at, s) = net.switches.first().expect("switched to the relay");
        assert_eq!(s.to.endpoint(), net.relay);
        assert!(s.rehandshake);
        assert!(at.saturating_duration_since(broke) <= Duration::from_millis(3600));

        let restored = net.now;
        net.direct_up = true;
        net.run(Duration::from_secs(25));
        let (at, s) = net.switches.last().expect("switched back");
        assert_eq!(s.to.endpoint(), addr("198.51.100.2:41820"));
        assert_eq!(s.reason, SwitchReason::BetterType);
        // High-frequency probing for 15 seconds after switching away; the simulation advances every 100 ms
        let took = at.saturating_duration_since(restored);
        assert!(took <= Duration::from_millis(300), "took {took:?}");
    }

    #[test]
    fn late_tunnel_replies_keep_a_congested_path() {
        let mut net = Net::new();
        net.run(Duration::from_secs(10));
        // B's uplink is filled: in-tunnel replies are 4 seconds late, beyond the lookup table's usual retention
        // time
        net.tunnel_queue = Duration::from_secs(4);
        net.run(Duration::from_secs(60));
        assert!(net.switches.is_empty(), "{:?}", net.switches);
    }

    #[test]
    fn ignores_unauthenticated_and_foreign_probes() {
        let mut net = Net::new();
        let now = net.now;
        // An in-tunnel probe not sent from a member's mesh address
        let probe = probe::encode_tunnel_probe(1);
        assert!(
            net.b
                .prober
                .on_packet(Incoming::Tunnel, addr("100.88.0.77:5000"), &probe, now, 0)
                .is_empty()
        );
        // A direct probe whose checksum is computed with the wrong key
        let forged = OuterProbe {
            kind: DIRECT_PROBE,
            key_id: net.a.prober.own_key_id,
            seq: 1,
            sent_ms: 0,
        }
        .encode(&ProbeKey::from_token(&[0; 32]));
        assert!(
            net.b
                .prober
                .on_packet(Incoming::Direct, net.a.wg, &forged, now, 0)
                .is_empty()
        );
        // Arbitrary bytes
        assert!(
            net.b
                .prober
                .on_packet(Incoming::Direct, net.a.wg, &[0x82; 64], now, 0)
                .is_empty()
        );
    }

    /// A and B are both `dial-only` (A has the smaller ID and is the decider), via relays R1 and R2; the
    /// tunnel works only when both ends' endpoints point to the same working relay. The two ends' candidate
    /// lists are in different orders.
    struct Pair {
        a: Node,
        b: Node,
        relays: [SocketAddr; 2],
        relay_up: [bool; 2],
        /// Via this relay, every few in-tunnel probes (or proposals) one is dropped; replies are not dropped.
        lossy: Option<(usize, u32)>,
        sent: u32,
        now: Instant,
        now_ms: u64,
        switches: Vec<(Instant, bool, Switch)>,
        /// Each end sits behind a port-restricted cone NAT: the mapped address is fixed; only after this machine
        /// first sends a packet to the other side's address can the other side's packets get in.
        mapped: [SocketAddr; 2],
        opened: [std::collections::HashSet<SocketAddr>; 2],
        direct_sent: [usize; 2],
        /// nett-node and the Hub relay switch messages between the two ends.
        hub: bool,
    }

    impl Pair {
        fn new() -> Self {
            Self::build(false)
        }

        /// Hole punching candidates are configured; both ends have learned their own mapped addresses from two
        /// `public` nodes (with `symmetric`, the two observers see different ports).
        fn with_punch(symmetric: bool) -> Self {
            let mut pair = Self::build(true);
            let now = pair.now;
            for (i, node) in [&mut pair.a, &mut pair.b].into_iter().enumerate() {
                let m = pair.mapped[i];
                let r1: IpAddr = "198.51.100.9".parse().expect("ip");
                let r2: IpAddr = "198.51.100.10".parse().expect("ip");
                node.prober.observations.record(r1, m, now);
                let other = if symmetric {
                    SocketAddr::new(m.ip(), m.port() + 1)
                } else {
                    m
                };
                node.prober.observations.record(r2, other, now);
            }
            pair
        }

        fn build(punch: bool) -> Self {
            let mesh = Mesh::new(&[1, 2]);
            let (a_priv, a_pub) = keypair(1);
            let (b_priv, b_pub) = keypair(2);
            let anchors =
                TrustAnchors::from_doc(&mesh.desired(1, vec![]).trust_anchors).expect("anchors");
            let members: BTreeMap<NodeId, Member> = [(1, a_pub), (2, b_pub)]
                .into_iter()
                .map(|(n, key)| {
                    let m = admit(
                        &mesh.material_for(mesh.policy(n, 1), key),
                        &anchors,
                        &Revocations::default(),
                    )
                    .expect("admitted");
                    (m.node_id.clone(), m)
                })
                .collect();
            let relays = [addr("198.51.100.9:41900"), addr("198.51.100.10:41900")];
            let relay = |i: usize, token: [u8; 32]| Candidate::Relay {
                relay: node_id(9 + u8::try_from(i).expect("small")),
                endpoint: relays[i],
                token: ProbeToken(token),
            };
            let paths =
                |peer: u8, candidates: Vec<Candidate>| -> BTreeMap<NodeId, PeerPathConfig> {
                    [(
                        node_id(peer),
                        PeerPathConfig {
                            reachability: Reachability::DialOnly,
                            candidates,
                        },
                    )]
                    .into()
                };
            let mut a = Node {
                id: node_id(1),
                prober: Prober::new(&a_pub),
                wg: addr("203.0.113.1:41820"),
                mesh: addr("100.88.0.1:41821"),
            };
            let mut b = Node {
                id: node_id(2),
                prober: Prober::new(&b_pub),
                wg: addr("192.0.2.2:41820"),
                mesh: addr("100.88.0.2:41821"),
            };
            a.prober.update(
                &a.id,
                Reachability::DialOnly,
                &a_priv,
                &members,
                &paths(2, {
                    let mut c = vec![relay(0, TOKEN_A), relay(1, TOKEN_A)];
                    c.extend(punch.then_some(Candidate::Punch));
                    c
                }),
                &BTreeMap::new(),
            );
            b.prober.update(
                &b.id,
                Reachability::DialOnly,
                &b_priv,
                &members,
                &paths(1, {
                    let mut c = vec![relay(1, TOKEN_B), relay(0, TOKEN_B)];
                    c.extend(punch.then_some(Candidate::Punch));
                    c
                }),
                &BTreeMap::new(),
            );
            let now = Instant::now();
            for (node, peer) in [(&mut a, node_id(2)), (&mut b, node_id(1))] {
                node.prober.mark_active(&peer, now);
                node.prober.set_clock_trusted(true);
            }
            Self {
                a,
                b,
                relays,
                relay_up: [true, true],
                lossy: None,
                sent: 0,
                now,
                // 1 second after the time slice boundary
                now_ms: 1_800_000_001_000 - 1_800_000_001_000 % ROTATION_SLOT_MS + 1_000,
                switches: Vec::new(),
                mapped: [addr("198.51.100.201:41820"), addr("198.51.100.202:41820")],
                opened: Default::default(),
                direct_sent: [0, 0],
                hub: false,
            }
        }

        fn endpoints(&self) -> (Option<SocketAddr>, Option<SocketAddr>) {
            (
                self.a.prober.desired_endpoint(&self.b.id),
                self.b.prober.desired_endpoint(&self.a.id),
            )
        }

        fn tunnel_up(&mut self, lossy: bool) -> bool {
            let (a, b) = self.endpoints();
            // The punched direct path: both ends point to the other side's mapped address
            if a == Some(self.mapped[1]) && b == Some(self.mapped[0]) {
                return true;
            }
            let shared = a.filter(|_| a == b);
            let Some(i) = self.relays.iter().position(|r| Some(*r) == shared) else {
                return false;
            };
            let dropping = match self.lossy {
                Some((relay, every)) if lossy && relay == i => {
                    self.sent += 1;
                    self.sent.is_multiple_of(every)
                }
                _ => false,
            };
            self.relay_up[i] && !dropping
        }

        fn deliver(&mut self, from_a: bool, out: Outgoing) {
            let (now, now_ms) = (self.now, self.now_ms);
            match out {
                Outgoing::Tunnel { data, .. } => {
                    if !self.tunnel_up(true) {
                        return;
                    }
                    let (src, dst) = if from_a {
                        (&mut self.a, &mut self.b)
                    } else {
                        (&mut self.b, &mut self.a)
                    };
                    let replies =
                        dst.prober
                            .on_packet(Incoming::Tunnel, src.mesh, &data, now, now_ms);
                    let dst_mesh = dst.mesh;
                    for reply in replies {
                        if let Outgoing::Tunnel { data, .. } = reply
                            && self.tunnel_up(false)
                        {
                            let src = if from_a { &mut self.a } else { &mut self.b };
                            src.prober
                                .on_packet(Incoming::Tunnel, dst_mesh, &data, now, now_ms);
                        }
                    }
                }
                Outgoing::Relay { to, data } => {
                    let Some(i) = self.relays.iter().position(|r| *r == to) else {
                        return;
                    };
                    if !self.relay_up[i] {
                        return;
                    }
                    let src = if from_a { &mut self.a } else { &mut self.b };
                    for token in [TOKEN_A, TOKEN_B] {
                        let key = ProbeKey::from_token(&token);
                        if let Some(p) = OuterProbe::verify(&data, &key, now_ms) {
                            let reply = OuterReply {
                                kind: RELAY_REPLY,
                                key_id: p.key_id,
                                seq: p.seq,
                                sent_ms: p.sent_ms,
                                observed: src.wg,
                            };
                            src.prober.on_packet(
                                Incoming::Relay,
                                to,
                                &reply.encode(&key),
                                now,
                                now_ms,
                            );
                        }
                    }
                }
                Outgoing::Hub { peer, data } => {
                    if !self.hub {
                        return;
                    }
                    let (src, dst) = if from_a {
                        (&mut self.a, &mut self.b)
                    } else {
                        (&mut self.b, &mut self.a)
                    };
                    if peer != dst.id {
                        return;
                    }
                    let src_id = src.id.clone();
                    let dst_id = dst.id.clone();
                    for reply in dst.prober.on_hub_message(&src_id, &data, now, now_ms) {
                        if let Outgoing::Hub { peer, data } = reply
                            && peer == src_id
                        {
                            let src = if from_a { &mut self.a } else { &mut self.b };
                            src.prober.on_hub_message(&dst_id, &data, now, now_ms);
                        }
                    }
                }
                Outgoing::Direct { to, data } => {
                    let (src, dst) = if from_a { (0, 1) } else { (1, 0) };
                    self.direct_sent[src] += 1;
                    // Sending opens a mapping to this address on this machine's NAT
                    self.opened[src].insert(to);
                    if to != self.mapped[dst] || !self.opened[dst].contains(&self.mapped[src]) {
                        return;
                    }
                    let from = self.mapped[src];
                    let (sender, receiver) = if from_a {
                        (&mut self.a, &mut self.b)
                    } else {
                        (&mut self.b, &mut self.a)
                    };
                    let replies =
                        receiver
                            .prober
                            .on_packet(Incoming::Direct, from, &data, now, now_ms);
                    for reply in replies {
                        if let Outgoing::Direct { to, data } = reply
                            && to == from
                            && self.opened[src].contains(&self.mapped[dst])
                        {
                            sender.prober.on_packet(
                                Incoming::Direct,
                                self.mapped[dst],
                                &data,
                                now,
                                now_ms,
                            );
                        }
                    }
                }
            }
        }

        fn run(&mut self, d: Duration) {
            let end = self.now + d;
            while self.now < end {
                self.now += Duration::from_millis(100);
                self.now_ms += 100;
                let (a_out, a_sw) = self.a.prober.tick(self.now, self.now_ms);
                let (b_out, b_sw) = self.b.prober.tick(self.now, self.now_ms);
                let now = self.now;
                self.switches
                    .extend(a_sw.into_iter().map(|s| (now, true, s)));
                self.switches
                    .extend(b_sw.into_iter().map(|s| (now, false, s)));
                for o in a_out {
                    self.deliver(true, o);
                }
                for o in b_out {
                    self.deliver(false, o);
                }
            }
        }
    }

    #[test]
    fn dial_only_pair_starts_on_the_same_relay() {
        let mut pair = Pair::new();
        let (a, b) = pair.endpoints();
        assert_eq!(a, b);
        assert!(a.is_some());
        pair.run(Duration::from_secs(10));
        assert!(pair.switches.is_empty(), "{:?}", pair.switches);
    }

    /// Both ends `dial-only`: the follower does not probe candidates, but it may have to move to a TLS
    /// relay together with the decider, so it keeps its standby TLS connection authenticated with a probe
    /// of its own (design/mesh.md sections 5.3 and 8.4).
    #[test]
    fn the_dial_only_follower_keeps_its_tls_relays_authenticated() {
        let mesh = Mesh::new(&[1, 2]);
        let (a_priv, a_pub) = keypair(1);
        let (_, b_pub) = keypair(2);
        let anchors =
            TrustAnchors::from_doc(&mesh.desired(1, vec![]).trust_anchors).expect("anchors");
        let members: BTreeMap<NodeId, Member> = [(1, a_pub), (2, b_pub)]
            .into_iter()
            .map(|(n, key)| {
                let m = admit(
                    &mesh.material_for(mesh.policy(n, 1), key),
                    &anchors,
                    &Revocations::default(),
                )
                .expect("admitted");
                (m.node_id.clone(), m)
            })
            .collect();
        let loopback = addr("127.0.0.1:41830");
        let candidates = vec![
            Candidate::Relay {
                relay: node_id(9),
                endpoint: addr("198.51.100.9:41822"),
                token: ProbeToken(TOKEN_A),
            },
            Candidate::RelayTls {
                relay: node_id(9),
                address: addr("198.51.100.9:443"),
                fingerprint: nett_core::transport::CertFingerprint([7; 32]),
                token: ProbeToken(TOKEN_A),
            },
        ];
        let tls: BTreeMap<NodeId, SocketAddr> = [(node_id(9), loopback)].into();
        let probes_to = |me: u8, private: &PrivateKey, public: &X25519PublicKey| {
            let peer = node_id(if me == 1 { 2 } else { 1 });
            let mut prober = Prober::new(public);
            prober.update(
                &node_id(me),
                Reachability::DialOnly,
                private,
                &members,
                &[(
                    peer,
                    PeerPathConfig {
                        reachability: Reachability::DialOnly,
                        candidates: candidates.clone(),
                    },
                )]
                .into(),
                &tls,
            );
            let (out, _) = prober.tick(Instant::now(), 1_700_000_000_000);
            out.into_iter()
                .filter_map(|o| match o {
                    Outgoing::Relay { to, .. } => Some(to),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        // Node 2 follows node 1 (the smaller node ID decides)
        let (b_priv, _) = keypair(2);
        let follower = probes_to(2, &b_priv, &b_pub);
        assert!(follower.contains(&loopback), "{follower:?}");
        assert!(
            follower.contains(&addr("198.51.100.9:41822")),
            "{follower:?}"
        );
        let decider = probes_to(1, &a_priv, &a_pub);
        assert!(decider.contains(&loopback), "{decider:?}");
    }

    #[test]
    fn dial_only_pair_switches_together_after_the_ack() {
        let mut pair = Pair::new();
        pair.run(Duration::from_secs(10));
        let (start, _) = pair.endpoints();
        // The current relay has severe loss but can still pass some traffic: the decider proposes through the
        // tunnel, and after the peer confirms both ends switch together
        let current = pair
            .relays
            .iter()
            .position(|r| Some(*r) == start)
            .expect("on a relay");
        pair.lossy = Some((current, 2));
        pair.run(Duration::from_secs(20));
        let (a, b) = pair.endpoints();
        assert_eq!(a, b);
        assert_ne!(a, start, "{:?}", pair.switches);
        let reasons: Vec<(bool, SwitchReason, bool)> = pair
            .switches
            .iter()
            .map(|(_, from_a, s)| (*from_a, s.reason, s.rehandshake))
            .collect();
        // When loss is noticeable, a better path of the same type switches within 5 seconds, possibly before it
        // is judged a failure
        assert!(
            reasons.contains(&(true, SwitchReason::HighLoss, true))
                || reasons.contains(&(true, SwitchReason::BetterScore, true)),
            "{reasons:?}"
        );
        assert!(
            reasons.contains(&(false, SwitchReason::Proposed, true)),
            "{reasons:?}"
        );
        // The two ends' switch times differ by no more than half a second
        let at = |side: bool| {
            pair.switches
                .iter()
                .find(|(_, from_a, _)| *from_a == side)
                .map(|(t, _, _)| *t)
                .expect("switched")
        };
        let gap = at(true).max(at(false)) - at(true).min(at(false));
        assert!(gap <= Duration::from_millis(500), "gap {gap:?}");
    }

    #[test]
    fn dial_only_pair_switches_through_the_hub_after_an_outage() {
        let mut pair = Pair::new();
        pair.hub = true;
        pair.a.prober.set_hub(true);
        pair.b.prober.set_hub(true);
        pair.run(Duration::from_secs(10));
        let (start, _) = pair.endpoints();
        let failed = pair
            .relays
            .iter()
            .position(|r| Some(*r) == start)
            .expect("on a relay");
        pair.relay_up[failed] = false;
        let down = pair.now;
        pair.run(Duration::from_secs(10));
        let (a, b) = pair.endpoints();
        assert_eq!(a, b, "{:?}", pair.switches);
        assert_ne!(a, start);
        let after: Vec<(bool, SwitchReason)> = pair
            .switches
            .iter()
            .filter(|(t, _, _)| *t > down)
            .map(|(_, from_a, s)| (*from_a, s.reason))
            .collect();
        // The decider proposes the other relay through the Hub and both move there once, without
        // rotating by time slot
        assert!(
            after.contains(&(true, SwitchReason::Unreachable)),
            "{after:?}"
        );
        assert!(
            after.contains(&(false, SwitchReason::Proposed)),
            "{after:?}"
        );
        assert!(
            !after.iter().any(|(_, r)| *r == SwitchReason::Rotation),
            "{after:?}"
        );
        let moved = pair
            .switches
            .iter()
            .filter(|(t, _, _)| *t > down)
            .map(|(t, _, _)| *t)
            .max()
            .expect("switched");
        assert!(
            moved - down <= Duration::from_secs(6),
            "both ends moved {:?} after the outage",
            moved - down
        );
    }

    #[test]
    fn dial_only_pair_rotates_when_the_hub_does_not_answer() {
        let mut pair = Pair::new();
        // nett-node reports the Hub up, but nothing gets through it
        pair.a.prober.set_hub(true);
        pair.b.prober.set_hub(true);
        pair.run(Duration::from_secs(10));
        let (start, _) = pair.endpoints();
        let failed = pair
            .relays
            .iter()
            .position(|r| Some(*r) == start)
            .expect("on a relay");
        pair.relay_up[failed] = false;
        pair.run(Duration::from_secs(45));
        let (a, b) = pair.endpoints();
        assert_eq!(a, b, "{:?}", pair.switches);
        assert_ne!(a, start);
        assert!(
            pair.switches
                .iter()
                .any(|(_, _, s)| s.reason == SwitchReason::Rotation),
            "falls back to the time slots"
        );
    }

    #[test]
    fn dial_only_pair_meets_by_time_slot_after_an_outage() {
        let mut pair = Pair::new();
        pair.run(Duration::from_secs(10));
        let (start, _) = pair.endpoints();
        let failed = pair
            .relays
            .iter()
            .position(|r| Some(*r) == start)
            .expect("on a relay");
        pair.relay_up[failed] = false;
        let down = pair.now;
        pair.run(Duration::from_secs(45));
        let (a, b) = pair.endpoints();
        assert_eq!(a, b);
        assert_ne!(a, start);
        // Both sides rotate by time slice; after confirming on another relay they stop and no longer rotate
        let rotations: Vec<(Instant, bool)> = pair
            .switches
            .iter()
            .filter(|(_, _, s)| s.reason == SwitchReason::Rotation)
            .map(|(t, side, _)| (*t, *side))
            .collect();
        assert!(rotations.iter().any(|(_, a)| *a) && rotations.iter().any(|(_, a)| !*a));
        let last = rotations.last().expect("rotated").0;
        assert!(
            last.saturating_duration_since(down) <= Duration::from_secs(20),
            "{rotations:?}"
        );
        let before = pair.switches.len();
        pair.run(Duration::from_secs(60));
        assert_eq!(pair.switches.len(), before);
    }

    #[test]
    fn switch_messages_need_the_right_role_round_and_relay() {
        let mut pair = Pair::new();
        let (now, now_ms) = (pair.now, pair.now_ms);
        let relay = KeyId::of(node_id(10).as_str().as_bytes());
        let proposal = |round: u32, relay: KeyId| {
            SwitchMessage {
                kind: SWITCH_PROPOSAL,
                round,
                target: SwitchTarget::Relay(relay),
            }
            .encode()
        };
        // The follower confirms the decider's proposal
        let acks = pair.b.prober.on_packet(
            Incoming::Tunnel,
            pair.a.mesh,
            &proposal(5, relay),
            now,
            now_ms,
        );
        assert_eq!(acks.len(), 1);
        // Stale round, a relay not among the candidates, a proposal from the follower: none are answered
        let stale = pair.b.prober.on_packet(
            Incoming::Tunnel,
            pair.a.mesh,
            &proposal(4, relay),
            now,
            now_ms,
        );
        let unknown = pair.b.prober.on_packet(
            Incoming::Tunnel,
            pair.a.mesh,
            &proposal(6, KeyId([7; 8])),
            now,
            now_ms,
        );
        let wrong_role = pair.a.prober.on_packet(
            Incoming::Tunnel,
            pair.b.mesh,
            &proposal(9, relay),
            now,
            now_ms,
        );
        assert!(stale.is_empty() && unknown.is_empty() && wrong_role.is_empty());
        // Not sent from a member's mesh address
        let foreign = pair.b.prober.on_packet(
            Incoming::Tunnel,
            addr("100.88.0.77:41821"),
            &proposal(10, relay),
            now,
            now_ms,
        );
        assert!(foreign.is_empty());
    }

    #[test]
    fn untrusted_clock_retries_at_random_intervals() {
        let mut pair = Pair::new();
        pair.run(Duration::from_secs(10));
        for node in [&mut pair.a, &mut pair.b] {
            node.prober.set_clock_trusted(false);
        }
        pair.relay_up = [false, false];
        pair.run(Duration::from_secs(120));
        let attempts: Vec<Instant> = pair
            .switches
            .iter()
            .filter(|(_, from_a, s)| *from_a && s.reason == SwitchReason::Rotation)
            .map(|(t, _, _)| *t)
            .collect();
        assert!(attempts.len() >= 7, "{attempts:?}");
        for w in attempts.windows(2) {
            let gap = w[1].saturating_duration_since(w[0]);
            assert!(
                gap >= RANDOM_RETRY_MIN && gap <= RANDOM_RETRY_MAX + Duration::from_millis(100),
                "gap {gap:?}"
            );
        }
    }

    #[test]
    fn dial_only_pair_punches_through_cone_nats_and_switches_together() {
        let mut pair = Pair::with_punch(false);
        pair.run(Duration::from_secs(15));
        let (a, b) = pair.endpoints();
        assert_eq!(
            (a, b),
            (Some(pair.mapped[1]), Some(pair.mapped[0])),
            "{:?}",
            pair.switches
        );
        let reasons: Vec<(bool, SwitchReason, bool)> = pair
            .switches
            .iter()
            .map(|(_, from_a, s)| (*from_a, s.reason, s.rehandshake))
            .collect();
        // The decider switches to the better one, the follower switches per the proposal; a direct path needs no
        // re-handshake
        assert!(
            reasons.contains(&(true, SwitchReason::BetterType, false)),
            "{reasons:?}"
        );
        assert!(
            reasons.contains(&(false, SwitchReason::Proposed, false)),
            "{reasons:?}"
        );
        let events = pair.a.prober.take_events();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::PunchStarted { .. })),
            "{events:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::PunchSucceeded { .. })),
            "{events:?}"
        );
        // Stay on the direct path afterwards
        let before = pair.switches.len();
        pair.run(Duration::from_secs(60));
        assert_eq!(pair.switches.len(), before);
    }

    #[test]
    fn both_symmetric_do_not_punch() {
        let mut pair = Pair::with_punch(true);
        pair.run(Duration::from_secs(20));
        assert!(pair.switches.is_empty(), "{:?}", pair.switches);
        assert_eq!(pair.direct_sent, [0, 0], "no punch probes");
        let events = pair.a.prober.take_events();
        assert!(
            events.iter().any(|e| matches!(e, Event::PunchFailed { reason, .. } if reason == "both behind symmetric NAT")),
            "{events:?}"
        );
    }
}
