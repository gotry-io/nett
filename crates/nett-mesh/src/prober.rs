//! Runtime state of probing and path selection (design/mesh.md sections 7 and 8): maintains candidate
//! paths for each peer, sends and receives probe messages, and produces the packets to send and the
//! switches to perform; when both sides are `dial-only`, coordinates a two-ended switchover (section
//! 8.4). It does not touch sockets or the data plane; [`crate::engine`] performs those, and tests can
//! drive it directly.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
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
    ProbeKey, PunchMessage, RELAY_PROBE, RelayReport, RestartNotice, SWITCH_ACK, SWITCH_PROPOSAL,
    SwitchMessage, SwitchTarget, THROUGH_PROBE, THROUGH_REPLY, TUNNEL_PROBE_PORT, Through,
};
use crate::punch::{Observations, Punch, PunchEvent};

/// Upper limit on how long a sent probe waits for a reply; after that it is removed from the lookup table
/// (each state machine decides loss itself). In-tunnel probes are kept for [`LATE_HORIZON`]: late
/// replies that queued for a few seconds must also be handed to the path selection state machine
/// (design/mesh.md section 7).
pub(crate) const OUTSTANDING_TTL: Duration = Duration::from_secs(2);
/// Endpoints recorded as blocked at most; a machine has a few relays and public peers.
pub const MAX_BLOCKED: usize = 64;

/// Upper limit of the lookup table: fewer than 20 in-tunnel probes within 10 seconds for each peer with
/// traffic, plus probes of candidates and relays.
const MAX_OUTSTANDING: usize = 4096;
/// Interval at which the follower measures relays: only to provide the decider with the "relay -> this
/// machine" leg.
pub(crate) const RELAY_MONITOR_INTERVAL: Duration = Duration::from_secs(5);
/// A path through a relay is measured by through probes while one came back through that relay
/// within this long; after that, from its segments again (ADR 0029).
pub(crate) const THROUGH_LAPSE: Duration = Duration::from_secs(30);
/// Window for judging whether there is traffic (design/mesh.md section 7).
pub const ACTIVE_WINDOW: Duration = Duration::from_secs(30);
/// Probing a peer's paths on request happens at most this often (design/status.md section 4.3).
pub const PROBE_REQUEST_INTERVAL: Duration = Duration::from_secs(1);
/// Bytes a second, both directions together (2 Mbit/s), above which a pair is busy: it stays on, or
/// returns to, its direct path rather than a faster relay with a narrower uplink (design/mesh.md
/// section 8.2).
pub const BUSY_RATE: u64 = 250_000;
/// The traffic rate is measured over this window, from byte counts sampled at most once a
/// [`BYTE_SAMPLE_INTERVAL`].
const BUSY_WINDOW: Duration = Duration::from_secs(10);
const BYTE_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// Upper limit of the byte count samples kept per peer.
const MAX_BYTE_SAMPLES: usize = 16;
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
    /// Sent from the mesh's own port to a TLS relay's loopback port, which the TLS transport
    /// carries to the relay (section 5.3).
    Transport { to: SocketAddr, data: Vec<u8> },
    /// Sent from the WireGuard port (section 7.1): direct probes, and probes of UDP relays.
    WgPort { to: SocketAddr, data: Vec<u8> },
    /// Sent wrapped from this machine's obfuscated port (design/obfuscation.md section 2): replies
    /// to what came in there.
    ObfsPort { to: SocketAddr, data: Vec<u8> },
    /// Handed to nett-node, which relays it through the Hub to the peer's nett-node (section 8.4).
    Hub { peer: NodeId, data: Vec<u8> },
}

/// Where a received packet came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Incoming {
    /// The probe port on the mesh address.
    Tunnel,
    /// The socket the mesh uses to send to TLS relays' loopback ports.
    Transport,
    /// The copy on the WireGuard port.
    WgPort,
    /// This machine's obfuscated port, opened by the userspace data plane (design/obfuscation.md
    /// section 2): handled as the WireGuard port, and answered through the port it came in on.
    ObfsPort,
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
    /// `loopback`: the candidate is the peer's obfuscated port, reached through the obfuscated
    /// transport's loopback port (design/obfuscation.md section 2); probes go there and their replies
    /// come back through it.
    Direct { loopback: bool },
    /// `via`: how the relay is reached; only a measurement over its UDP relay port counts as this
    /// machine's UDP measurement to the relay.
    Relay {
        relay: KeyId,
        key: ProbeKey,
        via: Via,
    },
}

/// How a relay candidate is reached: its UDP relay port from the WireGuard port, or through a
/// transport's loopback port, obfuscated UDP (design/obfuscation.md section 2) or TLS (design/mesh.md
/// section 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Via {
    Udp,
    Obfs,
    Tls,
}

impl Via {
    /// Probes and the tunnel go to the transport's loopback port, and replies come back through it.
    fn loopback(self) -> bool {
        self != Via::Udp
    }
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
    /// When a through reply from the peer last came back through each relay (ADR 0029).
    through: HashMap<KeyId, Instant>,
    /// The send time of the latest direct probe received from the peer (design/mesh.md section 6).
    latest_probe_ms: u64,
    /// When the paths to it were last probed on request (design/status.md section 4.3).
    probed_on_request: Option<Instant>,
    /// The restart number of the peer's latest restart notice handled (design/mesh.md section 8.4).
    heard_restart: Option<u32>,
    last_activity: Option<Instant>,
    /// WireGuard's byte count for this peer (received and sent), sampled for the traffic rate.
    bytes: VecDeque<(Instant, u64)>,
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
    /// The through probe sent with a candidate probe of a relay path (ADR 0029).
    Through {
        index: usize,
        local: u32,
        relay: KeyId,
    },
    /// A probe of a relay outside path selection: over UDP it measures the relay for the peer, over TLS it
    /// keeps the standby connection authenticated.
    Monitor {
        relay: KeyId,
        via: Via,
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
    monitored: HashMap<(KeyId, Via), (SocketAddr, ProbeKey, Option<Instant>)>,
    /// Endpoints whose plain UDP was lost while obfuscated UDP took over (design/obfuscation.md section
    /// 5): every peer's plain candidates to them stay unused. Kept in the state directory by the caller.
    blocked: BTreeSet<SocketAddr>,
    /// The blocked endpoints changed since the caller last took them.
    blocked_changed: bool,
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
    /// Drawn as the mesh starts: what this machine's restart notices carry (design/mesh.md section
    /// 8.4).
    restart: u32,
    /// Peers whose restart notice was just handled, and when each was sent (Unix ms), for the
    /// caller; at most one per peer.
    restarted: Vec<(NodeId, u64)>,
    /// Events to be reported by the caller.
    events: Vec<Event>,
}

/// A probe of a relay. Over UDP it leaves from the WireGuard port, so it measures the addresses the
/// tunnel through that relay uses: a network that treats WireGuard's port differently from other
/// ports (a NAT mapping, a firewall or a block keyed on the port) shows in the measurement (design/mesh.md
/// section 7.1). Over a transport it goes through the transport's loopback port, as the tunnel does.
fn relay_probe(via: Via, to: SocketAddr, data: Vec<u8>) -> Outgoing {
    if via.loopback() {
        Outgoing::Transport { to, data }
    } else {
        Outgoing::WgPort { to, data }
    }
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

/// The loopback ports of the transports, by what they reach.
#[derive(Debug, Clone, Copy)]
pub struct Loopbacks<'a> {
    /// Each TLS relay's ([`crate::config::DesiredMesh::tls_endpoints`]).
    pub tls: &'a BTreeMap<NodeId, SocketAddr>,
    /// Each obfuscated relay's ([`crate::config::DesiredMesh::obfs_endpoints`]).
    pub obfs: &'a BTreeMap<NodeId, SocketAddr>,
    /// Each peer's obfuscated port's on kernel WireGuard
    /// ([`crate::config::DesiredMesh::peer_obfs_endpoints`]); `None` where the data plane wraps for
    /// them on the WireGuard socket and the candidate's address is the endpoint.
    pub peer_obfs: Option<&'a BTreeMap<SocketAddr, SocketAddr>>,
}

#[cfg(test)]
static NO_LOOPBACK: BTreeMap<NodeId, SocketAddr> = BTreeMap::new();

#[cfg(test)]
impl Loopbacks<'static> {
    /// No transport's loopback ports, and peers' obfuscated ports reached on the WireGuard socket.
    pub const NONE: Self = Self {
        tls: &NO_LOOPBACK,
        obfs: &NO_LOOPBACK,
        peer_obfs: None,
    };
}

/// A candidate's endpoint in WireGuard and the information used for measurement. The endpoint of a TLS
/// or obfuscated candidate is its transport's loopback port, given by `loopbacks`; such a candidate
/// that was not assigned a port is not used.
fn routes(
    candidates: &[Candidate],
    loopbacks: Loopbacks<'_>,
) -> (Vec<(Route, PathKind)>, Vec<CandidateMeta>) {
    let plain = || CandidateMeta::Direct { loopback: false };
    candidates
        .iter()
        .filter_map(|c| match c {
            Candidate::Direct { endpoint } => {
                Some(((Route::Direct(*endpoint), PathKind::Direct), plain()))
            }
            Candidate::DirectObfs { endpoint, .. } => match loopbacks.peer_obfs {
                None => Some(((Route::Direct(*endpoint), PathKind::DirectObfs), plain())),
                Some(ports) => Some((
                    (Route::Direct(*ports.get(endpoint)?), PathKind::DirectObfs),
                    CandidateMeta::Direct { loopback: true },
                )),
            },
            Candidate::Lan { endpoint } => {
                Some(((Route::Direct(*endpoint), PathKind::Lan), plain()))
            }
            Candidate::Relay {
                relay,
                endpoint,
                token,
            } => Some(relay_route(relay, *endpoint, token, Via::Udp)),
            Candidate::RelayObfs { relay, token, .. } => Some(relay_route(
                relay,
                *loopbacks.obfs.get(relay)?,
                token,
                Via::Obfs,
            )),
            Candidate::RelayTls { relay, token, .. } => Some(relay_route(
                relay,
                *loopbacks.tls.get(relay)?,
                token,
                Via::Tls,
            )),
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
    via: Via,
) -> ((Route, PathKind), CandidateMeta) {
    let id = KeyId::of(relay.as_str().as_bytes());
    let kind = match via {
        Via::Udp => PathKind::Relay,
        Via::Obfs => PathKind::RelayObfs,
        Via::Tls => PathKind::RelayTls,
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
            via,
        },
    )
}

impl Prober {
    /// The endpoints recorded as blocked, as saved in the state directory (design/obfuscation.md
    /// section 5); applied to every peer.
    pub fn set_blocked(&mut self, blocked: BTreeSet<SocketAddr>) {
        self.blocked = blocked;
        for paths in self.peers.values_mut().filter_map(|p| p.paths.as_mut()) {
            paths.set_blocked(&self.blocked);
        }
    }

    /// The blocked endpoints, once after each change, for the caller to save.
    pub fn take_blocked_change(&mut self) -> Option<&BTreeSet<SocketAddr>> {
        std::mem::take(&mut self.blocked_changed).then_some(&self.blocked)
    }

    fn block(&mut self, endpoint: SocketAddr) {
        if self.blocked.len() >= MAX_BLOCKED || !self.blocked.insert(endpoint) {
            return;
        }
        self.blocked_changed = true;
        tracing::warn!(%endpoint, "plain UDP to this endpoint is blocked; obfuscated UDP stays in use");
        for paths in self.peers.values_mut().filter_map(|p| p.paths.as_mut()) {
            paths.set_blocked(&self.blocked);
        }
    }

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
            blocked: BTreeSet::new(),
            blocked_changed: false,
            round: 0,
            ready: Vec::new(),
            clock_trusted: false,
            hub: false,
            observations: Observations::default(),
            restart: random_u32(),
            restarted: Vec::new(),
            events: Vec::new(),
        }
    }

    /// The notices that this machine restarted, through the Hub, to `peers` (design/mesh.md section
    /// 8.4).
    pub fn restart_notices<'a>(
        &self,
        peers: impl IntoIterator<Item = &'a NodeId>,
        now_ms: u64,
    ) -> Vec<Outgoing> {
        let notice = RestartNotice {
            restart: self.restart,
        };
        peers
            .into_iter()
            .filter_map(|id| {
                let key = self.peers.get(id)?.switch_key.as_ref()?;
                Some(Outgoing::Hub {
                    peer: id.clone(),
                    data: notice.seal(now_ms, key).to_vec(),
                })
            })
            .collect()
    }

    pub fn public_key(&self, peer: &NodeId) -> Option<X25519PublicKey> {
        self.peers.get(peer).map(|p| p.public_key)
    }

    /// The peer's path that leads to `endpoint`, for a follower that names where it handshakes
    /// again; a direct path when none of them does.
    pub fn route_to(&self, peer: &NodeId, endpoint: SocketAddr) -> Route {
        self.peers
            .get(peer)
            .and_then(|p| p.routes.iter().find(|(r, _)| r.endpoint() == endpoint))
            .map_or(Route::Direct(endpoint), |(r, _)| *r)
    }

    /// Peers whose restart notice came since the last call, and when each was sent (Unix ms).
    pub fn take_restarted(&mut self) -> Vec<(NodeId, u64)> {
        std::mem::take(&mut self.restarted)
    }

    /// A peer restarted: the decider of the pair handshakes again on the path it is on, the switch
    /// to carry out; `None` for a peer this machine has no path selection state for, which follows
    /// on the endpoint WireGuard has (design/mesh.md section 8.4).
    pub fn handshake_again(&mut self, peer: &NodeId, at: Instant) -> Option<Switch> {
        let p = self.peers.get_mut(peer)?;
        let public_key = p.public_key;
        let action = p
            .paths
            .as_mut()?
            .handshake_again(SwitchReason::PeerRestarted, at);
        switch_of(peer, public_key, action)
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
    /// list has not changed keep their path selection state.
    pub fn update(
        &mut self,
        own_id: &NodeId,
        own_reach: Reachability,
        private_key: &PrivateKey,
        members: &BTreeMap<NodeId, Member>,
        paths: &BTreeMap<NodeId, PeerPathConfig>,
        loopbacks: Loopbacks<'_>,
    ) {
        let mut next = BTreeMap::new();
        self.monitored.clear();
        for (id, member) in members.iter().filter(|(id, _)| *id != own_id) {
            let config = paths.get(id);
            let candidates = config.map(|c| c.candidates.as_slice()).unwrap_or_default();
            let (mut routes, mut meta) = routes(candidates, loopbacks);
            let configured = routes.len();
            let role = config.and_then(|c| role(own_id, own_reach, id, c.reachability));
            let punch_wanted =
                role.is_some_and(Role::together) && candidates.contains(&Candidate::Punch);
            // The same member keeps what was learned about it; its path selection state is kept when
            // its candidates are unchanged, and reconfigured for the new ones otherwise, so the pair stays
            // on the path it uses (both ends of a two-ended pair stay together)
            let previous = self
                .peers
                .remove(id)
                .filter(|p| p.public_key == member.mesh_public_key);
            let unchanged = previous
                .as_ref()
                .is_some_and(|p| p.routes[..p.configured] == routes[..]);
            let before = previous
                .as_ref()
                .and_then(|p| p.paths.as_ref().map(|paths| (p, paths)))
                .filter(|(_, paths)| Some(paths.role()) == role);
            let fresh = before.is_none();
            let paths = match (before, role) {
                (Some((_, paths)), _) if unchanged => Some(paths.clone()),
                (Some((_, paths)), _) => paths.reconfigured(routes.clone()),
                (None, Some(role)) => PeerPaths::new(routes.clone(), role),
                (None, None) => None,
            };
            // The punched and learned direct paths the state kept come after the configured ones
            if let (Some((prev, _)), Some(next)) = (before, paths.as_ref())
                && next.candidate_count() > configured
            {
                for extra in &prev.routes[prev.configured..] {
                    routes.push(*extra);
                    meta.push(CandidateMeta::Direct { loopback: false });
                }
            }
            let together = match before {
                Some((prev, _)) if unchanged => prev.together.clone(),
                _ => role.and_then(|r| r.together().then(Together::default)),
            };
            let punch = match before {
                Some((prev, _)) if punch_wanted => prev
                    .punch
                    .clone()
                    .or_else(|| Some(Punch::new(Instant::now()))),
                _ if punch_wanted => Some(Punch::new(Instant::now())),
                _ => None,
            };
            let mut paths = paths;
            if let Some(p) = paths.as_mut() {
                p.set_peer_relay(KeyId::of(id.as_str().as_bytes()));
                p.set_blocked(&self.blocked);
                if fresh {
                    p.start_unblocked();
                }
            }
            let follows_together = role == Some(Role::FollowTogether);
            for (m, (route, _)) in meta.iter().zip(&routes) {
                let (CandidateMeta::Relay { relay, key, via }, Route::Relay { endpoint, .. }) =
                    (m, route)
                else {
                    continue;
                };
                // Over UDP the relay is measured for the peer; over TLS a follower keeps its standby
                // connection; obfuscated UDP has no connection to keep
                match via {
                    Via::Udp => {}
                    Via::Tls if follows_together => {}
                    Via::Tls | Via::Obfs => continue,
                }
                self.monitored
                    .entry((*relay, *via))
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
                    through: previous
                        .as_ref()
                        .map(|p| p.through.clone())
                        .unwrap_or_default(),
                    latest_probe_ms: previous.as_ref().map_or(0, |p| p.latest_probe_ms),
                    probed_on_request: previous.as_ref().and_then(|p| p.probed_on_request),
                    heard_restart: previous.as_ref().and_then(|p| p.heard_restart),
                    last_activity: previous.as_ref().and_then(|p| p.last_activity),
                    bytes: previous.map(|p| p.bytes).unwrap_or_default(),
                },
            );
        }
        self.peers = next;
        // A record ends once no candidate leads to its endpoint: that endpoint changed
        let recorded = self.blocked.len();
        self.blocked.retain(|endpoint| {
            self.peers
                .values()
                .filter_map(|p| p.paths.as_ref())
                .any(|p| p.leads_to_plain(endpoint))
        });
        self.blocked_changed |= self.blocked.len() != recorded;
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

    /// WireGuard's byte count for this peer, received and sent together, read by the engine.
    pub fn on_bytes(&mut self, peer: &NodeId, now: Instant, total: u64) {
        let Some(p) = self.peers.get_mut(peer) else {
            return;
        };
        if p.bytes
            .back()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) < BYTE_SAMPLE_INTERVAL)
        {
            return;
        }
        p.bytes.push_back((now, total));
        while p.bytes.len() > MAX_BYTE_SAMPLES
            || p.bytes.front().is_some_and(|(at, _)| {
                now.saturating_duration_since(*at) > BUSY_WINDOW + BYTE_SAMPLE_INTERVAL
            })
        {
            p.bytes.pop_front();
        }
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
    /// Probes every path to `peer` at the next tick, outside the schedule (design/status.md section 4.3),
    /// at most once per [`PROBE_REQUEST_INTERVAL`]; returns how many paths, or `None` when no member has
    /// that node ID. A machine that follows by roaming probes none.
    pub fn probe_now(&mut self, peer: &NodeId, now: Instant) -> Option<usize> {
        let peer = self.peers.get_mut(peer)?;
        let Some(paths) = peer.paths.as_mut() else {
            return Some(0);
        };
        if peer
            .probed_on_request
            .is_none_or(|t| now.saturating_duration_since(t) >= PROBE_REQUEST_INTERVAL)
        {
            peer.probed_on_request = Some(now);
            paths.probe_now();
        }
        Some(paths.probe_count())
    }

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
            if let Some((
                _,
                Pending::Monitor {
                    relay,
                    via: Via::Udp,
                },
                _,
            )) = self.outstanding.remove(&seq)
            {
                self.relay_stats.entry(relay).or_default().record_loss();
            }
        }

        let ids: Vec<NodeId> = self.peers.keys().cloned().collect();
        for id in ids {
            // A switch both ends agreed on is carried out before this tick measures: what the tick
            // finds is then about the path the pair is on, and an outage of the path it just left
            // does not start a recovery of its own (section 8.4)
            let mut actions = self.coordinate(&id, now, now_ms);
            let Some(peer) = self.peers.get_mut(&id) else {
                continue;
            };
            // During rotation always probe the tunnel: a reply to this end's probe is a two-way confirmation
            let active = peer
                .last_activity
                .is_some_and(|t| now.saturating_duration_since(t) < ACTIVE_WINDOW)
                || peer.together.as_ref().is_some_and(|t| t.rotation.is_some());
            let busy = busy(&peer.bytes);
            let Some(paths) = peer.paths.as_mut() else {
                continue;
            };
            paths.set_busy(busy);
            actions.extend(paths.tick(now, active));
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
                            (CandidateMeta::Direct { loopback }, Route::Direct(to)) => {
                                if let Some(key) = &peer.direct_key {
                                    let probe = OuterProbe {
                                        kind: DIRECT_PROBE,
                                        key_id: self.own_key_id,
                                        seq: wire,
                                        sent_ms: now_ms,
                                    };
                                    let data = probe.encode(key).to_vec();
                                    out.push(if *loopback {
                                        Outgoing::Transport { to, data }
                                    } else {
                                        Outgoing::WgPort { to, data }
                                    });
                                }
                            }
                            (
                                CandidateMeta::Relay { relay, key, via },
                                Route::Relay { endpoint, .. },
                            ) => {
                                let probe = OuterProbe {
                                    kind: RELAY_PROBE,
                                    key_id: self.own_key_id,
                                    seq: wire,
                                    sent_ms: now_ms,
                                };
                                out.push(relay_probe(*via, endpoint, probe.encode(key).to_vec()));
                                // The same way, a probe the relay forwards to the peer: its reply
                                // measures the whole path (ADR 0029)
                                let (relay, key, via) = (*relay, key.clone(), *via);
                                let receiver = KeyId::of(peer.public_key.as_bytes());
                                let Some(direct) = peer.direct_key.clone() else {
                                    continue;
                                };
                                let Some(wire) = self.remember(
                                    &id,
                                    Pending::Through {
                                        index,
                                        local: seq,
                                        relay,
                                    },
                                    now,
                                ) else {
                                    continue;
                                };
                                let through = Through {
                                    kind: THROUGH_PROBE,
                                    sender: self.own_key_id,
                                    seq: wire,
                                    sent_ms: now_ms,
                                    receiver,
                                };
                                out.push(relay_probe(
                                    via,
                                    endpoint,
                                    through.encode_probe(&direct, &key).to_vec(),
                                ));
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
                    Action::Lost { since } => self.lost(&id, since, now, now_ms),
                }
            }
            if let Some(endpoint) = self
                .peers
                .get_mut(&id)
                .and_then(|p| p.paths.as_mut())
                .and_then(PeerPaths::take_newly_blocked)
            {
                self.block(endpoint);
            }
            // A new proposal is sent immediately; those already waiting are resent at intervals
            out.extend(self.send_proposal(&id, now, now_ms));
            out.extend(self.punch_tick(&id, now, now_ms));
        }

        // The follower also measures relays, for the peer to estimate the other leg of the relay path, and
        // keeps its TLS standby connections authenticated
        let due: Vec<(KeyId, Via)> = self
            .monitored
            .iter()
            .filter(|(_, (_, _, last))| {
                last.is_none_or(|t| now.saturating_duration_since(t) >= RELAY_MONITOR_INTERVAL)
            })
            .map(|(id, _)| *id)
            .collect();
        let any_peer = self.peers.keys().next().cloned();
        for (relay, via) in due {
            let Some(owner) = any_peer.clone() else { break };
            let Some(wire) = self.remember(&owner, Pending::Monitor { relay, via }, now) else {
                break;
            };
            if let Some((endpoint, key, last)) = self.monitored.get_mut(&(relay, via)) {
                *last = Some(now);
                let probe = OuterProbe {
                    kind: RELAY_PROBE,
                    key_id: self.own_key_id,
                    seq: wire,
                    sent_ms: now_ms,
                };
                out.push(relay_probe(via, *endpoint, probe.encode(key).to_vec()));
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
            Some((Route::Direct(_), PathKind::Lan)) => Some(SwitchTarget::Lan),
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
    /// proposes through it the relay that answered best since the failure was suspected (`since`), and the
    /// follower waits for that proposal; otherwise both rotate by time slot. A recovery already under way
    /// continues.
    fn lost(&mut self, id: &NodeId, since: Instant, now: Instant, now_ms: u64) {
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
                    if let Some(index) = paths.best_other_relay(since, now)
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
        if kind == Incoming::ObfsPort {
            return self
                .on_packet(Incoming::WgPort, from, data, at, now_ms)
                .into_iter()
                .map(|o| match o {
                    Outgoing::WgPort { to, data } => Outgoing::ObfsPort { to, data },
                    o => o,
                })
                .collect();
        }
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
                        let loss = f64::from(r.loss_permille) / 1000.0;
                        peer.reports
                            .insert(r.relay, (Duration::from_millis(u64::from(r.rtt_ms)), loss));
                        if let Some(paths) = peer.paths.as_mut() {
                            paths.on_relay_report(r.relay, loss, at);
                        }
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
            (Incoming::WgPort, Some(DIRECT_PROBE)) => {
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
                // Answered from any address once authenticated, as WireGuard on this port answers
                // authenticated handshakes from any address (hard rule 2)
                let reply = probe.reply(self.own_key_id, from).encode(key);
                if let Some(peer) = self
                    .by_key_id
                    .get(&head.key_id)
                    .and_then(|id| self.peers.get_mut(id))
                {
                    // Only a probe sent later than every one before teaches anything, so one replayed
                    // from another address teaches nothing
                    let fresh = probe.sent_ms > peer.latest_probe_ms;
                    peer.latest_probe_ms = peer.latest_probe_ms.max(probe.sent_ms);
                    if let Some(paths) = peer.paths.as_mut() {
                        // During hole punching: the direction from the other side to this machine works
                        // (design/mesh.md section 6.1)
                        if let Some(punch) = peer.punch.as_mut() {
                            punch.on_probe_from(from, paths.role() == Role::FollowTogether);
                        }
                        // A LAN address no candidate has is where the peer can be reached when another
                        // NAT sits inside the LAN (design/mesh.md section 6)
                        let route = Route::Direct(from);
                        let known = peer.routes[..peer.configured]
                            .iter()
                            .any(|(r, _)| *r == route);
                        if fresh
                            && paths.role().together()
                            && crate::lan::is_lan(from.ip())
                            && !known
                        {
                            let index = paths.learn_lan(from, at);
                            let entry = (route, PathKind::Lan);
                            if index < peer.routes.len() {
                                peer.routes[index] = entry;
                            } else {
                                peer.routes.push(entry);
                                peer.meta.push(CandidateMeta::Direct { loopback: false });
                            }
                        }
                    }
                }
                vec![Outgoing::WgPort {
                    to: from,
                    data: reply.to_vec(),
                }]
            }
            (Incoming::WgPort, Some(THROUGH_PROBE)) => self.on_through_probe(from, data, now_ms),
            (Incoming::WgPort, Some(THROUGH_REPLY)) => {
                self.on_through_reply(data, at, now_ms);
                vec![]
            }
            (Incoming::WgPort, Some(probe::WG_COOKIE_REPLY))
                if data.len() == probe::WG_COOKIE_LEN =>
            {
                self.on_cookie_reply(from, at);
                vec![]
            }
            (Incoming::WgPort | Incoming::Transport, Some(DIRECT_REPLY)) => {
                let over_transport = kind == Incoming::Transport;
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
                // A reply comes back the way its probe went: a candidate reached through the
                // obfuscated transport is answered through it, any other on the WireGuard port
                let loopback = |index: usize| {
                    matches!(
                        self.peers[&id].meta.get(index),
                        Some(CandidateMeta::Direct { loopback }) if *loopback == over_transport
                    )
                };
                match self.outstanding.get(&reply.seq).cloned() {
                    Some((owner, Pending::Candidate { index, local }, _))
                        if owner == id && loopback(index) =>
                    {
                        self.outstanding.remove(&reply.seq);
                        // The source the other side sees is the mapped address of this machine's
                        // WireGuard port (design/mesh.md section 6.1); through the transport it is
                        // the transport's socket
                        if !over_transport {
                            self.observations.record(from.ip(), reply.observed, at);
                        }
                        if let Some(paths) =
                            self.peers.get_mut(&owner).and_then(|p| p.paths.as_mut())
                        {
                            paths.on_candidate_reply(index, local, at, None);
                        }
                    }
                    Some((owner, Pending::Punch, _)) if owner == id && !over_transport => {
                        self.outstanding.remove(&reply.seq);
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
            (Incoming::Transport, Some(probe::RELAY_REPLY)) => {
                self.on_relay_reply(data, at, true);
                vec![]
            }
            (Incoming::WgPort, Some(probe::RELAY_REPLY)) => {
                self.on_relay_reply(data, at, false);
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
        if let Some((notice, sent_ms)) = RestartNotice::open(data, &key, now_ms) {
            if let Some(peer) = self.peers.get_mut(sender)
                && peer.heard_restart != Some(notice.restart)
            {
                peer.heard_restart = Some(notice.restart);
                self.restarted.retain(|(id, _)| id != sender);
                self.restarted.push((sender.clone(), sent_ms));
            }
            return vec![];
        }
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
                    SwitchTarget::Lan => paths.lan_index(),
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
                peer.meta.push(CandidateMeta::Direct { loopback: false });
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
            out.push(Outgoing::WgPort {
                to: target,
                data: probe.encode(&key).to_vec(),
            });
        }
        out
    }

    /// A relay's reply, which comes back the way its probe went: through a transport's loopback port
    /// (`over_transport`) or to the WireGuard port.
    fn on_relay_reply(&mut self, data: &[u8], at: Instant, over_transport: bool) {
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
        let (relay, key, via) = match pending {
            Pending::Monitor { relay, via } => match self.monitored.get(&(relay, via)) {
                Some((_, key, _)) => (relay, key, via),
                None => return,
            },
            Pending::Candidate { index, .. } => {
                match self.peers.get(&owner).and_then(|p| p.meta.get(index)) {
                    Some(CandidateMeta::Relay { relay, key, via }) => (*relay, key, *via),
                    _ => return,
                }
            }
            Pending::Tunnel { .. } | Pending::Through { .. } | Pending::Punch => return,
        };
        if via.loopback() != over_transport || OuterReply::verify(data, key).is_none() {
            return;
        }
        self.outstanding.remove(&seq);
        let rtt = at.saturating_duration_since(sent);
        // What is carried to the peer with the in-tunnel reply is this machine's UDP measurement to the relay
        if via == Via::Udp {
            self.relay_stats.entry(relay).or_default().record_reply(rtt);
        }
        // While through probes come back through this relay, they alone measure paths through it: the
        // relay answering this end says nothing about its leg to the peer (ADR 0029)
        if let Pending::Candidate { index, local } = pending
            && let Some(peer) = self.peers.get_mut(&owner)
        {
            match peer.through.get(&relay) {
                Some(t) if at.saturating_duration_since(*t) < THROUGH_LAPSE => return,
                // The relay answers but the path through it has not for a while: until the peer
                // reports its leg to the relay working, that is a break beyond the relay, as when
                // a path through it fails while it answers. A peer or relay gone back to an older
                // release reports the leg working, and the relay is taken again
                Some(_) => {
                    peer.through.remove(&relay);
                    if let Some(paths) = peer.paths.as_mut() {
                        paths.hold_beyond(relay, at);
                    }
                }
                None => {}
            }
            let extra = peer.reports.get(&relay).copied();
            if let Some(paths) = peer.paths.as_mut() {
                paths.on_candidate_reply(index, local, at, extra);
            }
        }
    }

    /// A peer's through probe, forwarded by a relay (ADR 0029): answered, once its member checksum
    /// holds, to where it came from, as a direct probe is.
    fn on_through_probe(&self, from: SocketAddr, data: &[u8], now_ms: u64) -> Vec<Outgoing> {
        let Some(head) = Through::peek(data) else {
            return vec![];
        };
        let Some(key) = self
            .by_key_id
            .get(&head.sender)
            .and_then(|id| self.peers[id].direct_key.as_ref())
        else {
            return vec![];
        };
        match Through::verify_member(data, key, now_ms) {
            Some(probe) if probe.kind == THROUGH_PROBE && probe.receiver == self.own_key_id => {
                vec![Outgoing::WgPort {
                    to: from,
                    data: probe.encode_reply(key).to_vec(),
                }]
            }
            _ => vec![],
        }
    }

    /// The peer's reply to a through probe, back through the relay: the whole path through that relay
    /// works, and from now on through probes measure it.
    fn on_through_reply(&mut self, data: &[u8], at: Instant, now_ms: u64) {
        let Some(head) = Through::peek(data) else {
            return;
        };
        let Some(id) = self.by_key_id.get(&head.sender).cloned() else {
            return;
        };
        let Some(reply) = self.peers[&id]
            .direct_key
            .as_ref()
            .and_then(|k| Through::verify_member(data, k, now_ms))
        else {
            return;
        };
        if reply.kind != THROUGH_REPLY || reply.receiver != self.own_key_id {
            return;
        }
        let Some((
            owner,
            Pending::Through {
                index,
                local,
                relay,
            },
            _,
        )) = self.outstanding.remove(&reply.seq)
        else {
            return;
        };
        if owner != id {
            return;
        }
        if let Some(peer) = self.peers.get_mut(&owner) {
            peer.through.insert(relay, at);
            if let Some(paths) = peer.paths.as_mut() {
                paths.on_candidate_reply(index, local, at, Some((Duration::ZERO, 0.0)));
            }
        }
    }

    fn relay_reports(&self) -> Vec<RelayReport> {
        self.relay_stats
            .iter()
            .filter_map(|(relay, stats)| {
                // A relay that never replied has no round-trip time, and is reported fully lost
                let loss = stats.measured_loss()?;
                Some(RelayReport {
                    relay: *relay,
                    rtt_ms: stats
                        .rtt_ms()
                        .map_or(0, |rtt| rtt.round().clamp(0.0, f64::from(u16::MAX)) as u16),
                    loss_permille: (loss * 1000.0).round() as u16,
                })
            })
            .take(probe::MAX_RELAY_REPORTS)
            .collect()
    }
}

/// Whether the sampled byte counts show more than [`BUSY_RATE`] over the window they span.
fn busy(samples: &VecDeque<(Instant, u64)>) -> bool {
    let (Some((first_at, first)), Some((last_at, last))) = (samples.front(), samples.back()) else {
        return false;
    };
    let span = last_at.saturating_duration_since(*first_at).as_secs_f64();
    span >= BYTE_SAMPLE_INTERVAL.as_secs_f64()
        && last.saturating_sub(*first) as f64 / span > BUSY_RATE as f64
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

/// Random number for random retries, which only staggers the two ends' retries, and for the restart
/// number, which only tells one restart from the next: neither has a security role.
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

    #[test]
    fn a_pair_is_busy_above_two_megabits_over_the_window() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        // 300 kB a second for 10 seconds, then 100 kB a second
        let heavy: VecDeque<_> = (0..=10).map(|s| (at(s), s * 300_000)).collect();
        assert!(busy(&heavy));
        let light: VecDeque<_> = (0..=10).map(|s| (at(s), s * 100_000)).collect();
        assert!(!busy(&light));
        // One sample says nothing about a rate
        assert!(!busy(&VecDeque::from([(t0, 5_000_000)])));
    }

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
        /// Packets from B's WireGuard port reach R. `false` stands in for a network that drops what
        /// leaves B's WireGuard port toward R while B's other ports get through.
        b_wg_to_relay: bool,
        /// R forwards through probes and their replies (ADR 0029); a relay on an older release
        /// does not.
        relay_forwards_through: bool,
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
            Self::with_blocked(BTreeSet::new())
        }

        /// A starts with these endpoints recorded as blocked, as after a restart.
        fn with_blocked(blocked: BTreeSet<SocketAddr>) -> Self {
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
            a.prober.set_blocked(blocked);
            a.prober.update(
                &a.id,
                Reachability::DialOnly,
                &a_priv,
                &members,
                &paths(2, Reachability::Public, TOKEN_A, "198.51.100.2:41820"),
                Loopbacks::NONE,
            );
            b.prober.update(
                &b.id,
                Reachability::Public,
                &b_priv,
                &members,
                &paths(1, Reachability::DialOnly, TOKEN_B, "203.0.113.1:41820"),
                Loopbacks::NONE,
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
                b_wg_to_relay: true,
                relay_forwards_through: true,
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
                Some(e) if e == self.relay => self.relay_up && self.b_wg_to_relay,
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
                // A through probe: R forwards it to the other end and that end's reply back, over
                // R's legs to both (the checks on R are nett-relay's)
                Outgoing::WgPort { to, data }
                    if to == self.relay && data.first() == Some(&THROUGH_PROBE) =>
                {
                    if self.relay_up && self.relay_forwards_through && self.b_wg_to_relay {
                        let relay = self.relay;
                        for reply in dst.prober.on_packet(Incoming::WgPort, relay, &data, now, 0) {
                            if let Outgoing::WgPort { to, data } = reply
                                && to == relay
                            {
                                src.prober.on_packet(Incoming::WgPort, relay, &data, now, 0);
                            }
                        }
                    }
                }
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
                Outgoing::WgPort { to, data } if to == self.relay => {
                    let wg = src.wg;
                    if self.relay_up
                        && (from_a || self.b_wg_to_relay)
                        && let Some(reply) = self.relay_reply(&data, wg)
                    {
                        let src = if from_a { &mut self.a } else { &mut self.b };
                        src.prober
                            .on_packet(Incoming::WgPort, self.relay, &reply, now, 0);
                    }
                }
                Outgoing::WgPort { data, .. } if self.direct_up => {
                    for reply in dst
                        .prober
                        .on_packet(Incoming::WgPort, src.wg, &data, now, 0)
                    {
                        if let Outgoing::WgPort { data, .. } = reply {
                            src.prober
                                .on_packet(Incoming::WgPort, dst.wg, &data, now, 0);
                        }
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

    /// B, which follows, probes the relay without any reply: it reports the relay fully lost through the
    /// tunnel, so A knows the path through it is down (design/mesh.md section 7.2).
    #[test]
    fn a_relay_that_never_answered_is_reported_lost() {
        let mut net = Net::new();
        net.relay_up = false;
        net.run(Duration::from_secs(30));
        let relay = KeyId::of(node_id(9).as_str().as_bytes());
        let heard = net
            .a
            .prober
            .peers
            .get(&net.b.id)
            .and_then(|p| p.reports.get(&relay))
            .copied();
        assert_eq!(heard.map(|(_, loss)| loss), Some(1.0));
    }

    /// B's WireGuard port cannot reach R while its other ports can: B's measurement of R shares the
    /// addresses WireGuard uses, so it reports R lost, and A never moves onto a relay path the
    /// tunnel cannot cross (design/mesh.md section 7.1).
    #[test]
    fn a_relay_the_followers_wireguard_port_cannot_reach_is_not_used() {
        let mut net = Net::new();
        net.b_wg_to_relay = false;
        net.run(Duration::from_secs(10));
        let broke = net.now;
        net.direct_up = false;
        net.run(Duration::from_secs(120));
        let relay = KeyId::of(node_id(9).as_str().as_bytes());
        let heard = net.a.prober.peers[&net.b.id].reports.get(&relay).copied();
        assert_eq!(heard.map(|(_, loss)| loss), Some(1.0));
        let onto_relay: Vec<_> = net
            .switches
            .iter()
            .filter(|(at, s)| *at >= broke && s.to.endpoint() == net.relay)
            .map(|(_, s)| s.reason)
            .collect();
        assert!(onto_relay.is_empty(), "{onto_relay:?}");
    }

    /// A whose current path fails, with R as the only other candidate.
    fn onto_relay_after(net: &Net, since: Instant) -> Vec<SwitchReason> {
        net.switches
            .iter()
            .filter(|(at, s)| *at >= since && s.to.endpoint() == net.relay)
            .map(|(_, s)| s.reason)
            .collect()
    }

    /// B's leg to R breaks while R keeps answering A, as when a firewall upstream of B starts dropping
    /// its UDP, and then the direct path fails. B's reports of its leg to R are over a window of probes,
    /// one every 5 seconds, so they still show the leg mostly working; R's through probes do not come
    /// back, and A does not move onto the broken path (ADR 0029). A relay that does not forward through
    /// probes leaves A only the reports, and A moves there.
    #[test]
    fn a_relay_whose_leg_to_the_peer_broke_is_not_taken_on_the_relays_answers() {
        for forwards in [true, false] {
            let mut net = Net::new();
            net.relay_forwards_through = forwards;
            net.run(Duration::from_secs(10));
            net.b_wg_to_relay = false;
            net.run(Duration::from_secs(4));
            let broke = net.now;
            net.direct_up = false;
            net.run(Duration::from_secs(8));
            let onto = onto_relay_after(&net, broke);
            assert_eq!(
                onto.is_empty(),
                forwards,
                "forwards through probes: {forwards}, {onto:?}"
            );
        }
    }

    /// Through probes that stop coming back while the relay path works, as when the peer or the relay
    /// goes back to an older release: after 30 seconds the path through R is estimated from its
    /// segments again, and A can fail over to it.
    #[test]
    fn a_relay_whose_through_probes_stop_is_measured_from_its_segments_again() {
        let mut net = Net::new();
        net.run(Duration::from_secs(10));
        let relay = KeyId::of(node_id(9).as_str().as_bytes());
        assert!(
            net.a.prober.peers[&net.b.id].through.contains_key(&relay),
            "through replies came back"
        );
        net.relay_forwards_through = false;
        // The pair keeps carrying traffic all along
        let b = net.b.id.clone();
        for _ in 0..7 {
            net.a.prober.mark_active(&b, net.now);
            net.run(Duration::from_secs(5));
        }
        net.a.prober.mark_active(&b, net.now);
        let broke = net.now;
        net.direct_up = false;
        net.run(Duration::from_secs(10));
        // The test network signals no completed handshake, so the switch is followed by retries
        assert_eq!(
            onto_relay_after(&net, broke).first(),
            Some(&SwitchReason::Unreachable),
            "{:?}",
            net.switches
        );
    }

    /// With through probes coming back, a failover takes the relay path as usual.
    #[test]
    fn a_working_relay_path_is_taken_on_its_through_probes() {
        let mut net = Net::new();
        net.run(Duration::from_secs(10));
        let broke = net.now;
        net.direct_up = false;
        net.run(Duration::from_secs(10));
        // The test network signals no completed handshake, so the switch is followed by retries
        assert_eq!(
            onto_relay_after(&net, broke).first(),
            Some(&SwitchReason::Unreachable),
            "{:?}",
            net.switches
        );
    }

    /// After a restart, a connection whose first candidate is recorded as blocked starts on the next
    /// one instead of waiting for the blocked one to fail (design/obfuscation.md section 5).
    #[test]
    fn a_restarted_connection_starts_off_a_blocked_endpoint() {
        let direct = addr("198.51.100.2:41820");
        let fresh = Net::new();
        assert_eq!(fresh.a.prober.desired_endpoint(&fresh.b.id), Some(direct));
        let net = Net::with_blocked([direct].into());
        assert_eq!(
            net.a.prober.desired_endpoint(&net.b.id),
            Some(net.relay),
            "starts on the relay"
        );
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
                .on_packet(Incoming::WgPort, net.a.wg, &forged, now, 0)
                .is_empty()
        );
        // Arbitrary bytes
        assert!(
            net.b
                .prober
                .on_packet(Incoming::WgPort, net.a.wg, &[0x82; 64], now, 0)
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
        /// How long a message through the Hub takes, and those on their way (due, from a, data).
        hub_delay: Duration,
        hub_queue: Vec<(Instant, bool, Vec<u8>)>,
        /// B starts ticking this much later than A, so the two probe out of phase.
        b_from: Instant,
        /// The admitted members, for configuring an end again.
        members: BTreeMap<NodeId, Member>,
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
                Loopbacks::NONE,
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
                Loopbacks::NONE,
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
                hub_delay: Duration::ZERO,
                hub_queue: Vec::new(),
                b_from: now,
                members,
            }
        }

        /// A new desired state for B: its candidates to A are now `candidates`.
        fn reconfigure_b(&mut self, candidates: Vec<Candidate>) {
            let (b_priv, _) = keypair(2);
            let paths = [(
                node_id(1),
                PeerPathConfig {
                    reachability: Reachability::DialOnly,
                    candidates,
                },
            )]
            .into();
            let b = self.b.id.clone();
            self.b.prober.update(
                &b,
                Reachability::DialOnly,
                &b_priv,
                &self.members,
                &paths,
                Loopbacks::NONE,
            );
        }

        /// B's candidate through relay `i`, as configured at the start.
        fn b_relay(&self, i: usize) -> Candidate {
            Candidate::Relay {
                relay: node_id(9 + u8::try_from(i).expect("small")),
                endpoint: self.relays[i],
                token: ProbeToken(TOKEN_B),
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
                Outgoing::WgPort { to, data } if self.relays.contains(&to) => {
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
                                Incoming::WgPort,
                                to,
                                &reply.encode(&key),
                                now,
                                now_ms,
                            );
                        }
                    }
                }
                // Neither end has an obfuscated port here
                Outgoing::ObfsPort { .. } => {}
                Outgoing::Hub { peer, data } => {
                    let dst = if from_a { &self.b } else { &self.a };
                    if !self.hub || peer != dst.id {
                        return;
                    }
                    if self.hub_delay.is_zero() {
                        self.through_hub(from_a, data);
                    } else {
                        self.hub_queue.push((now + self.hub_delay, from_a, data));
                    }
                }
                Outgoing::WgPort { to, data } => {
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
                            .on_packet(Incoming::WgPort, from, &data, now, now_ms);
                    for reply in replies {
                        if let Outgoing::WgPort { to, data } = reply
                            && to == from
                            && self.opened[src].contains(&self.mapped[dst])
                        {
                            sender.prober.on_packet(
                                Incoming::WgPort,
                                self.mapped[dst],
                                &data,
                                now,
                                now_ms,
                            );
                        }
                    }
                }
                // No TLS relays in this network
                Outgoing::Transport { .. } => {}
            }
        }

        /// A message through the Hub reaches the other end; its reply comes back the same way.
        fn through_hub(&mut self, from_a: bool, data: Vec<u8>) {
            let (now, now_ms) = (self.now, self.now_ms);
            let (src, dst) = if from_a {
                (&mut self.a, &mut self.b)
            } else {
                (&mut self.b, &mut self.a)
            };
            let src_id = src.id.clone();
            for reply in dst.prober.on_hub_message(&src_id, &data, now, now_ms) {
                if let Outgoing::Hub { peer, data } = reply
                    && peer == src_id
                {
                    self.deliver(!from_a, Outgoing::Hub { peer, data });
                }
            }
        }

        fn run(&mut self, d: Duration) {
            let end = self.now + d;
            while self.now < end {
                self.now += Duration::from_millis(100);
                self.now_ms += 100;
                let now = self.now;
                let due: Vec<(Instant, bool, Vec<u8>)> = self
                    .hub_queue
                    .iter()
                    .filter(|(t, _, _)| *t <= now)
                    .cloned()
                    .collect();
                self.hub_queue.retain(|(t, _, _)| *t > now);
                for (_, from_a, data) in due {
                    self.through_hub(from_a, data);
                }
                let (a_out, a_sw) = self.a.prober.tick(self.now, self.now_ms);
                let (b_out, b_sw) = if self.now >= self.b_from {
                    self.b.prober.tick(self.now, self.now_ms)
                } else {
                    Default::default()
                };
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
                Loopbacks {
                    tls: &tls,
                    ..Loopbacks::NONE
                },
            );
            let (out, _) = prober.tick(Instant::now(), 1_700_000_000_000);
            out.into_iter()
                .filter_map(|o| match o {
                    Outgoing::Transport { to, .. } => Some((true, to)),
                    Outgoing::WgPort { to, .. } => Some((false, to)),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        // Node 2 follows node 1 (the smaller node ID decides). The TLS relay is probed through its
        // loopback port, the UDP relay from the WireGuard port
        let (b_priv, _) = keypair(2);
        let follower = probes_to(2, &b_priv, &b_pub);
        assert!(follower.contains(&(true, loopback)), "{follower:?}");
        assert!(
            follower.contains(&(false, addr("198.51.100.9:41822"))),
            "{follower:?}"
        );
        let decider = probes_to(1, &a_priv, &a_pub);
        assert!(decider.contains(&(true, loopback)), "{decider:?}");
    }

    /// A pair of admitted members, 1 and 2, as prober 1 sees them: 2 has `candidates`, and 1 is `own`.
    fn prober_of_one(own: Reachability, candidates: Vec<Candidate>) -> (Prober, ProbeKey, KeyId) {
        prober_of_one_with(own, candidates, Loopbacks::NONE)
    }

    fn prober_of_one_with(
        own: Reachability,
        candidates: Vec<Candidate>,
        loopbacks: Loopbacks<'_>,
    ) -> (Prober, ProbeKey, KeyId) {
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
        let mut a = Prober::new(&a_pub);
        a.update(
            &node_id(1),
            own,
            &a_priv,
            &members,
            &[(
                node_id(2),
                PeerPathConfig {
                    reachability: Reachability::DialOnly,
                    candidates,
                },
            )]
            .into(),
            loopbacks,
        );
        let key = ProbeKey::direct(&b_priv, &a_pub).expect("key");
        (a, key, KeyId::of(b_pub.as_bytes()))
    }

    /// A peer's obfuscated port is probed the way the tunnel reaches it (design/obfuscation.md
    /// section 6): on kernel WireGuard through the obfuscated transport's loopback port, whose reply
    /// alone answers the probe; on the userspace data plane at the port itself from the WireGuard
    /// port, which wraps it.
    #[test]
    fn a_peers_obfuscated_port_is_probed_the_way_the_tunnel_reaches_it() {
        let port = addr("198.51.100.2:30000");
        let loopback = addr("127.0.0.1:41851");
        // The pair starts on the first candidate, which the tunnel's own probes measure
        let candidates = vec![
            Candidate::Direct {
                endpoint: addr("198.51.100.2:41820"),
            },
            Candidate::DirectObfs {
                endpoint: port,
                key: crate::config::ObfsSecret([3; 32]),
                padding: crate::config::ObfsPadding { min: 0, max: 64 },
            },
        ];
        let now = Instant::now();
        let now_ms = 1_700_000_000_000;
        let probes = |out: &[Outgoing]| -> Vec<(bool, SocketAddr, Vec<u8>)> {
            out.iter()
                .filter_map(|o| match o {
                    Outgoing::Transport { to, data } => Some((true, *to, data.clone())),
                    Outgoing::WgPort { to, data } if data[0] == DIRECT_PROBE => {
                        Some((false, *to, data.clone()))
                    }
                    _ => None,
                })
                .collect()
        };

        let ports: BTreeMap<SocketAddr, SocketAddr> = [(port, loopback)].into();
        let kernel = Loopbacks {
            peer_obfs: Some(&ports),
            ..Loopbacks::NONE
        };
        let (mut a, key, key_id) =
            prober_of_one_with(Reachability::DialOnly, candidates.clone(), kernel);
        let sent = probes(&a.tick(now, now_ms).0);
        let to: Vec<(bool, SocketAddr)> = sent.iter().map(|(t, to, _)| (*t, *to)).collect();
        assert!(to.contains(&(true, loopback)), "{to:?}");
        assert!(!to.iter().any(|(_, to)| *to == port), "{to:?}");
        assert_eq!(
            a.peer_view(&node_id(2), now).expect("peer").routes[1],
            (Route::Direct(loopback), PathKind::DirectObfs)
        );
        let (_, _, data) = sent
            .iter()
            .find(|(t, ..)| *t)
            .expect("through the transport");
        let probe = OuterProbe::verify(data, &key, now_ms).expect("a probe from 1");
        let reply = probe
            .reply(key_id, addr("203.0.113.9:1"))
            .encode(&key)
            .to_vec();
        // Answered on the WireGuard port instead: not the path this probe measures
        a.on_packet(Incoming::WgPort, port, &reply, now, now_ms);
        assert!(a.outstanding.contains_key(&probe.seq));
        a.on_packet(Incoming::Transport, loopback, &reply, now, now_ms);
        assert!(!a.outstanding.contains_key(&probe.seq), "answered");

        let (mut a, _, _) = prober_of_one_with(Reachability::DialOnly, candidates, Loopbacks::NONE);
        let to: Vec<(bool, SocketAddr)> = probes(&a.tick(now, now_ms).0)
            .into_iter()
            .map(|(t, to, _)| (t, to))
            .collect();
        assert!(to.contains(&(false, port)), "{to:?}");
        assert!(!to.iter().any(|(t, _)| *t), "{to:?}");
    }

    /// A probe on this machine's obfuscated port is answered through that port, so a peer that
    /// probes both of this machine's ports measures each (design/obfuscation.md section 6).
    #[test]
    fn a_probe_on_the_obfuscated_port_is_answered_through_it() {
        let (mut a, key, key_id) = prober_of_one(Reachability::Public, vec![]);
        let now_ms = 1_700_000_000_000;
        let probe = probe_from_two(&key, key_id, 1, now_ms);
        let from = addr("198.51.100.5:41820");
        let replies = a.on_packet(Incoming::ObfsPort, from, &probe, Instant::now(), now_ms);
        assert!(
            matches!(replies[..], [Outgoing::ObfsPort { to, .. }] if to == from),
            "{replies:?}"
        );
        let replies = a.on_packet(Incoming::WgPort, from, &probe, Instant::now(), now_ms);
        assert!(matches!(replies[..], [Outgoing::WgPort { .. }]));
    }

    /// Member 2's direct probe, sent at `sent_ms`.
    fn probe_from_two(key: &ProbeKey, key_id: KeyId, seq: u32, sent_ms: u64) -> Vec<u8> {
        OuterProbe {
            kind: DIRECT_PROBE,
            key_id,
            seq,
            sent_ms,
        }
        .encode(key)
        .to_vec()
    }

    /// An authenticated probe is answered whatever address it comes from, as WireGuard answers an
    /// authenticated handshake (hard rule 2); an unauthenticated one never is.
    #[test]
    fn an_authenticated_probe_is_answered_from_any_address() {
        let (mut a, key, key_id) = prober_of_one(
            Reachability::Public,
            vec![Candidate::Lan {
                endpoint: addr("192.168.1.20:50002"),
            }],
        );
        let now_ms = 1_700_000_000_000;
        let probe = probe_from_two(&key, key_id, 1, now_ms);
        let mut answered = |from: &str, data: &[u8]| {
            !a.on_packet(Incoming::WgPort, addr(from), data, Instant::now(), now_ms)
                .is_empty()
        };
        assert!(
            answered("192.168.1.20:50002", &probe),
            "the LAN candidate's address"
        );
        assert!(
            answered("10.1.3.6:61000", &probe),
            "another LAN address, as through a NAT inside the LAN"
        );
        assert!(answered("198.51.100.5:41820", &probe), "a public address");
        let mut forged = probe.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(!answered("10.1.3.6:61000", &forged), "a forged probe");
    }

    /// Between two dial-only members, a LAN address the peer's probes come from that no candidate has
    /// becomes a LAN candidate (design/mesh.md section 6); a probe replayed from another address adds
    /// nothing.
    #[test]
    fn a_lan_address_the_peers_probes_come_from_becomes_a_candidate() {
        let (mut a, key, key_id) = prober_of_one(
            Reachability::DialOnly,
            vec![
                Candidate::Lan {
                    endpoint: addr("172.20.0.3:50002"),
                },
                Candidate::Punch,
            ],
        );
        let now = Instant::now();
        let now_ms = 1_700_000_000_000;
        let lan_routes = |a: &Prober| {
            a.peer_view(&node_id(2), now)
                .expect("peer")
                .routes
                .iter()
                .filter(|(_, kind)| *kind == PathKind::Lan)
                .map(|(r, _)| *r)
                .collect::<Vec<_>>()
        };
        let probe = probe_from_two(&key, key_id, 1, now_ms);
        a.on_packet(
            Incoming::WgPort,
            addr("10.1.3.6:61000"),
            &probe,
            now,
            now_ms,
        );
        let learned = Route::Direct(addr("10.1.3.6:61000"));
        assert_eq!(
            lan_routes(&a),
            [Route::Direct(addr("172.20.0.3:50002")), learned]
        );
        // The same probe again, from elsewhere: a replay
        a.on_packet(Incoming::WgPort, addr("10.1.3.9:1"), &probe, now, now_ms);
        assert_eq!(lan_routes(&a)[1], learned);
        // A public source is hole punching's to learn
        let later = probe_from_two(&key, key_id, 2, now_ms + 1);
        a.on_packet(
            Incoming::WgPort,
            addr("198.51.100.5:41820"),
            &later,
            now,
            now_ms + 1,
        );
        assert_eq!(lan_routes(&a)[1], learned);
    }

    /// A request probes every path to the peer at the next tick, at most once a second
    /// (design/status.md section 4.3).
    #[test]
    fn a_probe_request_probes_every_path_at_once() {
        let (mut a, _, _) = prober_of_one(
            Reachability::DialOnly,
            vec![
                Candidate::Lan {
                    endpoint: addr("192.168.1.20:50002"),
                },
                Candidate::Lan {
                    endpoint: addr("10.1.2.10:50002"),
                },
            ],
        );
        let start = Instant::now();
        let now_ms = 1_700_000_000_000;
        let probes = |out: &[Outgoing]| {
            out.iter()
                .filter(|o| matches!(o, Outgoing::WgPort { data, .. } if data[0] == DIRECT_PROBE))
                .count()
        };
        // Idle, after the first probes: nothing is due for minutes
        a.tick(start, now_ms);
        let at = start + Duration::from_secs(70);
        assert_eq!(probes(&a.tick(at, now_ms).0), 0);
        assert_eq!(a.probe_now(&node_id(2), at), Some(2));
        assert_eq!(probes(&a.tick(at, now_ms).0), 2);
        // Within a second of the last request: no probing again
        assert_eq!(
            a.probe_now(&node_id(2), at + Duration::from_millis(500)),
            Some(2)
        );
        assert_eq!(
            probes(&a.tick(at + Duration::from_millis(500), now_ms).0),
            0
        );
        assert_eq!(a.probe_now(&node_id(9), at), None, "no such member");
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

    /// The pair has moved together off the relay it started on; then a new desired state changes B's
    /// candidates to A (a LAN address A reports), which builds B's path selection state anew. B stays on
    /// the relay the pair is on: starting again from the first relay, as both ends do when they start,
    /// would leave A on the other one, and B would find its path broken and rotate on its own.
    #[test]
    fn dial_only_pair_stays_together_when_one_ends_candidates_change() {
        let mut pair = Pair::new();
        pair.run(Duration::from_secs(10));
        let (start, _) = pair.endpoints();
        let current = pair
            .relays
            .iter()
            .position(|r| Some(*r) == start)
            .expect("on a relay");
        pair.lossy = Some((current, 2));
        pair.run(Duration::from_secs(20));
        pair.lossy = None;
        let (a, b) = pair.endpoints();
        assert_eq!(a, b);
        assert_ne!(a, start, "{:?}", pair.switches);
        let before = pair.switches.len();

        let lan = Candidate::Lan {
            endpoint: addr("192.168.1.20:41820"),
        };
        pair.reconfigure_b(vec![pair.b_relay(1), pair.b_relay(0), lan]);
        assert_eq!(pair.endpoints().1, b, "B stays on the relay the pair uses");
        pair.run(Duration::from_secs(30));
        let (a2, b2) = pair.endpoints();
        assert_eq!((a2, b2), (a, b), "{:?}", &pair.switches[before..]);
        let rotations: Vec<_> = pair.switches[before..]
            .iter()
            .filter(|(_, _, s)| s.reason == SwitchReason::Rotation)
            .collect();
        assert!(rotations.is_empty(), "{rotations:?}");
    }

    /// A blocked endpoint's record lasts while a plain UDP candidate leads to it and ends once none
    /// does (design/obfuscation.md section 5); the candidate shows as blocked meanwhile.
    #[test]
    fn a_blocked_record_ends_when_its_endpoint_changes() {
        let mut pair = Pair::new();
        let blocked = pair.relays[0];
        pair.b.prober.set_blocked([blocked].into());
        pair.reconfigure_b(vec![pair.b_relay(0), pair.b_relay(1)]);
        assert!(
            pair.b.prober.take_blocked_change().is_none(),
            "still in use"
        );
        let states: Vec<_> = pair
            .b
            .prober
            .peers
            .get(&pair.a.id)
            .and_then(|p| p.paths.as_ref())
            .expect("paths")
            .candidate_views(pair.now)
            .into_iter()
            .map(|v| (v.route.endpoint(), v.state))
            .collect();
        assert!(
            states.contains(&(blocked, crate::path::CandidateState::Blocked)),
            "{states:?}"
        );

        pair.reconfigure_b(vec![pair.b_relay(1)]);
        assert_eq!(
            pair.b.prober.take_blocked_change(),
            Some(&BTreeSet::new()),
            "the record ends with the endpoint"
        );
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

    /// The follower carries out the decider's proposal through the Hub in the same tick as it finds
    /// the path it leaves broken: that outage is of a path the pair no longer uses, and the follower
    /// stays on the new one instead of waiting for another proposal and then rotating on its own
    /// (design/mesh.md section 8.4). Whatever the Hub's delay within the decider's 3 sends a second
    /// apart, the pair moves once, together.
    #[test]
    fn a_proposal_carried_out_with_an_outage_of_the_path_left_is_not_undone() {
        for (lag_ms, delay_ms) in (0..1000)
            .step_by(100)
            .flat_map(|lag| (0..=1000).step_by(100).map(move |delay| (lag, delay)))
        {
            let mut pair = Pair::new();
            pair.hub = true;
            pair.hub_delay = Duration::from_millis(delay_ms);
            pair.b_from = pair.now + Duration::from_millis(lag_ms);
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
            pair.run(Duration::from_secs(20));
            let after: Vec<(bool, SwitchReason)> = pair
                .switches
                .iter()
                .filter(|(t, _, _)| *t > down)
                .map(|(_, from_a, s)| (*from_a, s.reason))
                .collect();
            let (a, b) = pair.endpoints();
            assert_eq!(
                a, b,
                "B {lag_ms} ms behind, Hub delay {delay_ms} ms: {after:?}"
            );
            assert!(
                !after.iter().any(|(_, r)| *r == SwitchReason::Rotation),
                "B {lag_ms} ms behind, Hub delay {delay_ms} ms: {after:?}"
            );
        }
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
