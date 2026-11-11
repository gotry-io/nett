//! Lands the admitted members on the data plane: this machine's mesh interface, and one WireGuard peer for
//! each other member; switches peers' endpoints according to the result of path selection, and corrects
//! endpoints changed by WireGuard roaming (design/mesh.md sections 4 and 8).
//!
//! When a data plane operation fails the current state is kept and retried on the next desired state or
//! the next check ("when unsure, connections stay as they are"). Access control is the exception:
//! filter rules are installed before peers are added, and installation failure rejects (hard rule 6).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_core::transport::{CertFingerprint, TransportConfig};
use nett_trust::admission::Member;
use nett_trust::encoding::Timestamp;
use nett_trust::keys::X25519PublicKey;

use crate::access::{AccessRules, EdgeSpec, FilterSpec, IngressSpec};
use crate::config::{DesiredMesh, Reachability};
use crate::dataplane::{
    DataPlane, INTERFACE_NAME, InterfaceAddress, InterfaceSpec, MESH_MTU, PeerSpec,
};
use crate::event::{Event, EventSink};
use crate::helper::{AssignedMember, RelayAssignment};
use crate::key::PrivateKey;
use crate::members::{MemberSet, OwnPolicy};
use crate::path::{CandidateState, PathKind, Role, Route};
use crate::probe::{KeyId, NatType};
use crate::prober::{ACTIVE_WINDOW, Incoming, Outgoing, Prober};
use crate::routes::Routes;
use crate::status::{
    self, CandidateStateDoc, CandidateStatus, ConfigStatus, NatKind, NatStatus, NodeRef,
    NodeStatus, PathKindDoc, PathStatus, PeerRole, PeerState, PeerStatus, RelayStatus, StatusDoc,
};
use crate::store::{Saved, TrustStore};
use nett_core::prefix::IpPrefix;

/// Persistent keepalive interval (seconds) of `dial-only` members for each peer, keeping the NAT mapping
/// alive (design/mesh.md section 4).
pub const DIAL_ONLY_KEEPALIVE_SECS: u16 = 25;
/// Interval for reading each peer's state (traffic, endpoint): after an endpoint is changed by roaming it
/// is corrected within this time (section 8.3).
const STATS_INTERVAL: Duration = Duration::from_millis(100);

/// The mesh interface that is already ready.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// The interface configuration most recently applied successfully.
    pub spec: InterfaceSpec,
    /// The port WireGuard actually listens on: when the desired state has no port, the system assigns one
    /// (design/mesh.md section 5.5).
    pub listen_port: u16,
}

pub struct Engine<D> {
    node_id: NodeId,
    private_key: PrivateKey,
    dataplane: D,
    members: MemberSet,
    interface: Option<Interface>,
    /// The configuration most recently handed to the transport adapter.
    transport: Option<TransportConfig>,
    /// The assignment of the relay on this machine (design/mesh.md section 5.2), and the fingerprint and
    /// time nett-relay reported when it last fetched it.
    relay: Option<RelayAssignment>,
    relay_fetched: Option<(Option<CertFingerprint>, Instant)>,
    /// nett-node's Hub session is up, as nett-node last reported.
    hub: bool,
    reachability: Reachability,
    prober: Option<Prober>,
    /// Peers already configured on the data plane: the side that follows through roaming sets the endpoint
    /// only when adding a peer, and afterwards leaves it to WireGuard's roaming.
    configured: HashSet<X25519PublicKey>,
    traffic: HashMap<X25519PublicKey, Traffic>,
    /// The time of the most recent re-handshake execution (Unix milliseconds): a handshake time reported by
    /// WireGuard that is not earlier than it is the completion of this handshake (section 8.4). Between
    /// deciding and executing, what is read is still the old peer's handshake time.
    rehandshaked_at: HashMap<X25519PublicKey, u64>,
    last_stats: Option<Instant>,
    clock_trusted: bool,
    /// Loopback endpoints of TLS relays on the transport adapter, and the idle ports most recently set
    /// (design/mesh.md section 5.3).
    tls_endpoints: BTreeSet<SocketAddr>,
    tls_guarded: Option<Vec<u16>>,
    access: AccessRules,
    routes: Routes,
    /// Filter rules, Edge settings, smart gateway forwarding rules, and routes for other members' prefixes
    /// already installed on the data plane.
    filter: Option<FilterSpec>,
    edge: Option<Option<EdgeSpec>>,
    ingress: Option<Option<IngressSpec>>,
    installed_routes: Option<Vec<IpPrefix>>,
    /// Node names in the most recently accepted desired state, and the time of acceptance (local status,
    /// design/status.md sections 5 and 6).
    names: BTreeMap<NodeId, NodeName>,
    applied_at: Option<Instant>,
    /// Loopback ports of TLS relays on the transport adapter -> the relay's TLS address: local status shows
    /// the latter.
    tls_relays: BTreeMap<SocketAddr, SocketAddr>,
    /// This machine's trust store: the pinned trust anchors and the versions in effect for each artifact
    /// (design/mesh.md section 4.2).
    trust: TrustStore,
}

/// The traffic of a peer as read from the data plane, and the time its sent and received byte counts last
/// changed.
#[derive(Debug, Clone, Default)]
struct Traffic {
    rx_bytes: u64,
    tx_bytes: u64,
    last_rx: Option<Instant>,
    last_tx: Option<Instant>,
    endpoint: Option<SocketAddr>,
    last_handshake: Option<SystemTime>,
}

impl<D: DataPlane> Engine<D> {
    pub fn new(node_id: NodeId, private_key: PrivateKey, dataplane: D) -> Self {
        Self {
            node_id,
            private_key,
            dataplane,
            members: MemberSet::default(),
            interface: None,
            transport: None,
            relay: None,
            relay_fetched: None,
            hub: false,
            reachability: Reachability::Public,
            prober: None,
            configured: HashSet::new(),
            traffic: HashMap::new(),
            rehandshaked_at: HashMap::new(),
            last_stats: None,
            clock_trusted: false,
            tls_endpoints: BTreeSet::new(),
            tls_guarded: None,
            access: AccessRules::default(),
            routes: Routes::default(),
            filter: None,
            edge: None,
            ingress: None,
            installed_routes: None,
            names: BTreeMap::new(),
            applied_at: None,
            tls_relays: BTreeMap::new(),
            trust: TrustStore::in_memory(),
        }
    }

    /// Takes this trust store as the verification baseline: restores revocations and the versions previously
    /// accepted for each artifact.
    pub fn with_trust_store(mut self, trust: TrustStore) -> Self {
        if let Some(saved) = trust.saved() {
            self.members.restore(&saved.revoked, &saved.members);
            self.access.restore(saved.access_rules);
            self.routes.restore(&saved.routes);
        }
        self.trust = trust;
        self
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Node names in the most recently accepted desired state.
    pub fn names(&self) -> &BTreeMap<NodeId, NodeName> {
        &self.names
    }

    pub fn members(&self) -> &MemberSet {
        &self.members
    }

    /// Opens the sockets used for probing through the data plane at runtime ([`DataPlane::direct_probes`],
    /// [`DataPlane::bind_tunnel`]).
    pub fn dataplane_mut(&mut self) -> &mut D {
        &mut self.dataplane
    }

    /// The mesh interface is ready (probe sockets can bind to the mesh address).
    pub fn interface(&self) -> Option<&Interface> {
        self.interface.as_ref()
    }

    /// Applies a desired state. When the whole is rejected (not meant for this machine, or the trust anchors
    /// differ from the ones pinned on this machine) returns the reason and keeps using the state already
    /// in effect; after the whole is accepted it is written to the trust store.
    pub fn apply(
        &mut self,
        desired: &DesiredMesh,
        events: &mut impl EventSink,
    ) -> Result<(), String> {
        if let Some(problem) = self.trust.take_problem() {
            events.emit(Event::TrustStoreFailed { reason: problem });
        }
        let rejected = if desired.node_id != self.node_id {
            Some(format!(
                "desired state is for {}, this node is {}",
                desired.node_id, self.node_id
            ))
        } else {
            self.trust
                .saved()
                .filter(|saved| saved.trust_anchors != desired.trust_anchors)
                .map(|saved| {
                    format!(
                        "its trust anchors (version {}) differ from the ones this node pinned (version {}); \
                         trust anchors change only through an update signed by the pinned ones, or after \
                         this node leaves the network",
                        desired.trust_anchors.version, saved.trust_anchors.version
                    )
                })
        };
        if let Some(reason) = rejected {
            events.emit(Event::ConfigRejected {
                reason: reason.clone(),
            });
            return Err(reason);
        }
        // When the trust store has just been created (the first desired state), the expiry of this machine's
        // node policy is not checked (design/mesh.md section 4.2)
        let now = self.trust.saved().is_some().then(Timestamp::now);
        self.apply_accepted(desired, now, events);
        self.save_trust(desired, events);
        Ok(())
    }

    /// The whole desired state file was rejected at startup: uses the last whole desired state accepted in the
    /// trust store instead. Returns `false` when there is none.
    pub fn apply_saved(&mut self, events: &mut impl EventSink) -> bool {
        let doc = match self.trust.accepted() {
            Ok(Some(doc)) => doc,
            Ok(None) => return false,
            Err(reason) => {
                events.emit(Event::TrustStoreFailed { reason });
                return false;
            }
        };
        match DesiredMesh::from_doc(doc) {
            Ok(desired) => {
                events.emit(Event::AcceptedStateRestored);
                self.apply(&desired, events).is_ok()
            }
            Err(e) => {
                events.emit(Event::TrustStoreFailed {
                    reason: format!("the saved desired state is not valid: {e}"),
                });
                false
            }
        }
    }

    fn save_trust(&mut self, desired: &DesiredMesh, events: &mut impl EventSink) {
        let revoked = self.members.revoked().clone();
        let saved = Saved {
            members: self.members.saved_versions(),
            access_rules: self.access.saved_version(),
            routes: self.routes.saved_versions(&revoked),
            revoked,
            ..Saved::new(self.node_id.clone(), desired.trust_anchors.clone())
        };
        match self.trust.save(saved, desired.doc()) {
            Ok(()) => events.emit(Event::TrustStoreSaved),
            Err(reason) => events.emit(Event::TrustStoreFailed { reason }),
        }
    }

    fn apply_accepted(
        &mut self,
        desired: &DesiredMesh,
        now: Option<Timestamp>,
        events: &mut impl EventSink,
    ) {
        self.names = desired.names.clone();
        self.applied_at = Some(Instant::now());
        self.tls_relays = desired
            .tls_targets()
            .iter()
            .map(|t| (t.listen, t.connect))
            .collect();
        let own = OwnPolicy {
            node_id: &self.node_id,
            now,
        };
        self.members.apply(desired, &own, events);
        self.routes.apply(desired, self.members.members(), events);

        let Some(me) = self.members.get(&self.node_id) else {
            events.emit(Event::SelfNotAdmitted {
                node_id: self.node_id.clone(),
            });
            // This machine has been revoked: no communication with any peer
            if self.interface.is_some() {
                self.sync_peers(Vec::new(), events);
                self.sync_routes(Vec::new(), events);
            }
            self.prober = None;
            return;
        };

        let spec = interface_spec(me, desired);
        if self.interface.as_ref().map(|i| &i.spec) != Some(&spec) {
            match self.dataplane.ensure_interface(&spec, &self.private_key) {
                Ok(state) if state.public_key == me.mesh_public_key => {
                    if self.interface.as_ref().map(|i| i.listen_port) != Some(state.listen_port) {
                        events.emit(Event::InterfaceReady {
                            listen_port: state.listen_port,
                        });
                    }
                    self.interface = Some(Interface {
                        spec,
                        listen_port: state.listen_port,
                    });
                }
                Ok(state) => {
                    events.emit(Event::DataPlaneFailed {
                        reason: format!(
                            "interface public key {} does not match this node's admitted mesh key {}",
                            state.public_key, me.mesh_public_key
                        ),
                    });
                    return;
                }
                Err(e) => {
                    events.emit(Event::DataPlaneFailed {
                        reason: e.to_string(),
                    });
                    return;
                }
            }
        }

        let own_key = me.mesh_public_key;
        let edge = EdgeSpec::of(me);
        self.update_transport(desired, events);
        self.update_relay(desired, events);
        if !self.apply_access(desired, edge, events) {
            // Access control cannot be installed: no communication with any peer
            self.sync_peers(Vec::new(), events);
            return;
        }
        self.apply_ingress(events);

        self.reachability = desired.reachability;
        let (trusted, hub) = (self.clock_trusted, self.hub);
        let prober = self.prober.get_or_insert_with(|| {
            let mut prober = Prober::new(&own_key);
            prober.set_clock_trusted(trusted);
            prober.set_hub(hub);
            prober
        });
        prober.update(
            &self.node_id,
            desired.reachability,
            &self.private_key,
            self.members.members(),
            &desired.paths,
            desired.tls_endpoints(),
        );
        self.tls_endpoints = desired.tls_endpoints().values().copied().collect();
        let peers: Vec<PeerSpec> = self
            .members
            .members()
            .values()
            .filter(|m| m.node_id != self.node_id)
            .map(|m| {
                // The side with path selection state always writes the intended endpoint; the side that follows through
                // roaming writes it only when adding a peer
                let endpoint = prober.desired_endpoint(&m.node_id).or_else(|| {
                    (!self.configured.contains(&m.mesh_public_key))
                        .then(|| prober.endpoint(&m.node_id))
                        .flatten()
                });
                peer_spec(
                    m,
                    self.routes.of(&m.node_id),
                    desired.reachability,
                    endpoint,
                )
            })
            .collect();
        self.sync_peers(peers, events);
        let others: Vec<IpPrefix> = self.routes.of_others(&self.node_id).collect();
        self.sync_routes(others, events);
        self.guard_idle_tls(events);
    }

    /// When this machine advertises prefixes, installs the smart gateway forwarding rules (design/mesh.md
    /// section 10). On failure, retried on the next desired state.
    fn apply_ingress(&mut self, events: &mut impl EventSink) {
        let ingress = IngressSpec::of(self.routes.of(&self.node_id), self.members.members());
        if self.ingress.as_ref() == Some(&ingress) {
            return;
        }
        match self.dataplane.apply_ingress(ingress.as_ref()) {
            Ok(()) => self.ingress = Some(ingress),
            Err(e) => {
                self.ingress = None;
                events.emit(Event::DataPlaneFailed {
                    reason: e.to_string(),
                });
            }
        }
    }

    /// Prefixes advertised by other members: adds routes on the mesh interface. On failure, retried on the
    /// next desired state.
    fn sync_routes(&mut self, routes: Vec<IpPrefix>, events: &mut impl EventSink) {
        if self.installed_routes.as_ref() == Some(&routes) {
            return;
        }
        match self.dataplane.sync_routes(&routes) {
            Ok(()) => self.installed_routes = Some(routes),
            Err(e) => {
                self.installed_routes = None;
                events.emit(Event::DataPlaneFailed {
                    reason: e.to_string(),
                });
            }
        }
    }

    /// Verifies the rule set and installs this machine's filter rules and Edge settings (design/mesh.md
    /// section 12, ADR 0015). When the rules cannot be expanded or fail to install, installs rules that
    /// reject all new inbound connections instead; returns `false` when even that cannot be installed or
    /// the Edge settings fail, and the caller adds no peers.
    fn apply_access(
        &mut self,
        desired: &DesiredMesh,
        edge: Option<EdgeSpec>,
        events: &mut impl EventSink,
    ) -> bool {
        self.access.apply(desired, events);
        if self.edge.as_ref() != Some(&edge) {
            match self.dataplane.apply_edge(edge.as_ref()) {
                Ok(()) => self.edge = Some(edge),
                Err(e) => {
                    self.edge = None;
                    events.emit(Event::DataPlaneFailed {
                        reason: e.to_string(),
                    });
                    return false;
                }
            }
        }
        let filter = self
            .access
            .filter(&self.node_id, self.members.members())
            .unwrap_or_else(|e| {
                events.emit(Event::AccessRulesRejected {
                    reason: e.to_string(),
                });
                FilterSpec::deny_all()
            });
        if self.filter.as_ref() == Some(&filter) {
            return true;
        }
        match self.dataplane.apply_filter(&filter) {
            Ok(()) => {
                self.filter = Some(filter);
                return true;
            }
            Err(e) => events.emit(Event::DataPlaneFailed {
                reason: e.to_string(),
            }),
        }
        let deny = FilterSpec::deny_all();
        match self.dataplane.apply_filter(&deny) {
            Ok(()) => {
                self.filter = Some(deny);
                true
            }
            Err(e) => {
                self.filter = None;
                events.emit(Event::DataPlaneFailed {
                    reason: e.to_string(),
                });
                false
            }
        }
    }

    /// Configuration of the transport adapter (design/mesh.md section 5.3): TLS targets and the actual
    /// WireGuard port, handed out when changed. Called before peers are configured: when packets that
    /// WireGuard sends to the loopback port arrive, the transport adapter is already listening.
    fn update_transport(&mut self, desired: &DesiredMesh, events: &mut impl EventSink) {
        let Some(interface) = &self.interface else {
            return;
        };
        let config = desired.transport(interface.listen_port);
        if self.transport.as_ref() != Some(&config) {
            events.emit(Event::TransportConfigChanged {
                config: config.clone(),
            });
            self.transport = Some(config);
        }
    }

    /// The relay assignment for nett-relay (design/mesh.md section 5.2): members resolved to their mesh
    /// public keys from the verified admission material; members that are not admitted are left out with
    /// their links, so the relay forwards only between admitted members (hard rule 4).
    fn update_relay(&mut self, desired: &DesiredMesh, events: &mut impl EventSink) {
        let assignment = desired.relay.as_ref().map(|doc| {
            let key = |id: &NodeId| self.members.get(id).map(|m| m.mesh_public_key);
            RelayAssignment {
                port: doc.port,
                tls_port: doc.tls_port,
                members: doc
                    .members
                    .iter()
                    .filter_map(|m| {
                        Some(AssignedMember {
                            public_key: key(&m.node)?,
                            address: m.address,
                            token: m.token.clone(),
                        })
                    })
                    .collect(),
                links: doc
                    .links
                    .iter()
                    .filter_map(|[a, b]| Some([key(a)?, key(b)?]))
                    .collect(),
            }
        });
        if assignment != self.relay {
            events.emit(Event::RelayAssignmentChanged {
                members: assignment.as_ref().map_or(0, |a| a.members.len()),
                links: assignment.as_ref().map_or(0, |a| a.links.len()),
            });
            if assignment.is_none() {
                self.relay_fetched = None;
            }
            self.relay = assignment;
        }
    }

    /// nett-relay fetches its assignment, reporting the fingerprint of its TLS certificate.
    pub fn relay_assignment(
        &mut self,
        fingerprint: Option<CertFingerprint>,
        now: Instant,
    ) -> Option<RelayAssignment> {
        if self.relay.is_some() {
            self.relay_fetched = Some((fingerprint, now));
        }
        self.relay.clone()
    }

    /// The transport adapter fetches its configuration.
    pub fn transport_config(&self) -> Option<TransportConfig> {
        self.transport.clone()
    }

    /// nett-node reports whether its Hub session is up (design/status.md section 4.2).
    pub fn set_hub(&mut self, up: bool) {
        self.hub = up;
        if let Some(prober) = self.prober.as_mut() {
            prober.set_hub(up);
        }
    }

    /// A switch message from a peer, relayed through the Hub (design/mesh.md section 8.4).
    pub fn on_hub_message(
        &mut self,
        peer: &NodeId,
        data: &[u8],
        at: Instant,
        now_ms: u64,
    ) -> Vec<Outgoing> {
        match self.prober.as_mut() {
            Some(prober) => prober.on_hub_message(peer, data, at, now_ms),
            None => Vec::new(),
        }
    }

    /// TLS loopback ports that no peer is using: drops packets entering the WireGuard port from them
    /// (design/mesh.md section 5.3). Called before performing switches: the port switched to TLS is opened
    /// first, and the port switched away from is blocked afterwards. On failure, retried on the next
    /// advance.
    fn guard_idle_tls(&mut self, events: &mut impl EventSink) {
        let (Some(prober), Some(interface)) = (self.prober.as_ref(), self.interface.as_ref())
        else {
            return;
        };
        let in_use: BTreeSet<SocketAddr> = prober
            .peer_ids()
            .filter_map(|(id, _)| prober.endpoint(id))
            .collect();
        let idle: Vec<u16> = self
            .tls_endpoints
            .difference(&in_use)
            .map(SocketAddr::port)
            .collect();
        if self.tls_guarded.as_ref() == Some(&idle)
            || (self.tls_guarded.is_none() && self.tls_endpoints.is_empty())
        {
            return;
        }
        match self.dataplane.guard_tls_ports(interface.listen_port, &idle) {
            Ok(()) => self.tls_guarded = Some(idle),
            Err(e) => {
                self.tls_guarded = None;
                events.emit(Event::DataPlaneFailed {
                    reason: e.to_string(),
                });
            }
        }
    }

    fn sync_peers(&mut self, peers: Vec<PeerSpec>, events: &mut impl EventSink) {
        match self.dataplane.sync_peers(&peers) {
            Ok(()) => {
                events.emit(Event::PeersApplied { peers: peers.len() });
                self.configured = peers.iter().map(|p| p.public_key).collect();
            }
            Err(e) => events.emit(Event::DataPlaneFailed {
                reason: e.to_string(),
            }),
        }
    }

    /// A peer is probing at high frequency the better path it just switched away from because of a failure
    /// (design/mesh.md section 7), or is waiting for a re-handshake to complete (section 8.4): the runtime
    /// must advance more densely than [`crate::path::FAST_RECOVERY_INTERVAL`].
    pub fn needs_fine_ticks(&self, now: Instant) -> bool {
        self.prober
            .as_ref()
            .is_some_and(|p| p.needs_fine_ticks(now))
    }

    /// Whether the local clock error is within 2 seconds (design/mesh.md section 8.4), updated periodically
    /// by the runtime.
    pub fn set_clock_trusted(&mut self, trusted: bool) {
        self.clock_trusted = trusted;
        if let Some(prober) = self.prober.as_mut() {
            prober.set_clock_trusted(trusted);
        }
    }

    /// Called periodically (about every 100 ms): reads peer state, corrects endpoints, advances path
    /// selection, and returns the probes to send.
    pub fn tick(
        &mut self,
        now: Instant,
        now_ms: u64,
        events: &mut impl EventSink,
    ) -> Vec<Outgoing> {
        if self.interface.is_none() {
            return Vec::new();
        }
        // Also read when a re-handshake's confirmation is due: decide whether to re-handshake again based on
        // the handshake state just read
        let handshake_due = self.prober.as_ref().is_some_and(|p| p.handshake_due(now));
        if handshake_due
            || self
                .last_stats
                .is_none_or(|t| now.saturating_duration_since(t) >= STATS_INTERVAL)
        {
            self.last_stats = Some(now);
            self.check_peers(now, events);
        }
        let Some(prober) = self.prober.as_mut() else {
            return Vec::new();
        };
        let (out, switches) = prober.tick(now, now_ms);
        for event in prober.take_events() {
            events.emit(event);
        }
        self.guard_idle_tls(events);
        for switch in switches {
            let result = if switch.rehandshake {
                match self.members.get(&switch.peer) {
                    Some(member) => {
                        let spec = peer_spec(
                            member,
                            self.routes.of(&switch.peer),
                            self.reachability,
                            Some(switch.to.endpoint()),
                        );
                        let result = self.dataplane.rehandshake(&spec);
                        if result.is_ok() {
                            self.rehandshaked_at.insert(switch.public_key, now_ms);
                        }
                        result
                    }
                    None => continue,
                }
            } else {
                self.dataplane
                    .set_endpoint(&switch.public_key, switch.to.endpoint())
            };
            match result {
                Ok(()) => events.emit(Event::PathSwitched {
                    node_id: switch.peer,
                    to: route_label(&switch.to),
                    reason: switch.reason,
                    rehandshake: switch.rehandshake,
                }),
                Err(e) => events.emit(Event::DataPlaneFailed {
                    reason: e.to_string(),
                }),
            }
        }
        out
    }

    /// Reads each peer's traffic and endpoint: peers with traffic are probed at the frequency of section 7;
    /// when the decider finds the endpoint changed by roaming it changes it back (section 8.3).
    fn check_peers(&mut self, now: Instant, events: &mut impl EventSink) {
        let Some(prober) = self.prober.as_mut() else {
            return;
        };
        let stats = match self.dataplane.peer_stats() {
            Ok(stats) => stats,
            Err(e) => {
                events.emit(Event::DataPlaneFailed {
                    reason: e.to_string(),
                });
                return;
            }
        };
        let by_key: HashMap<X25519PublicKey, NodeId> = prober
            .peer_ids()
            .map(|(id, key)| (*key, id.clone()))
            .collect();
        self.rehandshaked_at
            .retain(|key, _| stats.iter().any(|s| s.public_key == *key));
        self.traffic
            .retain(|key, _| stats.iter().any(|s| s.public_key == *key));
        for stat in stats {
            let Some(id) = by_key.get(&stat.public_key) else {
                continue;
            };
            let bytes = (stat.rx_bytes, stat.tx_bytes);
            let before = self
                .traffic
                .get(&stat.public_key)
                .map(|t| (t.rx_bytes, t.tx_bytes));
            let traffic = self.traffic.entry(stat.public_key).or_default();
            if before.is_some_and(|(rx, _)| rx != stat.rx_bytes) {
                traffic.last_rx = Some(now);
            }
            if before.is_some_and(|(_, tx)| tx != stat.tx_bytes) {
                traffic.last_tx = Some(now);
            }
            traffic.rx_bytes = stat.rx_bytes;
            traffic.tx_bytes = stat.tx_bytes;
            traffic.endpoint = stat.endpoint;
            traffic.last_handshake = stat.last_handshake;
            if before != Some(bytes) {
                prober.mark_active(id, now);
            }
            if before.is_some_and(|(rx, _)| rx != stat.rx_bytes) {
                prober.on_receive(id, now);
            }
            if handshake_since(
                stat.last_handshake,
                self.rehandshaked_at.get(&stat.public_key).copied(),
            ) {
                prober.on_handshake(id);
            }
            let Some(want) = prober.desired_endpoint(id) else {
                continue;
            };
            if stat.endpoint != Some(want) {
                match self.dataplane.set_endpoint(&stat.public_key, want) {
                    Ok(()) => events.emit(Event::EndpointCorrected {
                        node_id: id.clone(),
                        from: stat.endpoint,
                        to: want,
                    }),
                    Err(e) => events.emit(Event::DataPlaneFailed {
                        reason: e.to_string(),
                    }),
                }
            }
        }
    }

    /// Snapshot of local status (design/status.md section 6). `now` and `wall` are the same moment. Problems,
    /// recent events, and the time and reason of switches are filled in by
    /// [`crate::status::Recorder::fill`].
    pub fn status(&self, now: Instant, wall: SystemTime, started_at: Timestamp) -> StatusDoc {
        let relays: HashMap<KeyId, &NodeId> = self
            .members
            .members()
            .keys()
            .map(|id| (KeyId::of(id.as_str().as_bytes()), id))
            .collect();
        let node_ref = |key: &KeyId| {
            relays.get(key).map(|id| NodeRef {
                id: (*id).clone(),
                name: self.names.get(*id).cloned(),
            })
        };
        let path_status = |route: Route, kind: PathKind, punched: bool| PathStatus {
            kind: kind_doc(kind),
            relay: match &route {
                Route::Relay { relay, .. } => node_ref(relay),
                Route::Direct(_) => None,
            },
            endpoint: Some(self.shown_endpoint(&route, kind)),
            punched,
            since: None,
            reason: None,
        };
        let me = self.members.get(&self.node_id);
        let node = NodeStatus {
            id: self.node_id.clone(),
            name: self.names.get(&self.node_id).cloned(),
            admitted: me.is_some(),
            mesh: me.map(mesh_addrs).unwrap_or_default(),
            edge: me.map(edge_addrs).unwrap_or_default(),
            routes: self.routes.of(&self.node_id).to_vec(),
            reachability: self.reachability,
            dataplane: self.dataplane.kind(),
            listen_port: self.interface.as_ref().map(|i| i.listen_port),
            nat: self
                .prober
                .as_ref()
                .filter(|_| self.reachability == Reachability::DialOnly)
                .map(|p| {
                    let own = p.own_nat(now);
                    NatStatus {
                        kind: match own.nat {
                            NatType::Cone => NatKind::Cone,
                            NatType::Symmetric => NatKind::Symmetric,
                            NatType::Unknown => NatKind::Unknown,
                        },
                        ipv4: own.v4.map(SocketAddr::V4),
                        ipv6: own.v6.map(SocketAddr::V6),
                    }
                }),
            clock_trusted: self.clock_trusted,
            started_at,
        };
        let recent = |t: Option<Instant>| {
            t.is_some_and(|t| now.saturating_duration_since(t) < ACTIVE_WINDOW)
        };
        let peers = self
            .members
            .members()
            .values()
            .filter(|m| m.node_id != self.node_id)
            .map(|m| {
                let view = self
                    .prober
                    .as_ref()
                    .and_then(|p| p.peer_view(&m.node_id, now));
                let traffic = self.traffic.get(&m.mesh_public_key);
                let last_rx = traffic.and_then(|t| t.last_rx);
                let ever_received = last_rx.is_some()
                    || traffic.is_some_and(|t| t.rx_bytes > 0 || t.last_handshake.is_some());
                let linked = view.as_ref().is_some_and(|v| v.linked);
                let state = if recent(last_rx) {
                    PeerState::Connected
                } else if !linked {
                    PeerState::NoPath
                } else if recent(traffic.and_then(|t| t.last_tx)) {
                    if ever_received {
                        PeerState::Unreachable
                    } else {
                        PeerState::Connecting
                    }
                } else {
                    PeerState::Idle
                };
                let role = linked.then(|| match view.as_ref().and_then(|v| v.role) {
                    Some(Role::Decide | Role::DecideTogether) => PeerRole::Decider,
                    Some(Role::FollowTogether) | None => PeerRole::Follower,
                });
                let candidates = view.as_ref().map(|v| &v.candidates[..]).unwrap_or_default();
                let path = match candidates
                    .iter()
                    .find(|c| c.state == CandidateState::Current)
                {
                    Some(c) => Some(path_status(c.route, c.kind, c.punched)),
                    // Following through roaming: which of this machine's candidates WireGuard's current endpoint is; when
                    // it is not among them, it is direct
                    None => traffic.and_then(|t| t.endpoint).map(|endpoint| {
                        let (route, kind) = view
                            .as_ref()
                            .and_then(|v| v.routes.iter().find(|(r, _)| r.endpoint() == endpoint))
                            .copied()
                            .unwrap_or((Route::Direct(endpoint), PathKind::Direct));
                        path_status(route, kind, false)
                    }),
                };
                let tunnel = view.as_ref().and_then(|v| v.tunnel);
                PeerStatus {
                    id: m.node_id.clone(),
                    name: self.names.get(&m.node_id).cloned(),
                    mesh: mesh_addrs(m),
                    edge: edge_addrs(m),
                    routes: self.routes.of(&m.node_id).to_vec(),
                    state,
                    role,
                    path,
                    rtt_ms: tunnel.and_then(|t| t.rtt_ms),
                    loss: tunnel.and_then(|t| t.loss),
                    jitter_ms: tunnel.and_then(|t| t.rtt_ms.map(|_| t.jitter_ms)),
                    last_handshake: traffic
                        .and_then(|t| t.last_handshake)
                        .map(status::timestamp),
                    last_received: last_rx.map(|t| status::wall_time(now, wall, t)),
                    rx_bytes: traffic.map_or(0, |t| t.rx_bytes),
                    tx_bytes: traffic.map_or(0, |t| t.tx_bytes),
                    candidates: candidates
                        .iter()
                        .map(|c| CandidateStatus {
                            kind: kind_doc(c.kind),
                            relay: match &c.route {
                                Route::Relay { relay, .. } => node_ref(relay),
                                Route::Direct(_) => None,
                            },
                            endpoint: self.shown_endpoint(&c.route, c.kind),
                            punched: c.punched,
                            rtt_ms: c.rtt_ms,
                            loss: c.loss,
                            state: match c.state {
                                CandidateState::Current => CandidateStateDoc::Current,
                                CandidateState::Ok => CandidateStateDoc::Ok,
                                CandidateState::Failing => CandidateStateDoc::Failing,
                                CandidateState::Untested => CandidateStateDoc::Untested,
                            },
                        })
                        .collect(),
                }
            })
            .collect();
        let relay = self.relay.as_ref().map(|a| RelayStatus {
            port: a.port,
            tls_port: a.tls_port,
            members: a.members.len(),
            links: a.links.len(),
            fingerprint: self.relay_fetched.and_then(|(f, _)| f),
            fetched_at: self
                .relay_fetched
                .map(|(_, at)| status::wall_time(now, wall, at)),
        });
        StatusDoc {
            v: status::VERSION,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            node,
            relay,
            config: ConfigStatus {
                applied_at: self.applied_at.map(|t| status::wall_time(now, wall, t)),
                access_rules_version: self.access.version(),
            },
            peers,
            problems: Vec::new(),
            events: Vec::new(),
        }
    }

    /// The address shown in local status: a TLS relay shows its TLS address, not the transport adapter's
    /// loopback port.
    fn shown_endpoint(&self, route: &Route, kind: PathKind) -> SocketAddr {
        let endpoint = route.endpoint();
        match kind {
            PathKind::RelayTls => self.tls_relays.get(&endpoint).copied().unwrap_or(endpoint),
            _ => endpoint,
        }
    }

    /// Handles a received probe message and returns the reply to send.
    pub fn on_packet(
        &mut self,
        kind: Incoming,
        from: SocketAddr,
        data: &[u8],
        at: Instant,
        now_ms: u64,
    ) -> Vec<Outgoing> {
        match self.prober.as_mut() {
            Some(prober) => prober.on_packet(kind, from, data, at, now_ms),
            None => Vec::new(),
        }
    }
}

fn kind_doc(kind: PathKind) -> PathKindDoc {
    match kind {
        PathKind::Lan => PathKindDoc::Lan,
        PathKind::Direct => PathKindDoc::Direct,
        PathKind::Relay => PathKindDoc::Relay,
        PathKind::RelayTls => PathKindDoc::RelayTls,
    }
}

fn mesh_addrs(m: &Member) -> Vec<IpAddr> {
    vec![IpAddr::V4(m.addresses.ipv4), IpAddr::V6(m.addresses.ipv6)]
}

fn edge_addrs(m: &Member) -> Vec<IpAddr> {
    m.edge
        .iter()
        .flat_map(|e| [IpAddr::V4(e.addresses.ipv4), IpAddr::V6(e.addresses.ipv6)])
        .collect()
}

fn route_label(route: &Route) -> String {
    match route {
        Route::Direct(e) => format!("direct {e}"),
        Route::Relay { endpoint, .. } => format!("relay {endpoint}"),
    }
}

fn interface_spec(me: &Member, desired: &DesiredMesh) -> InterfaceSpec {
    InterfaceSpec {
        name: INTERFACE_NAME.to_owned(),
        listen_port: desired.listen_port,
        mtu: MESH_MTU,
        addresses: vec![
            InterfaceAddress {
                addr: IpAddr::V4(me.addresses.ipv4),
                prefix_len: desired.prefixes.ipv4.prefix_len(),
            },
            InterfaceAddress {
                addr: IpAddr::V6(me.addresses.ipv6),
                prefix_len: desired.prefixes.ipv6.prefix_len(),
            },
        ],
    }
}

/// Whether a handshake has completed since the most recent re-handshake (`rehandshaked_ms`, Unix
/// milliseconds). With no re-handshake there is nothing to confirm; a handshake time earlier than the
/// re-handshake belongs to the old peer (state read between deciding and executing).
fn handshake_since(last_handshake: Option<SystemTime>, rehandshaked_ms: Option<u64>) -> bool {
    let done_ms = last_handshake.map(|t| {
        t.duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    });
    matches!((done_ms, rehandshaked_ms), (Some(done), Some(at)) if done >= at)
}

fn peer_spec(
    member: &Member,
    routes: &[IpPrefix],
    own: Reachability,
    endpoint: Option<SocketAddr>,
) -> PeerSpec {
    // The mesh address, the Edge address when there is an `edge` role, and the prefixes it advertises
    // (design/mesh.md section 4)
    let edge = member.edge.iter().map(|e| e.addresses);
    PeerSpec {
        public_key: member.mesh_public_key,
        allowed_ips: std::iter::once(member.addresses)
            .chain(edge)
            .flat_map(|a| [IpAddr::V4(a.ipv4), IpAddr::V6(a.ipv6)])
            .map(IpPrefix::host)
            .chain(routes.iter().copied())
            .collect(),
        endpoint,
        persistent_keepalive: (own == Reachability::DialOnly).then_some(DIAL_ONLY_KEEPALIVE_SECS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::VecSink;
    use crate::store::MemoryBackend;
    use crate::testutil::{FAKE_AUTO_PORT, FakeDataPlane, Mesh, mesh_key, node_id, validated};
    use nett_trust::revocation::Revocation;

    fn engine(me: u8) -> Engine<FakeDataPlane> {
        Engine::new(
            node_id(me),
            PrivateKey::from_bytes([me; 32]),
            FakeDataPlane::new(mesh_key(me)),
        )
    }

    fn peer_keys(e: &Engine<FakeDataPlane>) -> Vec<u8> {
        e.dataplane
            .peers
            .as_ref()
            .expect("peers applied")
            .iter()
            .map(|p| p.public_key.as_bytes()[0])
            .collect()
    }

    fn rejected(events: &VecSink) -> Vec<Option<NodeId>> {
        events
            .0
            .iter()
            .filter_map(|e| match e {
                Event::MemberRejected { node_id, .. } => Some(node_id.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn configures_interface_and_admitted_peers() {
        let mesh = Mesh::new(&[1, 2, 3]);
        let mut e = engine(1);
        let mut events = VecSink::default();
        let doc = mesh.desired(
            1,
            vec![
                mesh.material(1, 1),
                mesh.material(2, 1),
                mesh.material(3, 1),
            ],
        );
        e.apply(&validated(doc), &mut events).expect("accepted");

        let iface = &e.dataplane.interfaces[0];
        assert_eq!(iface.name, "nett0");
        assert_eq!(iface.mtu, 1280);
        assert_eq!(iface.addresses[0].addr.to_string(), "100.88.0.1");
        assert_eq!(iface.addresses[0].prefix_len, 16);
        assert_eq!(iface.addresses[1].prefix_len, 48);

        let peers = e.dataplane.peers.as_ref().expect("peers");
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].public_key, mesh_key(2));
        assert_eq!(
            peers[0].endpoint,
            Some("192.0.2.2:41820".parse().expect("addr"))
        );
        assert_eq!(
            peers[0]
                .allowed_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["100.88.0.2/32", "fd00:88::2/128"]
        );
        assert_eq!(
            peers[0].persistent_keepalive,
            Some(DIAL_ONLY_KEEPALIVE_SECS)
        );
        assert!(events.0.contains(&Event::PeersApplied { peers: 2 }));
    }

    #[test]
    fn without_a_port_the_assigned_one_is_reported_and_handed_to_the_transport() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        let mut doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        doc.listen_port = None;
        let mut events = VecSink::default();
        e.apply(&validated(doc.clone()), &mut events)
            .expect("accepted");
        assert_eq!(e.dataplane.interfaces[0].listen_port, None);
        assert_eq!(e.interface().map(|i| i.listen_port), Some(FAKE_AUTO_PORT));
        assert!(events.0.contains(&Event::InterfaceReady {
            listen_port: FAKE_AUTO_PORT
        }));
        // The transport adapter gets the actual port, and before the peers are configured
        let at = |pred: &dyn Fn(&Event) -> bool| events.0.iter().position(pred);
        let transport = at(
            &|e| matches!(e, Event::TransportConfigChanged { config } if config.wireguard_port == FAKE_AUTO_PORT),
        );
        let peers = at(&|e| matches!(e, Event::PeersApplied { .. }));
        assert!(transport.expect("transport config") < peers.expect("peers"));
        // No further report when nothing has changed
        let mut again = VecSink::default();
        e.apply(&validated(doc), &mut again).expect("accepted");
        assert!(!again.0.iter().any(|e| matches!(
            e,
            Event::InterfaceReady { .. } | Event::TransportConfigChanged { .. }
        )));
    }

    #[test]
    fn access_rules_are_installed_before_peers() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        let doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        e.apply(&validated(doc.clone()), &mut VecSink::default())
            .expect("accepted");
        assert_eq!(
            e.dataplane.calls,
            [
                "apply_edge",
                "apply_filter",
                "apply_ingress",
                "sync_peers",
                "sync_routes"
            ]
        );
        // Packets from member 2 to this machine's in-tunnel probe port are allowed (IPv4, IPv6), with no other
        // rules
        assert_eq!(e.dataplane.filter.as_ref().map(|f| f.rules.len()), Some(2));
        assert_eq!(e.dataplane.edge, None);
        // No reinstall when nothing has changed
        e.apply(&validated(doc), &mut VecSink::default())
            .expect("accepted");
        assert_eq!(
            e.dataplane.calls,
            [
                "apply_edge",
                "apply_filter",
                "apply_ingress",
                "sync_peers",
                "sync_routes",
                "sync_peers"
            ]
        );
    }

    #[test]
    fn failed_filter_falls_back_to_denying_new_inbound_connections() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        e.dataplane.fail_filter = Some(false);
        let mut events = VecSink::default();
        let doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        e.apply(&validated(doc), &mut events).expect("accepted");
        assert_eq!(e.dataplane.filter, Some(FilterSpec::deny_all()));
        assert_eq!(peer_keys(&e), [2]);
        assert!(
            events
                .0
                .iter()
                .any(|ev| matches!(ev, Event::DataPlaneFailed { .. }))
        );
    }

    #[test]
    fn no_peers_when_no_filter_can_be_installed() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        e.dataplane.fail_filter = Some(true);
        let doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        e.apply(&validated(doc), &mut VecSink::default())
            .expect("accepted");
        assert_eq!(e.dataplane.filter, None);
        assert_eq!(e.dataplane.peers, Some(vec![]));
    }

    #[test]
    fn edge_addresses_are_routed_to_the_edge_node_and_rewritten_there() {
        let mesh = Mesh::new(&[1, 2]);
        let members = vec![mesh.edge_material(1, 1), mesh.material(2, 1)];
        let mut edge_node = engine(1);
        edge_node
            .apply(
                &validated(mesh.desired(1, members.clone())),
                &mut VecSink::default(),
            )
            .expect("accepted");
        let edge = edge_node.dataplane.edge.as_ref().expect("edge rules");
        assert_eq!(edge.addresses.ipv4.to_string(), "100.88.1.1");
        assert_eq!(edge.containers[0].to_string(), "172.17.0.0/16");

        let mut other = engine(2);
        other
            .apply(
                &validated(mesh.desired(2, members)),
                &mut VecSink::default(),
            )
            .expect("accepted");
        assert_eq!(other.dataplane.edge, None);
        let peers = other.dataplane.peers.as_ref().expect("peers");
        assert_eq!(
            peers[0]
                .allowed_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            [
                "100.88.0.1/32",
                "fd00:88::1/128",
                "100.88.1.1/32",
                "fd00:88::1:1/128"
            ]
        );
        // A source that is an Edge address with no rule allowing it is rejected: only in-tunnel probes are
        // allowed, and their source is the mesh address
        let edge_source: IpPrefix = "100.88.1.1/32".parse().expect("prefix");
        let filter = other.dataplane.filter.as_ref().expect("filter");
        assert!(!filter.rules.iter().any(|r| {
            r.accept
                && r.matches
                    .iter()
                    .any(|m| matches!(m, crate::access::Match::Source(s) if s.covers(&edge_source)))
        }));
    }

    #[test]
    fn advertised_routes_reach_peers_routes_filter_and_forwarding() {
        let mesh = Mesh::new(&[1, 2, 3]);
        let members = vec![
            mesh.edge_material(1, 1),
            mesh.router_material(2, 1),
            mesh.material(3, 1),
        ];
        let with_routes = |me: u8| {
            let mut d = mesh.desired(me, members.clone());
            d.advertised_routes = vec![mesh.sign(&mesh.routes_doc(2, 1, &["192.0.2.10/32"]))];
            validated(d)
        };
        let route: IpPrefix = "192.0.2.10/32".parse().expect("prefix");
        // Other members: the peer's AllowedIPs and the routes on the mesh interface both have this prefix
        let mut edge = engine(1);
        edge.apply(&with_routes(1), &mut VecSink::default())
            .expect("accepted");
        let peer2 = edge
            .dataplane
            .peers
            .as_ref()
            .and_then(|p| p.iter().find(|p| p.public_key == mesh_key(2)).cloned())
            .expect("peer 2");
        assert!(peer2.allowed_ips.contains(&route));
        assert_eq!(edge.dataplane.routes, [route]);
        assert_eq!(edge.dataplane.ingress, None);

        // The smart gateway itself: forwards the Edge's traffic, rejects when the advertised prefixes have no
        // rules, and adds no route for its own prefixes
        let mut router = engine(2);
        router
            .apply(&with_routes(2), &mut VecSink::default())
            .expect("accepted");
        let ingress = router.dataplane.ingress.as_ref().expect("ingress");
        assert!(
            ingress
                .edge_sources
                .contains(&"100.88.1.1".parse().expect("ip"))
        );
        assert!(router.dataplane.routes.is_empty());
        let filter = router.dataplane.filter.as_ref().expect("filter");
        assert!(!filter.rules.iter().any(|r| {
            r.accept
                && r.matches
                    .iter()
                    .any(|m| matches!(m, crate::access::Match::Destination(d) if d.covers(&route)))
        }));
    }

    #[test]
    fn unchanged_state_does_not_touch_the_interface_again() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        let doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        e.apply(&validated(doc.clone()), &mut VecSink::default())
            .expect("accepted");
        e.apply(&validated(doc), &mut VecSink::default())
            .expect("accepted");
        assert_eq!(e.dataplane.interfaces.len(), 1);
    }

    #[test]
    fn invalid_members_are_not_configured() {
        let mesh = Mesh::new(&[1, 2, 3, 4, 5]);
        let mut e = engine(1);
        let mut events = VecSink::default();

        // 3: the mesh public key in the admission proof does not match the signature; 4: the address is outside
        // the mesh prefixes; 5: the node policy has no mesh module
        let mut bad_proof = mesh.material(3, 1);
        bad_proof.proof.signature[0] ^= 1;
        let mut outside = mesh.policy(4, 1);
        outside.addresses.mesh.ipv4 = "100.99.0.4".parse().expect("ipv4");
        let mut no_mesh = mesh.policy(5, 1);
        no_mesh.modules.clear();
        let members = vec![
            mesh.material(1, 1),
            mesh.material(2, 1),
            bad_proof,
            mesh.material_for(outside, mesh_key(4)),
            mesh.material_for(no_mesh, mesh_key(5)),
        ];
        e.apply(&validated(mesh.desired(1, members)), &mut events)
            .expect("accepted");

        assert_eq!(peer_keys(&e), [2]);
        assert_eq!(
            rejected(&events),
            [Some(node_id(3)), Some(node_id(5)), Some(node_id(4))]
        );
    }

    #[test]
    fn revocation_is_permanent_and_absence_is_not_revocation() {
        let mesh = Mesh::new(&[1, 2, 3]);
        let mut e = engine(1);
        let all = vec![
            mesh.material(1, 1),
            mesh.material(2, 1),
            mesh.material(3, 1),
        ];
        e.apply(&validated(mesh.desired(1, all)), &mut VecSink::default())
            .expect("accepted");
        assert_eq!(peer_keys(&e), [2, 3]);

        // Missing from the snapshot: 3 is not deleted
        let without_3 = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        e.apply(&validated(without_3), &mut VecSink::default())
            .expect("accepted");
        assert_eq!(peer_keys(&e), [2, 3]);

        // Revoke 3: it is deleted; signed material of a higher version afterwards cannot restore it either
        let mut revoke = mesh.desired(1, vec![]);
        revoke.revocations = vec![Revocation::Node {
            node_id: node_id(3),
        }];
        let mut events = VecSink::default();
        e.apply(&validated(revoke), &mut events).expect("accepted");
        assert!(events.0.contains(&Event::MemberRemoved {
            node_id: node_id(3)
        }));
        assert_eq!(peer_keys(&e), [2]);

        let mut events = VecSink::default();
        e.apply(
            &validated(mesh.desired(1, vec![mesh.material(3, 9)])),
            &mut events,
        )
        .expect("accepted");
        assert_eq!(peer_keys(&e), [2]);
        assert_eq!(rejected(&events), [Some(node_id(3))]);
    }

    #[test]
    fn versions_only_move_forward() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        e.apply(
            &validated(mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 2)])),
            &mut VecSink::default(),
        )
        .expect("accepted");
        let mut older = mesh.policy(2, 1);
        older.addresses.mesh.ipv4 = "100.88.0.42".parse().expect("ipv4");
        let mut events = VecSink::default();
        e.apply(
            &validated(mesh.desired(1, vec![mesh.material_for(older, mesh_key(2))])),
            &mut events,
        )
        .expect("accepted");
        assert_eq!(rejected(&events), [Some(node_id(2))]);
        let peers = e.dataplane.peers.as_ref().expect("peers");
        assert_eq!(peers[0].allowed_ips[0].to_string(), "100.88.0.2/32");

        // Two versions of the same node in one desired state: the higher is adopted and the lower is rejected
        let mut e = engine(1);
        let mut events = VecSink::default();
        let both = vec![
            mesh.material(1, 1),
            mesh.material(2, 1),
            mesh.material(2, 3),
        ];
        e.apply(&validated(mesh.desired(1, both)), &mut events)
            .expect("accepted");
        assert_eq!(
            e.members().get(&node_id(2)).map(|m| m.policy_version),
            Some(3)
        );
        assert_eq!(rejected(&events), [Some(node_id(2))]);
    }

    #[test]
    fn conflicting_addresses_and_keys_keep_the_existing_member() {
        let mesh = Mesh::new(&[1, 2, 3, 4]);
        let mut e = engine(1);
        let mut same_addr = mesh.policy(3, 1);
        same_addr.addresses.mesh.ipv6 = "fd00:88::2".parse().expect("ipv6");
        let members = vec![
            mesh.material(1, 1),
            mesh.material(2, 1),
            mesh.material_for(same_addr, mesh_key(3)),
            mesh.material_for(mesh.policy(4, 1), mesh_key(2)),
        ];
        let mut events = VecSink::default();
        e.apply(&validated(mesh.desired(1, members)), &mut events)
            .expect("accepted");
        assert_eq!(peer_keys(&e), [2]);
        assert_eq!(rejected(&events), [Some(node_id(3)), Some(node_id(4))]);
    }

    #[test]
    fn interface_key_must_match_own_admission() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = Engine::new(
            node_id(1),
            PrivateKey::from_bytes([1; 32]),
            FakeDataPlane::new(mesh_key(9)),
        );
        let mut events = VecSink::default();
        e.apply(
            &validated(mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)])),
            &mut events,
        )
        .expect("accepted");
        assert!(e.dataplane.peers.is_none());
        assert!(
            events
                .0
                .iter()
                .any(|e| matches!(e, Event::DataPlaneFailed { .. }))
        );
    }

    #[test]
    fn self_revoked_clears_peers() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        e.apply(
            &validated(mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)])),
            &mut VecSink::default(),
        )
        .expect("accepted");
        let mut revoke = mesh.desired(1, vec![]);
        revoke.revocations = vec![Revocation::Node {
            node_id: node_id(1),
        }];
        let mut events = VecSink::default();
        e.apply(&validated(revoke), &mut events).expect("accepted");
        assert!(events.0.contains(&Event::SelfNotAdmitted {
            node_id: node_id(1)
        }));
        assert_eq!(peer_keys(&e), Vec::<u8>::new());
    }

    #[test]
    fn rejects_state_for_another_node() {
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        let mut events = VecSink::default();
        e.apply(&validated(mesh.desired(2, vec![])), &mut events)
            .expect_err("the state is for another node");
        assert!(matches!(events.0[..], [Event::ConfigRejected { .. }]));
        assert!(e.dataplane.interfaces.is_empty());
    }

    #[test]
    fn only_a_handshake_after_the_rehandshake_confirms_it() {
        let at = |ms: u64| Some(UNIX_EPOCH + Duration::from_millis(ms));
        // No handshake yet after re-joining
        assert!(!handshake_since(None, Some(1_000)));
        // The old peer's handshake read after the decision and before the execution
        assert!(!handshake_since(at(900), Some(1_000)));
        assert!(!handshake_since(at(900), None));
        assert!(handshake_since(at(1_000), Some(1_000)));
        assert!(handshake_since(at(1_030), Some(1_000)));
    }

    #[test]
    fn guards_tls_ports_nobody_uses() {
        use crate::config::{Candidate, PathDoc, ProbeToken};
        use nett_core::transport::CertFingerprint;
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        let mut events = VecSink::default();
        let mut doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        let tls = Candidate::RelayTls {
            relay: node_id(9),
            address: "198.51.100.9:443".parse().expect("addr"),
            fingerprint: CertFingerprint([1; 32]),
            token: ProbeToken([9; 32]),
        };
        let direct = Candidate::Direct {
            endpoint: "192.0.2.2:41820".parse().expect("addr"),
        };
        // The current path is direct: the TLS port is idle, block it
        doc.paths = vec![PathDoc {
            peer: node_id(2),
            peer_reachability: Reachability::Public,
            candidates: vec![direct.clone(), tls.clone()],
        }];
        e.apply(&validated(doc.clone()), &mut events)
            .expect("accepted");
        assert_eq!(
            e.dataplane.tls_guards,
            vec![vec![crate::config::TLS_LOOPBACK_BASE]]
        );
        // Only TLS candidates remain: it is the current path, open it
        doc.paths[0].candidates = vec![tls];
        e.apply(&validated(doc.clone()), &mut events)
            .expect("accepted");
        assert_eq!(e.dataplane.tls_guards.last(), Some(&vec![]));
        // Nodes without TLS candidates set nothing
        let mut plain = engine(1);
        doc.paths[0].candidates = vec![direct];
        plain.apply(&validated(doc), &mut events).expect("accepted");
        assert!(plain.dataplane.tls_guards.is_empty());
    }

    /// Snapshot of local status (design/status.md section 6): node names; peer state changes with traffic; TLS
    /// relays show their real addresses; the reply contains no private key or probe token.
    #[test]
    fn status_reports_peers_paths_and_no_secrets() {
        use crate::config::{Candidate, PathDoc, ProbeToken};
        use crate::status::{PathKindDoc, PeerRole, PeerState};
        use base64::Engine as _;
        use nett_core::transport::CertFingerprint;

        let mesh = Mesh::new(&[1, 2, 3, 4]);
        let mut e = engine(1);
        let mut events = VecSink::default();
        let mut doc = mesh.desired(1, (1..=4).map(|n| mesh.material(n, 1)).collect());
        let token = ProbeToken([9; 32]);
        doc.paths = vec![
            PathDoc {
                peer: node_id(2),
                peer_reachability: Reachability::Public,
                candidates: vec![
                    Candidate::RelayTls {
                        relay: node_id(3),
                        address: "198.51.100.3:443".parse().expect("addr"),
                        fingerprint: CertFingerprint([1; 32]),
                        token: token.clone(),
                    },
                    Candidate::Direct {
                        endpoint: "192.0.2.2:41820".parse().expect("addr"),
                    },
                ],
            },
            PathDoc {
                peer: node_id(3),
                peer_reachability: Reachability::Public,
                candidates: vec![Candidate::Direct {
                    endpoint: "192.0.2.3:41820".parse().expect("addr"),
                }],
            },
        ];
        // Node 4 has no path
        e.apply(&validated(doc), &mut events).expect("accepted");
        let t0 = Instant::now();
        let wall = SystemTime::now();
        e.tick(t0, 0, &mut events);

        let st = e.status(t0, wall, Timestamp::now());
        assert_eq!(st.node.name.as_ref().map(NodeName::as_str), Some("node-1"));
        assert!(st.node.admitted);
        assert_eq!(st.node.mesh[0].to_string(), "100.88.0.1");
        assert_eq!(st.node.listen_port, Some(41820));
        let peer = |st: &StatusDoc, n: u8| {
            st.peers
                .iter()
                .find(|p| p.id == node_id(n))
                .cloned()
                .expect("peer")
        };
        assert_eq!(st.peers.len(), 3);
        // No traffic yet: peers with a path cannot be judged, and peers without a path are stated as such
        assert_eq!(peer(&st, 2).state, PeerState::Idle);
        assert_eq!(peer(&st, 4).state, PeerState::NoPath);
        assert_eq!(peer(&st, 4).role, None);
        // This machine is dial-only: decides the path for the public peer; the TLS relay shows its TLS address
        // and name
        let p2 = peer(&st, 2);
        assert_eq!(p2.role, Some(PeerRole::Decider));
        let path = p2.path.expect("path");
        assert_eq!(path.kind, PathKindDoc::RelayTls);
        assert_eq!(
            path.endpoint,
            Some("198.51.100.3:443".parse().expect("addr"))
        );
        assert_eq!(
            path.relay.and_then(|r| r.name).map(|n| n.to_string()),
            Some("node-3".to_owned())
        );
        assert_eq!(p2.candidates.len(), 2);

        // Packets in both directions: connected; only sent and never received: connecting
        e.dataplane.traffic.insert(mesh_key(2), (100, 100));
        e.dataplane.traffic.insert(mesh_key(3), (0, 100));
        let t1 = t0 + Duration::from_secs(1);
        e.tick(t1, 1_000, &mut events);
        let st = e.status(t1, wall, Timestamp::now());
        assert_eq!(peer(&st, 2).state, PeerState::Connected);
        assert_eq!(peer(&st, 2).rx_bytes, 100);
        assert_eq!(peer(&st, 3).state, PeerState::Connecting);

        // After that, only sent and not received for more than 30 seconds: not working
        let t2 = t1 + Duration::from_secs(31);
        e.dataplane.traffic.insert(mesh_key(2), (100, 200));
        e.tick(t2, 32_000, &mut events);
        assert_eq!(
            e.status(t2, wall, Timestamp::now()).peers[0].state,
            PeerState::Unreachable
        );
        // No packets in either direction for more than 30 seconds: idle
        let t3 = t2 + Duration::from_secs(31);
        e.tick(t3, 63_000, &mut events);
        assert_eq!(
            peer(&e.status(t3, wall, Timestamp::now()), 2).state,
            PeerState::Idle
        );

        let json = serde_json::to_string(&e.status(t3, wall, Timestamp::now())).expect("json");
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        for secret in [b64.encode([9u8; 32]), b64.encode([1u8; 32])] {
            assert!(!json.contains(&secret), "status leaks {secret}");
        }
    }

    /// This machine is public and the peer is dial-only: this machine follows, the path is judged from
    /// WireGuard's current endpoint, and there is no measurement.
    #[test]
    fn a_follower_reports_the_endpoint_without_measurements() {
        use crate::config::PathDoc;
        use crate::status::{PathKindDoc, PeerRole};
        let mesh = Mesh::new(&[1, 2]);
        let mut e = engine(1);
        let mut events = VecSink::default();
        let mut doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        doc.reachability = Reachability::Public;
        doc.paths = vec![PathDoc {
            peer: node_id(2),
            peer_reachability: Reachability::DialOnly,
            candidates: vec![],
        }];
        e.apply(&validated(doc), &mut events).expect("accepted");
        // After the peer connects in, WireGuard records its address
        let roamed: SocketAddr = "203.0.113.7:53557".parse().expect("addr");
        e.dataplane.peers.as_mut().expect("peers")[0].endpoint = Some(roamed);
        let now = Instant::now();
        e.tick(now, 0, &mut events);
        let st = e.status(now, SystemTime::now(), Timestamp::now());
        let p = &st.peers[0];
        assert_eq!(p.role, Some(PeerRole::Follower));
        assert_eq!(p.rtt_ms, None);
        assert!(p.candidates.is_empty());
        let path = p.path.as_ref().expect("path");
        assert_eq!(
            (path.kind, path.endpoint),
            (PathKindDoc::Direct, Some(roamed))
        );
        assert!(st.node.nat.is_none());
    }

    /// An engine that shares the trust store with `backend`: constructing a new one is equivalent to a mesh
    /// process restart.
    fn engine_with(me: u8, backend: &MemoryBackend) -> Engine<FakeDataPlane> {
        engine(me).with_trust_store(TrustStore::open(Box::new(backend.clone())))
    }

    fn version_of(e: &Engine<FakeDataPlane>, n: u8) -> Option<u64> {
        e.members().get(&node_id(n)).map(|m| m.policy_version)
    }

    #[test]
    fn trust_anchors_are_pinned_by_the_first_accepted_state() {
        let mesh = Mesh::new(&[1, 2]);
        let backend = MemoryBackend::default();
        let mut e = engine_with(1, &backend);
        e.apply(
            &validated(mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)])),
            &mut VecSink::default(),
        )
        .expect("accepted");
        // A rewritten desired state: signed by a different recovery key, with an attacker's member 3 added
        let attacker = Mesh::new(&[1, 2, 3]);
        let forged = attacker.desired(
            1,
            vec![
                attacker.material(1, 2),
                attacker.material(2, 2),
                attacker.material(3, 1),
            ],
        );
        let reason = e
            .apply(&validated(forged.clone()), &mut VecSink::default())
            .expect_err("other trust anchors");
        assert!(reason.contains("pinned"), "{reason}");
        assert_eq!(peer_keys(&e), vec![2]);
        assert_eq!(version_of(&e, 2), Some(1));
        // Also rejected after a restart
        engine_with(1, &backend)
            .apply(&validated(forged), &mut VecSink::default())
            .expect_err("still pinned after a restart");
    }

    #[test]
    fn a_restart_keeps_revocations_and_accepted_versions() {
        let mesh = Mesh::new(&[1, 2, 3]);
        let backend = MemoryBackend::default();
        let old = mesh.desired(
            1,
            vec![
                mesh.material(1, 1),
                mesh.material(2, 1),
                mesh.material(3, 1),
            ],
        );
        let mut e = engine_with(1, &backend);
        e.apply(&validated(old.clone()), &mut VecSink::default())
            .expect("accepted");
        let mut newer = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 2)]);
        newer.revocations = vec![Revocation::Node {
            node_id: node_id(3),
        }];
        e.apply(&validated(newer), &mut VecSink::default())
            .expect("accepted");
        assert_eq!(peer_keys(&e), vec![2]);

        // After a restart, an old desired state is received: the revoked 3 and the old version of 2 are both not
        // accepted
        let mut restarted = engine_with(1, &backend);
        let mut events = VecSink::default();
        restarted
            .apply(&validated(old), &mut events)
            .expect("accepted as a whole");
        let mut refused = rejected(&events);
        refused.sort();
        assert_eq!(refused, [Some(node_id(2)), Some(node_id(3))]);
        assert_eq!(version_of(&restarted, 2), None);
        assert_eq!(version_of(&restarted, 3), None);
        assert_eq!(version_of(&restarted, 1), Some(1));
    }

    #[test]
    fn a_rejected_file_at_startup_falls_back_to_the_last_accepted_state() {
        let mesh = Mesh::new(&[1, 2]);
        let backend = MemoryBackend::default();
        engine_with(1, &backend)
            .apply(
                &validated(mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)])),
                &mut VecSink::default(),
            )
            .expect("accepted");
        assert!(backend.get(crate::store::ACCEPTED_FILE).is_some());

        let mut restarted = engine_with(1, &backend);
        let mut events = VecSink::default();
        restarted
            .apply(&validated(mesh.desired(2, vec![])), &mut events)
            .expect_err("not for this node");
        assert!(restarted.apply_saved(&mut events));
        assert!(events.0.contains(&Event::AcceptedStateRestored));
        assert_eq!(peer_keys(&restarted), vec![2]);
    }

    #[test]
    fn a_new_version_of_the_own_policy_must_not_have_expired() {
        let mesh = Mesh::new(&[1, 2]);
        let past = Timestamp::from_unix_seconds(1_000_000_000);
        let expired = |n, v| mesh.material_expiring(mesh.policy(n, v), mesh_key(n), past);
        let mut e = engine(1);
        // The trust store has just been created (after a member already running upgrades): expiry is not checked
        e.apply(
            &validated(mesh.desired(1, vec![expired(1, 1), mesh.material(2, 1)])),
            &mut VecSink::default(),
        )
        .expect("accepted");
        assert_eq!(version_of(&e, 1), Some(1));
        // A new version that appears later has already expired: not accepted, version 1 continues to be used
        let mut events = VecSink::default();
        e.apply(
            &validated(mesh.desired(1, vec![expired(1, 2), mesh.material(2, 1)])),
            &mut events,
        )
        .expect("accepted as a whole");
        assert_eq!(rejected(&events), [Some(node_id(1))]);
        assert_eq!(version_of(&e, 1), Some(1));
        // A new version that has not expired is accepted as usual; other members' expiry is not checked
        e.apply(
            &validated(mesh.desired(1, vec![mesh.material(1, 3), expired(2, 2)])),
            &mut VecSink::default(),
        )
        .expect("accepted");
        assert_eq!(version_of(&e, 1), Some(3));
        assert_eq!(version_of(&e, 2), Some(2));
    }

    #[test]
    fn trust_store_failures_are_reported_until_a_write_succeeds() {
        let mesh = Mesh::new(&[1, 2]);
        let backend = MemoryBackend::default();
        backend.set_fail_writes(true);
        let mut e = engine_with(1, &backend);
        let doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.material(2, 1)]);
        let mut events = VecSink::default();
        e.apply(&validated(doc.clone()), &mut events)
            .expect("accepted");
        assert!(
            events
                .0
                .iter()
                .any(|e| matches!(e, Event::TrustStoreFailed { .. }))
        );
        // Mesh keeps working as usual
        assert_eq!(peer_keys(&e), vec![2]);
        backend.set_fail_writes(false);
        let mut events = VecSink::default();
        e.apply(&validated(doc), &mut events).expect("accepted");
        assert!(events.0.contains(&Event::TrustStoreSaved));
        assert!(backend.get(crate::store::TRUST_FILE).is_some());
    }
}
