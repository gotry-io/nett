//! Local status (design/status.md): the mesh answers read-only status queries on the local socket.
//!
//! - [`StatusDoc`] is the reply format, read by `nett status` (and later nett-node). Within the same major
//!   version only fields are added: the reader ignores fields it does not recognize, and fields added
//!   later carry defaults;
//! - [`Recorder`] wraps the event sink and records recent events, problems that need attention, and the
//!   most recent switch of each peer;
//! - [`StatusServer`] accepts connections: one query per connection, closed after the reply; [`query`] is
//!   the matching client.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_core::prefix::IpPrefix;
use nett_trust::encoding::Timestamp;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use serde::{Deserialize, Serialize};

use crate::config::Reachability;
use crate::event::{Event, EventSink};

/// Major version of the interface (design/status.md section 4).
pub const VERSION: u32 = 1;

/// Default socket path (design/status.md section 3).
#[cfg(target_os = "macos")]
pub const DEFAULT_SOCKET: &str = "/var/run/nett/mesh.sock";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_SOCKET: &str = "/run/nett/mesh.sock";

/// Upper limit on the length of a request.
pub(crate) const MAX_REQUEST: u64 = 1024;
/// After the reply, at most this much of the peer's unread input is discarded.
pub(crate) const MAX_DRAIN: u64 = 64 * 1024;
/// Upper limit on the length of a reply: several times the estimate based on the member limit.
pub const MAX_REPLY: u64 = 4 << 20;
/// Timeout for socket reads and writes.
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(1);
/// Upper limit on waiting for the background thread to hand over a snapshot: while a desired state is
/// being applied it may be busy with data plane operations.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// Upper limit on waiting for a re-read desired state to finish applying (design/status.md section 4.1).
pub const RELOAD_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper limit on concurrent `reload`s: the party that reads the desired state handles them one by one.
pub const MAX_PENDING_RELOADS: usize = 4;
/// Number of recent events kept.
const MAX_EVENTS: usize = 32;
/// Maximum number of per-node problems (members, advertised prefixes rejected) kept.
const MAX_NODE_PROBLEMS: usize = 32;
/// After a data plane operation fails, it is listed as a problem for this long, or until a retry of the
/// application it failed in succeeds: failed applications are retried and failed peer operations are
/// redone by later ticks, so while either keeps failing it stays listed.
const DATA_PLANE_WINDOW: Duration = Duration::from_secs(300);
/// Stack of the thread that accepts connections: it only does small reads, writes and serialization.
const SERVER_STACK: usize = 256 * 1024;
/// Timeout for waiting for a connection: used to periodically check whether it should exit, without
/// depending on the socket file still existing.
const ACCEPT_POLL: Duration = Duration::from_millis(500);

// ---- Status document (design/status.md section 6) ----

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusDoc {
    pub v: u32,
    /// `nett` version of the mesh.
    pub version: String,
    pub node: NodeStatus,
    pub config: ConfigStatus,
    pub peers: Vec<PeerStatus>,
    /// The relay on this machine (design/status.md section 6); absent when it is not a relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayStatus>,
    /// The devices this machine carries as a mobile gateway (design/devices.md section 6); absent when it
    /// carries none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<GatewayStatus>,
    pub problems: Vec<Problem>,
    pub events: Vec<EventRecord>,
}

impl StatusDoc {
    /// The status without the values that move on their own: byte counts, times of the last
    /// packet and handshake, measurements, whether a candidate other than the current one answers
    /// its probes, the NAT this machine measures, the time nett-relay last asked and the time a
    /// problem was noted. A change in what is left makes nett-node report to the Hub
    /// (design/hub.md section 5); the rest goes with the 10-minute report and the samples.
    pub fn without_measurements(&self) -> Self {
        let mut doc = self.clone();
        doc.node.nat = None;
        for p in &mut doc.peers {
            (p.rx_bytes, p.tx_bytes) = (0, 0);
            (p.last_received, p.last_handshake) = (None, None);
            (p.rtt_ms, p.loss, p.jitter_ms) = (None, None, None);
            for c in &mut p.candidates {
                (c.rtt_ms, c.loss) = (None, None);
                // One lost probe makes a candidate failing and the next answer ok again, as often
                // as every 15 seconds across a lossy border; the current path and a recorded
                // block are what stays
                if !matches!(
                    c.state,
                    CandidateStateDoc::Current | CandidateStateDoc::Blocked
                ) {
                    c.state = CandidateStateDoc::Untested;
                }
            }
        }
        if let Some(gateway) = &mut doc.gateway {
            for d in &mut gateway.devices {
                (d.rx_bytes, d.tx_bytes, d.last_handshake) = (0, 0, None);
            }
        }
        if let Some(relay) = &mut doc.relay {
            relay.fetched_at = None;
        }
        for p in &mut doc.problems {
            p.at = Timestamp::from_unix_seconds(0);
        }
        doc
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayStatus {
    /// Whether this machine forwards IPv6, where the data plane can tell; without it devices reach
    /// other machines over IPv4 only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_forwarding: Option<bool>,
    pub devices: Vec<DeviceStatus>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceStatus {
    pub credential: nett_core::id::CredentialId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<NodeName>,
    pub mesh: Vec<IpAddr>,
    /// Where the device last connected from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<std::net::SocketAddr>,
    pub last_handshake: Option<Timestamp>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayStatus {
    pub port: u16,
    pub tls_port: Option<u16>,
    pub members: usize,
    pub links: usize,
    /// The fingerprint of the TLS certificate nett-relay, the relay's TLS entry, reported when it last
    /// asked for its port.
    pub fingerprint: Option<nett_core::transport::CertFingerprint>,
    /// When nett-relay last asked for its port; empty when it has not since the mesh started.
    pub fetched_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeStatus {
    pub id: NodeId,
    pub name: Option<NodeName>,
    /// This machine is among the admitted members; when it is not, there is no address and it does not
    /// communicate with any peer.
    pub admitted: bool,
    pub mesh: Vec<IpAddr>,
    /// The Edge address when there is an `edge` role.
    pub edge: Vec<IpAddr>,
    /// Prefixes advertised by this machine.
    pub routes: Vec<IpPrefix>,
    /// Ports this machine serves to its services on `127.0.0.1` (design/mesh.md section 12.1).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub serve: Vec<u16>,
    pub reachability: Reachability,
    pub dataplane: DataPlaneKind,
    /// The port WireGuard actually listens on; empty while the interface is not ready yet.
    pub listen_port: Option<u16>,
    /// NAT type and mapped addresses of a `dial-only` node (design/mesh.md section 6.1).
    pub nat: Option<NatStatus>,
    /// LAN addresses, from which the Hub composes LAN direct candidates (design/mesh.md section 6).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lan: Vec<crate::lan::LanAddress>,
    /// The system's time service keeps the clock synchronized (design/mesh.md section 8.4).
    pub clock_trusted: bool,
    pub started_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataPlaneKind {
    Kernel,
    Userspace,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NatStatus {
    #[serde(rename = "type")]
    pub kind: NatKind,
    pub ipv4: Option<SocketAddr>,
    pub ipv6: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatKind {
    Cone,
    Symmetric,
    /// There are not yet observations from two `public` nodes, or the type exists only in a newer version.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigStatus {
    /// The time the desired state in effect was most recently accepted.
    pub applied_at: Option<Timestamp>,
    pub access_rules_version: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerStatus {
    pub id: NodeId,
    pub name: Option<NodeName>,
    pub mesh: Vec<IpAddr>,
    pub edge: Vec<IpAddr>,
    pub routes: Vec<IpPrefix>,
    pub state: PeerState,
    /// Empty when the desired state has no path to it.
    pub role: Option<PeerRole>,
    pub path: Option<PathStatus>,
    /// Measurement of in-tunnel probes on the current path; empty when this machine does not measure
    /// (following through roaming).
    pub rtt_ms: Option<f64>,
    pub loss: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub last_handshake: Option<Timestamp>,
    pub last_received: Option<Timestamp>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// The candidate paths during this machine's path selection, including the current path.
    pub candidates: Vec<CandidateStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerState {
    /// Packets from the peer were received in the last 30 seconds.
    Connected,
    /// Sending to it, and nothing has been received yet.
    Connecting,
    /// Sending to it, something was received before, but nothing in the last 30 seconds.
    Unreachable,
    /// No packets in either direction in the last 30 seconds: with no traffic there is no probing, so there
    /// is no way to tell.
    Idle,
    /// The desired state has no path to it.
    NoPath,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRole {
    /// This machine decides the path (design/mesh.md section 8.3).
    Decider,
    /// This machine follows the peer's choice.
    Follower,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathStatus {
    pub kind: PathKindDoc,
    pub relay: Option<NodeRef>,
    /// For a direct path, the peer's address; via a relay, the relay's address (for TLS, the relay's TLS
    /// address).
    pub endpoint: Option<SocketAddr>,
    pub punched: bool,
    /// The time and reason of the switch to this path; empty when this machine follows the peer or no switch
    /// has happened since startup.
    pub since: Option<Timestamp>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKindDoc {
    Lan,
    Direct,
    /// Obfuscated UDP to the peer's own obfuscated port (design/obfuscation.md section 5).
    DirectObfs,
    Relay,
    RelayObfs,
    RelayTls,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRef {
    pub id: NodeId,
    pub name: Option<NodeName>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateStatus {
    pub kind: PathKindDoc,
    pub relay: Option<NodeRef>,
    pub endpoint: SocketAddr,
    pub punched: bool,
    pub rtt_ms: Option<f64>,
    pub loss: Option<f64>,
    pub state: CandidateStateDoc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStateDoc {
    Current,
    Ok,
    Failing,
    Untested,
    Blocked,
    #[serde(other)]
    Other,
}

/// Situations that need attention (design/status.md section 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    pub kind: ProblemKind,
    /// The node involved, when related to a node (empty when the node ID cannot be read).
    pub node: Option<NodeRef>,
    pub at: Timestamp,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProblemKind {
    /// The whole desired state was rejected; the previous one stays in use.
    ConfigRejected,
    /// This machine is not among the admitted members.
    NotAdmitted,
    MemberRejected,
    AccessRulesRejected,
    RoutesRejected,
    /// A device credential failed verification (design/devices.md section 4).
    DeviceRejected,
    DataPlaneFailed,
    /// Reading or writing the trust store failed (design/mesh.md section 4.2).
    TrustStore,
    /// The DNS responder could not start (design/names-and-diagnostics.md section 2).
    Names,
    /// A port this machine serves is not forwarded (design/mesh.md section 12.1).
    Serve,
    #[serde(other)]
    Other,
}

/// An event: the time, plus the same event fields as the log (`event` is the event name).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventRecord {
    pub at: Timestamp,
    #[serde(flatten)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

impl EventRecord {
    pub fn name(&self) -> &str {
        self.fields
            .get("event")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
    }
}

/// Who an address belongs to, from this machine's verified admission material
/// (design/names-and-diagnostics.md section 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Whois {
    pub address: IpAddr,
    /// `member` (a mesh address), `edge` (an Edge address), `route` (inside a prefix a member
    /// advertises), `device` (a device credential; `node` is its gateway) or `none`.
    pub kind: WhoisKind,
    pub node: Option<NodeRef>,
    /// For a device address: the credential and the device's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mesh: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<nett_trust::payload::Role>,
    /// The advertised prefix the address is in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<IpPrefix>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WhoisKind {
    Member,
    Edge,
    Route,
    Device,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRef {
    pub credential: nett_core::id::CredentialId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<NodeName>,
}

/// Result of a `reload` (design/status.md section 4.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ReloadOutcome {
    /// It took effect; `problems` are the situations that still need attention after applying.
    Applied { problems: Vec<Problem> },
    /// The whole was rejected; the previous one stays in use.
    Rejected { reason: String },
}

/// The party waiting for a `reload` to finish applying: the background thread hands the result here
/// after applying.
pub type ReloadReply = std::sync::mpsc::SyncSender<ReloadOutcome>;

pub fn timestamp(t: SystemTime) -> Timestamp {
    Timestamp::from_unix_seconds(
        t.duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)),
    )
}

/// Converts an instant on the monotonic clock to wall clock time: `now` and `wall` are the same moment.
pub fn wall_time(now: Instant, wall: SystemTime, t: Instant) -> Timestamp {
    timestamp(
        wall.checked_sub(now.saturating_duration_since(t))
            .unwrap_or(UNIX_EPOCH),
    )
}

// ---- Event recording ----

/// Wraps the event sink: hands out every event as usual, and records the parts that status queries need.
pub struct Recorder<E> {
    inner: E,
    started_at: Timestamp,
    events: VecDeque<EventRecord>,
    problems: Problems,
    /// The time and reason of each peer's most recent switch.
    switches: HashMap<NodeId, (Timestamp, String)>,
}

#[derive(Debug, Default)]
struct Problems {
    config: Option<(Timestamp, String)>,
    not_admitted: Option<Timestamp>,
    members: BTreeMap<Option<NodeId>, (Timestamp, String)>,
    access: Option<(Timestamp, String)>,
    routes: BTreeMap<Option<NodeId>, (Timestamp, String)>,
    devices: BTreeMap<Option<nett_core::id::CredentialId>, (Timestamp, String)>,
    data_plane: Option<(Instant, Timestamp, String)>,
    /// Stays listed until the next write succeeds.
    trust_store: Option<(Timestamp, String)>,
    /// The DNS responder could not start.
    names: Option<(Timestamp, String)>,
    /// Served ports that could not be bound (at most `MAX_SERVED_PORTS`); they stay listed across
    /// desired states until the port is forwarded or no longer served.
    serve: BTreeMap<u16, (Timestamp, String)>,
}

impl<E: EventSink> Recorder<E> {
    pub fn new(inner: E) -> Self {
        Self {
            inner,
            started_at: Timestamp::now(),
            events: VecDeque::new(),
            problems: Problems::default(),
            switches: HashMap::new(),
        }
    }

    /// A new desired state has passed format validation and is about to be applied: problems left by the
    /// previous one are void, and those that still exist during applying are reported again (material
    /// that fails verification is reported on every apply).
    pub fn begin_apply(&mut self) {
        let data_plane = self.problems.data_plane.take();
        let trust_store = self.problems.trust_store.take();
        let serve = std::mem::take(&mut self.problems.serve);
        self.problems = Problems {
            data_plane,
            trust_store,
            serve,
            ..Problems::default()
        };
    }

    pub fn started_at(&self) -> Timestamp {
        self.started_at
    }

    /// Fills the recorded problems, recent events, and the time and reason of switches into the snapshot.
    /// `names` is used to attach names to the nodes in problems.
    pub fn fill(&self, doc: &mut StatusDoc, names: &BTreeMap<NodeId, NodeName>, now: Instant) {
        doc.problems = self.problems(&doc.node.id, names, now);
        doc.events = self.events.iter().cloned().collect();
        for peer in &mut doc.peers {
            if let (Some(path), Some((at, reason))) = (&mut peer.path, self.switches.get(&peer.id))
                && peer.role == Some(PeerRole::Decider)
            {
                path.since = Some(*at);
                path.reason = Some(reason.clone());
            }
        }
    }

    /// The situations that currently need attention (design/status.md section 6). `own` is this machine's
    /// node ID.
    pub fn problems(
        &self,
        own: &NodeId,
        names: &BTreeMap<NodeId, NodeName>,
        now: Instant,
    ) -> Vec<Problem> {
        let node_ref = |id: &Option<NodeId>| {
            id.as_ref().map(|id| NodeRef {
                id: id.clone(),
                name: names.get(id).cloned(),
            })
        };
        let p = &self.problems;
        let mut problems = Vec::new();
        let mut push = |kind, node: Option<NodeRef>, (at, reason): &(Timestamp, String)| {
            problems.push(Problem {
                kind,
                node,
                at: *at,
                reason: reason.clone(),
            });
        };
        if let Some(c) = &p.config {
            push(ProblemKind::ConfigRejected, None, c);
        }
        if let Some(at) = p.not_admitted {
            push(
                ProblemKind::NotAdmitted,
                node_ref(&Some(own.clone())),
                &(at, "this node is not among the admitted members".into()),
            );
        }
        for (id, r) in &p.members {
            push(ProblemKind::MemberRejected, node_ref(id), r);
        }
        if let Some(a) = &p.access {
            push(ProblemKind::AccessRulesRejected, None, a);
        }
        for (id, r) in &p.routes {
            push(ProblemKind::RoutesRejected, node_ref(id), r);
        }
        for (id, (at, reason)) in &p.devices {
            let reason = match id {
                Some(id) => format!("{id}: {reason}"),
                None => reason.clone(),
            };
            push(ProblemKind::DeviceRejected, None, &(*at, reason));
        }
        if let Some((seen, at, reason)) = &p.data_plane
            && now.saturating_duration_since(*seen) < DATA_PLANE_WINDOW
        {
            push(ProblemKind::DataPlaneFailed, None, &(*at, reason.clone()));
        }
        if let Some(t) = &p.trust_store {
            push(ProblemKind::TrustStore, None, t);
        }
        if let Some(n) = &p.names {
            push(ProblemKind::Names, None, n);
        }
        for (port, (at, reason)) in &p.serve {
            push(
                ProblemKind::Serve,
                None,
                &(*at, format!("port {port}/tcp: {reason}")),
            );
        }
        problems
    }

    fn record(&mut self, event: &Event) {
        let now = Timestamp::now();
        let bounded_insert =
            |map: &mut BTreeMap<Option<NodeId>, (Timestamp, String)>, id: &Option<NodeId>, r| {
                if map.len() < MAX_NODE_PROBLEMS || map.contains_key(id) {
                    map.insert(id.clone(), (now, r));
                }
            };
        match event {
            Event::ConfigRejected { reason } => self.problems.config = Some((now, reason.clone())),
            Event::SelfNotAdmitted { .. } => self.problems.not_admitted = Some(now),
            Event::MemberRejected { node_id, reason } => {
                bounded_insert(&mut self.problems.members, node_id, reason.clone());
            }
            Event::AccessRulesRejected { reason } => {
                self.problems.access = Some((now, reason.clone()));
            }
            Event::RoutesRejected { node_id, reason } => {
                bounded_insert(&mut self.problems.routes, node_id, reason.clone());
            }
            Event::DeviceRejected {
                credential_id,
                reason,
            } => {
                let devices = &mut self.problems.devices;
                if devices.len() < MAX_NODE_PROBLEMS || devices.contains_key(credential_id) {
                    devices.insert(credential_id.clone(), (now, reason.clone()));
                }
            }
            Event::DataPlaneFailed { reason } => {
                self.problems.data_plane = Some((Instant::now(), now, reason.clone()));
            }
            Event::DataPlaneRecovered => self.problems.data_plane = None,
            Event::TrustStoreFailed { reason } => {
                self.problems.trust_store = Some((now, reason.clone()));
            }
            Event::TrustStoreSaved => self.problems.trust_store = None,
            Event::NamesUnavailable { reason } => self.problems.names = Some((now, reason.clone())),
            Event::NamesReady => self.problems.names = None,
            Event::ServeUnavailable { port, reason }
                if self.problems.serve.len() < nett_trust::payload::MAX_SERVED_PORTS
                    || self.problems.serve.contains_key(port) =>
            {
                self.problems.serve.insert(*port, (now, reason.clone()));
            }
            Event::Serving { port } | Event::ServeStopped { port } => {
                self.problems.serve.remove(port);
            }
            Event::PathSwitched {
                node_id, reason, ..
            } => {
                let reason = serde_json::to_value(reason)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default();
                self.switches.insert(node_id.clone(), (now, reason));
            }
            Event::MemberRemoved { node_id } => {
                self.switches.remove(node_id);
            }
            _ => {}
        }
        // Events that appear on every apply, or that are very long, do not go into recent events: they cannot
        // say "what just happened"
        if matches!(
            event,
            Event::PeersApplied { .. }
                | Event::TransportConfigChanged { .. }
                | Event::TrustStoreSaved
        ) {
            return;
        }
        if let Ok(serde_json::Value::Object(fields)) = serde_json::to_value(event) {
            if self.events.len() == MAX_EVENTS {
                self.events.pop_front();
            }
            self.events.push_back(EventRecord { at: now, fields });
        }
    }
}

impl<E: EventSink> EventSink for Recorder<E> {
    fn emit(&mut self, event: Event) {
        self.record(&event);
        self.inner.emit(event);
    }
}

// ---- Local socket (design/status.md sections 3 and 4) ----

#[derive(Debug, Deserialize)]
struct Request {
    v: u32,
    query: String,
    /// The address a `whois` asks about.
    #[serde(default)]
    address: Option<IpAddr>,
    /// The peer whose paths a `probe` probes, checked as a node ID where it is answered.
    #[serde(default)]
    peer: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProbeReply {
    v: u32,
    probe: Probed,
}

/// What a `probe` request did (design/status.md section 4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Probed {
    /// The number of paths probed.
    pub candidates: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct WhoisReply {
    v: u32,
    whois: Whois,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReloadReplyDoc {
    v: u32,
    reload: ReloadOutcome,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorReply {
    v: u32,
    error: ErrorBody,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ErrorBody {
    code: String,
    message: String,
}

/// The mesh behind the interface.
pub trait StatusSource: Send + 'static {
    /// The current snapshot; `None` when the background thread is busy and cannot hand one over within
    /// [`QUERY_TIMEOUT`].
    fn snapshot(&self) -> Option<StatusDoc>;
    /// Re-reads the desired state file and waits for it to finish applying; `None` when too many are already
    /// waiting or applying did not finish within [`RELOAD_TIMEOUT`].
    fn reload(&self) -> Option<ReloadOutcome>;
    /// Takes over the coordination connection from nett-node in the same process (design/status.md
    /// section 4.2).
    fn coordinate(&self, stream: UnixStream) -> std::io::Result<()>;
    /// Who `address` belongs to; `None` when the background thread is busy.
    fn whois(&self, address: IpAddr) -> Option<Whois>;
    /// Probes every path to `peer` now (design/status.md section 4.3): how many, `Some(None)` when no
    /// member has that node ID, `None` when the background thread is busy.
    fn probe(&self, peer: NodeId) -> Option<Option<usize>>;
}

/// The thread that accepts status queries. Dropping it stops the thread and deletes the socket.
pub struct StatusServer {
    _server: LocalServer,
}

impl StatusServer {
    /// Creates the socket at `path` and starts accepting connections. If the directory does not exist it is
    /// created with `0700`; the socket is `0600`.
    pub fn spawn(path: &Path, source: impl StatusSource) -> std::io::Result<Self> {
        LocalServer::spawn(path, 0o666, "nett-status", move |stream| {
            handle(stream, &source)
        })
        .map(|server| Self { _server: server })
    }
}

/// A thread that accepts connections on a local socket one at a time and hands each to `handle`.
/// Dropping it stops the thread and deletes the socket.
pub(crate) struct LocalServer {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl LocalServer {
    /// Creates the socket at `path` with permissions `mode` and starts accepting connections. If the
    /// directory does not exist it is created with `0700`.
    pub(crate) fn spawn(
        path: &Path,
        mode: u32,
        name: &str,
        handle: impl Fn(UnixStream) -> std::io::Result<()> + Send + 'static,
    ) -> std::io::Result<Self> {
        let listener = bind(path, mode)?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name(name.into())
            .stack_size(SERVER_STACK)
            .spawn(move || {
                let timeout = Timespec::try_from(ACCEPT_POLL).unwrap_or(Timespec {
                    tv_sec: 0,
                    tv_nsec: 500_000_000,
                });
                while !thread_stop.load(Ordering::Relaxed) {
                    let mut fds = [PollFd::new(&listener, PollFlags::IN)];
                    match poll(&mut fds, Some(&timeout)) {
                        Ok(0) | Err(rustix::io::Errno::INTR) => continue,
                        Ok(_) => {}
                        Err(e) => {
                            tracing::debug!(error = %e, "waiting for a local connection");
                            std::thread::sleep(ACCEPT_POLL);
                            continue;
                        }
                    }
                    match listener.accept() {
                        // On macOS an accepted connection inherits the listening socket's non-blocking flag; queries use
                        // blocking reads and writes with a timeout
                        Ok((stream, _)) => {
                            let result =
                                stream.set_nonblocking(false).and_then(|()| handle(stream));
                            if let Err(e) = result {
                                tracing::debug!(error = %e, "local query failed");
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => tracing::debug!(error = %e, "accepting a local connection"),
                    }
                }
            })?;
        Ok(Self {
            path: path.to_owned(),
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Mode of the directory the sockets are in: others pass through it to a socket by name but cannot
/// list it (sections 3 and 3.1).
const SOCKET_DIR_MODE: u32 = 0o711;

fn bind(path: &Path, mode: u32) -> std::io::Result<UnixListener> {
    use std::io::{Error, ErrorKind};
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        // Set after creating, since a service manager's umask narrows the mode given to mkdir; the
        // default directory gets its mode whenever it has another one
        let default = Path::new(DEFAULT_SOCKET).parent() == Some(dir);
        if !dir.exists() {
            std::fs::DirBuilder::new().recursive(true).create(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(SOCKET_DIR_MODE))?;
        } else if default
            && std::fs::metadata(dir)
                .is_ok_and(|m| m.permissions().mode() & 0o777 != SOCKET_DIR_MODE)
        {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(SOCKET_DIR_MODE))?;
        }
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if UnixStream::connect(path).is_ok() {
                return Err(Error::new(
                    ErrorKind::AddrInUse,
                    format!("another process is serving {}", path.display()),
                ));
            }
            // The socket left by the previous abnormal exit
            std::fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // Create it under a temporary name and set its permissions first, then rename: the moment the socket
    // appears at the agreed path it already has its permissions
    let tmp = path.with_extension(format!("sock.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let listener = UnixListener::bind(&tmp)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&tmp, path)?;
    Ok(listener)
}

/// The caller is root or the mesh's own running identity, which may also change what the
/// mesh does (section 3).
fn privileged(stream: &UnixStream) -> std::io::Result<bool> {
    let uid = peer_uid(stream)?;
    Ok(uid == 0 || uid == rustix::process::geteuid().as_raw())
}

/// Queries that change what the mesh does, which only a privileged caller may send; every local user
/// may read and probe, as with Tailscale's LocalAPI (section 3).
fn changes_something(query: &str) -> bool {
    query == "reload"
}

#[cfg(target_os = "linux")]
pub(crate) fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    use std::os::fd::AsFd as _;
    crate::linux::peer_uid(stream.as_fd())
}

#[cfg(target_os = "macos")]
pub(crate) fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    use std::os::fd::AsFd as _;
    crate::macos::peer_uid(stream.as_fd())
}

/// Handles one connection. After the reply, closes the write direction, then discards the peer's unread
/// input (at most [`MAX_DRAIN`]): when closing with unread data, Linux sends a reset to the peer, and the
/// peer may not have read the reply yet.
fn handle(stream: UnixStream, source: &impl StatusSource) -> std::io::Result<()> {
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let result = answer(&stream, source);
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let _ = std::io::copy(
        &mut Deadline::new(&stream).take(MAX_DRAIN),
        &mut std::io::sink(),
    );
    result
}

/// Total time limit for reading [`IO_TIMEOUT`]: before each read the read timeout is set to the time
/// remaining. If computed per read, a peer sending bit by bit could hold this thread indefinitely
/// (design/status.md section 4).
pub(crate) struct Deadline<'a> {
    stream: &'a UnixStream,
    until: Instant,
}

impl<'a> Deadline<'a> {
    pub(crate) fn new(stream: &'a UnixStream) -> Self {
        Self {
            stream,
            until: Instant::now() + IO_TIMEOUT,
        }
    }
}

impl std::io::Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the request took longer than the time limit",
            ));
        }
        self.stream.set_read_timeout(Some(left))?;
        (&mut &*self.stream).read(buf)
    }
}

/// Answers one query.
fn answer(stream: &UnixStream, source: &impl StatusSource) -> std::io::Result<()> {
    let privileged = privileged(stream)?;
    let mut line = String::new();
    BufReader::new(Deadline::new(stream).take(MAX_REQUEST)).read_line(&mut line)?;
    let request: Request = match serde_json::from_str(line.trim_end()) {
        Ok(r) => r,
        Err(_) => {
            return reply_error(stream, "bad_request", "the request is not valid JSON");
        }
    };
    if changes_something(&request.query) && !privileged {
        return reply_error(
            stream,
            "permission_denied",
            "only root can change what nett does",
        );
    }
    if request.v != VERSION {
        return reply_error(
            stream,
            "unsupported_version",
            &format!(
                "interface version {} is not supported; this process speaks {VERSION}",
                request.v
            ),
        );
    }
    if request.query == "whois" {
        let Some(address) = request.address else {
            return reply_error(stream, "bad_request", "whois needs an address");
        };
        let Some(whois) = source.whois(address) else {
            return reply_error(stream, "busy", "nett is busy; try again");
        };
        let mut bytes =
            serde_json::to_vec(&WhoisReply { v: VERSION, whois }).map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        let mut out = stream;
        return out.write_all(&bytes);
    }
    if request.query == "probe" {
        let Some(peer) = request.peer else {
            return reply_error(stream, "bad_request", "probe needs a peer");
        };
        let Ok(peer) = peer.parse::<NodeId>() else {
            let shown: String = peer.chars().take(40).collect();
            return reply_error(
                stream,
                "bad_request",
                &format!("`{shown}` is not a node ID"),
            );
        };
        let reply = match source.probe(peer.clone()) {
            None => {
                return reply_error(stream, "busy", "nett is busy; try again");
            }
            Some(None) => {
                return reply_error(
                    stream,
                    "unknown_peer",
                    &format!("no member has the node ID {peer}"),
                );
            }
            Some(Some(candidates)) => ProbeReply {
                v: VERSION,
                probe: Probed { candidates },
            },
        };
        let mut bytes = serde_json::to_vec(&reply).map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        let mut out = stream;
        return out.write_all(&bytes);
    }
    if request.query == "reload" {
        let Some(outcome) = source.reload() else {
            return reply_error(
                stream,
                "busy",
                "nett did not finish applying in time; check again with nett status",
            );
        };
        let mut bytes = serde_json::to_vec(&ReloadReplyDoc {
            v: VERSION,
            reload: outcome,
        })
        .map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        let mut out = stream;
        return out.write_all(&bytes);
    }
    if request.query != "status" {
        let query: String = request.query.chars().take(32).collect();
        return reply_error(stream, "unknown_query", &format!("unknown query `{query}`"));
    }
    let Some(doc) = source.snapshot() else {
        return reply_error(stream, "busy", "nett is busy; try again");
    };
    let mut bytes = serde_json::to_vec(&doc).map_err(std::io::Error::other)?;
    if bytes.len() as u64 > MAX_REPLY {
        return reply_error(
            stream,
            "too_large",
            "the status is larger than the reply limit",
        );
    }
    bytes.push(b'\n');
    let mut out = stream;
    out.write_all(&bytes)
}

pub(crate) fn reply_error(stream: &UnixStream, code: &str, message: &str) -> std::io::Result<()> {
    let reply = ErrorReply {
        v: VERSION,
        error: ErrorBody {
            code: code.into(),
            message: message.into(),
        },
    };
    let mut bytes = serde_json::to_vec(&reply).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    let mut stream = stream;
    stream.write_all(&bytes)
}

// ---- Client ----

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("cannot reach the nett service at {}: {source}", path.display())]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("talking to the nett service at {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("the nett service answered {code}: {message}")]
    Refused { code: String, message: String },
    #[error("the nett service sent a reply this version cannot read: {0}")]
    Reply(String),
}

/// Queries the status of the mesh at `path`.
pub fn query(path: &Path) -> Result<StatusDoc, QueryError> {
    let value = query_raw(path)?;
    serde_json::from_value(value).map_err(|e| QueryError::Reply(e.to_string()))
}

/// Same as [`query`], returns the unparsed reply: it may contain fields this version does not recognize
/// (`nett status --json` outputs it as is).
pub fn query_raw(path: &Path) -> Result<serde_json::Value, QueryError> {
    request(path, "status", QUERY_TIMEOUT)
}

/// Asks the mesh at `path` who `address` belongs to (design/names-and-diagnostics.md section 4).
pub fn whois(path: &Path, address: IpAddr) -> Result<Whois, QueryError> {
    let value = send(
        path,
        &serde_json::json!({"v": VERSION, "query": "whois", "address": address}),
        QUERY_TIMEOUT,
    )?;
    let reply: WhoisReply =
        serde_json::from_value(value).map_err(|e| QueryError::Reply(e.to_string()))?;
    Ok(reply.whois)
}

/// Asks the mesh at `path` to probe every path to `peer` now (design/status.md section 4.3).
pub fn probe(path: &Path, peer: &NodeId) -> Result<Probed, QueryError> {
    let value = send(
        path,
        &serde_json::json!({"v": VERSION, "query": "probe", "peer": peer}),
        QUERY_TIMEOUT,
    )?;
    let reply: ProbeReply =
        serde_json::from_value(value).map_err(|e| QueryError::Reply(e.to_string()))?;
    Ok(reply.probe)
}

/// Asks the mesh at `path` to re-read the desired state file and waits for it to finish applying
/// (design/status.md section 4.1).
pub fn reload(path: &Path) -> Result<ReloadOutcome, QueryError> {
    let value = request(path, "reload", RELOAD_TIMEOUT)?;
    let doc: ReloadReplyDoc =
        serde_json::from_value(value).map_err(|e| QueryError::Reply(e.to_string()))?;
    Ok(doc.reload)
}

/// Sends a request and reads back the reply; the mesh side handles it for at most `wait`.
fn request(path: &Path, query: &str, wait: Duration) -> Result<serde_json::Value, QueryError> {
    send(
        path,
        &serde_json::json!({"v": VERSION, "query": query}),
        wait,
    )
}

/// Sends one request document and reads back the reply.
pub(crate) fn send(
    path: &Path,
    request: &serde_json::Value,
    wait: Duration,
) -> Result<serde_json::Value, QueryError> {
    let io = |source| QueryError::Io {
        path: path.to_owned(),
        source,
    };
    let stream = UnixStream::connect(path).map_err(|source| QueryError::Connect {
        path: path.to_owned(),
        source,
    })?;
    stream
        .set_read_timeout(Some(wait + IO_TIMEOUT))
        .map_err(io)?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(io)?;
    let mut line = request.to_string();
    line.push('\n');
    (&stream).write_all(line.as_bytes()).map_err(io)?;
    let mut bytes = Vec::new();
    (&stream)
        .take(MAX_REPLY + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| QueryError::Reply(e.to_string()))?;
    if let Some(error) = value.get("error") {
        let body: ErrorBody =
            serde_json::from_value(error.clone()).map_err(|e| QueryError::Reply(e.to_string()))?;
        return Err(QueryError::Refused {
            code: body.code,
            message: body.message,
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::VecSink;
    use crate::path::SwitchReason;

    fn node(n: u8) -> NodeId {
        crate::testutil::node_id(n)
    }

    fn sample() -> StatusDoc {
        StatusDoc {
            v: VERSION,
            version: "0.0.0".into(),
            gateway: None,
            node: NodeStatus {
                id: node(1),
                name: Some("edge-vps".parse().expect("name")),
                admitted: true,
                mesh: vec!["100.88.0.1".parse().expect("addr")],
                edge: vec![],
                routes: vec![],
                serve: vec![],
                reachability: Reachability::Public,
                dataplane: DataPlaneKind::Kernel,
                listen_port: Some(41820),
                nat: None,
                lan: vec![],
                clock_trusted: true,
                started_at: Timestamp::from_unix_seconds(1_700_000_000),
            },
            config: ConfigStatus {
                applied_at: None,
                access_rules_version: Some(3),
            },
            peers: vec![PeerStatus {
                id: node(2),
                name: None,
                mesh: vec![],
                edge: vec![],
                routes: vec![],
                state: PeerState::Connected,
                role: Some(PeerRole::Decider),
                path: Some(PathStatus {
                    kind: PathKindDoc::Direct,
                    relay: None,
                    endpoint: None,
                    punched: false,
                    since: None,
                    reason: None,
                }),
                rtt_ms: Some(9.4),
                loss: Some(0.0),
                jitter_ms: None,
                last_handshake: None,
                last_received: None,
                rx_bytes: 0,
                tx_bytes: 0,
                candidates: vec![],
            }],
            relay: None,
            problems: vec![],
            events: vec![],
        }
    }

    struct Fixed(Option<StatusDoc>);

    impl StatusSource for Fixed {
        fn snapshot(&self) -> Option<StatusDoc> {
            self.0.clone()
        }

        fn reload(&self) -> Option<ReloadOutcome> {
            self.0.as_ref().map(|_| ReloadOutcome::Rejected {
                reason: "bad json".into(),
            })
        }

        fn coordinate(&self, _: UnixStream) -> std::io::Result<()> {
            Ok(())
        }

        fn whois(&self, address: IpAddr) -> Option<Whois> {
            Some(Whois {
                address,
                kind: WhoisKind::None,
                node: None,
                device: None,
                mesh: vec![],
                roles: vec![],
                prefix: None,
            })
        }

        fn probe(&self, peer: NodeId) -> Option<Option<usize>> {
            let doc = self.0.as_ref()?;
            Some(doc.peers.iter().any(|p| p.id == peer).then_some(3))
        }
    }

    /// The directory the mesh makes for its sockets lets others reach a socket by name but
    /// not list it, whatever mode mkdir got
    #[test]
    fn the_socket_directory_is_passable_but_not_listable() {
        let (_dir_tmp, dir) = temp_dir();
        let path = dir.join("run").join("nett").join("mesh.sock");
        let _listener = bind(&path, 0o666).expect("bind");
        let mode = std::fs::metadata(dir.join("run").join("nett"))
            .expect("directory")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o711);
    }

    /// Every local user may read and probe; only root and the mesh's own identity may change
    /// what it does (section 3), as Tailscale's LocalAPI gives every local user read access
    #[test]
    fn only_queries_that_change_something_need_privileges() {
        for query in ["status", "whois", "probe"] {
            assert!(!changes_something(query), "{query}");
        }
        assert!(changes_something("reload"));
    }

    /// A short directory for tests (Unix socket paths on macOS are at most 104 bytes), removed with
    /// everything in it when the returned guard is dropped; keep the guard while the path is used.
    fn temp_dir() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::Builder::new()
            .prefix("nst-")
            .tempdir()
            .expect("temp dir");
        let dir = tmp.path().join("s");
        (tmp, dir)
    }

    fn raw(path: &Path, request: &[u8]) -> serde_json::Value {
        let mut stream = UnixStream::connect(path).expect("connect");
        stream.write_all(request).expect("write");
        let mut out = Vec::new();
        stream.read_to_end(&mut out).expect("read");
        serde_json::from_slice(&out).expect("json reply")
    }

    /// Server half of [`a_peer_in_another_pid_namespace_is_identified`]: runs in a new PID namespace
    /// and answers one connection with the peer's user ID.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "started by a_peer_in_another_pid_namespace_is_identified"]
    fn report_peer_uid_once() {
        let path = std::env::var_os("NETT_TEST_SOCKET").expect("NETT_TEST_SOCKET");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let (mut stream, _) = listener.accept().expect("accept");
        let reply = match peer_uid(&stream) {
            Ok(uid) => uid.to_string(),
            Err(e) => format!("error: {e}"),
        };
        stream.write_all(reply.as_bytes()).expect("reply");
    }

    /// nett-node in one container and the mesh in another: the kernel reports the peer's PID
    /// as 0 when the peer is outside the server's PID namespace, and its user ID must still be read.
    /// Creating a PID namespace needs root, so this runs in the lab containers, not as an ordinary
    /// user.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_peer_in_another_pid_namespace_is_identified() {
        if !rustix::process::geteuid().is_root() {
            return;
        }
        let (_dir_tmp, dir) = temp_dir();
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("peer.sock");
        let mut server = std::process::Command::new("unshare")
            .args(["--pid", "--fork"])
            .arg(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "status::tests::report_peer_uid_once",
                "--ignored",
                "--quiet",
            ])
            .env("NETT_TEST_SOCKET", &path)
            .spawn()
            .expect("unshare");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut stream = loop {
            match UnixStream::connect(&path) {
                Ok(s) => break s,
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => panic!("the server in the new PID namespace did not start: {e}"),
            }
        };
        let mut reply = String::new();
        stream.read_to_string(&mut reply).expect("reply");
        assert!(server.wait().expect("wait").success());
        assert_eq!(reply, "0");
    }

    #[test]
    fn answers_a_status_query_over_its_socket() {
        let (_dir_tmp, dir) = temp_dir();
        let path = dir.join("mesh.sock");
        let server = StatusServer::spawn(&path, Fixed(Some(sample()))).expect("spawn");
        let mode = |p: &Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o777;
        // Others reach the socket by name, and the mesh decides per query what they may do
        assert_eq!(mode(&dir), 0o711);
        assert_eq!(mode(&path), 0o666);
        assert_eq!(query(&path).expect("query"), sample());
        // The reader ignores fields it does not recognize: fields added in a newer version do not affect an older
        // nett
        let mut newer = serde_json::to_value(sample()).expect("value");
        newer["future_field"] = serde_json::json!({"x": 1});
        newer["peers"][0]["state"] = "something_new".into();
        let parsed: StatusDoc = serde_json::from_value(newer).expect("tolerant");
        assert_eq!(parsed.peers[0].state, PeerState::Other);

        drop(server);
        assert!(!path.exists(), "socket removed on shutdown");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_probe_request_names_a_member() {
        let (_dir_tmp, dir) = temp_dir();
        let path = dir.join("mesh.sock");
        let _server = StatusServer::spawn(&path, Fixed(Some(sample()))).expect("spawn");
        assert_eq!(
            probe(&path, &node(2)).expect("probe"),
            Probed { candidates: 3 }
        );
        assert!(matches!(
            probe(&path, &node(9)),
            Err(QueryError::Refused { code, .. }) if code == "unknown_peer"
        ));
        let code = |request: &[u8]| raw(&path, request)["error"]["code"].clone();
        assert_eq!(code(b"{\"v\":1,\"query\":\"probe\"}\n"), "bad_request");
        assert_eq!(
            code(b"{\"v\":1,\"query\":\"probe\",\"peer\":\"node_x\"}\n"),
            "bad_request"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_bad_requests() {
        let (_dir_tmp, dir) = temp_dir();
        let path = dir.join("mesh.sock");
        let _server = StatusServer::spawn(&path, Fixed(Some(sample()))).expect("spawn");
        let code = |request: &[u8]| raw(&path, request)["error"]["code"].clone();
        assert_eq!(code(b"hello\n"), "bad_request");
        assert_eq!(
            code(b"{\"v\":2,\"query\":\"status\"}\n"),
            "unsupported_version"
        );
        assert_eq!(code(b"{\"v\":1,\"query\":\"stats\"}\n"), "unknown_query");
        // A request over the length limit is not read to the end
        let mut long = vec![b' '; 4096];
        long.push(b'\n');
        assert_eq!(code(&long), "bad_request");
        drop(_server);

        let _busy = StatusServer::spawn(&path, Fixed(None)).expect("spawn");
        assert!(matches!(
            query(&path),
            Err(QueryError::Refused { code, .. }) if code == "busy"
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_slow_client_cannot_hold_the_socket_past_the_time_limit() {
        let (_dir_tmp, dir) = temp_dir();
        let path = dir.join("mesh.sock");
        let _server = StatusServer::spawn(&path, Fixed(Some(sample()))).expect("spawn");
        let mut slow = UnixStream::connect(&path).expect("connect");
        let started = Instant::now();
        // Send one byte every 200 ms, with no newline: if the timeout were computed per read, this could hold
        // the connection-handling thread indefinitely
        let mut closed = false;
        for _ in 0..40 {
            if slow.write_all(b" ").is_err() {
                closed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        assert!(
            closed,
            "still accepting bytes after {:?}",
            started.elapsed()
        );
        // Reading the request and discarding input after the reply each have a time limit
        assert!(started.elapsed() < IO_TIMEOUT * 5);
        // Later queries are answered as usual
        assert!(query(&path).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reload_reports_the_outcome_or_busy() {
        let (_dir_tmp, dir) = temp_dir();
        let path = dir.join("mesh.sock");
        let server = StatusServer::spawn(&path, Fixed(Some(sample()))).expect("spawn");
        assert_eq!(
            reload(&path).expect("reload"),
            ReloadOutcome::Rejected {
                reason: "bad json".into()
            }
        );
        // The form on the wire (design/status.md section 4.1)
        assert_eq!(
            raw(&path, b"{\"v\":1,\"query\":\"reload\"}\n"),
            serde_json::json!({"v": 1, "reload": {"result": "rejected", "reason": "bad json"}})
        );
        drop(server);
        let _busy = StatusServer::spawn(&path, Fixed(None)).expect("spawn");
        assert!(matches!(
            reload(&path),
            Err(QueryError::Refused { code, .. }) if code == "busy"
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn takes_over_a_stale_socket_but_not_a_live_one_or_a_file() {
        let (_dir_tmp, dir) = temp_dir();
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("mesh.sock");
        // The socket left by the previous abnormal exit: the file is still there and no process is listening
        drop(UnixListener::bind(&path).expect("bind"));
        assert!(path.exists());
        let live = StatusServer::spawn(&path, Fixed(Some(sample()))).expect("takes over");
        let second = StatusServer::spawn(&path, Fixed(Some(sample())));
        assert_eq!(
            second.err().map(|e| e.kind()),
            Some(std::io::ErrorKind::AddrInUse)
        );
        assert!(query(&path).is_ok(), "the first server keeps serving");
        drop(live);

        std::fs::write(&path, b"not a socket").expect("file");
        assert!(StatusServer::spawn(&path, Fixed(Some(sample()))).is_err());
        assert_eq!(std::fs::read(&path).expect("kept"), b"not a socket");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reports_a_missing_service() {
        let (_dir_tmp, dir) = temp_dir();
        let err = query(&dir.join("mesh.sock")).expect_err("no service");
        assert!(matches!(
            err,
            QueryError::Connect { ref source, .. } if source.kind() == std::io::ErrorKind::NotFound
        ));
    }

    /// A failed application is listed while its retries keep failing, also past the window of a
    /// single failure, and no longer once a retry succeeds
    #[test]
    fn a_data_plane_failure_is_listed_until_a_retry_succeeds() {
        let mut r = Recorder::new(VecSink::default());
        let names = BTreeMap::new();
        let listed = |r: &Recorder<VecSink>, at| {
            r.problems(&node(1), &names, at)
                .iter()
                .any(|p| p.kind == ProblemKind::DataPlaneFailed)
        };
        r.emit(Event::DataPlaneFailed {
            reason: "open /dev/net/tun: not found".into(),
        });
        let failed_at = Instant::now();
        assert!(listed(&r, failed_at));
        assert!(
            !listed(&r, failed_at + DATA_PLANE_WINDOW),
            "one failure passes"
        );
        // Retries fail at most 30 seconds apart, so the failure stays recent
        r.emit(Event::DataPlaneFailed {
            reason: "open /dev/net/tun: not found".into(),
        });
        assert!(listed(&r, Instant::now()));
        r.emit(Event::DataPlaneRecovered);
        assert!(!listed(&r, Instant::now()));
    }

    #[test]
    fn records_problems_until_the_next_desired_state() {
        let mut r = Recorder::new(VecSink::default());
        r.emit(Event::ConfigRejected {
            reason: "bad json".into(),
        });
        r.emit(Event::MemberRejected {
            node_id: Some(node(3)),
            reason: "signature".into(),
        });
        r.emit(Event::DataPlaneFailed {
            reason: "netlink".into(),
        });
        // Events are still handed to the original sink as usual
        assert_eq!(r.inner.0.len(), 3);
        let names = BTreeMap::from([(node(3), "nas".parse().expect("name"))]);
        let mut doc = sample();
        let now = Instant::now();
        r.fill(&mut doc, &names, now);
        let kinds: Vec<ProblemKind> = doc.problems.iter().map(|p| p.kind).collect();
        assert_eq!(
            kinds,
            [
                ProblemKind::ConfigRejected,
                ProblemKind::MemberRejected,
                ProblemKind::DataPlaneFailed
            ]
        );
        assert_eq!(
            doc.problems[1].node.as_ref().and_then(|n| n.name.clone()),
            names.get(&node(3)).cloned()
        );
        // The next desired state is accepted: problems left by the previous one are void; data plane failures
        // follow the time window and disappear afterwards
        r.begin_apply();
        r.fill(&mut doc, &names, now);
        assert_eq!(doc.problems.len(), 1);
        r.fill(&mut doc, &names, now + DATA_PLANE_WINDOW);
        assert!(doc.problems.is_empty());
    }

    #[test]
    fn keeps_recent_events_and_the_last_switch_of_a_decider() {
        let mut r = Recorder::new(VecSink::default());
        for _ in 0..(MAX_EVENTS + 5) {
            r.emit(Event::PeersApplied { peers: 1 });
            r.emit(Event::PathSwitched {
                node_id: node(2),
                to: "direct 192.0.2.2:41820".into(),
                reason: SwitchReason::BetterType,
                rehandshake: false,
            });
        }
        let mut doc = sample();
        r.fill(&mut doc, &BTreeMap::new(), Instant::now());
        assert_eq!(doc.events.len(), MAX_EVENTS);
        assert!(doc.events.iter().all(|e| e.name() == "path_switched"));
        let path = doc.peers[0].path.as_ref().expect("path");
        assert_eq!(path.reason.as_deref(), Some("better_type"));
        assert!(path.since.is_some());
        // The following side does not write a switch reason: the path was chosen by the peer
        let mut doc = sample();
        doc.peers[0].role = Some(PeerRole::Follower);
        r.fill(&mut doc, &BTreeMap::new(), Instant::now());
        assert_eq!(
            doc.peers[0].path.as_ref().and_then(|p| p.reason.clone()),
            None
        );
    }
}
