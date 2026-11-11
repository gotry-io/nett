//! Events reported by the mesh process. Every event is also written to the log; lab builds additionally
//! write a JSON-lines copy for `nett-lab` to collect.

use nett_core::id::NodeId;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// The whole desired state was rejected; the previous one stays in use.
    ConfigRejected {
        reason: String,
    },
    /// The whole desired state file was rejected at startup; the last whole desired state accepted in the
    /// trust store is used instead (design/mesh.md section 4.2).
    AcceptedStateRestored,
    /// Reading or writing the trust store failed: runs as usual and verifies against the in-memory state;
    /// a restart during this time may accept an artifact of an older version.
    TrustStoreFailed {
        reason: String,
    },
    /// Writing the trust store succeeded.
    TrustStoreSaved,
    /// This machine is not among the admitted members; the mesh interface is not enabled.
    SelfNotAdmitted {
        node_id: NodeId,
    },
    MemberAdmitted {
        node_id: NodeId,
        policy_version: u64,
    },
    /// A member's admission material failed verification; the peer is not configured (design/mesh.md
    /// section 4.1). Empty when the format is so malformed that the node ID cannot be read.
    MemberRejected {
        node_id: Option<NodeId>,
        reason: String,
    },
    /// A member was removed because of a revocation.
    MemberRemoved {
        node_id: NodeId,
    },
    /// WireGuard peers now match the admitted members.
    PeersApplied {
        peers: usize,
    },
    /// The mesh interface is ready, or the WireGuard port changed: when the desired state carries no port,
    /// the system assigns one (design/mesh.md section 5.5).
    InterfaceReady {
        listen_port: u16,
    },
    /// The configuration handed to the transport adapter changed (design/mesh.md section 5.3; lab builds
    /// write it to a local file).
    TransportConfigChanged {
        config: nett_core::transport::TransportConfig,
    },
    /// The assignment of the relay on this machine changed (design/mesh.md section 5.2): the number of
    /// admitted members and links it forwards for.
    RelayAssignmentChanged {
        members: usize,
        links: usize,
    },
    /// The DNS responder answers on the mesh addresses (design/names-and-diagnostics.md section 2).
    NamesReady,
    /// The DNS responder could not start: names do not resolve, the mesh works as before.
    NamesUnavailable {
        reason: String,
    },
    /// A data plane operation failed; the current state is kept and the operation is retried on the next
    /// desired state.
    DataPlaneFailed {
        reason: String,
    },
    /// A new version of the access rule set passed verification (design/mesh.md section 12).
    AccessRulesApplied {
        version: u64,
    },
    /// The access rule set failed verification or cannot be expanded; the rules already in effect keep being
    /// enforced; when it cannot be expanded, all inbound traffic is rejected.
    AccessRulesRejected {
        reason: String,
    },
    /// The routes advertised by a smart gateway passed verification (design/mesh.md section 10).
    RoutesApplied {
        node_id: NodeId,
        version: u64,
    },
    /// Advertised routes failed verification; the ones already in effect keep being used. Empty when the
    /// node ID cannot be read.
    RoutesRejected {
        node_id: Option<NodeId>,
        reason: String,
    },
    /// The decider switched the path to a peer (design/mesh.md section 8.2).
    PathSwitched {
        node_id: NodeId,
        to: String,
        reason: crate::path::SwitchReason,
        rehandshake: bool,
    },
    /// Starts a hole punching attempt (design/mesh.md section 6.1): the NAT types of both sides.
    PunchStarted {
        node_id: NodeId,
        round: u32,
        nat: crate::probe::NatType,
        peer_nat: crate::probe::NatType,
        /// Address of the other side to send probes to.
        targets: Vec<std::net::SocketAddr>,
    },
    /// Hole punching succeeded: the other side's address.
    PunchSucceeded {
        node_id: NodeId,
        address: std::net::SocketAddr,
    },
    PunchFailed {
        node_id: NodeId,
        reason: String,
    },
    /// The endpoint was changed back to the old path by WireGuard roaming, and the decider sets it back to
    /// the intended path (section 8.3).
    EndpointCorrected {
        node_id: NodeId,
        from: Option<std::net::SocketAddr>,
        to: std::net::SocketAddr,
    },
}

pub trait EventSink {
    fn emit(&mut self, event: Event);
}

impl<T: EventSink + ?Sized> EventSink for Box<T> {
    fn emit(&mut self, event: Event) {
        (**self).emit(event);
    }
}

/// Writes the log only.
#[derive(Debug, Default)]
pub struct LogSink;

impl EventSink for LogSink {
    fn emit(&mut self, event: Event) {
        log_event(&event);
    }
}

pub fn log_event(event: &Event) {
    match event {
        Event::ConfigRejected { reason } => tracing::warn!(%reason, "desired state rejected"),
        Event::AcceptedStateRestored => {
            tracing::warn!("using the last accepted desired state from the trust store")
        }
        Event::TrustStoreFailed { reason } => tracing::error!(%reason, "trust store unavailable"),
        Event::TrustStoreSaved => tracing::debug!("trust store saved"),
        Event::SelfNotAdmitted { node_id } => {
            tracing::error!(%node_id, "this node is not an admitted member")
        }
        Event::MemberAdmitted {
            node_id,
            policy_version,
        } => tracing::info!(%node_id, policy_version, "member admitted"),
        Event::MemberRejected { node_id, reason } => match node_id {
            Some(node_id) => tracing::warn!(%node_id, %reason, "member rejected"),
            None => tracing::warn!(%reason, "member rejected"),
        },
        Event::MemberRemoved { node_id } => tracing::info!(%node_id, "member removed"),
        Event::PeersApplied { peers } => tracing::info!(peers, "peers applied"),
        Event::InterfaceReady { listen_port } => {
            tracing::info!(listen_port, "mesh interface ready")
        }
        Event::TransportConfigChanged { config } => tracing::debug!(
            wireguard_port = config.wireguard_port,
            targets = config.targets.len(),
            "transport config changed"
        ),
        Event::RelayAssignmentChanged { members, links } => {
            tracing::info!(members, links, "relay assignment changed")
        }
        Event::NamesReady => tracing::info!("answering names under {}", crate::dns::SUFFIX),
        Event::NamesUnavailable { reason } => {
            tracing::warn!(%reason, "names under {} do not resolve", crate::dns::SUFFIX)
        }
        Event::DataPlaneFailed { reason } => tracing::warn!(%reason, "data plane update failed"),
        Event::AccessRulesApplied { version } => tracing::info!(version, "access rules applied"),
        Event::AccessRulesRejected { reason } => {
            tracing::warn!(%reason, "access rules rejected")
        }
        Event::RoutesApplied { node_id, version } => {
            tracing::info!(%node_id, version, "advertised routes applied")
        }
        Event::RoutesRejected { node_id, reason } => match node_id {
            Some(node_id) => tracing::warn!(%node_id, %reason, "advertised routes rejected"),
            None => tracing::warn!(%reason, "advertised routes rejected"),
        },
        Event::PathSwitched {
            node_id,
            to,
            reason,
            rehandshake,
        } => tracing::info!(%node_id, %to, ?reason, rehandshake, "path switched"),
        Event::PunchStarted {
            node_id,
            round,
            nat,
            peer_nat,
            targets,
        } => tracing::info!(%node_id, round, ?nat, ?peer_nat, ?targets, "hole punching started"),
        Event::PunchSucceeded { node_id, address } => {
            tracing::info!(%node_id, %address, "hole punched")
        }
        Event::PunchFailed { node_id, reason } => {
            tracing::info!(%node_id, %reason, "hole punching failed")
        }
        Event::EndpointCorrected { node_id, from, to } => {
            tracing::debug!(%node_id, ?from, %to, "endpoint corrected")
        }
    }
}

/// Collects events in tests and lab scenarios.
#[derive(Debug, Default)]
pub struct VecSink(pub Vec<Event>);

impl EventSink for VecSink {
    fn emit(&mut self, event: Event) {
        self.0.push(event);
    }
}
