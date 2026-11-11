//! Single-port forwarding (design/mesh.md sections 5.1, 5.2): decides the destination by `mac1` and
//! session index, and updates member addresses from handshake responses. A member's address is a
//! UDP source or an authenticated TLS connection (section 5.3).
//!
//! Pure logic: the caller passes in the time and gets back what to do; sending and receiving are
//! handled by [`crate::server`].

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use nett_mesh::probe::{self, KeyId, OuterProbe, ProbeKey, RELAY_PROBE};
use nett_trust::keys::X25519PublicKey;

use crate::wg::{self, Index, Mac1Key, Message};

/// The maximum number of members one relay serves: a handshake initiation requires trying `mac1`
/// for each one.
pub const MAX_MEMBERS: usize = 1024;
/// Upper limits for pending entries and for established entries.
const MAX_PENDING: usize = 4096;
const MAX_SESSIONS: usize = 16 * 1024;
/// When the receiver has no address yet, the maximum number of candidate addresses a handshake
/// initiation is forwarded to (design/mesh.md section 5.2).
const MAX_CANDIDATES: usize = 4;
/// Lifetime of a pending entry: WireGuard retries the handshake with a new index after 5 seconds.
const PENDING_TTL: Duration = Duration::from_secs(5);
/// How long an idle session is kept before deletion: a WireGuard session lasts at most 180 seconds
/// (REJECT_AFTER_TIME), after which a new handshake is necessarily required.
const SESSION_IDLE: Duration = Duration::from_secs(180);
/// Minimum interval between two binding changes for the same member.
const BIND_MIN_INTERVAL: Duration = Duration::from_secs(1);
/// After a new binding, if no data arrives from the new address within this time, the old binding
/// is restored.
const BIND_CONFIRM: Duration = Duration::from_secs(10);

/// A TLS connection (design/mesh.md section 5.3), numbered by the receive/send loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(pub u64);

/// A member's address: a UDP source or an authenticated TLS connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerAddr {
    Udp(SocketAddr),
    Tls(ConnId),
}

/// Format version of the saved state.
const STATE_V1: u32 = 1;

/// State restored at restart (design/mesh.md section 5.2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayState {
    pub v: u32,
    pub bindings: Vec<Binding>,
    pub sessions: Vec<SavedSession>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub public_key: X25519PublicKey,
    pub address: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedSession {
    pub index: Index,
    pub owner: X25519PublicKey,
    /// How long it had been idle when saved.
    pub idle_ms: u64,
}

/// A member in the relay's allocation (design/mesh.md section 5.2).
#[derive(Debug, Clone)]
pub struct AssignedMember {
    pub public_key: X25519PublicKey,
    /// The address of a `public` member is delivered with the allocation; the address of a
    /// `dial-only` member is determined by the handshake.
    pub address: Option<SocketAddr>,
    pub token: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AssignmentError {
    #[error("assignment has {0} members, more than {MAX_MEMBERS}")]
    TooManyMembers(usize),
    #[error("member {0} is listed twice")]
    DuplicateMember(X25519PublicKey),
    #[error("connection names member {0}, which is not in the assignment")]
    UnknownMember(X25519PublicKey),
}

/// Reason for a drop, for counting and troubleshooting; the relay sends no response to dropped
/// packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drop {
    NotWireGuard,
    UnknownReceiver,
    ReceiverUnbound,
    IndexCollision,
    TableFull,
    NoPending,
    ResponseFromUnbound,
    NotAssigned,
    BindRateLimited,
    UnknownIndex,
    BadProbe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Forward as is to this address.
    Forward(PeerAddr),
    /// The receiver has no address yet: forward as is to each candidate address (design/mesh.md
    /// section 5.2).
    ForwardEach(Vec<PeerAddr>),
    /// Send a reply (probe) back to the source.
    Reply(Vec<u8>),
    Drop(Drop),
}

struct Member {
    public_key: X25519PublicKey,
    mac1: Mac1Key,
    key_id: KeyId,
    probe_key: ProbeKey,
    bound: Option<PeerAddr>,
    /// A binding change not yet confirmed by data on the new address: the address before the change
    /// and the time of the change.
    unconfirmed: Option<(Option<PeerAddr>, Instant)>,
    last_change: Option<Instant>,
}

struct Pending {
    src: PeerAddr,
    receiver: usize,
    /// When the receiver has no address yet, the candidate addresses a handshake initiation was
    /// forwarded to: the response must come from one of them.
    candidates: Vec<PeerAddr>,
    at: Instant,
}

struct Session {
    owner: usize,
    at: Instant,
}

pub struct Relay {
    members: Vec<Member>,
    connections: HashSet<(usize, usize)>,
    pending: HashMap<Index, Pending>,
    sessions: HashMap<Index, Session>,
}

fn pair(a: usize, b: usize) -> (usize, usize) {
    (a.min(b), a.max(b))
}

impl Relay {
    pub fn new(
        members: &[AssignedMember],
        connections: &[(X25519PublicKey, X25519PublicKey)],
    ) -> Result<Self, AssignmentError> {
        if members.len() > MAX_MEMBERS {
            return Err(AssignmentError::TooManyMembers(members.len()));
        }
        let mut seen = HashSet::new();
        for m in members {
            if !seen.insert(m.public_key) {
                return Err(AssignmentError::DuplicateMember(m.public_key));
            }
        }
        let position = |key: &X25519PublicKey| {
            members
                .iter()
                .position(|m| m.public_key == *key)
                .ok_or(AssignmentError::UnknownMember(*key))
        };
        let connections = connections
            .iter()
            .map(|(a, b)| Ok(pair(position(a)?, position(b)?)))
            .collect::<Result<_, AssignmentError>>()?;
        Ok(Self {
            members: members
                .iter()
                .map(|m| Member {
                    public_key: m.public_key,
                    mac1: Mac1Key::for_public_key(m.public_key.as_bytes()),
                    key_id: KeyId::of(m.public_key.as_bytes()),
                    probe_key: ProbeKey::from_token(&m.token),
                    bound: m.address.map(PeerAddr::Udp),
                    unconfirmed: None,
                    last_change: None,
                })
                .collect(),
            connections,
            pending: HashMap::new(),
            sessions: HashMap::new(),
        })
    }

    /// Handles a payload from `from`. An IPv4-mapped address in a UDP source is first restored to
    /// IPv4 by the caller; messages on a TLS connection are passed in only after the connection is
    /// authenticated ([`Relay::authenticate`]).
    pub fn handle(&mut self, from: PeerAddr, packet: &[u8], now: Instant, now_ms: u64) -> Outcome {
        if packet.first() == Some(&RELAY_PROBE) {
            return self.probe(from, packet, now_ms);
        }
        let Some(message) = wg::parse(packet) else {
            return Outcome::Drop(Drop::NotWireGuard);
        };
        match message {
            Message::Initiation {
                sender,
                signed,
                mac1,
            } => self.initiation(from, sender, signed, mac1, now),
            Message::Response {
                sender,
                receiver,
                signed,
                mac1,
            } => self.response(from, sender, receiver, signed, mac1, now),
            Message::Cookie { receiver } => {
                if let Some(p) = self.pending.get(&receiver) {
                    Outcome::Forward(p.src)
                } else {
                    self.forward_to_owner(receiver, now)
                }
            }
            Message::Data { receiver } => {
                self.confirm_binding(from);
                self.forward_to_owner(receiver, now)
            }
        }
    }

    fn find_by_mac1(&self, signed: &[u8], mac1: &[u8]) -> Option<usize> {
        self.members
            .iter()
            .position(|m| m.mac1.matches(signed, mac1))
    }

    fn index_taken(&self, index: Index, src: PeerAddr) -> bool {
        self.sessions.contains_key(&index) || self.pending.get(&index).is_some_and(|p| p.src != src)
    }

    fn initiation(
        &mut self,
        from: PeerAddr,
        sender: Index,
        signed: &[u8],
        mac1: &[u8],
        now: Instant,
    ) -> Outcome {
        let Some(receiver) = self.find_by_mac1(signed, mac1) else {
            return Outcome::Drop(Drop::UnknownReceiver);
        };
        // Session index collision: drop it, WireGuard retries with a new index
        if self.index_taken(sender, from) {
            return Outcome::Drop(Drop::IndexCollision);
        }
        if self.pending.len() >= MAX_PENDING && !self.pending.contains_key(&sender) {
            return Outcome::Drop(Drop::TableFull);
        }
        let bound = self.members[receiver].bound;
        let candidates = match bound {
            Some(_) => Vec::new(),
            None => self.candidates_for(receiver, from),
        };
        let outcome = match (bound, candidates.as_slice()) {
            (Some(dest), _) => Outcome::Forward(dest),
            // Stay in the pending table first, until the other end's handshake initiation takes it
            // as a candidate address
            (None, []) => Outcome::Drop(Drop::ReceiverUnbound),
            (None, [dest]) => Outcome::Forward(*dest),
            (None, _) => Outcome::ForwardEach(candidates.clone()),
        };
        self.pending.insert(
            sender,
            Pending {
                src: from,
                receiver,
                candidates,
                at: now,
            },
        );
        outcome
    }

    /// Where a `receiver` that has no address yet might be: the source of the handshake initiation
    /// it sent. Its handshake initiation took one of its allocated peers as the receiver and is
    /// still in the pending table.
    fn candidates_for(&self, receiver: usize, from: PeerAddr) -> Vec<PeerAddr> {
        let mut out = Vec::new();
        for p in self.pending.values() {
            if out.len() >= MAX_CANDIDATES {
                break;
            }
            if p.src != from
                && p.receiver != receiver
                && self.connections.contains(&pair(receiver, p.receiver))
                && !out.contains(&p.src)
            {
                out.push(p.src);
            }
        }
        out
    }

    fn response(
        &mut self,
        from: PeerAddr,
        sender: Index,
        receiver: Index,
        signed: &[u8],
        mac1: &[u8],
        now: Instant,
    ) -> Outcome {
        let Some(initiator) = self.find_by_mac1(signed, mac1) else {
            return Outcome::Drop(Drop::UnknownReceiver);
        };
        let Some(pending) = self.pending.get(&receiver) else {
            return Outcome::Drop(Drop::NoPending);
        };
        let responder = pending.receiver;
        // A handshake response is accepted only from the responder's current bound address; when
        // the responder has no address yet, only from a candidate address the initiation was
        // forwarded to
        let from_responder = match self.members[responder].bound {
            Some(bound) => bound == from,
            None => pending.candidates.contains(&from),
        };
        if !from_responder {
            return Outcome::Drop(Drop::ResponseFromUnbound);
        }
        if !self.connections.contains(&pair(initiator, responder)) {
            return Outcome::Drop(Drop::NotAssigned);
        }
        if self.sessions.contains_key(&sender) || self.pending.contains_key(&sender) {
            return Outcome::Drop(Drop::IndexCollision);
        }
        if self.sessions.len() + 2 > MAX_SESSIONS {
            return Outcome::Drop(Drop::TableFull);
        }
        // The peer sent a response to the initiator's new address: update the initiator's binding,
        // and when the responder has no address yet, bind it as well (rate limited, then confirmed
        // later by data on the new address)
        let new_addr = pending.src;
        if !self.may_bind(initiator, new_addr, now) || !self.may_bind(responder, from, now) {
            return Outcome::Drop(Drop::BindRateLimited);
        }
        self.bind(initiator, new_addr, now);
        self.bind(responder, from, now);
        self.pending.remove(&receiver);
        self.sessions.insert(
            receiver,
            Session {
                owner: initiator,
                at: now,
            },
        );
        self.sessions.insert(
            sender,
            Session {
                owner: responder,
                at: now,
            },
        );
        Outcome::Forward(new_addr)
    }

    fn may_bind(&self, member: usize, addr: PeerAddr, now: Instant) -> bool {
        let m = &self.members[member];
        m.bound == Some(addr)
            || !m
                .last_change
                .is_some_and(|t| now.saturating_duration_since(t) < BIND_MIN_INTERVAL)
    }

    fn bind(&mut self, member: usize, addr: PeerAddr, now: Instant) {
        let m = &mut self.members[member];
        if m.bound != Some(addr) {
            m.unconfirmed = Some((m.bound, now));
            m.bound = Some(addr);
            m.last_change = Some(now);
        }
    }

    fn forward_to_owner(&mut self, receiver: Index, now: Instant) -> Outcome {
        let Some(session) = self.sessions.get_mut(&receiver) else {
            return Outcome::Drop(Drop::UnknownIndex);
        };
        session.at = now;
        match self.members[session.owner].bound {
            Some(dest) => Outcome::Forward(dest),
            None => Outcome::Drop(Drop::ReceiverUnbound),
        }
    }

    /// Data arrived on the new address: the binding is confirmed.
    fn confirm_binding(&mut self, from: PeerAddr) {
        for m in &mut self.members {
            if m.unconfirmed.is_some() && m.bound == Some(from) {
                m.unconfirmed = None;
            }
        }
    }

    fn probe(&self, from: PeerAddr, packet: &[u8], now_ms: u64) -> Outcome {
        match self.verify_probe(from, packet, now_ms) {
            Some((_, reply)) => Outcome::Reply(reply),
            None => Outcome::Drop(Drop::BadProbe),
        }
    }

    /// Verifies a relay probe and returns the member that sent it and the reply. The reply echoes
    /// the WireGuard address bound for this member, which is its mapped address (design/mesh.md
    /// section 6.1): the probe itself is sent from the mesh process's own port, so its source is
    /// not the WireGuard mapping. When no UDP address is bound yet, the probe's source is echoed;
    /// over TLS there is no mapped address.
    fn verify_probe(&self, from: PeerAddr, packet: &[u8], now_ms: u64) -> Option<(usize, Vec<u8>)> {
        let head = OuterProbe::peek(packet)?;
        let index = self.members.iter().position(|m| m.key_id == head.key_id)?;
        let member = &self.members[index];
        let probe = OuterProbe::verify(packet, &member.probe_key, now_ms)?;
        if probe.kind != RELAY_PROBE {
            return None;
        }
        let observed = match (member.bound, from) {
            (Some(PeerAddr::Udp(bound)), _) => bound,
            (_, PeerAddr::Udp(addr)) => addr,
            (_, PeerAddr::Tls(_)) => probe::UNSPECIFIED,
        };
        let reply = probe
            .reply(member.key_id, observed)
            .encode(&member.probe_key);
        Some((index, reply.to_vec()))
    }

    /// The first message on a TLS connection (design/mesh.md section 5.3): it must be an
    /// authenticated relay probe, from which the member is identified. On success returns the probe
    /// reply; when this member has no address yet, its address is this connection (the token
    /// already proves its identity).
    pub fn authenticate(&mut self, conn: ConnId, packet: &[u8], now_ms: u64) -> Option<Vec<u8>> {
        if packet.first() != Some(&RELAY_PROBE) {
            return None;
        }
        let (index, reply) = self.verify_probe(PeerAddr::Tls(conn), packet, now_ms)?;
        let member = &mut self.members[index];
        if member.bound.is_none() {
            member.bound = Some(PeerAddr::Tls(conn));
        }
        Some(reply)
    }

    /// A TLS connection closed: the member bound to it has no address, and is bound again when it
    /// reconnects and authenticates or via a handshake response.
    pub fn closed(&mut self, conn: ConnId) {
        let gone = Some(PeerAddr::Tls(conn));
        for m in &mut self.members {
            if m.bound == gone {
                m.bound = None;
                m.unconfirmed = None;
            }
            if m.unconfirmed.is_some_and(|(previous, _)| previous == gone) {
                m.unconfirmed = None;
            }
        }
        self.pending.retain(|_, p| p.src != PeerAddr::Tls(conn));
    }

    /// Called periodically: removes expired entries and restores bindings that were not confirmed.
    pub fn expire(&mut self, now: Instant) {
        self.pending
            .retain(|_, p| now.saturating_duration_since(p.at) < PENDING_TTL);
        self.sessions
            .retain(|_, s| now.saturating_duration_since(s.at) < SESSION_IDLE);
        for m in &mut self.members {
            if let Some((previous, at)) = m.unconfirmed
                && now.saturating_duration_since(at) >= BIND_CONFIRM
            {
                m.bound = previous;
                m.unconfirmed = None;
            }
        }
    }

    /// The state to save: address bindings and established entries (design/mesh.md section 5.2).
    /// Only session indexes and addresses, no keys.
    pub fn snapshot(&self, now: Instant) -> RelayState {
        RelayState {
            v: STATE_V1,
            bindings: self
                .members
                .iter()
                // TLS connections do not exist after a restart, so only UDP addresses are saved
                .filter_map(|m| match m.bound {
                    Some(PeerAddr::Udp(addr)) => Some(Binding {
                        public_key: m.public_key,
                        address: addr,
                    }),
                    _ => None,
                })
                .collect(),
            sessions: self
                .sessions
                .iter()
                .map(|(index, s)| SavedSession {
                    index: *index,
                    owner: self.members[s.owner].public_key,
                    idle_ms: u64::try_from(now.saturating_duration_since(s.at).as_millis())
                        .unwrap_or(u64::MAX),
                })
                .collect(),
        }
    }

    /// Restores saved state. Only members still in the allocation are restored; expired or
    /// conflicting entries are dropped.
    pub fn restore(&mut self, state: &RelayState, now: Instant) {
        if state.v != STATE_V1 {
            return;
        }
        let find = |members: &[Member], key: &X25519PublicKey| {
            members.iter().position(|m| m.public_key == *key)
        };
        for b in &state.bindings {
            if let Some(i) = find(&self.members, &b.public_key) {
                self.members[i].bound = Some(PeerAddr::Udp(b.address));
            }
        }
        for saved in &state.sessions {
            let idle = Duration::from_millis(saved.idle_ms);
            let Some(owner) = find(&self.members, &saved.owner) else {
                continue;
            };
            if idle >= SESSION_IDLE
                || self.sessions.len() >= MAX_SESSIONS
                || self.sessions.contains_key(&saved.index)
            {
                continue;
            }
            let at = now.checked_sub(idle).unwrap_or(now);
            self.sessions.insert(saved.index, Session { owner, at });
        }
    }

    pub fn table_sizes(&self) -> (usize, usize) {
        (self.pending.len(), self.sessions.len())
    }

    /// Applies a changed assignment in place (design/mesh.md section 5.2): members that remain keep
    /// their binding and their sessions, members that are gone lose theirs, and handshakes still
    /// pending are dropped (WireGuard retries them). An invalid assignment leaves the relay as it was.
    pub fn reassign(
        &mut self,
        members: &[AssignedMember],
        connections: &[(X25519PublicKey, X25519PublicKey)],
    ) -> Result<(), AssignmentError> {
        let mut next = Self::new(members, connections)?;
        let old: HashMap<X25519PublicKey, usize> = self
            .members
            .iter()
            .enumerate()
            .map(|(i, m)| (m.public_key, i))
            .collect();
        let mut moved = HashMap::new();
        for (i, m) in next.members.iter_mut().enumerate() {
            let Some(&o) = old.get(&m.public_key) else {
                continue;
            };
            moved.insert(o, i);
            let before = &self.members[o];
            // A binding learned from handshakes is newer than an address in the assignment
            if before.bound.is_some() {
                m.bound = before.bound;
                m.unconfirmed = before.unconfirmed;
                m.last_change = before.last_change;
            }
        }
        next.sessions = self
            .sessions
            .drain()
            .filter_map(|(index, s)| {
                let owner = *moved.get(&s.owner)?;
                Some((index, Session { owner, at: s.at }))
            })
            .collect();
        *self = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wg::tests::{data, initiation, response};
    use nett_mesh::probe::{OuterReply, RELAY_REPLY};

    const A: [u8; 32] = [1; 32];
    const B: [u8; 32] = [2; 32];
    const C: [u8; 32] = [3; 32];
    const D: [u8; 32] = [4; 32];
    const E: [u8; 32] = [5; 32];

    fn sock(s: &str) -> SocketAddr {
        s.parse().expect("addr")
    }

    fn addr(s: &str) -> PeerAddr {
        PeerAddr::Udp(sock(s))
    }

    /// A is `public` (its address is delivered with the allocation), B and C are `dial-only`; only
    /// A-B is allocated.
    fn relay() -> Relay {
        let member = |k: [u8; 32], a: Option<&str>| AssignedMember {
            public_key: X25519PublicKey::from_bytes(k),
            address: a.map(sock),
            token: [k[0]; 32],
        };
        Relay::new(
            &[
                member(A, Some("198.51.100.1:41820")),
                member(B, None),
                member(C, None),
            ],
            &[(
                X25519PublicKey::from_bytes(A),
                X25519PublicKey::from_bytes(B),
            )],
        )
        .expect("assignment")
    }

    fn handshake(r: &mut Relay, b_addr: &str, now: Instant, b_idx: Index, a_idx: Index) {
        assert_eq!(
            r.handle(addr(b_addr), &initiation(b_idx, &A), now, 0),
            Outcome::Forward(addr("198.51.100.1:41820"))
        );
        assert_eq!(
            r.handle(
                addr("198.51.100.1:41820"),
                &response(a_idx, b_idx, &B),
                now,
                0
            ),
            Outcome::Forward(addr(b_addr))
        );
    }

    #[test]
    fn forwards_handshake_and_data_and_binds_dial_only_member() {
        let mut r = relay();
        let now = Instant::now();
        handshake(&mut r, "203.0.113.5:50000", now, 11, 22);
        // A → B: delivered by receiver index 11 (B's) to the address B was just bound to
        assert_eq!(
            r.handle(addr("198.51.100.1:41820"), &data(11), now, 0),
            Outcome::Forward(addr("203.0.113.5:50000"))
        );
        assert_eq!(
            r.handle(addr("203.0.113.5:50000"), &data(22), now, 0),
            Outcome::Forward(addr("198.51.100.1:41820"))
        );
        assert_eq!(
            r.handle(addr("203.0.113.5:50000"), &data(33), now, 0),
            Outcome::Drop(Drop::UnknownIndex)
        );
    }

    #[test]
    fn a_new_assignment_keeps_the_links_that_remain() {
        let mut r = relay();
        let now = Instant::now();
        handshake(&mut r, "203.0.113.5:50000", now, 11, 22);
        let key = X25519PublicKey::from_bytes;
        let member = |k: [u8; 32], a: Option<&str>| AssignedMember {
            public_key: key(k),
            address: a.map(sock),
            token: [k[0]; 32],
        };
        // C joins with a link to A; B and A keep their link, binding and sessions
        r.reassign(
            &[
                member(C, None),
                member(B, None),
                member(A, Some("198.51.100.1:41820")),
            ],
            &[(key(A), key(B)), (key(A), key(C))],
        )
        .expect("reassigned");
        assert_eq!(
            r.handle(addr("198.51.100.1:41820"), &data(11), now, 0),
            Outcome::Forward(addr("203.0.113.5:50000")),
            "the session to B survives"
        );
        assert_eq!(
            r.handle(addr("203.0.113.5:50000"), &data(22), now, 0),
            Outcome::Forward(addr("198.51.100.1:41820"))
        );
        // B's link is removed: its sessions go with it
        r.reassign(
            &[member(A, Some("198.51.100.1:41820")), member(C, None)],
            &[(key(A), key(C))],
        )
        .expect("reassigned");
        assert_eq!(
            r.handle(addr("198.51.100.1:41820"), &data(11), now, 0),
            Outcome::Drop(Drop::UnknownIndex)
        );
        // An invalid assignment changes nothing
        assert!(r.reassign(&[member(A, None)], &[(key(A), key(D))]).is_err());
        assert_eq!(r.members.len(), 2);
    }

    #[test]
    fn rejects_unassigned_pairs_and_unknown_receivers() {
        let mut r = relay();
        let now = Instant::now();
        // C has no allocation with A: A's response is not accepted
        assert!(matches!(
            r.handle(addr("203.0.113.9:1"), &initiation(5, &A), now, 0),
            Outcome::Forward(_)
        ));
        assert_eq!(
            r.handle(addr("198.51.100.1:41820"), &response(6, 5, &C), now, 0),
            Outcome::Drop(Drop::NotAssigned)
        );
        // The receiver is not any member
        assert_eq!(
            r.handle(addr("203.0.113.9:1"), &initiation(7, &[9; 32]), now, 0),
            Outcome::Drop(Drop::UnknownReceiver)
        );
    }

    /// D and E are both `dial-only` and neither has an address yet.
    fn dial_only_pair() -> Relay {
        let member = |k: [u8; 32]| AssignedMember {
            public_key: X25519PublicKey::from_bytes(k),
            address: None,
            token: [k[0]; 32],
        };
        Relay::new(
            &[member(D), member(E), member(C)],
            &[(
                X25519PublicKey::from_bytes(D),
                X25519PublicKey::from_bytes(E),
            )],
        )
        .expect("assignment")
    }

    #[test]
    fn two_unbound_dial_only_members_meet() {
        let mut r = dial_only_pair();
        let now = Instant::now();
        let (d, e) = (addr("203.0.113.4:40000"), addr("192.0.2.5:50000"));
        // D arrives first: E's address is unknown, so the handshake initiation stays in the pending
        // table
        assert_eq!(
            r.handle(d, &initiation(41, &E), now, 0),
            Outcome::Drop(Drop::ReceiverUnbound)
        );
        // E's handshake initiation is forwarded to the address D might be at; D replies from there
        // and both ends are bound together
        assert_eq!(
            r.handle(e, &initiation(51, &D), now, 0),
            Outcome::Forward(d)
        );
        assert_eq!(
            r.handle(d, &response(42, 51, &E), now, 0),
            Outcome::Forward(e)
        );
        assert_eq!(r.handle(d, &data(51), now, 0), Outcome::Forward(e));
        assert_eq!(r.handle(e, &data(42), now, 0), Outcome::Forward(d));
    }

    #[test]
    fn unbound_responder_must_answer_from_a_candidate() {
        let mut r = dial_only_pair();
        let now = Instant::now();
        let (d, e) = (addr("203.0.113.4:40000"), addr("192.0.2.5:50000"));
        r.handle(d, &initiation(41, &E), now, 0);
        r.handle(e, &initiation(51, &D), now, 0);
        assert_eq!(
            r.handle(addr("198.51.100.66:1"), &response(42, 51, &E), now, 0),
            Outcome::Drop(Drop::ResponseFromUnbound)
        );
        // A handshake initiation that was never forwarded (D's) does not get the responder's
        // address
        assert_eq!(
            r.handle(e, &response(52, 41, &D), now, 0),
            Outcome::Drop(Drop::ResponseFromUnbound)
        );
        // A handshake initiation whose receiver is a member not allocated to D (C): the source is
        // not a candidate address of D
        let mut r = dial_only_pair();
        r.handle(addr("198.51.100.3:1"), &initiation(61, &C), now, 0);
        assert_eq!(
            r.handle(e, &initiation(51, &D), now, 0),
            Outcome::Drop(Drop::ReceiverUnbound)
        );
    }

    #[test]
    fn response_must_come_from_the_bound_address() {
        let mut r = relay();
        let now = Instant::now();
        r.handle(addr("203.0.113.5:50000"), &initiation(11, &A), now, 0);
        assert_eq!(
            r.handle(addr("192.0.2.66:41820"), &response(22, 11, &B), now, 0),
            Outcome::Drop(Drop::ResponseFromUnbound)
        );
    }

    #[test]
    fn index_collisions_drop_the_newcomer() {
        let mut r = relay();
        let now = Instant::now();
        handshake(&mut r, "203.0.113.5:50000", now, 11, 22);
        assert_eq!(
            r.handle(addr("203.0.113.7:50000"), &initiation(22, &A), now, 0),
            Outcome::Drop(Drop::IndexCollision)
        );
    }

    #[test]
    fn rebinding_needs_data_from_the_new_address() {
        let mut r = relay();
        let t0 = Instant::now();
        handshake(&mut r, "203.0.113.5:50000", t0, 11, 22);
        r.handle(addr("203.0.113.5:50000"), &data(22), t0, 0);
        // B changed address and handshook again; afterwards no data arrives on the new address:
        // after 10 seconds the old binding is restored
        let t1 = t0 + Duration::from_secs(30);
        handshake(&mut r, "203.0.113.6:50001", t1, 13, 24);
        r.expire(t1 + BIND_CONFIRM);
        assert_eq!(
            r.handle(addr("198.51.100.1:41820"), &data(11), t1 + BIND_CONFIRM, 0),
            Outcome::Forward(addr("203.0.113.5:50000"))
        );
    }

    #[test]
    fn rebinding_is_rate_limited() {
        let mut r = relay();
        let t0 = Instant::now();
        handshake(&mut r, "203.0.113.5:50000", t0, 11, 22);
        r.handle(addr("203.0.113.6:50001"), &initiation(13, &A), t0, 0);
        assert_eq!(
            r.handle(
                addr("198.51.100.1:41820"),
                &response(24, 13, &B),
                t0 + Duration::from_millis(500),
                0
            ),
            Outcome::Drop(Drop::BindRateLimited)
        );
    }

    #[test]
    fn expires_idle_entries() {
        let mut r = relay();
        let t0 = Instant::now();
        handshake(&mut r, "203.0.113.5:50000", t0, 11, 22);
        r.handle(addr("203.0.113.9:1"), &initiation(40, &A), t0, 0);
        assert_eq!(r.table_sizes(), (1, 2));
        r.expire(t0 + PENDING_TTL);
        assert_eq!(r.table_sizes(), (0, 2));
        r.expire(t0 + SESSION_IDLE);
        assert_eq!(r.table_sizes(), (0, 0));
    }

    #[test]
    fn restored_state_keeps_forwarding() {
        let mut r = relay();
        let now = Instant::now();
        handshake(&mut r, "203.0.113.5:50000", now, 11, 22);
        let saved = r.snapshot(now + Duration::from_secs(1));
        let text = serde_json::to_string(&saved).expect("serialize");
        // Restart: the new relay has only the allocation and no index table; after restoring, data
        // in both directions is forwarded as usual
        let mut restarted = relay();
        assert_eq!(
            restarted.handle(addr("198.51.100.1:41820"), &data(11), now, 0),
            Outcome::Drop(Drop::UnknownIndex)
        );
        restarted.restore(&serde_json::from_str(&text).expect("parse"), now);
        assert_eq!(
            restarted.handle(addr("198.51.100.1:41820"), &data(11), now, 0),
            Outcome::Forward(addr("203.0.113.5:50000"))
        );
        assert_eq!(
            restarted.handle(addr("203.0.113.5:50000"), &data(22), now, 0),
            Outcome::Forward(addr("198.51.100.1:41820"))
        );
        // Entries that have already expired are not restored
        let mut stale = relay();
        stale.restore(&r.snapshot(now + SESSION_IDLE), now);
        assert_eq!(stale.table_sizes(), (0, 0));
    }

    #[test]
    fn answers_authenticated_probes_only() {
        let r = relay();
        let key = ProbeKey::from_token(&[2; 32]);
        let id = KeyId::of(&B);
        let probe = OuterProbe {
            kind: RELAY_PROBE,
            key_id: id,
            seq: 4,
            sent_ms: 1_000,
        };
        let from = addr("203.0.113.5:40000");
        let Outcome::Reply(reply) = r.probe(from, &probe.encode(&key), 1_000) else {
            panic!("expected a reply");
        };
        let decoded = OuterReply::verify(&reply, &key).expect("valid reply");
        assert_eq!(
            (decoded.kind, decoded.seq, decoded.observed),
            (RELAY_REPLY, 4, sock("203.0.113.5:40000"))
        );
        // Use another member's token
        let wrong = probe.encode(&ProbeKey::from_token(&[3; 32]));
        assert_eq!(r.probe(from, &wrong, 1_000), Outcome::Drop(Drop::BadProbe));
        // Expired
        assert_eq!(
            r.probe(from, &probe.encode(&key), 100_000),
            Outcome::Drop(Drop::BadProbe)
        );
    }

    #[test]
    fn probe_replies_echo_the_bound_wireguard_address() {
        let mut r = relay();
        let now = Instant::now();
        handshake(&mut r, "203.0.113.5:50000", now, 11, 22);
        let key = ProbeKey::from_token(&[2; 32]);
        let probe = OuterProbe {
            kind: RELAY_PROBE,
            key_id: KeyId::of(&B),
            seq: 1,
            sent_ms: 1_000,
        };
        // The probe is sent from the mesh process's own port; what is echoed is the WireGuard
        // mapping bound during the handshake
        let Outcome::Reply(reply) = r.probe(addr("203.0.113.5:40999"), &probe.encode(&key), 1_000)
        else {
            panic!("expected a reply");
        };
        let decoded = OuterReply::verify(&reply, &key).expect("valid reply");
        assert_eq!(decoded.observed, sock("203.0.113.5:50000"));
    }

    #[test]
    fn tls_connection_authenticates_with_the_first_probe() {
        let mut r = relay();
        let now = Instant::now();
        let conn = ConnId(7);
        let key = ProbeKey::from_token(&[2; 32]);
        let probe = OuterProbe {
            kind: RELAY_PROBE,
            key_id: KeyId::of(&B),
            seq: 1,
            sent_ms: 1_000,
        };
        // Not a probe, or wrong token: neither authenticates
        assert_eq!(r.authenticate(conn, &initiation(11, &A), 1_000), None);
        let wrong = probe.encode(&ProbeKey::from_token(&[9; 32]));
        assert_eq!(r.authenticate(conn, &wrong, 1_000), None);
        // After B authenticates, the connection is B's address: the handshake A sends to B is
        // delivered over this connection
        let reply = r
            .authenticate(conn, &probe.encode(&key), 1_000)
            .expect("authenticated");
        let decoded = OuterReply::verify(&reply, &key).expect("valid reply");
        assert_eq!(decoded.observed, probe::UNSPECIFIED);
        let tls = PeerAddr::Tls(conn);
        assert_eq!(
            r.handle(tls, &initiation(11, &A), now, 0),
            Outcome::Forward(addr("198.51.100.1:41820"))
        );
        assert_eq!(
            r.handle(addr("198.51.100.1:41820"), &response(22, 11, &B), now, 0),
            Outcome::Forward(tls)
        );
        assert_eq!(
            r.handle(addr("198.51.100.1:41820"), &data(11), now, 0),
            Outcome::Forward(tls)
        );
        // Connection closed: B has no address, and data sent to it is dropped; after it reconnects
        // and authenticates it is restored
        r.closed(conn);
        assert_eq!(
            r.handle(addr("198.51.100.1:41820"), &data(11), now, 0),
            Outcome::Drop(Drop::ReceiverUnbound)
        );
        let again = ConnId(8);
        r.authenticate(again, &probe.encode(&key), 1_000)
            .expect("authenticated");
        assert_eq!(
            r.handle(addr("198.51.100.1:41820"), &data(11), now, 0),
            Outcome::Forward(PeerAddr::Tls(again))
        );
        // Only UDP addresses are saved
        assert!(
            r.snapshot(now)
                .bindings
                .iter()
                .all(|b| b.public_key != X25519PublicKey::from_bytes(B))
        );
    }
}
