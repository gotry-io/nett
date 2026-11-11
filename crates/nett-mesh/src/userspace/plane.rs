//! Core of the userspace data plane (design/userspace.md section 4): does no I/O. The data plane thread
//! hands it the packets received on the WireGuard port and the TUN, and sends and receives according to
//! the [`Action`] it returns; control commands are executed in the same thread, so state needs no locks.
//!
//! Inbound: demultiplex -> decrypt -> validate the inner packet -> the source must be within that peer's
//! `AllowedIPs` -> the destination must be this machine -> filter -> TUN.
//! Outbound: TUN -> longest prefix match of the destination address to a peer -> record the connection ->
//! encrypt -> the peer's current endpoint. A packet that fails any step is dropped with no response.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime};

use nett_core::prefix::IpPrefix;
use nett_trust::keys::X25519PublicKey;

use super::filter::Filter;
use super::packet;
use super::session::{Output, Sessions};
use crate::access::FilterSpec;
use crate::dataplane::{PeerSpec, PeerStat};
use crate::probe::{DIRECT_PROBE, DIRECT_REPLY, OUTER_LEN, WG_COOKIE_LEN, WG_COOKIE_REPLY};

/// The maximum number of handshake messages per source IP per second that enter the session layer
/// (design/userspace.md section 4.1). It is higher than the threshold at which the session layer replies
/// with a cookie (100 per second), and the part in between gets a cookie as usual.
pub const HANDSHAKES_PER_SOURCE: u32 = 128;
/// The maximum number of handshake messages per second, summed over all sources, that enter the session
/// layer.
pub const HANDSHAKES_TOTAL: u32 = 2048;
/// The maximum number of entries in the handshake limit's source table; once full, new sources within
/// that second are all over the limit.
pub const HANDSHAKE_SOURCES: usize = 4096;
const BUDGET_WINDOW: Duration = Duration::from_secs(1);

/// Limit on handshake messages: counted per source IP and reset every second. Over-limit ones are dropped
/// before any encryption or decryption, so a flood costs only one receive and one table lookup.
#[derive(Debug)]
struct HandshakeBudget {
    window: Instant,
    total: u32,
    sources: HashMap<IpAddr, u32>,
}

impl HandshakeBudget {
    fn new(now: Instant) -> Self {
        Self {
            window: now,
            total: 0,
            sources: HashMap::new(),
        }
    }

    fn admit(&mut self, from: IpAddr, now: Instant) -> bool {
        if now.saturating_duration_since(self.window) >= BUDGET_WINDOW {
            self.window = now;
            self.total = 0;
            self.sources.clear();
        }
        if self.total >= HANDSHAKES_TOTAL {
            return false;
        }
        let full = self.sources.len() >= HANDSHAKE_SOURCES;
        let count = match self.sources.get_mut(&from) {
            Some(count) => count,
            None if full => return false,
            None => self.sources.entry(from).or_insert(0),
        };
        if *count >= HANDSHAKES_PER_SOURCE {
            return false;
        }
        *count += 1;
        self.total += 1;
        true
    }
}

/// Actions for the data plane to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send from the WireGuard port.
    Udp { to: SocketAddr, datagram: Vec<u8> },
    /// Write to the TUN, handing it to this machine's protocol stack.
    Tun(Vec<u8>),
    /// Hand to the engine ([`crate::prober::Incoming::Direct`]): direct probe messages, and copies of cookie
    /// replies.
    Probe { from: SocketAddr, data: Vec<u8> },
}

#[derive(Debug)]
struct Peer {
    key: X25519PublicKey,
    allowed: Vec<IpPrefix>,
    endpoint: Option<SocketAddr>,
    keepalive: Option<u16>,
    rx_bytes: u64,
    tx_bytes: u64,
}

impl Peer {
    fn new(spec: &PeerSpec) -> Self {
        Self {
            key: spec.public_key,
            allowed: spec.allowed_ips.clone(),
            endpoint: spec.endpoint,
            keepalive: spec.persistent_keepalive,
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("no peer with this public key")]
pub struct UnknownPeer;

pub struct Plane<S> {
    sessions: S,
    peers: Vec<Peer>,
    filter: Filter,
    /// This machine's mesh addresses: only packets addressed to them are written to the TUN.
    local: Vec<IpAddr>,
    /// Idle TLS loopback ports: packets coming in from them are dropped (design/mesh.md section 5.3).
    guarded: BTreeSet<u16>,
    handshakes: HandshakeBudget,
}

impl<S: Sessions> Plane<S> {
    pub fn new(sessions: S) -> Self {
        Self {
            sessions,
            peers: Vec::new(),
            filter: Filter::default(),
            local: Vec::new(),
            guarded: BTreeSet::new(),
            handshakes: HandshakeBudget::new(Instant::now()),
        }
    }

    pub fn set_local(&mut self, local: Vec<IpAddr>) {
        self.filter.set_local(local.clone());
        self.local = local;
    }

    pub fn set_filter(&mut self, filter: FilterSpec) {
        self.filter.set_rules(filter);
    }

    pub fn guard_tls_ports(&mut self, idle: &[u16]) {
        self.guarded = idle.iter().copied().collect();
    }

    /// Makes the peers exactly `peers`. An existing peer with an empty `endpoint` keeps its current endpoint;
    /// existing sessions are unchanged.
    pub fn sync_peers(&mut self, peers: &[PeerSpec]) {
        let mut next = Vec::with_capacity(peers.len());
        for spec in peers {
            let mut peer = match self.peers.iter().position(|p| p.key == spec.public_key) {
                Some(i) => self.peers.swap_remove(i),
                None => Peer::new(spec),
            };
            peer.allowed.clone_from(&spec.allowed_ips);
            peer.keepalive = spec.persistent_keepalive;
            if spec.endpoint.is_some() {
                peer.endpoint = spec.endpoint;
            }
            next.push(peer);
        }
        self.peers = next;
        let keys: Vec<_> = self.peers.iter().map(|p| (p.key, p.keepalive)).collect();
        self.sessions.sync(&keys);
    }

    pub fn set_endpoint(
        &mut self,
        key: &X25519PublicKey,
        endpoint: SocketAddr,
    ) -> Result<(), UnknownPeer> {
        let peer = self
            .peers
            .iter_mut()
            .find(|p| p.key == *key)
            .ok_or(UnknownPeer)?;
        peer.endpoint = Some(endpoint);
        Ok(())
    }

    /// The same as "delete the peer and add it back" on the kernel: the session and counters are reset, and
    /// the next packet triggers a new handshake.
    pub fn rehandshake(&mut self, spec: &PeerSpec) -> Result<(), UnknownPeer> {
        let peer = self
            .peers
            .iter_mut()
            .find(|p| p.key == spec.public_key)
            .ok_or(UnknownPeer)?;
        *peer = Peer::new(spec);
        self.sessions.reset(&spec.public_key);
        Ok(())
    }

    pub fn stats(&self, now: SystemTime) -> Vec<PeerStat> {
        self.peers
            .iter()
            .map(|p| PeerStat {
                public_key: p.key,
                endpoint: p.endpoint,
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
                last_handshake: self
                    .sessions
                    .since_handshake(&p.key)
                    .and_then(|d| now.checked_sub(d)),
            })
            .collect()
    }

    /// A packet received on the WireGuard port.
    pub fn from_udp(
        &mut self,
        from: SocketAddr,
        datagram: &[u8],
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        if from.ip().is_loopback() && self.guarded.contains(&from.port()) {
            return;
        }
        match datagram.first() {
            Some(1 | 2) => {
                if !self.handshakes.admit(from.ip(), now) {
                    return;
                }
            }
            Some(3 | 4) => {}
            Some(&kind) if (DIRECT_PROBE..=DIRECT_REPLY).contains(&kind) => {
                if datagram.len() == OUTER_LEN {
                    out.push(Action::Probe {
                        from,
                        data: datagram.to_vec(),
                    });
                }
                return;
            }
            _ => return,
        }
        if datagram[0] == WG_COOKIE_REPLY && datagram.len() == WG_COOKIE_LEN {
            out.push(Action::Probe {
                from,
                data: datagram.to_vec(),
            });
        }
        let mut outputs = Vec::new();
        self.sessions.receive(from, datagram, &mut outputs);
        let mut authenticated = None;
        for o in outputs {
            match o {
                Output::Authenticated { peer, from } => {
                    if let Some(p) = self.peer_mut(&peer) {
                        p.endpoint = Some(from);
                        p.rx_bytes += datagram.len() as u64;
                        authenticated = Some(peer);
                    }
                }
                Output::SendTo { to, datagram } => {
                    if let Some(p) = authenticated.and_then(|k| self.peer_mut(&k)) {
                        p.tx_bytes += datagram.len() as u64;
                    }
                    out.push(Action::Udp { to, datagram });
                }
                Output::SendToPeer { peer, datagram } => self.send_to_peer(&peer, datagram, out),
                Output::Deliver { peer, packet } => self.deliver(&peer, packet, now, out),
            }
        }
    }

    /// A packet read from the TUN: traffic from this machine to the mesh.
    pub fn from_tun(&mut self, packet: &[u8], now: Instant, out: &mut Vec<Action>) {
        let Some(ip) = packet::parse(packet) else {
            return;
        };
        // macOS routes this machine's own mesh address into the utun (design/userspace.md section 4):
        // handed back, the packet is delivered locally
        if self.local.contains(&ip.dst) {
            out.push(Action::Tun(packet[..ip.len].to_vec()));
            return;
        }
        let Some(key) = self.route(ip.dst) else {
            return;
        };
        self.filter.outbound(&ip, now);
        let mut outputs = Vec::new();
        self.sessions.send(&key, &packet[..ip.len], &mut outputs);
        self.apply(outputs, now, out);
    }

    /// Advances the session timers and cleans up expired connections. Called once every
    /// [`super::session::TIMER_TICK`].
    pub fn tick(&mut self, now: Instant, out: &mut Vec<Action>) {
        let mut outputs = Vec::new();
        self.sessions.tick(&mut outputs);
        self.apply(outputs, now, out);
        self.filter.expire(now);
    }

    fn apply(&mut self, outputs: Vec<Output>, now: Instant, out: &mut Vec<Action>) {
        for o in outputs {
            match o {
                Output::SendToPeer { peer, datagram } => self.send_to_peer(&peer, datagram, out),
                Output::SendTo { to, datagram } => out.push(Action::Udp { to, datagram }),
                Output::Deliver { peer, packet } => self.deliver(&peer, packet, now, out),
                Output::Authenticated { .. } => {}
            }
        }
    }

    fn peer_mut(&mut self, key: &X25519PublicKey) -> Option<&mut Peer> {
        self.peers.iter_mut().find(|p| p.key == *key)
    }

    /// Dropped when the peer has no endpoint yet (a `dial-only` peer waiting for it to connect first).
    fn send_to_peer(&mut self, key: &X25519PublicKey, datagram: Vec<u8>, out: &mut Vec<Action>) {
        let Some(peer) = self.peer_mut(key) else {
            return;
        };
        let Some(to) = peer.endpoint else {
            return;
        };
        peer.tx_bytes += datagram.len() as u64;
        out.push(Action::Udp { to, datagram });
    }

    /// Longest prefix match: the longest prefix among the peer's `AllowedIPs` that contains `dst`.
    fn route(&self, dst: IpAddr) -> Option<X25519PublicKey> {
        self.peers
            .iter()
            .flat_map(|p| p.allowed.iter().map(move |a| (a, p.key)))
            .filter(|(a, _)| a.contains(dst))
            .max_by_key(|(a, _)| a.prefix_len())
            .map(|(_, key)| key)
    }

    fn deliver(
        &mut self,
        key: &X25519PublicKey,
        mut packet: Vec<u8>,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let Some(ip) = packet::parse(&packet) else {
            return;
        };
        let Some(peer) = self.peers.iter().find(|p| p.key == *key) else {
            return;
        };
        // The source address is guaranteed by WireGuard's public key: only addresses this peer is allowed to use
        // are accepted
        if !peer.allowed.iter().any(|a| a.contains(ip.src)) {
            return;
        }
        if !self.local.contains(&ip.dst) {
            return;
        }
        if !self.filter.inbound(&ip, now) {
            return;
        }
        packet.truncate(ip.len);
        out.push(Action::Tun(packet));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{FilterRule, Match};
    use crate::key::PrivateKey;
    use crate::userspace::packet::build;
    use crate::userspace::session::Gotatun;

    const SYN: u8 = 0x02;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect(s)
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().expect(s)
    }

    struct Node {
        plane: Plane<Gotatun>,
        key: X25519PublicKey,
        mesh: IpAddr,
        at: SocketAddr,
    }

    fn node(mesh: &str, at: &str) -> Node {
        let private = PrivateKey::generate().expect("key");
        let mut plane = Plane::new(Gotatun::new(&private));
        plane.set_local(vec![ip(mesh)]);
        Node {
            plane,
            key: private.public_key(),
            mesh: ip(mesh),
            at: sa(at),
        }
    }

    fn spec(of: &Node, endpoint: Option<SocketAddr>) -> PeerSpec {
        PeerSpec {
            public_key: of.key,
            allowed_ips: vec![IpPrefix::host(of.mesh)],
            endpoint,
            persistent_keepalive: None,
        }
    }

    /// a and b are peers of each other; `open` when b allows all connections from a.
    fn pair(open: bool) -> (Node, Node) {
        let mut a = node("100.88.0.1", "198.51.100.1:41820");
        let mut b = node("100.88.0.2", "198.51.100.2:41820");
        a.plane.sync_peers(&[spec(&b, Some(b.at))]);
        b.plane.sync_peers(&[spec(&a, None)]);
        if open {
            b.plane.set_filter(FilterSpec {
                rules: vec![FilterRule {
                    matches: vec![Match::Source(IpPrefix::host(a.mesh))],
                    accept: true,
                }],
            });
        }
        (a, b)
    }

    /// Delivers UDP packets addressed to the other side back and forth between a and b until there are no new
    /// ones; returns the packets both sides wrote to the TUN.
    fn exchange(a: &mut Node, b: &mut Node, from_a: Vec<Action>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let now = Instant::now();
        let (mut tun_a, mut tun_b) = (Vec::new(), Vec::new());
        let mut pending: Vec<(bool, Action)> = from_a.into_iter().map(|x| (true, x)).collect();
        let mut rounds = 0;
        while let Some((by_a, action)) = pending.pop() {
            rounds += 1;
            assert!(rounds < 100, "packets keep bouncing");
            let (sender, receiver, tun) = if by_a {
                (&*a, &mut *b, &mut tun_b)
            } else {
                (&*b, &mut *a, &mut tun_a)
            };
            if let Action::Udp { to, datagram } = action {
                assert_eq!(to, receiver.at);
                let mut out = Vec::new();
                receiver.plane.from_udp(sender.at, &datagram, now, &mut out);
                for o in out {
                    match o {
                        Action::Tun(p) => tun.push(p),
                        other => pending.push((!by_a, other)),
                    }
                }
            }
        }
        (tun_a, tun_b)
    }

    fn send(n: &mut Node, packet: &[u8]) -> Vec<Action> {
        let mut out = Vec::new();
        n.plane.from_tun(packet, Instant::now(), &mut out);
        out
    }

    #[test]
    fn a_packet_to_this_machines_own_address_goes_back_to_the_tun() {
        let (mut a, _b) = pair(false);
        let query = build::udp(a.mesh, 50000, a.mesh, 53);
        let out = send(&mut a, &query);
        assert!(
            matches!(out.as_slice(), [Action::Tun(p)] if *p == query),
            "{out:?}"
        );
    }

    #[test]
    fn packets_cross_after_the_handshake_and_learn_the_endpoint() {
        let (mut a, mut b) = pair(true);
        let syn = build::tcp(a.mesh, 40000, b.mesh, 22, SYN);
        let out = send(&mut a, &syn);
        let (_, at_b) = exchange(&mut a, &mut b, out);
        assert_eq!(at_b, [syn]);
        // b learns a's endpoint from an authenticated packet
        let stat = &b.plane.stats(SystemTime::now())[0];
        assert_eq!(stat.endpoint, Some(a.at));
        assert!(stat.last_handshake.is_some() && stat.rx_bytes > 0 && stat.tx_bytes > 0);

        // Return direction: b's TCP reply (with ACK) is allowed directly on a, even if a has no rules at all
        let reply = build::tcp(b.mesh, 22, a.mesh, 40000, SYN | 0x10);
        let out = send(&mut b, &reply);
        let (_, at_a) = exchange(&mut b, &mut a, out);
        assert_eq!(at_a, [reply]);
    }

    #[test]
    fn denied_spoofed_and_misaddressed_packets_are_dropped() {
        let (mut a, mut b) = pair(false);
        // No rules: new connections are rejected
        let packet = build::tcp(a.mesh, 1, b.mesh, 22, SYN);
        let out = send(&mut a, &packet);
        assert!(exchange(&mut a, &mut b, out).1.is_empty());

        let (mut a, mut b) = pair(true);
        // a forges the source: b accepts only the addresses a is allowed to use
        let forged = build::udp(ip("100.88.0.9"), 1, b.mesh, 53);
        let out = send_raw(&mut a, &b, &forged);
        assert!(exchange(&mut a, &mut b, out).1.is_empty());
        // The destination is not b's address
        let elsewhere = build::udp(a.mesh, 1, ip("100.88.0.7"), 53);
        let out = send_raw(&mut a, &b, &elsewhere);
        assert!(exchange(&mut a, &mut b, out).1.is_empty());
        // Comparison: a normal packet on the same session gets through
        let ok = build::udp(a.mesh, 1, b.mesh, 53);
        let out = send(&mut a, &ok);
        assert_eq!(exchange(&mut a, &mut b, out).1, [ok]);
    }

    /// Without going through a's path selection and filtering, encrypts a packet directly with the session of
    /// a and b: simulates a compromised member.
    fn send_raw(a: &mut Node, b: &Node, packet: &[u8]) -> Vec<Action> {
        let mut outputs = Vec::new();
        a.plane.sessions.send(&b.key, packet, &mut outputs);
        let mut out = Vec::new();
        a.plane.apply(outputs, Instant::now(), &mut out);
        out
    }

    #[test]
    fn padding_is_stripped_before_the_tun() {
        let (mut a, mut b) = pair(true);
        // The length is not a multiple of 16: the session layer pads it, and it is stripped before writing to the
        // TUN
        let odd = build::echo(a.mesh, b.mesh, true, 1);
        assert_ne!(odd.len() % 16, 0);
        let out = send(&mut a, &odd);
        assert_eq!(exchange(&mut a, &mut b, out).1, [odd]);
    }

    #[test]
    fn probes_and_cookie_copies_go_to_the_engine() {
        let (_, mut b) = pair(true);
        let from = sa("203.0.113.5:41820");
        let now = Instant::now();
        let mut out = Vec::new();
        let mut probe = vec![DIRECT_PROBE; OUTER_LEN];
        b.plane.from_udp(from, &probe, now, &mut out);
        probe.truncate(OUTER_LEN - 1);
        b.plane.from_udp(from, &probe, now, &mut out);
        b.plane.from_udp(from, &[0x80; OUTER_LEN], now, &mut out);
        b.plane.from_udp(from, &[], now, &mut out);
        let mut cookie = vec![0u8; WG_COOKIE_LEN];
        cookie[0] = WG_COOKIE_REPLY;
        b.plane.from_udp(from, &cookie, now, &mut out);
        assert_eq!(
            out,
            [
                Action::Probe {
                    from,
                    data: vec![DIRECT_PROBE; OUTER_LEN]
                },
                Action::Probe { from, data: cookie }
            ]
        );
    }

    #[test]
    fn handshake_floods_are_capped_per_source_and_in_total() {
        let start = Instant::now();
        let mut budget = HandshakeBudget::new(start);
        let flooder = ip("203.0.113.66");
        let admitted = (0..10_000).filter(|_| budget.admit(flooder, start)).count();
        assert_eq!(admitted, HANDSHAKES_PER_SOURCE as usize);
        // The flood used up its own quota and other sources are not affected
        assert!(budget.admit(ip("198.51.100.3"), start));
        // Counting starts over in the next second
        assert!(budget.admit(flooder, start + BUDGET_WINDOW));

        // Many sources: the total does not exceed the overall limit, and the source table does not exceed its
        // upper limit
        let mut budget = HandshakeBudget::new(start);
        let mut total = 0;
        for i in 0..20_000u32 {
            let src = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            total += (0..4).filter(|_| budget.admit(src, start)).count();
        }
        assert_eq!(total, HANDSHAKES_TOTAL as usize);
        assert!(budget.sources.len() <= HANDSHAKE_SOURCES);
    }

    #[test]
    fn over_budget_handshakes_get_no_response() {
        let (mut a, mut b) = pair(true);
        let packet = build::udp(a.mesh, 1, b.mesh, 53);
        let out = send(&mut a, &packet);
        let Some(Action::Udp { datagram, .. }) = out.first().cloned() else {
            panic!("handshake initiation");
        };
        let now = Instant::now();
        let mut at_b = Vec::new();
        // Flood: garbage packets of type 1 use up this source's quota (they get no response themselves)
        let mut junk = vec![0x5a; 148];
        junk[0] = 1;
        for _ in 0..HANDSHAKES_PER_SOURCE {
            b.plane
                .from_udp(sa("203.0.113.66:5000"), &junk, now, &mut at_b);
        }
        assert!(at_b.is_empty(), "{at_b:?}");
        // After the limit is exceeded, even valid handshakes from the same source are not handed to the session
        // layer, with no response
        b.plane
            .from_udp(sa("203.0.113.66:5000"), &datagram, now, &mut at_b);
        assert!(at_b.is_empty(), "{at_b:?}");
        // Another source (a's real address) completes the handshake as usual
        assert_eq!(exchange(&mut a, &mut b, out).1, [packet]);
    }

    #[test]
    fn idle_tls_ports_are_dropped() {
        let (mut a, mut b) = pair(true);
        let packet = build::udp(a.mesh, 1, b.mesh, 53);
        let out = send(&mut a, &packet);
        let Some(Action::Udp { datagram, .. }) = out.first().cloned() else {
            panic!("handshake initiation");
        };
        b.plane.guard_tls_ports(&[50000]);
        let mut at_b = Vec::new();
        b.plane
            .from_udp(sa("127.0.0.1:50000"), &datagram, Instant::now(), &mut at_b);
        assert!(at_b.is_empty());
        b.plane
            .from_udp(sa("127.0.0.1:50001"), &datagram, Instant::now(), &mut at_b);
        assert!(!at_b.is_empty(), "other loopback ports are used by TLS");
    }

    #[test]
    fn sync_keeps_learned_endpoints_and_rehandshake_resets() {
        let (mut a, mut b) = pair(true);
        let packet = build::udp(a.mesh, 1, b.mesh, 53);
        let out = send(&mut a, &packet);
        exchange(&mut a, &mut b, out);
        b.plane.sync_peers(&[spec(&a, None)]);
        let stat = b.plane.stats(SystemTime::now()).remove(0);
        assert_eq!(stat.endpoint, Some(a.at));
        assert!(stat.last_handshake.is_some());

        b.plane.rehandshake(&spec(&a, None)).expect("known peer");
        let stat = b.plane.stats(SystemTime::now()).remove(0);
        assert_eq!(
            (stat.endpoint, stat.last_handshake, stat.rx_bytes),
            (None, None, 0)
        );
        let unknown = node("100.88.0.5", "198.51.100.5:41820");
        assert_eq!(b.plane.rehandshake(&spec(&unknown, None)), Err(UnknownPeer));
        assert_eq!(
            b.plane.set_endpoint(&unknown.key, unknown.at),
            Err(UnknownPeer)
        );

        b.plane.sync_peers(&[]);
        assert!(b.plane.stats(SystemTime::now()).is_empty());
    }

    #[test]
    fn longest_prefix_selects_the_peer() {
        let (mut a, b) = pair(true);
        let c = node("100.88.0.3", "198.51.100.3:41820");
        let mut wide = spec(&b, Some(b.at));
        wide.allowed_ips
            .push("192.0.2.0/24".parse().expect("prefix"));
        let mut narrow = spec(&c, Some(c.at));
        narrow
            .allowed_ips
            .push("192.0.2.10/32".parse().expect("prefix"));
        a.plane.sync_peers(&[wide, narrow]);
        let to =
            |a: &mut Node, dst: &str| match send(a, &build::udp(a.mesh, 1, ip(dst), 53)).first() {
                Some(Action::Udp { to, .. }) => Some(*to),
                _ => None,
            };
        assert_eq!(to(&mut a, "192.0.2.10"), Some(c.at));
        assert_eq!(to(&mut a, "192.0.2.11"), Some(b.at));
        assert_eq!(to(&mut a, "198.18.0.1"), None);
    }
}
