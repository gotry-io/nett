//! In-process stateful filtering (design/userspace.md section 5): the same [`FilterSpec`] as on Linux,
//! applied only to new connections coming in from the tunnel and addressed to this machine, rejecting
//! those no rule allows (ADR 0023).
//!
//! State is recorded only for UDP flows and ICMP echo: a new TCP connection is a packet with SYN and
//! without ACK, and other TCP packets that belong to no connection are dropped or reset by this
//! machine's protocol stack and cannot be used to establish a connection.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use nett_trust::payload::Protocol;

use super::packet::{Ip, Transport};
use crate::access::{FilterSpec, Match};

/// Maximum number of entries in the connection table (hard rule 14): when full, the least recently used
/// one is evicted.
pub const MAX_FLOWS: usize = 4096;
/// Entries in the connection table expire after being idle this long.
pub const FLOW_IDLE: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Flow {
    Udp {
        local: (IpAddr, u16),
        remote: (IpAddr, u16),
    },
    Echo {
        local: IpAddr,
        remote: IpAddr,
        id: u16,
    },
}

/// Filter rules and connection table. Initially there are no rules: all new connections are rejected
/// (hard rule 6).
#[derive(Debug, Default)]
pub struct Filter {
    rules: FilterSpec,
    /// This machine's mesh addresses: an ICMP error message whose embedded header's source is one of them
    /// belongs to a connection this machine made.
    local: Vec<IpAddr>,
    flows: HashMap<Flow, Instant>,
}

impl Filter {
    /// Replaces the rules as a whole, done in one step on the caller's thread with no intermediate state.
    /// Established flows are not affected.
    pub fn set_rules(&mut self, rules: FilterSpec) {
        self.rules = rules;
    }

    pub fn set_local(&mut self, local: Vec<IpAddr>) {
        self.local = local;
    }

    /// Packets this machine sends through the tunnel: records UDP flows and echo requests, so that their
    /// return packets pass.
    pub fn outbound(&mut self, ip: &Ip, now: Instant) {
        let flow = match ip.transport {
            Transport::Udp { src_port, dst_port } => Flow::Udp {
                local: (ip.src, src_port),
                remote: (ip.dst, dst_port),
            },
            Transport::Echo { request: true, id } => Flow::Echo {
                local: ip.src,
                remote: ip.dst,
                id,
            },
            _ => return,
        };
        if self.flows.len() >= MAX_FLOWS && !self.flows.contains_key(&flow) {
            let oldest = self.flows.iter().min_by_key(|(_, seen)| **seen);
            if let Some(oldest) = oldest.map(|(flow, _)| *flow) {
                self.flows.remove(&oldest);
            }
        }
        self.flows.insert(flow, now);
    }

    /// Whether a packet coming in from the tunnel and addressed to this machine is allowed.
    pub fn inbound(&mut self, ip: &Ip, now: Instant) -> bool {
        let flow = match ip.transport {
            Transport::Tcp { syn, ack, .. } => {
                if syn && !ack {
                    return self.allowed(ip);
                }
                return true;
            }
            Transport::Udp { src_port, dst_port } => Flow::Udp {
                local: (ip.dst, dst_port),
                remote: (ip.src, src_port),
            },
            Transport::Echo { request: false, id } => Flow::Echo {
                local: ip.dst,
                remote: ip.src,
                id,
            },
            Transport::IcmpError { inner } => {
                return self.local.contains(&inner.src) || self.allowed(ip);
            }
            Transport::Fragment => return true,
            Transport::Echo { request: true, .. } | Transport::IcmpOther | Transport::Other => {
                return self.allowed(ip);
            }
        };
        if let Some(seen) = self.flows.get_mut(&flow) {
            *seen = now;
            return true;
        }
        self.allowed(ip)
    }

    /// Deletes entries idle for longer than [`FLOW_IDLE`].
    pub fn expire(&mut self, now: Instant) {
        self.flows
            .retain(|_, seen| now.saturating_duration_since(*seen) < FLOW_IDLE);
    }

    /// In rule order, the first matching rule decides; reject when none match.
    fn allowed(&self, ip: &Ip) -> bool {
        self.rules
            .rules
            .iter()
            .find(|rule| rule.matches.iter().all(|m| matches(m, ip)))
            .is_some_and(|rule| rule.accept)
    }

    #[cfg(test)]
    fn flows(&self) -> usize {
        self.flows.len()
    }
}

fn matches(m: &Match, ip: &Ip) -> bool {
    match m {
        Match::Source(prefix) => prefix.contains(ip.src),
        Match::Destination(prefix) => prefix.contains(ip.dst),
        Match::Port(range) => {
            let port = match (range.protocol, ip.transport) {
                (Protocol::Tcp, Transport::Tcp { dst_port, .. })
                | (Protocol::Udp, Transport::Udp { dst_port, .. }) => dst_port,
                _ => return false,
            };
            (range.first..=range.last).contains(&port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::FilterRule;
    use crate::userspace::packet::{build, parse};
    use nett_core::prefix::IpPrefix;
    use nett_trust::payload::PortRange;

    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect(s)
    }

    fn p(packet: &[u8]) -> Ip {
        parse(packet).expect("packet")
    }

    fn me() -> IpAddr {
        ip("100.88.0.1")
    }

    fn peer() -> IpAddr {
        ip("100.88.0.2")
    }

    fn filter(rules: Vec<FilterRule>) -> Filter {
        let mut f = Filter::default();
        f.set_rules(FilterSpec { rules });
        f.set_local(vec![me(), ip("fd00:88::1")]);
        f
    }

    fn allow_tcp(from: IpAddr, port: u16) -> FilterRule {
        FilterRule {
            matches: vec![
                Match::Source(IpPrefix::host(from)),
                Match::Port(PortRange {
                    protocol: Protocol::Tcp,
                    first: port,
                    last: port,
                }),
            ],
            accept: true,
        }
    }

    #[test]
    fn new_connections_are_denied_without_a_rule() {
        let now = Instant::now();
        let mut f = filter(vec![]);
        assert!(!f.inbound(&p(&build::tcp(peer(), 40000, me(), 22, SYN)), now));
        assert!(!f.inbound(&p(&build::udp(peer(), 40000, me(), 53)), now));
        assert!(!f.inbound(&p(&build::echo(peer(), me(), true, 1)), now));
        // TCP packets that belong to no connection are handed to this machine's protocol stack; they cannot
        // establish a connection
        assert!(f.inbound(&p(&build::tcp(peer(), 40000, me(), 22, ACK)), now));
        assert!(f.inbound(&p(&build::tcp(peer(), 40000, me(), 22, SYN | ACK)), now));
    }

    #[test]
    fn rules_match_in_order_by_source_and_port() {
        let now = Instant::now();
        let mut f = filter(vec![
            FilterRule {
                matches: vec![Match::Source(IpPrefix::host(ip("100.88.0.3")))],
                accept: false,
            },
            allow_tcp(peer(), 22),
            FilterRule {
                matches: vec![Match::Source("100.88.0.0/16".parse().expect("prefix"))],
                accept: true,
            },
        ]);
        assert!(f.inbound(&p(&build::tcp(peer(), 1, me(), 22, SYN)), now));
        // The third rule allows all protocols for the whole prefix, but 100.88.0.3 is rejected first by the
        // first rule
        assert!(!f.inbound(&p(&build::tcp(ip("100.88.0.3"), 1, me(), 22, SYN)), now));
        assert!(f.inbound(&p(&build::udp(ip("100.88.0.4"), 1, me(), 53)), now));
        // A port rule matches only its protocol
        let mut udp_only = filter(vec![allow_tcp(peer(), 53)]);
        assert!(!udp_only.inbound(&p(&build::udp(peer(), 1, me(), 53)), now));
        // A rule of a different address family does not match
        let mut v4 = filter(vec![allow_tcp(peer(), 22)]);
        assert!(!v4.inbound(
            &p(&build::tcp(ip("fd00:88::2"), 1, ip("fd00:88::1"), 22, SYN)),
            now
        ));
    }

    #[test]
    fn replies_to_outbound_udp_and_echo_pass() {
        let now = Instant::now();
        let mut f = filter(vec![]);
        f.outbound(&p(&build::udp(me(), 5353, peer(), 53)), now);
        assert!(f.inbound(&p(&build::udp(peer(), 53, me(), 5353)), now));
        assert!(!f.inbound(&p(&build::udp(peer(), 54, me(), 5353)), now));
        assert!(!f.inbound(&p(&build::udp(ip("100.88.0.3"), 53, me(), 5353)), now));

        f.outbound(&p(&build::echo(me(), peer(), true, 9)), now);
        assert!(f.inbound(&p(&build::echo(peer(), me(), false, 9)), now));
        assert!(!f.inbound(&p(&build::echo(peer(), me(), false, 10)), now));

        let v6 = (ip("fd00:88::1"), ip("fd00:88::2"));
        f.outbound(&p(&build::udp(v6.0, 1000, v6.1, 2000)), now);
        assert!(f.inbound(&p(&build::udp(v6.1, 2000, v6.0, 1000)), now));
    }

    #[test]
    fn icmp_errors_about_local_packets_and_later_fragments_pass() {
        let now = Instant::now();
        let mut f = filter(vec![]);
        let mine = build::tcp(me(), 40000, peer(), 443, SYN);
        let error = build::icmp_error(ip("100.88.0.9"), me(), &mine);
        assert!(f.inbound(&p(&error), now));
        let theirs = build::tcp(peer(), 40000, ip("100.88.0.7"), 443, SYN);
        let forged = build::icmp_error(peer(), me(), &theirs);
        assert!(!f.inbound(&p(&forged), now));

        let mut fragment = build::udp(peer(), 1, me(), 2);
        fragment[6..8].copy_from_slice(&0x0010u16.to_be_bytes());
        assert!(f.inbound(&p(&fragment), now));
    }

    #[test]
    fn flow_table_is_bounded_and_expires() {
        let start = Instant::now();
        let mut f = filter(vec![]);
        for port in 0..u16::try_from(MAX_FLOWS).expect("fits") {
            let at = start + Duration::from_millis(u64::from(port));
            f.outbound(&p(&build::udp(me(), 10000 + port, peer(), 53)), at);
        }
        assert_eq!(f.flows(), MAX_FLOWS);
        // Full: the least recently used one is evicted (port 10000)
        let later = start + Duration::from_secs(10);
        f.outbound(&p(&build::udp(me(), 9999, peer(), 53)), later);
        assert_eq!(f.flows(), MAX_FLOWS);
        assert!(!f.inbound(&p(&build::udp(peer(), 53, me(), 10000)), later));
        assert!(f.inbound(&p(&build::udp(peer(), 53, me(), 10001)), later));
        // A return packet refreshed the time of 10001; the others expire from being idle
        f.expire(start + FLOW_IDLE + Duration::from_secs(5));
        assert_eq!(f.flows(), 2);
    }
}
