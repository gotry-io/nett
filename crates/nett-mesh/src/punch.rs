//! Hole punching (design/mesh.md section 6.1): this machine's mapped addresses and NAT type, and the
//! hole punching procedure between a pair of members that are both `dial-only`. Pure logic: the caller
//! passes in the time and takes over the messages and probes to send.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};

use crate::probe::{NatType, PUNCH_ACK, PUNCH_PROPOSAL, PunchMessage};

/// Interval and duration of hole punching probes.
pub const PUNCH_INTERVAL: Duration = Duration::from_millis(200);
pub const PUNCH_DURATION: Duration = Duration::from_secs(10);
/// How long after the tunnel is established the first attempt starts; after a failure, retries start at
/// 30 seconds, doubling with each attempt, up to 1 hour.
const FIRST_ATTEMPT: Duration = Duration::from_secs(2);
const BACKOFF_BASE: Duration = Duration::from_secs(30);
const BACKOFF_MAX: Duration = Duration::from_secs(3600);
/// When the other side does not yet know any of its own addresses (for example just started, no reply
/// from a `public` node yet), try again after this long.
const RETRY_SOON: Duration = Duration::from_secs(5);
/// After a successful punch, how long no further attempts are made: path selection decides per
/// section 8.2 whether to use it.
const AFTER_SUCCESS: Duration = Duration::from_secs(60);
/// Resend interval and count for proposals.
const PROPOSAL_RETRY: Duration = Duration::from_millis(300);
const PROPOSAL_TRIES: u32 = 7;
/// How long an observed mapped address stays valid: the network may have changed since.
const OBSERVATION_TTL: Duration = Duration::from_secs(600);
/// The maximum number of addresses one hole punching attempt sends probes to (the addresses given by
/// the other side, plus addresses learned from the source of the other side's probes).
const MAX_TARGETS: usize = 4;

/// Mapped addresses that `public` nodes report to this machine in probe replies, recorded by the
/// observer's address.
#[derive(Debug, Default)]
pub struct Observations {
    by_observer: HashMap<IpAddr, (SocketAddr, Instant)>,
}

/// This machine's NAT type and addresses, written into hole punching proposals and confirmations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnInfo {
    pub nat: NatType,
    pub v4: Option<SocketAddrV4>,
    pub v6: Option<SocketAddrV6>,
}

impl Observations {
    pub fn record(&mut self, observer: IpAddr, observed: SocketAddr, now: Instant) {
        if observed.ip().is_unspecified() {
            return;
        }
        self.by_observer.insert(observer, (observed, now));
    }

    /// Two `public` nodes seeing the same IPv4 mapped address means cone; different means symmetric; fewer
    /// than two means unknown. A symmetric mapped address is of no use to the other side, so it is not
    /// told to the other side. The IPv6 address is the source seen by an IPv6 observer.
    pub fn own(&self, now: Instant) -> OwnInfo {
        let fresh = |(_, (_, at)): &(&IpAddr, &(SocketAddr, Instant))| {
            now.saturating_duration_since(*at) < OBSERVATION_TTL
        };
        let mut v4: Vec<(Instant, SocketAddrV4)> = self
            .by_observer
            .iter()
            .filter(fresh)
            .filter_map(|(_, (addr, at))| match addr {
                SocketAddr::V4(a) => Some((*at, *a)),
                SocketAddr::V6(_) => None,
            })
            .collect();
        v4.sort();
        let nat = match v4.as_slice() {
            [] | [_] => NatType::Unknown,
            many if many.iter().all(|(_, a)| *a == many[0].1) => NatType::Cone,
            _ => NatType::Symmetric,
        };
        let v6 = self
            .by_observer
            .iter()
            .filter(fresh)
            .filter_map(|(_, (addr, at))| match addr {
                SocketAddr::V6(a) => Some((*at, *a)),
                SocketAddr::V4(_) => None,
            })
            .max()
            .map(|(_, a)| a);
        OwnInfo {
            nat,
            v4: (nat != NatType::Symmetric)
                .then(|| v4.last().map(|(_, a)| *a))
                .flatten(),
            v6,
        }
    }
}

#[derive(Debug, Clone)]
enum Phase {
    Idle {
        next: Instant,
    },
    Proposing {
        round: u32,
        next_send: Instant,
        sent: u32,
    },
    Punching {
        until: Instant,
        next_probe: Instant,
        targets: Vec<SocketAddr>,
    },
}

/// Noteworthy events during hole punching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PunchEvent {
    Started {
        round: u32,
        own: NatType,
        peer: NatType,
        /// Address of the other side to send probes to.
        targets: Vec<SocketAddr>,
    },
    Succeeded {
        address: SocketAddr,
    },
    Failed {
        reason: &'static str,
    },
}

/// Hole punching state between a pair of members. The decider initiates; the follower responds.
#[derive(Debug, Clone)]
pub struct Punch {
    phase: Phase,
    failures: u32,
    /// Follower: the round most recently accepted.
    accepted_round: u32,
    /// The address that was punched through: for the decider, the source of the received reply; for the
    /// follower, the source of the other side's received probe.
    punched: Option<SocketAddr>,
    events: Vec<PunchEvent>,
}

impl Punch {
    pub fn new(now: Instant) -> Self {
        Self {
            phase: Phase::Idle {
                next: now + FIRST_ATTEMPT,
            },
            failures: 0,
            accepted_round: 0,
            punched: None,
            events: Vec::new(),
        }
    }

    pub fn punched(&self) -> Option<SocketAddr> {
        self.punched
    }

    pub fn take_events(&mut self) -> Vec<PunchEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn punching(&self) -> bool {
        matches!(self.phase, Phase::Punching { .. })
    }

    /// Decider: `eligible` means it is now suitable to punch (tunnel up, not currently on a direct path, no
    /// other two-ended switchover in progress). Returns the proposal to send through the tunnel.
    /// `round` is used only when a new attempt starts.
    pub fn decider_tick(
        &mut self,
        now: Instant,
        eligible: bool,
        own: &OwnInfo,
        round: impl FnOnce() -> u32,
    ) -> Option<PunchMessage> {
        self.expire(now);
        if let Phase::Idle { next } = self.phase {
            // With no observation yet there is no way to punch: neither the NAT type nor an address to tell the
            // other side is known
            let known = own.nat != NatType::Unknown || own.v4.is_some() || own.v6.is_some();
            if !(eligible && known && now >= next) {
                return None;
            }
            self.phase = Phase::Proposing {
                round: round(),
                next_send: now,
                sent: 0,
            };
        }
        let Phase::Proposing {
            round,
            next_send,
            sent,
        } = self.phase
        else {
            return None;
        };
        if now < next_send {
            return None;
        }
        if sent >= PROPOSAL_TRIES {
            self.fail(now, "no acknowledgement");
            return None;
        }
        self.phase = Phase::Proposing {
            round,
            next_send: now + PROPOSAL_RETRY,
            sent: sent + 1,
        };
        Some(message(PUNCH_PROPOSAL, round, own))
    }

    /// Follower receives a proposal: starts punching and returns the confirmation. Earlier rounds are
    /// dropped; a resend of the same round is confirmed again.
    pub fn on_proposal(
        &mut self,
        proposal: &PunchMessage,
        own: &OwnInfo,
        now: Instant,
    ) -> Option<PunchMessage> {
        if proposal.round < self.accepted_round {
            return None;
        }
        if proposal.round > self.accepted_round {
            self.accepted_round = proposal.round;
            self.start(proposal.round, own.nat, proposal, now);
        }
        Some(message(PUNCH_ACK, proposal.round, own))
    }

    /// Decider receives a confirmation: gives up if both ends are symmetric, otherwise starts punching.
    pub fn on_ack(&mut self, ack: &PunchMessage, own: &OwnInfo, now: Instant) {
        let Phase::Proposing { round, .. } = self.phase else {
            return;
        };
        if ack.round != round {
            return;
        }
        let v6 = own.v6.is_some() && ack.v6.is_some();
        if own.nat == NatType::Symmetric && ack.nat == NatType::Symmetric && !v6 {
            self.events.push(PunchEvent::Started {
                round,
                own: own.nat,
                peer: ack.nat,
                targets: Vec::new(),
            });
            self.fail_for(now, "both behind symmetric NAT", BACKOFF_MAX);
            return;
        }
        if ack.nat == NatType::Unknown && ack.v4.is_none() && ack.v6.is_none() {
            // The other side does not yet know anything about itself (a symmetric end never gives an address in
            // the first place; the address is learned from its probe): try again later
            self.fail_for(now, "peer does not know its address yet", RETRY_SOON);
            return;
        }
        self.start(round, own.nat, ack, now);
    }

    /// Starts punching toward the other side's addresses. If the other side gave an IPv6 address, always
    /// punch it: when this machine has no IPv6 connectivity the send fails, which does no harm.
    fn start(&mut self, round: u32, own: NatType, peer: &PunchMessage, now: Instant) {
        let mut targets: Vec<SocketAddr> = Vec::new();
        if let Some(v4) = peer.v4 {
            targets.push(SocketAddr::V4(v4));
        }
        if let Some(v6) = peer.v6 {
            targets.push(SocketAddr::V6(v6));
        }
        self.events.push(PunchEvent::Started {
            round,
            own,
            peer: peer.nat,
            targets: targets.clone(),
        });
        self.phase = Phase::Punching {
            until: now + PUNCH_DURATION,
            next_probe: now,
            targets,
        };
    }

    /// The addresses to send probes to in this round (once every 200 ms).
    pub fn probe_targets(&mut self, now: Instant) -> Vec<SocketAddr> {
        self.expire(now);
        let Phase::Punching {
            next_probe,
            targets,
            ..
        } = &mut self.phase
        else {
            return Vec::new();
        };
        if now < *next_probe {
            return Vec::new();
        }
        *next_probe = now + PUNCH_INTERVAL;
        targets.clone()
    }

    /// During punching, a probe with authentication received from the other side: the direction from the
    /// other side to this machine works, and the source is the other side's address (for a symmetric NAT
    /// end, the port allocated for this machine is learned this way), so probes are also sent to it from
    /// now on. The follower takes it as the punched-through address.
    pub fn on_probe_from(&mut self, from: SocketAddr, follower: bool) {
        let Phase::Punching { targets, .. } = &mut self.phase else {
            return;
        };
        if !targets.contains(&from) && targets.len() < MAX_TARGETS {
            targets.push(from);
        }
        if follower && self.punched != Some(from) {
            self.punched = Some(from);
            self.events.push(PunchEvent::Succeeded { address: from });
        }
    }

    /// Receives the reply to its own probe: both directions work.
    pub fn on_reply_from(&mut self, from: SocketAddr, now: Instant) {
        if !matches!(self.phase, Phase::Punching { .. }) {
            return;
        }
        self.failures = 0;
        if self.punched != Some(from) {
            self.punched = Some(from);
            self.events.push(PunchEvent::Succeeded { address: from });
        }
        self.phase = Phase::Idle {
            next: now + AFTER_SUCCESS,
        };
    }

    fn expire(&mut self, now: Instant) {
        if let Phase::Punching { until, .. } = self.phase
            && now >= until
        {
            if self.punched.is_some() {
                self.phase = Phase::Idle {
                    next: now + AFTER_SUCCESS,
                };
            } else {
                self.fail(now, "no reply within 10 s");
            }
        }
    }

    fn fail(&mut self, now: Instant, reason: &'static str) {
        let factor = 1u32 << self.failures.min(7);
        self.fail_for(now, reason, (BACKOFF_BASE * factor).min(BACKOFF_MAX));
    }

    fn fail_for(&mut self, now: Instant, reason: &'static str, wait: Duration) {
        self.failures += 1;
        self.events.push(PunchEvent::Failed { reason });
        self.phase = Phase::Idle { next: now + wait };
    }
}

fn message(kind: u8, round: u32, own: &OwnInfo) -> PunchMessage {
    PunchMessage {
        kind,
        round,
        nat: own.nat,
        v4: own.v4,
        v6: own.v6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("addr")
    }

    fn cone(ip: &str) -> OwnInfo {
        OwnInfo {
            nat: NatType::Cone,
            v4: Some(ip.parse().expect("v4")),
            v6: None,
        }
    }

    #[test]
    fn nat_type_from_two_observers() {
        let now = Instant::now();
        let mut o = Observations::default();
        let r1: IpAddr = "198.51.100.3".parse().expect("ip");
        let r2: IpAddr = "198.51.100.4".parse().expect("ip");
        o.record(r1, addr("198.51.100.201:41820"), now);
        assert_eq!(o.own(now).nat, NatType::Unknown);
        assert_eq!(
            o.own(now).v4,
            Some("198.51.100.201:41820".parse().expect("v4"))
        );
        o.record(r2, addr("198.51.100.201:41820"), now);
        assert_eq!(o.own(now).nat, NatType::Cone);
        o.record(r2, addr("198.51.100.201:61234"), now);
        let own = o.own(now);
        assert_eq!((own.nat, own.v4), (NatType::Symmetric, None));
        // Re-evaluate after the observation expires
        assert_eq!(o.own(now + OBSERVATION_TTL).nat, NatType::Unknown);
    }

    #[test]
    fn decider_proposes_then_punches_until_a_reply() {
        let t0 = Instant::now();
        let mut a = Punch::new(t0);
        let mut b = Punch::new(t0);
        let (own_a, own_b) = (cone("198.51.100.201:41820"), cone("198.51.100.202:41820"));
        assert_eq!(a.decider_tick(t0, true, &own_a, || 1), None);
        let t1 = t0 + FIRST_ATTEMPT;
        let proposal = a.decider_tick(t1, true, &own_a, || 7).expect("proposal");
        assert_eq!((proposal.round, proposal.v4), (7, own_a.v4));
        let ack = b.on_proposal(&proposal, &own_b, t1).expect("ack");
        assert_eq!(b.probe_targets(t1), vec![addr("198.51.100.201:41820")]);
        a.on_ack(&ack, &own_a, t1);
        assert_eq!(a.probe_targets(t1), vec![addr("198.51.100.202:41820")]);
        // Once every 200 ms
        assert!(a.probe_targets(t1 + Duration::from_millis(100)).is_empty());
        assert_eq!(a.probe_targets(t1 + PUNCH_INTERVAL).len(), 1);
        b.on_probe_from(addr("198.51.100.201:41820"), true);
        a.on_reply_from(addr("198.51.100.202:41820"), t1 + PUNCH_INTERVAL);
        assert_eq!(a.punched(), Some(addr("198.51.100.202:41820")));
        assert_eq!(b.punched(), Some(addr("198.51.100.201:41820")));
        assert!(a.take_events().contains(&PunchEvent::Succeeded {
            address: addr("198.51.100.202:41820")
        }));
    }

    #[test]
    fn learns_the_symmetric_side_from_its_probes() {
        let t0 = Instant::now();
        let mut a = Punch::new(t0);
        let own_a = cone("198.51.100.201:41820");
        let t1 = t0 + FIRST_ATTEMPT;
        a.decider_tick(t1, true, &own_a, || 1).expect("proposal");
        let symmetric = PunchMessage {
            kind: PUNCH_ACK,
            round: 1,
            nat: NatType::Symmetric,
            v4: None,
            v6: None,
        };
        a.on_ack(&symmetric, &own_a, t1);
        assert!(a.probe_targets(t1).is_empty());
        // A probe from a symmetric end comes from a new port: send probes to it from now on
        a.on_probe_from(addr("198.51.100.202:61234"), false);
        assert_eq!(
            a.probe_targets(t1 + PUNCH_INTERVAL),
            vec![addr("198.51.100.202:61234")]
        );
    }

    #[test]
    fn gives_up_when_both_are_symmetric_and_backs_off_after_failures() {
        let t0 = Instant::now();
        let own = OwnInfo {
            nat: NatType::Symmetric,
            v4: None,
            v6: None,
        };
        let mut a = Punch::new(t0);
        let t1 = t0 + FIRST_ATTEMPT;
        a.decider_tick(t1, true, &own, || 1).expect("proposal");
        a.on_ack(
            &PunchMessage {
                kind: PUNCH_ACK,
                round: 1,
                nat: NatType::Symmetric,
                v4: None,
                v6: None,
            },
            &own,
            t1,
        );
        assert!(!a.punching());
        assert!(a.take_events().contains(&PunchEvent::Failed {
            reason: "both behind symmetric NAT"
        }));
        assert_eq!(a.decider_tick(t1 + BACKOFF_BASE, true, &own, || 2), None);

        // No reply in 10 seconds: give up, retry in 30 seconds, doubling after that
        let own = cone("198.51.100.201:41820");
        let mut b = Punch::new(t0);
        b.decider_tick(t1, true, &own, || 1).expect("proposal");
        b.on_ack(
            &PunchMessage {
                kind: PUNCH_ACK,
                round: 1,
                nat: NatType::Cone,
                v4: Some("198.51.100.202:41820".parse().expect("v4")),
                v6: None,
            },
            &own,
            t1,
        );
        let t2 = t1 + PUNCH_DURATION;
        assert!(b.probe_targets(t2).is_empty());
        assert_eq!(
            b.decider_tick(t2 + BACKOFF_BASE - PUNCH_INTERVAL, true, &own, || 2),
            None
        );
        assert!(
            b.decider_tick(t2 + BACKOFF_BASE, true, &own, || 2)
                .is_some()
        );
    }
}
