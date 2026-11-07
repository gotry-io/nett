//! 打洞（design/mesh.md 第 6.1 节）：本机的映射地址与 NAT 类型，以及一对双方都是 `dial-only` 的成员之间的
//! 打洞过程。纯逻辑：时间由调用方传入，要发的消息和探测交给调用方。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};

use crate::probe::{NatType, PUNCH_ACK, PUNCH_PROPOSAL, PunchMessage};

/// 打洞探测的间隔与持续时间。
pub const PUNCH_INTERVAL: Duration = Duration::from_millis(200);
pub const PUNCH_DURATION: Duration = Duration::from_secs(10);
/// 隧道建立后多久开始第一次尝试；失败后的重试从 30 秒起按次数加倍，最长 1 小时。
const FIRST_ATTEMPT: Duration = Duration::from_secs(2);
const BACKOFF_BASE: Duration = Duration::from_secs(30);
const BACKOFF_MAX: Duration = Duration::from_secs(3600);
/// 对方还不知道自己的任何地址时（例如刚启动、还没有 `public` 节点的应答），隔这么久再试。
const RETRY_SOON: Duration = Duration::from_secs(5);
/// 打通之后，多久之内不再尝试：这时由选路按第 8.2 节决定用不用它。
const AFTER_SUCCESS: Duration = Duration::from_secs(60);
/// 提议的重发间隔与次数。
const PROPOSAL_RETRY: Duration = Duration::from_millis(300);
const PROPOSAL_TRIES: u32 = 7;
/// 映射地址的观察多久之后作废：网络可能已经变了。
const OBSERVATION_TTL: Duration = Duration::from_secs(600);
/// 一次打洞最多向几个地址发探测（对方给的地址，加上从对方探测的来源得知的地址）。
const MAX_TARGETS: usize = 4;

/// `public` 节点在探测应答中告诉本机的映射地址，按观察者的地址记录。
#[derive(Debug, Default)]
pub struct Observations {
    by_observer: HashMap<IpAddr, (SocketAddr, Instant)>,
}

/// 本机的 NAT 类型与地址，写进打洞提议和确认。
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

    /// 两个 `public` 节点看到同一个 IPv4 映射地址是锥形，不同是对称型，不足两个是未知。对称型的映射
    /// 地址对方用不上，不告诉对方。IPv6 地址取 IPv6 观察者看到的来源。
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

/// 打洞过程中值得记录的事。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PunchEvent {
    Started {
        round: u32,
        own: NatType,
        peer: NatType,
        /// 要发探测的对方地址。
        targets: Vec<SocketAddr>,
    },
    Succeeded {
        address: SocketAddr,
    },
    Failed {
        reason: &'static str,
    },
}

/// 一对成员之间的打洞状态。决定方发起，跟随方响应。
#[derive(Debug, Clone)]
pub struct Punch {
    phase: Phase,
    failures: u32,
    /// 跟随方：最近一次接受的轮次。
    accepted_round: u32,
    /// 打通的地址：决定方是收到应答的来源，跟随方是收到对方探测的来源。
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

    /// 决定方：`eligible` 表示现在适合打洞（隧道通、当前不在直连上、没有别的两端一起切换在进行）。返回要
    /// 经隧道发出的提议。`round` 只在开始新的一次时取用。
    pub fn decider_tick(
        &mut self,
        now: Instant,
        eligible: bool,
        own: &OwnInfo,
        round: impl FnOnce() -> u32,
    ) -> Option<PunchMessage> {
        self.expire(now);
        if let Phase::Idle { next } = self.phase {
            // 还没有任何观察时无从打洞：既不知道 NAT 类型，也没有地址可以告诉对方
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

    /// 跟随方收到提议：开始打洞，返回确认。更早的轮次丢弃；同一轮次的重发再确认一次。
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

    /// 决定方收到确认：两端都是对称型就放弃，否则开始打洞。
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
            // 对方还不知道自己的任何情况（对称型一端本来就不给地址，地址从它的探测得知）：过一会儿再试
            self.fail_for(now, "peer does not know its address yet", RETRY_SOON);
            return;
        }
        self.start(round, own.nat, ack, now);
    }

    /// 开始向对方的地址打洞。对方给了 IPv6 地址就一律去打：本机没有 IPv6 连通时发送失败，没有坏处。
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

    /// 这一轮要发出探测的地址（每 200 毫秒一次）。
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

    /// 打洞期间收到对方带认证的探测：对方到本机这个方向通了，来源就是对方的地址（对称型 NAT 一端为本机
    /// 分配的端口由此得知），以后也向它发探测。跟随方以它作为打通的地址。
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

    /// 收到自己探测的应答：两个方向都通了。
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
        // 观察过期之后重新判断
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
        // 每 200 毫秒一次
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
        // 对称型一端的探测从一个新端口来：以后也向它发
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

        // 10 秒没有应答：放弃，30 秒后再试，之后加倍
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
