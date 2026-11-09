//! 进程内的状态过滤（design/userspace.md 第 5 节）：与 Linux 相同的 [`FilterSpec`]，只作用于从隧道进来、
//! 发往本机的新建连接，没有规则放行的拒绝（ADR 0023）。
//!
//! 只为 UDP 流和 ICMP 回显记录状态：TCP 的新建连接就是带 SYN、不带 ACK 的包，其他 TCP 包不属于任何连接时
//! 由本机协议栈丢弃或复位，不能借此建立连接。

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use nett_trust::payload::Protocol;

use super::packet::{Ip, Transport};
use crate::access::{FilterSpec, Match};

/// 连接表最多的条数（硬性规则 14）：满了淘汰最久没用的一条。
pub const MAX_FLOWS: usize = 4096;
/// 连接表中的条目空闲这么久之后过期。
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

/// 过滤规则与连接表。初始时没有规则：所有新建连接都拒绝（硬性规则 6）。
#[derive(Debug, Default)]
pub struct Filter {
    rules: FilterSpec,
    /// 本机的组网地址：内嵌包头的来源是它们的 ICMP 差错报文属于本机发出的连接。
    local: Vec<IpAddr>,
    flows: HashMap<Flow, Instant>,
}

impl Filter {
    /// 整体替换规则，在调用方的线程中一次完成，没有中间状态。已建立的流不受影响。
    pub fn set_rules(&mut self, rules: FilterSpec) {
        self.rules = rules;
    }

    pub fn set_local(&mut self, local: Vec<IpAddr>) {
        self.local = local;
    }

    /// 本机经隧道发出的包：记录 UDP 流和回显请求，让它们的回包通过。
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

    /// 从隧道进来、发往本机的包是否放行。
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

    /// 删除空闲超过 [`FLOW_IDLE`] 的条目。
    pub fn expire(&mut self, now: Instant) {
        self.flows
            .retain(|_, seen| now.saturating_duration_since(*seen) < FLOW_IDLE);
    }

    /// 按规则的顺序，第一条匹配的规则决定；都不匹配时拒绝。
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
        // 不属于任何连接的 TCP 包交给本机协议栈，它们不能建立连接
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
        // 第三条放行整个网段的所有协议，但 100.88.0.3 先被第一条拒绝
        assert!(!f.inbound(&p(&build::tcp(ip("100.88.0.3"), 1, me(), 22, SYN)), now));
        assert!(f.inbound(&p(&build::udp(ip("100.88.0.4"), 1, me(), 53)), now));
        // 端口规则只匹配它的协议
        let mut udp_only = filter(vec![allow_tcp(peer(), 53)]);
        assert!(!udp_only.inbound(&p(&build::udp(peer(), 1, me(), 53)), now));
        // 地址族不同的规则不匹配
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
        // 满了：淘汰最久没用的一条（端口 10000）
        let later = start + Duration::from_secs(10);
        f.outbound(&p(&build::udp(me(), 9999, peer(), 53)), later);
        assert_eq!(f.flows(), MAX_FLOWS);
        assert!(!f.inbound(&p(&build::udp(peer(), 53, me(), 10000)), later));
        assert!(f.inbound(&p(&build::udp(peer(), 53, me(), 10001)), later));
        // 回包刷新了 10001 的时间；其他的空闲过期
        f.expire(start + FLOW_IDLE + Duration::from_secs(5));
        assert_eq!(f.flows(), 2);
    }
}
