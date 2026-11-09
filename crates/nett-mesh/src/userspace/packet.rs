//! 内层 IP 包的解析：过滤和选择对端只需要地址、协议、端口和少数标志。包来自隧道或 TUN，一律当作不可信
//! 数据校验（硬性规则 13），格式不对的返回 `None`，由调用方丢弃。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
/// IPv6 扩展头最多跟几层，防止构造的长链。
const MAX_EXTENSION_HEADERS: usize = 8;

/// 传输层的内容。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp {
        src_port: u16,
        dst_port: u16,
        syn: bool,
        ack: bool,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
    },
    /// 回显请求或应答（ICMP 与 ICMPv6）。
    Echo {
        request: bool,
        id: u16,
    },
    /// 差错报文（不可达、超时、包过大、参数错误）：`inner` 是触发它的那个包的头部。
    IcmpError {
        inner: Inner,
    },
    /// 其他 ICMP 类型。
    IcmpOther,
    /// 后续分片：不带传输层头。
    Fragment,
    /// 其他协议，或传输层头不完整。
    Other,
}

/// ICMP 差错报文中内嵌的原始包头部。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inner {
    pub src: IpAddr,
    pub dst: IpAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ip {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// 上层协议号（IPv6 跳过扩展头之后的）。
    pub protocol: u8,
    pub transport: Transport,
    /// IP 头中声明的总长度；包末尾超出的部分是填充。
    pub len: usize,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

/// 解析一个 IPv4 或 IPv6 包。总长度超出缓冲区、头部不完整的包返回 `None`。
pub fn parse(packet: &[u8]) -> Option<Ip> {
    match packet.first()? >> 4 {
        4 => parse_v4(packet),
        6 => parse_v6(packet),
        _ => None,
    }
}

fn parse_v4(p: &[u8]) -> Option<Ip> {
    let header = usize::from(p.first()? & 0x0f) * 4;
    let len = usize::from(u16_at(p, 2)?);
    if header < IPV4_MIN_HEADER || len < header || len > p.len() {
        return None;
    }
    let src = IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19]));
    let protocol = p[9];
    let offset = u16_at(p, 6)? & 0x1fff;
    let payload = &p[header..len];
    let transport = if offset != 0 {
        Transport::Fragment
    } else {
        transport(protocol, payload, false)
    };
    Some(Ip {
        src,
        dst,
        protocol,
        transport,
        len,
    })
}

fn v6_addr(b: &[u8]) -> Option<Ipv6Addr> {
    let octets: [u8; 16] = b.get(..16)?.try_into().ok()?;
    Some(Ipv6Addr::from(octets))
}

fn parse_v6(p: &[u8]) -> Option<Ip> {
    let len = IPV6_HEADER + usize::from(u16_at(p, 4)?);
    if p.len() < IPV6_HEADER || len > p.len() {
        return None;
    }
    let src = IpAddr::V6(v6_addr(&p[8..])?);
    let dst = IpAddr::V6(v6_addr(&p[24..])?);
    let mut next = p[6];
    let mut at = IPV6_HEADER;
    let mut fragment = false;
    for _ in 0..MAX_EXTENSION_HEADERS {
        match next {
            // 逐跳选项、路由、目的选项：长度以 8 字节为单位，不含前 8 字节
            0 | 43 | 60 => {
                next = *p.get(at)?;
                at += (usize::from(*p.get(at + 1)?) + 1) * 8;
            }
            44 => {
                next = *p.get(at)?;
                fragment = u16_at(p, at + 2)? >> 3 != 0;
                at += 8;
            }
            _ => break,
        }
    }
    if at > len {
        return None;
    }
    let transport = if fragment {
        Transport::Fragment
    } else {
        transport(next, &p[at..len], true)
    };
    Some(Ip {
        src,
        dst,
        protocol: next,
        transport,
        len,
    })
}

fn transport(protocol: u8, l4: &[u8], v6: bool) -> Transport {
    let ports = || Some((u16_at(l4, 0)?, u16_at(l4, 2)?));
    match protocol {
        PROTO_TCP => match (ports(), l4.get(13)) {
            (Some((src_port, dst_port)), Some(flags)) => Transport::Tcp {
                src_port,
                dst_port,
                syn: flags & 0x02 != 0,
                ack: flags & 0x10 != 0,
            },
            _ => Transport::Other,
        },
        PROTO_UDP => match ports() {
            Some((src_port, dst_port)) => Transport::Udp { src_port, dst_port },
            None => Transport::Other,
        },
        PROTO_ICMP if !v6 => icmp(l4, 8, 0, &[3, 11, 12]),
        PROTO_ICMPV6 if v6 => icmp(l4, 128, 129, &[1, 2, 3, 4]),
        _ => Transport::Other,
    }
}

fn icmp(l4: &[u8], echo_request: u8, echo_reply: u8, errors: &[u8]) -> Transport {
    let Some(&kind) = l4.first() else {
        return Transport::Other;
    };
    if kind == echo_request || kind == echo_reply {
        return match u16_at(l4, 4) {
            Some(id) => Transport::Echo {
                request: kind == echo_request,
                id,
            },
            None => Transport::Other,
        };
    }
    if errors.contains(&kind) {
        // 内嵌的原始包从 ICMP 头之后（8 字节）开始，只需要它的地址；它往往被截断，不校验长度
        let inner = l4.get(8..).and_then(|b| match b.first()? >> 4 {
            4 if b.len() >= IPV4_MIN_HEADER => Some(Inner {
                src: IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15])),
                dst: IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19])),
            }),
            6 if b.len() >= IPV6_HEADER => Some(Inner {
                src: IpAddr::V6(v6_addr(&b[8..])?),
                dst: IpAddr::V6(v6_addr(&b[24..])?),
            }),
            _ => None,
        });
        return match inner {
            Some(inner) => Transport::IcmpError { inner },
            None => Transport::Other,
        };
    }
    Transport::IcmpOther
}

#[cfg(test)]
pub(crate) mod build {
    //! 测试中构造内层包。

    use std::net::IpAddr;

    fn header(src: IpAddr, dst: IpAddr, protocol: u8, l4: &[u8]) -> Vec<u8> {
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let len = u16::try_from(20 + l4.len()).expect("len");
                let mut p = vec![0x45, 0];
                p.extend_from_slice(&len.to_be_bytes());
                p.extend_from_slice(&[0, 0, 0, 0, 64, protocol, 0, 0]);
                p.extend_from_slice(&s.octets());
                p.extend_from_slice(&d.octets());
                p.extend_from_slice(l4);
                p
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                let len = u16::try_from(l4.len()).expect("len");
                let mut p = vec![0x60, 0, 0, 0];
                p.extend_from_slice(&len.to_be_bytes());
                p.extend_from_slice(&[protocol, 64]);
                p.extend_from_slice(&s.octets());
                p.extend_from_slice(&d.octets());
                p.extend_from_slice(l4);
                p
            }
            _ => panic!("mixed address families"),
        }
    }

    pub fn tcp(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, flags: u8) -> Vec<u8> {
        let mut l4 = vec![0u8; 20];
        l4[..2].copy_from_slice(&sport.to_be_bytes());
        l4[2..4].copy_from_slice(&dport.to_be_bytes());
        l4[12] = 0x50;
        l4[13] = flags;
        header(src, dst, super::PROTO_TCP, &l4)
    }

    pub fn udp(src: IpAddr, sport: u16, dst: IpAddr, dport: u16) -> Vec<u8> {
        let mut l4 = vec![0u8; 12];
        l4[..2].copy_from_slice(&sport.to_be_bytes());
        l4[2..4].copy_from_slice(&dport.to_be_bytes());
        l4[4..6].copy_from_slice(&12u16.to_be_bytes());
        header(src, dst, super::PROTO_UDP, &l4)
    }

    pub fn echo(src: IpAddr, dst: IpAddr, request: bool, id: u16) -> Vec<u8> {
        let v6 = src.is_ipv6();
        let kind = match (v6, request) {
            (false, true) => 8,
            (false, false) => 0,
            (true, true) => 128,
            (true, false) => 129,
        };
        let mut l4 = vec![kind, 0, 0, 0];
        l4.extend_from_slice(&id.to_be_bytes());
        l4.extend_from_slice(&[0, 1]);
        let protocol = if v6 {
            super::PROTO_ICMPV6
        } else {
            super::PROTO_ICMP
        };
        header(src, dst, protocol, &l4)
    }

    /// `src` 发出的、关于 `original` 的 ICMP 差错报文（IPv4 不可达 / IPv6 包过大）。
    pub fn icmp_error(src: IpAddr, dst: IpAddr, original: &[u8]) -> Vec<u8> {
        let v6 = src.is_ipv6();
        let mut l4 = vec![if v6 { 2 } else { 3 }, 0, 0, 0, 0, 0, 0, 0];
        l4.extend_from_slice(&original[..original.len().min(48)]);
        let protocol = if v6 {
            super::PROTO_ICMPV6
        } else {
            super::PROTO_ICMP
        };
        header(src, dst, protocol, &l4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect(s)
    }

    #[test]
    fn parses_tcp_udp_and_icmp_in_both_families() {
        for (a, b) in [("100.88.0.1", "100.88.0.2"), ("fd00:88::1", "fd00:88::2")] {
            let (a, b) = (ip(a), ip(b));
            let syn = parse(&build::tcp(a, 40000, b, 22, 0x02)).expect("tcp");
            assert_eq!((syn.src, syn.dst), (a, b));
            assert_eq!(
                syn.transport,
                Transport::Tcp {
                    src_port: 40000,
                    dst_port: 22,
                    syn: true,
                    ack: false
                }
            );
            let udp = parse(&build::udp(a, 5353, b, 53)).expect("udp");
            assert_eq!(
                udp.transport,
                Transport::Udp {
                    src_port: 5353,
                    dst_port: 53
                }
            );
            let echo = parse(&build::echo(a, b, true, 7)).expect("echo");
            assert_eq!(
                echo.transport,
                Transport::Echo {
                    request: true,
                    id: 7
                }
            );
            let original = build::udp(b, 53, a, 5353);
            let err = parse(&build::icmp_error(ip_router(a), b, &original)).expect("error");
            assert_eq!(
                err.transport,
                Transport::IcmpError {
                    inner: Inner { src: b, dst: a }
                }
            );
        }
    }

    fn ip_router(a: IpAddr) -> IpAddr {
        if a.is_ipv4() {
            ip("100.88.0.9")
        } else {
            ip("fd00:88::9")
        }
    }

    #[test]
    fn padding_is_outside_the_declared_length() {
        let mut p = build::udp(ip("100.88.0.1"), 1, ip("100.88.0.2"), 2);
        let len = p.len();
        p.extend_from_slice(&[0; 12]);
        assert_eq!(parse(&p).expect("padded").len, len);
    }

    #[test]
    fn rejects_truncated_and_malformed_packets() {
        let good = build::tcp(ip("100.88.0.1"), 1, ip("100.88.0.2"), 2, 0x02);
        assert!(
            parse(&good[..good.len() - 1]).is_none(),
            "shorter than declared"
        );
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x45; 10]).is_none());
        let mut bad_ihl = good.clone();
        bad_ihl[0] = 0x44;
        assert!(parse(&bad_ihl).is_none());
        let mut v5 = good;
        v5[0] = 0x55;
        assert!(parse(&v5).is_none());
        let v6 = build::udp(ip("fd00:88::1"), 1, ip("fd00:88::2"), 2);
        assert!(parse(&v6[..39]).is_none());
        // 截断的传输层头：仍是合法的 IP 包，但没有端口
        let mut short = build::tcp(ip("100.88.0.1"), 1, ip("100.88.0.2"), 2, 0x02);
        short.truncate(30);
        short[2..4].copy_from_slice(&30u16.to_be_bytes());
        assert_eq!(parse(&short).expect("ip").transport, Transport::Other);
    }

    #[test]
    fn later_fragments_carry_no_transport_header() {
        let mut p = build::udp(ip("100.88.0.1"), 1, ip("100.88.0.2"), 2);
        p[6..8].copy_from_slice(&0x0010u16.to_be_bytes());
        assert_eq!(parse(&p).expect("fragment").transport, Transport::Fragment);
        // IPv6：分片扩展头，偏移不为 0
        let udp = build::udp(ip("fd00:88::1"), 1, ip("fd00:88::2"), 2);
        let mut v6 = udp[..40].to_vec();
        v6[6] = 44;
        v6.extend_from_slice(&[PROTO_UDP, 0, 0x00, 0x08, 0, 0, 0, 1]);
        v6.extend_from_slice(&udp[40..]);
        let plen = u16::try_from(v6.len() - 40).expect("len");
        v6[4..6].copy_from_slice(&plen.to_be_bytes());
        assert_eq!(parse(&v6).expect("fragment").transport, Transport::Fragment);
        // 偏移为 0 的分片照常解析传输层
        v6[42..44].copy_from_slice(&[0, 0x01]);
        assert!(matches!(
            parse(&v6).expect("first fragment").transport,
            Transport::Udp { .. }
        ));
    }
}
