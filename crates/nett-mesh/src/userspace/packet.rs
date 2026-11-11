//! Parsing of inner IP packets: filtering and peer selection need only the address, protocol, port and a
//! few flags. Packets come from the tunnel or the TUN and are always validated as untrusted data (hard
//! rule 13); those with a bad format return `None` and are dropped by the caller.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
/// The maximum number of IPv6 extension headers followed, preventing a crafted long chain.
const MAX_EXTENSION_HEADERS: usize = 8;

/// Content of the transport layer.
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
    /// Echo request or reply (ICMP and ICMPv6).
    Echo {
        request: bool,
        id: u16,
    },
    /// Error message (unreachable, time exceeded, packet too big, parameter problem): `inner` is the header of
    /// the packet that triggered it.
    IcmpError {
        inner: Inner,
    },
    /// Other ICMP types.
    IcmpOther,
    /// A subsequent fragment: carries no transport layer header.
    Fragment,
    /// Other protocols, or an incomplete transport layer header.
    Other,
}

/// The original packet header embedded in an ICMP error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inner {
    pub src: IpAddr,
    pub dst: IpAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ip {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Upper layer protocol number (for IPv6, after skipping extension headers).
    pub protocol: u8,
    pub transport: Transport,
    /// Total length declared in the IP header; the part past it at the end of the packet is padding.
    pub len: usize,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

/// Parses an IPv4 or IPv6 packet. Packets whose total length exceeds the buffer or whose header is
/// incomplete return `None`.
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
            // Hop-by-hop options, routing, destination options: the length is in units of 8 bytes, excluding the
            // first 8 bytes
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
        // The embedded original packet starts after the ICMP header (8 bytes) and only its addresses are needed;
        // it is often truncated, and its length is not validated
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

/// Where the TCP or UDP header starts and which it is, for a packet whose transport header follows the
/// IP header directly: an IPv4 packet that is not a fragment, or an IPv6 packet without extension
/// headers. Other packets return `None`.
fn transport_at(packet: &[u8]) -> Option<(usize, u8)> {
    match packet.first()? >> 4 {
        4 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            let fragment = u16_at(packet, 6)? & 0x3fff;
            (header >= IPV4_MIN_HEADER && fragment == 0).then_some((header, *packet.get(9)?))
        }
        6 => Some((IPV6_HEADER, *packet.get(6)?)),
        _ => None,
    }
}

/// Adds `data` as 16-bit big-endian words to `sum`; an odd last byte is padded with zero.
fn add_words(mut sum: u32, data: &[u8]) -> u32 {
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        sum += u32::from(u16::from_be_bytes(*w));
    }
    if let [last] = rest {
        sum += u32::from(*last) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

/// The TCP or UDP checksum of `segment` between `src` and `dst`, computed with the checksum field
/// treated as zero.
fn transport_checksum(src: IpAddr, dst: IpAddr, protocol: u8, segment: &[u8], at: usize) -> u16 {
    let mut sum = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => add_words(add_words(0, &s.octets()), &d.octets()),
        (IpAddr::V6(s), IpAddr::V6(d)) => add_words(add_words(0, &s.octets()), &d.octets()),
        // Both addresses of a packet are of one family
        _ => 0,
    };
    sum += u32::from(protocol) + u32::try_from(segment.len()).unwrap_or(0);
    sum = add_words(sum, &segment[..at]);
    sum = add_words(sum, segment.get(at + 2..).unwrap_or(&[]));
    match fold(sum) {
        // Zero means "no checksum" for UDP
        0 if protocol == PROTO_UDP => 0xffff,
        c => c,
    }
}

/// Fills in the TCP or UDP checksum of a packet from this machine to itself: macOS leaves it unfilled
/// for local traffic, which on the utun is then rejected on the way back in (design/userspace.md
/// section 4). Other packets are left as they are.
pub fn fill_checksum(packet: &mut [u8]) {
    let Some(ip) = parse(packet) else {
        return;
    };
    let Some((header, protocol)) = transport_at(packet) else {
        return;
    };
    let field = match protocol {
        PROTO_TCP => 16,
        PROTO_UDP => 6,
        _ => return,
    };
    let Some(segment) = packet.get_mut(header..ip.len) else {
        return;
    };
    if segment.len() < field + 2 {
        return;
    }
    let sum = transport_checksum(ip.src, ip.dst, protocol, segment, field);
    segment[field..field + 2].copy_from_slice(&sum.to_be_bytes());
}

/// The UDP payload of a packet whose UDP header follows the IP header directly.
pub fn udp_payload<'a>(packet: &'a [u8], ip: &Ip) -> Option<&'a [u8]> {
    let (header, protocol) = transport_at(packet)?;
    (protocol == PROTO_UDP).then_some(())?;
    packet.get(header + 8..ip.len)
}

/// A UDP datagram from `src`:`sport` to `dst`:`dport` carrying `payload`, with its checksums; `None`
/// when the addresses are of different families or it would not fit in one IP packet.
pub fn udp(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, payload: &[u8]) -> Option<Vec<u8>> {
    let udp_len = u16::try_from(8 + payload.len()).ok()?;
    let mut segment = Vec::with_capacity(usize::from(udp_len));
    segment.extend_from_slice(&sport.to_be_bytes());
    segment.extend_from_slice(&dport.to_be_bytes());
    segment.extend_from_slice(&udp_len.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);
    let sum = transport_checksum(src, dst, PROTO_UDP, &segment, 6);
    segment[6..8].copy_from_slice(&sum.to_be_bytes());
    let mut packet = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = u16::try_from(IPV4_MIN_HEADER + segment.len()).ok()?;
            let mut h = vec![0x45, 0];
            h.extend_from_slice(&total.to_be_bytes());
            // No identification, do not fragment, time to live 64
            h.extend_from_slice(&[0, 0, 0x40, 0, 64, PROTO_UDP, 0, 0]);
            h.extend_from_slice(&s.octets());
            h.extend_from_slice(&d.octets());
            let sum = fold(add_words(0, &h));
            h[10..12].copy_from_slice(&sum.to_be_bytes());
            h
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut h = vec![0x60, 0, 0, 0];
            h.extend_from_slice(&udp_len.to_be_bytes());
            h.extend_from_slice(&[PROTO_UDP, 64]);
            h.extend_from_slice(&s.octets());
            h.extend_from_slice(&d.octets());
            h
        }
        _ => return None,
    };
    packet.extend_from_slice(&segment);
    Some(packet)
}

#[cfg(test)]
pub(crate) mod build {
    //! Builds inner packets in tests.

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
                // Header checksum: this machine's protocol stack verifies it on receipt
                let mut sum: u32 = p
                    .chunks(2)
                    .map(|c| u32::from(u16::from_be_bytes([c[0], c[1]])))
                    .sum();
                while sum >> 16 != 0 {
                    sum = (sum & 0xffff) + (sum >> 16);
                }
                let sum = !u16::try_from(sum).expect("folded");
                p[10..12].copy_from_slice(&sum.to_be_bytes());
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

    /// An ICMP error message sent by `src` about `original` (IPv4 unreachable / IPv6 packet too big).
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

    /// The UDP checksum carried by `packet`.
    fn udp_sum(packet: &[u8]) -> u16 {
        let (at, _) = transport_at(packet).expect("udp");
        u16::from_be_bytes([packet[at + 6], packet[at + 7]])
    }

    #[test]
    fn builds_a_udp_datagram_with_its_checksums() {
        // Reference checksums computed independently from the pseudo-headers of RFC 768 and RFC 8200
        for (addr, want) in [("100.88.0.4", 0x90be), ("fd00:88::4", 0x5e5d)] {
            let a = ip(addr);
            let packet = udp(a, 50000, a, 53, b"nett").expect("fits");
            let parsed = parse(&packet).expect("parses");
            assert_eq!(
                parsed.transport,
                Transport::Udp {
                    src_port: 50000,
                    dst_port: 53
                }
            );
            assert_eq!(udp_payload(&packet, &parsed), Some(&b"nett"[..]));
            assert_eq!(udp_sum(&packet), want, "{addr}");
            if a.is_ipv4() {
                assert_eq!(fold(add_words(0, &packet[..20])), 0, "IPv4 header checksum");
            }
        }
        assert!(udp(ip("100.88.0.4"), 1, ip("fd00:88::4"), 2, b"").is_none());
    }

    #[test]
    fn fills_in_a_checksum_the_system_left_out() {
        for addr in ["100.88.0.4", "fd00:88::4"] {
            let a = ip(addr);
            let whole = udp(a, 50000, a, 53, b"nett").expect("fits");
            let mut unfilled = whole.clone();
            let (at, _) = transport_at(&unfilled).expect("udp");
            unfilled[at + 6..at + 8].copy_from_slice(&[0x12, 0x34]);
            fill_checksum(&mut unfilled);
            assert_eq!(unfilled, whole, "{addr}");
        }
        // A TCP segment gets its checksum at its own offset; the rest of the packet is unchanged
        let mut syn = build::tcp(ip("fd00:88::4"), 40000, ip("fd00:88::4"), 22, 0x02);
        let before = syn.clone();
        fill_checksum(&mut syn);
        assert_eq!(syn[..56], before[..56]);
        assert_ne!(syn[56..58], [0, 0]);
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
        // Truncated transport layer header: still a valid IP packet, but with no ports
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
        // IPv6: a fragment extension header with a non-zero offset
        let udp = build::udp(ip("fd00:88::1"), 1, ip("fd00:88::2"), 2);
        let mut v6 = udp[..40].to_vec();
        v6[6] = 44;
        v6.extend_from_slice(&[PROTO_UDP, 0, 0x00, 0x08, 0, 0, 0, 1]);
        v6.extend_from_slice(&udp[40..]);
        let plen = u16::try_from(v6.len() - 40).expect("len");
        v6[4..6].copy_from_slice(&plen.to_be_bytes());
        assert_eq!(parse(&v6).expect("fragment").transport, Transport::Fragment);
        // A fragment with offset 0 parses the transport layer as usual
        v6[42..44].copy_from_slice(&[0, 0x01]);
        assert!(matches!(
            parse(&v6).expect("first fragment").transport,
            Transport::Udp { .. }
        ));
    }
}
