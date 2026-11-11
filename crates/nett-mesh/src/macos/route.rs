//! Messages of the routing socket (`<net/route.h>`): routes on the mesh interface are added and deleted
//! through it, and the physical interface carrying the default route is selected from the routing table
//! (design/userspace.md sections 6.1 and 6.4). This module only encodes and parses bytes; the system
//! calls are in [`super::sys`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nett_core::prefix::IpPrefix;

/// Length of `struct rt_msghdr`.
const HEADER: usize = 92;
const RTM_VERSION: u8 = 5;
pub const RTM_ADD: u8 = 1;
pub const RTM_DELETE: u8 = 2;
const RTF_UP: i32 = 0x1;
const RTF_GATEWAY: i32 = 0x2;
const RTF_STATIC: i32 = 0x800;
const RTF_IFSCOPE: i32 = 0x0100_0000;
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const RTA_NETMASK: i32 = 0x4;
/// The order of addresses in a message: each bit corresponds to one kind of address, arranged in turn.
const RTAX_MAX: usize = 8;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 30;

/// Addresses in routing messages are aligned to 4 bytes, and a length of 0 occupies 4 bytes.
fn rounded(len: usize) -> usize {
    if len == 0 { 4 } else { (len + 3) & !3 }
}

fn sockaddr(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(a) => {
            let mut s = vec![16, AF_INET, 0, 0];
            s.extend_from_slice(&a.octets());
            s.extend_from_slice(&[0; 8]);
            s
        }
        IpAddr::V6(a) => {
            let mut s = vec![28, AF_INET6, 0, 0, 0, 0, 0, 0];
            s.extend_from_slice(&a.octets());
            s.extend_from_slice(&[0; 4]);
            s
        }
    }
}

fn mask(prefix: &IpPrefix) -> IpAddr {
    let len = u32::from(prefix.prefix_len());
    match prefix.addr() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(u32::MAX.checked_shl(32 - len).unwrap_or(0))),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(
            u128::MAX.checked_shl(128 - len).unwrap_or(0),
        )),
    }
}

/// Adds or deletes a route via the interface address `via`: the gateway is the address on this machine's
/// interface, without `RTF_GATEWAY`, i.e. "directly reachable via this interface", the same as
/// `route add -net <prefix> -interface <address>`.
pub fn message(kind: u8, prefix: &IpPrefix, via: IpAddr, seq: i32) -> Vec<u8> {
    let addrs = [
        sockaddr(prefix.addr()),
        sockaddr(via),
        sockaddr(mask(prefix)),
    ];
    let len = HEADER + addrs.iter().map(|a| rounded(a.len())).sum::<usize>();
    let mut m = vec![0u8; HEADER];
    m[0..2].copy_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_ne_bytes());
    m[2] = RTM_VERSION;
    m[3] = kind;
    m[8..12].copy_from_slice(&(RTF_UP | RTF_STATIC).to_ne_bytes());
    m[12..16].copy_from_slice(&(RTA_DST | RTA_GATEWAY | RTA_NETMASK).to_ne_bytes());
    m[20..24].copy_from_slice(&seq.to_ne_bytes());
    for a in addrs {
        let padded = rounded(a.len());
        m.extend_from_slice(&a);
        m.resize(m.len() + padded - a.len(), 0);
    }
    m
}

/// A default route in the routing table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    pub index: u16,
    /// An interface-scoped route (`RTF_IFSCOPE`): when another interface (for example the proxy app's utun)
    /// has taken over the unscoped default route, the physical interface's default route is of this kind.
    pub scoped: bool,
}

/// Takes the IPv4 default routes with a gateway from a routing table dump (`NET_RT_FLAGS`). Messages with
/// a bad format are skipped.
pub fn defaults(dump: &[u8]) -> Vec<DefaultRoute> {
    let mut out = Vec::new();
    let mut rest = dump;
    while rest.len() >= 4 {
        let len = usize::from(u16::from_ne_bytes([rest[0], rest[1]]));
        if len < 4 || len > rest.len() {
            break;
        }
        let (msg, next) = rest.split_at(len);
        rest = next;
        if msg.len() < HEADER || msg[2] != RTM_VERSION {
            continue;
        }
        let index = u16::from_ne_bytes([msg[4], msg[5]]);
        let flags = i32::from_ne_bytes([msg[8], msg[9], msg[10], msg[11]]);
        let addrs = i32::from_ne_bytes([msg[12], msg[13], msg[14], msg[15]]);
        if flags & RTF_GATEWAY == 0 {
            continue;
        }
        let mut at = HEADER;
        let mut dst = None;
        let mut netmask_zero = true;
        for bit in 0..RTAX_MAX {
            if addrs & (1 << bit) == 0 {
                continue;
            }
            let Some(&sa_len) = msg.get(at) else {
                break;
            };
            let sa = msg.get(at..at + usize::from(sa_len)).unwrap_or(&[]);
            match 1 << bit {
                RTA_DST => dst = sa.get(4..8).map(|o| Ipv4Addr::new(o[0], o[1], o[2], o[3])),
                // The mask may be truncated: only written up to the last non-zero byte
                RTA_NETMASK => netmask_zero = sa.iter().skip(4).all(|b| *b == 0),
                _ => {}
            }
            at += rounded(usize::from(sa_len));
        }
        if dst == Some(Ipv4Addr::UNSPECIFIED) && netmask_zero {
            out.push(DefaultRoute {
                index,
                scoped: flags & RTF_IFSCOPE != 0,
            });
        }
    }
    out
}

/// Selects the physical interface carrying the default route: skips tunnel and similar interfaces (`skip`
/// judges the interface name), and prefers the unscoped default route.
pub fn physical(defaults: &[DefaultRoute], name_of: impl Fn(u16) -> Option<String>) -> Option<u16> {
    let candidates: Vec<&DefaultRoute> = defaults
        .iter()
        .filter(|d| name_of(d.index).is_some_and(|n| !is_virtual(&n)))
        .collect();
    candidates
        .iter()
        .find(|d| !d.scoped)
        .or_else(|| candidates.first())
        .map(|d| d.index)
}

/// Tunnel, virtual machine bridge, point-to-point and similar interfaces: they do not carry traffic to the
/// underlying network.
pub fn is_virtual(name: &str) -> bool {
    const PREFIXES: [&str; 10] = [
        "utun", "ipsec", "ppp", "gif", "stf", "awdl", "llw", "bridge", "anpi", "lo",
    ];
    PREFIXES.iter().any(|p| name.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> IpPrefix {
        s.parse().expect(s)
    }

    #[test]
    fn route_message_layout() {
        let m = message(
            RTM_ADD,
            &p("100.88.0.0/16"),
            "100.88.0.4".parse().expect("ip"),
            7,
        );
        assert_eq!(m.len(), HEADER + 16 * 3);
        assert_eq!(usize::from(u16::from_ne_bytes([m[0], m[1]])), m.len());
        assert_eq!((m[2], m[3]), (RTM_VERSION, RTM_ADD));
        // The destination is a network address, with mask /16
        assert_eq!(&m[HEADER + 4..HEADER + 8], &[100, 88, 0, 0]);
        assert_eq!(&m[HEADER + 20..HEADER + 24], &[100, 88, 0, 4]);
        assert_eq!(&m[HEADER + 36..HEADER + 40], &[255, 255, 0, 0]);

        let v6 = message(
            RTM_DELETE,
            &p("fd00:88::/48"),
            "fd00:88::5".parse().expect("ip"),
            8,
        );
        assert_eq!(v6.len(), HEADER + 28 * 3);
        assert_eq!(v6[HEADER + 1], AF_INET6);
        let mask: [u8; 16] = v6[HEADER + 56 + 8..HEADER + 56 + 24]
            .try_into()
            .expect("mask");
        assert_eq!(
            Ipv6Addr::from(mask),
            "ffff:ffff:ffff::".parse::<Ipv6Addr>().expect("ip")
        );
    }

    /// Builds a message in a dump: destination address, gateway, and a mask that may be truncated.
    fn entry(index: u16, flags: i32, dst: [u8; 4], mask_len: u8) -> Vec<u8> {
        let mut m = vec![0u8; HEADER];
        m[2] = RTM_VERSION;
        m[4..6].copy_from_slice(&index.to_ne_bytes());
        m[8..12].copy_from_slice(&flags.to_ne_bytes());
        m[12..16].copy_from_slice(&(RTA_DST | RTA_GATEWAY | RTA_NETMASK).to_ne_bytes());
        m.extend_from_slice(&[16, AF_INET, 0, 0]);
        m.extend_from_slice(&dst);
        m.extend_from_slice(&[0; 8]);
        m.extend_from_slice(&[16, AF_INET, 0, 0, 10, 0, 20, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        // Truncated mask: length 0 means all zeros
        m.extend_from_slice(&[mask_len, 0, 0, 0]);
        let len = u16::try_from(m.len()).expect("len");
        m[0..2].copy_from_slice(&len.to_ne_bytes());
        m
    }

    #[test]
    fn picks_the_physical_default_behind_a_proxy_tun() {
        let up_gw = RTF_UP | RTF_GATEWAY;
        let mut dump = Vec::new();
        // The proxy app's utun has taken over the unscoped default route; en0's default route is scoped to the
        // interface
        dump.extend(entry(29, up_gw, [0, 0, 0, 0], 0));
        dump.extend(entry(11, up_gw | RTF_IFSCOPE, [0, 0, 0, 0], 0));
        // Not a default route
        dump.extend(entry(11, up_gw, [10, 0, 0, 0], 0));
        dump.extend(vec![0xff; 3]);
        let defaults = defaults(&dump);
        assert_eq!(defaults.len(), 2);
        let name = |i: u16| match i {
            29 => Some("utun6".to_owned()),
            11 => Some("en0".to_owned()),
            _ => None,
        };
        assert_eq!(physical(&defaults, name), Some(11));
        // Without a proxy app: the unscoped physical default route is preferred
        let plain = [
            DefaultRoute {
                index: 12,
                scoped: true,
            },
            DefaultRoute {
                index: 11,
                scoped: false,
            },
        ];
        let names = |i: u16| Some(format!("en{}", i - 11));
        assert_eq!(physical(&plain, names), Some(11));
        assert_eq!(physical(&[], names), None);
    }
}
