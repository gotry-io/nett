//! This machine's LAN addresses (design/status.md section 6): private IPv4 addresses and IPv6 unique
//! local addresses on its interfaces, with their prefix lengths. The mesh process lists them in status,
//! and the Hub composes LAN direct candidates from them (design/mesh.md section 6).
//!
//! `unsafe` is allowed in this module only: the standard library cannot list interface addresses, so it
//! calls `getifaddrs` from libc; every use says why it holds.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use nett_core::prefix::IpPrefix;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Most LAN addresses listed.
pub const MAX_LAN_ADDRESSES: usize = 8;

/// Interfaces of containers, virtual machines and bridges carry addresses that are not a LAN shared with
/// other machines.
const VIRTUAL_PREFIXES: [&str; 9] = [
    "docker", "br-", "veth", "virbr", "cni", "flannel", "vmnet", "bridge", "utun",
];

/// A LAN address and the length of its prefix, written `192.168.1.10/24`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LanAddress {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl LanAddress {
    /// The network it is on.
    pub fn network(&self) -> Option<IpPrefix> {
        IpPrefix::containing(self.addr, self.prefix_len)
    }

    /// Whether `other` is a different address on the same network.
    pub fn shares_network(&self, other: &LanAddress) -> bool {
        self.addr != other.addr
            && self.prefix_len == other.prefix_len
            && self.network().is_some()
            && self.network() == other.network()
    }
}

impl fmt::Display for LanAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{0}` is not a LAN address with a prefix length, such as 192.168.1.10/24")]
pub struct LanAddressError(String);

impl FromStr for LanAddress {
    type Err = LanAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || LanAddressError(s.chars().take(64).collect());
        let (addr, len) = s.split_once('/').ok_or_else(err)?;
        let addr: IpAddr = addr.parse().map_err(|_| err())?;
        let prefix_len: u8 = len.parse().map_err(|_| err())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix_len == 0 || prefix_len > max || !is_lan(addr) {
            return Err(err());
        }
        Ok(Self { addr, prefix_len })
    }
}

impl Serialize for LanAddress {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for LanAddress {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A private IPv4 address or an IPv6 unique local address: what a LAN uses, and what is not reachable
/// from the internet.
pub fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// The LAN addresses on this machine's interfaces, leaving out loopback, virtual interfaces and the
/// addresses in `mesh` (the mesh interface's own); at most [`MAX_LAN_ADDRESSES`].
pub fn addresses(mesh: &[IpPrefix]) -> Vec<LanAddress> {
    let mut out: Vec<LanAddress> = interfaces()
        .into_iter()
        .filter(|(name, _)| !VIRTUAL_PREFIXES.iter().any(|p| name.starts_with(p)))
        .map(|(_, a)| a)
        .filter(|a| is_lan(a.addr) && !mesh.iter().any(|m| m.contains(a.addr)))
        .collect();
    out.sort();
    out.dedup();
    out.truncate(MAX_LAN_ADDRESSES);
    out
}

/// Interface names and their addresses with prefix lengths.
fn interfaces() -> Vec<(String, LanAddress)> {
    let mut out = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list` with a linked list it allocates, freed below with freeifaddrs
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return out;
    }
    let mut cursor = list;
    while !cursor.is_null() {
        // SAFETY: `cursor` is a node of the list getifaddrs returned, valid until freeifaddrs
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_name.is_null() || (entry.ifa_flags & libc::IFF_LOOPBACK as libc::c_uint) != 0 {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated string owned by the list
        let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: the address and netmask point at sockaddr structures of their family, or are null
        let pair = unsafe { (sockaddr_ip(entry.ifa_addr), sockaddr_ip(entry.ifa_netmask)) };
        if let (Some(addr), Some(mask)) = pair {
            let prefix_len = match mask {
                IpAddr::V4(m) => u32::from(m).count_ones(),
                IpAddr::V6(m) => u128::from(m).count_ones(),
            };
            if let Ok(prefix_len) = u8::try_from(prefix_len)
                && prefix_len > 0
                && addr.is_ipv4() == mask.is_ipv4()
            {
                out.push((name, LanAddress { addr, prefix_len }));
            }
        }
    }
    // SAFETY: frees the list getifaddrs returned; no reference into it outlives this call
    unsafe { libc::freeifaddrs(list) };
    out
}

/// The IP address in a `sockaddr` of family IPv4 or IPv6.
///
/// # Safety
///
/// `sa` is null or points at a `sockaddr` whose family field tells its real type.
unsafe fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `sa` points at a sockaddr; the family says which one
    match i32::from(unsafe { (*sa).sa_family }) {
        libc::AF_INET => {
            let v4 = unsafe { &*(sa.cast::<libc::sockaddr_in>()) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr))))
        }
        libc::AF_INET6 => {
            let v6 = unsafe { &*(sa.cast::<libc::sockaddr_in6>()) };
            Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_addresses_parse_and_share_networks() {
        let a: LanAddress = "192.168.1.10/24".parse().expect("valid");
        let b: LanAddress = "192.168.1.20/24".parse().expect("valid");
        let c: LanAddress = "192.168.2.20/24".parse().expect("valid");
        assert!(a.shares_network(&b));
        assert!(!a.shares_network(&c));
        assert!(
            !a.shares_network(&a),
            "the same address is not a peer on the LAN"
        );
        assert_eq!(a.to_string(), "192.168.1.10/24");
        assert!("8.8.8.8/24".parse::<LanAddress>().is_err(), "public");
        assert!("192.168.1.10".parse::<LanAddress>().is_err(), "no prefix");
        assert!("fd12::1/64".parse::<LanAddress>().is_ok());
        assert!("2001:db8::1/64".parse::<LanAddress>().is_err());
        let json = serde_json::to_string(&a).expect("json");
        assert_eq!(json, "\"192.168.1.10/24\"");
    }

    #[test]
    fn this_machine_lists_no_loopback_or_mesh_addresses() {
        let mesh: IpPrefix = "fd00:88::/48".parse().expect("prefix");
        for a in addresses(&[mesh]) {
            assert!(!a.addr.is_loopback());
            assert!(!mesh.contains(a.addr));
            assert!(is_lan(a.addr));
        }
    }
}
