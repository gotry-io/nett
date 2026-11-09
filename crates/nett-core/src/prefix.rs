//! 网段：组网网段、WireGuard 的 `AllowedIPs`、访问规则与 Edge 的来源。

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{0}` is not an address/prefix-length with zero host bits")]
pub struct PrefixError(String);

/// 一个 IPv4 或 IPv6 网段，主机位必须为 0。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpPrefix {
    addr: IpAddr,
    len: u8,
}

impl IpPrefix {
    pub fn new(addr: IpAddr, len: u8) -> Option<Self> {
        let max = max_len(addr);
        (len <= max && mask(addr, len) == addr).then_some(Self { addr, len })
    }

    /// 只含一个地址的网段（`/32` 或 `/128`）。
    pub fn host(addr: IpAddr) -> Self {
        Self {
            addr,
            len: max_len(addr),
        }
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        addr.is_ipv4() == self.addr.is_ipv4() && mask(addr, self.len) == self.addr
    }

    /// `other` 整个落在本网段之内。
    pub fn covers(&self, other: &IpPrefix) -> bool {
        other.len >= self.len && self.contains(other.addr)
    }
}

fn max_len(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

fn mask(addr: IpAddr, len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => {
            let bits = u32::from(a);
            let m = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(bits & m))
        }
        IpAddr::V6(a) => {
            let bits = u128::from(a);
            let m = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(bits & m))
        }
    }
}

impl FromStr for IpPrefix {
    type Err = PrefixError;

    fn from_str(s: &str) -> Result<Self, PrefixError> {
        let err = || PrefixError(s.to_owned());
        let (addr, len) = s.split_once('/').ok_or_else(err)?;
        let addr: IpAddr = addr.parse().map_err(|_| err())?;
        // 只接受规范的十进制写法，例如不接受 `/016`
        let len: u8 = len.parse().map_err(|_| err())?;
        if s != format!("{addr}/{len}") {
            return Err(err());
        }
        Self::new(addr, len).ok_or_else(err)
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl Serialize for IpPrefix {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for IpPrefix {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> IpPrefix {
        s.parse().expect(s)
    }

    #[test]
    fn parses_canonical_prefixes_only() {
        assert_eq!(p("100.88.0.0/16").prefix_len(), 16);
        assert_eq!(p("fd00:88::/48").to_string(), "fd00:88::/48");
        for bad in [
            "100.88.0.1/16",
            "100.88.0.0/33",
            "100.88.0.0/016",
            "fd00:88:0::/48",
            "100.88.0.0",
        ] {
            assert!(bad.parse::<IpPrefix>().is_err(), "{bad}");
        }
    }

    #[test]
    fn containment() {
        let mesh = p("100.88.0.0/16");
        assert!(mesh.contains("100.88.3.4".parse().expect("ip")));
        assert!(!mesh.contains("100.89.0.1".parse().expect("ip")));
        assert!(!mesh.contains("fd00::1".parse().expect("ip")));
        assert!(p("100.64.0.0/10").covers(&mesh));
        assert!(!mesh.covers(&p("100.64.0.0/10")));
        assert!(p("0.0.0.0/0").contains("8.8.8.8".parse().expect("ip")));
    }
}
