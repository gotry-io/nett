//! 以内核 WireGuard 的端口为源端口发送直连探测（design/mesh.md 第 7.1 节），走的就是 WireGuard 自己的
//! NAT 映射。接收由 nftables 规则只拷贝探测包（[`super::nft`]）。
//!
//! 发送用 `IPPROTO_RAW` 原始套接字，IP 头自己构造：这种套接字只能发送，内核不会把收到的包复制给它；
//! `IPPROTO_UDP` 的原始套接字则会收到每个进来的 UDP 包的副本，即使从不读取，也拖慢 WireGuard 的收包。
//! 发出的包照常经过连接跟踪与 NAT。需要 `CAP_NET_RAW`。

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::OwnedFd;

use rustix::net::{
    AddressFamily, SendFlags, SocketFlags, SocketType, ipproto, sendto, socket_with,
};

const UDP_HEADER_LEN: usize = 8;
const IPPROTO_UDP: u8 = 17;
const TTL: u8 = 64;

pub struct WgPort {
    port: u16,
    v4: OwnedFd,
    v6: OwnedFd,
}

fn raw_socket(family: AddressFamily) -> io::Result<OwnedFd> {
    Ok(socket_with(
        family,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        Some(ipproto::RAW),
    )?)
}

impl WgPort {
    pub fn open(port: u16) -> io::Result<Self> {
        Ok(Self {
            port,
            v4: raw_socket(AddressFamily::INET)?,
            v6: raw_socket(AddressFamily::INET6)?,
        })
    }

    /// 以 WireGuard 端口为源端口发出一个 UDP 包。
    pub fn send(&self, to: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let src = source_for(to)?;
        let udp = udp_packet(src, to, self.port, payload);
        match (src, to.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let packet = ipv4_packet(s, d, &udp);
                sendto(
                    &self.v4,
                    &packet,
                    SendFlags::empty(),
                    &SocketAddrV4::new(d, 0),
                )?;
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                let packet = ipv6_packet(s, d, &udp);
                sendto(
                    &self.v6,
                    &packet,
                    SendFlags::empty(),
                    &SocketAddrV6::new(d, 0, 0, 0),
                )?;
            }
            _ => {
                return Err(io::Error::other(
                    "source and destination address families differ",
                ));
            }
        }
        Ok(())
    }
}

/// IPv4 头（20 字节）加 UDP 包。标识与头校验和留 0，由内核填写。
fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> Vec<u8> {
    let total = u16::try_from(20 + udp.len()).unwrap_or(u16::MAX);
    let mut p = Vec::with_capacity(20 + udp.len());
    p.extend_from_slice(&[0x45, 0]);
    p.extend_from_slice(&total.to_be_bytes());
    // 标识 0（内核填写）；不分片标志
    p.extend_from_slice(&[0, 0, 0x40, 0]);
    p.extend_from_slice(&[TTL, IPPROTO_UDP, 0, 0]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(udp);
    p
}

/// IPv6 头（40 字节）加 UDP 包。
fn ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, udp: &[u8]) -> Vec<u8> {
    let len = u16::try_from(udp.len()).unwrap_or(u16::MAX);
    let mut p = Vec::with_capacity(40 + udp.len());
    p.extend_from_slice(&[0x60, 0, 0, 0]);
    p.extend_from_slice(&len.to_be_bytes());
    p.extend_from_slice(&[IPPROTO_UDP, TTL]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(udp);
    p
}

/// 内核发往 `to` 时会选用的源地址：与 WireGuard 自己的包一样按路由选择。
fn source_for(to: SocketAddr) -> io::Result<IpAddr> {
    let bind: SocketAddr = match to {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let probe = UdpSocket::bind(bind)?;
    probe.connect(to)?;
    Ok(probe.local_addr()?.ip())
}

/// UDP 头加负载，校验和按伪首部计算（IPv6 必须有校验和）。
fn udp_packet(src: IpAddr, dst: SocketAddr, sport: u16, payload: &[u8]) -> Vec<u8> {
    let len = UDP_HEADER_LEN + payload.len();
    let len16 = u16::try_from(len).unwrap_or(u16::MAX);
    let mut packet = Vec::with_capacity(len);
    packet.extend_from_slice(&sport.to_be_bytes());
    packet.extend_from_slice(&dst.port().to_be_bytes());
    packet.extend_from_slice(&len16.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(payload);

    let mut pseudo = Vec::with_capacity(40);
    match (src, dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.extend_from_slice(&[0, IPPROTO_UDP]);
            pseudo.extend_from_slice(&len16.to_be_bytes());
        }
        (s, d) => {
            let v6 = |ip: IpAddr| match ip {
                IpAddr::V6(a) => a.octets(),
                IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
            };
            pseudo.extend_from_slice(&v6(s));
            pseudo.extend_from_slice(&v6(d));
            pseudo.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, IPPROTO_UDP]);
        }
    }
    let sum = checksum(&[&pseudo, &packet]);
    // 校验和为 0 表示"没有校验和"，算出 0 时写作 0xffff
    let sum = if sum == 0 { 0xffff } else { sum };
    packet[6..8].copy_from_slice(&sum.to_be_bytes());
    packet
}

fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for part in parts {
        let (pairs, rest) = part.as_chunks::<2>();
        for c in pairs {
            sum += u32::from(u16::from_be_bytes(*c));
        }
        if let [last] = rest {
            sum += u32::from(*last) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(u16::try_from(sum).unwrap_or(u16::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_checksum_verifies() {
        let src: IpAddr = "198.51.100.1".parse().expect("ip");
        let dst: SocketAddr = "198.51.100.2:41820".parse().expect("addr");
        let packet = udp_packet(src, dst, 41820, &[0x82; 64]);
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&[198, 51, 100, 1, 198, 51, 100, 2, 0, 17]);
        pseudo.extend_from_slice(&u16::try_from(packet.len()).expect("len").to_be_bytes());
        // 带上校验和重新计算，结果为 0 说明校验和正确
        assert_eq!(checksum(&[&pseudo, &packet]), 0);
    }

    #[test]
    fn ip_headers_carry_lengths_and_protocol() {
        let udp = vec![0u8; 72];
        let v4 = ipv4_packet(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), &udp);
        assert_eq!(
            (v4[0], u16::from_be_bytes([v4[2], v4[3]]), v4[9]),
            (0x45, 92, 17)
        );
        let v6 = ipv6_packet(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, &udp);
        assert_eq!(
            (v6[0] >> 4, u16::from_be_bytes([v6[4], v6[5]]), v6[6]),
            (6, 72, 17)
        );
    }
}
