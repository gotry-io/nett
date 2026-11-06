//! 在内核 WireGuard 的端口上收发直连探测（design/mesh.md 第 7.1 节）：原始套接字发出源端口为
//! WireGuard 端口的 UDP 包，走的就是 WireGuard 自己的 NAT 映射；接收用挂了 BPF 过滤器的原始套接字，
//! 只把发往这个端口、首字节为直连探测类型的包的副本交给用户态。内核 WireGuard 收到这些包后直接丢弃。
//! 需要 `CAP_NET_RAW`。

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::{AsFd, OwnedFd};
use std::time::Duration;

use rustix::net::sockopt::{Timeout, set_socket_timeout};
use rustix::net::{
    AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, ipproto, recvfrom, sendto,
    socket_with,
};

use super::sys::{BpfInsn, attach_filter, insn};
use crate::probe::{DIRECT_PROBE, DIRECT_REPLY};

/// 接收超时：接收线程据此定期检查是否该退出。
const RECV_TIMEOUT: Duration = Duration::from_millis(500);
const UDP_HEADER_LEN: usize = 8;
const IPPROTO_UDP: u8 = 17;

// 经典 BPF 的指令码（include/uapi/linux/filter.h）
const LD_H_ABS: u16 = 0x28;
const LD_B_ABS: u16 = 0x30;
const LD_H_IND: u16 = 0x48;
const LD_B_IND: u16 = 0x50;
const LDX_B_MSH: u16 = 0xb1;
const JEQ_K: u16 = 0x15;
const RET_K: u16 = 0x06;

/// IPv4：数据从 IP 头开始。X = IP 头长度；目的端口为 WireGuard 端口、负载首字节为 0x82 或 0x83 时放行。
fn filter_v4(port: u16) -> [BpfInsn; 8] {
    [
        insn(LDX_B_MSH, 0, 0, 0),
        insn(LD_H_IND, 0, 0, 2),
        insn(JEQ_K, 0, 4, u32::from(port)),
        insn(LD_B_IND, 0, 0, 8),
        insn(JEQ_K, 1, 0, u32::from(DIRECT_PROBE)),
        insn(JEQ_K, 0, 1, u32::from(DIRECT_REPLY)),
        insn(RET_K, 0, 0, 0xffff),
        insn(RET_K, 0, 0, 0),
    ]
}

/// IPv6：原始套接字收到的数据从 UDP 头开始。
fn filter_v6(port: u16) -> [BpfInsn; 7] {
    [
        insn(LD_H_ABS, 0, 0, 2),
        insn(JEQ_K, 0, 4, u32::from(port)),
        insn(LD_B_ABS, 0, 0, 8),
        insn(JEQ_K, 1, 0, u32::from(DIRECT_PROBE)),
        insn(JEQ_K, 0, 1, u32::from(DIRECT_REPLY)),
        insn(RET_K, 0, 0, 0xffff),
        insn(RET_K, 0, 0, 0),
    ]
}

pub struct WgPort {
    port: u16,
    v4: OwnedFd,
    v6: OwnedFd,
}

fn raw_socket(family: AddressFamily) -> io::Result<OwnedFd> {
    let fd = socket_with(
        family,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        Some(ipproto::UDP),
    )?;
    set_socket_timeout(&fd, Timeout::Recv, Some(RECV_TIMEOUT))?;
    Ok(fd)
}

impl WgPort {
    pub fn open(port: u16) -> io::Result<Self> {
        let v4 = raw_socket(AddressFamily::INET)?;
        attach_filter(v4.as_fd(), &filter_v4(port))?;
        let v6 = raw_socket(AddressFamily::INET6)?;
        attach_filter(v6.as_fd(), &filter_v6(port))?;
        Ok(Self { port, v4, v6 })
    }

    /// 以 WireGuard 端口为源端口发出一个 UDP 包。
    pub fn send(&self, to: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let src = source_for(to)?;
        let packet = udp_packet(src, to, self.port, payload);
        // 原始套接字的目的端口写在 UDP 头里，地址中的端口为 0
        match to.ip() {
            IpAddr::V4(ip) => sendto(
                &self.v4,
                &packet,
                SendFlags::empty(),
                &SocketAddrV4::new(ip, 0),
            )?,
            IpAddr::V6(ip) => sendto(
                &self.v6,
                &packet,
                SendFlags::empty(),
                &SocketAddrV6::new(ip, 0, 0, 0),
            )?,
        };
        Ok(())
    }

    /// 接收一个 IPv4 副本：返回来源与负载。超时或不是发往本端口的包时返回 `None`。
    pub fn recv_v4(&self, buf: &mut [u8]) -> io::Result<Option<(SocketAddr, Vec<u8>)>> {
        let Some(len) = recv(&self.v4, buf)?.map(|(len, _)| len) else {
            return Ok(None);
        };
        let b = &buf[..len];
        if b.len() < 20 || b[0] >> 4 != 4 || b[9] != IPPROTO_UDP {
            return Ok(None);
        }
        let ihl = usize::from(b[0] & 0x0f) * 4;
        let src = Ipv4Addr::new(b[12], b[13], b[14], b[15]);
        Ok(self.parse_udp(IpAddr::V4(src), b.get(ihl..).unwrap_or_default()))
    }

    pub fn recv_v6(&self, buf: &mut [u8]) -> io::Result<Option<(SocketAddr, Vec<u8>)>> {
        let Some((len, from)) = recv(&self.v6, buf)? else {
            return Ok(None);
        };
        let Some(IpAddr::V6(src)) = from else {
            return Ok(None);
        };
        Ok(self.parse_udp(IpAddr::V6(src), &buf[..len]))
    }

    fn parse_udp(&self, src: IpAddr, udp: &[u8]) -> Option<(SocketAddr, Vec<u8>)> {
        if udp.len() < UDP_HEADER_LEN {
            return None;
        }
        let sport = u16::from_be_bytes([udp[0], udp[1]]);
        let dport = u16::from_be_bytes([udp[2], udp[3]]);
        let len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
        if dport != self.port || len < UDP_HEADER_LEN || len > udp.len() {
            return None;
        }
        Some((
            SocketAddr::new(src, sport),
            udp[UDP_HEADER_LEN..len].to_vec(),
        ))
    }
}

fn recv(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<Option<(usize, Option<IpAddr>)>> {
    match recvfrom(fd, &mut *buf, RecvFlags::empty()) {
        Ok((len, _, addr)) => {
            let ip = addr
                .and_then(|a| SocketAddr::try_from(a).ok())
                .map(|a| a.ip());
            Ok(Some((len, ip)))
        }
        Err(e) if e == rustix::io::Errno::AGAIN || e == rustix::io::Errno::INTR => Ok(None),
        Err(e) => Err(e.into()),
    }
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
}
