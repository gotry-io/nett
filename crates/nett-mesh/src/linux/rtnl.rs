//! rtnetlink：创建 WireGuard 接口、查询接口、设置 MTU 与启用、同步地址（`include/uapi/linux/rtnetlink.h`）。

use std::net::IpAddr;

use super::netlink::{
    Message, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REPLACE, NlError, Socket,
    attrs, parse_str, parse_u32,
};

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;

const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;
/// 不做重复地址检测：组网接口上的地址由 Hub 分配，不与其他主机争用，DAD 只会让地址晚一秒可用。
const IFA_F_NODAD: u32 = 0x02;

const IFF_UP: u32 = 0x1;
const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const RT_SCOPE_UNIVERSE: u8 = 0;

const ENODEV: i32 = 19;
const EEXIST: i32 = 17;

/// `ifinfomsg` 的长度。
const IFINFO_LEN: usize = 16;
/// `ifaddrmsg` 的长度。
const IFADDR_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Link {
    pub index: u32,
    pub kind: Option<String>,
}

fn ifinfo(index: u32, flags: u32, change: u32) -> [u8; IFINFO_LEN] {
    let mut b = [0u8; IFINFO_LEN];
    b[0] = AF_UNSPEC;
    b[4..8].copy_from_slice(&index.to_ne_bytes());
    b[8..12].copy_from_slice(&flags.to_ne_bytes());
    b[12..16].copy_from_slice(&change.to_ne_bytes());
    b
}

/// 创建 WireGuard 接口；已存在时返回 `false`。
pub(crate) fn create_wireguard(sock: &mut Socket, name: &str) -> Result<bool, NlError> {
    let mut m = Message::new(RTM_NEWLINK, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
    m.fixed(&ifinfo(0, 0, 0));
    m.attr_str(IFLA_IFNAME, name);
    let info = m.begin_nested(IFLA_LINKINFO);
    m.attr_str(IFLA_INFO_KIND, "wireguard");
    m.end_nested(info);
    match sock.request(m) {
        Ok(_) => Ok(true),
        Err(e) if e.errno() == Some(EEXIST) => Ok(false),
        Err(e) => Err(e),
    }
}

/// 按名称查询接口；不存在时返回 `None`。
pub(crate) fn get_link(sock: &mut Socket, name: &str) -> Result<Option<Link>, NlError> {
    let mut m = Message::new(RTM_GETLINK, NLM_F_ACK);
    m.fixed(&ifinfo(0, 0, 0));
    m.attr_str(IFLA_IFNAME, name);
    let replies = match sock.request(m) {
        Ok(replies) => replies,
        Err(e) if e.errno() == Some(ENODEV) => return Ok(None),
        Err(e) => return Err(e),
    };
    let reply = replies
        .first()
        .ok_or(NlError::Malformed("no reply to link query"))?;
    if reply.len() < IFINFO_LEN {
        return Err(NlError::Malformed("short ifinfomsg"));
    }
    let index = parse_u32(&reply[4..8])?;
    let mut kind = None;
    for attr in attrs(&reply[IFINFO_LEN..]) {
        let (ty, payload) = attr?;
        if ty == IFLA_LINKINFO {
            for inner in attrs(payload) {
                let (ty, payload) = inner?;
                if ty == IFLA_INFO_KIND {
                    kind = Some(parse_str(payload)?.to_owned());
                }
            }
        }
    }
    Ok(Some(Link { index, kind }))
}

/// 设置 MTU 并启用接口。
pub(crate) fn set_mtu_up(sock: &mut Socket, index: u32, mtu: u32) -> Result<(), NlError> {
    let mut m = Message::new(RTM_NEWLINK, NLM_F_ACK);
    m.fixed(&ifinfo(index, IFF_UP, IFF_UP));
    m.attr_u32(IFLA_MTU, mtu);
    sock.request(m).map(drop)
}

fn ifaddr(family: u8, prefix_len: u8, index: u32) -> [u8; IFADDR_LEN] {
    let mut b = [0u8; IFADDR_LEN];
    b[0] = family;
    b[1] = prefix_len;
    b[3] = RT_SCOPE_UNIVERSE;
    b[4..8].copy_from_slice(&index.to_ne_bytes());
    b
}

fn addr_bytes(addr: IpAddr) -> (u8, Vec<u8>) {
    match addr {
        IpAddr::V4(a) => (AF_INET, a.octets().to_vec()),
        IpAddr::V6(a) => (AF_INET6, a.octets().to_vec()),
    }
}

/// 接口上现有的地址及前缀长度。
pub(crate) fn get_addresses(sock: &mut Socket, index: u32) -> Result<Vec<(IpAddr, u8)>, NlError> {
    let mut m = Message::new(RTM_GETADDR, NLM_F_DUMP);
    m.fixed(&ifaddr(AF_UNSPEC, 0, 0));
    let mut out = Vec::new();
    for reply in sock.request(m)? {
        if reply.len() < IFADDR_LEN {
            return Err(NlError::Malformed("short ifaddrmsg"));
        }
        let (family, prefix_len) = (reply[0], reply[1]);
        if parse_u32(&reply[4..8])? != index {
            continue;
        }
        for attr in attrs(&reply[IFADDR_LEN..]) {
            let (ty, payload) = attr?;
            // 点对点接口上 IFA_ADDRESS 是对端地址，本机地址在 IFA_LOCAL；IPv6 只有 IFA_ADDRESS
            let wanted = match family {
                AF_INET => ty == IFA_LOCAL,
                AF_INET6 => ty == IFA_ADDRESS,
                _ => false,
            };
            if !wanted {
                continue;
            }
            let addr = match (family, payload.len()) {
                (AF_INET, 4) => IpAddr::from(
                    <[u8; 4]>::try_from(payload).map_err(|_| NlError::Malformed("ipv4"))?,
                ),
                (AF_INET6, 16) => IpAddr::from(
                    <[u8; 16]>::try_from(payload).map_err(|_| NlError::Malformed("ipv6"))?,
                ),
                _ => return Err(NlError::Malformed("address length")),
            };
            out.push((addr, prefix_len));
        }
    }
    Ok(out)
}

pub(crate) fn add_address(
    sock: &mut Socket,
    index: u32,
    addr: IpAddr,
    prefix_len: u8,
) -> Result<(), NlError> {
    let (family, bytes) = addr_bytes(addr);
    let mut m = Message::new(RTM_NEWADDR, NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE);
    m.fixed(&ifaddr(family, prefix_len, index));
    m.attr(IFA_LOCAL, &bytes);
    m.attr(IFA_ADDRESS, &bytes);
    if family == AF_INET6 {
        m.attr_u32(IFA_FLAGS, IFA_F_NODAD);
    }
    sock.request(m).map(drop)
}

pub(crate) fn del_address(
    sock: &mut Socket,
    index: u32,
    addr: IpAddr,
    prefix_len: u8,
) -> Result<(), NlError> {
    let (family, bytes) = addr_bytes(addr);
    let mut m = Message::new(RTM_DELADDR, NLM_F_ACK);
    m.fixed(&ifaddr(family, prefix_len, index));
    m.attr(IFA_LOCAL, &bytes);
    sock.request(m).map(drop)
}
