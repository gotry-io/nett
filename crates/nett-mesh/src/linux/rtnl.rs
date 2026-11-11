//! rtnetlink: creates the WireGuard interface, queries interfaces, sets the MTU and brings it up, and
//! syncs addresses and routes (`include/uapi/linux/rtnetlink.h`).

use std::net::IpAddr;

use nett_core::prefix::IpPrefix;

use super::netlink::{
    Message, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REPLACE, NlError, Socket,
    attrs, parse_str, parse_u32,
};

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_TABLE: u16 = 15;
const RT_TABLE_MAIN: u8 = 254;
/// Routes that nett adds on the mesh interface are marked with this protocol number, to tell them apart
/// from routes the kernel adds automatically per address (`kernel`).
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_LINK: u8 = 253;
const RTN_UNICAST: u8 = 1;
const RTMSG_LEN: usize = 12;

const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;
/// No duplicate address detection: addresses on the mesh interface are allocated by the Hub and do not
/// compete with other hosts, so DAD would only make the address available a second later.
const IFA_F_NODAD: u32 = 0x02;

const IFF_UP: u32 = 0x1;
const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const RT_SCOPE_UNIVERSE: u8 = 0;

const ENODEV: i32 = 19;
const EEXIST: i32 = 17;

/// Length of `ifinfomsg`.
const IFINFO_LEN: usize = 16;
/// Length of `ifaddrmsg`.
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

/// Creates a WireGuard interface; returns `false` if it already exists.
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

/// Deletes an interface (along with its addresses and routes); returns `false` if it does not exist.
pub(crate) fn del_link(sock: &mut Socket, name: &str) -> Result<bool, NlError> {
    let mut m = Message::new(RTM_DELLINK, NLM_F_ACK);
    m.fixed(&ifinfo(0, 0, 0));
    m.attr_str(IFLA_IFNAME, name);
    match sock.request(m) {
        Ok(_) => Ok(true),
        Err(e) if e.errno() == Some(ENODEV) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Queries an interface by name; returns `None` if it does not exist.
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

/// Sets the MTU and brings up the interface.
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

/// Existing addresses on the interface and their prefix lengths.
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
            // On a point-to-point interface IFA_ADDRESS is the peer address and the local address is in IFA_LOCAL;
            // IPv6 has only IFA_ADDRESS
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

fn rtmsg(family: u8, dst_len: u8) -> [u8; RTMSG_LEN] {
    let mut b = [0u8; RTMSG_LEN];
    b[0] = family;
    b[1] = dst_len;
    b[4] = RT_TABLE_MAIN;
    b[5] = RTPROT_STATIC;
    b[6] = RT_SCOPE_LINK;
    b[7] = RTN_UNICAST;
    b
}

/// A route to `prefix` via interface `index` (main routing table, `static`). Replaces it if it already
/// exists.
pub(crate) fn add_route(sock: &mut Socket, index: u32, prefix: IpPrefix) -> Result<(), NlError> {
    let (family, bytes) = addr_bytes(prefix.addr());
    let mut m = Message::new(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE);
    m.fixed(&rtmsg(family, prefix.prefix_len()));
    m.attr(RTA_DST, &bytes);
    m.attr_u32(RTA_OIF, index);
    sock.request(m).map(drop)
}

pub(crate) fn del_route(sock: &mut Socket, index: u32, prefix: IpPrefix) -> Result<(), NlError> {
    let (family, bytes) = addr_bytes(prefix.addr());
    let mut m = Message::new(RTM_DELROUTE, NLM_F_ACK);
    m.fixed(&rtmsg(family, prefix.prefix_len()));
    m.attr(RTA_DST, &bytes);
    m.attr_u32(RTA_OIF, index);
    sock.request(m).map(drop)
}

/// Routes in the main routing table via interface `index` with protocol `static`: the ones nett adds on
/// the mesh interface.
pub(crate) fn get_routes(sock: &mut Socket, index: u32) -> Result<Vec<IpPrefix>, NlError> {
    let mut m = Message::new(RTM_GETROUTE, NLM_F_DUMP);
    m.fixed(&rtmsg(AF_UNSPEC, 0));
    let mut out = Vec::new();
    for reply in sock.request(m)? {
        if reply.len() < RTMSG_LEN {
            return Err(NlError::Malformed("short rtmsg"));
        }
        let (family, dst_len, protocol) = (reply[0], reply[1], reply[5]);
        let mut table = u32::from(reply[4]);
        if protocol != RTPROT_STATIC {
            continue;
        }
        let (mut dst, mut oif) = (None, None);
        for attr in attrs(&reply[RTMSG_LEN..]) {
            let (ty, payload) = attr?;
            match ty {
                RTA_DST => dst = Some(payload.to_vec()),
                RTA_OIF => oif = Some(parse_u32(payload)?),
                RTA_TABLE => table = parse_u32(payload)?,
                _ => {}
            }
        }
        if oif != Some(index) || table != u32::from(RT_TABLE_MAIN) {
            continue;
        }
        let addr = match (family, dst.as_deref()) {
            (AF_INET, Some(b)) if b.len() == 4 => {
                IpAddr::from(<[u8; 4]>::try_from(b).map_err(|_| NlError::Malformed("ipv4"))?)
            }
            (AF_INET6, Some(b)) if b.len() == 16 => {
                IpAddr::from(<[u8; 16]>::try_from(b).map_err(|_| NlError::Malformed("ipv6"))?)
            }
            _ => continue,
        };
        if let Some(prefix) = IpPrefix::new(addr, dst_len) {
            out.push(prefix);
        }
    }
    Ok(out)
}
