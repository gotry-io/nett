//! Kernel WireGuard's generic netlink interface (`include/uapi/linux/wireguard.h`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nett_trust::keys::X25519PublicKey;

use super::netlink::{
    Message, NLM_F_ACK, NLM_F_DUMP, NlError, Socket, attrs, parse_u16, parse_u32, parse_u64,
};
use nett_core::prefix::IpPrefix;

const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const WG_GENL_NAME: &str = "wireguard";
const WG_GENL_VERSION: u8 = 1;
const WG_CMD_GET_DEVICE: u8 = 0;
const WG_CMD_SET_DEVICE: u8 = 1;

const WGDEVICE_A_IFINDEX: u16 = 1;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_PUBLIC_KEY: u16 = 4;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_PEERS: u16 = 8;

const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_FLAGS: u16 = 3;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
const WGPEER_A_RX_BYTES: u16 = 7;
const WGPEER_A_TX_BYTES: u16 = 8;
const WGPEER_A_ALLOWEDIPS: u16 = 9;
const WGPEER_F_REMOVE_ME: u32 = 1;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 2;
const WGPEER_F_UPDATE_ONLY: u32 = 4;

const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Upper limit of a single message that sets peers; beyond it, split into several (by page size, as with
/// wireguard-tools).
const SET_MESSAGE_BUDGET: usize = 4096;

/// Current state of a peer on the interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PeerState {
    pub public_key: X25519PublicKey,
    pub endpoint: Option<SocketAddr>,
    pub keepalive: u16,
    pub allowed_ips: Vec<IpPrefix>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Time of the most recent completed handshake (wall clock); empty when no handshake has completed since
    /// the peer joined.
    pub last_handshake: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Device {
    pub public_key: Option<X25519PublicKey>,
    pub listen_port: u16,
    pub peers: Vec<PeerState>,
}

/// One change to a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PeerChange {
    /// Add or update: `AllowedIPs` is replaced as a whole; when `endpoint` is empty the kernel's current
    /// endpoint is kept.
    Upsert {
        public_key: X25519PublicKey,
        endpoint: Option<SocketAddr>,
        keepalive: u16,
        allowed_ips: Vec<IpPrefix>,
    },
    Remove(X25519PublicKey),
    /// Changes only the endpoint; the kernel does not create the peer if it does not exist.
    Endpoint {
        public_key: X25519PublicKey,
        endpoint: SocketAddr,
    },
}

fn genl_header(cmd: u8, version: u8) -> [u8; 4] {
    [cmd, version, 0, 0]
}

/// Queries the family ID of WireGuard's generic netlink family (assigned dynamically by the kernel after
/// the wireguard module is loaded).
pub(crate) fn resolve_family(sock: &mut Socket) -> Result<u16, NlError> {
    let mut m = Message::new(GENL_ID_CTRL, NLM_F_ACK);
    m.fixed(&genl_header(CTRL_CMD_GETFAMILY, 1));
    m.attr_str(CTRL_ATTR_FAMILY_NAME, WG_GENL_NAME);
    for reply in sock.request(m)? {
        for attr in attrs(reply.get(4..).unwrap_or_default()) {
            let (ty, payload) = attr?;
            if ty == CTRL_ATTR_FAMILY_ID {
                return parse_u16(payload);
            }
        }
    }
    Err(NlError::Malformed("no family id in reply"))
}

/// Sets the private key and listen port. When the private key is the same as the current one the kernel
/// changes nothing and sessions are unaffected. When the port is empty it is not changed: a newly created
/// interface gets one from the kernel when enabled; `Some(0)` makes the kernel reassign one.
pub(crate) fn set_device(
    sock: &mut Socket,
    family: u16,
    ifindex: u32,
    private_key: &[u8; 32],
    listen_port: Option<u16>,
) -> Result<(), NlError> {
    let mut m = Message::new(family, NLM_F_ACK);
    m.fixed(&genl_header(WG_CMD_SET_DEVICE, WG_GENL_VERSION));
    m.attr_u32(WGDEVICE_A_IFINDEX, ifindex);
    m.attr(WGDEVICE_A_PRIVATE_KEY, private_key);
    if let Some(port) = listen_port {
        m.attr_u16(WGDEVICE_A_LISTEN_PORT, port);
    }
    sock.request(m).map(drop)
}

pub(crate) fn get_device(sock: &mut Socket, family: u16, ifindex: u32) -> Result<Device, NlError> {
    let mut m = Message::new(family, NLM_F_DUMP);
    m.fixed(&genl_header(WG_CMD_GET_DEVICE, WG_GENL_VERSION));
    m.attr_u32(WGDEVICE_A_IFINDEX, ifindex);
    let mut device = Device {
        public_key: None,
        listen_port: 0,
        peers: Vec::new(),
    };
    for reply in sock.request(m)? {
        for attr in attrs(reply.get(4..).unwrap_or_default()) {
            let (ty, payload) = attr?;
            match ty {
                WGDEVICE_A_PUBLIC_KEY => device.public_key = Some(parse_key(payload)?),
                WGDEVICE_A_LISTEN_PORT => device.listen_port = parse_u16(payload)?,
                WGDEVICE_A_PEERS => {
                    for peer in attrs(payload) {
                        let (_, peer) = peer?;
                        let peer = parse_peer(peer)?;
                        // One peer's AllowedIPs may span several messages, and subsequent messages continue with the same
                        // public key
                        match device.peers.last_mut() {
                            Some(last) if last.public_key == peer.public_key => {
                                last.allowed_ips.extend(peer.allowed_ips);
                            }
                            _ => device.peers.push(peer),
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(device)
}

/// Applies peer changes. Only incremental changes are made, never "replace all peers": replacing would
/// clear existing sessions and interrupt connections in progress.
pub(crate) fn apply_peers(
    sock: &mut Socket,
    family: u16,
    ifindex: u32,
    changes: &[PeerChange],
) -> Result<(), NlError> {
    let mut pending = changes;
    while !pending.is_empty() {
        let mut m = Message::new(family, NLM_F_ACK);
        m.fixed(&genl_header(WG_CMD_SET_DEVICE, WG_GENL_VERSION));
        m.attr_u32(WGDEVICE_A_IFINDEX, ifindex);
        let peers = m.begin_nested(WGDEVICE_A_PEERS);
        let mut taken = 0;
        for change in pending {
            let before = m.len();
            encode_peer(&mut m, taken, change);
            if m.len() > SET_MESSAGE_BUDGET && taken > 0 {
                m.truncate(before);
                break;
            }
            taken += 1;
        }
        m.end_nested(peers);
        sock.request(m)?;
        pending = &pending[taken..];
    }
    Ok(())
}

fn encode_peer(m: &mut Message, index: usize, change: &PeerChange) {
    let entry = m.begin_nested(u16::try_from(index).unwrap_or(u16::MAX));
    match change {
        PeerChange::Remove(public_key) => {
            m.attr(WGPEER_A_PUBLIC_KEY, public_key.as_bytes());
            m.attr_u32(WGPEER_A_FLAGS, WGPEER_F_REMOVE_ME);
        }
        PeerChange::Endpoint {
            public_key,
            endpoint,
        } => {
            m.attr(WGPEER_A_PUBLIC_KEY, public_key.as_bytes());
            m.attr_u32(WGPEER_A_FLAGS, WGPEER_F_UPDATE_ONLY);
            m.attr(WGPEER_A_ENDPOINT, &encode_sockaddr(endpoint));
        }
        PeerChange::Upsert {
            public_key,
            endpoint,
            keepalive,
            allowed_ips,
        } => {
            m.attr(WGPEER_A_PUBLIC_KEY, public_key.as_bytes());
            m.attr_u32(WGPEER_A_FLAGS, WGPEER_F_REPLACE_ALLOWEDIPS);
            if let Some(endpoint) = endpoint {
                m.attr(WGPEER_A_ENDPOINT, &encode_sockaddr(endpoint));
            }
            m.attr_u16(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, *keepalive);
            let ips = m.begin_nested(WGPEER_A_ALLOWEDIPS);
            for (i, prefix) in allowed_ips.iter().enumerate() {
                let ip = m.begin_nested(u16::try_from(i).unwrap_or(u16::MAX));
                match prefix.addr() {
                    IpAddr::V4(a) => {
                        m.attr_u16(WGALLOWEDIP_A_FAMILY, AF_INET);
                        m.attr(WGALLOWEDIP_A_IPADDR, &a.octets());
                    }
                    IpAddr::V6(a) => {
                        m.attr_u16(WGALLOWEDIP_A_FAMILY, AF_INET6);
                        m.attr(WGALLOWEDIP_A_IPADDR, &a.octets());
                    }
                }
                m.attr_u8(WGALLOWEDIP_A_CIDR_MASK, prefix.prefix_len());
                m.end_nested(ip);
            }
            m.end_nested(ips);
        }
    }
    m.end_nested(entry);
}

fn parse_key(b: &[u8]) -> Result<X25519PublicKey, NlError> {
    <[u8; 32]>::try_from(b)
        .map(X25519PublicKey::from_bytes)
        .map_err(|_| NlError::Malformed("key length"))
}

fn parse_peer(buf: &[u8]) -> Result<PeerState, NlError> {
    let mut public_key = None;
    let mut endpoint = None;
    let mut keepalive = 0;
    let mut allowed_ips = Vec::new();
    let (mut rx_bytes, mut tx_bytes) = (0, 0);
    let mut last_handshake = None;
    for attr in attrs(buf) {
        let (ty, payload) = attr?;
        match ty {
            WGPEER_A_PUBLIC_KEY => public_key = Some(parse_key(payload)?),
            WGPEER_A_ENDPOINT => endpoint = decode_sockaddr(payload)?,
            WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL => keepalive = parse_u16(payload)?,
            WGPEER_A_RX_BYTES => rx_bytes = parse_u64(payload)?,
            WGPEER_A_TX_BYTES => tx_bytes = parse_u64(payload)?,
            WGPEER_A_LAST_HANDSHAKE_TIME => last_handshake = parse_timespec(payload)?,
            WGPEER_A_ALLOWEDIPS => {
                for ip in attrs(payload) {
                    let (_, ip) = ip?;
                    allowed_ips.push(parse_allowed_ip(ip)?);
                }
            }
            _ => {}
        }
    }
    Ok(PeerState {
        public_key: public_key.ok_or(NlError::Malformed("peer without public key"))?,
        endpoint,
        keepalive,
        allowed_ips,
        rx_bytes,
        tx_bytes,
        last_handshake,
    })
}

/// `struct __kernel_timespec` (two 64-bit integers: seconds, nanoseconds); all zeros means no handshake
/// yet.
fn parse_timespec(b: &[u8]) -> Result<Option<SystemTime>, NlError> {
    let (secs, nanos) = b
        .split_at_checked(8)
        .ok_or(NlError::Malformed("timespec attribute"))?;
    let (secs, nanos) = (parse_u64(secs)?, parse_u64(nanos)?);
    if secs == 0 && nanos == 0 {
        return Ok(None);
    }
    let nanos = u32::try_from(nanos).map_err(|_| NlError::Malformed("timespec nanoseconds"))?;
    UNIX_EPOCH
        .checked_add(Duration::new(secs, nanos))
        .map(Some)
        .ok_or(NlError::Malformed("timespec out of range"))
}

fn parse_allowed_ip(buf: &[u8]) -> Result<IpPrefix, NlError> {
    let mut family = 0;
    let mut addr = None;
    let mut cidr = None;
    for attr in attrs(buf) {
        let (ty, payload) = attr?;
        match ty {
            WGALLOWEDIP_A_FAMILY => family = parse_u16(payload)?,
            WGALLOWEDIP_A_IPADDR => addr = Some(payload),
            WGALLOWEDIP_A_CIDR_MASK => cidr = payload.first().copied(),
            _ => {}
        }
    }
    let addr = match (family, addr) {
        (AF_INET, Some(b)) => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(b).map_err(|_| NlError::Malformed("allowed ip"))?,
        )),
        (AF_INET6, Some(b)) => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(b).map_err(|_| NlError::Malformed("allowed ip"))?,
        )),
        _ => return Err(NlError::Malformed("allowed ip family")),
    };
    let cidr = cidr.ok_or(NlError::Malformed("allowed ip without mask"))?;
    IpPrefix::new(addr, cidr).ok_or(NlError::Malformed("allowed ip prefix"))
}

/// `sockaddr_in` / `sockaddr_in6`: the family is in host byte order, and the port and IPv4 address are in
/// network byte order.
fn encode_sockaddr(addr: &SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(a) => {
            let mut b = vec![0u8; 16];
            b[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
            b[2..4].copy_from_slice(&a.port().to_be_bytes());
            b[4..8].copy_from_slice(&a.ip().octets());
            b
        }
        SocketAddr::V6(a) => {
            let mut b = vec![0u8; 28];
            b[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            b[2..4].copy_from_slice(&a.port().to_be_bytes());
            b[4..8].copy_from_slice(&a.flowinfo().to_be_bytes());
            b[8..24].copy_from_slice(&a.ip().octets());
            b[24..28].copy_from_slice(&a.scope_id().to_ne_bytes());
            b
        }
    }
}

fn decode_sockaddr(b: &[u8]) -> Result<Option<SocketAddr>, NlError> {
    let family = b
        .get(0..2)
        .map(parse_u16)
        .transpose()?
        .ok_or(NlError::Malformed("endpoint"))?;
    let port = |b: &[u8]| u16::from_be_bytes([b[2], b[3]]);
    match (family, b.len()) {
        (0, _) => Ok(None),
        (AF_INET, 16..) => {
            let ip = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
            Ok(Some(SocketAddr::V4(SocketAddrV4::new(ip, port(b)))))
        }
        (AF_INET6, 28..) => {
            let ip = Ipv6Addr::from(
                <[u8; 16]>::try_from(&b[8..24]).map_err(|_| NlError::Malformed("endpoint"))?,
            );
            let flowinfo = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
            let scope = parse_u32(&b[24..28])?;
            Ok(Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port(b),
                flowinfo,
                scope,
            ))))
        }
        _ => Err(NlError::Malformed("endpoint family")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_time_is_empty_until_the_first_handshake() {
        assert_eq!(parse_timespec(&[0u8; 16]).expect("parse"), None);
        let mut b = Vec::new();
        b.extend_from_slice(&1_794_000_000u64.to_ne_bytes());
        b.extend_from_slice(&5_000_000u64.to_ne_bytes());
        assert_eq!(
            parse_timespec(&b).expect("parse"),
            Some(UNIX_EPOCH + Duration::new(1_794_000_000, 5_000_000))
        );
        assert!(parse_timespec(&b[..8]).is_err());
    }

    #[test]
    fn sockaddr_round_trip() {
        for s in ["192.0.2.1:41820", "[2001:db8::1]:41820"] {
            let addr: SocketAddr = s.parse().expect(s);
            assert_eq!(
                decode_sockaddr(&encode_sockaddr(&addr)).expect("decode"),
                Some(addr)
            );
        }
        assert_eq!(decode_sockaddr(&[0u8; 16]).expect("decode"), None);
    }
}
