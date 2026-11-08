//! 探测消息（design/mesh.md 第 7.2 节）：编解码与校验码。
//!
//! 首个字节是类型，与 WireGuard 的四种消息（1–4）都不同。隧道外的消息都是 64 字节、末尾 16 字节为
//! 校验码；应答与探测等长，不能用来放大流量。格式不对或认证不过的包由调用方丢弃，不作任何响应。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use nett_trust::keys::X25519PublicKey;
use ring::{hkdf, hmac};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::key::PrivateKey;

/// 组网地址上的隧道内探测端口，只在 `nett0` 上监听。
pub const TUNNEL_PROBE_PORT: u16 = 41821;

pub const TUNNEL_PROBE: u8 = 0x80;
pub const TUNNEL_REPLY: u8 = 0x81;
pub const DIRECT_PROBE: u8 = 0x82;
pub const DIRECT_REPLY: u8 = 0x83;
pub const SWITCH_PROPOSAL: u8 = 0x84;
pub const SWITCH_ACK: u8 = 0x85;
pub const PUNCH_PROPOSAL: u8 = 0x86;
pub const PUNCH_ACK: u8 = 0x87;
pub use nett_core::transport::{RELAY_PROBE, RELAY_REPLY};

/// WireGuard 的 cookie 应答：类型与长度（WireGuard 协议）。组网进程从 WireGuard 端口拿到它的副本，据此
/// 知道对端处于负载状态、WireGuard 会带着 cookie 重试（design/mesh.md 第 8.4 节）。
pub const WG_COOKIE_REPLY: u8 = 3;
pub const WG_COOKIE_LEN: usize = 64;

/// 隧道外消息的长度。
pub const OUTER_LEN: usize = 64;
const MAC_LEN: usize = 16;
const MAC_AT: usize = OUTER_LEN - MAC_LEN;
/// 发送时间与接收方时钟之差的上限，限制重放。
pub const MAX_CLOCK_SKEW_MS: u64 = 30_000;
/// 隧道内应答最多带的中继测量条数。
pub const MAX_RELAY_REPORTS: usize = 16;
const TUNNEL_PROBE_LEN: usize = 8;
const SWITCH_LEN: usize = 16;
const PUNCH_LEN: usize = 32;
const RELAY_REPORT_LEN: usize = 12;

const DIRECT_KEY_LABEL: &[u8] = b"nett direct probe v1";

/// 公钥（或其他标识）的 8 字节编号：SHA-256 的前 8 字节。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(pub [u8; 8]);

impl KeyId {
    pub fn of(bytes: &[u8]) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
        let mut id = [0u8; 8];
        id.copy_from_slice(&digest.as_ref()[..8]);
        Self(id)
    }
}

/// 校验码的密钥：直连探测由双方组网密钥派生，中继探测是分配时下发的令牌。
#[derive(Clone)]
pub struct ProbeKey(hmac::Key);

impl ProbeKey {
    pub fn from_token(token: &[u8; 32]) -> Self {
        Self(hmac::Key::new(hmac::HMAC_SHA256, token))
    }

    /// 由本机组网私钥与对端组网公钥派生直连探测的密钥。对端公钥是小阶点等使共享值全为 0 时返回 `None`。
    pub fn direct(own: &PrivateKey, peer: &X25519PublicKey) -> Option<Self> {
        let secret = StaticSecret::from(*own.as_bytes());
        let own_public = PublicKey::from(&secret);
        let shared = secret.diffie_hellman(&PublicKey::from(*peer.as_bytes()));
        if !shared.was_contributory() {
            return None;
        }
        let (lo, hi) = if own_public.as_bytes() <= peer.as_bytes() {
            (own_public.to_bytes(), *peer.as_bytes())
        } else {
            (*peer.as_bytes(), own_public.to_bytes())
        };
        let mut okm = Zeroizing::new([0u8; 32]);
        let info: [&[u8]; 3] = [DIRECT_KEY_LABEL, &lo, &hi];
        hkdf::Salt::new(hkdf::HKDF_SHA256, &[])
            .extract(shared.as_bytes())
            .expand(&info, HmacKeyLen)
            .and_then(|prk| prk.fill(&mut okm[..]))
            .ok()?;
        Some(Self(hmac::Key::new(hmac::HMAC_SHA256, &okm[..])))
    }

    fn mac(&self, data: &[u8]) -> [u8; MAC_LEN] {
        let tag = hmac::sign(&self.0, data);
        let mut out = [0u8; MAC_LEN];
        out.copy_from_slice(&tag.as_ref()[..MAC_LEN]);
        out
    }

    fn verify(&self, data: &[u8], mac: &[u8]) -> bool {
        // 截断后的校验码按常量时间比较：逐字节异或后合并，不在第一个不同处提前返回
        let expected = self.mac(data);
        mac.len() == MAC_LEN
            && expected
                .iter()
                .zip(mac)
                .fold(0u8, |acc, (x, y)| acc | (x ^ y))
                == 0
    }
}

struct HmacKeyLen;

impl hkdf::KeyType for HmacKeyLen {
    fn len(&self) -> usize {
        32
    }
}

/// 隧道外的探测（直连 `0x82`、中继 `0x90`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OuterProbe {
    pub kind: u8,
    /// 直连：发送方组网公钥的编号；中继：令牌编号。
    pub key_id: KeyId,
    pub seq: u32,
    pub sent_ms: u64,
}

/// 隧道外的应答（直连 `0x83`、中继 `0x91`），带应答方看到的来源地址。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OuterReply {
    pub kind: u8,
    pub key_id: KeyId,
    pub seq: u32,
    pub sent_ms: u64,
    pub observed: SocketAddr,
}

impl OuterProbe {
    pub fn encode(&self, key: &ProbeKey) -> [u8; OUTER_LEN] {
        let mut b = [0u8; OUTER_LEN];
        b[0] = self.kind;
        b[4..12].copy_from_slice(&self.key_id.0);
        b[12..16].copy_from_slice(&self.seq.to_be_bytes());
        b[16..24].copy_from_slice(&self.sent_ms.to_be_bytes());
        let mac = key.mac(&b[..MAC_AT]);
        b[MAC_AT..].copy_from_slice(&mac);
        b
    }

    /// 读出未认证的头部，供接收方按编号选择密钥；之后必须用 [`Self::verify`] 认证。
    pub fn peek(b: &[u8]) -> Option<Self> {
        let kind = *b.first()?;
        if b.len() != OUTER_LEN || !matches!(kind, DIRECT_PROBE | RELAY_PROBE) || b[1..4] != [0; 3]
        {
            return None;
        }
        Some(Self {
            kind,
            key_id: KeyId(b[4..12].try_into().ok()?),
            seq: u32::from_be_bytes(b[12..16].try_into().ok()?),
            sent_ms: u64::from_be_bytes(b[16..24].try_into().ok()?),
        })
    }

    /// 认证并检查发送时间。
    pub fn verify(b: &[u8], key: &ProbeKey, now_ms: u64) -> Option<Self> {
        let probe = Self::peek(b)?;
        let fresh = now_ms.abs_diff(probe.sent_ms) <= MAX_CLOCK_SKEW_MS;
        (b[24..MAC_AT] == [0; MAC_AT - 24] && fresh && key.verify(&b[..MAC_AT], &b[MAC_AT..]))
            .then_some(probe)
    }

    /// 应答：类型加 1，原样带回序号和发送时间。
    pub fn reply(&self, key_id: KeyId, observed: SocketAddr) -> OuterReply {
        OuterReply {
            kind: self.kind + 1,
            key_id,
            seq: self.seq,
            sent_ms: self.sent_ms,
            observed,
        }
    }
}

impl OuterReply {
    pub fn encode(&self, key: &ProbeKey) -> [u8; OUTER_LEN] {
        let mut b = [0u8; OUTER_LEN];
        b[0] = self.kind;
        b[4..12].copy_from_slice(&self.key_id.0);
        b[12..16].copy_from_slice(&self.seq.to_be_bytes());
        b[16..24].copy_from_slice(&self.sent_ms.to_be_bytes());
        let (family, addr) = match self.observed.ip() {
            IpAddr::V4(a) => (4u8, a.to_ipv6_mapped().octets()),
            IpAddr::V6(a) => (6u8, a.octets()),
        };
        b[24] = family;
        b[25..27].copy_from_slice(&self.observed.port().to_be_bytes());
        b[27..43].copy_from_slice(&addr);
        let mac = key.mac(&b[..MAC_AT]);
        b[MAC_AT..].copy_from_slice(&mac);
        b
    }

    pub fn peek(b: &[u8]) -> Option<KeyId> {
        let kind = *b.first()?;
        (b.len() == OUTER_LEN && matches!(kind, DIRECT_REPLY | RELAY_REPLY))
            .then(|| b[4..12].try_into().ok().map(KeyId))
            .flatten()
    }

    pub fn verify(b: &[u8], key: &ProbeKey) -> Option<Self> {
        let key_id = Self::peek(b)?;
        if b[1..4] != [0; 3]
            || b[43..MAC_AT] != [0; MAC_AT - 43]
            || !key.verify(&b[..MAC_AT], &b[MAC_AT..])
        {
            return None;
        }
        let octets: [u8; 16] = b[27..43].try_into().ok()?;
        let ip = match b[24] {
            4 => IpAddr::V4(Ipv6Addr::from(octets).to_ipv4_mapped()?),
            6 => IpAddr::V6(Ipv6Addr::from(octets)),
            _ => return None,
        };
        Some(Self {
            kind: b[0],
            key_id,
            seq: u32::from_be_bytes(b[12..16].try_into().ok()?),
            sent_ms: u64::from_be_bytes(b[16..24].try_into().ok()?),
            observed: SocketAddr::new(ip, u16::from_be_bytes([b[25], b[26]])),
        })
    }
}

/// 应答方到一个中继的最新测量，随隧道内应答带给对端（design/mesh.md 第 7.2 节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayReport {
    pub relay: KeyId,
    pub rtt_ms: u16,
    /// 丢包率，千分比。
    pub loss_permille: u16,
}

/// 隧道内探测：`类型 | 0 | 0 | 0 | 序号`。
pub fn encode_tunnel_probe(seq: u32) -> [u8; TUNNEL_PROBE_LEN] {
    let mut b = [0u8; TUNNEL_PROBE_LEN];
    b[0] = TUNNEL_PROBE;
    b[4..8].copy_from_slice(&seq.to_be_bytes());
    b
}

pub fn decode_tunnel_probe(b: &[u8]) -> Option<u32> {
    (b.len() == TUNNEL_PROBE_LEN && b[0] == TUNNEL_PROBE && b[1..4] == [0; 3])
        .then(|| u32::from_be_bytes([b[4], b[5], b[6], b[7]]))
}

/// 切换的目标（design/mesh.md 第 8.4 节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchTarget {
    /// 经这个中继（中继节点 ID 的编号）。
    Relay(KeyId),
    /// 这一对打通的直连（第 6.1 节）。
    Punched,
}

/// 切换提议与确认：`类型 | 目标种类 | 0 | 0 | 轮次 | 目标中继的编号`。目标种类 0 为中继，1 为打通的
/// 直连（中继编号为 0）。经隧道收发，来源已由 WireGuard 认证。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchMessage {
    pub kind: u8,
    pub round: u32,
    pub target: SwitchTarget,
}

impl SwitchMessage {
    pub fn encode(&self) -> [u8; SWITCH_LEN] {
        let mut b = [0u8; SWITCH_LEN];
        b[0] = self.kind;
        if let SwitchTarget::Relay(relay) = self.target {
            b[8..16].copy_from_slice(&relay.0);
        } else {
            b[1] = 1;
        }
        b[4..8].copy_from_slice(&self.round.to_be_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let b: &[u8; SWITCH_LEN] = b.try_into().ok()?;
        if !matches!(b[0], SWITCH_PROPOSAL | SWITCH_ACK) || b[2..4] != [0; 2] {
            return None;
        }
        let mut relay = [0u8; 8];
        relay.copy_from_slice(&b[8..16]);
        let target = match b[1] {
            0 => SwitchTarget::Relay(KeyId(relay)),
            1 if relay == [0; 8] => SwitchTarget::Punched,
            _ => return None,
        };
        Some(Self {
            kind: b[0],
            round: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            target,
        })
    }
}

/// 本机所在 NAT 的类型（design/mesh.md 第 6.1 节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NatType {
    Unknown,
    /// 映射与目的地址无关：两个 `public` 节点看到同一个映射地址。
    Cone,
    /// 每个目的地址一个映射。
    Symmetric,
}

/// 打洞提议与确认（design/mesh.md 第 6.1 节）：
/// `类型 | NAT 类型 | 地址标志 | 0 | 轮次 | IPv4 地址 | IPv4 端口 | IPv6 地址 | IPv6 端口`，共 32 字节。
/// 地址标志的第 0 位表示有 IPv4 映射地址，第 1 位表示有 IPv6 地址；没有的字段为 0。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchMessage {
    pub kind: u8,
    pub round: u32,
    pub nat: NatType,
    pub v4: Option<SocketAddrV4>,
    pub v6: Option<SocketAddrV6>,
}

impl PunchMessage {
    pub fn encode(&self) -> [u8; PUNCH_LEN] {
        let mut b = [0u8; PUNCH_LEN];
        b[0] = self.kind;
        b[1] = match self.nat {
            NatType::Unknown => 0,
            NatType::Cone => 1,
            NatType::Symmetric => 2,
        };
        b[4..8].copy_from_slice(&self.round.to_be_bytes());
        if let Some(v4) = self.v4 {
            b[2] |= 1;
            b[8..12].copy_from_slice(&v4.ip().octets());
            b[12..14].copy_from_slice(&v4.port().to_be_bytes());
        }
        if let Some(v6) = self.v6 {
            b[2] |= 2;
            b[14..30].copy_from_slice(&v6.ip().octets());
            b[30..32].copy_from_slice(&v6.port().to_be_bytes());
        }
        b
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let b: &[u8; PUNCH_LEN] = b.try_into().ok()?;
        if !matches!(b[0], PUNCH_PROPOSAL | PUNCH_ACK) || b[2] & !3 != 0 || b[3] != 0 {
            return None;
        }
        let nat = match b[1] {
            0 => NatType::Unknown,
            1 => NatType::Cone,
            2 => NatType::Symmetric,
            _ => return None,
        };
        let v4 = (b[2] & 1 != 0).then(|| {
            SocketAddrV4::new(
                Ipv4Addr::new(b[8], b[9], b[10], b[11]),
                u16::from_be_bytes([b[12], b[13]]),
            )
        });
        let v6 = (b[2] & 2 != 0).then(|| {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&b[14..30]);
            SocketAddrV6::new(Ipv6Addr::from(ip), u16::from_be_bytes([b[30], b[31]]), 0, 0)
        });
        Some(Self {
            kind: b[0],
            round: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            nat,
            v4,
            v6,
        })
    }
}

/// 隧道内应答：`类型 | 条数 | 0 | 0 | 序号 | 每条 12 字节的中继测量`。
pub fn encode_tunnel_reply(seq: u32, reports: &[RelayReport]) -> Vec<u8> {
    let reports = &reports[..reports.len().min(MAX_RELAY_REPORTS)];
    let mut b = Vec::with_capacity(TUNNEL_PROBE_LEN + reports.len() * RELAY_REPORT_LEN);
    b.push(TUNNEL_REPLY);
    b.push(u8::try_from(reports.len()).unwrap_or(0));
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(&seq.to_be_bytes());
    for r in reports {
        b.extend_from_slice(&r.relay.0);
        b.extend_from_slice(&r.rtt_ms.to_be_bytes());
        b.extend_from_slice(&r.loss_permille.to_be_bytes());
    }
    b
}

pub fn decode_tunnel_reply(b: &[u8]) -> Option<(u32, Vec<RelayReport>)> {
    if b.len() < TUNNEL_PROBE_LEN || b[0] != TUNNEL_REPLY || b[2..4] != [0; 2] {
        return None;
    }
    let count = usize::from(b[1]);
    if count > MAX_RELAY_REPORTS || b.len() != TUNNEL_PROBE_LEN + count * RELAY_REPORT_LEN {
        return None;
    }
    let seq = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
    let reports = b[TUNNEL_PROBE_LEN..]
        .as_chunks::<RELAY_REPORT_LEN>()
        .0
        .iter()
        .map(|c| RelayReport {
            relay: KeyId([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]),
            rtt_ms: u16::from_be_bytes([c[8], c[9]]),
            loss_permille: u16::from_be_bytes([c[10], c[11]]),
        })
        .collect();
    Some((seq, reports))
}

/// 未指定地址：`observed` 无从得知时使用。
pub const UNSPECIFIED: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair(n: u8) -> (PrivateKey, X25519PublicKey) {
        let secret = StaticSecret::from([n; 32]);
        let public = PublicKey::from(&secret);
        (
            PrivateKey::from_bytes([n; 32]),
            X25519PublicKey::from_bytes(public.to_bytes()),
        )
    }

    #[test]
    fn direct_keys_agree_and_differ_per_pair() {
        let (a_priv, a_pub) = keypair(1);
        let (b_priv, b_pub) = keypair(2);
        let (_, c_pub) = keypair(3);
        let ab = ProbeKey::direct(&a_priv, &b_pub).expect("key");
        let ba = ProbeKey::direct(&b_priv, &a_pub).expect("key");
        let ac = ProbeKey::direct(&a_priv, &c_pub).expect("key");
        let probe = OuterProbe {
            kind: DIRECT_PROBE,
            key_id: KeyId::of(a_pub.as_bytes()),
            seq: 7,
            sent_ms: 1_000,
        };
        let wire = probe.encode(&ab);
        assert_eq!(OuterProbe::verify(&wire, &ba, 1_000), Some(probe));
        assert_eq!(OuterProbe::verify(&wire, &ac, 1_000), None);
    }

    #[test]
    fn rejects_low_order_peer_keys() {
        let (a_priv, _) = keypair(1);
        assert!(ProbeKey::direct(&a_priv, &X25519PublicKey::from_bytes([0; 32])).is_none());
    }

    #[test]
    fn outer_probe_checks_freshness_and_tampering() {
        let key = ProbeKey::from_token(&[9; 32]);
        let probe = OuterProbe {
            kind: RELAY_PROBE,
            key_id: KeyId([1; 8]),
            seq: 1,
            sent_ms: 100_000,
        };
        let wire = probe.encode(&key);
        assert!(OuterProbe::verify(&wire, &key, 100_000 + MAX_CLOCK_SKEW_MS).is_some());
        assert!(OuterProbe::verify(&wire, &key, 100_000 + MAX_CLOCK_SKEW_MS + 1).is_none());
        for i in [0, 5, 13, 20, 30, 60] {
            let mut bad = wire;
            bad[i] ^= 1;
            assert!(
                OuterProbe::verify(&bad, &key, 100_000).is_none(),
                "byte {i}"
            );
        }
        assert!(OuterProbe::verify(&wire[..63], &key, 100_000).is_none());
    }

    #[test]
    fn reply_round_trip_carries_observed_address() {
        let key = ProbeKey::from_token(&[9; 32]);
        let probe = OuterProbe {
            kind: RELAY_PROBE,
            key_id: KeyId([1; 8]),
            seq: 3,
            sent_ms: 5,
        };
        for observed in ["198.51.100.7:40000", "[2001:db8::7]:41820"] {
            let reply = probe.reply(KeyId([1; 8]), observed.parse().expect("addr"));
            assert_eq!(reply.kind, RELAY_REPLY);
            let wire = reply.encode(&key);
            assert_eq!(wire.len(), OUTER_LEN);
            assert_eq!(OuterReply::verify(&wire, &key), Some(reply));
            let mut bad = wire;
            bad[30] ^= 1;
            assert!(OuterReply::verify(&bad, &key).is_none());
        }
    }

    #[test]
    fn tunnel_messages_round_trip() {
        assert_eq!(decode_tunnel_probe(&encode_tunnel_probe(42)), Some(42));
        let proposal = SwitchMessage {
            kind: SWITCH_PROPOSAL,
            round: 7,
            target: SwitchTarget::Relay(KeyId([9; 8])),
        };
        assert_eq!(SwitchMessage::decode(&proposal.encode()), Some(proposal));
        let punched = SwitchMessage {
            kind: SWITCH_ACK,
            round: 8,
            target: SwitchTarget::Punched,
        };
        assert_eq!(SwitchMessage::decode(&punched.encode()), Some(punched));
        let punch = PunchMessage {
            kind: PUNCH_PROPOSAL,
            round: 9,
            nat: NatType::Cone,
            v4: Some("198.51.100.201:41820".parse().expect("v4")),
            v6: Some("[2001:db8::1]:41820".parse().expect("v6")),
        };
        assert_eq!(PunchMessage::decode(&punch.encode()), Some(punch));
        let none = PunchMessage {
            v4: None,
            v6: None,
            nat: NatType::Symmetric,
            ..punch
        };
        assert_eq!(PunchMessage::decode(&none.encode()), Some(none));
        let mut bad = punch.encode();
        bad[1] = 9;
        assert_eq!(PunchMessage::decode(&bad), None);
        let mut bad = proposal.encode();
        bad[0] = TUNNEL_PROBE;
        assert_eq!(SwitchMessage::decode(&bad), None);
        assert_eq!(SwitchMessage::decode(&proposal.encode()[..15]), None);
        assert_eq!(
            decode_tunnel_probe(&[TUNNEL_PROBE, 0, 0, 1, 0, 0, 0, 1]),
            None
        );
        let reports = vec![RelayReport {
            relay: KeyId([3; 8]),
            rtt_ms: 25,
            loss_permille: 100,
        }];
        let wire = encode_tunnel_reply(9, &reports);
        assert_eq!(decode_tunnel_reply(&wire), Some((9, reports)));
        assert_eq!(decode_tunnel_reply(&wire[..wire.len() - 1]), None);
    }
}
