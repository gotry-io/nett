//! Probe messages (design/mesh.md section 7.2): encoding, decoding and checksums.
//!
//! The first byte is the type, different from all four WireGuard messages (1-4). Messages outside the
//! tunnel are all 64 bytes, with the last 16 bytes being the checksum; a reply is the same length as the
//! probe and cannot be used to amplify traffic. Packets with a bad format or failed authentication are
//! dropped by the caller with no response.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use nett_trust::keys::X25519PublicKey;
use ring::{hkdf, hmac};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::key::PrivateKey;

/// The in-tunnel probe port on the mesh address, listening only on `nett0`.
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

/// WireGuard's cookie reply: type and length (WireGuard protocol). The mesh process gets a copy of it from
/// the WireGuard port, and from it learns that the peer is under load and WireGuard will retry with the
/// cookie (design/mesh.md section 8.4).
pub const WG_COOKIE_REPLY: u8 = 3;
pub const WG_COOKIE_LEN: usize = 64;

/// Length of messages outside the tunnel.
pub const OUTER_LEN: usize = 64;
const MAC_LEN: usize = 16;
const MAC_AT: usize = OUTER_LEN - MAC_LEN;
/// Upper limit of the difference between the send time and the receiver's clock, limiting replay.
pub const MAX_CLOCK_SKEW_MS: u64 = 30_000;
/// Maximum number of relay measurements an in-tunnel reply carries.
pub const MAX_RELAY_REPORTS: usize = 16;
const TUNNEL_PROBE_LEN: usize = 8;
const SWITCH_LEN: usize = 16;
const PUNCH_LEN: usize = 32;
const RELAY_REPORT_LEN: usize = 12;

const DIRECT_KEY_LABEL: &[u8] = b"nett direct probe v1";
const SWITCH_KEY_LABEL: &[u8] = b"nett path switch v1";
/// A switch message relayed through the Hub: the message, the send time and the checksum.
pub const HUB_SWITCH_LEN: usize = SWITCH_LEN + 8 + MAC_LEN;

/// 8-byte identifier of a public key (or other identity): the first 8 bytes of SHA-256.
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

/// Key of the checksum: for direct probes it is derived from both sides' mesh keys; for relay probes it is
/// the token issued at allocation.
#[derive(Clone)]
pub struct ProbeKey(hmac::Key);

impl ProbeKey {
    pub fn from_token(token: &[u8; 32]) -> Self {
        Self(hmac::Key::new(hmac::HMAC_SHA256, token))
    }

    /// Derives the direct probe key from this machine's mesh private key and the peer's mesh public key.
    /// Returns `None` when the peer's public key is a small-order point or otherwise makes the shared
    /// value all zeros.
    pub fn direct(own: &PrivateKey, peer: &X25519PublicKey) -> Option<Self> {
        Self::derive(own, peer, DIRECT_KEY_LABEL)
    }

    /// The key of switch messages relayed through the Hub (design/mesh.md section 8.4): derived like the
    /// direct probe key, for another purpose, so that only the two members can compute it.
    pub fn path_switch(own: &PrivateKey, peer: &X25519PublicKey) -> Option<Self> {
        Self::derive(own, peer, SWITCH_KEY_LABEL)
    }

    fn derive(own: &PrivateKey, peer: &X25519PublicKey, label: &[u8]) -> Option<Self> {
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
        let info: [&[u8]; 3] = [label, &lo, &hi];
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
        // The truncated checksum is compared in constant time: XOR byte by byte and combine, without returning
        // early at the first difference
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

/// Probes outside the tunnel (direct `0x82`, relay `0x90`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OuterProbe {
    pub kind: u8,
    /// Direct: the identifier of the sender's mesh public key; relay: the token identifier.
    pub key_id: KeyId,
    pub seq: u32,
    pub sent_ms: u64,
}

/// Replies outside the tunnel (direct `0x83`, relay `0x91`), carrying the source address as seen by the
/// replier.
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

    /// Reads the unauthenticated header, so the receiver can choose the key by identifier; it must then be
    /// authenticated with [`Self::verify`].
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

    /// Authenticates and checks the send time.
    pub fn verify(b: &[u8], key: &ProbeKey, now_ms: u64) -> Option<Self> {
        let probe = Self::peek(b)?;
        let fresh = now_ms.abs_diff(probe.sent_ms) <= MAX_CLOCK_SKEW_MS;
        (b[24..MAC_AT] == [0; MAC_AT - 24] && fresh && key.verify(&b[..MAC_AT], &b[MAC_AT..]))
            .then_some(probe)
    }

    /// Reply: the type plus 1, with the sequence number and send time carried back unchanged.
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

/// The replier's latest measurement to a relay, carried to the peer with the in-tunnel reply (design/mesh.md
/// section 7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayReport {
    pub relay: KeyId,
    pub rtt_ms: u16,
    /// Loss rate, in per mille.
    pub loss_permille: u16,
}

/// In-tunnel probe: `type | 0 | 0 | 0 | sequence number`.
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

/// Target of a switch (design/mesh.md section 8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchTarget {
    /// Via this relay (the identifier of the relay node ID).
    Relay(KeyId),
    /// The direct path punched for this pair (section 6.1).
    Punched,
}

/// Switch proposal and confirmation: `type | target kind | 0 | 0 | round | identifier of the target relay`.
/// Target kind 0 is a relay, 1 is a punched direct path (relay identifier is 0). Sent and received
/// through the tunnel; the source has been authenticated by WireGuard.
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

impl SwitchMessage {
    /// The message relayed through the Hub: `message | send time (Unix ms) | checksum`. The Hub cannot
    /// forge it; the send time limits replay.
    pub fn seal(&self, sent_ms: u64, key: &ProbeKey) -> [u8; HUB_SWITCH_LEN] {
        let mut b = [0u8; HUB_SWITCH_LEN];
        b[..SWITCH_LEN].copy_from_slice(&self.encode());
        b[SWITCH_LEN..SWITCH_LEN + 8].copy_from_slice(&sent_ms.to_be_bytes());
        let mac = key.mac(&b[..SWITCH_LEN + 8]);
        b[SWITCH_LEN + 8..].copy_from_slice(&mac);
        b
    }

    /// Opens a message relayed through the Hub: `None` when it is malformed, does not authenticate, or
    /// was sent more than [`MAX_CLOCK_SKEW_MS`] from this machine's clock.
    pub fn open(b: &[u8], key: &ProbeKey, now_ms: u64) -> Option<Self> {
        if b.len() != HUB_SWITCH_LEN || !key.verify(&b[..SWITCH_LEN + 8], &b[SWITCH_LEN + 8..]) {
            return None;
        }
        let mut sent = [0u8; 8];
        sent.copy_from_slice(&b[SWITCH_LEN..SWITCH_LEN + 8]);
        if now_ms.abs_diff(u64::from_be_bytes(sent)) > MAX_CLOCK_SKEW_MS {
            return None;
        }
        Self::decode(&b[..SWITCH_LEN])
    }
}

/// The type of NAT this machine is behind (design/mesh.md section 6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NatType {
    Unknown,
    /// The mapping is independent of the destination address: two `public` nodes see the same mapped address.
    Cone,
    /// One mapping per destination address.
    Symmetric,
}

/// Hole punching proposal and confirmation (design/mesh.md section 6.1):
/// `type | NAT type | address flags | 0 | round | IPv4 address | IPv4 port | IPv6 address | IPv6 port`, 32
/// bytes in total.
/// Bit 0 of the address flags means there is an IPv4 mapped address, and bit 1 means there is an IPv6
/// address; fields that are absent are 0.
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

/// In-tunnel reply: `type | count | 0 | 0 | sequence number | relay measurements of 12 bytes each`.
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

/// Unspecified address: used when `observed` cannot be known.
pub const UNSPECIFIED: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switch_messages_through_the_hub_authenticate_and_expire() {
        let own = PrivateKey::from_bytes([3; 32]);
        let peer_secret = PrivateKey::from_bytes([4; 32]);
        let peer = peer_secret.public_key();
        let key = ProbeKey::path_switch(&own, &peer).expect("key");
        let theirs = ProbeKey::path_switch(&peer_secret, &own.public_key()).expect("key");
        let message = SwitchMessage {
            kind: SWITCH_PROPOSAL,
            round: 7,
            target: SwitchTarget::Relay(KeyId([5; 8])),
        };
        let sealed = message.seal(1_000_000, &key);
        assert_eq!(
            SwitchMessage::open(&sealed, &theirs, 1_000_000),
            Some(message)
        );
        assert_eq!(
            SwitchMessage::open(&sealed, &theirs, 1_000_000 + MAX_CLOCK_SKEW_MS + 1),
            None,
            "too old"
        );
        let mut forged = sealed;
        forged[5] ^= 1;
        assert_eq!(SwitchMessage::open(&forged, &theirs, 1_000_000), None);
        // The direct probe key is a different key
        let direct = ProbeKey::direct(&peer_secret, &own.public_key()).expect("key");
        assert_eq!(SwitchMessage::open(&sealed, &direct, 1_000_000), None);
    }

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
