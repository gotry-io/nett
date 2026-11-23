//! The wire format of the obfuscated UDP transport, version 1 (design/obfuscation.md section 3).
//!
//! Every datagram starts with a random salt. A WireGuard data message longer than a keepalive has its
//! first 16 bytes masked with a keyed BLAKE2s of the salt and the rest left as it is, already
//! ciphertext; everything else (handshakes, cookie replies, keepalives, relay probes) is sealed with
//! ChaCha20-Poly1305 together with the version, a time and random padding. What does not unwrap is
//! dropped: the caller answers nothing.

use std::collections::{HashSet, VecDeque};

use blake2::Blake2sMac;
use blake2::digest::consts::U16;
use blake2::digest::{KeyInit as _, Mac as _};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use ring::rand::SecureRandom;
use zeroize::Zeroizing;

/// The format version, inside the sealed form; the keys' derivation carries it too (section 4).
pub const VERSION: u8 = 1;
/// The random salt in front of every datagram; the nonce of the sealed form.
pub const SALT_LEN: usize = 12;
/// The part of a WireGuard data message that is masked: type, reserved bytes, receiver index and
/// counter (WireGuard whitepaper section 5.4.6).
const MASKED: usize = 16;
const DATA_TYPE: u8 = 4;
/// A WireGuard data message with no payload, a keepalive: the 16-byte header and the tag.
const KEEPALIVE_LEN: usize = 32;
/// Version, time in milliseconds and the message's length, in front of the message in the sealed form.
const SEALED_HEADER: usize = 1 + 8 + 2;
const TAG_LEN: usize = 16;
/// The largest padding a site may choose (section 4: a minimum up to 64 and a maximum up to 256 above).
pub const MAX_PADDING: u16 = 320;
/// The largest message the transport carries; outer WireGuard packets are about 1360 bytes.
pub const MAX_MESSAGE: usize = 2048;
/// A sealed message whose time differs from the receiver's clock by more than this is dropped.
const MAX_SKEW_MS: u64 = 30_000;
/// How long a sealed message's salt is remembered, so a replay within the time window is dropped.
const SALT_MEMORY_MS: u64 = 60_000;
/// Salts remembered at once; when this many are unexpired, further sealed messages are dropped.
pub const MAX_SALTS: usize = 16_384;

/// A relay's obfuscation key (design/obfuscation.md section 4), derived by the site and the Hub.
#[derive(Clone)]
pub struct ObfsKey(Zeroizing<[u8; 32]>);

impl ObfsKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl std::fmt::Debug for ObfsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ObfsKey(..)")
    }
}

/// The site's padding range for sealed messages, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Padding {
    min: u16,
    max: u16,
}

impl Padding {
    pub fn new(min: u16, max: u16) -> Result<Self, ObfsError> {
        if min > max || max > MAX_PADDING {
            return Err(ObfsError::Padding { min, max });
        }
        Ok(Self { min, max })
    }

    pub fn min(&self) -> u16 {
        self.min
    }

    pub fn max(&self) -> u16 {
        self.max
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ObfsError {
    #[error("padding range {min}-{max} is not within 0-{MAX_PADDING} with the minimum first")]
    Padding { min: u16, max: u16 },
    #[error("a message of {0} bytes is larger than the transport carries ({MAX_MESSAGE})")]
    TooLong(usize),
    #[error("no random bytes from the system")]
    Random,
    #[error("datagram too short")]
    TooShort,
    #[error("datagram does not open with the relay's key")]
    Open,
    #[error("sealed message of format version {0}")]
    Version(u8),
    #[error("sealed message too far from this machine's time")]
    Stale,
    #[error("sealed message seen before")]
    Replay,
    #[error("too many recent sealed messages to remember another")]
    Full,
    #[error("sealed message with a wrong length")]
    Length,
}

/// The keys of one relay's obfuscated transport, with the site's padding range.
pub struct Obfuscator {
    data: Zeroizing<[u8; 32]>,
    control: LessSafeKey,
    padding: Padding,
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

impl Obfuscator {
    pub fn new(key: &ObfsKey, padding: Padding) -> Self {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(key.0.as_slice());
        let mut data = Zeroizing::new([0u8; 32]);
        prk.expand(&[b"data"], Len(32))
            .and_then(|okm| okm.fill(data.as_mut_slice()))
            .expect("HKDF-SHA256 gives 32 bytes");
        let control = prk
            .expand(&[b"control"], &CHACHA20_POLY1305)
            .map(UnboundKey::from)
            .map(LessSafeKey::new)
            .expect("HKDF-SHA256 gives a ChaCha20-Poly1305 key");
        Self {
            data,
            control,
            padding,
        }
    }

    fn mask(&self, salt: &[u8]) -> [u8; MASKED] {
        let mut mac = Blake2sMac::<U16>::new_from_slice(self.data.as_slice())
            .expect("BLAKE2s takes a 32-byte key");
        mac.update(salt);
        mac.finalize().into_bytes().into()
    }

    /// Wraps `message` into `out` (cleared first), with `now_ms` as the time of a sealed form.
    pub fn wrap(
        &self,
        rng: &dyn SecureRandom,
        now_ms: u64,
        message: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), ObfsError> {
        if message.len() > MAX_MESSAGE {
            return Err(ObfsError::TooLong(message.len()));
        }
        let mut salt = [0u8; SALT_LEN];
        rng.fill(&mut salt).map_err(|_| ObfsError::Random)?;
        out.clear();
        out.extend_from_slice(&salt);
        if is_data(message) {
            let mask = self.mask(&salt);
            out.extend(message[..MASKED].iter().zip(mask).map(|(b, m)| b ^ m));
            out.extend_from_slice(&message[MASKED..]);
            return Ok(());
        }
        let padding = self.padding_len(rng)?;
        let len = u16::try_from(message.len()).map_err(|_| ObfsError::TooLong(message.len()))?;
        out.push(VERSION);
        out.extend_from_slice(&now_ms.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(message);
        // The padding is sealed with the message, so its bytes need not be random
        out.resize(out.len() + padding, 0);
        let mut sealed = out.split_off(SALT_LEN);
        self.control
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(salt),
                Aad::empty(),
                &mut sealed,
            )
            .map_err(|_| ObfsError::TooLong(message.len()))?;
        out.extend_from_slice(&sealed);
        Ok(())
    }

    fn padding_len(&self, rng: &dyn SecureRandom) -> Result<usize, ObfsError> {
        let span = u32::from(self.padding.max - self.padding.min) + 1;
        let mut r = [0u8; 4];
        rng.fill(&mut r).map_err(|_| ObfsError::Random)?;
        // The span is at most 321, so the bias of the modulo is below one in ten million
        Ok(usize::from(self.padding.min) + (u32::from_be_bytes(r) % span) as usize)
    }

    /// Unwraps `datagram` into `out` (cleared first). A sealed message is checked against `now_ms`
    /// and its salt against `salts`.
    pub fn unwrap(
        &self,
        now_ms: u64,
        salts: &mut Salts,
        datagram: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), ObfsError> {
        if datagram.len() < SALT_LEN + MASKED {
            return Err(ObfsError::TooShort);
        }
        let (salt, body) = datagram.split_at(SALT_LEN);
        let mask = self.mask(salt);
        out.clear();
        out.extend(body[..MASKED].iter().zip(mask).map(|(b, m)| b ^ m));
        if out[0] == DATA_TYPE && out[1..4] == [0, 0, 0] && body.len() > KEEPALIVE_LEN {
            out.extend_from_slice(&body[MASKED..]);
            return Ok(());
        }
        if body.len() < SEALED_HEADER + TAG_LEN {
            return Err(ObfsError::TooShort);
        }
        out.clear();
        out.extend_from_slice(body);
        let nonce = Nonce::try_assume_unique_for_key(salt).map_err(|_| ObfsError::TooShort)?;
        let plain_len = self
            .control
            .open_in_place(nonce, Aad::empty(), out)
            .map_err(|_| ObfsError::Open)?
            .len();
        if plain_len < SEALED_HEADER {
            return Err(ObfsError::Length);
        }
        if out[0] != VERSION {
            return Err(ObfsError::Version(out[0]));
        }
        let mut time = [0u8; 8];
        time.copy_from_slice(&out[1..9]);
        let time = u64::from_be_bytes(time);
        if time.abs_diff(now_ms) > MAX_SKEW_MS {
            return Err(ObfsError::Stale);
        }
        let len = usize::from(u16::from_be_bytes([out[9], out[10]]));
        if SEALED_HEADER + len > plain_len {
            return Err(ObfsError::Length);
        }
        let mut s = [0u8; SALT_LEN];
        s.copy_from_slice(salt);
        salts.remember(s, now_ms)?;
        out.truncate(SEALED_HEADER + len);
        out.drain(..SEALED_HEADER);
        Ok(())
    }
}

/// A WireGuard data message that carries a payload: masked, not sealed.
fn is_data(message: &[u8]) -> bool {
    message.len() > KEEPALIVE_LEN && message[0] == DATA_TYPE && message[1..4] == [0, 0, 0]
}

/// The salts of the sealed messages received in the last minute, so a replay is dropped.
#[derive(Default)]
pub struct Salts {
    seen: HashSet<[u8; SALT_LEN]>,
    order: VecDeque<([u8; SALT_LEN], u64)>,
}

impl Salts {
    fn remember(&mut self, salt: [u8; SALT_LEN], now_ms: u64) -> Result<(), ObfsError> {
        while let Some((old, at)) = self.order.front().copied() {
            if now_ms.saturating_sub(at) < SALT_MEMORY_MS {
                break;
            }
            self.order.pop_front();
            self.seen.remove(&old);
        }
        if self.seen.contains(&salt) {
            return Err(ObfsError::Replay);
        }
        if self.order.len() >= MAX_SALTS {
            return Err(ObfsError::Full);
        }
        self.seen.insert(salt);
        self.order.push_back((salt, now_ms));
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;

    const NOW: u64 = 1_795_400_000_000;

    fn obfuscator(key: u8) -> Obfuscator {
        Obfuscator::new(
            &ObfsKey::from_bytes([key; 32]),
            Padding::new(16, 200).expect("padding"),
        )
    }

    fn data(len: usize) -> Vec<u8> {
        let mut m = vec![4, 0, 0, 0];
        m.extend((4..len).map(|i| (i * 7) as u8));
        m
    }

    fn handshake(kind: u8, len: usize) -> Vec<u8> {
        let mut m = vec![kind, 0, 0, 0];
        m.resize(len, 0x5a);
        m
    }

    fn round_trip(o: &Obfuscator, message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let mut wire = Vec::new();
        o.wrap(&rng, NOW, message, &mut wire).expect("wrap");
        let mut back = Vec::new();
        o.unwrap(NOW, &mut Salts::default(), &wire, &mut back)
            .expect("unwrap");
        (wire, back)
    }

    /// A data message keeps its length plus the salt, and only its header changes on the wire.
    #[test]
    fn a_data_message_is_masked_and_comes_back() {
        let o = obfuscator(1);
        for len in [48, 96, 1360] {
            let message = data(len);
            let (wire, back) = round_trip(&o, &message);
            assert_eq!(back, message);
            assert_eq!(wire.len(), len + SALT_LEN);
            assert_eq!(wire[SALT_LEN + MASKED..], message[MASKED..]);
        }
    }

    /// Handshakes, cookie replies, keepalives and probes are sealed with padding in the site's range.
    #[test]
    fn other_messages_are_sealed_with_padding_and_come_back() {
        let o = obfuscator(2);
        for message in [
            handshake(1, 148),
            handshake(2, 92),
            handshake(3, 64),
            data(KEEPALIVE_LEN),
            handshake(0x90, 40),
        ] {
            let (wire, back) = round_trip(&o, &message);
            assert_eq!(back, message);
            let overhead = wire.len() - message.len() - SALT_LEN - SEALED_HEADER - TAG_LEN;
            assert!((16..=200).contains(&overhead), "padding {overhead}");
        }
    }

    /// Over many datagrams no byte position keeps a value, and handshakes have no fixed length.
    #[test]
    fn nothing_on_the_wire_keeps_a_value_or_a_length() {
        let o = obfuscator(3);
        let rng = SystemRandom::new();
        let mut wire = Vec::new();
        let mut firsts: Vec<HashSet<u8>> = vec![HashSet::new(); 8];
        let mut lengths = HashSet::new();
        for i in 0..2000 {
            let message = if i % 2 == 0 {
                handshake(1, 148)
            } else {
                data(96)
            };
            o.wrap(&rng, NOW, &message, &mut wire).expect("wrap");
            for (seen, b) in firsts.iter_mut().zip(&wire) {
                seen.insert(*b);
            }
            if i % 2 == 0 {
                lengths.insert(wire.len());
            }
        }
        for (position, seen) in firsts.iter().enumerate() {
            assert!(
                seen.len() > 200,
                "byte {position} took {} values",
                seen.len()
            );
        }
        assert!(lengths.len() > 100, "{} handshake lengths", lengths.len());
        // The masked header of a data message differs from WireGuard's cleartext header
        o.wrap(&rng, NOW, &data(96), &mut wire).expect("wrap");
        assert_ne!(wire[SALT_LEN..SALT_LEN + 4], [4, 0, 0, 0]);
    }

    /// A replayed, stale, tampered or foreign datagram is dropped.
    #[test]
    fn replays_stale_tampered_and_foreign_datagrams_are_dropped() {
        let o = obfuscator(4);
        let rng = SystemRandom::new();
        let mut wire = Vec::new();
        let mut out = Vec::new();
        o.wrap(&rng, NOW, &handshake(1, 148), &mut wire)
            .expect("wrap");
        let mut salts = Salts::default();
        assert_eq!(o.unwrap(NOW, &mut salts, &wire, &mut out), Ok(()));
        assert_eq!(
            o.unwrap(NOW + 1_000, &mut salts, &wire, &mut out),
            Err(ObfsError::Replay)
        );
        // After the salt is forgotten, the time check still refuses it
        assert_eq!(
            o.unwrap(NOW + SALT_MEMORY_MS, &mut salts, &wire, &mut out),
            Err(ObfsError::Stale)
        );
        o.wrap(&rng, NOW - MAX_SKEW_MS - 1, &handshake(2, 92), &mut wire)
            .expect("wrap");
        assert_eq!(
            o.unwrap(NOW, &mut Salts::default(), &wire, &mut out),
            Err(ObfsError::Stale)
        );
        o.wrap(&rng, NOW, &handshake(2, 92), &mut wire)
            .expect("wrap");
        let last = wire.len() - 1;
        wire[last] ^= 1;
        assert_eq!(
            o.unwrap(NOW, &mut Salts::default(), &wire, &mut out),
            Err(ObfsError::Open)
        );
        // Another relay's key opens neither form
        let other = obfuscator(5);
        for message in [handshake(1, 148), data(96)] {
            o.wrap(&rng, NOW, &message, &mut wire).expect("wrap");
            assert_eq!(
                other.unwrap(NOW, &mut Salts::default(), &wire, &mut out),
                Err(ObfsError::Open)
            );
        }
        assert_eq!(
            o.unwrap(NOW, &mut Salts::default(), &[0u8; 20], &mut out),
            Err(ObfsError::TooShort)
        );
    }

    /// The salts remembered are bounded: once full of recent ones, a sealed message is dropped, and
    /// a minute later there is room again.
    #[test]
    fn remembered_salts_are_bounded() {
        let mut salts = Salts::default();
        for i in 0..MAX_SALTS as u64 {
            let mut s = [0u8; SALT_LEN];
            s[..8].copy_from_slice(&i.to_be_bytes());
            salts.remember(s, NOW).expect("room");
        }
        assert_eq!(salts.remember([0xff; SALT_LEN], NOW), Err(ObfsError::Full));
        assert_eq!(
            salts.remember([0xff; SALT_LEN], NOW + SALT_MEMORY_MS),
            Ok(())
        );
        assert_eq!(salts.len(), 1);
    }

    #[test]
    fn padding_stays_within_its_limit() {
        assert!(Padding::new(64, 320).is_ok());
        assert!(Padding::new(65, 64).is_err());
        assert!(Padding::new(0, 321).is_err());
    }
}
