//! Noise_IK_25519_ChaChaPoly_BLAKE2s (design/protocol.md section 3), implemented per sections 5 and
//! 7.5 of the Noise protocol specification: nett-node is the initiator and knows the Hub's static
//! public key in advance (pinned at enrollment); the Hub is the responder and extracts the node's
//! static public key from the first message. After one round trip both sides have a transport key
//! for each direction.
//!
//! Uses only ring (ChaCha20-Poly1305), x25519-dalek and blake2, which are already in the dependency
//! tree; tests interoperate with an independent implementation (snow).

use blake2::Blake2s256;
use blake2::digest::Digest as _;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize as _, Zeroizing};

/// Prevents mixing with other protocols (protocol.md section 3.2).
pub const PROLOGUE: &[u8] = b"nett-control/1";
const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";
/// Upper limit on a Noise message (specification section 3).
pub const MAX_MESSAGE: usize = 65535;
const TAG: usize = 16;
const DH: usize = 32;
const HASH: usize = 32;
const BLOCK: usize = 64;
/// Rekey after this many messages in each direction (Rekey in specification section 11.3): each end
/// rekeys by message count and no extra messages are needed.
pub const REKEY_EVERY: u64 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NoiseError {
    #[error("Noise message is malformed or too short")]
    Malformed,
    #[error("Noise message failed to decrypt or authenticate")]
    Decrypt,
    #[error("Noise message would exceed {MAX_MESSAGE} bytes")]
    TooLong,
    #[error("Diffie-Hellman with a low-order point")]
    LowOrder,
    #[error("Noise nonce exhausted")]
    Exhausted,
    #[error("the system random number generator failed")]
    Random,
}

/// Generates a new X25519 private key.
pub fn generate_key() -> Result<StaticSecret, NoiseError> {
    use ring::rand::{SecureRandom as _, SystemRandom};
    let mut bytes = Zeroizing::new([0u8; 32]);
    SystemRandom::new()
        .fill(bytes.as_mut())
        .map_err(|_| NoiseError::Random)?;
    Ok(StaticSecret::from(*bytes))
}

fn hash(parts: &[&[u8]]) -> [u8; HASH] {
    let mut h = Blake2s256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// HMAC-BLAKE2s (RFC 2104, 64-byte block length).
fn hmac(key: &[u8; HASH], parts: &[&[u8]]) -> [u8; HASH] {
    let mut padded = Zeroizing::new([0u8; BLOCK]);
    padded[..HASH].copy_from_slice(key);
    let mut ipad = Zeroizing::new([0x36u8; BLOCK]);
    let mut opad = Zeroizing::new([0x5cu8; BLOCK]);
    for i in 0..BLOCK {
        ipad[i] ^= padded[i];
        opad[i] ^= padded[i];
    }
    let mut inner = Blake2s256::new();
    inner.update(ipad.as_ref());
    for p in parts {
        inner.update(p);
    }
    let inner: [u8; HASH] = inner.finalize().into();
    hash(&[opad.as_ref(), &inner])
}

/// HKDF from specification section 4.3, outputting two 32-byte values.
fn hkdf(ck: &[u8; HASH], ikm: &[u8]) -> (Zeroizing<[u8; HASH]>, Zeroizing<[u8; HASH]>) {
    let temp = Zeroizing::new(hmac(ck, &[ikm]));
    let one = Zeroizing::new(hmac(&temp, &[&[1]]));
    let two = Zeroizing::new(hmac(&temp, &[one.as_ref(), &[2]]));
    (one, two)
}

fn dh(secret: &StaticSecret, public: &[u8; DH]) -> Result<Zeroizing<[u8; DH]>, NoiseError> {
    let shared = secret.diffie_hellman(&PublicKey::from(*public));
    // A low-order point gives all zeros: reject it, the peer must contribute randomness
    if !shared.was_contributory() {
        return Err(NoiseError::LowOrder);
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

/// CipherState from specification section 5.1.
struct CipherState {
    key: Option<LessSafeKey>,
    n: u64,
}

impl CipherState {
    fn empty() -> Self {
        Self { key: None, n: 0 }
    }

    fn with_key(k: &[u8; 32]) -> Self {
        let key = UnboundKey::new(&CHACHA20_POLY1305, k)
            .expect("a 32-byte key is valid for ChaCha20-Poly1305");
        Self {
            key: Some(LessSafeKey::new(key)),
            n: 0,
        }
    }

    fn nonce(n: u64) -> Nonce {
        let mut bytes = [0u8; 12];
        bytes[4..].copy_from_slice(&n.to_le_bytes());
        Nonce::assume_unique_for_key(bytes)
    }

    fn encrypt(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let Some(key) = &self.key else {
            return Ok(plaintext.to_vec());
        };
        if self.n == u64::MAX {
            return Err(NoiseError::Exhausted);
        }
        let mut buf = plaintext.to_vec();
        key.seal_in_place_append_tag(Self::nonce(self.n), Aad::from(ad), &mut buf)
            .map_err(|_| NoiseError::Exhausted)?;
        self.n += 1;
        Ok(buf)
    }

    fn decrypt(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let Some(key) = &self.key else {
            return Ok(ciphertext.to_vec());
        };
        if self.n == u64::MAX {
            return Err(NoiseError::Exhausted);
        }
        let mut buf = ciphertext.to_vec();
        let len = key
            .open_in_place(Self::nonce(self.n), Aad::from(ad), &mut buf)
            .map_err(|_| NoiseError::Decrypt)?
            .len();
        buf.truncate(len);
        self.n += 1;
        Ok(buf)
    }

    /// Specification section 11.3: k = ENCRYPT(k, maxnonce, zerolen, zeros), taking the first 32
    /// bytes; n is unchanged.
    fn rekey(&mut self) {
        let Some(key) = &self.key else {
            return;
        };
        let mut zeros = vec![0u8; 32];
        key.seal_in_place_append_tag(Self::nonce(u64::MAX), Aad::empty(), &mut zeros)
            .expect("sealing 32 bytes cannot fail");
        let mut k = [0u8; 32];
        k.copy_from_slice(&zeros[..32]);
        zeros.zeroize();
        let n = self.n;
        *self = Self::with_key(&k);
        k.zeroize();
        self.n = n;
    }
}

/// SymmetricState from specification section 5.2.
struct Symmetric {
    ck: Zeroizing<[u8; HASH]>,
    h: [u8; HASH],
    cs: CipherState,
}

impl Symmetric {
    fn new() -> Self {
        // Protocol name longer than 32 bytes: h = HASH(protocol name)
        let h = hash(&[PROTOCOL_NAME]);
        let mut s = Self {
            ck: Zeroizing::new(h),
            h,
            cs: CipherState::empty(),
        };
        s.mix_hash(PROLOGUE);
        s
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = hash(&[&self.h, data]);
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = hkdf(&self.ck, ikm);
        self.ck = ck;
        self.cs = CipherState::with_key(&k);
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let ct = self.cs.encrypt(&self.h, plaintext)?;
        self.mix_hash(&ct);
        Ok(ct)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let pt = self.cs.decrypt(&self.h, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    /// Transport keys for the two directions: the initiator sends with the first and the responder
    /// receives with the first.
    fn split(&self) -> (CipherState, CipherState) {
        let (one, two) = hkdf(&self.ck, &[]);
        (CipherState::with_key(&one), CipherState::with_key(&two))
    }
}

/// The initiator (nett-node).
pub struct Initiator {
    sym: Symmetric,
    s: StaticSecret,
    e: StaticSecret,
    rs: [u8; DH],
}

impl Initiator {
    /// `remote` is the Hub's static public key.
    pub fn new(local: &StaticSecret, remote: [u8; DH]) -> Result<Self, NoiseError> {
        let mut sym = Symmetric::new();
        // Pre-message <- s
        sym.mix_hash(&remote);
        Ok(Self {
            sym,
            s: local.clone(),
            e: generate_key()?,
            rs: remote,
        })
    }

    /// First message: -> e, es, s, ss, plus the encrypted payload.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let e_pub = PublicKey::from(&self.e).to_bytes();
        let mut out = e_pub.to_vec();
        self.sym.mix_hash(&e_pub);
        self.sym.mix_key(dh(&self.e, &self.rs)?.as_ref());
        let s_pub = PublicKey::from(&self.s).to_bytes();
        out.extend(self.sym.encrypt_and_hash(&s_pub)?);
        self.sym.mix_key(dh(&self.s, &self.rs)?.as_ref());
        out.extend(self.sym.encrypt_and_hash(payload)?);
        if out.len() > MAX_MESSAGE {
            return Err(NoiseError::TooLong);
        }
        Ok(out)
    }

    /// Second message: <- e, ee, se, returns the payload and the transport state.
    pub fn read_message(mut self, message: &[u8]) -> Result<(Vec<u8>, Transport), NoiseError> {
        if message.len() < DH + TAG || message.len() > MAX_MESSAGE {
            return Err(NoiseError::Malformed);
        }
        let mut re = [0u8; DH];
        re.copy_from_slice(&message[..DH]);
        self.sym.mix_hash(&re);
        self.sym.mix_key(dh(&self.e, &re)?.as_ref());
        self.sym.mix_key(dh(&self.s, &re)?.as_ref());
        let payload = self.sym.decrypt_and_hash(&message[DH..])?;
        let (send, recv) = self.sym.split();
        Ok((payload, Transport::new(send, recv, self.sym.h)))
    }
}

/// The responder (Hub).
pub struct Responder {
    sym: Symmetric,
    s: StaticSecret,
    re: [u8; DH],
    rs: [u8; DH],
}

impl Responder {
    pub fn new(local: &StaticSecret) -> Self {
        let mut sym = Symmetric::new();
        sym.mix_hash(&PublicKey::from(local).to_bytes());
        Self {
            sym,
            s: local.clone(),
            re: [0; DH],
            rs: [0; DH],
        }
    }

    /// Reads the first message and returns the payload and the initiator's static public key.
    pub fn read_message(&mut self, message: &[u8]) -> Result<(Vec<u8>, [u8; DH]), NoiseError> {
        if message.len() < DH + DH + TAG + TAG || message.len() > MAX_MESSAGE {
            return Err(NoiseError::Malformed);
        }
        self.re.copy_from_slice(&message[..DH]);
        self.sym.mix_hash(&self.re);
        self.sym.mix_key(dh(&self.s, &self.re)?.as_ref());
        let rs = self.sym.decrypt_and_hash(&message[DH..DH + DH + TAG])?;
        self.rs.copy_from_slice(&rs);
        self.sym.mix_key(dh(&self.s, &self.rs)?.as_ref());
        let payload = self.sym.decrypt_and_hash(&message[DH + DH + TAG..])?;
        Ok((payload, self.rs))
    }

    /// Second message: <- e, ee, se, returns the message and the transport state.
    pub fn write_message(mut self, payload: &[u8]) -> Result<(Vec<u8>, Transport), NoiseError> {
        let e = generate_key()?;
        let e_pub = PublicKey::from(&e).to_bytes();
        let mut out = e_pub.to_vec();
        self.sym.mix_hash(&e_pub);
        self.sym.mix_key(dh(&e, &self.re)?.as_ref());
        self.sym.mix_key(dh(&e, &self.rs)?.as_ref());
        out.extend(self.sym.encrypt_and_hash(payload)?);
        if out.len() > MAX_MESSAGE {
            return Err(NoiseError::TooLong);
        }
        let (recv, send) = self.sym.split();
        Ok((out, Transport::new(send, recv, self.sym.h)))
    }
}

/// Transport state after the handshake: one key per direction, rekeyed by message count.
pub struct Transport {
    send: CipherState,
    recv: CipherState,
    handshake_hash: [u8; HASH],
}

impl Transport {
    fn new(send: CipherState, recv: CipherState, handshake_hash: [u8; HASH]) -> Self {
        Self {
            send,
            recv,
            handshake_hash,
        }
    }

    /// Handshake hash: identical on both sides and uniquely identifies this session (specification
    /// section 11.2).
    pub fn handshake_hash(&self) -> [u8; HASH] {
        self.handshake_hash
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if plaintext.len() + TAG > MAX_MESSAGE {
            return Err(NoiseError::TooLong);
        }
        let out = self.send.encrypt(&[], plaintext)?;
        if self.send.n.is_multiple_of(REKEY_EVERY) {
            self.send.rekey();
        }
        Ok(out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if ciphertext.len() < TAG || ciphertext.len() > MAX_MESSAGE {
            return Err(NoiseError::Malformed);
        }
        let out = self.recv.decrypt(&[], ciphertext)?;
        if self.recv.n.is_multiple_of(REKEY_EVERY) {
            self.recv.rekey();
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

    fn pair() -> (StaticSecret, StaticSecret) {
        (generate_key().expect("key"), generate_key().expect("key"))
    }

    #[test]
    fn our_initiator_talks_to_snow_as_responder() {
        let (node, hub) = pair();
        let hub_pub = PublicKey::from(&hub).to_bytes();
        let mut snow_r = snow::Builder::new(NAME.parse().expect("params"))
            .local_private_key(&hub.to_bytes())
            .expect("key")
            .prologue(PROLOGUE)
            .expect("prologue")
            .build_responder()
            .expect("responder");
        let mut ours = Initiator::new(&node, hub_pub).expect("initiator");
        let m1 = ours.write_message(b"hello").expect("m1");
        let mut buf = vec![0u8; MAX_MESSAGE];
        let n = snow_r.read_message(&m1, &mut buf).expect("snow reads m1");
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(
            snow_r.get_remote_static().expect("remote static"),
            PublicKey::from(&node).to_bytes()
        );
        let n = snow_r.write_message(b"welcome", &mut buf).expect("m2");
        let (payload, mut t) = ours.read_message(&buf[..n]).expect("we read m2");
        assert_eq!(payload, b"welcome");
        let mut snow_t = snow_r.into_transport_mode().expect("transport");
        for i in 0..3u8 {
            let ct = t.encrypt(&[i; 100]).expect("encrypt");
            let n = snow_t.read_message(&ct, &mut buf).expect("snow decrypts");
            assert_eq!(&buf[..n], &[i; 100]);
            let n = snow_t
                .write_message(&[i ^ 0xff; 50], &mut buf)
                .expect("snow encrypts");
            assert_eq!(t.decrypt(&buf[..n]).expect("we decrypt"), [i ^ 0xff; 50]);
        }
    }

    #[test]
    fn snow_as_initiator_talks_to_our_responder() {
        let (node, hub) = pair();
        let mut snow_i = snow::Builder::new(NAME.parse().expect("params"))
            .local_private_key(&node.to_bytes())
            .expect("key")
            .remote_public_key(&PublicKey::from(&hub).to_bytes())
            .expect("remote")
            .prologue(PROLOGUE)
            .expect("prologue")
            .build_initiator()
            .expect("initiator");
        let mut buf = vec![0u8; MAX_MESSAGE];
        let n = snow_i.write_message(b"hello", &mut buf).expect("m1");
        let mut ours = Responder::new(&hub);
        let (payload, rs) = ours.read_message(&buf[..n]).expect("we read m1");
        assert_eq!(payload, b"hello");
        assert_eq!(rs, PublicKey::from(&node).to_bytes());
        let (m2, mut t) = ours.write_message(b"welcome").expect("m2");
        let n = snow_i.read_message(&m2, &mut buf).expect("snow reads m2");
        assert_eq!(&buf[..n], b"welcome");
        assert_eq!(snow_i.get_handshake_hash(), t.handshake_hash());
        let mut snow_t = snow_i.into_transport_mode().expect("transport");
        let n = snow_t.write_message(b"state", &mut buf).expect("encrypt");
        assert_eq!(t.decrypt(&buf[..n]).expect("decrypt"), b"state");
        let ct = t.encrypt(b"ack").expect("encrypt");
        let n = snow_t.read_message(&ct, &mut buf).expect("snow decrypts");
        assert_eq!(&buf[..n], b"ack");
    }

    #[test]
    fn a_wrong_hub_key_or_tampering_fails_the_handshake() {
        let (node, hub) = pair();
        let other = generate_key().expect("key");
        // The Hub public key the node believes in is wrong: the Hub cannot decrypt the first
        // message
        let mut i = Initiator::new(&node, PublicKey::from(&other).to_bytes()).expect("initiator");
        let m1 = i.write_message(b"hello").expect("m1");
        assert!(Responder::new(&hub).read_message(&m1).is_err());
        // Tamper with the first message
        let mut i = Initiator::new(&node, PublicKey::from(&hub).to_bytes()).expect("initiator");
        let mut m1 = i.write_message(b"hello").expect("m1");
        let last = m1.len() - 1;
        m1[last] ^= 1;
        assert_eq!(
            Responder::new(&hub).read_message(&m1),
            Err(NoiseError::Decrypt)
        );
        // A low-order point as the ephemeral public key
        let mut zero = vec![0u8; 32 + 48 + 16];
        zero[0] = 0;
        assert_eq!(
            Responder::new(&hub).read_message(&zero),
            Err(NoiseError::LowOrder)
        );
        assert_eq!(
            Responder::new(&hub).read_message(&[0; 10]),
            Err(NoiseError::Malformed)
        );
    }

    fn session(node: &StaticSecret, hub: &StaticSecret) -> (Transport, Transport) {
        let mut i = Initiator::new(node, PublicKey::from(hub).to_bytes()).expect("initiator");
        let mut r = Responder::new(hub);
        let m1 = i.write_message(&[]).expect("m1");
        r.read_message(&m1).expect("read m1");
        let (m2, rt) = r.write_message(&[]).expect("m2");
        let (_, it) = i.read_message(&m2).expect("read m2");
        (it, rt)
    }

    #[test]
    fn transport_messages_are_in_order_and_keys_rotate_alike_on_both_ends() {
        let (node, hub) = pair();
        let (mut it, mut rt) = session(&node, &hub);
        let _first = it.encrypt(b"one").expect("one");
        let second = it.encrypt(b"two").expect("two");
        // Replay or out of order: the counter does not match and it cannot be decrypted
        assert_eq!(rt.decrypt(&second), Err(NoiseError::Decrypt));
        // Across the rekey boundary: each end rekeys by message count and decrypts as usual
        let (mut it, mut rt) = session(&node, &hub);
        it.send.n = REKEY_EVERY - 1;
        rt.recv.n = REKEY_EVERY - 1;
        let before = it.encrypt(b"before").expect("before");
        let after = it.encrypt(b"after").expect("after");
        assert_eq!(rt.decrypt(&before).expect("before"), b"before");
        assert_eq!(rt.decrypt(&after).expect("after"), b"after");
        assert_eq!(it.encrypt(&vec![0; MAX_MESSAGE]), Err(NoiseError::TooLong));
    }
}
