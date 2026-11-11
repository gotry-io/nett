//! Encryption of the Hub's backups (design/hub.md section 8.2, auth.md section 12): a backup is sealed to
//! the site's backup public key with an ephemeral X25519 key agreement, HKDF-SHA256 and
//! ChaCha20-Poly1305. The Hub holds only the public key, so it can make backups but not read them; the
//! private key stays in the site directory.
//!
//! Format: `NETTBAK1 | ephemeral public key (32) | nonce (12) | ciphertext and tag`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use ring::rand::{SecureRandom as _, SystemRandom};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::keys::X25519PublicKey;

const MAGIC: &[u8; 8] = b"NETTBAK1";
const INFO: &[u8] = b"nett hub backup v1";
const LINE_PREFIX: &str = "nett-backup-";
const HEADER: usize = MAGIC.len() + 32 + 12;
pub use crate::MAX_BACKUP_BYTES as MAX_BACKUP;

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("the system random number generator failed")]
    Random,
    #[error("the backup is larger than {MAX_BACKUP} bytes")]
    TooLarge,
    #[error("this is not a nett Hub backup")]
    Format,
    #[error(
        "the backup does not open with this key: the key is another site's, or the file is damaged"
    )]
    Open,
    #[error("a backup key is one line starting with `nett-backup-`")]
    KeyLine,
}

/// The site's backup private key. `Debug` does not print it (hard rule 10).
pub struct BackupKey(StaticSecret);

impl std::fmt::Debug for BackupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackupKey(<redacted>)")
    }
}

impl BackupKey {
    pub fn generate() -> Result<Self, BackupError> {
        let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
        SystemRandom::new()
            .fill(&mut bytes[..])
            .map_err(|_| BackupError::Random)?;
        Ok(Self(StaticSecret::from(*bytes)))
    }

    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from_bytes(PublicKey::from(&self.0).to_bytes())
    }

    /// The one line kept in the site directory and written down offline: `nett-backup-` and the key in
    /// base64url.
    pub fn to_line(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(format!(
            "{LINE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(self.0.as_bytes())
        ))
    }

    /// Reads the line back; surrounding whitespace is ignored.
    pub fn from_line(line: &str) -> Result<Self, BackupError> {
        let encoded = line
            .trim()
            .strip_prefix(LINE_PREFIX)
            .ok_or(BackupError::KeyLine)?;
        let bytes = zeroize::Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| BackupError::KeyLine)?,
        );
        let key: [u8; 32] = bytes[..].try_into().map_err(|_| BackupError::KeyLine)?;
        Ok(Self(StaticSecret::from(key)))
    }
}

fn aead_key(shared: &[u8], ephemeral: &[u8; 32], recipient: &[u8; 32]) -> LessSafeKey {
    let salt = [&ephemeral[..], &recipient[..]].concat();
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    hkdf::Salt::new(hkdf::HKDF_SHA256, &salt)
        .extract(shared)
        .expand(&[INFO], &CHACHA20_POLY1305)
        .and_then(|okm| okm.fill(&mut key[..]))
        .expect("HKDF output of 32 bytes for ChaCha20-Poly1305");
    LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, &key[..]).expect("a 32-byte ChaCha20-Poly1305 key"),
    )
}

/// Seals `plaintext` to the backup public key.
pub fn seal(recipient: &X25519PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, BackupError> {
    if plaintext.len() + HEADER + CHACHA20_POLY1305.tag_len() > MAX_BACKUP {
        return Err(BackupError::TooLarge);
    }
    let rng = SystemRandom::new();
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    rng.fill(&mut secret[..]).map_err(|_| BackupError::Random)?;
    let ephemeral = StaticSecret::from(*secret);
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*recipient.as_bytes()));
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce).map_err(|_| BackupError::Random)?;
    let key = aead_key(shared.as_bytes(), &ephemeral_public, recipient.as_bytes());
    let mut out = Vec::with_capacity(plaintext.len() + HEADER + CHACHA20_POLY1305.tag_len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&ephemeral_public);
    out.extend_from_slice(&nonce);
    let mut body = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&out[..MAGIC.len() + 32]),
        &mut body,
    )
    .map_err(|_| BackupError::Format)?;
    out.extend_from_slice(&body);
    Ok(out)
}

/// Opens a sealed backup with the backup private key.
pub fn open(key: &BackupKey, sealed: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, BackupError> {
    if sealed.len() > MAX_BACKUP {
        return Err(BackupError::TooLarge);
    }
    if sealed.len() < HEADER + CHACHA20_POLY1305.tag_len() || &sealed[..MAGIC.len()] != MAGIC {
        return Err(BackupError::Format);
    }
    let ephemeral: [u8; 32] = sealed[MAGIC.len()..MAGIC.len() + 32]
        .try_into()
        .map_err(|_| BackupError::Format)?;
    let nonce: [u8; 12] = sealed[MAGIC.len() + 32..HEADER]
        .try_into()
        .map_err(|_| BackupError::Format)?;
    let shared = key.0.diffie_hellman(&PublicKey::from(ephemeral));
    let recipient = PublicKey::from(&key.0).to_bytes();
    let aead = aead_key(shared.as_bytes(), &ephemeral, &recipient);
    let mut body = zeroize::Zeroizing::new(sealed[HEADER..].to_vec());
    let len = aead
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&sealed[..MAGIC.len() + 32]),
            &mut body,
        )
        .map_err(|_| BackupError::Open)?
        .len();
    body.truncate(len);
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backup_opens_only_with_its_key() {
        let key = BackupKey::generate().expect("key");
        let sealed = seal(&key.public_key(), b"database and identity").expect("sealed");
        assert_eq!(
            &open(&key, &sealed).expect("opened")[..],
            b"database and identity"
        );
        let other = BackupKey::generate().expect("key");
        assert!(matches!(open(&other, &sealed), Err(BackupError::Open)));
        let mut damaged = sealed.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(matches!(open(&key, &damaged), Err(BackupError::Open)));
        assert!(matches!(open(&key, b"NETTBAK0"), Err(BackupError::Format)));
        // Two backups of the same content differ: a fresh ephemeral key each time
        assert_ne!(
            sealed,
            seal(&key.public_key(), b"database and identity").expect("sealed")
        );
    }

    #[test]
    fn the_key_line_round_trips_and_is_not_printed() {
        let key = BackupKey::generate().expect("key");
        let line = key.to_line();
        assert!(line.starts_with("nett-backup-"));
        let back = BackupKey::from_line(&format!("  {}\n", *line)).expect("parsed");
        assert_eq!(back.public_key(), key.public_key());
        assert!(BackupKey::from_line("nett-recovery-abc").is_err());
        assert_eq!(format!("{key:?}"), "BackupKey(<redacted>)");
    }
}
