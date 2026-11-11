//! Trust anchor list (design/auth.md section 11.1).

use nett_core::id::PasskeyId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{CanonicalError, to_canonical};
use crate::encoding::Sha256Digest;
use crate::keys::{Algorithm, AnchorKey, KeyError};

/// Version of the list format.
const FORMAT_V1: u64 = 1;

/// The document form of the trust anchor list, with fields matching design/auth.md section 11.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchorsDoc {
    pub v: u64,
    pub version: u64,
    pub rp_id: String,
    pub origin: String,
    pub passkeys: Vec<PasskeyDoc>,
    pub recovery_key: RecoveryKeyDoc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyDoc {
    pub id: PasskeyId,
    pub alg: Algorithm,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKeyDoc {
    pub alg: Algorithm,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnchorsError {
    #[error("trust anchors: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("trust anchors: invalid document: {0}")]
    Document(String),
    #[error("trust anchors: unsupported format version {0}")]
    Format(u64),
    #[error("trust anchors: origin must be https://<host>[:port] with a host under rp_id")]
    Origin,
    #[error("trust anchors: duplicate passkey id {0}")]
    DuplicatePasskey(PasskeyId),
    #[error("trust anchors: passkey {id}: {source}")]
    PasskeyKey { id: PasskeyId, source: KeyError },
    #[error("trust anchors: recovery key: {0}")]
    RecoveryKey(KeyError),
}

/// A validated trust anchor list.
#[derive(Debug, Clone)]
pub struct TrustAnchors {
    version: u64,
    origin: String,
    rp_id_hash: Sha256Digest,
    passkeys: Vec<(PasskeyId, AnchorKey)>,
    recovery_key: AnchorKey,
    fingerprint: [u8; 16],
}

impl TrustAnchors {
    pub fn from_value(value: &Value) -> Result<Self, AnchorsError> {
        let canonical = to_canonical(value)?;
        let doc = TrustAnchorsDoc::deserialize(value)
            .map_err(|e| AnchorsError::Document(e.to_string()))?;
        if doc.v != FORMAT_V1 {
            return Err(AnchorsError::Format(doc.v));
        }
        if !origin_matches_rp_id(&doc.origin, &doc.rp_id) {
            return Err(AnchorsError::Origin);
        }
        let mut passkeys: Vec<(PasskeyId, AnchorKey)> = Vec::with_capacity(doc.passkeys.len());
        for pk in doc.passkeys {
            if passkeys.iter().any(|(id, _)| *id == pk.id) {
                return Err(AnchorsError::DuplicatePasskey(pk.id));
            }
            match AnchorKey::from_b64(pk.alg, &pk.public_key) {
                Ok(key) => passkeys.push((pk.id, key)),
                Err(source) => return Err(AnchorsError::PasskeyKey { id: pk.id, source }),
            }
        }
        if doc.recovery_key.alg != Algorithm::Es256 {
            return Err(AnchorsError::RecoveryKey(KeyError::RecoveryAlgorithm));
        }
        let recovery_key = AnchorKey::from_b64(doc.recovery_key.alg, &doc.recovery_key.public_key)
            .map_err(AnchorsError::RecoveryKey)?;
        let mut fingerprint = [0u8; 16];
        fingerprint.copy_from_slice(&Sha256Digest::of(&canonical).0[..16]);
        Ok(Self {
            version: doc.version,
            origin: doc.origin,
            rp_id_hash: Sha256Digest::of(doc.rp_id.as_bytes()),
            passkeys,
            recovery_key,
            fingerprint,
        })
    }

    pub fn from_doc(doc: &TrustAnchorsDoc) -> Result<Self, AnchorsError> {
        let value = serde_json::to_value(doc).map_err(|e| AnchorsError::Document(e.to_string()))?;
        Self::from_value(&value)
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    /// The 128-bit fingerprint in the enrollment token: the first 16 bytes of the SHA-256 of the
    /// list's canonical form (design/auth.md section 10.5).
    pub fn fingerprint(&self) -> [u8; 16] {
        self.fingerprint
    }

    pub(crate) fn origin(&self) -> &str {
        &self.origin
    }

    pub(crate) fn rp_id_hash(&self) -> &Sha256Digest {
        &self.rp_id_hash
    }

    pub(crate) fn passkey(&self, id: &PasskeyId) -> Option<&AnchorKey> {
        self.passkeys
            .iter()
            .find(|(pid, _)| pid == id)
            .map(|(_, k)| k)
    }

    pub(crate) fn recovery_key(&self) -> &AnchorKey {
        &self.recovery_key
    }
}

/// Passkey-bound RP ID: the hostname of the console address must equal the RP ID or be a subdomain
/// of it (the WebAuthn rule).
fn origin_matches_rp_id(origin: &str, rp_id: &str) -> bool {
    let Some(authority) = origin.strip_prefix("https://") else {
        return false;
    };
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        Some(_) => return false,
        None => authority,
    };
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    host_ok
        && !rp_id.is_empty()
        && (host == rp_id
            || host
                .strip_suffix(rp_id)
                .is_some_and(|prefix| prefix.ends_with('.')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn p256_point() -> String {
        let mut point = vec![0x04];
        point.extend_from_slice(&[7u8; 64]);
        crate::encoding::encode_b64(&point)
    }

    fn doc() -> Value {
        json!({
            "v": 1,
            "version": 3,
            "rp_id": "hub.example.com",
            "origin": "https://hub.example.com",
            "passkeys": [{ "id": "pk_01J9Z3K8Q2T7V4X6Y8A0B2C4D6", "alg": "EdDSA", "public_key": crate::encoding::encode_b64(&[1u8; 32]) }],
            "recovery_key": { "alg": "ES256", "public_key": p256_point() }
        })
    }

    #[test]
    fn parses_and_fingerprints_the_canonical_form() {
        let anchors = TrustAnchors::from_value(&doc()).expect("valid anchors");
        assert_eq!(anchors.version(), 3);
        let canonical = to_canonical(&doc()).expect("canonical");
        assert_eq!(
            anchors.fingerprint()[..],
            Sha256Digest::of(&canonical).0[..16]
        );
    }

    #[test]
    fn rejects_unknown_fields_and_formats() {
        let mut v = doc();
        v["extra"] = json!(1);
        assert!(matches!(
            TrustAnchors::from_value(&v),
            Err(AnchorsError::Document(_))
        ));
        let mut v = doc();
        v["v"] = json!(2);
        assert_eq!(
            TrustAnchors::from_value(&v).err(),
            Some(AnchorsError::Format(2))
        );
    }

    #[test]
    fn recovery_key_must_be_es256() {
        let mut v = doc();
        v["recovery_key"] =
            json!({ "alg": "EdDSA", "public_key": crate::encoding::encode_b64(&[1u8; 32]) });
        assert!(matches!(
            TrustAnchors::from_value(&v),
            Err(AnchorsError::RecoveryKey(_))
        ));
    }

    #[test]
    fn rejects_duplicate_passkeys() {
        let mut v = doc();
        let pk = v["passkeys"][0].clone();
        v["passkeys"] = json!([pk.clone(), pk]);
        assert!(matches!(
            TrustAnchors::from_value(&v),
            Err(AnchorsError::DuplicatePasskey(_))
        ));
    }

    #[test]
    fn origin_must_sit_under_rp_id() {
        for (origin, rp_id, ok) in [
            ("https://hub.example.com", "hub.example.com", true),
            ("https://hub.example.com:8443", "example.com", true),
            ("http://hub.example.com", "hub.example.com", false),
            ("https://evilexample.com", "example.com", false),
            ("https://hub.example.com/", "hub.example.com", false),
            ("https://hub.example.com:", "hub.example.com", false),
            ("https://HUB.example.com", "hub.example.com", false),
        ] {
            assert_eq!(origin_matches_rp_id(origin, rp_id), ok, "{origin} {rp_id}");
        }
    }
}
