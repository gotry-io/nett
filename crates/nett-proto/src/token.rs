//! Formats of the link code and the join token (design/hub.md sections 3.1, 3.5): a fixed prefix
//! followed by base64url-encoded JSON.
//!
//! - Link code `nett_lnk_…`: the Hub address, the Hub identity public key, a one-time random
//!   secret, and, when the Hub is self-signed, the certificate fingerprint;
//! - Join token `nett_enr_…`: the Hub address, the Hub identity public key, the node ID, and the
//!   fingerprint of the trust anchor list. The one used by a machine that is already a member holds
//!   no secrets, and the machine connects to the Hub with its own identity key; the one used by a
//!   new machine (enrollment token, design/auth.md section 8.1) additionally has the enrollment
//!   private key and an expiry time.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const LINK_PREFIX: &str = "nett_lnk_";
pub const JOIN_PREFIX: &str = "nett_enr_";
/// Upper limit on token text: far larger than these fields, which prevents parsing something else
/// as a token.
const MAX_TOKEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("this is not a {0} token")]
    Prefix(&'static str),
    #[error("the token is damaged: {0}")]
    Damaged(String),
}

/// A 32-byte value whose text form is base64url.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bytes32(pub [u8; 32]);

impl Serialize for Bytes32 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes32 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map(Self)
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

/// A 32-byte secret: zeroed in memory after use and not shown in debug output (hard rule 10).
#[derive(Clone, PartialEq, Eq)]
pub struct Secret32(pub Zeroizing<[u8; 32]>);

impl Secret32 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret32(..)")
    }
}

impl Serialize for Secret32 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        Bytes32(*self.0).serialize(s)
    }
}

impl<'de> Deserialize<'de> for Secret32 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Bytes32::deserialize(d).map(|b| Self(Zeroizing::new(b.0)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkCode {
    pub url: String,
    pub hub_key: Bytes32,
    pub secret: Bytes32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_fingerprint: Option<Bytes32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinToken {
    pub url: String,
    pub hub_key: Bytes32,
    pub node_id: String,
    /// 128-bit fingerprint of the trust anchor list (auth.md section 10.5), base64url.
    pub anchors: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_fingerprint: Option<Bytes32>,
    /// Only in the enrollment token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enroll: Option<Enroll>,
}

/// The secret part of the enrollment token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enroll {
    /// Enrollment private key: a 32-byte Ed25519 seed.
    pub key: Secret32,
    /// Expiry time (Unix seconds).
    pub expires_at: i64,
}

fn encode(prefix: &str, value: &impl Serialize) -> String {
    let json = serde_json::to_vec(value).expect("token fields always serialize");
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(json))
}

fn decode<T: for<'de> Deserialize<'de>>(prefix: &'static str, text: &str) -> Result<T, TokenError> {
    let text = text.trim();
    if text.len() > MAX_TOKEN {
        return Err(TokenError::Damaged("too long".into()));
    }
    let body = text
        .strip_prefix(prefix)
        .ok_or(TokenError::Prefix(prefix))?;
    let json = URL_SAFE_NO_PAD
        .decode(body.as_bytes())
        .map_err(|e| TokenError::Damaged(e.to_string()))?;
    serde_json::from_slice(&json).map_err(|e| TokenError::Damaged(e.to_string()))
}

impl LinkCode {
    pub fn encode(&self) -> String {
        encode(LINK_PREFIX, self)
    }

    pub fn decode(text: &str) -> Result<Self, TokenError> {
        decode(LINK_PREFIX, text)
    }
}

impl JoinToken {
    pub fn encode(&self) -> String {
        encode(JOIN_PREFIX, self)
    }

    pub fn decode(text: &str) -> Result<Self, TokenError> {
        decode(JOIN_PREFIX, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_round_trip_and_keep_their_prefixes_apart() {
        let link = LinkCode {
            url: "https://hub.example.com".into(),
            hub_key: Bytes32([7; 32]),
            secret: Bytes32([9; 32]),
            tls_fingerprint: None,
        };
        let text = link.encode();
        assert!(text.starts_with("nett_lnk_"));
        assert_eq!(LinkCode::decode(&text), Ok(link));
        assert_eq!(
            JoinToken::decode(&text),
            Err(TokenError::Prefix(JOIN_PREFIX))
        );
        let join = JoinToken {
            url: "https://hub.example.com".into(),
            hub_key: Bytes32([7; 32]),
            node_id: "node_01J9Z3K8Q2T7V4X6Y8A0B2C401".into(),
            anchors: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            tls_fingerprint: Some(Bytes32([1; 32])),
            enroll: None,
        };
        assert_eq!(JoinToken::decode(&format!(" {} ", join.encode())), Ok(join));
        assert!(LinkCode::decode("nett_lnk_!!!").is_err());
    }

    #[test]
    fn the_enrollment_key_round_trips_and_stays_out_of_debug_output() {
        let join = JoinToken {
            url: "https://hub.example.com".into(),
            hub_key: Bytes32([7; 32]),
            node_id: "node_01J9Z3K8Q2T7V4X6Y8A0B2C401".into(),
            anchors: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            tls_fingerprint: None,
            enroll: Some(Enroll {
                key: Secret32(Zeroizing::new([0xab; 32])),
                expires_at: 1_800_000_000,
            }),
        };
        let text = join.encode();
        assert_eq!(JoinToken::decode(&text), Ok(join.clone()));
        let debug = format!("{join:?}");
        assert!(!debug.contains("171"), "{debug}");
        assert!(debug.contains("Secret32(..)"), "{debug}");
    }
}
