//! External IDs: `<prefix>_<ULID>` (design/api-resources.md section 2.2).
//!
//! Parsed only once at the boundary and passed as strong types afterwards; a ULID accepts only the
//! canonical form (uppercase Crockford base32), so the same ID has only one spelling, and IDs in
//! signed payloads can be compared byte by byte.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Text length of a ULID (128 bits, Crockford base32).
const ULID_LEN: usize = 26;

/// The Crockford base32 alphabet, which does not contain I, L, O, U.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    #[error("id must start with `{expected}_`")]
    Prefix { expected: &'static str },
    #[error("id must end with a 26-character ULID in canonical upper-case Crockford base32")]
    Ulid,
}

/// ULID: a 48-bit millisecond timestamp first, then 80 random bits, written in Crockford base32 as
/// 26 characters (the top two bits are 0).
fn ulid(unix_ms: u64, random: [u8; 10]) -> String {
    let mut bits = u128::from(unix_ms & 0xffff_ffff_ffff) << 80;
    for (i, b) in random.iter().enumerate() {
        bits |= u128::from(*b) << (72 - 8 * i);
    }
    (0..ULID_LEN)
        .rev()
        .map(|i| char::from(CROCKFORD[usize::try_from((bits >> (5 * i)) & 0x1f).unwrap_or(0)]))
        .collect()
}

fn validate(s: &str, prefix: &'static str) -> Result<(), IdError> {
    let ulid = s
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('_'))
        .ok_or(IdError::Prefix { expected: prefix })?;
    let bytes = ulid.as_bytes();
    // The first character is at most 7: 26 characters are 130 bits, and the top two bits must be 0
    let valid =
        bytes.len() == ULID_LEN && bytes[0] <= b'7' && bytes.iter().all(|b| CROCKFORD.contains(b));
    if valid { Ok(()) } else { Err(IdError::Ulid) }
}

macro_rules! prefixed_id {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// A new ID made of a Unix millisecond timestamp and 80 random bits (the canonical form
            /// of a ULID). The random bits are provided by the caller.
            pub fn from_parts(unix_ms: u64, random: [u8; 10]) -> Self {
                Self(format!("{}_{}", $prefix, ulid(unix_ms, random)))
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(s: &str) -> Result<Self, IdError> {
                validate(s, $prefix)?;
                Ok(Self(s.to_owned()))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

prefixed_id!(
    /// Node ID, assigned when an enrollment token is created.
    NodeId,
    "node"
);
prefixed_id!(
    /// ID of a passkey in the trust anchor list.
    PasskeyId,
    "pk"
);
prefixed_id!(
    /// Change set ID.
    ChangeId,
    "chg"
);

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "node_01J9Z3K8Q2T7V4X6Y8A0B2C4D6";

    #[test]
    fn accepts_canonical_ulid() {
        let id: NodeId = VALID.parse().expect("valid id");
        assert_eq!(id.as_str(), VALID);
    }

    #[test]
    fn rejects_wrong_prefix() {
        assert_eq!(
            "pk_01J9Z3K8Q2T7V4X6Y8A0B2C4D6".parse::<NodeId>(),
            Err(IdError::Prefix { expected: "node" })
        );
        assert!("node01J9Z3K8Q2T7V4X6Y8A0B2C4D6".parse::<NodeId>().is_err());
    }

    #[test]
    fn rejects_non_canonical_ulid() {
        for bad in [
            "node_01j9z3k8q2t7v4x6y8a0b2c4d6", // lowercase
            "node_01J9Z3K8Q2T7V4X6Y8A0B2C4D",  // 25 characters
            "node_01J9Z3K8Q2T7V4X6Y8A0B2C4DI", // outside the alphabet
            "node_81J9Z3K8Q2T7V4X6Y8A0B2C4D6", // more than 128 bits
        ] {
            assert_eq!(bad.parse::<NodeId>(), Err(IdError::Ulid), "{bad}");
        }
    }

    #[test]
    fn generated_ids_are_canonical_and_ordered_by_time() {
        // Example from the ULID specification: with timestamp 1469918176385 and all-zero random
        // bits it is 01ARYZ6S41 followed by 16 zeros
        let id = NodeId::from_parts(1_469_918_176_385, [0; 10]);
        assert_eq!(id.as_str(), "node_01ARYZ6S410000000000000000");
        let later = NodeId::from_parts(1_469_918_176_386, [0xff; 10]);
        assert!(later.as_str().parse::<NodeId>().is_ok());
        assert!(id < later);
    }

    #[test]
    fn serde_round_trip_validates() {
        let json = format!("\"{VALID}\"");
        let id: NodeId = serde_json::from_str(&json).expect("valid id");
        assert_eq!(serde_json::to_string(&id).expect("serialize"), json);
        assert!(serde_json::from_str::<NodeId>("\"node_x\"").is_err());
    }
}
