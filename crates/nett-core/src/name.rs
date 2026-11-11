//! Node name: the name in the site description and the Hub, used in the mesh for display and lookup
//! (design/status.md section 5, mesh.md section 11). It later serves as the first label of the
//! hostname, so it takes the DNS label form.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Upper limit on the length of a DNS label.
pub const MAX_NAME_LEN: usize = 63;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("node name `{0}` must be 1-{MAX_NAME_LEN} lower-case letters, digits or `-`")]
pub struct NameError(pub String);

/// Lowercase letters, digits and `-`, 1 to 63 characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeName(String);

impl NodeName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for NodeName {
    type Err = NameError;

    fn from_str(s: &str) -> Result<Self, NameError> {
        let valid = (1..=MAX_NAME_LEN).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if valid {
            Ok(Self(s.to_owned()))
        } else {
            // Only the first MAX_NAME_LEN characters go in the error message: the input may come
            // from untrusted desired state
            Err(NameError(s.chars().take(MAX_NAME_LEN).collect()))
        }
    }
}

impl fmt::Display for NodeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for NodeName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for NodeName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_dns_labels() {
        for ok in ["a", "edge-vps", "mac2", &"x".repeat(MAX_NAME_LEN)] {
            assert_eq!(ok.parse::<NodeName>().expect("valid").as_str(), ok);
        }
    }

    #[test]
    fn rejects_other_forms() {
        for bad in [
            "",
            "Mac",
            "edge_vps",
            "a.b",
            "\u{540d}\u{5b57}",
            &"x".repeat(MAX_NAME_LEN + 1),
        ] {
            assert!(bad.parse::<NodeName>().is_err(), "{bad}");
        }
    }

    #[test]
    fn deserializes_with_validation() {
        let ok: NodeName = serde_json::from_str("\"edge-vps\"").expect("valid");
        assert_eq!(ok.to_string(), "edge-vps");
        assert!(serde_json::from_str::<NodeName>("\"Bad Name\"").is_err());
    }
}
