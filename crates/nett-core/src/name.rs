//! 节点名：站点描述与 Hub 中的名字，组网中用于显示和定位（design/status.md 第 5 节、mesh.md 第 11 节）。
//! 以后作为主机名的第一段，所以取 DNS 标签的写法。

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// DNS 标签的长度上限。
pub const MAX_NAME_LEN: usize = 63;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("node name `{0}` must be 1-{MAX_NAME_LEN} lower-case letters, digits or `-`")]
pub struct NameError(pub String);

/// 小写字母、数字和 `-`，1 到 63 个字符。
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
            // 错误信息中只放前 MAX_NAME_LEN 个字符：输入可能来自不可信的期望状态
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
            "名字",
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
