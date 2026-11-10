//! 关联码与接入 token 的格式（design/hub.md 第 3.1、3.5 节）：固定前缀加上 base64url 编码的 JSON。
//!
//! - 关联码 `nett_lnk_…`：Hub 地址、Hub 身份公钥、一次性的随机密钥，以及 Hub 自签证书时证书的指纹；
//! - 接入 token `nett_enr_…`：已是成员的机器接入 Hub 用。只有 Hub 地址、Hub 身份公钥、节点 ID、信任锚
//!   清单的指纹，没有秘密：机器用自己的身份密钥连接 Hub。

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

pub const LINK_PREFIX: &str = "nett_lnk_";
pub const JOIN_PREFIX: &str = "nett_enr_";
/// token 文本的上限：远大于这些字段，防止把别的东西当成 token 解析。
const MAX_TOKEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("this is not a {0} token")]
    Prefix(&'static str),
    #[error("the token is damaged: {0}")]
    Damaged(String),
}

/// 32 字节的值，文本形式为 base64url。
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
    /// 信任锚清单的 128 位指纹（auth.md 第 10.5 节），base64url。
    pub anchors: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_fingerprint: Option<Bytes32>,
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
        };
        assert_eq!(JoinToken::decode(&format!(" {} ", join.encode())), Ok(join));
        assert!(LinkCode::decode("nett_lnk_!!!").is_err());
    }
}
