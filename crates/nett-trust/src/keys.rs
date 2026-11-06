//! 公钥与签名验证（design/auth.md 第 10.5 节）。只验证，不签名：签名在用户的设备上完成。

use std::fmt;

use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED, ED25519, UnparsedPublicKey,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::encoding::{EncodingError, decode_b64, decode_b64_fixed, encode_b64};

/// 未压缩 SEC1 点的长度：`0x04 ‖ X ‖ Y`。
const P256_POINT_LEN: usize = 65;

/// passkey 允许的算法（design/auth.md 第 10.2 节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "EdDSA")]
    EdDsa,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("public key encoding: {0}")]
    Encoding(#[from] EncodingError),
    #[error("{alg:?} public key must be {expected} bytes, got {actual}")]
    Length {
        alg: Algorithm,
        expected: usize,
        actual: usize,
    },
    #[error("ES256 public key must be an uncompressed SEC1 point")]
    NotUncompressed,
    #[error("the recovery key must use ES256")]
    RecoveryAlgorithm,
}

/// 信任锚中的一把公钥：passkey 或恢复密钥。
#[derive(Clone, PartialEq, Eq)]
pub struct AnchorKey {
    alg: Algorithm,
    bytes: Vec<u8>,
}

impl AnchorKey {
    pub fn new(alg: Algorithm, bytes: Vec<u8>) -> Result<Self, KeyError> {
        let expected = match alg {
            Algorithm::Es256 => P256_POINT_LEN,
            Algorithm::EdDsa => 32,
        };
        if bytes.len() != expected {
            return Err(KeyError::Length {
                alg,
                expected,
                actual: bytes.len(),
            });
        }
        if alg == Algorithm::Es256 && bytes[0] != 0x04 {
            return Err(KeyError::NotUncompressed);
        }
        Ok(Self { alg, bytes })
    }

    pub fn from_b64(alg: Algorithm, s: &str) -> Result<Self, KeyError> {
        Self::new(alg, decode_b64(s)?)
    }

    pub fn alg(&self) -> Algorithm {
        self.alg
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 验证 WebAuthn 断言的签名：ES256 为 ASN.1 DER，EdDSA 为 64 字节。
    pub(crate) fn verify_webauthn(&self, message: &[u8], signature: &[u8]) -> bool {
        let alg: &dyn ring::signature::VerificationAlgorithm = match self.alg {
            Algorithm::Es256 => &ECDSA_P256_SHA256_ASN1,
            Algorithm::EdDsa => &ED25519,
        };
        UnparsedPublicKey::new(alg, &self.bytes)
            .verify(message, signature)
            .is_ok()
    }

    /// 验证恢复密钥的签名：ECDSA P-256 与 SHA-256，64 字节的 `r ‖ s`（WebCrypto 的输出）。
    pub(crate) fn verify_recovery(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        self.alg == Algorithm::Es256
            && UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &self.bytes)
                .verify(message, signature)
                .is_ok()
    }
}

impl fmt::Debug for AnchorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AnchorKey({:?}, {})", self.alg, encode_b64(&self.bytes))
    }
}

/// 入网公钥（Ed25519，浏览器生成）。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed25519PublicKey([u8; 32]);

impl Ed25519PublicKey {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        UnparsedPublicKey::new(&ED25519, &self.0)
            .verify(message, signature)
            .is_ok()
    }
}

/// X25519 公钥：组网公钥（WireGuard）或节点身份公钥（Noise）。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct X25519PublicKey([u8; 32]);

impl X25519PublicKey {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

macro_rules! b64_key_impls {
    ($name:ident) => {
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), encode_b64(&self.0))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&encode_b64(&self.0))
            }
        }

        impl std::str::FromStr for $name {
            type Err = EncodingError;

            fn from_str(s: &str) -> Result<Self, EncodingError> {
                decode_b64_fixed(s).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
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

b64_key_impls!(Ed25519PublicKey);
b64_key_impls!(X25519PublicKey);
