//! 生成签名，只用于实验工具和测试（`signing` 特性）。正式构建中的节点只验证签名：
//! 用户的签名在用户的设备上生成，入网私钥由浏览器生成。

use nett_core::id::PasskeyId;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair,
    KeyPair as _,
};
use zeroize::Zeroizing;

use crate::admission::{AdmissionProof, AdmissionProofDoc};
use crate::anchors::{PasskeyDoc, RecoveryKeyDoc};
use crate::canonical::CanonicalError;
use crate::encoding::{Sha256Digest, encode_b64};
use crate::keys::{Algorithm, Ed25519PublicKey};
use crate::signed::{PayloadSignature, SignedPayload};

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("key generation or signing failed")]
    Crypto,
    #[error("private key is not valid PKCS#8 for this algorithm")]
    KeyFormat,
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
}

impl From<ring::error::Unspecified> for SigningError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self::Crypto
    }
}

/// 恢复密钥（ECDSA P-256），签名格式与 WebCrypto 相同（64 字节的 `r ‖ s`）。
pub struct RecoveryKeyPair {
    pkcs8: Zeroizing<Vec<u8>>,
    key: EcdsaKeyPair,
}

impl RecoveryKeyPair {
    pub fn generate() -> Result<Self, SigningError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)?;
        Self::from_pkcs8(pkcs8.as_ref())
    }

    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, SigningError> {
        let key = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8,
            &SystemRandom::new(),
        )
        .map_err(|_| SigningError::KeyFormat)?;
        Ok(Self {
            pkcs8: Zeroizing::new(pkcs8.to_vec()),
            key,
        })
    }

    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    pub fn doc(&self) -> RecoveryKeyDoc {
        RecoveryKeyDoc {
            alg: Algorithm::Es256,
            public_key: encode_b64(self.key.public_key().as_ref()),
        }
    }

    pub fn sign(&self, payload: Vec<u8>) -> Result<SignedPayload, SigningError> {
        let sig = self.key.sign(&SystemRandom::new(), &payload)?;
        let signature: [u8; 64] = sig.as_ref().try_into().map_err(|_| SigningError::Crypto)?;
        Ok(SignedPayload {
            payload,
            signature: PayloadSignature::Recovery { signature },
        })
    }
}

enum PasskeyInner {
    Es256(EcdsaKeyPair),
    EdDsa(Ed25519KeyPair),
}

/// 模拟的 passkey：按 WebAuthn 的格式生成断言，用于测试验证路径。
pub struct PasskeyKeyPair {
    id: PasskeyId,
    inner: PasskeyInner,
}

impl PasskeyKeyPair {
    pub fn generate(id: PasskeyId, alg: Algorithm) -> Result<Self, SigningError> {
        let rng = SystemRandom::new();
        let inner = match alg {
            Algorithm::Es256 => {
                let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)?;
                PasskeyInner::Es256(
                    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                        .map_err(|_| SigningError::KeyFormat)?,
                )
            }
            Algorithm::EdDsa => {
                let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)?;
                PasskeyInner::EdDsa(
                    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
                        .map_err(|_| SigningError::KeyFormat)?,
                )
            }
        };
        Ok(Self { id, inner })
    }

    pub fn doc(&self) -> PasskeyDoc {
        let (alg, public_key) = match &self.inner {
            PasskeyInner::Es256(k) => (Algorithm::Es256, k.public_key().as_ref().to_vec()),
            PasskeyInner::EdDsa(k) => (Algorithm::EdDsa, k.public_key().as_ref().to_vec()),
        };
        PasskeyDoc {
            id: self.id.clone(),
            alg,
            public_key: encode_b64(&public_key),
        }
    }

    /// 生成一份 WebAuthn 断言，`flags` 为 `authenticatorData` 的标志字节。
    pub fn sign(
        &self,
        payload: Vec<u8>,
        rp_id: &str,
        origin: &str,
        flags: u8,
    ) -> Result<SignedPayload, SigningError> {
        let mut authenticator_data = Sha256Digest::of(rp_id.as_bytes()).0.to_vec();
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&0u32.to_be_bytes());
        let challenge = encode_b64(&Sha256Digest::of(&payload).0);
        let client = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false,
        });
        let client_data_json =
            serde_json::to_vec(&client).map_err(|e| CanonicalError::Syntax(e.to_string()))?;
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&Sha256Digest::of(&client_data_json).0);
        let signature = match &self.inner {
            PasskeyInner::Es256(k) => k.sign(&SystemRandom::new(), &message)?.as_ref().to_vec(),
            PasskeyInner::EdDsa(k) => k.sign(&message).as_ref().to_vec(),
        };
        Ok(SignedPayload {
            payload,
            signature: PayloadSignature::Webauthn {
                passkey_id: self.id.clone(),
                authenticator_data,
                client_data_json,
                signature,
            },
        })
    }
}

/// 入网签名密钥（Ed25519）。
pub struct EnrollmentKeyPair {
    pkcs8: Zeroizing<Vec<u8>>,
    key: Ed25519KeyPair,
}

impl EnrollmentKeyPair {
    pub fn generate() -> Result<Self, SigningError> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())?;
        Self::from_pkcs8(pkcs8.as_ref())
    }

    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, SigningError> {
        let key = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| SigningError::KeyFormat)?;
        Ok(Self {
            pkcs8: Zeroizing::new(pkcs8.to_vec()),
            key,
        })
    }

    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(self.key.public_key().as_ref());
        Ed25519PublicKey::from_bytes(bytes)
    }

    pub fn sign_proof(&self, doc: &AdmissionProofDoc) -> Result<AdmissionProof, SigningError> {
        self.sign_bytes(doc.to_canonical()?)
    }

    /// 对任意字节签名，用于构造格式错误的准入证明（测试反例）。
    pub fn sign_bytes(&self, payload: Vec<u8>) -> Result<AdmissionProof, SigningError> {
        let mut signature = [0u8; 64];
        signature.copy_from_slice(self.key.sign(&payload).as_ref());
        Ok(AdmissionProof { payload, signature })
    }
}
