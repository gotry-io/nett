//! Generating signatures (`signing` feature): the signing tool signs with the recovery key, and a
//! new machine signs the admission proof at enrollment with the enrollment private key from the
//! token; lab tools and tests use them to construct material. The mesh process only verifies
//! signatures.

use nett_core::id::PasskeyId;
use ring::rand::{SecureRandom as _, SystemRandom};
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

/// Recovery key (ECDSA P-256), with the same signature format as WebCrypto (64-byte `r ‖ s`).
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

/// A simulated passkey: generates assertions in the WebAuthn format, used to test the verification
/// path.
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

    /// Generates a WebAuthn assertion; `flags` is the flags byte of `authenticatorData`.
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

/// Enrollment signing key (Ed25519). The private key is handed to the new machine as a 32-byte seed
/// (enrollment token, design/auth.md section 8.1).
pub struct EnrollmentKeyPair {
    seed: Zeroizing<[u8; 32]>,
    key: Ed25519KeyPair,
}

impl EnrollmentKeyPair {
    pub fn generate() -> Result<Self, SigningError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        SystemRandom::new().fill(seed.as_mut())?;
        Self::from_seed(&seed)
    }

    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, SigningError> {
        let key = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| SigningError::Crypto)?;
        Ok(Self {
            seed: Zeroizing::new(*seed),
            key,
        })
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(self.key.public_key().as_ref());
        Ed25519PublicKey::from_bytes(bytes)
    }

    pub fn sign_proof(&self, doc: &AdmissionProofDoc) -> Result<AdmissionProof, SigningError> {
        self.sign_bytes(doc.to_canonical()?)
    }

    /// Signs arbitrary bytes, used to construct malformed admission proofs (negative tests).
    pub fn sign_bytes(&self, payload: Vec<u8>) -> Result<AdmissionProof, SigningError> {
        let mut signature = [0u8; 64];
        signature.copy_from_slice(self.key.sign(&payload).as_ref());
        Ok(AdmissionProof { payload, signature })
    }
}
