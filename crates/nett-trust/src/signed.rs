//! 签名产物：签名载荷的字节加一个签名，用信任锚验证（design/auth.md 第 10.2、10.3、10.5 节）。

use nett_core::id::PasskeyId;
use serde::{Deserialize, Serialize};

use crate::anchors::TrustAnchors;
use crate::canonical::MAX_DOCUMENT_BYTES;
use crate::encoding::{Sha256Digest, b64, b64_fixed, decode_b64};
use crate::payload::{Payload, PayloadError};

/// `clientDataJSON` 与 `authenticatorData` 的上限；浏览器生成的通常只有几百字节。
const MAX_WEBAUTHN_FIELD_BYTES: usize = 4 * 1024;

/// `authenticatorData` 的固定头：RP ID 哈希（32）、标志（1）、签名计数器（4）。
const AUTH_DATA_HEADER_LEN: usize = 37;
const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;

/// 签名产物的传输形式。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPayload {
    #[serde(with = "b64")]
    pub payload: Vec<u8>,
    pub signature: PayloadSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PayloadSignature {
    Webauthn {
        passkey_id: PasskeyId,
        #[serde(with = "b64")]
        authenticator_data: Vec<u8>,
        #[serde(with = "b64")]
        client_data_json: Vec<u8>,
        #[serde(with = "b64")]
        signature: Vec<u8>,
    },
    Recovery {
        #[serde(with = "b64_fixed")]
        signature: [u8; 64],
    },
}

/// 签名者：信任锚中的哪一把钥匙。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signer {
    Passkey(PasskeyId),
    RecoveryKey,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("signed payload is {len} bytes, larger than the {MAX_DOCUMENT_BYTES}-byte limit")]
    TooLarge { len: usize },
    #[error("passkey {0} is not in the trust anchors")]
    UnknownPasskey(PasskeyId),
    #[error("webauthn: {0}")]
    WebAuthn(&'static str),
    #[error("signature does not verify against the trust anchors")]
    BadSignature,
    #[error(transparent)]
    Payload(#[from] PayloadError),
}

/// 签名已验证、格式已校验的载荷。
#[derive(Debug, Clone)]
pub struct VerifiedPayload {
    pub payload: Payload,
    pub signer: Signer,
}

impl SignedPayload {
    /// 先验证签名，再解析载荷：签名之前只做长度检查，不解析不可信的内容。
    pub fn verify(&self, anchors: &TrustAnchors) -> Result<VerifiedPayload, SignatureError> {
        if self.payload.len() > MAX_DOCUMENT_BYTES {
            return Err(SignatureError::TooLarge {
                len: self.payload.len(),
            });
        }
        let payload_hash = Sha256Digest::of(&self.payload);
        let signer = match &self.signature {
            PayloadSignature::Webauthn {
                passkey_id,
                authenticator_data,
                client_data_json,
                signature,
            } => {
                verify_webauthn(
                    anchors,
                    passkey_id,
                    authenticator_data,
                    client_data_json,
                    signature,
                    &payload_hash,
                )?;
                Signer::Passkey(passkey_id.clone())
            }
            PayloadSignature::Recovery { signature } => {
                if !anchors
                    .recovery_key()
                    .verify_recovery(&self.payload, signature)
                {
                    return Err(SignatureError::BadSignature);
                }
                Signer::RecoveryKey
            }
        };
        let payload = Payload::parse(&self.payload)?;
        Ok(VerifiedPayload { payload, signer })
    }
}

/// `clientDataJSON` 中验证方关心的字段；浏览器可能加入其他字段（WebAuthn 规定验证方忽略它们）。
#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    ty: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
}

/// design/auth.md 第 10.2 节的检查 1–5。过期时间和版本号由调用方按产物的种类检查（检查 6、7）。
fn verify_webauthn(
    anchors: &TrustAnchors,
    passkey_id: &PasskeyId,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
    payload_hash: &Sha256Digest,
) -> Result<(), SignatureError> {
    let key = anchors
        .passkey(passkey_id)
        .ok_or_else(|| SignatureError::UnknownPasskey(passkey_id.clone()))?;
    if client_data_json.len() > MAX_WEBAUTHN_FIELD_BYTES
        || authenticator_data.len() > MAX_WEBAUTHN_FIELD_BYTES
    {
        return Err(SignatureError::WebAuthn("assertion field too large"));
    }

    let client: ClientData = serde_json::from_slice(client_data_json)
        .map_err(|_| SignatureError::WebAuthn("clientDataJSON is not valid"))?;
    if client.ty != "webauthn.get" {
        return Err(SignatureError::WebAuthn(
            "clientDataJSON.type is not webauthn.get",
        ));
    }
    let challenge = decode_b64(&client.challenge)
        .map_err(|_| SignatureError::WebAuthn("challenge is not base64url"))?;
    if challenge != payload_hash.0 {
        return Err(SignatureError::WebAuthn(
            "challenge is not the payload hash",
        ));
    }
    if client.origin != anchors.origin() || client.cross_origin == Some(true) {
        return Err(SignatureError::WebAuthn(
            "origin does not match the console",
        ));
    }

    if authenticator_data.len() < AUTH_DATA_HEADER_LEN {
        return Err(SignatureError::WebAuthn("authenticatorData is too short"));
    }
    if authenticator_data[..32] != anchors.rp_id_hash().0 {
        return Err(SignatureError::WebAuthn("RP ID hash does not match"));
    }
    let flags = authenticator_data[32];
    if flags & FLAG_USER_PRESENT == 0 || flags & FLAG_USER_VERIFIED == 0 {
        return Err(SignatureError::WebAuthn(
            "user presence or verification flag not set",
        ));
    }

    let mut message = Vec::with_capacity(authenticator_data.len() + 32);
    message.extend_from_slice(authenticator_data);
    message.extend_from_slice(&Sha256Digest::of(client_data_json).0);
    if key.verify_webauthn(&message, signature) {
        Ok(())
    } else {
        Err(SignatureError::BadSignature)
    }
}
