//! 新机器经 Hub 入网（design/hub.md 第 6 节）：用 token 中的入网私钥签准入证明，以本机的身份密钥连接 Hub，
//! 收到第一份期望状态之后核对它属于 token 所说的站点和节点。`sudo nett install <token>` 与实验工具都调用
//! 这里；写文件、安装服务由调用方完成。

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nett_core::id::NodeId;
use nett_mesh::config::DesiredMeshDoc;
use nett_mesh::key::PrivateKey;
use nett_proto::token::JoinToken;
use nett_trust::admission::{AdmissionProofDoc, AdmissionProofKind, PROOF_V1};
use nett_trust::anchors::TrustAnchors;
use nett_trust::signing::EnrollmentKeyPair;
use x25519_dalek::StaticSecret;

use crate::config::HubConfig;
use crate::session::{self, SessionError};

#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error("this token is for a machine that is already a member; it carries no enrollment key")]
    NotEnrollment,
    #[error(
        "the token expired; on the computer that holds the site, `nett site invite <name>` prints a new one"
    )]
    Expired,
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(
        "the Hub's desired state for this machine {0}; the Hub may not be the one in the token"
    )]
    Mismatch(String),
}

/// 入网的结果：Hub 的配置与第一份期望状态（组网进程的期望状态文件的内容）。
#[derive(Debug)]
pub struct Enrolled {
    pub config: HubConfig,
    pub desired: Vec<u8>,
}

/// 用 `dir` 中已有的身份密钥与组网密钥入网。重试时用同一对密钥：Hub 已经记下这台机器时按身份认出它。
pub async fn enroll(dir: &Path, token: &JoinToken, now: i64) -> Result<Enrolled, EnrollError> {
    let secret = token.enroll.as_ref().ok_or(EnrollError::NotEnrollment)?;
    if now > secret.expires_at {
        return Err(EnrollError::Expired);
    }
    let invalid = |e: &dyn std::fmt::Display| EnrollError::Invalid(e.to_string());
    let node_id: NodeId = token
        .node_id
        .parse()
        .map_err(|e| invalid(&format!("the token's node ID: {e}")))?;
    let identity = PrivateKey::load(&dir.join("identity.key")).map_err(|e| invalid(&e))?;
    let mesh = PrivateKey::load(&dir.join("mesh.key")).map_err(|e| invalid(&e))?;
    let proof = EnrollmentKeyPair::from_seed(&secret.key.0)
        .and_then(|key| {
            key.sign_proof(&AdmissionProofDoc {
                v: PROOF_V1,
                kind: AdmissionProofKind::AdmissionProof,
                node_id: node_id.clone(),
                identity_public_key: identity.public_key(),
                mesh_public_key: mesh.public_key(),
            })
        })
        .map_err(|e| invalid(&format!("signing the admission proof: {e}")))?;
    let proof = serde_json::to_vec(&proof).map_err(|e| invalid(&e))?;
    let config = HubConfig {
        url: token.url.clone(),
        hub_key: token.hub_key,
        node_id: token.node_id.clone(),
        tls_fingerprint: token.tls_fingerprint,
    };
    let desired =
        session::enroll(&config, &StaticSecret::from(*identity.as_bytes()), proof).await?;
    check(&desired, &node_id, &token.anchors)?;
    Ok(Enrolled { config, desired })
}

/// 期望状态是给这个节点的，信任锚清单的指纹与 token 中的相同（auth.md 第 8.2 节）：Hub 换不了这台机器
/// 认的站点。其余内容由组网进程用这份信任锚验证。
fn check(desired: &[u8], node_id: &NodeId, anchors: &str) -> Result<(), EnrollError> {
    let doc: DesiredMeshDoc = serde_json::from_slice(desired)
        .map_err(|e| EnrollError::Mismatch(format!("is not valid: {e}")))?;
    if doc.node_id != *node_id {
        return Err(EnrollError::Mismatch(format!(
            "is for node {}",
            doc.node_id
        )));
    }
    let fingerprint = TrustAnchors::from_doc(&doc.trust_anchors)
        .map_err(|e| EnrollError::Mismatch(format!("carries invalid trust anchors: {e}")))?
        .fingerprint();
    if URL_SAFE_NO_PAD.encode(fingerprint) != anchors {
        return Err(EnrollError::Mismatch(
            "carries other trust anchors than the token".into(),
        ));
    }
    Ok(())
}
