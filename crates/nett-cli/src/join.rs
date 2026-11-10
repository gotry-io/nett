//! `sudo nett install <token>` 中两个平台共用的一步（design/hub.md 第 3.5、7 节）：核对接入 token 与本机，写入
//! Hub 的配置。H1 只接入已是成员的机器：它沿用自己的密钥、地址和产物版本，用身份密钥连接 Hub。
//!
//! token 中的节点 ID 必须是本机的；信任锚清单的指纹必须与本机固定的信任锚相同（先看组网进程的信任存储，
//! 还没有时看期望状态文件）。所以一个被攻破的 Hub 发出的 token 换不了这台机器认的站点；换到另一个 Hub 也只能
//! 在本机以 root 执行（第 8.1 节）。

use std::path::Path;

use anyhow::{Context as _, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nett_core::id::NodeId;
use nett_mesh::config::{DesiredMeshDoc, MAX_DESIRED_BYTES, read_bounded};
use nett_mesh::store::{Saved, TRUST_FILE};
use nett_node::config::HubConfig;
use nett_proto::token::JoinToken;
use nett_trust::anchors::{TrustAnchors, TrustAnchorsDoc};

/// 写入 Hub 配置的结果。
#[derive(Debug, PartialEq, Eq)]
pub enum Joined {
    New(String),
    Switched { from: String, to: String },
    Unchanged,
}

/// 本机的节点 ID 与固定的信任锚。
fn membership(dir: &Path, state_dir: &Path) -> anyhow::Result<Option<(NodeId, TrustAnchorsDoc)>> {
    let trust = state_dir.join(TRUST_FILE);
    if let Some(bytes) = read_bounded(&trust, MAX_DESIRED_BYTES)
        .with_context(|| format!("reading {}", trust.display()))?
    {
        let saved: Saved = serde_json::from_slice(&bytes)
            .with_context(|| format!("{} is not valid", trust.display()))?;
        return Ok(Some((saved.node_id, saved.trust_anchors)));
    }
    let desired = dir.join("desired.json");
    let Some(bytes) = crate::site::read_desired(&desired)? else {
        return Ok(None);
    };
    let doc: DesiredMeshDoc = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not valid", desired.display()))?;
    Ok(Some((doc.node_id, doc.trust_anchors)))
}

/// 核对 `token` 并写入 `dir` 中的 Hub 配置。
pub fn join(dir: &Path, state_dir: &Path, token: &str) -> anyhow::Result<Joined> {
    let token = JoinToken::decode(token)?;
    if !dir.join("identity.key").exists() {
        bail!(
            "this machine has no identity key in {}; joining new machines through the Hub comes later, \
             for now add it with `nett site add --keys`",
            dir.display()
        );
    }
    let Some((node_id, anchors)) = membership(dir, state_dir)? else {
        bail!(
            "this machine is not a member of the site yet (no desired state in {}); joining new machines \
             through the Hub comes later",
            dir.display()
        );
    };
    if node_id.as_str() != token.node_id {
        bail!(
            "the token is for node {}, but this machine is {node_id}; run `nett site invite` with this \
             machine's name",
            token.node_id
        );
    }
    let fingerprint = TrustAnchors::from_doc(&anchors)
        .map_err(|e| anyhow::anyhow!("this machine's trust anchors: {e}"))?
        .fingerprint();
    if URL_SAFE_NO_PAD.encode(fingerprint) != token.anchors {
        bail!(
            "the token belongs to another site: its trust anchors differ from the ones this machine \
             holds. To move this machine to that site, `nett leave` first"
        );
    }
    let config = HubConfig {
        url: token.url,
        hub_key: token.hub_key,
        node_id: token.node_id,
        tls_fingerprint: token.tls_fingerprint,
    };
    let old = HubConfig::load(dir).map_err(anyhow::Error::msg)?;
    if old.as_ref() == Some(&config) {
        return Ok(Joined::Unchanged);
    }
    config.save(dir).map_err(anyhow::Error::msg)?;
    Ok(match old {
        Some(old) => Joined::Switched {
            from: old.url,
            to: config.url,
        },
        None => Joined::New(config.url),
    })
}

#[cfg(test)]
mod tests {
    use nett_proto::token::Bytes32;
    use nett_site::dir::{SiteDir, new_node_id};
    use nett_site::ops::MachineOptions;
    use nett_site::sign::sign;
    use nett_site::state::NodeKeys;
    use nett_trust::encoding::Timestamp;
    use nett_trust::keys::X25519PublicKey;

    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("nett-cli-join-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    /// 一个站点中的一台机器：返回它的期望状态与站点的信任锚。
    fn member(site_dir: &Path) -> (DesiredMeshDoc, TrustAnchorsDoc) {
        SiteDir::init(site_dir, "https://nett.invalid").expect("init");
        let site = SiteDir::open(site_dir).expect("open");
        let mut state = site.load().expect("load");
        state
            .add(
                "nas".parse().expect("name"),
                MachineOptions {
                    keys: Some(NodeKeys {
                        mesh: X25519PublicKey::from_bytes([1; 32]),
                        identity: X25519PublicKey::from_bytes([2; 32]),
                    }),
                    ..MachineOptions::default()
                },
                new_node_id().expect("id"),
            )
            .expect("add");
        sign(
            &mut state,
            &site.recovery().expect("key"),
            Timestamp::now(),
            &[],
        )
        .expect("sign");
        let doc = nett_site::compose::desired(&state, &"nas".parse().expect("name"))
            .expect("compose")
            .expect("signed");
        (doc, state.trust_anchors)
    }

    fn token(node_id: &str, anchors: &TrustAnchorsDoc, url: &str) -> String {
        JoinToken {
            url: url.into(),
            hub_key: Bytes32([5; 32]),
            node_id: node_id.into(),
            anchors: URL_SAFE_NO_PAD.encode(
                TrustAnchors::from_doc(anchors)
                    .expect("anchors")
                    .fingerprint(),
            ),
            tls_fingerprint: None,
        }
        .encode()
    }

    #[test]
    fn tokens_must_match_this_machine_and_its_site() {
        let root = temp_dir("match");
        let (doc, anchors) = member(&root.join("site"));
        let (_, other_anchors) = member(&root.join("other-site"));
        let dir = root.join("etc");
        let state_dir = root.join("state");
        std::fs::create_dir_all(&dir).expect("dir");
        let id = doc.node_id.to_string();

        // 还没有身份密钥、还不是成员
        assert!(
            join(
                &dir,
                &state_dir,
                &token(&id, &anchors, "https://hub.example.com")
            )
            .is_err()
        );
        std::fs::write(dir.join("identity.key"), b"placeholder").expect("key");
        assert!(
            join(
                &dir,
                &state_dir,
                &token(&id, &anchors, "https://hub.example.com")
            )
            .is_err()
        );
        std::fs::write(
            dir.join("desired.json"),
            serde_json::to_vec(&doc).expect("json"),
        )
        .expect("desired");

        let other_id = new_node_id().expect("id").to_string();
        let e = join(
            &dir,
            &state_dir,
            &token(&other_id, &anchors, "https://hub.example.com"),
        )
        .expect_err("another node");
        assert!(e.to_string().contains("token is for node"), "{e}");
        let e = join(
            &dir,
            &state_dir,
            &token(&id, &other_anchors, "https://hub.example.com"),
        )
        .expect_err("another site");
        assert!(e.to_string().contains("another site"), "{e}");
        assert!(!dir.join("hub.json").exists());

        let t = token(&id, &anchors, "https://hub.example.com");
        assert_eq!(
            join(&dir, &state_dir, &t).expect("joined"),
            Joined::New("https://hub.example.com".into())
        );
        assert_eq!(
            join(&dir, &state_dir, &t).expect("again"),
            Joined::Unchanged
        );
        assert_eq!(
            join(
                &dir,
                &state_dir,
                &token(&id, &anchors, "https://hub2.example.com")
            )
            .expect("switched"),
            Joined::Switched {
                from: "https://hub.example.com".into(),
                to: "https://hub2.example.com".into()
            }
        );

        // 信任存储优先于期望状态文件：文件被换成另一个站点的，token 仍按固定的信任锚核对
        std::fs::create_dir_all(&state_dir).expect("state dir");
        let saved = Saved::new(doc.node_id.clone(), other_anchors.clone());
        std::fs::write(
            state_dir.join(TRUST_FILE),
            serde_json::to_vec(&saved).expect("json"),
        )
        .expect("trust");
        assert!(
            join(
                &dir,
                &state_dir,
                &token(&id, &anchors, "https://hub.example.com")
            )
            .is_err()
        );
    }
}
