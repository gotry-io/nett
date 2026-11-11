//! 新机器经 Hub 入网、机器自行退出、Hub 得知的公网地址（design/hub.md 第 4、5、6 节）：Hub 在 127.0.0.1 上
//! 自己终止 TLS，真实的 nett-node 入网与退出会话连上来。token 只能用一次、过期了不能用，伪造的准入证明和
//! 别人的身份都入不了网；还没有取回这些事的推送不会把它们抹掉，站点取回之后两边一致。

mod common;

use std::path::Path;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nett_core::id::NodeId;
use nett_mesh::config::{Candidate, DesiredMeshDoc};
use nett_mesh::key::PrivateKey;
use nett_node::config::HubConfig;
use nett_node::join::EnrollError;
use nett_node::session::SessionError;
use nett_proto::token::{Bytes32, Enroll, JoinToken, Secret32};
use nett_proto::v1::ErrorCode;
use nett_site::dir::new_node_id;
use nett_site::ops::MachineOptions;
use nett_site::state::{AddressSource, Learned, LearnedIp, NodeKeys, State};
use nett_site::updates::Updates;
use nett_trust::admission::{AdmissionProofDoc, AdmissionProofKind, PROOF_V1};
use nett_trust::anchors::TrustAnchors;
use nett_trust::signing::EnrollmentKeyPair;
use x25519_dalek::StaticSecret;

use common::*;

/// 新机器本机的两把密钥，写在 `dir` 中（`sudo nett install` 先做的那一步）。
fn machine_keys(dir: &Path) -> NodeKeys {
    let (mesh, identity) = (
        PrivateKey::generate().expect("mesh key"),
        PrivateKey::generate().expect("identity key"),
    );
    mesh.save_new(&dir.join("mesh.key")).expect("save");
    identity.save_new(&dir.join("identity.key")).expect("save");
    NodeKeys {
        mesh: mesh.public_key(),
        identity: identity.public_key(),
    }
}

fn anchors(state: &State) -> String {
    URL_SAFE_NO_PAD.encode(
        TrustAnchors::from_doc(&state.trust_anchors)
            .expect("anchors")
            .fingerprint(),
    )
}

/// 站点中加一台等待入网的机器 `box`，返回它的节点 ID 与入网密钥。
fn pending(
    site: &nett_site::dir::SiteDir,
    state: &mut State,
    expires_at: i64,
) -> (NodeId, EnrollmentKeyPair) {
    let key = EnrollmentKeyPair::generate().expect("enrollment key");
    let id = new_node_id().expect("id");
    state
        .add(name("box"), MachineOptions::default(), id.clone())
        .expect("add");
    state
        .await_enrollment(&name("box"), key.public_key(), expires_at)
        .expect("await");
    resign(site, state);
    (id, key)
}

fn token(
    url: &str,
    state: &State,
    node: &NodeId,
    key: &EnrollmentKeyPair,
    expires_at: i64,
) -> JoinToken {
    JoinToken {
        url: url.to_owned(),
        hub_key: hub_key(),
        node_id: node.to_string(),
        anchors: anchors(state),
        tls_fingerprint: Some(Bytes32(cert_fingerprint())),
        enroll: Some(Enroll {
            key: Secret32::new(*key.seed()),
            expires_at,
        }),
    }
}

fn refused(e: &EnrollError) -> Option<&str> {
    match e {
        EnrollError::Session(SessionError::Refused {
            code: ErrorCode::EnrollmentRefused,
            message,
        }) => Some(message),
        _ => None,
    }
}

#[tokio::test]
async fn a_new_machine_joins_through_the_hub_once() {
    let (hub, app, owner, site, mut state) = linked("enroll", URL).await;
    let expires = nett_hub::now() + 1800;
    let (box_id, key) = pending(&site, &mut state, expires);
    assert_eq!(push(&app, &owner, &state).await.0, StatusCode::OK);
    let url = serve(hub.clone()).await;
    let join = token(&url, &state, &box_id, &key, expires);

    // 新机器入网：拿到的第一份期望状态是给它的，其中有它自己的准入材料
    let dir = temp_dir("enroll-box");
    let mine = machine_keys(&dir);
    let enrolled = nett_node::join::enroll(&dir, &join, nett_hub::now())
        .await
        .expect("joined");
    let doc: DesiredMeshDoc = serde_json::from_slice(&enrolled.desired).expect("desired");
    assert_eq!(doc.node_id, box_id);
    assert_eq!(doc.members.len(), 4);
    assert_eq!(enrolled.config.node_id, box_id.as_str());

    // Hub 记下了它的公钥，其他成员的期望状态中有了它
    let current = hub.site().await.expect("site");
    assert_eq!(
        current.state.machine(&name("box")).expect("box").keys,
        Some(mine)
    );
    let mac = current
        .state
        .machine(&name("mac"))
        .expect("mac")
        .node_id
        .clone();
    let mac_doc: DesiredMeshDoc =
        serde_json::from_slice(&current.desired[&mac]).expect("mac desired");
    assert_eq!(mac_doc.members.len(), 4);
    let generation = current.generation;

    // 同一个 token 换一台机器：拒绝
    let other = temp_dir("enroll-other");
    machine_keys(&other);
    let e = nett_node::join::enroll(&other, &join, nett_hub::now())
        .await
        .expect_err("refused");
    assert!(
        refused(&e).is_some_and(|m| m.contains("already joined")),
        "{e}"
    );
    // 同一台机器重试：按身份认出，照常拿到期望状态
    nett_node::join::enroll(&dir, &join, nett_hub::now())
        .await
        .expect("the same machine again");

    // 还没有取回入网的站点再推一次：Hub 保留入网的结果，不换代数
    assert_eq!(push(&app, &owner, &state).await.0, StatusCode::OK);
    let current = hub.site().await.expect("site");
    assert_eq!(current.generation, generation);
    assert_eq!(
        current.state.machine(&name("box")).expect("box").keys,
        Some(mine)
    );

    // 站点取回、自己验证后记下；再推一次之后 Hub 不再保留这件事
    let (status, body) = call(&app, "GET", "/api/v1/site/updates", Some(&owner), vec![]).await;
    assert_eq!(status, StatusCode::OK);
    let updates: Updates = serde_json::from_slice(&body).expect("updates");
    assert_eq!(updates.enrolled.len(), 1);
    let applied = updates.apply(&mut state).expect("recorded");
    assert_eq!(applied.joined, vec![name("box")]);
    resign(&site, &mut state);
    assert_eq!(
        state
            .machine(&name("box"))
            .expect("box")
            .policy
            .as_ref()
            .map(|p| p.version),
        Some(1),
        "the policy signed for the token stays"
    );
    assert_eq!(push(&app, &owner, &state).await.0, StatusCode::OK);
    assert!(hub.db.updates().await.expect("updates").is_empty());
    assert_eq!(hub.site().await.expect("site").state, state);
}

#[tokio::test]
async fn expired_forged_and_borrowed_enrollments_are_refused() {
    let (hub, app, owner, site, mut state) = linked("enroll-refused", URL).await;
    let expired = nett_hub::now() - 10;
    let (box_id, key) = pending(&site, &mut state, expired);
    assert_eq!(push(&app, &owner, &state).await.0, StatusCode::OK);
    let url = serve(hub.clone()).await;
    let config = HubConfig {
        url: url.clone(),
        hub_key: hub_key(),
        node_id: box_id.to_string(),
        tls_fingerprint: Some(Bytes32(cert_fingerprint())),
    };
    let identity = StaticSecret::from([77; 32]);
    let identity_public = nett_trust::keys::X25519PublicKey::from_bytes(
        x25519_dalek::PublicKey::from(&identity).to_bytes(),
    );
    let proof = |key: &EnrollmentKeyPair, identity_key| {
        serde_json::to_vec(
            &key.sign_proof(&AdmissionProofDoc {
                v: PROOF_V1,
                kind: AdmissionProofKind::AdmissionProof,
                node_id: box_id.clone(),
                identity_public_key: identity_key,
                mesh_public_key: nett_trust::keys::X25519PublicKey::from_bytes([9; 32]),
            })
            .expect("proof"),
        )
        .expect("json")
    };
    let attempt = |proof: Vec<u8>| {
        let (config, identity) = (config.clone(), identity.clone());
        async move {
            match nett_node::session::enroll(&config, &identity, proof).await {
                Err(SessionError::Refused {
                    code: ErrorCode::EnrollmentRefused,
                    message,
                }) => message,
                other => panic!("expected a refusal, got {:?}", other.map(|_| ())),
            }
        }
    };

    // 过期：本机先拒绝，绕过本机的检查时 Hub 也拒绝
    let join = token(&url, &state, &box_id, &key, expired);
    let dir = temp_dir("enroll-expired");
    machine_keys(&dir);
    assert!(matches!(
        nett_node::join::enroll(&dir, &join, nett_hub::now()).await,
        Err(EnrollError::Expired)
    ));
    assert!(
        attempt(proof(&key, identity_public))
            .await
            .contains("expired")
    );

    // 没过期之后：别的入网密钥签的证明、为另一把身份公钥签的证明都拒绝
    state
        .await_enrollment(&name("box"), key.public_key(), nett_hub::now() + 1800)
        .expect("await");
    resign(&site, &mut state);
    assert_eq!(push(&app, &owner, &state).await.0, StatusCode::OK);
    let stranger = EnrollmentKeyPair::generate().expect("key");
    let m = attempt(proof(&stranger, identity_public)).await;
    assert!(m.contains("enrollment key"), "{m}");
    let m = attempt(proof(
        &key,
        nett_trust::keys::X25519PublicKey::from_bytes([5; 32]),
    ))
    .await;
    assert!(m.contains("identity key"), "{m}");
    assert!(
        hub.site()
            .await
            .expect("site")
            .state
            .machine(&name("box"))
            .expect("box")
            .keys
            .is_none()
    );
    assert!(hub.db.updates().await.expect("updates").is_empty());
}

#[tokio::test]
async fn a_machine_that_leaves_is_removed_from_every_member() {
    let (hub, app, owner, site, mut state) = linked("leave", URL).await;
    state
        .allow(&["mac".into()], &["nas".into()], vec![tcp(22)], None)
        .expect("allow");
    resign(&site, &mut state);
    assert_eq!(push(&app, &owner, &state).await.0, StatusCode::OK);
    let url = serve(hub.clone()).await;
    let nas = state.machine(&name("nas")).expect("nas").node_id.clone();
    let config = HubConfig {
        url,
        hub_key: hub_key(),
        node_id: nas.to_string(),
        tls_fingerprint: Some(Bytes32(cert_fingerprint())),
    };
    nett_node::session::leave(&config, &identity(3))
        .await
        .expect("left");

    // Hub 当场移除它：其他成员不再有它，撤销记录先到
    let current = hub.site().await.expect("site");
    assert!(current.state.by_id(&nas).is_none());
    assert!(current.state.revoked.iter().any(|r| r.node_id == nas));
    assert!(
        current.state.rules.is_empty(),
        "the rule naming it goes with it"
    );
    let mac = current
        .state
        .machine(&name("mac"))
        .expect("mac")
        .node_id
        .clone();
    let mac_doc: DesiredMeshDoc = serde_json::from_slice(&current.desired[&mac]).expect("desired");
    assert_eq!(mac_doc.members.len(), 2, "edge-vps and mac");
    assert_eq!(mac_doc.revocations.len(), 1);
    // 它再也连不上
    let e = nett_node::session::leave(&config, &identity(3))
        .await
        .expect_err("refused");
    assert!(matches!(e, SessionError::Refused { .. }), "{e}");

    // 还没有取回的站点推送：仍然没有它
    assert_eq!(push(&app, &owner, &state).await.0, StatusCode::OK);
    assert!(hub.site().await.expect("site").state.by_id(&nas).is_none());
    // 站点取回之后移除它、以新的版本重签访问规则（收窄）
    let (_, body) = call(&app, "GET", "/api/v1/site/updates", Some(&owner), vec![]).await;
    let updates: Updates = serde_json::from_slice(&body).expect("updates");
    assert_eq!(updates.left, vec![nas.clone()]);
    let rules_before = state.access_rules.as_ref().map(|r| r.version);
    assert_eq!(
        updates.apply(&mut state).expect("applied").left,
        vec![name("nas")]
    );
    resign(&site, &mut state);
    assert!(state.access_rules.as_ref().map(|r| r.version) > rules_before);
    assert_eq!(push(&app, &owner, &state).await.0, StatusCode::OK);
    assert!(hub.db.updates().await.expect("updates").is_empty());
}

#[tokio::test]
async fn learned_public_addresses_reach_the_other_members() {
    let (hub, app, owner, site, mut state) = linked("learned", URL).await;
    // 一台没有写明地址的 public 机器
    state
        .add(
            name("vps"),
            MachineOptions {
                public: true,
                keys: Some(keys(4)),
                ..MachineOptions::default()
            },
            new_node_id().expect("id"),
        )
        .expect("add");
    resign(&site, &mut state);
    assert_eq!(push(&app, &owner, &state).await.0, StatusCode::OK);
    let vps = state.machine(&name("vps")).expect("vps").node_id.clone();
    let mac = state.machine(&name("mac")).expect("mac").node_id.clone();
    let candidates = |hub_site: &nett_hub::hub::Site| {
        let doc: DesiredMeshDoc = serde_json::from_slice(&hub_site.desired[&mac]).expect("desired");
        doc.paths
            .into_iter()
            .find(|p| p.peer == vps)
            .map(|p| p.candidates)
            .unwrap_or_default()
    };
    assert!(candidates(&hub.site().await.expect("site")).is_empty());

    let learned = Learned {
        ipv4: Some(LearnedIp {
            ip: "198.51.100.7".parse().expect("ip"),
            from: AddressSource::Hub,
        }),
        ipv6: None,
    };
    // 地址在机器连上时得知
    hub.db
        .seen(vps.as_str(), nett_hub::now(), "0.0.0")
        .await
        .expect("seen");
    hub.learned(&vps, learned, nett_hub::now())
        .await
        .expect("learned");
    let current = hub.site().await.expect("site");
    assert_eq!(
        candidates(&current),
        vec![Candidate::Direct {
            endpoint: "198.51.100.7:41820".parse().expect("endpoint")
        }]
    );
    // 同样的地址不换代数
    let generation = current.generation;
    hub.learned(&vps, learned, nett_hub::now())
        .await
        .expect("again");
    assert_eq!(hub.site().await.expect("site").generation, generation);
    // 站点取回之后记下；写明的地址优先
    let (_, body) = call(&app, "GET", "/api/v1/site/updates", Some(&owner), vec![]).await;
    let updates: Updates = serde_json::from_slice(&body).expect("updates");
    updates.apply(&mut state).expect("applied");
    assert_eq!(state.machine(&name("vps")).expect("vps").learned, learned);
    state
        .set(
            &name("vps"),
            nett_site::ops::MachineChange {
                ipv4: Some(Some("203.0.113.30".parse().expect("ip"))),
                ..Default::default()
            },
        )
        .expect("set");
    resign(&site, &mut state);
    assert_eq!(push(&app, &owner, &state).await.0, StatusCode::OK);
    assert_eq!(
        candidates(&hub.site().await.expect("site")),
        vec![Candidate::Direct {
            endpoint: "203.0.113.30:41820".parse().expect("endpoint")
        }]
    );
}
