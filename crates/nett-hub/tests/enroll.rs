//! A new machine joins via the Hub, a machine leaves on its own, and the public address learned by
//! the Hub (design/hub.md sections 4, 5, 6): the Hub terminates TLS itself on 127.0.0.1, and real
//! nett-node enrollment and leave sessions connect to it. A token can be used only once and cannot
//! be used after it expires; forged admission proofs and other machines' identities cannot enroll;
//! a push that has not yet fetched these events does not erase them, and after the site fetches
//! them both sides agree.

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

/// The new machine's two local keys, written in `dir` (the step `sudo nett install` does first).
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

/// Adds a machine `box` waiting to join to the site, and returns its node ID and enrollment key.
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

    // The new machine enrolls: the first desired state it gets is for it, and contains its own
    // admission material
    let dir = temp_dir("enroll-box");
    let mine = machine_keys(&dir);
    let enrolled = nett_node::join::enroll(&dir, &join, nett_hub::now())
        .await
        .expect("joined");
    let doc: DesiredMeshDoc = serde_json::from_slice(&enrolled.desired).expect("desired");
    assert_eq!(doc.node_id, box_id);
    assert_eq!(doc.members.len(), 4);
    assert_eq!(enrolled.config.node_id, box_id.as_str());

    // The Hub recorded its public key, and other members' desired state now contains it
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

    // The same token with a different machine: rejected
    let other = temp_dir("enroll-other");
    machine_keys(&other);
    let e = nett_node::join::enroll(&other, &join, nett_hub::now())
        .await
        .expect_err("refused");
    assert!(
        refused(&e).is_some_and(|m| m.contains("already joined")),
        "{e}"
    );
    // The same machine retries: recognized by identity, and gets the desired state as usual
    nett_node::join::enroll(&dir, &join, nett_hub::now())
        .await
        .expect("the same machine again");

    // Push again a site that has not yet fetched the enrollment: the Hub keeps the enrollment
    // result and does not change the generation
    assert_eq!(push(&app, &owner, &state).await.0, StatusCode::OK);
    let current = hub.site().await.expect("site");
    assert_eq!(current.generation, generation);
    assert_eq!(
        current.state.machine(&name("box")).expect("box").keys,
        Some(mine)
    );

    // The site fetches it, verifies it itself and records it; after one more push the Hub no longer
    // keeps it
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

    // Expired: this machine rejects it first, and the Hub also rejects it when this machine's check
    // is bypassed
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

    // Once not expired: a proof signed by another enrollment key, and a proof signed for another
    // identity public key, are both rejected
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

    // The Hub removes it on the spot: other members no longer have it, and the revocation arrives
    // first
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
    // It can no longer connect
    let e = nett_node::session::leave(&config, &identity(3))
        .await
        .expect_err("refused");
    assert!(matches!(e, SessionError::Refused { .. }), "{e}");

    // A site push that has not yet been fetched: still without it
    assert_eq!(push(&app, &owner, &state).await.0, StatusCode::OK);
    assert!(hub.site().await.expect("site").state.by_id(&nas).is_none());
    // After the site fetches it, remove it and re-sign the access rules with a new version (narrow)
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
    // A public machine with no address written
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
        ..Learned::default()
    };
    // The address is learned when the machine connects
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
    // The same address does not change the generation
    let generation = current.generation;
    hub.learned(&vps, learned, nett_hub::now())
        .await
        .expect("again");
    assert_eq!(hub.site().await.expect("site").generation, generation);
    // After the site fetches it, it is recorded; an explicitly written address takes precedence
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
