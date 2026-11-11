//! The Hub's HTTP interface (design/hub.md section 4, section 10): temporary SQLite, called through
//! the real router. A link code can be used only once; requests with no token or a wrong token are
//! rejected; pushed signed artifacts are verified against the trust anchor pinned at link time, and
//! forgeries, version rollback, same version with different content, and restoring a revoked
//! machine are all rejected as a whole.

mod common;

use axum::http::StatusCode;
use nett_proto::api::{LinkResponse, PushResponse, StatusResponse};

use common::*;

#[tokio::test]
async fn link_code_works_once() {
    let dir = temp_dir("link");
    let (_site, state) = site(&dir.join("site"));
    let app = nett_hub::api::router(hub(&dir, URL).await);
    let (status, _) = call(
        &app,
        "POST",
        "/api/v1/link",
        None,
        link_body([1; 32], &state),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a wrong secret");
    let (status, body) = call(
        &app,
        "POST",
        "/api/v1/link",
        None,
        link_body(SECRET, &state),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = serde_json::from_slice::<LinkResponse>(&body)
        .expect("token")
        .token;
    assert!(token.starts_with("nett_tok_"), "{token}");
    let (status, _) = call(
        &app,
        "POST",
        "/api/v1/link",
        None,
        link_body(SECRET, &state),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "used once already");
}

#[tokio::test]
async fn expired_link_code_is_refused() {
    let dir = temp_dir("expired");
    let (_site, state) = site(&dir.join("site"));
    let db = nett_hub::db::Db::open(&dir.join("hub.db"))
        .await
        .expect("database");
    db.set_link(URL, &nett_hub::sha256(&SECRET), nett_hub::now() - 1)
        .await
        .expect("set link");
    let hub = nett_hub::hub::Hub::load(
        db,
        x25519_dalek::StaticSecret::from([200; 32]),
        URL.into(),
        None,
    )
    .await
    .expect("hub");
    let app = nett_hub::api::router(hub);
    let (status, _) = call(
        &app,
        "POST",
        "/api/v1/link",
        None,
        link_body(SECRET, &state),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn site_routes_need_the_owner_token() {
    let (_hub, app, token, _site, state) = linked("token", URL).await;
    let body = serde_json::to_vec(&state).expect("json");
    for t in [
        None,
        Some("nett_tok_00_wrong"),
        Some(&token[..token.len() - 1]),
    ] {
        let (status, _) = call(&app, "PUT", "/api/v1/site", t, body.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{t:?}");
        let (status, _) = call(&app, "GET", "/api/v1/site/status", t, vec![]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{t:?}");
    }
    let (status, _) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn pushes_advance_and_status_lists_the_machines() {
    let (_hub, app, token, site, mut state) = linked("push", URL).await;
    let (status, body) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<PushResponse>(&body)
            .expect("reply")
            .generation,
        1
    );
    // Push the same version again: the generation does not change
    let (_, body) = push(&app, &token, &state).await;
    assert_eq!(
        serde_json::from_slice::<PushResponse>(&body)
            .expect("reply")
            .generation,
        1
    );

    state
        .allow(&["mac".into()], &["nas".into()], vec![tcp(22)], None)
        .expect("allow");
    resign(&site, &mut state);
    let (status, body) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        serde_json::from_slice::<PushResponse>(&body)
            .expect("reply")
            .generation,
        2
    );

    let (status, body) = call(&app, "GET", "/api/v1/site/status", Some(&token), vec![]).await;
    assert_eq!(status, StatusCode::OK);
    let reply: StatusResponse = serde_json::from_slice(&body).expect("status");
    assert_eq!(reply.generation, 2);
    let names: Vec<&str> = reply.machines.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, ["edge-vps", "mac", "nas"]);
    assert!(
        reply
            .machines
            .iter()
            .all(|m| !m.online && m.last_seen.is_none())
    );
}

#[tokio::test]
async fn forged_or_older_artifacts_are_refused_whole() {
    let (_hub, app, token, site, state) = linked("forged", URL).await;
    let (status, _) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::OK);

    // Two different modifications each signed as the same version
    let mut a = state.clone();
    a.allow(&["mac".into()], &["nas".into()], vec![tcp(22)], None)
        .expect("allow");
    resign(&site, &mut a);
    let mut b = state.clone();
    b.allow(&["nas".into()], &["mac".into()], vec![tcp(80)], None)
        .expect("allow");
    resign(&site, &mut b);
    assert_eq!(
        a.access_rules.as_ref().map(|r| r.version),
        b.access_rules.as_ref().map(|r| r.version)
    );
    let (status, _) = push(&app, &token, &a).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = push(&app, &token, &b).await;
    assert_eq!(status, StatusCode::CONFLICT, "same version, other content");
    assert!(String::from_utf8_lossy(&body).contains("access rules"));

    // Going back to an older version, or removing the signed access rules
    let mut c = a.clone();
    c.allow(&["edge-vps".into()], &["mac".into()], vec![tcp(443)], None)
        .expect("allow");
    resign(&site, &mut c);
    let (status, _) = push(&app, &token, &c).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = push(&app, &token, &a).await;
    assert_eq!(status, StatusCode::CONFLICT, "older version");
    assert!(String::from_utf8_lossy(&body).contains("does not follow"));
    let (status, body) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::CONFLICT, "access rules gone");
    assert!(String::from_utf8_lossy(&body).contains("gone"));
    let a = c;

    // The signature does not match
    let mut forged = a.clone();
    forged
        .allow(&["edge-vps".into()], &["nas".into()], vec![tcp(22)], None)
        .expect("allow");
    resign(&site, &mut forged);
    if let Some(rules) = forged.access_rules.as_mut()
        && let Some(byte) = rules.signed.payload.last_mut()
    {
        *byte ^= 1;
    }
    let (status, _) = push(&app, &token, &forged).await;
    assert_eq!(status, StatusCode::CONFLICT, "bad signature");

    // Another site's trust anchor
    let other = temp_dir("forged-other");
    let (_, foreign) = common::site(&other);
    let (status, body) = push(&app, &token, &foreign).await;
    assert_eq!(status, StatusCode::CONFLICT, "other trust anchors");
    assert!(String::from_utf8_lossy(&body).contains("trust anchors"));
}

#[tokio::test]
async fn removed_machines_stay_removed() {
    let (_hub, app, token, site, state) = linked("revoked", URL).await;
    let (status, _) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::OK);
    // Dropping a machine without leaving a revocation
    let mut gone = state.clone();
    gone.machines.remove(&name("nas"));
    let (status, _) = push(&app, &token, &gone).await;
    assert_eq!(status, StatusCode::CONFLICT);
    // Normal removal
    let mut removed = state.clone();
    removed.remove(&name("nas")).expect("remove");
    resign(&site, &mut removed);
    let (status, body) = push(&app, &token, &removed).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    // A revocation cannot be removed
    let mut back = removed.clone();
    back.revoked.clear();
    let (status, _) = push(&app, &token, &back).await;
    assert_eq!(status, StatusCode::CONFLICT);
}
