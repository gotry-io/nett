//! Machine events (design/hub.md section 8): kept 100 per machine for 30 days, recorded when a
//! machine connects and acknowledges, and served newest first through the API.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use nett_hub::db::{Db, EVENTS_KEPT_SECS, EVENTS_PER_NODE};
use nett_proto::api::Event;

use common::*;

#[tokio::test]
async fn events_are_bounded_per_machine_and_in_time() {
    let dir = temp_dir("events-retention");
    let db = Db::open(&dir.join("hub.db")).await.expect("db");
    let now = nett_hub::now();
    // an old event of another machine expires when anything is recorded
    db.add_event("node_other", now - EVENTS_KEPT_SECS - 1, "connected", "old")
        .await
        .expect("old");
    for i in 0..EVENTS_PER_NODE + 5 {
        db.add_event("node_a", now, "config", &format!("{i}"))
            .await
            .expect("event");
    }
    let events = db.events("node_a", 1000).await.expect("events");
    assert_eq!(events.len(), EVENTS_PER_NODE as usize);
    assert_eq!(
        events[0].detail,
        format!("{}", EVENTS_PER_NODE + 4),
        "newest first"
    );
    assert!(
        db.events("node_other", 10)
            .await
            .expect("events")
            .is_empty()
    );
}

#[tokio::test]
async fn a_connected_machine_has_events_through_the_api() {
    let (hub, app, token, _site, state) = linked("events-api", "https://127.0.0.1").await;
    assert_eq!(push(&app, &token, &state).await.0, StatusCode::OK);
    let url = serve(hub.clone()).await;
    let mac = state
        .machine(&name("mac"))
        .expect("mac")
        .node_id
        .to_string();
    let dir = temp_dir("events-api-mac");
    let config = nett_node::config::HubConfig {
        url,
        hub_key: hub_key(),
        node_id: mac.clone(),
        tls_fingerprint: Some(nett_proto::token::Bytes32(cert_fingerprint())),
    };
    let node = nett_node::session::Node {
        config,
        identity: identity(2),
        desired: dir.join("desired.json"),
        socket: dir.join("mesh.sock"),
        upgrader: None,
        services: None,
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(nett_node::session::run(node, async move {
        stopped.await.ok();
    }));
    let mut kinds = Vec::new();
    for _ in 0..100 {
        let (status, body) = call(
            &app,
            "GET",
            &format!("/api/v1/site/events?node={mac}&limit=5"),
            Some(&token),
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let events: Vec<Event> = serde_json::from_slice(&body).expect("events");
        kinds = events.into_iter().map(|e| e.kind).collect();
        if kinds.contains(&"config".to_owned()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(kinds.contains(&"connected".to_owned()), "{kinds:?}");
    assert!(kinds.contains(&"config".to_owned()), "{kinds:?}");
    // the token is required, and the node must be a node ID
    let (status, _) = call(
        &app,
        "GET",
        &format!("/api/v1/site/events?node={mac}"),
        None,
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(
        &app,
        "GET",
        "/api/v1/site/events?node=x';--",
        Some(&token),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    stop.send(()).ok();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("stops")
        .expect("no panic");
}
