//! End-to-end test of the node gateway (design/hub.md section 5): the Hub terminates TLS itself on
//! 127.0.0.1 (test certificate, verified by fingerprint), and a real nett-node session connects: it
//! receives the desired state, writes it as the desired state file and acknowledges; after the site
//! changes it receives a new one. Identities not in the site, mismatched node IDs and a wrong Hub
//! public key all fail to connect.

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::http::StatusCode;
use nett_hub::hub::Hub;
use nett_mesh::config::DesiredMeshDoc;
use nett_node::config::HubConfig;
use nett_node::session::{Exit, Node, SessionError};
use nett_proto::token::Bytes32;
use nett_proto::v1::ErrorCode;
use x25519_dalek::{PublicKey, StaticSecret};

use common::*;

fn node(url: &str, node_id: &str, identity: StaticSecret, dir: &Path) -> Node {
    Node {
        config: HubConfig {
            url: url.to_owned(),
            hub_key: Bytes32(PublicKey::from(&StaticSecret::from([200; 32])).to_bytes()),
            node_id: node_id.to_owned(),
            tls_fingerprint: Some(Bytes32(cert_fingerprint())),
        },
        identity,
        desired: dir.join("desired.json"),
        // No mesh process: after the desired state is written it is acknowledged as pending
        socket: dir.join("mesh.sock"),
        upgrader: None,
        link: std::sync::Arc::new(nett_node::fetch::HubLink::new()),
        services: None,
    }
}

/// Waits until the Hub records that this machine acknowledged `generation`.
async fn acked(hub: &Hub, node_id: &str, generation: i64) -> nett_hub::db::NodeRow {
    for _ in 0..200 {
        if let Some(row) = hub
            .db
            .nodes()
            .await
            .expect("nodes")
            .into_iter()
            .find(|r| r.node_id == node_id && r.applied_generation == Some(generation))
        {
            return row;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{node_id} did not acknowledge generation {generation}");
}

fn written(path: &PathBuf) -> DesiredMeshDoc {
    serde_json::from_slice(&std::fs::read(path).expect("desired state written")).expect("valid")
}

#[tokio::test]
async fn nodes_receive_apply_and_acknowledge_the_desired_state() {
    // The Hub's address must be fixed before linking: reserve a port first
    let (hub, app, token, site, mut state, _linked_tmp) =
        linked("gateway", "https://127.0.0.1").await;
    let (status, _) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::OK);
    let url = serve(hub.clone()).await;
    let (_dir_tmp, dir) = temp_dir("gateway-mac");
    let mac = state
        .machine(&name("mac"))
        .expect("mac")
        .node_id
        .to_string();

    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let agent = node(&url, &mac, identity(2), &dir);
    let task = tokio::spawn(nett_node::session::run(agent, async move {
        stopped.await.ok();
    }));

    let row = acked(&hub, &mac, 1).await;
    assert_eq!(
        row.ack_result.as_deref(),
        Some("pending"),
        "no mesh process here"
    );
    assert_eq!(row.platform.as_deref().map(|p| p.contains('-')), Some(true));
    let expected = nett_site::compose::desired(&state, &name("mac"))
        .expect("composed")
        .expect("signed");
    assert_eq!(written(&dir.join("desired.json")), expected);

    // Site changes: the Hub sends down a new one
    state
        .allow(&["mac".into()], &["nas".into()], vec![tcp(22)], None)
        .expect("allow");
    resign(&site, &mut state);
    let (status, _) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::OK);
    acked(&hub, &mac, 2).await;
    let doc = written(&dir.join("desired.json"));
    assert!(doc.access_rules.is_some());
    assert_eq!(
        doc,
        nett_site::compose::desired(&state, &name("mac"))
            .expect("composed")
            .expect("signed")
    );
    assert!(hub.online().await.iter().any(|n| n.as_str() == mac));

    stop.send(()).ok();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the node stops")
        .expect("no panic");
}

#[tokio::test]
async fn unknown_or_mismatched_machines_are_refused() {
    let (hub, app, token, _site, state, _linked_tmp) =
        linked("gateway-refuse", "https://127.0.0.1").await;
    let (status, _) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::OK);
    let url = serve(hub.clone()).await;
    let (_dir_tmp, dir) = temp_dir("gateway-refuse-node");
    let mac = state
        .machine(&name("mac"))
        .expect("mac")
        .node_id
        .to_string();
    let nas = state
        .machine(&name("nas"))
        .expect("nas")
        .node_id
        .to_string();

    let refused = |r: Result<nett_node::session::Exit, SessionError>| match r {
        Err(SessionError::Refused { code, .. }) => code,
        other => panic!("expected a refusal, got {other:?}"),
    };
    // An identity not in the site
    assert_eq!(
        refused(
            node(&url, &mac, identity(9), &dir)
                .session(
                    &mut None,
                    &nett_node::coord::Coordination::start(dir.join("mesh.sock"))
                )
                .await
        ),
        ErrorCode::NodeUnknown
    );
    // mac's identity impersonates nas
    assert_eq!(
        refused(
            node(&url, &nas, identity(2), &dir)
                .session(
                    &mut None,
                    &nett_node::coord::Coordination::start(dir.join("mesh.sock"))
                )
                .await
        ),
        ErrorCode::NodeUnknown
    );
    // Wrong Hub public key: the handshake fails
    let mut wrong = node(&url, &mac, identity(2), &dir);
    wrong.config.hub_key = Bytes32([7; 32]);
    assert!(matches!(
        wrong
            .session(
                &mut None,
                &nett_node::coord::Coordination::start(dir.join("mesh.sock"))
            )
            .await,
        Err(SessionError::Connect(_))
    ));
    // Wrong certificate fingerprint: TLS fails
    let mut wrong = node(&url, &mac, identity(2), &dir);
    wrong.config.tls_fingerprint = Some(Bytes32([1; 32]));
    assert!(matches!(
        wrong
            .session(
                &mut None,
                &nett_node::coord::Coordination::start(dir.join("mesh.sock"))
            )
            .await,
        Err(SessionError::Connect(_))
    ));
    assert!(!dir.join("desired.json").exists());
}

#[tokio::test]
async fn release_manifests_reach_connected_nodes_and_their_answers_are_kept() {
    let (hub, app, token, _site, state, _linked_tmp) =
        linked("gateway-release", "https://127.0.0.1").await;
    assert_eq!(push(&app, &token, &state).await.0, StatusCode::OK);
    let url = serve(hub.clone()).await;
    let (_dir_tmp, dir) = temp_dir("gateway-release-mac");
    let mac = state
        .machine(&name("mac"))
        .expect("mac")
        .node_id
        .to_string();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(nett_node::session::run(
        node(&url, &mac, identity(2), &dir),
        async move {
            stopped.await.ok();
        },
    ));
    acked(&hub, &mac, 1).await;

    // A manifest that does not parse is not taken
    assert!(
        hub.take_release(b"{\"version\": \"1\"}".to_vec())
            .await
            .is_err()
    );
    // A new release reaches the connected node as an increment; this one does not upgrade itself.
    // Nothing serves its program, so the Hub does not hold it and relays the manifest all the same
    let manifest = serde_json::json!({
        "version": "9.9.9",
        "programs": { "x86_64-unknown-linux-musl": {
            "url": "https://127.0.0.1:9/dl/nett-9.9.9-x86_64-unknown-linux-musl",
            "sha256": "ab".repeat(32),
            "minisig": include_str!("../../nett-trust/tests/data/SHA256SUMS.minisig"),
        }}
    });
    let missing = hub
        .take_release(manifest.to_string().into_bytes())
        .await
        .expect("manifest")
        .missing;
    assert_eq!(missing.len(), 1, "{missing:?}");
    let mut answer = None;
    for _ in 0..200 {
        answer = hub
            .db
            .nodes()
            .await
            .expect("nodes")
            .into_iter()
            .find(|r| r.node_id == mac && r.upgrade_result.is_some());
        if answer.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let row = answer.expect("the node answered the release");
    assert_eq!(row.upgrade_result.as_deref(), Some("rejected"));
    assert_eq!(
        row.upgrade_reason.as_deref(),
        Some("9.9.9 is available; this machine does not upgrade itself")
    );
    // The answer appears in the site status
    let (_, body) = call(&app, "GET", "/api/v1/site/status", Some(&token), vec![]).await;
    let status: nett_proto::api::StatusResponse = serde_json::from_slice(&body).expect("status");
    let m = status
        .machines
        .iter()
        .find(|m| m.name == "mac")
        .expect("mac");
    assert_eq!(m.upgrade_result.as_deref(), Some("rejected"));

    stop.send(()).ok();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the node stops")
        .expect("no panic");
}

/// The Hub holds the verified programs of the current release before it relays the manifest, and a
/// node fetches one over its session (ADR 0025); a program the Hub does not hold is answered with
/// `NOT_FOUND`, which leaves the node to fetch it from its URL
#[tokio::test]
async fn nodes_fetch_the_program_of_a_release_from_the_hub() {
    let (hub, app, token, _site, state, linked_tmp) =
        linked("gateway-program", "https://127.0.0.1").await;
    assert_eq!(push(&app, &token, &state).await.0, StatusCode::OK);
    let target = "x86_64-unknown-linux-musl";
    let version: nett_trust::release::Version = "9.9.9".parse().expect("version");
    // Several parts, the last one shorter
    let program: Vec<u8> = (0..150_000u32).map(|i| (i % 253) as u8).collect();
    // Already on disk, as after a restart of the Hub: checked again, not fetched
    let releases = linked_tmp.path().join(nett_hub::mirror::DIR);
    std::fs::create_dir_all(&releases).expect("releases");
    std::fs::write(releases.join(format!("nett-{version}-{target}")), &program).expect("program");
    std::fs::write(
        releases.join("nett-9.9.8-x86_64-unknown-linux-musl"),
        b"older",
    )
    .expect("older");
    let manifest = release_key().manifest(version, target, "https://127.0.0.1:9/nett", &program);
    let missing = hub.take_release(manifest).await.expect("manifest").missing;
    assert!(missing.is_empty(), "{missing:?}");
    // Only the current version is kept
    assert!(
        !releases
            .join("nett-9.9.8-x86_64-unknown-linux-musl")
            .exists()
    );

    let url = serve(hub.clone()).await;
    let (_dir_tmp, dir) = temp_dir("gateway-program-mac");
    let mac = state
        .machine(&name("mac"))
        .expect("mac")
        .node_id
        .to_string();
    let node = node(&url, &mac, identity(2), &dir);
    let link = node.link.clone();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(nett_node::session::run(node, async move {
        stopped.await.ok();
    }));
    acked(&hub, &mac, 1).await;

    let path = dir.join("nett.new");
    let mut file = nett_node::fetch::ProgramFile::create(&path).expect("file");
    nett_node::fetch::from_hub(&link, "9.9.9", target, &mut file)
        .await
        .expect("fetched from the Hub");
    file.finish().expect("written");
    assert_eq!(std::fs::read(&path).expect("read"), program);

    for (version, target) in [("9.9.8", target), ("9.9.9", "aarch64-apple-darwin")] {
        let mut file = nett_node::fetch::ProgramFile::create(&path).expect("file");
        let result = nett_node::fetch::from_hub(&link, version, target, &mut file).await;
        assert!(
            matches!(&result, Err(nett_node::fetch::FetchError::Unavailable(r)) if r.contains("does not hold")),
            "{result:?}"
        );
    }

    stop.send(()).ok();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the node stops")
        .expect("no panic");
}

/// A coordination with the mesh process replaced by channels the test holds: what the mesh process
/// would send, and what it would receive.
fn coordination() -> (
    nett_node::coord::Coordination,
    tokio::sync::mpsc::Sender<nett_mesh::coord::PathSwitchLine>,
    tokio::sync::mpsc::Receiver<nett_mesh::coord::PathSwitchLine>,
) {
    let (hub, _) = tokio::sync::watch::channel(false);
    let (to_mesh, received) = tokio::sync::mpsc::channel(16);
    let (sent, from_mesh) = tokio::sync::mpsc::channel(16);
    (
        nett_node::coord::Coordination {
            hub,
            to_mesh,
            from_mesh: tokio::sync::Mutex::new(from_mesh),
        },
        sent,
        received,
    )
}

/// Switch messages between two dial-only members pass through the Hub (design/mesh.md section 8.4),
/// and only between members the site connects.
#[tokio::test]
async fn switch_messages_pass_between_connected_members() {
    let (hub, app, token, site, mut state, _linked_tmp) =
        linked("gateway-switch", "https://127.0.0.1").await;
    state
        .allow(&["mac".into()], &["nas".into()], vec![tcp(22)], None)
        .expect("allow");
    resign(&site, &mut state);
    let (status, _) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::OK);
    let url = serve(hub.clone()).await;
    let id = |n: &str| state.machine(&name(n)).expect("machine").node_id.clone();
    let (mac, nas) = (id("mac"), id("nas"));

    let mut ends = Vec::new();
    for (n, key) in [("mac", 2), ("nas", 3)] {
        let (_dir_tmp, dir) = temp_dir(&format!("gateway-switch-{n}"));
        let agent = node(&url, id(n).as_str(), identity(key), &dir);
        let (coordination, sent, received) = coordination();
        tokio::spawn(async move { agent.session(&mut None, &coordination).await });
        ends.push((sent, received));
    }
    for _ in 0..200 {
        let online = hub.online().await;
        if online.contains(&mac) && online.contains(&nas) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (mac_sends, _) = &ends[0];
    mac_sends
        .send(nett_mesh::coord::PathSwitchLine {
            peer: nas.clone(),
            message: vec![1, 2, 3],
        })
        .await
        .expect("queued");
    let got = tokio::time::timeout(Duration::from_secs(5), ends[1].1.recv())
        .await
        .expect("delivered in time")
        .expect("open");
    assert_eq!(got.peer, mac, "the receiver learns who sent it");
    assert_eq!(got.message, vec![1, 2, 3]);

    // Without the rule there is no connection between the two: the Hub does not pass it on
    state.rules.clear();
    resign(&site, &mut state);
    let (status, _) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::OK);
    ends[0]
        .0
        .send(nett_mesh::coord::PathSwitchLine {
            peer: nas.clone(),
            message: vec![4],
        })
        .await
        .expect("queued");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), ends[1].1.recv())
            .await
            .is_err(),
        "not passed on between members the site does not connect"
    );
}

/// A stopping Hub says goodbye to each connected machine and records when it was last seen and the
/// disconnection before it exits.
#[tokio::test]
async fn a_stopping_hub_says_goodbye_and_records_the_disconnection() {
    let (hub, app, token, _site, state, _linked_tmp) =
        linked("gateway-stop", "https://127.0.0.1").await;
    let (status, _) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::OK);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let (url, hub_task) = serve_until(hub.clone(), async move {
        stopped.await.ok();
    })
    .await;
    let mac = state
        .machine(&name("mac"))
        .expect("mac")
        .node_id
        .to_string();
    let (_dir_tmp, dir) = temp_dir("gateway-stop-mac");
    let agent = node(&url, &mac, identity(2), &dir);
    let session = tokio::spawn(async move {
        let (coordination, _sent, _received) = coordination();
        agent.session(&mut None, &coordination).await
    });
    acked(&hub, &mac, 1).await;
    // Seen long ago: the Hub must record the end of the session
    hub.db.seen(&mac, 0, "0.0.0").await.expect("seen");
    let stopped_at = nett_hub::now();

    stop.send(()).ok();
    let ended = tokio::time::timeout(Duration::from_secs(5), session)
        .await
        .expect("the session ends")
        .expect("no panic");
    assert!(matches!(ended, Ok(Exit::Shutdown)), "{ended:?}");
    tokio::time::timeout(nett_hub::SHUTDOWN_GRACE + Duration::from_secs(1), hub_task)
        .await
        .expect("the Hub stops")
        .expect("no panic");
    let row = hub
        .db
        .nodes()
        .await
        .expect("nodes")
        .into_iter()
        .find(|r| r.node_id == mac)
        .expect("mac");
    assert!(row.last_seen >= stopped_at, "last seen {}", row.last_seen);
    let events = hub.db.events(&mac, 1).await.expect("events");
    assert_eq!(
        (events[0].kind.as_str(), events[0].detail.as_str()),
        ("disconnected", "the Hub is stopping")
    );
}

/// The Hub upgrades itself before it relays a higher release (design/release.md section 7, ADR
/// 0026): once it holds its own program, it readies it for the upgrade instead of relaying; a
/// version that failed before is relayed without upgrading, and shows as the Hub's problem.
#[tokio::test]
async fn the_hub_upgrades_itself_before_it_relays_a_release() {
    let (hub, app, token, _site, _state, linked_tmp) =
        linked("gateway-self-upgrade", "https://127.0.0.1").await;
    let version: nett_trust::release::Version = "99.0.0".parse().expect("version");
    let data = linked_tmp.path();
    let releases = data.join(nett_hub::mirror::DIR);
    std::fs::create_dir_all(&releases).expect("releases");
    let (node, hub_program) = (b"node program".to_vec(), b"hub program".to_vec());
    let mut programs = serde_json::Map::new();
    for (target, bytes) in [
        ("x86_64-unknown-linux-musl", &node),
        (common::HUB_TARGET, &hub_program),
    ] {
        std::fs::write(releases.join(format!("nett-{version}-{target}")), bytes).expect("program");
        let entry: serde_json::Value = serde_json::from_slice(&common::release_key().manifest(
            version,
            target,
            "https://127.0.0.1:9/nett",
            bytes,
        ))
        .expect("manifest");
        programs.insert(target.into(), entry["programs"][target].clone());
    }
    let manifest = serde_json::json!({ "version": version.to_string(), "programs": programs })
        .to_string()
        .into_bytes();

    // Where the program goes cannot be written: the release is relayed, the Hub says why it does
    // not upgrade and tries again sooner
    let taken = hub.take_release(manifest.clone()).await.expect("manifest");
    assert!(taken.missing.is_empty(), "{:?}", taken.missing);
    assert_eq!(hub.upgrade_problem(), None);
    let upgrade = taken.upgrade.expect("the Hub upgrades itself");
    assert_eq!(upgrade.version, version);
    assert!(
        upgrade
            .minisig
            .contains(&format!("nett-{version}-{}", common::HUB_TARGET))
    );
    assert_eq!(
        std::fs::read(data.join("nett-hub.new")).expect("readied"),
        hub_program
    );
    assert!(
        hub.subscribe_release().borrow().is_none(),
        "not relayed before the Hub has upgraded"
    );

    // Where the program goes cannot be written: the release is relayed, and the Hub says why it
    // does not upgrade and tries again sooner
    std::fs::remove_file(data.join("nett-hub.new")).expect("readied");
    std::fs::create_dir_all(data.join("nett-hub.new/in-the-way")).expect("in the way");
    let taken = hub.take_release(manifest.clone()).await.expect("manifest");
    assert!(taken.upgrade.is_none());
    assert_eq!(taken.missing.len(), 1, "{:?}", taken.missing);
    let problem = hub.upgrade_problem().expect("a problem");
    assert!(
        problem.starts_with("99.0.0: not placed yet (copying"),
        "{problem}"
    );
    assert!(hub.subscribe_release().borrow().is_some(), "relayed");

    std::fs::write(
        data.join("upgrade.json"),
        br#"{"failed": {"99.0.0": "nett-hub 99.0.0 started 3 times without settling; back to 0.5.0"}}"#,
    )
    .expect("record");
    let taken = hub.take_release(manifest).await.expect("manifest");
    assert!(
        taken.upgrade.is_none(),
        "a version that failed is not tried again"
    );
    assert!(taken.missing.is_empty(), "{:?}", taken.missing);
    let (_, body) = call(&app, "GET", "/api/v1/site/status", Some(&token), vec![]).await;
    let status: nett_proto::api::StatusResponse = serde_json::from_slice(&body).expect("status");
    assert_eq!(
        status.hub_upgrade.as_deref(),
        Some("99.0.0: nett-hub 99.0.0 started 3 times without settling; back to 0.5.0")
    );
}
