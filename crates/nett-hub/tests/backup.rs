//! Backup and rebuild (design/hub.md section 8.2): a connected machine asks for the Hub's backup and
//! keeps it; the Hub records that the machine holds it; `nett-hub restore` rebuilds the Hub from that
//! file in an empty directory with the site's backup key, and the rebuilt Hub has the same identity and
//! site.

mod common;

use std::io::Write as _;
use std::time::Duration;

use axum::http::StatusCode;
use nett_node::config::HubConfig;
use nett_node::session::Node;
use nett_proto::api::StatusResponse;
use nett_proto::token::Bytes32;
use nett_site::dir::BACKUP_FILE;
use nett_trust::backup::BackupKey;
use x25519_dalek::{PublicKey, StaticSecret};

use common::*;

#[tokio::test]
async fn a_machine_keeps_the_backup_and_the_hub_is_rebuilt_from_it() {
    let (hub, app, token, site, mut state, _linked_tmp) =
        linked("backup", "https://127.0.0.1").await;
    // `nett site link` creates the backup key in the site directory and pushes its public half
    assert!(site.ensure_backup_key(&mut state).expect("backup key"));
    let line = std::fs::read_to_string(site.path().join(BACKUP_FILE)).expect("key file");
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        std::fs::metadata(site.path().join(BACKUP_FILE))
            .expect("key file")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let (status, _) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::OK);
    let url = serve(hub.clone()).await;

    let mac = state
        .machine(&name("mac"))
        .expect("mac")
        .node_id
        .to_string();
    let (_dir_tmp, dir) = temp_dir("backup-mac");
    let agent = Node {
        config: HubConfig {
            url: url.clone(),
            hub_key: Bytes32(PublicKey::from(&StaticSecret::from([200; 32])).to_bytes()),
            node_id: mac.clone(),
            tls_fingerprint: Some(Bytes32(cert_fingerprint())),
        },
        identity: identity(2),
        desired: dir.join("desired.json"),
        socket: dir.join("mesh.sock"),
        upgrader: None,
        services: None,
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(nett_node::session::run(agent, async move {
        stopped.await.ok();
    }));

    // The machine asks for the backup when it connects, keeps it, and says so
    let kept = dir.join(nett_node::session::BACKUP_FILE);
    let mut held = false;
    for _ in 0..200 {
        let (_, body) = call(&app, "GET", "/api/v1/site/status", Some(&token), vec![]).await;
        let reply: StatusResponse = serde_json::from_slice(&body).expect("status");
        if reply
            .backup
            .as_ref()
            .is_some_and(|b| b.held_by.contains(&"mac".to_owned()))
        {
            held = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(held, "the Hub records that mac holds its backup");
    assert_eq!(
        std::fs::metadata(&kept).expect("kept").permissions().mode() & 0o777,
        0o600
    );
    let sealed = std::fs::read(&kept).expect("kept");
    // Only the site's backup key opens it; the Hub could make it but cannot read it
    let other = BackupKey::generate().expect("key");
    assert!(nett_trust::backup::open(&other, &sealed).is_err());
    stop.send(()).ok();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the node stops")
        .expect("no panic");

    // Rebuild in an empty directory with the backup key on standard input
    let (_rebuilt_tmp, rebuilt) = temp_dir("backup-rebuilt");
    let mut restore = std::process::Command::new(env!("CARGO_BIN_EXE_nett-hub"))
        .args(["restore", "--data"])
        .arg(&rebuilt)
        .arg(&kept)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("nett-hub");
    restore
        .stdin
        .take()
        .expect("stdin")
        .write_all(line.as_bytes())
        .expect("key line");
    let out = restore.wait_with_output().expect("restored");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("3 machines"));
    let key = nett_mesh::key::PrivateKey::load(&rebuilt.join("hub.key")).expect("identity key");
    assert_eq!(key.as_bytes(), &[200; 32], "the same Hub identity");
    let db = nett_hub::db::Db::open(&rebuilt.join("hub.db"))
        .await
        .expect("database");
    let (_, json) = db.site().await.expect("read").expect("a site");
    let restored = nett_site::state::State::from_json(json.as_bytes()).expect("site");
    assert_eq!(restored.machines.len(), state.machines.len());
    assert_eq!(restored.backup_key, state.backup_key);

    // A second restore into the same directory is refused
    let again = std::process::Command::new(env!("CARGO_BIN_EXE_nett-hub"))
        .args(["restore", "--data"])
        .arg(&rebuilt)
        .arg(&kept)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("nett-hub");
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("already holds a Hub"));
}
