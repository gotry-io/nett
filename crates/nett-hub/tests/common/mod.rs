//! Shared by Hub tests: temporary directory, a signed site, starting the Hub.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use nett_core::name::NodeName;
use nett_hub::db::Db;
use nett_hub::hub::Hub;
use nett_proto::api::LinkResponse;
use nett_site::dir::{SiteDir, new_node_id};
use nett_site::ops::MachineOptions;
use nett_site::sign::sign;
use nett_site::state::{NodeKeys, State};
use nett_trust::encoding::Timestamp;
use nett_trust::keys::X25519PublicKey;
use nett_trust::payload::{PortRange, Protocol};
use tower::ServiceExt as _;
use x25519_dalek::{PublicKey, StaticSecret};

pub const URL: &str = "https://127.0.0.1";
pub const SECRET: [u8; 32] = [42; 32];

pub fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nett-hub-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

pub fn name(s: &str) -> NodeName {
    s.parse().expect("valid name")
}

/// A machine's identity key: its public key is registered in the site, and the Hub recognizes the
/// machine by it.
pub fn identity(n: u8) -> StaticSecret {
    StaticSecret::from([n; 32])
}

pub fn keys(n: u8) -> NodeKeys {
    NodeKeys {
        mesh: X25519PublicKey::from_bytes([n.wrapping_add(100); 32]),
        identity: X25519PublicKey::from_bytes(PublicKey::from(&identity(n)).to_bytes()),
    }
}

pub fn tcp(port: u16) -> PortRange {
    PortRange {
        protocol: Protocol::Tcp,
        first: port,
        last: port,
    }
}

/// The site: public edge-vps (identity key 1), dial-only mac (2) and nas (3), signed.
pub fn site(dir: &Path) -> (SiteDir, State) {
    SiteDir::init(dir, "https://nett.invalid").expect("init");
    let site = SiteDir::open(dir).expect("open");
    let mut state = site.load().expect("load");
    state
        .add(
            name("edge-vps"),
            MachineOptions {
                public: true,
                ipv4: Some("203.0.113.10".parse().expect("ip")),
                keys: Some(keys(1)),
                ..MachineOptions::default()
            },
            new_node_id().expect("id"),
        )
        .expect("add edge-vps");
    for (n, k) in [("mac", 2), ("nas", 3)] {
        state
            .add(
                name(n),
                MachineOptions {
                    keys: Some(keys(k)),
                    ..MachineOptions::default()
                },
                new_node_id().expect("id"),
            )
            .expect("add");
    }
    resign(&site, &mut state);
    (site, state)
}

pub fn resign(site: &SiteDir, state: &mut State) {
    sign(
        state,
        &site.recovery().expect("recovery"),
        Timestamp::now(),
        &[],
    )
    .expect("signed");
}

/// An initialized Hub waiting to be linked (the random secret in the link code is `SECRET`).
pub async fn hub(dir: &Path, url: &str) -> Arc<Hub> {
    let db = Db::open(&dir.join("hub.db")).await.expect("database");
    assert!(
        db.set_link(url, &nett_hub::sha256(&SECRET), nett_hub::now() + 3600)
            .await
            .expect("set link")
    );
    Hub::load(db, StaticSecret::from([200; 32]), url.to_owned())
        .await
        .expect("hub")
}

pub async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::from(body)).expect("request"))
        .await
        .expect("response");
    let status = res.status();
    let bytes = res
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    (status, bytes)
}

pub fn link_body(secret: [u8; 32], state: &State) -> Vec<u8> {
    serde_json::to_vec(&nett_proto::api::LinkRequest {
        secret: nett_proto::token::Bytes32(secret),
        trust_anchors: serde_json::to_value(&state.trust_anchors).expect("anchors"),
    })
    .expect("json")
}

pub async fn push(app: &axum::Router, token: &str, state: &State) -> (StatusCode, Vec<u8>) {
    call(
        app,
        "PUT",
        "/api/v1/site",
        Some(token),
        serde_json::to_vec(state).expect("json"),
    )
    .await
}

/// A linked Hub: returns the Hub, router, owner token and site.
pub async fn linked(name: &str, url: &str) -> (Arc<Hub>, axum::Router, String, SiteDir, State) {
    let dir = temp_dir(name);
    let (site, state) = site(&dir.join("site"));
    let hub = hub(&dir, url).await;
    let app = nett_hub::api::router(hub.clone());
    let (status, body) = call(
        &app,
        "POST",
        "/api/v1/link",
        None,
        link_body(SECRET, &state),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let token = serde_json::from_slice::<LinkResponse>(&body)
        .expect("token")
        .token;
    (hub, app, token, site, state)
}

pub const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

pub fn cert_fingerprint() -> [u8; 32] {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject as _;
    let der = CertificateDer::from_pem_file(Path::new(DATA).join("test-cert.pem")).expect("cert");
    let digest = ring::digest::digest(&ring::digest::SHA256, der.as_ref());
    digest.as_ref().try_into().expect("32 bytes")
}

/// Starts the Hub's HTTPS service and returns its address.
pub async fn serve(hub: Arc<Hub>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("address").port();
    let acceptor = nett_hub::tls::acceptor(
        &Path::new(DATA).join("test-cert.pem"),
        &Path::new(DATA).join("test-key.pem"),
    )
    .expect("tls");
    let app = nett_hub::api::router(hub);
    tokio::spawn(async move {
        axum::serve(
            nett_hub::tls::TlsListener::new(listener, acceptor),
            app.into_make_service_with_connect_info::<nett_hub::gateway::Peer>(),
        )
        .await
        .ok();
    });
    format!("https://127.0.0.1:{port}")
}

/// The Hub's identity public key (the private key used by `hub()` is `[200; 32]`).
pub fn hub_key() -> nett_proto::token::Bytes32 {
    nett_proto::token::Bytes32(PublicKey::from(&StaticSecret::from([200; 32])).to_bytes())
}
