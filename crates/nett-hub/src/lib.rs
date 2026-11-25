//! The Hub server (design/hub.md): database, site verification and composition, HTTP interface,
//! node gateway. The executable `nett-hub` is in `main.rs`; integration tests call through the same
//! router and [`serve`].

pub mod api;
pub mod db;
pub mod gateway;
pub mod hub;
pub mod live;
pub mod mirror;
pub mod openapi;
pub mod tls;

use std::sync::Arc;
use std::time::Duration;

/// How long a stopping Hub waits for the node sessions to record their end (design/hub.md section
/// 8).
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Serves the HTTP interface and the node gateway on `listener` until `shutdown` completes,
/// terminating TLS itself when given an acceptor; then ends the node sessions. axum waits only for
/// HTTP connections, and a node's WebSocket leaves its HTTP connection once upgraded.
pub async fn serve(
    listener: tokio::net::TcpListener,
    tls: Option<tokio_rustls::TlsAcceptor>,
    hub: Arc<hub::Hub>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    // Peer address: the Hub learns the public address of a `public` machine from it
    // (design/hub.md section 5)
    let app = api::router(hub.clone()).into_make_service_with_connect_info::<gateway::Peer>();
    // The server waits for its connections, and a live view's stream lasts until the view ends:
    // the streams end when the shutdown begins
    let shutdown = {
        let hub = hub.clone();
        async move {
            shutdown.await;
            hub.views.end();
        }
    };
    match tls {
        None => {
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await?;
        }
        Some(acceptor) => {
            axum::serve(tls::TlsListener::new(listener, acceptor), app)
                .with_graceful_shutdown(shutdown)
                .await?;
        }
    }
    hub.shut_down(SHUTDOWN_GRACE).await;
    Ok(())
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

pub fn random<const N: usize>() -> Result<[u8; N], ring::error::Unspecified> {
    use ring::rand::{SecureRandom as _, SystemRandom};
    let mut bytes = [0u8; N];
    SystemRandom::new().fill(&mut bytes)?;
    Ok(bytes)
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .to_vec()
}
