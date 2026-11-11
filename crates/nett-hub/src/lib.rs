//! The Hub server (design/hub.md): database, site verification and composition, HTTP interface,
//! node gateway. The executable `nett-hub` is in `main.rs`; integration tests call through the same
//! router.

pub mod api;
pub mod db;
pub mod gateway;
pub mod hub;
pub mod tls;

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
