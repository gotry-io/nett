//! Forwarding between loopback ports and obfuscated ports, relays' and peers' (design/obfuscation.md
//! section 2), one task per port. Each packet from the loopback port is wrapped and sent on a socket
//! connected to the obfuscated port; each datagram from there is unwrapped and dispatched as on the
//! TLS transport: replies to probes go to the mesh's port that sent the probe, the rest to
//! WireGuard. What does not unwrap is dropped. The socket is connected, so the system delivers to it
//! only that port's datagrams: nothing here listens on a public address (hard rule 2).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use nett_core::transport::{ObfsTarget, RELAY_PROBE, RELAY_REPLY};
use nett_mesh::probe::{DIRECT_PROBE, DIRECT_REPLY};
use ring::rand::SystemRandom;
use tokio::net::UdpSocket;

use crate::forward::{REOPEN_DELAY, REOPEN_MAX};
use nett_mesh::obfs::{MAX_MESSAGE, MAX_OVERHEAD, ObfsKey, Obfuscator, Padding, Salts};

/// The largest datagram from an obfuscated port: the largest message, wrapped.
const MAX_DATAGRAM: usize = MAX_MESSAGE + MAX_OVERHEAD;

/// Runs one obfuscated port's forwarding until the task is aborted with its configuration: a port
/// that fails is opened again, so the port stays reachable once the cause goes away.
pub(crate) async fn target_or_log(
    target: ObfsTarget,
    wireguard: SocketAddr,
    interface: Option<u32>,
) {
    let listen = target.listen;
    let mut delay = REOPEN_DELAY;
    loop {
        let started = Instant::now();
        if let Err(error) = target_loop(&target, wireguard, interface).await {
            // A port that worked for a while starts over from the shortest delay
            if started.elapsed() > REOPEN_MAX {
                delay = REOPEN_DELAY;
            }
            tracing::warn!(%listen, %error, retry_in = ?delay, "obfuscated transport for this port stopped");
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(REOPEN_MAX);
    }
}

async fn target_loop(
    target: &ObfsTarget,
    wireguard: SocketAddr,
    interface: Option<u32>,
) -> std::io::Result<()> {
    let local = UdpSocket::bind(target.listen).await?;
    let relay = connected(target.connect, interface).await?;
    for socket in [&local, &relay] {
        nett_mesh::sockbuf::enlarge_receive_buffer(socket);
    }
    let padding =
        Padding::new(target.padding.min, target.padding.max).map_err(std::io::Error::other)?;
    let obfuscator = Obfuscator::new(&ObfsKey::from_bytes(target.key.0), padding);
    let rng = SystemRandom::new();
    let mut salts = Salts::default();
    // The mesh port that sent the probe: replies to probes go back to it
    let mut probe_source: Option<SocketAddr> = None;
    let mut buf = vec![0u8; MAX_MESSAGE];
    let mut datagram = vec![0u8; MAX_DATAGRAM];
    let mut wire = Vec::with_capacity(MAX_DATAGRAM);
    let mut plain = Vec::with_capacity(MAX_MESSAGE);
    tracing::info!(to = %target.connect, listen = %target.listen, "obfuscated transport ready");
    loop {
        tokio::select! {
            received = local.recv_from(&mut buf) => {
                let (len, from) = received?;
                // Forward only packets sent by this machine
                if !from.ip().is_loopback() || len == 0 {
                    continue;
                }
                if matches!(buf[0], RELAY_PROBE | DIRECT_PROBE) {
                    probe_source = Some(from);
                }
                // A packet that cannot go out now is dropped, as UDP would drop it
                if obfuscator.wrap(&rng, now_ms(), &buf[..len], &mut wire).is_ok() {
                    drop(relay.try_send(&wire));
                }
            }
            received = relay.recv(&mut datagram) => {
                // An ICMP error on the connected socket surfaces as a failed receive
                let Ok(len) = received else { continue };
                if obfuscator.unwrap(now_ms(), &mut salts, &datagram[..len], &mut plain).is_err() {
                    continue;
                }
                let reply = matches!(plain.first(), Some(&(RELAY_REPLY | DIRECT_REPLY)));
                let to = if reply { probe_source } else { Some(wireguard) };
                if let Some(to) = to {
                    drop(local.try_send_to(&plain, to));
                }
            }
        }
    }
}

/// A UDP socket connected to the relay, bound to `interface` when the mesh names one (design/
/// userspace.md section 6.2).
async fn connected(relay: SocketAddr, interface: Option<u32>) -> std::io::Result<UdpSocket> {
    let any: SocketAddr = if relay.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = std::net::UdpSocket::bind(any)?;
    if let Some(index) = interface {
        bind_to_interface(&socket, index, relay.is_ipv6())?;
    }
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket)?;
    socket.connect(relay).await?;
    Ok(socket)
}

#[cfg(target_os = "macos")]
fn bind_to_interface(socket: &std::net::UdpSocket, index: u32, v6: bool) -> std::io::Result<()> {
    use std::os::fd::AsFd as _;
    nett_mesh::macos::bind_to_interface(socket.as_fd(), index, v6)
}

/// Only the macOS mesh names an interface.
#[cfg(not(target_os = "macos"))]
fn bind_to_interface(_socket: &std::net::UdpSocket, _index: u32, _v6: bool) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "binding a socket to an interface is only done on macOS",
    ))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nett_core::transport::{ObfsKeyBytes, ObfsPadding};
    use std::time::Duration;

    fn free_loopback_port() -> SocketAddr {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .and_then(|s| s.local_addr())
            .expect("a free port")
    }

    /// Packets from the loopback port reach the relay wrapped, the relay's datagrams reach
    /// WireGuard unwrapped, a relay reply goes back to the port that sent the probe, and neither a
    /// datagram from anywhere but the relay nor one that does not unwrap reaches WireGuard.
    #[tokio::test]
    async fn packets_cross_wrapped_and_only_the_relay_is_heard() {
        let key = [9u8; 32];
        let padding = Padding::new(8, 64).expect("padding");
        let relay = UdpSocket::bind("127.0.0.1:0").await.expect("relay");
        let wireguard = UdpSocket::bind("127.0.0.1:0").await.expect("wireguard");
        let mesh = UdpSocket::bind("127.0.0.1:0").await.expect("mesh");
        let target = ObfsTarget {
            listen: free_loopback_port(),
            connect: relay.local_addr().expect("addr"),
            key: ObfsKeyBytes(key),
            padding: ObfsPadding { min: 8, max: 64 },
        };
        let listen = target.listen;
        let wg_addr = wireguard.local_addr().expect("addr");
        let task = tokio::spawn(async move { target_or_log(target, wg_addr, None).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        let o = Obfuscator::new(&ObfsKey::from_bytes(key), padding);
        let rng = SystemRandom::new();
        let mut salts = Salts::default();
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let within = Duration::from_secs(2);
        let quiet = Duration::from_millis(300);

        // WireGuard's data, wrapped on the way to the relay
        let mut data = vec![4u8, 0, 0, 0];
        data.resize(96, 0x33);
        wireguard.send_to(&data, listen).await.expect("send");
        let (len, from) = tokio::time::timeout(within, relay.recv_from(&mut buf))
            .await
            .expect("in time")
            .expect("relay receives");
        let mut plain = Vec::new();
        o.unwrap(now_ms(), &mut salts, &buf[..len], &mut plain)
            .expect("unwraps");
        assert_eq!(plain, data);
        let member = from;

        // A probe from the mesh's port, of a relay or of a peer's own port: the reply goes back to
        // that port
        let mut wire = Vec::new();
        for (probe, reply) in [(RELAY_PROBE, RELAY_REPLY), (DIRECT_PROBE, DIRECT_REPLY)] {
            mesh.send_to(&[probe, 1, 2, 3], listen)
                .await
                .expect("probe");
            tokio::time::timeout(within, relay.recv_from(&mut buf))
                .await
                .expect("in time")
                .expect("relay receives the probe");
            o.wrap(&rng, now_ms(), &[reply, 4, 5, 6], &mut wire)
                .expect("wrap");
            relay.send_to(&wire, member).await.expect("reply");
            let (len, _) = tokio::time::timeout(within, mesh.recv_from(&mut buf))
                .await
                .expect("in time")
                .expect("mesh gets the reply");
            assert_eq!(buf[..len], [reply, 4, 5, 6]);
        }

        // The relay's handshake reaches WireGuard as WireGuard sent it
        let mut handshake = vec![2u8, 0, 0, 0];
        handshake.resize(92, 0x44);
        o.wrap(&rng, now_ms(), &handshake, &mut wire).expect("wrap");
        relay.send_to(&wire, member).await.expect("handshake");
        let (len, _) = tokio::time::timeout(within, wireguard.recv_from(&mut buf))
            .await
            .expect("in time")
            .expect("wireguard gets it");
        assert_eq!(buf[..len], handshake[..]);

        // Neither another sender nor garbage from the relay reaches WireGuard
        let stranger = UdpSocket::bind("127.0.0.1:0").await.expect("stranger");
        o.wrap(&rng, now_ms(), &handshake, &mut wire).expect("wrap");
        stranger.send_to(&wire, member).await.expect("send");
        relay.send_to(&[0u8; 80], member).await.expect("garbage");
        assert!(
            tokio::time::timeout(quiet, wireguard.recv_from(&mut buf))
                .await
                .is_err(),
            "nothing but the relay's wrapped datagrams reaches WireGuard"
        );
        task.abort();
    }
}
