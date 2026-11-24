//! The relay's receive/send loop (design/mesh.md sections 5.1-5.3), in the nett daemon (ADR 0032):
//! one task owns the [`Relay`] and receives on the relay port, the obfuscated port and the TLS
//! hand-off port, then forwards or answers according to the result. nett-relay terminates each TLS
//! connection and hands its messages here from a socket of its own on the loopback address, one
//! datagram each; an empty datagram says the connection closed. A packet that cannot go out at once
//! is dropped (WireGuard retransmits on its own), so the loop never blocks.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::relay::{AssignedMember, ConnId, Outcome, PeerAddr, Relay, RelayState};
use nett_mesh::config::{ObfsPadding, ObfsSecret};
use nett_mesh::obfs::{ObfsKey, Obfuscator, Padding, Salts};
use nett_trust::keys::X25519PublicKey;
use ring::rand::SystemRandom;

const EXPIRE_INTERVAL: Duration = Duration::from_secs(1);
/// Outer packets are at most about 1360 bytes (design/mesh.md section 4); leave some margin.
pub(crate) const MAX_DATAGRAM: usize = 2048;
/// A datagram on the obfuscated port: a message of up to [`MAX_DATAGRAM`], wrapped.
const MAX_OBFS_DATAGRAM: usize = MAX_DATAGRAM + nett_mesh::obfs::MAX_OVERHEAD;
/// Interval for saving state (design/mesh.md section 5.2).
const SAVE_INTERVAL: Duration = Duration::from_secs(1);
/// Upper limit on TLS connections, and on those among them that are waiting for authentication.
pub(crate) const MAX_TLS_CONNECTIONS: usize = 1024;
pub(crate) const MAX_UNAUTHENTICATED: usize = 64;
/// How long after a connection opens an authenticated probe must arrive (design/mesh.md section 5.3).
pub(crate) const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
/// A TLS connection the relay has heard nothing from for this long is taken as gone, as when
/// nett-relay ended without saying so: its member keeps a keepalive every 25 seconds.
const HANDOFF_IDLE: Duration = Duration::from_secs(120);

/// The obfuscated port (design/obfuscation.md section 2): what arrives is unwrapped before it is
/// routed, and what goes to a member bound here is wrapped, with the relay's key, or with a
/// member's own when it is that member's obfuscated port.
pub struct ObfsIngress {
    pub socket: UdpSocket,
    pub obfuscator: Obfuscator,
    pub rng: SystemRandom,
    pub salts: Salts,
    /// Members' own obfuscated ports this relay reaches, by address.
    pub members: HashMap<SocketAddr, MemberPort>,
}

/// A member's own obfuscated port: its key, and the salts of what was opened with it.
pub struct MemberPort {
    key: ObfsSecret,
    padding: ObfsPadding,
    obfuscator: Obfuscator,
    salts: Salts,
}

impl ObfsIngress {
    /// The members' own obfuscated ports, as the assignment gives them; one whose key stays keeps
    /// the salts it remembers. Bounded by the assignment's members.
    pub fn set_members(&mut self, ports: &[(SocketAddr, ObfsSecret, ObfsPadding)]) {
        let mut old = std::mem::take(&mut self.members);
        self.members = ports
            .iter()
            .filter_map(|(addr, key, padding)| {
                let port = match old.remove(addr) {
                    Some(p) if p.key == *key && p.padding == *padding => p,
                    _ => MemberPort {
                        key: key.clone(),
                        padding: *padding,
                        obfuscator: Obfuscator::new(
                            &ObfsKey::from_bytes(key.0),
                            Padding::new(padding.min, padding.max).ok()?,
                        ),
                        salts: Salts::default(),
                    },
                };
                Some((*addr, port))
            })
            .collect();
    }

    /// Opens a datagram from `from`: with that member's key when it is a member's obfuscated port,
    /// with the relay's otherwise.
    fn open(&mut self, from: SocketAddr, datagram: &[u8], plain: &mut Vec<u8>) -> bool {
        let (obfuscator, salts) = match self.members.get_mut(&from) {
            Some(m) => (&m.obfuscator, &mut m.salts),
            None => (&self.obfuscator, &mut self.salts),
        };
        obfuscator.unwrap(now_ms(), salts, datagram, plain).is_ok()
    }

    /// Wraps for `to` with the key its datagrams are opened with.
    fn wrap(&self, to: SocketAddr, data: &[u8], wire: &mut Vec<u8>) -> bool {
        let obfuscator = self
            .members
            .get(&to)
            .map_or(&self.obfuscator, |m| &m.obfuscator);
        obfuscator.wrap(&self.rng, now_ms(), data, wire).is_ok()
    }
}

/// One TLS connection, as nett-relay hands it over: the loopback address it sends from.
struct Handoff {
    id: ConnId,
    opened: Instant,
    seen: Instant,
    authenticated: bool,
}

/// The TLS connections handed over, by the address they come from and by their ID.
#[derive(Default)]
struct Handoffs {
    by_addr: HashMap<SocketAddr, Handoff>,
    by_id: HashMap<ConnId, SocketAddr>,
    next: u64,
}

impl Handoffs {
    fn remove(&mut self, from: SocketAddr, relay: &mut Relay) {
        if let Some(conn) = self.by_addr.remove(&from) {
            self.by_id.remove(&conn.id);
            if conn.authenticated {
                tracing::info!(conn = conn.id.0, "TLS connection closed");
            }
            relay.closed(conn.id);
        }
    }
}

/// A changed assignment from the mesh (design/mesh.md section 5.2).
#[derive(Debug, Clone)]
pub struct Assignment {
    pub members: Vec<AssignedMember>,
    pub connections: Vec<(X25519PublicKey, X25519PublicKey)>,
    /// The members' own obfuscated ports this relay reaches through its obfuscated port.
    pub member_ports: Vec<(SocketAddr, ObfsSecret, ObfsPadding)>,
}

/// Bound on assignments waiting to be applied: the fetcher sends one only when it changed.
pub const ASSIGNMENT_QUEUE: usize = 4;

/// Runs until `shutdown` completes. `udp` is the dual-stack relay port, `handoff` the loopback port
/// nett-relay hands TLS connections to when the relay serves TLS, `obfs` the obfuscated port when
/// the relay offers it. `state` is the file holding the index table: restored at startup, and
/// written once per second and again before exit, so connections through the relay survive a
/// restart. Assignments arriving on `updates` are applied in place.
pub async fn serve(
    udp: UdpSocket,
    handoff: Option<UdpSocket>,
    mut obfs: Option<ObfsIngress>,
    mut relay: Relay,
    state: Option<PathBuf>,
    mut updates: Option<mpsc::Receiver<Assignment>>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let granted = nett_mesh::sockbuf::enlarge_receive_buffer(&udp);
    tracing::debug!(bytes = ?granted, "relay receive buffer");
    if let Some(o) = &obfs {
        let granted = nett_mesh::sockbuf::enlarge_receive_buffer(&o.socket);
        tracing::debug!(bytes = ?granted, "obfuscated port receive buffer");
    }
    if let Some(path) = &state {
        match load(path) {
            Ok(Some(saved)) => {
                relay.restore(&saved, Instant::now());
                let (_, sessions) = relay.table_sizes();
                tracing::info!(sessions, "relay state restored");
            }
            Ok(None) => {}
            // A corrupt state file only affects restoration: connections through the relay
            // handshake again per design/mesh.md section 8.4
            Err(error) => tracing::warn!(%error, "relay state not restored"),
        }
    }
    let mut conns = Handoffs::default();
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut hbuf = vec![0u8; MAX_DATAGRAM];
    // The obfuscated port's datagram, what it unwraps to, and what is wrapped for a member bound there
    let mut obuf = vec![0u8; MAX_OBFS_DATAGRAM];
    let mut plain = Vec::with_capacity(MAX_DATAGRAM);
    let mut wire = Vec::with_capacity(MAX_OBFS_DATAGRAM);
    let mut tick = tokio::time::interval(EXPIRE_INTERVAL);
    let mut last_save = Instant::now();
    // Writing to disk can stall for a few hundred milliseconds when the disk is busy (for example
    // when ext4 commits its journal every 5 seconds), so it runs on a blocking thread and does not
    // hold up forwarding; only one save runs at a time: if the previous one has not finished, skip
    // it and save the latest state the next second
    let mut saving: Option<tokio::task::JoinHandle<()>> = None;
    let mut dropped: u64 = 0;
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            received = udp.recv_from(&mut buf) => {
                let (len, from) = received?;
                let from = PeerAddr::Udp(unmap(from));
                let packet = &buf[..len];
                let outcome = relay.handle(from, packet, Instant::now(), now_ms());
                dispatch(&udp, handoff.as_ref(), obfs.as_ref(), &mut wire, &conns.by_id, from, packet, outcome, &mut dropped);
            }
            received = recv_on(handoff.as_ref(), &mut hbuf) => {
                let (len, from) = received?;
                if len == 0 {
                    conns.remove(from, &mut relay);
                    continue;
                }
                let now = Instant::now();
                let unauthenticated = conns.by_addr.values().filter(|c| !c.authenticated).count();
                if !conns.by_addr.contains_key(&from) {
                    if conns.by_addr.len() >= MAX_TLS_CONNECTIONS || unauthenticated >= MAX_UNAUTHENTICATED {
                        dropped += 1;
                        continue;
                    }
                    conns.next += 1;
                    let id = ConnId(conns.next);
                    conns.by_id.insert(id, from);
                    conns.by_addr.insert(from, Handoff { id, opened: now, seen: now, authenticated: false });
                }
                let Some(conn) = conns.by_addr.get_mut(&from) else { continue };
                conn.seen = now;
                let packet = &hbuf[..len];
                if conn.authenticated {
                    let from = PeerAddr::Tls(conn.id);
                    let outcome = relay.handle(from, packet, now, now_ms());
                    dispatch(&udp, handoff.as_ref(), obfs.as_ref(), &mut wire, &conns.by_id, from, packet, outcome, &mut dropped);
                } else if let Some(reply) = relay.authenticate(conn.id, packet, now_ms()) {
                    conn.authenticated = true;
                    tracing::info!(conn = conn.id.0, "TLS connection authenticated");
                    if let Some(h) = handoff.as_ref() {
                        drop(h.try_send_to(&reply, from));
                    }
                } else {
                    // The first message is not an authenticated probe: forget the connection and
                    // send no reply; nett-relay closes it when nothing comes back in time
                    conns.remove(from, &mut relay);
                }
            }
            received = recv_on(obfs.as_ref().map(|o| &o.socket), &mut obuf) => {
                let (len, from) = received?;
                let Some(o) = obfs.as_mut() else { continue };
                let from = unmap(from);
                // What does not unwrap is dropped and gets no answer (hard rule 2)
                if !o.open(from, &obuf[..len], &mut plain) {
                    dropped += 1;
                    continue;
                }
                let from = PeerAddr::Obfs(from);
                let outcome = relay.handle(from, &plain, Instant::now(), now_ms());
                dispatch(&udp, handoff.as_ref(), obfs.as_ref(), &mut wire, &conns.by_id, from, &plain, outcome, &mut dropped);
            }
            Some(update) = next_update(&mut updates) => {
                if let Some(o) = obfs.as_mut() {
                    o.set_members(&update.member_ports);
                }
                match relay.reassign(&update.members, &update.connections) {
                    Ok(()) => tracing::info!(
                        members = update.members.len(),
                        links = update.connections.len(),
                        "relay assignment applied"
                    ),
                    Err(error) => tracing::warn!(%error, "relay assignment not applied; keeping the previous one"),
                }
            }
            _ = tick.tick() => {
                let now = Instant::now();
                relay.expire(now);
                // A connection that has not authenticated in time, or that went quiet
                let gone: Vec<SocketAddr> = conns
                    .by_addr
                    .iter()
                    .filter(|(_, c)| {
                        if c.authenticated {
                            now.saturating_duration_since(c.seen) >= HANDOFF_IDLE
                        } else {
                            now.saturating_duration_since(c.opened) >= AUTH_TIMEOUT
                        }
                    })
                    .map(|(from, _)| *from)
                    .collect();
                for from in gone {
                    conns.remove(from, &mut relay);
                }
                if let Some(path) = &state
                    && now.saturating_duration_since(last_save) >= SAVE_INTERVAL
                    && saving.as_ref().is_none_or(tokio::task::JoinHandle::is_finished)
                {
                    last_save = now;
                    saving = Some(save_in_background(path, relay.snapshot(now)));
                }
            }
        }
    }
    if let Some(path) = &state {
        if let Some(previous) = saving.take() {
            drop(previous.await);
        }
        drop(save_in_background(path, relay.snapshot(Instant::now())).await);
    }
    Ok(())
}

/// The next assignment; waits forever when there is no channel or it has closed.
async fn next_update(updates: &mut Option<mpsc::Receiver<Assignment>>) -> Option<Assignment> {
    match updates {
        Some(rx) => match rx.recv().await {
            Some(update) => Some(update),
            None => {
                *updates = None;
                std::future::pending().await
            }
        },
        None => std::future::pending().await,
    }
}

/// Receives on a socket the relay may not have; waits forever without one.
async fn recv_on(
    socket: Option<&UdpSocket>,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    match socket {
        Some(s) => s.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

/// The result of running [`Relay::handle`]. A send failure (for example the peer has no route yet
/// or the connection's queue is full) drops only that one packet.
#[allow(clippy::too_many_arguments)]
fn dispatch(
    udp: &UdpSocket,
    handoff: Option<&UdpSocket>,
    obfs: Option<&ObfsIngress>,
    wire: &mut Vec<u8>,
    conns: &HashMap<ConnId, SocketAddr>,
    from: PeerAddr,
    packet: &[u8],
    outcome: Outcome,
    dropped: &mut u64,
) {
    let mut send = |to: PeerAddr, data: &[u8]| match to {
        PeerAddr::Udp(addr) => drop(udp.try_send_to(data, map_v6(addr))),
        PeerAddr::Tls(id) => {
            if let (Some(h), Some(addr)) = (handoff, conns.get(&id)) {
                drop(h.try_send_to(data, *addr));
            }
        }
        PeerAddr::Obfs(addr) => {
            if let Some(o) = obfs
                && o.wrap(addr, data, wire)
            {
                drop(o.socket.try_send_to(wire, map_v6(addr)));
            }
        }
    };
    match outcome {
        Outcome::Forward(to) => send(to, packet),
        Outcome::ForwardEach(targets) => {
            for to in targets {
                send(to, packet);
            }
        }
        Outcome::Reply(reply) => send(from, &reply),
        Outcome::Drop(reason) => {
            *dropped += 1;
            tracing::debug!(?reason, ?from, dropped, "relay dropped a packet");
        }
    }
}

fn load(path: &Path) -> std::io::Result<Option<RelayState>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(std::io::Error::other),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn save_in_background(path: &Path, snapshot: RelayState) -> tokio::task::JoinHandle<()> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || save_or_warn(&path, &snapshot))
}

/// Write a temporary file first, then rename: what is read at restart is always a complete state.
fn save(path: &Path, snapshot: &RelayState) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let bytes = serde_json::to_vec(snapshot).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(&bytes)?;
    std::fs::rename(&tmp, path)
}

fn save_or_warn(path: &Path, snapshot: &RelayState) {
    if let Err(error) = save(path, snapshot) {
        tracing::warn!(%error, path = %path.display(), "saving relay state failed");
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn unmap(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

fn map_v6(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(a) => SocketAddr::new(IpAddr::V6(a.ip().to_ipv6_mapped()), a.port()),
        SocketAddr::V6(_) => addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::AssignedMember;
    use nett_mesh::probe::{KeyId, OuterProbe, OuterReply, ProbeKey, RELAY_PROBE};
    use nett_trust::keys::X25519PublicKey;

    /// A TLS connection handed over on the loopback address (ADR 0032): what it sends before an
    /// authenticated probe gets no answer and is forgotten; once a probe authenticates it, it is
    /// that member's address, forwarded to and from as any other; an empty datagram closes it.
    #[test]
    fn a_handed_over_tls_connection_authenticates_and_carries_its_member() {
        use crate::wg::tests::{data, initiation, response};

        let (a, b) = ([1; 32], [2; 32]);
        let plain_a = std::net::UdpSocket::bind("127.0.0.1:0").expect("a's socket");
        plain_a
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let member = |k: [u8; 32], address| AssignedMember {
            public_key: X25519PublicKey::from_bytes(k),
            address,
            obfs: false,
            token: [k[0]; 32],
        };
        let relay = Relay::new(
            &[
                member(a, Some(plain_a.local_addr().expect("addr"))),
                member(b, None),
            ],
            &[(
                X25519PublicKey::from_bytes(a),
                X25519PublicKey::from_bytes(b),
            )],
        )
        .expect("assignment");
        let udp = std::net::UdpSocket::bind("[::]:0").expect("relay socket");
        let handoff = std::net::UdpSocket::bind("127.0.0.1:0").expect("hand-off socket");
        for s in [&udp, &handoff] {
            s.set_nonblocking(true).expect("nonblocking");
        }
        let relay_addr = SocketAddr::from(([127, 0, 0, 1], udp.local_addr().expect("addr").port()));
        let handoff_addr = handoff.local_addr().expect("addr");
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async move {
                let udp = UdpSocket::from_std(udp).expect("tokio socket");
                let handoff = UdpSocket::from_std(handoff).expect("tokio socket");
                serve(udp, Some(handoff), None, relay, None, None, async {
                    drop(stopped.await);
                })
                .await
            })
        });

        // b's TLS connection, as nett-relay hands it over: a socket of its own on loopback
        let conn = std::net::UdpSocket::bind("127.0.0.1:0").expect("b's connection");
        conn.connect(handoff_addr).expect("connect");
        conn.set_read_timeout(Some(Duration::from_millis(500)))
            .expect("timeout");
        let mut buf = [0u8; MAX_DATAGRAM];
        let mut receive = || conn.recv(&mut buf).ok().map(|len| buf[..len].to_vec());

        conn.send(&initiation(11, &a)).expect("send");
        assert_eq!(receive(), None, "nothing before an authenticated probe");

        let probe_key = ProbeKey::from_token(&[2; 32]);
        let probe = OuterProbe {
            kind: RELAY_PROBE,
            key_id: KeyId::of(&b),
            seq: 1,
            sent_ms: now_ms(),
        };
        conn.send(&probe.encode(&probe_key)).expect("probe");
        let reply = receive().expect("a reply to the probe");
        assert!(OuterReply::verify(&reply, &probe_key).is_some());

        let mut plain = [0u8; MAX_DATAGRAM];
        conn.send(&initiation(11, &a)).expect("initiation");
        let (len, _) = plain_a
            .recv_from(&mut plain)
            .expect("a gets the initiation");
        assert_eq!(plain[..len], initiation(11, &a)[..]);
        plain_a
            .send_to(&response(22, 11, &b), relay_addr)
            .expect("a answers");
        assert_eq!(receive(), Some(response(22, 11, &b)), "b gets the response");
        plain_a.send_to(&data(11), relay_addr).expect("a's data");
        assert_eq!(receive(), Some(data(11)), "b gets a's data");

        // Closed: a's packets no longer reach it
        conn.send(&[]).expect("close");
        std::thread::sleep(Duration::from_millis(100));
        plain_a.send_to(&data(11), relay_addr).expect("a's data");
        assert_eq!(receive(), None, "a closed connection gets nothing");

        stop.send(()).expect("relay still running");
        server.join().expect("server thread").expect("serve");
    }

    /// The obfuscated port unwraps what it receives, routes it as the relay port does, and wraps only
    /// what goes to the member bound there (design/obfuscation.md section 2): garbage gets no answer,
    /// a probe gets a wrapped reply, and a handshake and data cross between a member on the relay
    /// port and a member on the obfuscated port.
    #[test]
    fn the_obfuscated_port_routes_between_plain_and_obfuscated_members() {
        use crate::wg::tests::{data, initiation, response};
        use nett_mesh::obfs::{ObfsKey, Obfuscator, Padding, Salts};

        let (a, b) = ([1; 32], [2; 32]);
        let plain_a = std::net::UdpSocket::bind("127.0.0.1:0").expect("a's socket");
        plain_a
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let member = |k: [u8; 32], address| AssignedMember {
            public_key: X25519PublicKey::from_bytes(k),
            address,
            obfs: false,
            token: [k[0]; 32],
        };
        let relay = Relay::new(
            &[
                member(a, Some(plain_a.local_addr().expect("addr"))),
                member(b, None),
            ],
            &[(
                X25519PublicKey::from_bytes(a),
                X25519PublicKey::from_bytes(b),
            )],
        )
        .expect("assignment");
        let key = ObfsKey::from_bytes([7; 32]);
        let padding = Padding::new(8, 64).expect("padding");
        let udp = std::net::UdpSocket::bind("[::]:0").expect("relay socket");
        let obfs = std::net::UdpSocket::bind("[::]:0").expect("obfuscated socket");
        for s in [&udp, &obfs] {
            s.set_nonblocking(true).expect("nonblocking");
        }
        let at = |s: &std::net::UdpSocket| {
            SocketAddr::from(([127, 0, 0, 1], s.local_addr().expect("addr").port()))
        };
        let (relay_addr, obfs_addr) = (at(&udp), at(&obfs));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server_key = key.clone();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async move {
                let ingress = ObfsIngress {
                    socket: UdpSocket::from_std(obfs).expect("tokio socket"),
                    obfuscator: Obfuscator::new(&server_key, padding),
                    rng: SystemRandom::new(),
                    salts: Salts::default(),
                    members: HashMap::new(),
                };
                let udp = UdpSocket::from_std(udp).expect("tokio socket");
                serve(udp, None, Some(ingress), relay, None, None, async {
                    drop(stopped.await);
                })
                .await
            })
        });

        // b reaches the relay only through the obfuscated port
        let obfs_b = std::net::UdpSocket::bind("127.0.0.1:0").expect("b's socket");
        obfs_b.connect(obfs_addr).expect("connect");
        obfs_b
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("timeout");
        let wrapper = Obfuscator::new(&key, padding);
        let rng = SystemRandom::new();
        let mut salts = Salts::default();
        let send = |message: &[u8]| {
            let mut wire = Vec::new();
            wrapper
                .wrap(&rng, now_ms(), message, &mut wire)
                .expect("wrap");
            obfs_b.send(&wire).expect("send");
        };
        let mut buf = [0u8; MAX_OBFS_DATAGRAM];
        let mut receive = |salts: &mut Salts| -> Option<Vec<u8>> {
            let len = obfs_b.recv(&mut buf).ok()?;
            let mut message = Vec::new();
            wrapper
                .unwrap(now_ms(), salts, &buf[..len], &mut message)
                .ok()?;
            Some(message)
        };

        obfs_b.send(&[0u8; 60]).expect("send garbage");
        assert_eq!(receive(&mut salts), None, "garbage gets no answer");

        let probe_key = ProbeKey::from_token(&[2; 32]);
        let probe = OuterProbe {
            kind: RELAY_PROBE,
            key_id: KeyId::of(&b),
            seq: 1,
            sent_ms: now_ms(),
        };
        send(&probe.encode(&probe_key));
        let reply = receive(&mut salts).expect("a wrapped reply to the probe");
        assert!(OuterReply::verify(&reply, &probe_key).is_some());

        let mut plain = [0u8; MAX_DATAGRAM];
        let init = initiation(11, &a);
        send(&init);
        let (len, _) = plain_a
            .recv_from(&mut plain)
            .expect("a gets the initiation");
        assert_eq!(plain[..len], init[..], "a gets it as WireGuard sent it");
        let resp = response(22, 11, &b);
        plain_a.send_to(&resp, relay_addr).expect("a answers");
        assert_eq!(
            receive(&mut salts),
            Some(resp),
            "b gets the response wrapped"
        );

        send(&data(22));
        let (len, _) = plain_a.recv_from(&mut plain).expect("a gets b's data");
        assert_eq!(plain[..len], data(22)[..]);
        plain_a.send_to(&data(11), relay_addr).expect("a's data");
        assert_eq!(
            receive(&mut salts),
            Some(data(11)),
            "b gets a's data wrapped"
        );

        stop.send(()).expect("relay still running");
        server.join().expect("server thread").expect("serve");
    }

    /// A member that offers its own obfuscated port is reached there from the relay's obfuscated
    /// port, wrapped with its key, and what comes from there is opened with it, so neither leg of
    /// the path is plain (design/obfuscation.md section 2); from that port, what does not open with
    /// the member's key gets nowhere.
    #[test]
    fn a_member_with_its_own_obfuscated_port_is_reached_there_with_its_key() {
        use crate::wg::tests::{data, initiation, response};
        use nett_mesh::obfs::{ObfsKey, Obfuscator, Padding, Salts};

        let (a, c) = ([1; 32], [3; 32]);
        let range = ObfsPadding { min: 8, max: 64 };
        let padding = Padding::new(8, 64).expect("padding");
        let (relay_key, c_key) = ([7u8; 32], [9u8; 32]);
        let socket = |timeout| {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("socket");
            s.set_read_timeout(Some(timeout)).expect("timeout");
            s
        };
        // a reaches the relay's obfuscated port; c listens on its own
        let (obfs_a, obfs_c) = (
            socket(Duration::from_millis(500)),
            socket(Duration::from_millis(500)),
        );
        let c_port = obfs_c.local_addr().expect("addr");
        let relay = Relay::new(
            &[
                AssignedMember {
                    public_key: X25519PublicKey::from_bytes(a),
                    address: None,
                    obfs: false,
                    token: [1; 32],
                },
                AssignedMember {
                    public_key: X25519PublicKey::from_bytes(c),
                    address: Some(c_port),
                    obfs: true,
                    token: [3; 32],
                },
            ],
            &[(
                X25519PublicKey::from_bytes(a),
                X25519PublicKey::from_bytes(c),
            )],
        )
        .expect("assignment");
        let udp = std::net::UdpSocket::bind("[::]:0").expect("relay socket");
        let obfs = std::net::UdpSocket::bind("[::]:0").expect("obfuscated socket");
        for s in [&udp, &obfs] {
            s.set_nonblocking(true).expect("nonblocking");
        }
        let obfs_addr = SocketAddr::from(([127, 0, 0, 1], obfs.local_addr().expect("addr").port()));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async move {
                let mut ingress = ObfsIngress {
                    socket: UdpSocket::from_std(obfs).expect("tokio socket"),
                    obfuscator: Obfuscator::new(&ObfsKey::from_bytes(relay_key), padding),
                    rng: SystemRandom::new(),
                    salts: Salts::default(),
                    members: HashMap::new(),
                };
                ingress.set_members(&[(c_port, ObfsSecret(c_key), range)]);
                let udp = UdpSocket::from_std(udp).expect("tokio socket");
                serve(udp, None, Some(ingress), relay, None, None, async {
                    drop(stopped.await);
                })
                .await
            })
        });

        let rng = SystemRandom::new();
        let with_relay = Obfuscator::new(&ObfsKey::from_bytes(relay_key), padding);
        let with_c = Obfuscator::new(&ObfsKey::from_bytes(c_key), padding);
        let wrap = |o: &Obfuscator, message: &[u8]| {
            let mut wire = Vec::new();
            o.wrap(&rng, now_ms(), message, &mut wire).expect("wrap");
            wire
        };
        let receive = |s: &std::net::UdpSocket, o: &Obfuscator, salts: &mut Salts| {
            let mut buf = [0u8; MAX_OBFS_DATAGRAM];
            let len = s.recv(&mut buf).ok()?;
            let mut message = Vec::new();
            o.unwrap(now_ms(), salts, &buf[..len], &mut message).ok()?;
            Some(message)
        };
        let (mut salts_a, mut salts_c) = (Salts::default(), Salts::default());

        let init = initiation(11, &c);
        obfs_a
            .send_to(&wrap(&with_relay, &init), obfs_addr)
            .expect("a's initiation");
        assert_eq!(
            receive(&obfs_c, &with_c, &mut salts_c),
            Some(init),
            "c gets it wrapped with its own key"
        );
        let resp = response(33, 11, &a);
        obfs_c
            .send_to(&wrap(&with_relay, &resp), obfs_addr)
            .expect("wrapped with the wrong key");
        assert_eq!(
            receive(&obfs_a, &with_relay, &mut salts_a),
            None,
            "from c's port only c's key opens"
        );
        obfs_c
            .send_to(&wrap(&with_c, &resp), obfs_addr)
            .expect("c answers");
        assert_eq!(receive(&obfs_a, &with_relay, &mut salts_a), Some(resp));
        obfs_a
            .send_to(&wrap(&with_relay, &data(33)), obfs_addr)
            .expect("a's data");
        assert_eq!(receive(&obfs_c, &with_c, &mut salts_c), Some(data(33)));
        obfs_c
            .send_to(&wrap(&with_c, &data(11)), obfs_addr)
            .expect("c's data");
        assert_eq!(receive(&obfs_a, &with_relay, &mut salts_a), Some(data(11)));

        stop.send(()).expect("relay still running");
        server.join().expect("server thread").expect("serve");
    }

    /// When the state write stalls (a named pipe with no reader stands in for a busy disk here),
    /// the relay keeps answering and forwarding.
    #[test]
    fn a_stuck_state_write_does_not_hold_up_forwarding() {
        let dir_tmp = tempfile::Builder::new()
            .prefix("nett-relay-save-")
            .tempdir()
            .expect("temp dir");
        let dir = dir_tmp.path().join("dir");
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let state = dir.join("relay-state.json");
        // The temporary file written first when saving is a pipe: opening it for writing blocks
        // until someone reads
        let fifo = state.with_extension("tmp");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(made.success(), "mkfifo failed");

        let (a, b) = ([1; 32], [2; 32]);
        let member = |k: [u8; 32], address| AssignedMember {
            public_key: X25519PublicKey::from_bytes(k),
            address,
            obfs: false,
            token: [k[0]; 32],
        };
        let relay = Relay::new(
            &[
                member(a, Some("198.51.100.1:41820".parse().expect("addr"))),
                member(b, None),
            ],
            &[(
                X25519PublicKey::from_bytes(a),
                X25519PublicKey::from_bytes(b),
            )],
        )
        .expect("assignment");

        // The relay port is dual-stack: replies are sent to the IPv6-mapped address
        let socket = std::net::UdpSocket::bind("[::]:0").expect("relay socket");
        socket.set_nonblocking(true).expect("nonblocking");
        let relay_addr =
            SocketAddr::from(([127, 0, 0, 1], socket.local_addr().expect("addr").port()));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server_state = state.clone();
        // Runs on a single-threaded runtime, like `nett relay`
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async move {
                let udp = UdpSocket::from_std(socket).expect("tokio socket");
                serve(udp, None, None, relay, Some(server_state), None, async {
                    drop(stopped.await);
                })
                .await
            })
        });

        // The first save happens about 1 second after startup; after that it stays stuck on the
        // pipe
        std::thread::sleep(SAVE_INTERVAL + Duration::from_millis(1_500));
        let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("client socket");
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("timeout");
        let key = ProbeKey::from_token(&[2; 32]);
        let probe = OuterProbe {
            kind: RELAY_PROBE,
            key_id: KeyId::of(&b),
            seq: 1,
            sent_ms: now_ms(),
        };
        client
            .send_to(&probe.encode(&key), relay_addr)
            .expect("send probe");
        let mut buf = [0u8; MAX_DATAGRAM];
        let replied = client
            .recv_from(&mut buf)
            .map(|(len, _)| OuterReply::verify(&buf[..len], &key).is_some());

        // Release the stalled write so the save before the relay exits can finish
        let reader = std::thread::spawn(move || std::fs::read(&fifo));
        stop.send(()).expect("relay still running");
        server.join().expect("server thread").expect("serve");
        reader
            .join()
            .expect("reader thread")
            .expect("read the pipe");
        let saved = load(&state).expect("load");
        std::fs::remove_dir_all(&dir).expect("clean up");

        assert!(
            matches!(replied, Ok(true)),
            "relay did not answer while saving was stuck: {replied:?}"
        );
        assert!(saved.is_some(), "state saved on exit");
    }
}
