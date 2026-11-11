//! WireGuard session layer (design/userspace.md section 3): handshakes, encryption/decryption and timers
//! for multiple peers, doing no I/O. The rest of the data plane uses it only through [`Sessions`]; the
//! implementation is gotatun's noise layer, and changing the implementation only changes this module.
//!
//! Dispatch among peers is done here: the side that initiates a handshake is recognized by the static
//! public key in the handshake message, and other messages are recognized by this end's session index.
//! An unknown public key is always dropped, and no session is created for it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use gotatun::noise::handshake::parse_handshake_anon;
use gotatun::noise::index_table::IndexTable;
use gotatun::noise::rate_limiter::RateLimiter;
use gotatun::noise::{Tunn, TunnResult};
use gotatun::packet::{Packet, WgKind};
use gotatun::tun::MtuWatcher;
use gotatun::x25519;
use nett_trust::keys::X25519PublicKey;

use crate::dataplane::MESH_MTU;
use crate::key::PrivateKey;

/// Interval for advancing timers (gotatun's timers work at this granularity).
pub const TIMER_TICK: Duration = Duration::from_millis(250);

/// Number of handshake initiations accepted per second; beyond it the peer is required to retry with a
/// cookie (WireGuard's load protection).
const HANDSHAKE_RATE_LIMIT: u64 = 100;

/// Actions the session layer asks the data plane to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Returned to the packet's source: handshake replies, cookie replies under load, and packets queued
    /// after the handshake completes.
    SendTo { to: SocketAddr, datagram: Vec<u8> },
    /// Sent to the peer's current endpoint: data, handshake initiation, keepalive.
    SendToPeer {
        peer: X25519PublicKey,
        datagram: Vec<u8>,
    },
    /// A packet from `from` passed authentication: the data plane updates this peer's endpoint accordingly
    /// (the same as kernel WireGuard).
    Authenticated {
        peer: X25519PublicKey,
        from: SocketAddr,
    },
    /// A decrypted inner packet, possibly with padding up to 16 bytes. A keepalive is an empty packet and
    /// produces no such item.
    Deliver {
        peer: X25519PublicKey,
        packet: Vec<u8>,
    },
}

pub trait Sessions {
    /// Makes the peers in the session layer exactly `peers` (public key and persistent keepalive interval, in
    /// seconds). An existing peer whose keepalive interval is unchanged keeps its session.
    fn sync(&mut self, peers: &[(X25519PublicKey, Option<u16>)]);
    /// Discards a peer's session: the next packet to it triggers a new handshake (design/mesh.md section
    /// 8.4).
    fn reset(&mut self, peer: &X25519PublicKey);
    /// Encrypts an inner packet addressed to `peer`; when there is no session yet, queues it and initiates a
    /// handshake.
    fn send(&mut self, peer: &X25519PublicKey, packet: &[u8], out: &mut Vec<Output>);
    /// Handles a WireGuard message (types 1-4) received from `from`.
    fn receive(&mut self, from: SocketAddr, datagram: &[u8], out: &mut Vec<Output>);
    /// Advances timers (re-handshake, keepalive, session expiry), called once every [`TIMER_TICK`].
    fn tick(&mut self, out: &mut Vec<Output>);
    /// Time since the most recent completed handshake; empty when none has completed since the peer joined or
    /// since [`Sessions::reset`].
    fn since_handshake(&self, peer: &X25519PublicKey) -> Option<Duration>;
}

struct Peer {
    tunn: Tunn,
    keepalive: Option<u16>,
}

/// [`Sessions`] on gotatun's noise layer.
pub struct Gotatun {
    private: x25519::StaticSecret,
    public: x25519::PublicKey,
    rate_limiter: Arc<RateLimiter>,
    index_table: IndexTable,
    peers: HashMap<X25519PublicKey, Peer>,
    /// This end's session index -> peer: registered when a handshake message is sent, and deleted when the
    /// index is no longer used. The count is bounded by the number of peers x sessions per peer.
    by_index: HashMap<u32, X25519PublicKey>,
    mtu: MtuWatcher,
}

impl Gotatun {
    pub fn new(private_key: &PrivateKey) -> Self {
        let private = x25519::StaticSecret::from(*private_key.as_bytes());
        let public = x25519::PublicKey::from(&private);
        Self {
            rate_limiter: Arc::new(RateLimiter::new(&public, HANDSHAKE_RATE_LIMIT)),
            private,
            public,
            index_table: IndexTable::from_os_rng(),
            peers: HashMap::new(),
            by_index: HashMap::new(),
            mtu: MtuWatcher::new(u16::try_from(MESH_MTU).unwrap_or(u16::MAX)),
        }
    }

    fn tunnel(&self, peer: &X25519PublicKey, keepalive: Option<u16>) -> Tunn {
        Tunn::new(
            self.private.clone(),
            x25519::PublicKey::from(*peer.as_bytes()),
            None,
            keepalive,
            self.index_table.clone(),
            Arc::clone(&self.rate_limiter),
        )
    }

    /// The local index in a sent handshake message, pointing to this peer.
    fn register(&mut self, packet: &WgKind, peer: X25519PublicKey) {
        let index = match packet {
            WgKind::HandshakeInit(p) => p.sender_idx.get(),
            WgKind::HandshakeResp(p) => p.sender_idx.get(),
            WgKind::CookieReply(_) | WgKind::Data(_) => return,
        };
        self.by_index.insert(index, peer);
    }

    fn peer_of(&self, packet: &WgKind) -> Option<X25519PublicKey> {
        match packet {
            WgKind::HandshakeInit(p) => parse_handshake_anon(&self.private, &self.public, p)
                .ok()
                .map(|h| X25519PublicKey::from_bytes(h.peer_static_public)),
            WgKind::HandshakeResp(p) => self.by_index.get(&p.receiver_idx.get()).copied(),
            WgKind::CookieReply(p) => self.by_index.get(&p.receiver_idx.get()).copied(),
            WgKind::Data(p) => self.by_index.get(&p.header.receiver_idx.get()).copied(),
        }
    }
}

fn bytes(packet: WgKind) -> Vec<u8> {
    Packet::from(packet).as_ref().to_vec()
}

impl Sessions for Gotatun {
    fn sync(&mut self, peers: &[(X25519PublicKey, Option<u16>)]) {
        self.peers.retain(|key, peer| {
            peers
                .iter()
                .any(|(k, ka)| k == key && *ka == peer.keepalive)
        });
        for (key, keepalive) in peers {
            if !self.peers.contains_key(key) {
                let tunn = self.tunnel(key, *keepalive);
                self.peers.insert(
                    *key,
                    Peer {
                        tunn,
                        keepalive: *keepalive,
                    },
                );
            }
        }
    }

    fn reset(&mut self, peer: &X25519PublicKey) {
        if let Some(keepalive) = self.peers.get(peer).map(|p| p.keepalive) {
            let tunn = self.tunnel(peer, keepalive);
            self.peers.insert(*peer, Peer { tunn, keepalive });
        }
    }

    fn send(&mut self, peer: &X25519PublicKey, packet: &[u8], out: &mut Vec<Output>) {
        let Some(p) = self.peers.get_mut(peer) else {
            return;
        };
        let packet = Packet::from_bytes(BytesMut::from(packet));
        if let Some(wg) = p.tunn.handle_outgoing_packet(packet, Some(&mut self.mtu)) {
            self.register(&wg, *peer);
            out.push(Output::SendToPeer {
                peer: *peer,
                datagram: bytes(wg),
            });
        }
    }

    fn receive(&mut self, from: SocketAddr, datagram: &[u8], out: &mut Vec<Output>) {
        let packet = Packet::from_bytes(BytesMut::from(datagram));
        let parsed = match self.rate_limiter.verify_packet(from, packet) {
            Ok(parsed) => parsed,
            // Under load, require the other side to retry with a cookie; this reply is not counted for any peer
            Err(TunnResult::WriteToNetwork(reply)) => {
                out.push(Output::SendTo {
                    to: from,
                    datagram: bytes(reply),
                });
                return;
            }
            Err(_) => return,
        };
        let Some(key) = self.peer_of(&parsed) else {
            return;
        };
        let Some(peer) = self.peers.get_mut(&key) else {
            return;
        };
        match peer.tunn.handle_incoming_packet(parsed) {
            TunnResult::WriteToNetwork(reply) => {
                out.push(Output::Authenticated { peer: key, from });
                let mut replies = vec![reply];
                replies.extend(peer.tunn.get_queued_packets(&mut self.mtu));
                for reply in replies {
                    self.register(&reply, key);
                    out.push(Output::SendTo {
                        to: from,
                        datagram: bytes(reply),
                    });
                }
            }
            TunnResult::WriteToTunnel(packet) => {
                out.push(Output::Authenticated { peer: key, from });
                if !packet.is_empty() {
                    out.push(Output::Deliver {
                        peer: key,
                        packet: packet.as_ref().to_vec(),
                    });
                }
            }
            // Authentication failure, replay, no session and so on: drop, with no response
            TunnResult::Done | TunnResult::Err(_) => {}
        }
    }

    fn tick(&mut self, out: &mut Vec<Output>) {
        self.rate_limiter.try_reset_count();
        let table = &self.index_table;
        self.by_index.retain(|index, _| table.in_use(*index));
        let mut sent = Vec::new();
        for (key, peer) in &mut self.peers {
            // Errors such as session expiry are handled by the timer itself, and the next packet initiates a new
            // handshake
            if let Ok(Some(packet)) = peer.tunn.update_timers() {
                sent.push((*key, packet));
            }
        }
        for (key, packet) in sent {
            self.register(&packet, key);
            out.push(Output::SendToPeer {
                peer: key,
                datagram: bytes(packet),
            });
        }
    }

    fn since_handshake(&self, peer: &X25519PublicKey) -> Option<Duration> {
        self.peers.get(peer).and_then(|p| p.tunn.stats().0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "198.51.100.1:41820";
    const B: &str = "198.51.100.2:41820";

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect(s)
    }

    struct Side {
        key: X25519PublicKey,
        sessions: Gotatun,
        addr: SocketAddr,
    }

    fn side(at: &str) -> Side {
        let private = PrivateKey::generate().expect("key");
        Side {
            key: private.public_key(),
            sessions: Gotatun::new(&private),
            addr: addr(at),
        }
    }

    fn pair() -> (Side, Side) {
        let (mut a, mut b) = (side(A), side(B));
        a.sessions.sync(&[(b.key, None)]);
        b.sessions.sync(&[(a.key, None)]);
        (a, b)
    }

    /// An IPv4/UDP packet, 48 bytes in total (a multiple of 16, so padding does not change it).
    fn ip_packet(tag: u8) -> Vec<u8> {
        let mut p = vec![0u8; 48];
        p[0] = 0x45;
        p[3] = 48;
        p[9] = 17;
        p[12..16].copy_from_slice(&[100, 88, 0, 1]);
        p[16..20].copy_from_slice(&[100, 88, 0, 2]);
        p[47] = tag;
        p
    }

    fn datagrams(out: &[Output]) -> Vec<Vec<u8>> {
        out.iter()
            .filter_map(|o| match o {
                Output::SendTo { datagram, .. } | Output::SendToPeer { datagram, .. } => {
                    Some(datagram.clone())
                }
                _ => None,
            })
            .collect()
    }

    /// Hands the packet sent by `from` to `to`, and returns `to`'s output.
    fn deliver(from: &Side, to: &mut Side, sent: &[Output]) -> Vec<Output> {
        let mut out = Vec::new();
        for d in datagrams(sent) {
            to.sessions.receive(from.addr, &d, &mut out);
        }
        out
    }

    #[test]
    fn handshake_then_data_with_queued_first_packet() {
        let (mut a, mut b) = pair();
        let mut out = Vec::new();
        // No session yet: the first packet is queued, and a handshake initiation is sent
        a.sessions.send(&b.key, &ip_packet(1), &mut out);
        assert_eq!(datagrams(&out).len(), 1);
        assert_eq!(datagrams(&out)[0][0], 1);

        let at_b = deliver(&a, &mut b, &out);
        assert!(at_b.contains(&Output::Authenticated {
            peer: a.key,
            from: a.addr
        }));
        let at_a = deliver(&b, &mut a, &at_b);
        // After the handshake reply: keepalive and queued packets
        assert!(at_a.contains(&Output::Authenticated {
            peer: b.key,
            from: b.addr
        }));
        assert_eq!(datagrams(&at_a).len(), 2, "{at_a:?}");
        let at_b = deliver(&a, &mut b, &at_a);
        assert!(at_b.contains(&Output::Deliver {
            peer: a.key,
            packet: ip_packet(1)
        }));
        assert!(a.sessions.since_handshake(&b.key).is_some());
        assert!(b.sessions.since_handshake(&a.key).is_some());

        // After the session is established, encrypt directly
        let mut out = Vec::new();
        b.sessions.send(&a.key, &ip_packet(2), &mut out);
        let at_a = deliver(&b, &mut a, &out);
        assert!(at_a.contains(&Output::Deliver {
            peer: b.key,
            packet: ip_packet(2)
        }));
    }

    #[test]
    fn unknown_keys_and_garbage_get_no_response() {
        let (mut a, _) = pair();
        let stranger = side("198.51.100.9:41820");
        let mut s = stranger.sessions;
        s.sync(&[(a.key, None)]);
        let mut out = Vec::new();
        s.send(&a.key, &ip_packet(1), &mut out);
        // a does not know this public key: no reply
        let mut at_a = Vec::new();
        for d in datagrams(&out) {
            a.sessions.receive(stranger.addr, &d, &mut at_a);
        }
        assert!(at_a.is_empty(), "{at_a:?}");
        for junk in [vec![], vec![1u8; 10], vec![4u8; 64], vec![0x82; 64]] {
            a.sessions.receive(stranger.addr, &junk, &mut at_a);
        }
        assert!(at_a.is_empty(), "{at_a:?}");
    }

    #[test]
    fn reset_drops_the_session_and_removed_peers_are_ignored() {
        let (mut a, mut b) = pair();
        let mut out = Vec::new();
        a.sessions.send(&b.key, &ip_packet(1), &mut out);
        let at_b = deliver(&a, &mut b, &out);
        deliver(&b, &mut a, &at_b);
        assert!(a.sessions.since_handshake(&b.key).is_some());

        a.sessions.reset(&b.key);
        assert!(a.sessions.since_handshake(&b.key).is_none());
        let mut out = Vec::new();
        a.sessions.send(&b.key, &ip_packet(2), &mut out);
        assert_eq!(datagrams(&out)[0][0], 1, "a new handshake initiation");

        // After b deletes a, a's handshake no longer gets a reply
        b.sessions.sync(&[]);
        assert!(deliver(&a, &mut b, &out).is_empty());
    }

    #[test]
    fn keepalive_change_recreates_only_that_peer() {
        let (mut a, mut b) = pair();
        let mut out = Vec::new();
        a.sessions.send(&b.key, &ip_packet(1), &mut out);
        let at_b = deliver(&a, &mut b, &out);
        deliver(&b, &mut a, &at_b);
        a.sessions.sync(&[(b.key, None)]);
        assert!(a.sessions.since_handshake(&b.key).is_some());
        a.sessions.sync(&[(b.key, Some(25))]);
        assert!(a.sessions.since_handshake(&b.key).is_none());
    }
}
