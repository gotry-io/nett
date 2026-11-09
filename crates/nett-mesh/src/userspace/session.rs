//! WireGuard 会话层（design/userspace.md 第 3 节）：多个对端的握手、加解密与定时，不做 I/O。数据面的其他
//! 部分只经 [`Sessions`] 使用它；实现是 gotatun 的 noise 层，换实现只改这个模块。
//!
//! 对端之间的分发在这里完成：发起握手的一方按握手消息中的静态公钥认出，其他消息按本端的会话索引认出。
//! 不认识的公钥一律丢弃，不为它创建会话。

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

/// 推进定时器的间隔（gotatun 的定时器按这个粒度工作）。
pub const TIMER_TICK: Duration = Duration::from_millis(250);

/// 每秒接受的握手发起数，超过时要求对方带 cookie 重试（WireGuard 的负载保护）。
const HANDSHAKE_RATE_LIMIT: u64 = 100;

/// 会话层要求数据面执行的动作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// 回给包的来源：握手应答、负载时的 cookie 应答，以及握手完成后排队的包。
    SendTo { to: SocketAddr, datagram: Vec<u8> },
    /// 发往对端当前的 endpoint：数据、发起握手、保活。
    SendToPeer {
        peer: X25519PublicKey,
        datagram: Vec<u8>,
    },
    /// 来自 `from` 的包通过了认证：数据面据此更新这个对端的 endpoint（与内核 WireGuard 相同）。
    Authenticated {
        peer: X25519PublicKey,
        from: SocketAddr,
    },
    /// 解密出的内层包，可能带有补齐到 16 字节的填充。保活是空包，不产生这一项。
    Deliver {
        peer: X25519PublicKey,
        packet: Vec<u8>,
    },
}

pub trait Sessions {
    /// 让会话层中的对端恰好是 `peers`（公钥与持久保活间隔，秒）。已有且保活间隔不变的对端保留会话。
    fn sync(&mut self, peers: &[(X25519PublicKey, Option<u16>)]);
    /// 丢弃一个对端的会话：下一个发往它的包触发新的握手（design/mesh.md 第 8.4 节）。
    fn reset(&mut self, peer: &X25519PublicKey);
    /// 加密一个发往 `peer` 的内层包；还没有会话时排队并发起握手。
    fn send(&mut self, peer: &X25519PublicKey, packet: &[u8], out: &mut Vec<Output>);
    /// 处理从 `from` 收到的一个 WireGuard 消息（类型 1–4）。
    fn receive(&mut self, from: SocketAddr, datagram: &[u8], out: &mut Vec<Output>);
    /// 推进定时器（重新握手、保活、会话过期），每 [`TIMER_TICK`] 调用一次。
    fn tick(&mut self, out: &mut Vec<Output>);
    /// 距最近一次完成握手的时间；对端加入或 [`Sessions::reset`] 以来还没有完成过时为空。
    fn since_handshake(&self, peer: &X25519PublicKey) -> Option<Duration>;
}

struct Peer {
    tunn: Tunn,
    keepalive: Option<u16>,
}

/// gotatun 的 noise 层上的 [`Sessions`]。
pub struct Gotatun {
    private: x25519::StaticSecret,
    public: x25519::PublicKey,
    rate_limiter: Arc<RateLimiter>,
    index_table: IndexTable,
    peers: HashMap<X25519PublicKey, Peer>,
    /// 本端的会话索引 → 对端：发出握手消息时登记，索引不再使用时删除。条数受对端数 × 每个对端的会话数
    /// 限制。
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

    /// 发出的握手消息中的本端索引，指向这个对端。
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
            // 负载时要求对方带 cookie 重试；这条应答不计入任何对端
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
            // 认证失败、重放、没有会话等：丢弃，不作响应
            TunnResult::Done | TunnResult::Err(_) => {}
        }
    }

    fn tick(&mut self, out: &mut Vec<Output>) {
        self.rate_limiter.try_reset_count();
        let table = &self.index_table;
        self.by_index.retain(|index, _| table.in_use(*index));
        let mut sent = Vec::new();
        for (key, peer) in &mut self.peers {
            // 会话过期等错误由定时器自己处理，下一个包会发起新的握手
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

    /// 一个 IPv4/UDP 包，总长 48 字节（16 的倍数，填充不改变它）。
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

    /// 把 `from` 发出的包交给 `to`，返回 `to` 的输出。
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
        // 还没有会话：第一个包排队，发出握手发起
        a.sessions.send(&b.key, &ip_packet(1), &mut out);
        assert_eq!(datagrams(&out).len(), 1);
        assert_eq!(datagrams(&out)[0][0], 1);

        let at_b = deliver(&a, &mut b, &out);
        assert!(at_b.contains(&Output::Authenticated {
            peer: a.key,
            from: a.addr
        }));
        let at_a = deliver(&b, &mut a, &at_b);
        // 握手应答之后：保活与排队的包
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

        // 会话建立之后直接加密
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
        // a 不认识这个公钥：不应答
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

        // b 删掉 a 之后，a 的握手不再得到应答
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
