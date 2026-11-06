//! 单端口转发（design/mesh.md 第 5.1、5.2 节）：按 `mac1` 和会话索引判断去向，按握手应答更新成员地址。
//!
//! 纯逻辑：时间由调用方传入，返回要做的事；收发由 [`crate::server`] 负责。

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use nett_mesh::probe::{KeyId, OuterProbe, ProbeKey, RELAY_PROBE};
use nett_trust::keys::X25519PublicKey;

use crate::wg::{self, Index, Mac1Key, Message};

/// 一个中继最多服务的成员数：握手发起时要逐个试算 `mac1`。
pub const MAX_MEMBERS: usize = 1024;
/// 待定表项与正式表项的上限。
const MAX_PENDING: usize = 4096;
const MAX_SESSIONS: usize = 16 * 1024;
/// 待定表项的寿命：WireGuard 5 秒后会以新索引重试握手。
const PENDING_TTL: Duration = Duration::from_secs(5);
/// 会话空闲多久后删除：WireGuard 的会话最长 180 秒（REJECT_AFTER_TIME），过后必然重新握手。
const SESSION_IDLE: Duration = Duration::from_secs(180);
/// 同一个成员两次绑定变化的最短间隔。
const BIND_MIN_INTERVAL: Duration = Duration::from_secs(1);
/// 新绑定后这么久收不到来自新地址的数据，恢复旧绑定。
const BIND_CONFIRM: Duration = Duration::from_secs(10);

/// 保存状态的格式版本。
const STATE_V1: u32 = 1;

/// 重启时恢复的状态（design/mesh.md 第 5.2 节）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayState {
    pub v: u32,
    pub bindings: Vec<Binding>,
    pub sessions: Vec<SavedSession>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub public_key: X25519PublicKey,
    pub address: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedSession {
    pub index: Index,
    pub owner: X25519PublicKey,
    /// 保存时已经空闲了多久。
    pub idle_ms: u64,
}

/// 中继分配中的一个成员（design/mesh.md 第 5.2 节）。
#[derive(Debug, Clone)]
pub struct AssignedMember {
    pub public_key: X25519PublicKey,
    /// `public` 成员的地址随分配下发；`dial-only` 成员的地址取自它发来的第一份握手消息。
    pub address: Option<SocketAddr>,
    pub token: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AssignmentError {
    #[error("assignment has {0} members, more than {MAX_MEMBERS}")]
    TooManyMembers(usize),
    #[error("member {0} is listed twice")]
    DuplicateMember(X25519PublicKey),
    #[error("connection names member {0}, which is not in the assignment")]
    UnknownMember(X25519PublicKey),
}

/// 丢弃的原因，供计数和排障；中继对被丢弃的包不作任何响应。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drop {
    NotWireGuard,
    UnknownReceiver,
    ReceiverUnbound,
    IndexCollision,
    TableFull,
    NoPending,
    ResponseFromUnbound,
    NotAssigned,
    BindRateLimited,
    UnknownIndex,
    BadProbe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// 原样转发到这个地址。
    Forward(SocketAddr),
    /// 回给来源一份应答（探测）。
    Reply(Vec<u8>),
    Drop(Drop),
}

struct Member {
    public_key: X25519PublicKey,
    mac1: Mac1Key,
    key_id: KeyId,
    probe_key: ProbeKey,
    bound: Option<SocketAddr>,
    /// 绑定变化后尚未被新地址上的数据确认：变化前的地址与变化时刻。
    unconfirmed: Option<(Option<SocketAddr>, Instant)>,
    last_change: Option<Instant>,
}

struct Pending {
    src: SocketAddr,
    receiver: usize,
    at: Instant,
}

struct Session {
    owner: usize,
    at: Instant,
}

pub struct Relay {
    members: Vec<Member>,
    connections: HashSet<(usize, usize)>,
    pending: HashMap<Index, Pending>,
    sessions: HashMap<Index, Session>,
}

fn pair(a: usize, b: usize) -> (usize, usize) {
    (a.min(b), a.max(b))
}

impl Relay {
    pub fn new(
        members: &[AssignedMember],
        connections: &[(X25519PublicKey, X25519PublicKey)],
    ) -> Result<Self, AssignmentError> {
        if members.len() > MAX_MEMBERS {
            return Err(AssignmentError::TooManyMembers(members.len()));
        }
        let mut seen = HashSet::new();
        for m in members {
            if !seen.insert(m.public_key) {
                return Err(AssignmentError::DuplicateMember(m.public_key));
            }
        }
        let position = |key: &X25519PublicKey| {
            members
                .iter()
                .position(|m| m.public_key == *key)
                .ok_or(AssignmentError::UnknownMember(*key))
        };
        let connections = connections
            .iter()
            .map(|(a, b)| Ok(pair(position(a)?, position(b)?)))
            .collect::<Result<_, AssignmentError>>()?;
        Ok(Self {
            members: members
                .iter()
                .map(|m| Member {
                    public_key: m.public_key,
                    mac1: Mac1Key::for_public_key(m.public_key.as_bytes()),
                    key_id: KeyId::of(m.public_key.as_bytes()),
                    probe_key: ProbeKey::from_token(&m.token),
                    bound: m.address,
                    unconfirmed: None,
                    last_change: None,
                })
                .collect(),
            connections,
            pending: HashMap::new(),
            sessions: HashMap::new(),
        })
    }

    /// 处理一个来自 `from` 的 UDP 负载。`from` 中的 IPv4 映射地址由调用方先还原为 IPv4。
    pub fn handle(
        &mut self,
        from: SocketAddr,
        packet: &[u8],
        now: Instant,
        now_ms: u64,
    ) -> Outcome {
        if packet.first() == Some(&RELAY_PROBE) {
            return self.probe(from, packet, now_ms);
        }
        let Some(message) = wg::parse(packet) else {
            return Outcome::Drop(Drop::NotWireGuard);
        };
        match message {
            Message::Initiation {
                sender,
                signed,
                mac1,
            } => self.initiation(from, sender, signed, mac1, now),
            Message::Response {
                sender,
                receiver,
                signed,
                mac1,
            } => self.response(from, sender, receiver, signed, mac1, now),
            Message::Cookie { receiver } => {
                if let Some(p) = self.pending.get(&receiver) {
                    Outcome::Forward(p.src)
                } else {
                    self.forward_to_owner(receiver, now)
                }
            }
            Message::Data { receiver } => {
                self.confirm_binding(from);
                self.forward_to_owner(receiver, now)
            }
        }
    }

    fn find_by_mac1(&self, signed: &[u8], mac1: &[u8]) -> Option<usize> {
        self.members
            .iter()
            .position(|m| m.mac1.matches(signed, mac1))
    }

    fn index_taken(&self, index: Index, src: SocketAddr) -> bool {
        self.sessions.contains_key(&index) || self.pending.get(&index).is_some_and(|p| p.src != src)
    }

    fn initiation(
        &mut self,
        from: SocketAddr,
        sender: Index,
        signed: &[u8],
        mac1: &[u8],
        now: Instant,
    ) -> Outcome {
        let Some(receiver) = self.find_by_mac1(signed, mac1) else {
            return Outcome::Drop(Drop::UnknownReceiver);
        };
        let Some(dest) = self.members[receiver].bound else {
            return Outcome::Drop(Drop::ReceiverUnbound);
        };
        // 会话索引冲突：丢弃，WireGuard 会以新索引重试
        if self.index_taken(sender, from) {
            return Outcome::Drop(Drop::IndexCollision);
        }
        if self.pending.len() >= MAX_PENDING && !self.pending.contains_key(&sender) {
            return Outcome::Drop(Drop::TableFull);
        }
        self.pending.insert(
            sender,
            Pending {
                src: from,
                receiver,
                at: now,
            },
        );
        Outcome::Forward(dest)
    }

    fn response(
        &mut self,
        from: SocketAddr,
        sender: Index,
        receiver: Index,
        signed: &[u8],
        mac1: &[u8],
        now: Instant,
    ) -> Outcome {
        let Some(initiator) = self.find_by_mac1(signed, mac1) else {
            return Outcome::Drop(Drop::UnknownReceiver);
        };
        let Some(pending) = self.pending.get(&receiver) else {
            return Outcome::Drop(Drop::NoPending);
        };
        let responder = pending.receiver;
        // 握手应答只接受来自应答方当前绑定地址的
        if self.members[responder].bound != Some(from) {
            return Outcome::Drop(Drop::ResponseFromUnbound);
        }
        if !self.connections.contains(&pair(initiator, responder)) {
            return Outcome::Drop(Drop::NotAssigned);
        }
        if self.sessions.contains_key(&sender) || self.pending.contains_key(&sender) {
            return Outcome::Drop(Drop::IndexCollision);
        }
        if self.sessions.len() + 2 > MAX_SESSIONS {
            return Outcome::Drop(Drop::TableFull);
        }
        // 对端针对发起方的新地址发回了应答：更新发起方的绑定（限速，之后等新地址上的数据确认）
        let new_addr = pending.src;
        let member = &mut self.members[initiator];
        if member.bound != Some(new_addr) {
            if member
                .last_change
                .is_some_and(|t| now.saturating_duration_since(t) < BIND_MIN_INTERVAL)
            {
                return Outcome::Drop(Drop::BindRateLimited);
            }
            member.unconfirmed = Some((member.bound, now));
            member.bound = Some(new_addr);
            member.last_change = Some(now);
        }
        self.pending.remove(&receiver);
        self.sessions.insert(
            receiver,
            Session {
                owner: initiator,
                at: now,
            },
        );
        self.sessions.insert(
            sender,
            Session {
                owner: responder,
                at: now,
            },
        );
        Outcome::Forward(new_addr)
    }

    fn forward_to_owner(&mut self, receiver: Index, now: Instant) -> Outcome {
        let Some(session) = self.sessions.get_mut(&receiver) else {
            return Outcome::Drop(Drop::UnknownIndex);
        };
        session.at = now;
        match self.members[session.owner].bound {
            Some(dest) => Outcome::Forward(dest),
            None => Outcome::Drop(Drop::ReceiverUnbound),
        }
    }

    /// 新地址上来了数据：绑定得到确认。
    fn confirm_binding(&mut self, from: SocketAddr) {
        for m in &mut self.members {
            if m.unconfirmed.is_some() && m.bound == Some(from) {
                m.unconfirmed = None;
            }
        }
    }

    fn probe(&self, from: SocketAddr, packet: &[u8], now_ms: u64) -> Outcome {
        let Some(head) = OuterProbe::peek(packet) else {
            return Outcome::Drop(Drop::BadProbe);
        };
        let Some(member) = self.members.iter().find(|m| m.key_id == head.key_id) else {
            return Outcome::Drop(Drop::BadProbe);
        };
        match OuterProbe::verify(packet, &member.probe_key, now_ms) {
            Some(probe) if probe.kind == RELAY_PROBE => {
                let reply = probe.reply(member.key_id, from).encode(&member.probe_key);
                Outcome::Reply(reply.to_vec())
            }
            _ => Outcome::Drop(Drop::BadProbe),
        }
    }

    /// 定期调用：清理过期的表项，恢复未被确认的绑定。
    pub fn expire(&mut self, now: Instant) {
        self.pending
            .retain(|_, p| now.saturating_duration_since(p.at) < PENDING_TTL);
        self.sessions
            .retain(|_, s| now.saturating_duration_since(s.at) < SESSION_IDLE);
        for m in &mut self.members {
            if let Some((previous, at)) = m.unconfirmed
                && now.saturating_duration_since(at) >= BIND_CONFIRM
            {
                m.bound = previous;
                m.unconfirmed = None;
            }
        }
    }

    /// 要保存的状态：地址绑定与正式表项（design/mesh.md 第 5.2 节）。只有会话索引和地址，没有密钥。
    pub fn snapshot(&self, now: Instant) -> RelayState {
        RelayState {
            v: STATE_V1,
            bindings: self
                .members
                .iter()
                .filter_map(|m| {
                    m.bound.map(|addr| Binding {
                        public_key: m.public_key,
                        address: addr,
                    })
                })
                .collect(),
            sessions: self
                .sessions
                .iter()
                .map(|(index, s)| SavedSession {
                    index: *index,
                    owner: self.members[s.owner].public_key,
                    idle_ms: u64::try_from(now.saturating_duration_since(s.at).as_millis())
                        .unwrap_or(u64::MAX),
                })
                .collect(),
        }
    }

    /// 恢复保存的状态。只恢复仍在分配中的成员，过期或冲突的表项丢弃。
    pub fn restore(&mut self, state: &RelayState, now: Instant) {
        if state.v != STATE_V1 {
            return;
        }
        let find = |members: &[Member], key: &X25519PublicKey| {
            members.iter().position(|m| m.public_key == *key)
        };
        for b in &state.bindings {
            if let Some(i) = find(&self.members, &b.public_key) {
                self.members[i].bound = Some(b.address);
            }
        }
        for saved in &state.sessions {
            let idle = Duration::from_millis(saved.idle_ms);
            let Some(owner) = find(&self.members, &saved.owner) else {
                continue;
            };
            if idle >= SESSION_IDLE
                || self.sessions.len() >= MAX_SESSIONS
                || self.sessions.contains_key(&saved.index)
            {
                continue;
            }
            let at = now.checked_sub(idle).unwrap_or(now);
            self.sessions.insert(saved.index, Session { owner, at });
        }
    }

    pub fn table_sizes(&self) -> (usize, usize) {
        (self.pending.len(), self.sessions.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wg::tests::{data, initiation, response};
    use nett_mesh::probe::{OuterReply, RELAY_REPLY};

    const A: [u8; 32] = [1; 32];
    const B: [u8; 32] = [2; 32];
    const C: [u8; 32] = [3; 32];

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("addr")
    }

    /// A 是 `public`（地址随分配下发），B、C 是 `dial-only`；只分配了 A–B。
    fn relay() -> Relay {
        let member = |k: [u8; 32], a: Option<&str>| AssignedMember {
            public_key: X25519PublicKey::from_bytes(k),
            address: a.map(addr),
            token: [k[0]; 32],
        };
        Relay::new(
            &[
                member(A, Some("198.51.100.1:41820")),
                member(B, None),
                member(C, None),
            ],
            &[(
                X25519PublicKey::from_bytes(A),
                X25519PublicKey::from_bytes(B),
            )],
        )
        .expect("assignment")
    }

    fn handshake(r: &mut Relay, b_addr: &str, now: Instant, b_idx: Index, a_idx: Index) {
        assert_eq!(
            r.handle(addr(b_addr), &initiation(b_idx, &A), now, 0),
            Outcome::Forward(addr("198.51.100.1:41820"))
        );
        assert_eq!(
            r.handle(
                addr("198.51.100.1:41820"),
                &response(a_idx, b_idx, &B),
                now,
                0
            ),
            Outcome::Forward(addr(b_addr))
        );
    }

    #[test]
    fn forwards_handshake_and_data_and_binds_dial_only_member() {
        let mut r = relay();
        let now = Instant::now();
        handshake(&mut r, "203.0.113.5:50000", now, 11, 22);
        // A → B：按接收方索引 11（B 的）送到 B 刚绑定的地址
        assert_eq!(
            r.handle(addr("198.51.100.1:41820"), &data(11), now, 0),
            Outcome::Forward(addr("203.0.113.5:50000"))
        );
        assert_eq!(
            r.handle(addr("203.0.113.5:50000"), &data(22), now, 0),
            Outcome::Forward(addr("198.51.100.1:41820"))
        );
        assert_eq!(
            r.handle(addr("203.0.113.5:50000"), &data(33), now, 0),
            Outcome::Drop(Drop::UnknownIndex)
        );
    }

    #[test]
    fn rejects_unassigned_pairs_and_unknown_receivers() {
        let mut r = relay();
        let now = Instant::now();
        // C 与 A 没有分配：A 的应答不被接受
        assert!(matches!(
            r.handle(addr("203.0.113.9:1"), &initiation(5, &A), now, 0),
            Outcome::Forward(_)
        ));
        assert_eq!(
            r.handle(addr("198.51.100.1:41820"), &response(6, 5, &C), now, 0),
            Outcome::Drop(Drop::NotAssigned)
        );
        // 接收方不是任何成员
        assert_eq!(
            r.handle(addr("203.0.113.9:1"), &initiation(7, &[9; 32]), now, 0),
            Outcome::Drop(Drop::UnknownReceiver)
        );
        // 接收方还没有地址
        assert_eq!(
            r.handle(addr("198.51.100.1:41820"), &initiation(8, &B), now, 0),
            Outcome::Drop(Drop::ReceiverUnbound)
        );
    }

    #[test]
    fn response_must_come_from_the_bound_address() {
        let mut r = relay();
        let now = Instant::now();
        r.handle(addr("203.0.113.5:50000"), &initiation(11, &A), now, 0);
        assert_eq!(
            r.handle(addr("192.0.2.66:41820"), &response(22, 11, &B), now, 0),
            Outcome::Drop(Drop::ResponseFromUnbound)
        );
    }

    #[test]
    fn index_collisions_drop_the_newcomer() {
        let mut r = relay();
        let now = Instant::now();
        handshake(&mut r, "203.0.113.5:50000", now, 11, 22);
        assert_eq!(
            r.handle(addr("203.0.113.7:50000"), &initiation(22, &A), now, 0),
            Outcome::Drop(Drop::IndexCollision)
        );
    }

    #[test]
    fn rebinding_needs_data_from_the_new_address() {
        let mut r = relay();
        let t0 = Instant::now();
        handshake(&mut r, "203.0.113.5:50000", t0, 11, 22);
        r.handle(addr("203.0.113.5:50000"), &data(22), t0, 0);
        // B 换了地址并重新握手；之后新地址上一直没有数据：10 秒后恢复旧绑定
        let t1 = t0 + Duration::from_secs(30);
        handshake(&mut r, "203.0.113.6:50001", t1, 13, 24);
        r.expire(t1 + BIND_CONFIRM);
        assert_eq!(
            r.handle(addr("198.51.100.1:41820"), &data(11), t1 + BIND_CONFIRM, 0),
            Outcome::Forward(addr("203.0.113.5:50000"))
        );
    }

    #[test]
    fn rebinding_is_rate_limited() {
        let mut r = relay();
        let t0 = Instant::now();
        handshake(&mut r, "203.0.113.5:50000", t0, 11, 22);
        r.handle(addr("203.0.113.6:50001"), &initiation(13, &A), t0, 0);
        assert_eq!(
            r.handle(
                addr("198.51.100.1:41820"),
                &response(24, 13, &B),
                t0 + Duration::from_millis(500),
                0
            ),
            Outcome::Drop(Drop::BindRateLimited)
        );
    }

    #[test]
    fn expires_idle_entries() {
        let mut r = relay();
        let t0 = Instant::now();
        handshake(&mut r, "203.0.113.5:50000", t0, 11, 22);
        r.handle(addr("203.0.113.9:1"), &initiation(40, &A), t0, 0);
        assert_eq!(r.table_sizes(), (1, 2));
        r.expire(t0 + PENDING_TTL);
        assert_eq!(r.table_sizes(), (0, 2));
        r.expire(t0 + SESSION_IDLE);
        assert_eq!(r.table_sizes(), (0, 0));
    }

    #[test]
    fn restored_state_keeps_forwarding() {
        let mut r = relay();
        let now = Instant::now();
        handshake(&mut r, "203.0.113.5:50000", now, 11, 22);
        let saved = r.snapshot(now + Duration::from_secs(1));
        let text = serde_json::to_string(&saved).expect("serialize");
        // 重启：新的中继只有分配，没有索引表；恢复后照常转发两个方向的数据
        let mut restarted = relay();
        assert_eq!(
            restarted.handle(addr("198.51.100.1:41820"), &data(11), now, 0),
            Outcome::Drop(Drop::UnknownIndex)
        );
        restarted.restore(&serde_json::from_str(&text).expect("parse"), now);
        assert_eq!(
            restarted.handle(addr("198.51.100.1:41820"), &data(11), now, 0),
            Outcome::Forward(addr("203.0.113.5:50000"))
        );
        assert_eq!(
            restarted.handle(addr("203.0.113.5:50000"), &data(22), now, 0),
            Outcome::Forward(addr("198.51.100.1:41820"))
        );
        // 已经过期的表项不恢复
        let mut stale = relay();
        stale.restore(&r.snapshot(now + SESSION_IDLE), now);
        assert_eq!(stale.table_sizes(), (0, 0));
    }

    #[test]
    fn answers_authenticated_probes_only() {
        let r = relay();
        let key = ProbeKey::from_token(&[2; 32]);
        let id = KeyId::of(&B);
        let probe = OuterProbe {
            kind: RELAY_PROBE,
            key_id: id,
            seq: 4,
            sent_ms: 1_000,
        };
        let from = addr("203.0.113.5:40000");
        let Outcome::Reply(reply) = r.probe(from, &probe.encode(&key), 1_000) else {
            panic!("expected a reply");
        };
        let decoded = OuterReply::verify(&reply, &key).expect("valid reply");
        assert_eq!(
            (decoded.kind, decoded.seq, decoded.observed),
            (RELAY_REPLY, 4, from)
        );
        // 用另一个成员的令牌
        let wrong = probe.encode(&ProbeKey::from_token(&[3; 32]));
        assert_eq!(r.probe(from, &wrong, 1_000), Outcome::Drop(Drop::BadProbe));
        // 过期
        assert_eq!(
            r.probe(from, &probe.encode(&key), 100_000),
            Outcome::Drop(Drop::BadProbe)
        );
    }
}
