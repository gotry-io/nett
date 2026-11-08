//! 中继需要读懂的 WireGuard 消息头（WireGuard 白皮书第 5.4 节）。中继不持有任何密钥，只读类型、
//! 会话索引和 `mac1`。

use blake2::digest::consts::U16;
use blake2::digest::{Digest as _, KeyInit as _, Mac as _};
use blake2::{Blake2s256, Blake2sMac};

pub const HANDSHAKE_INITIATION: u8 = 1;
pub const HANDSHAKE_RESPONSE: u8 = 2;
pub const COOKIE_REPLY: u8 = 3;
pub const TRANSPORT_DATA: u8 = 4;

const INITIATION_LEN: usize = 148;
const RESPONSE_LEN: usize = 92;
const COOKIE_LEN: usize = 64;
/// 数据消息的最小长度：头部 16 字节加上认证标签 16 字节（保活包没有负载）。
const DATA_MIN_LEN: usize = 32;
const LABEL_MAC1: &[u8] = b"mac1----";

/// WireGuard 的会话索引（发送方选择，小端序）。
pub type Index = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message<'a> {
    /// `sender`：发起方的索引；`mac1` 覆盖的内容与 `mac1` 本身。
    Initiation {
        sender: Index,
        signed: &'a [u8],
        mac1: &'a [u8],
    },
    Response {
        sender: Index,
        receiver: Index,
        signed: &'a [u8],
        mac1: &'a [u8],
    },
    Cookie {
        receiver: Index,
    },
    Data {
        receiver: Index,
    },
}

fn index(b: &[u8], at: usize) -> Index {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// 解析一个 UDP 负载；不是 WireGuard 消息时返回 `None`。
pub fn parse(b: &[u8]) -> Option<Message<'_>> {
    if b.len() < 4 || b[1..4] != [0, 0, 0] {
        return None;
    }
    match (b[0], b.len()) {
        (HANDSHAKE_INITIATION, INITIATION_LEN) => Some(Message::Initiation {
            sender: index(b, 4),
            signed: &b[..116],
            mac1: &b[116..132],
        }),
        (HANDSHAKE_RESPONSE, RESPONSE_LEN) => Some(Message::Response {
            sender: index(b, 4),
            receiver: index(b, 8),
            signed: &b[..60],
            mac1: &b[60..76],
        }),
        (COOKIE_REPLY, COOKIE_LEN) => Some(Message::Cookie {
            receiver: index(b, 4),
        }),
        (TRANSPORT_DATA, n) if n >= DATA_MIN_LEN => Some(Message::Data {
            receiver: index(b, 4),
        }),
        _ => None,
    }
}

/// 以某个接收方公钥计算 `mac1` 用的密钥：`HASH("mac1----" ‖ 公钥)`。每个成员算一次，之后复用。
#[derive(Clone)]
pub struct Mac1Key([u8; 32]);

impl Mac1Key {
    pub fn for_public_key(public_key: &[u8; 32]) -> Self {
        let mut h = Blake2s256::new();
        h.update(LABEL_MAC1);
        h.update(public_key);
        Self(h.finalize().into())
    }

    /// `mac1 = MAC(密钥, 消息中 mac1 之前的部分)`，MAC 为 16 字节输出的带密钥 BLAKE2s。
    pub fn matches(&self, signed: &[u8], mac1: &[u8]) -> bool {
        let Ok(mut mac) = Blake2sMac::<U16>::new_from_slice(&self.0) else {
            return false;
        };
        mac.update(signed);
        // mac1 不是机密：它只用来确定接收方，比较不需要常量时间
        mac.finalize().into_bytes().as_slice() == mac1
    }

    /// 计算 `mac1`：测试和实验工具（场景 20 的洪泛）用来构造握手发起。
    #[cfg(any(test, feature = "lab"))]
    pub fn compute(&self, signed: &[u8]) -> [u8; 16] {
        let mut mac = Blake2sMac::<U16>::new_from_slice(&self.0).expect("32-byte key");
        mac.update(signed);
        mac.finalize().into_bytes().into()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// 构造一个 `mac1` 正确、其余内容随意的握手发起。
    pub fn initiation(sender: Index, receiver_public: &[u8; 32]) -> Vec<u8> {
        let mut b = vec![0u8; INITIATION_LEN];
        b[0] = HANDSHAKE_INITIATION;
        b[4..8].copy_from_slice(&sender.to_le_bytes());
        b[8..116].fill(0xab);
        let mac = Mac1Key::for_public_key(receiver_public).compute(&b[..116]);
        b[116..132].copy_from_slice(&mac);
        b
    }

    pub fn response(sender: Index, receiver: Index, initiator_public: &[u8; 32]) -> Vec<u8> {
        let mut b = vec![0u8; RESPONSE_LEN];
        b[0] = HANDSHAKE_RESPONSE;
        b[4..8].copy_from_slice(&sender.to_le_bytes());
        b[8..12].copy_from_slice(&receiver.to_le_bytes());
        b[12..60].fill(0xcd);
        let mac = Mac1Key::for_public_key(initiator_public).compute(&b[..60]);
        b[60..76].copy_from_slice(&mac);
        b
    }

    pub fn data(receiver: Index) -> Vec<u8> {
        let mut b = vec![0u8; DATA_MIN_LEN + 16];
        b[0] = TRANSPORT_DATA;
        b[4..8].copy_from_slice(&receiver.to_le_bytes());
        b
    }

    #[test]
    fn parses_message_headers() {
        let init = initiation(7, &[1; 32]);
        let Some(Message::Initiation {
            sender,
            signed,
            mac1,
        }) = parse(&init)
        else {
            panic!("initiation");
        };
        assert_eq!(sender, 7);
        assert!(Mac1Key::for_public_key(&[1; 32]).matches(signed, mac1));
        assert!(!Mac1Key::for_public_key(&[2; 32]).matches(signed, mac1));
        assert_eq!(parse(&data(9)), Some(Message::Data { receiver: 9 }));
        assert_eq!(parse(&init[..147]), None);
        assert_eq!(parse(&[0x90; 64]), None, "probe messages are not WireGuard");
    }
}
