//! Minimal netlink implementation: encodes only the few kinds of messages the mesh process uses
//! (rtnetlink interfaces and addresses, WireGuard's generic netlink).
//!
//! For the message format see Linux's `include/uapi/linux/netlink.h`. All fields are in host byte order;
//! attributes are aligned to 4 bytes.

use std::io;
use std::os::fd::OwnedFd;
use std::time::Duration;

use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::sockopt::{Timeout, set_socket_timeout};
use rustix::net::{
    AddressFamily, Protocol, RecvFlags, SendFlags, SocketFlags, SocketType, bind, recv, sendto,
    socket_with,
};
use zeroize::Zeroizing;

/// Upper limit on waiting for the kernel's reply. Netlink operations all complete locally and normally
/// take microseconds.
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Receive buffer. A single netlink datagram from the kernel does not exceed one skb (about a page to 32
/// KiB for a dump).
const RECV_BUFFER: usize = 64 * 1024;

pub(crate) const NLMSG_HDR_LEN: usize = 16;
const NLA_HDR_LEN: usize = 4;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

pub(crate) const NLM_F_REQUEST: u16 = 0x1;
pub(crate) const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP_INTR: u16 = 0x10;
pub(crate) const NLM_F_DUMP: u16 = 0x300;
pub(crate) const NLM_F_REPLACE: u16 = 0x100;
pub(crate) const NLM_F_EXCL: u16 = 0x200;
pub(crate) const NLM_F_CREATE: u16 = 0x400;

pub(crate) const NLA_F_NESTED: u16 = 1 << 15;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | (1 << 14));

#[derive(Debug, thiserror::Error)]
pub(crate) enum NlError {
    #[error("netlink socket: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Kernel(io::Error),
    #[error("malformed netlink reply: {0}")]
    Malformed(&'static str),
    #[error("dump was interrupted by a concurrent change")]
    Interrupted,
}

impl NlError {
    pub(crate) fn errno(&self) -> Option<i32> {
        match self {
            NlError::Kernel(e) => e.raw_os_error(),
            _ => None,
        }
    }
}

impl From<rustix::io::Errno> for NlError {
    fn from(e: rustix::io::Errno) -> Self {
        NlError::Io(e.into())
    }
}

pub(crate) struct Socket {
    fd: OwnedFd,
    seq: u32,
    buf: Vec<u8>,
}

impl Socket {
    /// When `protocol` is `None` it is `NETLINK_ROUTE` (its value is 0).
    pub(crate) fn open(protocol: Option<Protocol>) -> Result<Self, NlError> {
        let fd = socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            protocol,
        )?;
        bind(&fd, &SocketAddrNetlink::new(0, 0))?;
        set_socket_timeout(&fd, Timeout::Recv, Some(REPLY_TIMEOUT))?;
        set_socket_timeout(&fd, Timeout::Send, Some(REPLY_TIMEOUT))?;
        Ok(Self {
            fd,
            seq: 0,
            buf: vec![0; RECV_BUFFER],
        })
    }

    /// Sends a request and collects the replies until the kernel acknowledges (ordinary requests) or the dump
    /// ends. Returns the content of each reply message with the message header removed. Requests that
    /// carry a private key are zeroed after sending ([`Message`] uses `Zeroizing` internally).
    pub(crate) fn request(&mut self, msg: Message) -> Result<Vec<Vec<u8>>, NlError> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let dump = msg.flags & NLM_F_DUMP == NLM_F_DUMP;
        let bytes = msg.finish(seq);
        let sent = sendto(
            &self.fd,
            &bytes,
            SendFlags::empty(),
            &SocketAddrNetlink::new(0, 0),
        )?;
        if sent != bytes.len() {
            return Err(NlError::Malformed("short send"));
        }

        let mut replies = Vec::new();
        let mut interrupted = false;
        loop {
            let (len, full_len) = recv(&self.fd, &mut self.buf[..], RecvFlags::TRUNC)?;
            if full_len > len {
                return Err(NlError::Malformed("reply larger than the receive buffer"));
            }
            let mut rest = &self.buf[..len];
            while !rest.is_empty() {
                let (header, payload, next) = split_message(rest)?;
                rest = next;
                if header.seq != seq {
                    // Not a reply to this request (for example a reply that arrived late after the previous timeout)
                    continue;
                }
                interrupted |= header.flags & NLM_F_DUMP_INTR != 0;
                match header.ty {
                    NLMSG_ERROR | NLMSG_DONE => {
                        let code = payload
                            .get(..4)
                            .and_then(|b| b.try_into().ok())
                            .map(i32::from_ne_bytes)
                            .ok_or(NlError::Malformed("short error message"))?;
                        if code < 0 {
                            return Err(NlError::Kernel(io::Error::from_raw_os_error(-code)));
                        }
                        // An ordinary request ends with an acknowledgement (error code 0), a dump ends with DONE
                        if header.ty == NLMSG_DONE || !dump {
                            return if interrupted {
                                Err(NlError::Interrupted)
                            } else {
                                Ok(replies)
                            };
                        }
                    }
                    // After an ordinary request's reply there is still an acknowledgement; keep reading until it arrives
                    _ => replies.push(payload.to_vec()),
                }
            }
        }
    }
}

impl Socket {
    /// Sends a batch of messages (an nftables transaction) and waits until every message with the
    /// acknowledgement flag is acknowledged; returns an error if any one fails.
    pub(crate) fn request_batch(&mut self, msgs: Vec<Message>) -> Result<(), NlError> {
        let mut bytes = Vec::new();
        let mut pending = std::collections::BTreeSet::new();
        for msg in msgs {
            self.seq = self.seq.wrapping_add(1);
            if msg.flags & NLM_F_ACK != 0 {
                pending.insert(self.seq);
            }
            bytes.extend_from_slice(&msg.finish(self.seq));
        }
        let sent = sendto(
            &self.fd,
            &bytes,
            SendFlags::empty(),
            &SocketAddrNetlink::new(0, 0),
        )?;
        if sent != bytes.len() {
            return Err(NlError::Malformed("short send"));
        }
        while !pending.is_empty() {
            let (len, _) = recv(&self.fd, &mut self.buf[..], RecvFlags::empty())?;
            let mut rest = &self.buf[..len];
            while !rest.is_empty() {
                let (header, payload, next) = split_message(rest)?;
                rest = next;
                if header.ty == NLMSG_ERROR && pending.remove(&header.seq) {
                    let code = payload
                        .get(..4)
                        .and_then(|b| b.try_into().ok())
                        .map(i32::from_ne_bytes)
                        .ok_or(NlError::Malformed("short error message"))?;
                    if code < 0 {
                        return Err(NlError::Kernel(io::Error::from_raw_os_error(-code)));
                    }
                }
            }
        }
        Ok(())
    }

    /// Receives one datagram (for subscription-type sockets, for example nfnetlink_log); returns `None` on
    /// timeout.
    pub(crate) fn recv_datagram(&mut self) -> Result<Option<&[u8]>, NlError> {
        match recv(&self.fd, &mut self.buf[..], RecvFlags::empty()) {
            Ok((len, _)) => Ok(Some(&self.buf[..len])),
            Err(e) if e == rustix::io::Errno::AGAIN || e == rustix::io::Errno::INTR => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub(crate) fn set_recv_timeout(&self, timeout: Duration) -> Result<(), NlError> {
        set_socket_timeout(&self.fd, Timeout::Recv, Some(timeout))?;
        Ok(())
    }
}

pub(crate) struct Header {
    pub(crate) ty: u16,
    flags: u16,
    pub(crate) seq: u32,
}

pub(crate) fn split_message(buf: &[u8]) -> Result<(Header, &[u8], &[u8]), NlError> {
    if buf.len() < NLMSG_HDR_LEN {
        return Err(NlError::Malformed("truncated message header"));
    }
    let len = u32::from_ne_bytes(read4(buf, 0)) as usize;
    if len < NLMSG_HDR_LEN || len > buf.len() {
        return Err(NlError::Malformed("bad message length"));
    }
    let header = Header {
        ty: u16::from_ne_bytes([buf[4], buf[5]]),
        flags: u16::from_ne_bytes([buf[6], buf[7]]),
        seq: u32::from_ne_bytes(read4(buf, 8)),
    };
    let next = align(len).min(buf.len());
    Ok((header, &buf[NLMSG_HDR_LEN..len], &buf[next..]))
}

fn read4(buf: &[u8], at: usize) -> [u8; 4] {
    [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]
}

pub(crate) const fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// A netlink message to send. The content uses `Zeroizing`: a message that sets the WireGuard private key
/// is zeroed after sending.
pub(crate) struct Message {
    ty: u16,
    flags: u16,
    buf: Zeroizing<Vec<u8>>,
}

impl Message {
    pub(crate) fn new(ty: u16, flags: u16) -> Self {
        let mut buf = Zeroizing::new(Vec::with_capacity(256));
        buf.resize(NLMSG_HDR_LEN, 0);
        Self { ty, flags, buf }
    }

    /// The fixed-size structure after the message header (`ifinfomsg`, `ifaddrmsg`, `genlmsghdr`), whose
    /// length is always a multiple of 4.
    pub(crate) fn fixed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        self.pad();
    }

    pub(crate) fn attr(&mut self, ty: u16, payload: &[u8]) {
        let len = u16::try_from(NLA_HDR_LEN + payload.len()).unwrap_or(u16::MAX);
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(payload);
        self.pad();
    }

    pub(crate) fn attr_u8(&mut self, ty: u16, v: u8) {
        self.attr(ty, &[v]);
    }

    pub(crate) fn attr_u16(&mut self, ty: u16, v: u16) {
        self.attr(ty, &v.to_ne_bytes());
    }

    pub(crate) fn attr_u32(&mut self, ty: u16, v: u32) {
        self.attr(ty, &v.to_ne_bytes());
    }

    /// A NUL-terminated string attribute.
    pub(crate) fn attr_str(&mut self, ty: u16, s: &str) {
        let mut bytes = Vec::with_capacity(s.len() + 1);
        bytes.extend_from_slice(s.as_bytes());
        bytes.push(0);
        self.attr(ty, &bytes);
    }

    /// Starts a nested attribute and returns its position, to hand to [`Self::end_nested`].
    pub(crate) fn begin_nested(&mut self, ty: u16) -> usize {
        let start = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf
            .extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
        start
    }

    pub(crate) fn end_nested(&mut self, start: usize) {
        let len = u16::try_from(self.buf.len() - start).unwrap_or(u16::MAX);
        self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
    }

    /// Undoes back to a position, used to move the last item to the next message when it does not fit.
    pub(crate) fn truncate(&mut self, len: usize) {
        self.buf.truncate(len);
    }

    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    fn pad(&mut self) {
        let padded = align(self.buf.len());
        self.buf.resize(padded, 0);
    }

    fn finish(mut self, seq: u32) -> Zeroizing<Vec<u8>> {
        let len = u32::try_from(self.buf.len()).unwrap_or(u32::MAX);
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf[4..6].copy_from_slice(&self.ty.to_ne_bytes());
        self.buf[6..8].copy_from_slice(&(self.flags | NLM_F_REQUEST).to_ne_bytes());
        self.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        // Port number 0: filled in by the kernel
        self.buf[12..16].copy_from_slice(&0u32.to_ne_bytes());
        self.buf
    }
}

/// Iterates over a run of attributes. The attribute type has the nesting and byte order flags removed.
pub(crate) fn attrs(buf: &[u8]) -> impl Iterator<Item = Result<(u16, &[u8]), NlError>> {
    let mut rest = buf;
    std::iter::from_fn(move || {
        if rest.len() < NLA_HDR_LEN {
            return None;
        }
        let len = usize::from(u16::from_ne_bytes([rest[0], rest[1]]));
        let ty = u16::from_ne_bytes([rest[2], rest[3]]) & NLA_TYPE_MASK;
        if len < NLA_HDR_LEN || len > rest.len() {
            rest = &[];
            return Some(Err(NlError::Malformed("bad attribute length")));
        }
        let payload = &rest[NLA_HDR_LEN..len];
        rest = &rest[align(len).min(rest.len())..];
        Some(Ok((ty, payload)))
    })
}

pub(crate) fn parse_u16(b: &[u8]) -> Result<u16, NlError> {
    b.try_into()
        .map(u16::from_ne_bytes)
        .map_err(|_| NlError::Malformed("u16 attribute"))
}

pub(crate) fn parse_u32(b: &[u8]) -> Result<u32, NlError> {
    b.try_into()
        .map(u32::from_ne_bytes)
        .map_err(|_| NlError::Malformed("u32 attribute"))
}

pub(crate) fn parse_u64(b: &[u8]) -> Result<u64, NlError> {
    b.try_into()
        .map(u64::from_ne_bytes)
        .map_err(|_| NlError::Malformed("u64 attribute"))
}

pub(crate) fn parse_str(b: &[u8]) -> Result<&str, NlError> {
    let b = b.strip_suffix(&[0]).unwrap_or(b);
    std::str::from_utf8(b).map_err(|_| NlError::Malformed("string attribute"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_parses_nested_attributes() {
        let mut m = Message::new(16, NLM_F_ACK);
        m.fixed(&[0u8; 4]);
        m.attr_str(3, "nett0");
        let nest = m.begin_nested(18);
        m.attr_str(1, "wireguard");
        m.end_nested(nest);
        m.attr_u32(4, 1280);
        let bytes = m.finish(7);

        let (header, payload, rest) = split_message(&bytes).expect("message");
        assert!(rest.is_empty());
        assert_eq!((header.ty, header.seq), (16, 7));
        assert_eq!(header.flags, NLM_F_ACK | NLM_F_REQUEST);
        let parsed: Vec<_> = attrs(&payload[4..])
            .collect::<Result<_, _>>()
            .expect("attrs");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].0, 3);
        assert_eq!(parse_str(parsed[0].1).expect("str"), "nett0");
        assert_eq!(parsed[1].0, 18);
        let inner: Vec<_> = attrs(parsed[1].1)
            .collect::<Result<_, _>>()
            .expect("nested");
        assert_eq!(parse_str(inner[0].1).expect("str"), "wireguard");
        assert_eq!(parse_u32(parsed[2].1).expect("u32"), 1280);
    }

    #[test]
    fn rejects_malformed_attributes() {
        let bad = [8u8, 0, 1, 0, 0, 0];
        assert!(matches!(
            attrs(&bad).next(),
            Some(Err(NlError::Malformed(_)))
        ));
        let mut short = vec![0u8; NLMSG_HDR_LEN];
        short[0..4].copy_from_slice(&64u32.to_ne_bytes());
        assert!(split_message(&short).is_err());
    }
}
