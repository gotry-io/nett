//! Batched receive and send on Linux (design/userspace.md section 4): one `recvmmsg` takes up to
//! [`SLOTS`] datagrams from a socket and one `sendmmsg` sends as many, so a burst or a flood costs a
//! system call per batch instead of one per packet, as Tailscale's batching connection reads and
//! writes on Linux (v1.104.7, `net/batching/conn_linux.go`). rustix has `sendmmsg` and no `recvmmsg`,
//! so the receive side calls libc here.

use std::io::{self, IoSlice};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::AsRawFd as _;

use rustix::net::addr::SocketAddrArg as _;
use rustix::net::{MMsgHdr, SendAncillaryBuffer, SendFlags};

/// Datagrams taken or sent per system call, Tailscale's batch size.
pub(super) const SLOTS: usize = 64;
/// Room for one datagram: tunnel packets are about 1360 bytes and wrapped ones at most 300 more
/// (design/mesh.md section 4); a longer datagram is not one of nett's and is dropped.
const SLOT: usize = 2048;

/// The datagrams of one receive, in a buffer reused for every receive.
pub(super) struct RecvBatch {
    slab: Vec<u8>,
    /// Each datagram kept: its slot in the slab, its length and where it came from.
    received: Vec<(usize, usize, SocketAddr)>,
}

impl RecvBatch {
    pub(super) fn new() -> Self {
        Self {
            slab: vec![0; SLOTS * SLOT],
            received: Vec::with_capacity(SLOTS),
        }
    }

    /// Takes what `socket` holds, up to [`SLOTS`] datagrams, without waiting: `WouldBlock` when it
    /// holds none. The datagrams are then [`RecvBatch::get`]; one too long for a slot is left out.
    pub(super) fn recv(&mut self, socket: &UdpSocket) -> io::Result<usize> {
        // SAFETY: sockaddr_storage is plain data that any bytes, zeros included, make valid
        let mut names: [libc::sockaddr_storage; SLOTS] = unsafe { std::mem::zeroed() };
        // SAFETY: iovec and mmsghdr are plain data; every one used is filled in below before the
        // call
        let mut iovecs: [libc::iovec; SLOTS] = unsafe { std::mem::zeroed() };
        // SAFETY: as above
        let mut msgs: [libc::mmsghdr; SLOTS] = unsafe { std::mem::zeroed() };
        for (i, slot) in self.slab.as_chunks_mut::<SLOT>().0.iter_mut().enumerate() {
            iovecs[i] = libc::iovec {
                iov_base: slot.as_mut_ptr().cast(),
                iov_len: SLOT,
            };
            let hdr = &mut msgs[i].msg_hdr;
            hdr.msg_name = std::ptr::from_mut(&mut names[i]).cast();
            hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            hdr.msg_iov = std::ptr::from_mut(&mut iovecs[i]);
            hdr.msg_iovlen = 1;
        }
        // SAFETY: each header points at its own name and at an iovec covering its own slot of the
        // slab, all of which outlive the call; the kernel writes at most SLOT bytes per slot and
        // the sizes given for the names
        let n = unsafe {
            libc::recvmmsg(
                socket.as_raw_fd(),
                msgs.as_mut_ptr(),
                SLOTS as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        self.received.clear();
        for (slot, (msg, name)) in msgs.iter().zip(&names).take(n as usize).enumerate() {
            if msg.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
                continue;
            }
            if let Some(from) = socket_addr(name) {
                self.received.push((slot, msg.msg_len as usize, from));
            }
        }
        Ok(self.received.len())
    }

    /// Datagram `i` of the last receive and where it came from.
    pub(super) fn get(&self, i: usize) -> Option<(&[u8], SocketAddr)> {
        let &(slot, len, from) = self.received.get(i)?;
        Some((&self.slab[slot * SLOT..slot * SLOT + len.min(SLOT)], from))
    }
}

/// A received source address, IPv4 or IPv6.
fn socket_addr(name: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match libc::c_int::from(name.ss_family) {
        libc::AF_INET => {
            // SAFETY: the family says the storage holds a sockaddr_in, which is smaller
            let v4 = unsafe { &*std::ptr::from_ref(name).cast::<libc::sockaddr_in>() };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr)),
                u16::from_be(v4.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says the storage holds a sockaddr_in6, which is smaller
            let v6 = unsafe { &*std::ptr::from_ref(name).cast::<libc::sockaddr_in6>() };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(v6.sin6_addr.s6_addr),
                u16::from_be(v6.sin6_port),
                v6.sin6_flowinfo,
                v6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// Sends `datagrams` from `socket`, [`SLOTS`] per system call, in order. What does not go out at once
/// (a full send buffer) is dropped, as a lost packet: WireGuard and the path layer handle loss.
pub(super) fn send(socket: &UdpSocket, datagrams: &[(SocketAddr, Vec<u8>)]) {
    for chunk in datagrams.chunks(SLOTS) {
        let addrs: Vec<_> = chunk.iter().map(|(to, _)| to.as_any()).collect();
        let iovs: Vec<[IoSlice<'_>; 1]> = chunk.iter().map(|(_, d)| [IoSlice::new(d)]).collect();
        let mut controls: Vec<SendAncillaryBuffer<'_, '_, '_>> = chunk
            .iter()
            .map(|_| SendAncillaryBuffer::default())
            .collect();
        let mut msgs: Vec<MMsgHdr<'_>> = addrs
            .iter()
            .zip(&iovs)
            .zip(controls.iter_mut())
            .map(|((addr, iov), control)| MMsgHdr::new_with_addr(addr, iov, control))
            .collect();
        let mut sent = 0;
        while sent < msgs.len() {
            match rustix::net::sendmmsg(socket, &mut msgs[sent..], SendFlags::DONTWAIT) {
                Ok(0) | Err(_) => break,
                Ok(n) => sent += n,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn receiver() -> UdpSocket {
        let socket = crate::userspace::dual_stack_udp(0).expect("dual-stack socket");
        socket.set_nonblocking(true).expect("nonblocking");
        socket
    }

    fn at(socket: &UdpSocket) -> SocketAddr {
        SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            socket.local_addr().expect("addr").port(),
        ))
    }

    /// One receive takes what is queued, each datagram with its own source; a datagram too long
    /// for a slot is left out, and the ones after it are kept.
    #[test]
    fn a_batch_takes_what_is_queued_and_leaves_out_what_is_too_long() {
        let socket = receiver();
        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
        for datagram in [vec![1u8; 100], vec![2u8; SLOT + 1], vec![3u8; 1400]] {
            sender.send_to(&datagram, at(&socket)).expect("sent");
        }
        std::thread::sleep(Duration::from_millis(50));
        let mut batch = RecvBatch::new();
        assert_eq!(batch.recv(&socket).expect("received"), 2);
        let from = sender.local_addr().expect("addr");
        let unmapped = |a: SocketAddr| match a {
            SocketAddr::V6(v6) => v6
                .ip()
                .to_ipv4_mapped()
                .map_or(a, |ip| SocketAddr::from((ip, v6.port()))),
            v4 => v4,
        };
        let (first, src) = batch.get(0).expect("first");
        assert_eq!((first, unmapped(src)), (&[1u8; 100][..], from));
        let (third, _) = batch.get(1).expect("third");
        assert_eq!(third, &[3u8; 1400][..]);
        assert!(batch.get(2).is_none());
        assert_eq!(
            batch.recv(&socket).map_err(|e| e.kind()),
            Err(io::ErrorKind::WouldBlock)
        );
    }

    /// More datagrams than one batch go out in order, to each one's own address.
    #[test]
    fn datagrams_go_out_in_order_batch_after_batch() {
        let socket = receiver();
        let (a, b) = (receiver(), receiver());
        let datagrams: Vec<(SocketAddr, Vec<u8>)> = (0..SLOTS as u16 + 10)
            .map(|i| {
                let to = if i % 2 == 0 { &a } else { &b };
                let to = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), at(to).port());
                (to, i.to_be_bytes().to_vec())
            })
            .collect();
        send(&socket, &datagrams);
        std::thread::sleep(Duration::from_millis(50));
        for (to, parity) in [(&a, 0u16), (&b, 1)] {
            let mut batch = RecvBatch::new();
            let mut got = Vec::new();
            while let Ok(n) = batch.recv(to) {
                for i in 0..n {
                    let (d, _) = batch.get(i).expect("datagram");
                    got.push(u16::from_be_bytes([d[0], d[1]]));
                }
            }
            let want: Vec<u16> = (0..SLOTS as u16 + 10).filter(|i| i % 2 == parity).collect();
            assert_eq!(got, want);
        }
    }
}
