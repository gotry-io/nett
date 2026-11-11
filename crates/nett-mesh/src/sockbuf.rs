//! Receive buffers of the sockets that carry tunnel traffic (design/userspace.md section 4).

use std::os::fd::AsFd;

use rustix::net::sockopt;

/// Requested receive buffer of a socket that carries tunnel traffic. The system default (about 200 KiB on
/// Linux) holds less than 2 ms at gigabit rates, so a short scheduling delay of the thread reading the
/// socket drops packets, which TCP inside the tunnel reads as congestion. Linux doubles the value for its
/// own bookkeeping.
pub const RECEIVE_BUFFER: usize = 1 << 20;

/// Asks for [`RECEIVE_BUFFER`] on `socket` and returns the size the system reports. On Linux a process
/// with `CAP_NET_ADMIN` goes past the system limit (`net.core.rmem_max`); others get at most that limit.
/// A refusal keeps the default, which costs throughput and nothing else.
pub fn enlarge_receive_buffer(socket: impl AsFd) -> Option<usize> {
    let fd = socket.as_fd();
    #[cfg(target_os = "linux")]
    let forced = sockopt::set_socket_recv_buffer_size_force(fd, RECEIVE_BUFFER).is_ok();
    #[cfg(not(target_os = "linux"))]
    let forced = false;
    if !forced {
        let _ = sockopt::set_socket_recv_buffer_size(fd, RECEIVE_BUFFER);
    }
    sockopt::socket_recv_buffer_size(fd).ok()
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;

    use super::*;

    #[test]
    fn the_buffer_never_shrinks() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
        let before = sockopt::socket_recv_buffer_size(&socket).expect("default size");
        let after = enlarge_receive_buffer(&socket).expect("size");
        assert!(after >= before, "{after} < {before}");
    }
}
