//! 中继端口的收发循环：一个阻塞线程，收一个包、按 [`Relay`] 的结果转发或应答。

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::relay::{Outcome, Relay};

/// 读超时：据此定期清理表项、检查是否该退出。
const RECV_TIMEOUT: Duration = Duration::from_millis(500);
const EXPIRE_INTERVAL: Duration = Duration::from_secs(1);
/// 外层包最大约 1360 字节（design/mesh.md 第 4 节），留出余量。
const MAX_DATAGRAM: usize = 2048;

/// 一直运行到 `stop` 被置位。`socket` 是双栈的中继端口。
pub fn serve(socket: &UdpSocket, mut relay: Relay, stop: &AtomicBool) -> std::io::Result<()> {
    socket.set_read_timeout(Some(RECV_TIMEOUT))?;
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut last_expire = Instant::now();
    let mut dropped: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let from = unmap(from);
                match relay.handle(from, &buf[..len], Instant::now(), now_ms()) {
                    // 发送失败（例如对方暂时没有路由）只丢这一个包
                    Outcome::Forward(to) => drop(socket.send_to(&buf[..len], map_v6(to))),
                    Outcome::Reply(reply) => drop(socket.send_to(&reply, map_v6(from))),
                    Outcome::Drop(reason) => {
                        dropped += 1;
                        tracing::debug!(?reason, %from, dropped, "relay dropped a packet");
                    }
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e),
        }
        if last_expire.elapsed() >= EXPIRE_INTERVAL {
            last_expire = Instant::now();
            relay.expire(last_expire);
        }
    }
    Ok(())
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
