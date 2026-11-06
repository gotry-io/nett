//! 中继端口的收发循环：一个阻塞线程，收一个包、按 [`Relay`] 的结果转发或应答。

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::relay::{Outcome, Relay, RelayState};

/// 读超时：据此定期清理表项、检查是否该退出。
const RECV_TIMEOUT: Duration = Duration::from_millis(500);
const EXPIRE_INTERVAL: Duration = Duration::from_secs(1);
/// 外层包最大约 1360 字节（design/mesh.md 第 4 节），留出余量。
const MAX_DATAGRAM: usize = 2048;

/// 保存状态的间隔（design/mesh.md 第 5.2 节）。
const SAVE_INTERVAL: Duration = Duration::from_secs(1);

/// 一直运行到 `stop` 被置位。`socket` 是双栈的中继端口。`state` 为保存索引表的文件：启动时恢复，
/// 每秒一次、以及退出之前写入，重启时经它的连接不中断。
pub fn serve(
    socket: &UdpSocket,
    mut relay: Relay,
    stop: &AtomicBool,
    state: Option<&Path>,
) -> std::io::Result<()> {
    if let Some(path) = state {
        match load(path) {
            Ok(Some(saved)) => {
                relay.restore(&saved, Instant::now());
                let (_, sessions) = relay.table_sizes();
                tracing::info!(sessions, "relay state restored");
            }
            Ok(None) => {}
            // 状态文件损坏只影响恢复：经它的连接按 design/mesh.md 第 8.4 节重新握手
            Err(error) => tracing::warn!(%error, "relay state not restored"),
        }
    }
    let mut last_save = Instant::now();
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
        if let Some(path) = state
            && last_save.elapsed() >= SAVE_INTERVAL
        {
            last_save = Instant::now();
            save_or_warn(path, &relay);
        }
    }
    if let Some(path) = state {
        save_or_warn(path, &relay);
    }
    Ok(())
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

/// 先写临时文件再改名：重启时读到的总是一份完整的状态。
fn save(path: &Path, relay: &Relay) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let bytes =
        serde_json::to_vec(&relay.snapshot(Instant::now())).map_err(std::io::Error::other)?;
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

fn save_or_warn(path: &Path, relay: &Relay) {
    if let Err(error) = save(path, relay) {
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
