//! 测量（design/prototype.md 第 6.1 节）：隧道内探测流与长连接。
//!
//! 两端都是 `nett-lab` 的子命令，在节点的网络命名空间中运行，结果写成文件，由场景读取后计算指标。
//! 所有时间都取同一台主机的系统时钟，接收端只用自己的时钟计算间隔。

use std::fs::File;
use std::io::{BufWriter, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

/// 探测流的发送间隔。
pub const PROBE_INTERVAL: Duration = Duration::from_millis(100);
/// 探测包：8 字节序号，补齐到一个小包的大小。
const PROBE_LEN: usize = 64;
/// 长连接的写入块大小与节奏：每 10 毫秒写 16 KiB，约 13 Mbit/s，既能反映吞吐又不压垮实验网络。
const TCP_CHUNK: usize = 16 * 1024;
const TCP_PACE: Duration = Duration::from_millis(10);
/// 长连接接收端记录进度的间隔。
const TCP_SAMPLE: Duration = Duration::from_millis(100);

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// 发送探测流，直到进程被结束。
pub fn probe_send(to: SocketAddr) -> anyhow::Result<()> {
    let bind: SocketAddr = if to.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let socket = UdpSocket::bind(bind).context("binding probe sender")?;
    let mut packet = [0u8; PROBE_LEN];
    let mut next = std::time::Instant::now();
    // 一直发到进程被结束
    let mut seq: u64 = 0;
    loop {
        packet[..8].copy_from_slice(&seq.to_be_bytes());
        // 路径断开时发送可能失败（例如没有路由），照常继续，接收端据此看到中断
        socket.send_to(&packet, to).ok();
        seq = seq.wrapping_add(1);
        next += PROBE_INTERVAL;
        std::thread::sleep(next.saturating_duration_since(std::time::Instant::now()));
    }
}

/// 接收探测流，每个包写一行 `序号 接收时间（毫秒）`，直到进程被结束。
pub fn probe_recv(listen: SocketAddr, out: &Path) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(listen).context("binding probe receiver")?;
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    let mut file =
        BufWriter::new(File::create(out).with_context(|| format!("creating {}", out.display()))?);
    let mut buf = [0u8; 1500];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, _)) if len >= 8 => {
                let seq = u64::from_be_bytes(buf[..8].try_into().context("probe seq")?);
                writeln!(file, "{seq} {}", now_ms())?;
            }
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e).context("receiving probes"),
        }
        file.flush()?;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeStats {
    pub received: usize,
    /// 最长的一段没有收到包的时间（毫秒）：中断时间（design/prototype.md 第 6.1 节）。
    pub max_gap_ms: u64,
    /// 超过正常间隔两倍的空档：`(开始时间, 时长)`，毫秒。
    pub gaps: Vec<(u64, u64)>,
}

/// 只统计 `[from_ms, to_ms]` 之间收到的包。
pub fn probe_stats(file: &Path, from_ms: u64, to_ms: u64) -> anyhow::Result<ProbeStats> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let mut times: Vec<u64> = text
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1)?.parse().ok())
        .filter(|t| (from_ms..=to_ms).contains(t))
        .collect();
    times.sort_unstable();
    // 窗口的两端也算：窗口开始后迟迟收不到包，同样是中断
    let mut edges = vec![from_ms];
    edges.extend(&times);
    edges.push(to_ms);
    let threshold = 2 * u64::try_from(PROBE_INTERVAL.as_millis()).unwrap_or(100);
    let gaps: Vec<(u64, u64)> = edges
        .windows(2)
        .map(|w| (w[0], w[1].saturating_sub(w[0])))
        .filter(|(_, d)| *d > threshold)
        .collect();
    Ok(ProbeStats {
        received: times.len(),
        max_gap_ms: edges
            .windows(2)
            .map(|w| w[1].saturating_sub(w[0]))
            .max()
            .unwrap_or(0),
        gaps,
    })
}

/// 场景 18 的"陌生人"：从 41820 端口向 `to` 发送 `count` 个伪造的直连探测（首字节 0x82，其余随机）和
/// 同样多的随机握手发起（WireGuard 类型 1），每 100 毫秒一组。它们都没有合法的校验码。
pub fn forge(to: SocketAddr, count: u32) -> anyhow::Result<()> {
    let bind: SocketAddr = if to.is_ipv4() {
        "0.0.0.0:41820".parse()?
    } else {
        "[::]:41820".parse()?
    };
    let socket = UdpSocket::bind(bind).context("binding forger")?;
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15 ^ now_ms();
    let mut fill = |buf: &mut [u8]| {
        for b in buf.iter_mut() {
            // xorshift：只需要看起来随机的字节
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = (state & 0xff) as u8;
        }
    };
    for _ in 0..count {
        let mut probe = [0u8; 64];
        fill(&mut probe);
        probe[0] = 0x82;
        probe[1..4].fill(0);
        socket.send_to(&probe, to).ok();
        let mut init = [0u8; 148];
        fill(&mut init);
        init[0] = 1;
        init[1..4].fill(0);
        socket.send_to(&init, to).ok();
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

/// 洪泛预先生成的握手发起数。WireGuard 不对握手发起去重，同样的包每次都要做一次 Diffie-Hellman 才知道
/// 解不开，所以反复发送这几个就能占满对端处理握手的能力。
const FLOOD_DISTINCT: usize = 64;

/// 场景 20(c) 的洪泛：向 `to` 尽快发送 `mac1` 正确、其余内容随机的握手发起，持续 `secs` 秒。`public_key`
/// 是对端的组网公钥（`mac1` 的密钥由它导出）。超过对端处理握手的能力时，它的握手队列积压、进入负载
/// 状态，改为回 cookie。
pub fn flood(to: SocketAddr, public_key: &[u8; 32], secs: u64) -> anyhow::Result<()> {
    let bind: SocketAddr = if to.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let socket = UdpSocket::bind(bind).context("binding flooder")?;
    let mac1 = nett_relay::wg::Mac1Key::for_public_key(public_key);
    let mut state: u64 = 0x2545_f491_4f6c_dd1d ^ now_ms();
    let packets: Vec<[u8; 148]> = (0..FLOOD_DISTINCT)
        .map(|_| {
            let mut init = [0u8; 148];
            for b in init.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *b = (state & 0xff) as u8;
            }
            init[0] = 1;
            init[1..4].fill(0);
            let tag = mac1.compute(&init[..116]);
            init[116..132].copy_from_slice(&tag);
            init[132..].fill(0);
            init
        })
        .collect();
    let end = std::time::Instant::now() + Duration::from_secs(secs);
    let mut sent: u64 = 0;
    while std::time::Instant::now() < end {
        for p in &packets {
            socket.send_to(p, to).ok();
        }
        sent += packets.len() as u64;
    }
    println!("sent {sent} initiations in {secs} s");
    Ok(())
}

/// 访问控制的接收端：接受连接，把每个连接的来源地址写成一行，随即关闭连接。
pub fn accept_log(listen: SocketAddr, out: &Path) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).context("binding the accept logger")?;
    let mut file = File::options()
        .create(true)
        .append(true)
        .open(out)
        .with_context(|| format!("opening {}", out.display()))?;
    for stream in listener.incoming() {
        let peer = stream.context("accepting")?.peer_addr()?;
        writeln!(file, "{}", peer.ip())?;
        file.flush()?;
    }
    Ok(())
}

/// 在 `timeout` 之内尝试建立一个 TCP 连接：连上时输出 `connected`，否则输出 `blocked <原因>`。
pub fn connect(to: SocketAddr, timeout: Duration) -> anyhow::Result<()> {
    match TcpStream::connect_timeout(&to, timeout) {
        Ok(_) => println!("connected"),
        Err(e) => println!("blocked {:?}", e.kind()),
    }
    Ok(())
}

/// 长连接的发送端：连接后持续写入，直到出错或进程被结束。出错时以非 0 退出，原因写入标准错误。
pub fn tcp_source(to: SocketAddr) -> anyhow::Result<()> {
    let mut stream =
        TcpStream::connect_timeout(&to, Duration::from_secs(10)).context("connecting")?;
    stream.set_nodelay(true)?;
    let chunk = vec![0x5au8; TCP_CHUNK];
    let mut next = std::time::Instant::now();
    loop {
        stream
            .write_all(&chunk)
            .context("writing to the long connection")?;
        next += TCP_PACE;
        std::thread::sleep(next.saturating_duration_since(std::time::Instant::now()));
    }
}

/// 长连接的接收端：接受一个连接，每 100 毫秒写一行 `时间 累计字节数`；连接结束时写一行
/// `end 时间 原因`（`eof` 或错误）。
pub fn tcp_sink(listen: SocketAddr, out: &Path) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).context("binding long-connection sink")?;
    let (mut stream, _) = listener.accept().context("accepting the long connection")?;
    stream.set_read_timeout(Some(TCP_SAMPLE))?;
    let mut file =
        BufWriter::new(File::create(out).with_context(|| format!("creating {}", out.display()))?);
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    let mut last_sample = 0;
    let end = loop {
        match stream.read(&mut buf) {
            Ok(0) => break "eof".to_owned(),
            Ok(n) => total += n as u64,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => break format!("{:?}", e.kind()),
        }
        let now = now_ms();
        if now >= last_sample + 100 {
            writeln!(file, "{now} {total}")?;
            file.flush()?;
            last_sample = now;
        }
    };
    writeln!(file, "end {} {end}", now_ms())?;
    file.flush()?;
    Ok(())
}

/// 大块传输（场景 19）的写入块大小，以及接收端判定传输停住的时间。
const BULK_CHUNK: usize = 64 * 1024;
const BULK_STALL: Duration = Duration::from_secs(30);

/// 大块传输的内容：第 `offset` 个字节，取自按 8 字节一组编号的 splitmix64 序列。发送端和接收端各自
/// 生成，不用传递种子；错位、缺失、重复都会让后面的字节对不上。
fn bulk_fill(offset: u64, buf: &mut [u8]) {
    let (mut at, mut i) = (offset, 0);
    while i < buf.len() {
        let mut z = (at / 8).wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        let word = z.to_le_bytes();
        let start = usize::try_from(at % 8).unwrap_or(0);
        let n = (8 - start).min(buf.len() - i);
        buf[i..i + n].copy_from_slice(&word[start..start + n]);
        i += n;
        at += n as u64;
    }
}

/// 大块传输的发送端：连接后写入 `bytes` 个字节，关闭写方向，等接收端关闭连接。
pub fn bulk_send(to: SocketAddr, bytes: u64) -> anyhow::Result<()> {
    let mut stream =
        TcpStream::connect_timeout(&to, Duration::from_secs(10)).context("connecting")?;
    let mut buf = vec![0u8; BULK_CHUNK];
    let mut sent: u64 = 0;
    while sent < bytes {
        let n = usize::try_from((bytes - sent).min(BULK_CHUNK as u64)).unwrap_or(BULK_CHUNK);
        bulk_fill(sent, &mut buf[..n]);
        stream
            .write_all(&buf[..n])
            .context("writing the bulk stream")?;
        sent += n as u64;
    }
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut rest = [0u8; 16];
    while stream.read(&mut rest).context("waiting for the receiver")? > 0 {}
    Ok(())
}

/// 大块传输的结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkResult {
    pub expected: u64,
    pub received: u64,
    /// 第一个对不上的字节的位置。
    pub mismatch_at: Option<u64>,
    pub ms: u64,
    /// `eof`、`stalled`（[`BULK_STALL`] 内没有收到数据）或错误。
    pub ended: String,
}

impl BulkResult {
    pub fn complete(&self) -> bool {
        self.received == self.expected && self.mismatch_at.is_none() && self.ended == "eof"
    }

    pub fn mbps(&self) -> u64 {
        self.received * 8 / 1000 / self.ms.max(1)
    }
}

/// 大块传输的接收端：接受一个连接，逐字节校验内容，结束时把 [`BulkResult`] 写成 JSON。
pub fn bulk_recv(listen: SocketAddr, bytes: u64, out: &Path) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).context("binding bulk receiver")?;
    let (mut stream, _) = listener.accept().context("accepting the bulk stream")?;
    stream.set_read_timeout(Some(BULK_STALL))?;
    let started = std::time::Instant::now();
    let mut buf = vec![0u8; BULK_CHUNK];
    let mut want = vec![0u8; BULK_CHUNK];
    let (mut received, mut mismatch_at) = (0u64, None);
    let ended = loop {
        match stream.read(&mut buf) {
            Ok(0) => break "eof".to_owned(),
            Ok(n) => {
                if mismatch_at.is_none() {
                    bulk_fill(received, &mut want[..n]);
                    if let Some(i) = buf[..n].iter().zip(&want[..n]).position(|(a, b)| a != b) {
                        mismatch_at = Some(received + i as u64);
                    }
                }
                received += n as u64;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break "stalled".to_owned();
            }
            Err(e) => break format!("{:?}", e.kind()),
        }
    };
    let result = BulkResult {
        expected: bytes,
        received,
        mismatch_at,
        ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        ended,
    };
    let tmp = out.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(&result)?)
        .with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, out).with_context(|| format!("writing {}", out.display()))?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpStats {
    /// 连接被重置或出错；`None` 表示测量结束时连接仍然正常。
    pub ended: Option<String>,
    pub bytes: u64,
    /// 窗口内的平均吞吐（kbit/s）。
    pub kbps: u64,
}

pub fn tcp_stats(file: &Path, from_ms: u64, to_ms: u64) -> anyhow::Result<TcpStats> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let mut ended = None;
    let mut samples = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.as_slice() {
            ["end", _, reason] => ended = Some((*reason).to_owned()),
            [t, total] => {
                if let (Ok(t), Ok(total)) = (t.parse::<u64>(), total.parse::<u64>()) {
                    samples.push((t, total));
                }
            }
            _ => {}
        }
    }
    let in_window: Vec<_> = samples
        .iter()
        .filter(|(t, _)| (from_ms..=to_ms).contains(t))
        .collect();
    let (bytes, kbps) = match (in_window.first(), in_window.last()) {
        (Some((t0, b0)), Some((t1, b1))) if t1 > t0 => {
            let bytes = b1 - b0;
            (bytes, bytes * 8 / (t1 - t0))
        }
        _ => (0, 0),
    };
    Ok(TcpStats { ended, bytes, kbps })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_content_does_not_depend_on_chunking() {
        let mut whole = vec![0u8; 100];
        bulk_fill(5, &mut whole);
        let (mut left, mut right) = (vec![0u8; 37], vec![0u8; 63]);
        bulk_fill(5, &mut left);
        bulk_fill(42, &mut right);
        assert_eq!([left, right].concat(), whole);
        // 错开一个字节就对不上
        let mut shifted = vec![0u8; 100];
        bulk_fill(6, &mut shifted);
        assert_ne!(shifted, whole);
    }

    #[test]
    fn probe_gaps_include_window_edges() {
        let dir = std::env::temp_dir().join(format!("nett-lab-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("probe.txt");
        // 1000..1300 正常，1300..3300 中断 2 秒，之后恢复；窗口到 4000
        let mut lines = String::new();
        for (seq, t) in [1000u64, 1100, 1200, 1300, 3300, 3400, 3500]
            .iter()
            .enumerate()
        {
            lines.push_str(&format!("{seq} {t}\n"));
        }
        std::fs::write(&file, lines).expect("write");
        let stats = probe_stats(&file, 1000, 4000).expect("stats");
        assert_eq!(stats.received, 7);
        assert_eq!(stats.max_gap_ms, 2000);
        assert_eq!(stats.gaps, vec![(1300, 2000), (3500, 500)]);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
