//! Measurement (design/prototype.md section 6.1): in-tunnel probe streams and long-lived
//! connections.
//!
//! Both ends are `nett-lab` subcommands, run in the node's network namespace, with results written
//! to files that the scenario reads to compute metrics. All times come from the same host's system
//! clock, and a receiver only uses its own clock to compute intervals.

use std::fs::File;
use std::io::{BufWriter, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

/// Send interval of the probe stream.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(100);
/// Probe packet: an 8-byte sequence number, padded to the size of a small packet.
const PROBE_LEN: usize = 64;
/// Write chunk size and pacing of the long-lived connection: 16 KiB every 10 milliseconds, about 13
/// Mbit/s, enough to reflect throughput without overwhelming the lab network.
const TCP_CHUNK: usize = 16 * 1024;
const TCP_PACE: Duration = Duration::from_millis(10);
/// Interval at which the long-lived connection's receiver records progress.
const TCP_SAMPLE: Duration = Duration::from_millis(100);

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Sends the probe stream until the process is killed.
pub fn probe_send(to: SocketAddr) -> anyhow::Result<()> {
    let bind: SocketAddr = if to.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let socket = UdpSocket::bind(bind).context("binding probe sender")?;
    let mut packet = [0u8; PROBE_LEN];
    let mut next = std::time::Instant::now();
    // Keeps sending until the process is killed
    let mut seq: u64 = 0;
    loop {
        packet[..8].copy_from_slice(&seq.to_be_bytes());
        // Sending may fail when the path is down (for example no route); continue as usual, and the
        // receiver sees the interruption from this
        socket.send_to(&packet, to).ok();
        seq = seq.wrapping_add(1);
        next += PROBE_INTERVAL;
        std::thread::sleep(next.saturating_duration_since(std::time::Instant::now()));
    }
}

/// Receives the probe stream and writes one line `sequence receive-time (milliseconds)` per packet,
/// until the process is killed.
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
    /// The longest time without receiving a packet (milliseconds): the interruption time
    /// (design/prototype.md section 6.1).
    pub max_gap_ms: u64,
    /// Gaps longer than twice the normal interval: `(start time, duration)`, in milliseconds.
    pub gaps: Vec<(u64, u64)>,
}

/// Only counts packets received within `[from_ms, to_ms]`.
pub fn probe_stats(file: &Path, from_ms: u64, to_ms: u64) -> anyhow::Result<ProbeStats> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let mut times: Vec<u64> = text
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1)?.parse().ok())
        .filter(|t| (from_ms..=to_ms).contains(t))
        .collect();
    times.sort_unstable();
    // Both ends of the window count: if no packet arrives for a long time after the window starts,
    // that is also an interruption
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

/// The "stranger" of scenario 18: sends `count` forged direct probes (first byte 0x82, the rest
/// random) from port 41820 to `to`, and as many random handshake initiations (WireGuard type 1),
/// one group every 100 milliseconds. None of them has a valid MAC.
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
            // xorshift: only needs bytes that look random
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

/// Number of pregenerated handshake initiations for the flood. WireGuard does not deduplicate
/// handshake initiations: for the same packet, a Diffie-Hellman has to be done each time before it
/// is known to be undecryptable, so sending these few repeatedly can exhaust the peer's capacity to
/// process handshakes.
const FLOOD_DISTINCT: usize = 64;

/// The flood of scenario 20(c): sends handshake initiations with a correct `mac1` and otherwise
/// random content to `to` as fast as possible, for `secs` seconds. `public_key` is the peer's mesh
/// public key (the key for `mac1` is derived from it). When the peer's capacity to process
/// handshakes is exceeded, its handshake queue backs up, it enters the under-load state, and
/// replies with a cookie instead.
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

/// Receiver for access control: accepts connections, writes the source address of each connection
/// as one line, and closes the connection immediately.
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

/// Tries to establish a TCP connection within `timeout`: prints `connected` when connected,
/// otherwise `blocked <reason>`.
pub fn connect(to: SocketAddr, timeout: Duration) -> anyhow::Result<()> {
    match TcpStream::connect_timeout(&to, timeout) {
        Ok(_) => println!("connected"),
        Err(e) => println!("blocked {:?}", e.kind()),
    }
    Ok(())
}

/// Sender of the long-lived connection: keeps writing after connecting, until an error occurs or
/// the process is killed. On error it exits non-zero and writes the reason to standard error.
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

/// Receiver of the long-lived connection: accepts one connection and writes one line `time
/// cumulative-bytes` every 100 milliseconds; when the connection ends, writes one line `end time
/// reason` (`eof` or an error).
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

/// Write chunk size of the bulk transfer (scenario 19), and the time after which the receiver
/// decides the transfer has stalled.
const BULK_CHUNK: usize = 64 * 1024;
const BULK_STALL: Duration = Duration::from_secs(30);

/// Content of the bulk transfer: the byte at position `offset`, taken from a splitmix64 sequence
/// numbered in groups of 8 bytes. The sender and the receiver each generate it, so no seed needs to
/// be passed; misaligned, missing or duplicated data makes the following bytes mismatch.
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

/// Sender of the bulk transfer: after connecting, writes `bytes` bytes, closes the write direction,
/// and waits for the receiver to close the connection.
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

/// Result of the bulk transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkResult {
    pub expected: u64,
    pub received: u64,
    /// Position of the first byte that does not match.
    pub mismatch_at: Option<u64>,
    pub ms: u64,
    /// `eof`, `stalled` (no data received within [`BULK_STALL`]) or an error.
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

/// Receiver of the bulk transfer: accepts one connection, checks the content byte by byte, and
/// writes the [`BulkResult`] as JSON at the end.
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
    /// The connection was reset or failed; `None` means the connection was still fine when the
    /// measurement ended.
    pub ended: Option<String>,
    pub bytes: u64,
    /// Average throughput within the window (kbit/s).
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
        // Off by one byte and it no longer matches
        let mut shifted = vec![0u8; 100];
        bulk_fill(6, &mut shifted);
        assert_ne!(shifted, whole);
    }

    #[test]
    fn probe_gaps_include_window_edges() {
        let dir_tmp = tempfile::Builder::new()
            .prefix("nett-lab-probe-")
            .tempdir()
            .expect("temp dir");
        let dir = dir_tmp.path().join("dir");
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("probe.txt");
        // 1000..1300 normal, 1300..3300 interrupted for 2 seconds, then recovered; the window ends
        // at 4000
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
