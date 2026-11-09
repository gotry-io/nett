//! 数据面线程（design/userspace.md 第 4 节）：用 `poll` 同时等待 TUN、WireGuard 端口和控制命令；会话、
//! 对端表和连接表只属于这个线程。控制命令经有界队列送来，带超时等待应答。

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::unix::net::UnixDatagram;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use nett_trust::keys::X25519PublicKey;
use rustix::event::{PollFd, PollFlags, Timespec, poll};

use super::Tun;
use super::plane::{Action, Plane, UnknownPeer};
use super::session::{Sessions, TIMER_TICK};
use crate::access::FilterSpec;
use crate::dataplane::{DataPlaneError, DirectRecv, DirectSend, PeerSpec, PeerStat};

/// 控制命令队列的上限。
const COMMANDS: usize = 64;
/// 等待数据面线程应答的上限（硬性规则 14）。
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
/// 每次唤醒最多从一个来源读这么多个包，TUN 与 UDP 轮流处理，一边的洪水不会饿死另一边。
const BATCH: usize = 64;
/// 接收缓冲区：一个 UDP 数据报或 IP 包的最大长度。
const MAX_PACKET: usize = 65_535;
/// 交给引擎的直连探测队列的上限；满了丢弃（只影响一次测量）。
const PROBES: usize = 256;
/// [`DirectRecv::recv`] 的等待上限。
const PROBE_WAIT: Duration = Duration::from_millis(500);

pub(super) enum Command {
    SyncPeers(Vec<PeerSpec>, SyncSender<()>),
    SetEndpoint(
        X25519PublicKey,
        SocketAddr,
        SyncSender<Result<(), UnknownPeer>>,
    ),
    Rehandshake(PeerSpec, SyncSender<Result<(), UnknownPeer>>),
    Stats(SyncSender<Vec<PeerStat>>),
    Filter(FilterSpec, SyncSender<()>),
    GuardTlsPorts(Vec<u16>, SyncSender<()>),
    SetLocal(Vec<IpAddr>, SyncSender<()>),
    Shutdown,
}

/// 数据面线程的句柄；丢弃时让线程退出并等它结束。
pub(super) struct Worker {
    commands: SyncSender<Command>,
    wake: UnixDatagram,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    /// 启动数据面线程。`socket` 是 WireGuard 端口的套接字（非阻塞）；直连探测与 cookie 副本放进返回的接收端。
    pub(super) fn spawn<S, T>(
        plane: Plane<S>,
        tun: T,
        socket: UdpSocket,
    ) -> io::Result<(Self, ProbeQueue)>
    where
        S: Sessions + Send + 'static,
        T: Tun,
    {
        let (commands, rx) = sync_channel(COMMANDS);
        let (probes_tx, probes_rx) = sync_channel(PROBES);
        let (wake, wake_rx) = UnixDatagram::pair()?;
        wake.set_nonblocking(true)?;
        wake_rx.set_nonblocking(true)?;
        socket.set_nonblocking(true)?;
        let mut loop_ = Loop {
            plane,
            tun,
            v6: socket.local_addr()?.is_ipv6(),
            socket,
            wake: wake_rx,
            commands: rx,
            probes: probes_tx,
        };
        let thread = std::thread::Builder::new()
            .name("nett-dataplane".into())
            .spawn(move || loop_.run())?;
        Ok((
            Self {
                commands,
                wake,
                thread: Some(thread),
            },
            ProbeQueue(probes_rx),
        ))
    }

    /// 发一个命令并等待应答。
    pub(super) fn call<R>(
        &self,
        command: impl FnOnce(SyncSender<R>) -> Command,
    ) -> Result<R, DataPlaneError> {
        let (tx, rx) = sync_channel(1);
        match self.commands.try_send(command(tx)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(DataPlaneError::Worker("command queue full")),
            Err(TrySendError::Disconnected(_)) => return Err(DataPlaneError::Worker("stopped")),
        }
        // 唤醒失败只在缓冲区已满时发生，那时线程已经有待处理的唤醒
        let _ = self.wake.send(&[0]);
        rx.recv_timeout(COMMAND_TIMEOUT)
            .map_err(|_| DataPlaneError::Worker("did not answer in time"))
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.commands.try_send(Command::Shutdown);
        let _ = self.wake.send(&[0]);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// 数据面线程交给引擎的直连探测与 cookie 副本。
pub(super) struct ProbeQueue(Receiver<(SocketAddr, Vec<u8>)>);

impl DirectRecv for ProbeQueue {
    fn recv(&mut self) -> io::Result<Vec<(SocketAddr, Vec<u8>)>> {
        let first = match self.0.recv_timeout(PROBE_WAIT) {
            Ok(first) => first,
            Err(RecvTimeoutError::Timeout) => return Ok(Vec::new()),
            Err(RecvTimeoutError::Disconnected) => {
                // 数据面线程已经退出；仍按超时返回，让调用方照常检查是否该退出
                std::thread::sleep(PROBE_WAIT);
                return Ok(Vec::new());
            }
        };
        let mut batch = vec![first];
        batch.extend(self.0.try_iter().take(PROBES));
        Ok(batch)
    }
}

/// 从 WireGuard 端口发出直连探测：与数据面线程共用同一个套接字。
pub(super) struct ProbeSender {
    pub(super) socket: UdpSocket,
}

impl DirectSend for ProbeSender {
    fn send(&self, to: SocketAddr, data: &[u8]) -> io::Result<()> {
        let v6 = self.socket.local_addr()?.is_ipv6();
        self.socket.send_to(data, outgoing(to, v6)).map(drop)
    }
}

/// 双栈套接字发往 IPv4 地址时用映射地址。
fn outgoing(to: SocketAddr, v6: bool) -> SocketAddr {
    match to {
        SocketAddr::V4(a) if v6 => SocketAddr::new(IpAddr::V6(a.ip().to_ipv6_mapped()), a.port()),
        _ => to,
    }
}

/// 双栈套接字收到的 IPv4 来源是映射地址，还原为 IPv4。
fn incoming(from: SocketAddr) -> SocketAddr {
    match from {
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => from,
        },
        SocketAddr::V4(_) => from,
    }
}

struct Loop<S, T> {
    plane: Plane<S>,
    tun: T,
    socket: UdpSocket,
    v6: bool,
    wake: UnixDatagram,
    commands: Receiver<Command>,
    probes: SyncSender<(SocketAddr, Vec<u8>)>,
}

impl<S: Sessions, T: Tun> Loop<S, T> {
    fn run(&mut self) {
        let mut buf = vec![0u8; MAX_PACKET];
        let mut out = Vec::new();
        let mut next_tick = Instant::now() + TIMER_TICK;
        loop {
            let wait = next_tick.saturating_duration_since(Instant::now());
            let ready = self.wait(wait);
            let (commands, udp, tun) = match ready {
                Ok(ready) => ready,
                Err(e) => {
                    tracing::error!(error = %e, "data plane: poll failed");
                    std::thread::sleep(TIMER_TICK);
                    (true, true, true)
                }
            };
            if commands && !self.commands_ready() {
                return;
            }
            let now = Instant::now();
            if udp {
                for _ in 0..BATCH {
                    match self.socket.recv_from(&mut buf) {
                        Ok((len, from)) => {
                            self.plane
                                .from_udp(incoming(from), &buf[..len], now, &mut out);
                        }
                        Err(_) => break,
                    }
                }
                self.execute(&mut out);
            }
            if tun {
                for _ in 0..BATCH {
                    match self.tun.recv(&mut buf) {
                        Ok(len) => self.plane.from_tun(&buf[..len], now, &mut out),
                        Err(_) => break,
                    }
                }
                self.execute(&mut out);
            }
            if Instant::now() >= next_tick {
                self.plane.tick(Instant::now(), &mut out);
                self.execute(&mut out);
                next_tick = Instant::now() + TIMER_TICK;
            }
        }
    }

    /// 等待任一来源可读，最多 `wait`。返回（命令、UDP、TUN）各自是否可读。
    fn wait(&self, wait: Duration) -> io::Result<(bool, bool, bool)> {
        let mut fds = [
            PollFd::new(&self.wake, PollFlags::IN),
            PollFd::new(&self.socket, PollFlags::IN),
            PollFd::new(&self.tun, PollFlags::IN),
        ];
        let timeout = Timespec::try_from(wait).unwrap_or(Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        });
        match poll(&mut fds, Some(&timeout)) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => return Ok((false, false, false)),
            Err(e) => return Err(e.into()),
        }
        let readable = |fd: &PollFd<'_>| !fd.revents().is_empty();
        Ok((readable(&fds[0]), readable(&fds[1]), readable(&fds[2])))
    }

    /// 处理所有待处理的命令；收到退出命令时返回 `false`。
    fn commands_ready(&mut self) -> bool {
        let mut drain = [0u8; 64];
        while self.wake.recv(&mut drain).is_ok() {}
        while let Ok(command) = self.commands.try_recv() {
            // 应答失败说明调用方已经超时放弃，命令照样执行完
            match command {
                Command::SyncPeers(peers, reply) => {
                    self.plane.sync_peers(&peers);
                    let _ = reply.send(());
                }
                Command::SetEndpoint(key, endpoint, reply) => {
                    let _ = reply.send(self.plane.set_endpoint(&key, endpoint));
                }
                Command::Rehandshake(peer, reply) => {
                    let _ = reply.send(self.plane.rehandshake(&peer));
                }
                Command::Stats(reply) => {
                    let _ = reply.send(self.plane.stats(SystemTime::now()));
                }
                Command::Filter(filter, reply) => {
                    self.plane.set_filter(filter);
                    let _ = reply.send(());
                }
                Command::GuardTlsPorts(ports, reply) => {
                    self.plane.guard_tls_ports(&ports);
                    let _ = reply.send(());
                }
                Command::SetLocal(local, reply) => {
                    self.plane.set_local(local);
                    let _ = reply.send(());
                }
                Command::Shutdown => return false,
            }
        }
        true
    }

    fn execute(&mut self, out: &mut Vec<Action>) {
        for action in out.drain(..) {
            // 发送失败（缓冲区满、没有路由）与丢包相同，由 WireGuard 和路径层处理
            match action {
                Action::Udp { to, datagram } => {
                    let _ = self.socket.send_to(&datagram, outgoing(to, self.v6));
                }
                Action::Tun(packet) => {
                    let _ = self.tun.send(&packet);
                }
                // 队列满了丢弃：只影响一次测量
                Action::Probe { from, data } => {
                    let _ = self.probes.try_send((from, data));
                }
            }
        }
    }
}
