//! Linux 上组网进程的运行时：一个后台线程持有引擎，推进选路、执行切换；每个套接字一个接收线程，把收到的
//! 探测消息交给后台线程。队列有上限，满了丢弃测量消息（只影响一次测量）。
//!
//! 套接字：组网地址上的探测端口（绑定到 `nett0`）；发往中继的探测从组网进程自己的端口发出；直连探测走
//! WireGuard 端口（[`super::wgport`]）。

use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::AsFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::KernelWireGuard;
use super::sys::bind_to_device;
use super::wgport::WgPort;
use crate::config::{ConfigError, DesiredMesh};
use crate::dataplane::INTERFACE_NAME;
use crate::engine::Engine;
use crate::event::{Event, EventSink};
use crate::probe::TUNNEL_PROBE_PORT;
use crate::prober::{Incoming, Outgoing};
use crate::run::Applier;

/// 推进的间隔：endpoint 被漫游改掉后在这个时间内纠正（design/mesh.md 第 8.3 节），也细于疑似故障时
/// 200 毫秒的加探间隔（第 8.2 节）。
const TICK: Duration = Duration::from_millis(100);
/// 后台线程的消息队列上限。
const QUEUE: usize = 1024;
/// 接收线程的读超时：据此定期检查是否该退出。
const RECV_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_DATAGRAM: usize = 2048;

enum Msg {
    Desired(Result<DesiredMesh, ConfigError>),
    Packet {
        kind: Incoming,
        from: SocketAddr,
        data: Vec<u8>,
        at: Instant,
    },
    Shutdown,
}

/// 后台线程的句柄。
pub struct Runtime {
    tx: SyncSender<Msg>,
    thread: Option<JoinHandle<()>>,
}

impl Applier for Runtime {
    fn apply(&mut self, desired: Result<DesiredMesh, ConfigError>) {
        // 后台线程退出时（只在 bug 时发生）发送失败，由 shutdown 报告
        let _ = self.tx.send(Msg::Desired(desired));
    }
}

impl Runtime {
    pub fn spawn<E: EventSink + Send + 'static>(
        engine: Engine<KernelWireGuard>,
        events: E,
    ) -> std::io::Result<Self> {
        let (tx, rx) = sync_channel(QUEUE);
        let worker_tx = tx.clone();
        let thread = std::thread::Builder::new()
            .name("nett-mesh".into())
            .spawn(move || {
                let mut worker = Worker {
                    engine,
                    events,
                    tx: worker_tx,
                    sockets: None,
                    stop: Arc::new(AtomicBool::new(false)),
                    dropped: Arc::new(AtomicU64::new(0)),
                    receivers: Vec::new(),
                };
                let mut last_tick = Instant::now();
                loop {
                    match rx.recv_timeout(TICK.saturating_sub(last_tick.elapsed())) {
                        Ok(Msg::Desired(Ok(desired))) => {
                            worker.engine.apply(&desired, &mut worker.events);
                            worker.ensure_sockets(&desired);
                        }
                        Ok(Msg::Desired(Err(e))) => worker.events.emit(Event::ConfigRejected {
                            reason: e.to_string(),
                        }),
                        Ok(Msg::Packet {
                            kind,
                            from,
                            data,
                            at,
                        }) => {
                            let out = worker.engine.on_packet(kind, from, &data, at, now_ms());
                            worker.send_all(out);
                        }
                        Ok(Msg::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
                        Err(RecvTimeoutError::Timeout) => {}
                    }
                    if last_tick.elapsed() >= TICK {
                        last_tick = Instant::now();
                        let out = worker.engine.tick(last_tick, now_ms(), &mut worker.events);
                        worker.send_all(out);
                    }
                }
                worker.stop.store(true, Ordering::Relaxed);
                for r in worker.receivers.drain(..) {
                    let _ = r.join();
                }
            })?;
        Ok(Self {
            tx,
            thread: Some(thread),
        })
    }

    /// 通知后台线程退出并等它结束。组网接口保持不变（[`crate::run`]）。
    pub fn shutdown(mut self) -> Result<(), String> {
        let _ = self.tx.send(Msg::Shutdown);
        match self.thread.take().map(JoinHandle::join) {
            Some(Err(_)) => Err("the mesh worker thread panicked; this is a bug".into()),
            _ => Ok(()),
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

struct Sockets {
    tunnel_v4: UdpSocket,
    tunnel_v6: UdpSocket,
    relay: UdpSocket,
    wg_port: Arc<WgPort>,
}

struct Worker<E> {
    engine: Engine<KernelWireGuard>,
    events: E,
    tx: SyncSender<Msg>,
    sockets: Option<Sockets>,
    stop: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
    receivers: Vec<JoinHandle<()>>,
}

impl<E: EventSink> Worker<E> {
    /// 组网接口就绪后创建探测用的套接字和接收线程（只创建一次）。
    fn ensure_sockets(&mut self, desired: &DesiredMesh) {
        if self.sockets.is_some() {
            return;
        }
        let Some(interface) = self.engine.interface() else {
            return;
        };
        let addrs: Vec<IpAddr> = interface.addresses.iter().map(|a| a.addr).collect();
        match self.open(&addrs, desired.listen_port) {
            Ok(sockets) => self.sockets = Some(sockets),
            Err(e) => self.events.emit(Event::DataPlaneFailed {
                reason: format!("opening probe sockets: {e}"),
            }),
        }
    }

    fn open(&mut self, addrs: &[IpAddr], listen_port: u16) -> std::io::Result<Sockets> {
        let tunnel = |ip: Option<&IpAddr>| -> std::io::Result<UdpSocket> {
            let ip =
                ip.ok_or_else(|| std::io::Error::other("interface has no address of this family"))?;
            let s = UdpSocket::bind(SocketAddr::new(*ip, TUNNEL_PROBE_PORT))?;
            // 只在 nett0 上收发：其他接口上发往组网地址的包不交给这个套接字
            bind_to_device(s.as_fd(), INTERFACE_NAME)?;
            Ok(s)
        };
        let tunnel_v4 = tunnel(addrs.iter().find(|a| a.is_ipv4()))?;
        let tunnel_v6 = tunnel(addrs.iter().find(|a| a.is_ipv6()))?;
        let relay = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))?;
        let wg_port = Arc::new(WgPort::open(listen_port)?);

        for (socket, kind) in [
            (tunnel_v4.try_clone()?, Incoming::Tunnel),
            (tunnel_v6.try_clone()?, Incoming::Tunnel),
            (relay.try_clone()?, Incoming::Relay),
        ] {
            socket.set_read_timeout(Some(RECV_TIMEOUT))?;
            let (tx, stop, dropped) = (self.tx.clone(), self.stop.clone(), self.dropped.clone());
            self.receivers.push(std::thread::spawn(move || {
                let mut buf = vec![0u8; MAX_DATAGRAM];
                while !stop.load(Ordering::Relaxed) {
                    if let Ok((len, from)) = socket.recv_from(&mut buf) {
                        forward(&tx, &dropped, kind, unmap(from), buf[..len].to_vec());
                    }
                }
            }));
        }
        for v6 in [false, true] {
            let (port, tx, stop, dropped) = (
                wg_port.clone(),
                self.tx.clone(),
                self.stop.clone(),
                self.dropped.clone(),
            );
            self.receivers.push(std::thread::spawn(move || {
                let mut buf = vec![0u8; MAX_DATAGRAM];
                while !stop.load(Ordering::Relaxed) {
                    let got = if v6 {
                        port.recv_v6(&mut buf)
                    } else {
                        port.recv_v4(&mut buf)
                    };
                    if let Ok(Some((from, data))) = got {
                        forward(&tx, &dropped, Incoming::Direct, from, data);
                    }
                }
            }));
        }
        Ok(Sockets {
            tunnel_v4,
            tunnel_v6,
            relay,
            wg_port,
        })
    }

    fn send_all(&mut self, out: Vec<Outgoing>) {
        let Some(s) = &self.sockets else {
            return;
        };
        for o in out {
            // 发送失败（例如没有路由）只影响这一次测量，由状态机按丢失处理
            let _ = match o {
                Outgoing::Tunnel { to, data } => {
                    let socket = if to.is_ipv4() {
                        &s.tunnel_v4
                    } else {
                        &s.tunnel_v6
                    };
                    socket.send_to(&data, to).map(drop)
                }
                Outgoing::Relay { to, data } => s.relay.send_to(&data, map_v6(to)).map(drop),
                Outgoing::Direct { to, data } => s.wg_port.send(to, &data),
            };
        }
    }
}

fn forward(
    tx: &SyncSender<Msg>,
    dropped: &AtomicU64,
    kind: Incoming,
    from: SocketAddr,
    data: Vec<u8>,
) {
    let msg = Msg::Packet {
        kind,
        from,
        data,
        at: Instant::now(),
    };
    if let Err(TrySendError::Full(_)) = tx.try_send(msg) {
        dropped.fetch_add(1, Ordering::Relaxed);
    }
}

/// 双栈套接字收到的 IPv4 来源是映射地址，还原为 IPv4。
fn unmap(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

/// 双栈套接字发往 IPv4 地址时用映射地址。
fn map_v6(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(a) => SocketAddr::new(IpAddr::V6(a.ip().to_ipv6_mapped()), a.port()),
        SocketAddr::V6(_) => addr,
    }
}
