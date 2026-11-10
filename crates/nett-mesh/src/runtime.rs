//! 组网进程的运行时：一个后台线程持有引擎，推进选路、执行切换；每个套接字一个接收线程，把收到的
//! 探测消息交给后台线程。队列有上限，满了丢弃测量消息（只影响一次测量）。
//!
//! 套接字：组网地址上的探测端口（只收发经组网接口的包）；发往中继的探测从组网进程自己的端口发出；直连
//! 探测以 WireGuard 端口为源端口收发，由数据面提供（[`DataPlane::direct_probes`]）。

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use crate::clock::Clock;
use crate::config::{ConfigError, DesiredMesh};
use crate::dataplane::{DataPlane, DirectProbes, DirectSend};
use crate::engine::Engine;
use crate::event::{Event, EventSink};
use crate::path::FAST_RECOVERY_INTERVAL;
use crate::probe::TUNNEL_PROBE_PORT;
use crate::prober::{Incoming, Outgoing};
use crate::run::{Applier, Delivery};
use crate::status::{
    QUERY_TIMEOUT, RELOAD_TIMEOUT, Recorder, ReloadOutcome, ReloadReply, StatusDoc, StatusSource,
};

/// 推进的间隔：endpoint 被漫游改掉后在这个时间内纠正（design/mesh.md 第 8.3 节），也细于疑似故障时
/// 200 毫秒的加探间隔（第 8.2 节）。有候选在高频探测时（第 7 节）、等待重新握手完成时（第 8.4 节）改为
/// [`FAST_RECOVERY_INTERVAL`] 的一半：收到探测消息时的立即推进会打乱定时，推进得更密，到期的探测和
/// 确认才能及时进行。
const TICK: Duration = Duration::from_millis(100);
/// 检查本机时钟误差的间隔（design/mesh.md 第 8.4 节）。
const CLOCK_CHECK: Duration = Duration::from_secs(10);
/// 后台线程的消息队列上限。
const QUEUE: usize = 1024;
/// 接收线程的读超时：据此定期检查是否该退出。
const RECV_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_DATAGRAM: usize = 2048;

enum Msg {
    /// 一份期望状态，以及在等应用结果的一方（design/status.md 第 4.1 节）。
    Desired(Box<Result<DesiredMesh, ConfigError>>, Option<ReloadReply>),
    Packet {
        kind: Incoming,
        from: SocketAddr,
        data: Vec<u8>,
        at: Instant,
    },
    /// 本机状态的查询（design/status.md 第 8 节）：后台线程生成快照，经这个通道交回。
    Status(SyncSender<StatusDoc>),
    Shutdown,
}

/// 后台线程的句柄。
pub struct Runtime {
    tx: SyncSender<Msg>,
    thread: Option<JoinHandle<()>>,
}

impl Applier for Runtime {
    fn apply(&mut self, delivery: Delivery) {
        // 后台线程退出时（只在 bug 时发生）发送失败，由 shutdown 报告
        let _ = self
            .tx
            .send(Msg::Desired(Box::new(delivery.desired), delivery.reply));
    }
}

impl Runtime {
    pub fn spawn<D: DataPlane + 'static, E: EventSink + Send + 'static, C: Clock + 'static>(
        engine: Engine<D>,
        events: E,
        clock: C,
    ) -> std::io::Result<Self> {
        let (tx, rx) = sync_channel(QUEUE);
        let worker_tx = tx.clone();
        let thread = std::thread::Builder::new()
            .name("nett-mesh".into())
            .spawn(move || {
                let mut worker = Worker {
                    engine,
                    events: Recorder::new(events),
                    tx: worker_tx,
                    sockets: None,
                    stop: Arc::new(AtomicBool::new(false)),
                    dropped: Arc::new(AtomicU64::new(0)),
                    receivers: Vec::new(),
                    started: false,
                };
                let mut last_tick = Instant::now();
                let mut last_clock_check: Option<Instant> = None;
                loop {
                    let interval = if worker.engine.needs_fine_ticks(Instant::now()) {
                        FAST_RECOVERY_INTERVAL / 2
                    } else {
                        TICK
                    };
                    // 收到探测消息后立即推进：高频探测时应答一到就处理，不等下一次定时推进
                    let mut tick_now = false;
                    match rx.recv_timeout(interval.saturating_sub(last_tick.elapsed())) {
                        Ok(Msg::Desired(desired, reply)) => {
                            let applied = match *desired {
                                Ok(desired) => {
                                    worker.events.begin_apply();
                                    worker.engine.apply(&desired, &mut worker.events)
                                }
                                Err(e) => {
                                    let reason = e.to_string();
                                    worker.events.emit(Event::ConfigRejected {
                                        reason: reason.clone(),
                                    });
                                    Err(reason)
                                }
                            };
                            // 启动时期望状态文件整份被拒绝：改用信任存储中最近一次整份接受的那一份
                            // （design/mesh.md 第 4.2 节）；运行中被拒绝时继续使用已生效的状态
                            if !worker.started && applied.is_err() {
                                worker.engine.apply_saved(&mut worker.events);
                            }
                            worker.started = true;
                            worker.ensure_sockets();
                            let outcome = match applied {
                                Ok(()) => ReloadOutcome::Applied {
                                    problems: worker.events.problems(
                                        worker.engine.node_id(),
                                        worker.engine.names(),
                                        Instant::now(),
                                    ),
                                },
                                Err(reason) => ReloadOutcome::Rejected { reason },
                            };
                            // 等结果的一方已经超时离开时丢弃
                            if let Some(reply) = reply {
                                let _ = reply.try_send(outcome);
                            }
                        }
                        Ok(Msg::Packet {
                            kind,
                            from,
                            data,
                            at,
                        }) => {
                            let out =
                                worker
                                    .engine
                                    .on_packet(kind, from, &data, at, clock.now_ms());
                            worker.send_all(out);
                            tick_now = true;
                        }
                        Ok(Msg::Status(reply)) => {
                            let now = Instant::now();
                            let mut doc = worker.engine.status(
                                now,
                                SystemTime::now(),
                                worker.events.started_at(),
                            );
                            worker.events.fill(&mut doc, worker.engine.names(), now);
                            // 查询的一方已经超时离开时丢弃
                            let _ = reply.try_send(doc);
                        }
                        Ok(Msg::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
                        Err(RecvTimeoutError::Timeout) => {}
                    }
                    if last_clock_check.is_none_or(|t| t.elapsed() >= CLOCK_CHECK) {
                        last_clock_check = Some(Instant::now());
                        worker.engine.set_clock_trusted(clock.trusted());
                    }
                    if tick_now || last_tick.elapsed() >= interval {
                        last_tick = Instant::now();
                        let out = worker
                            .engine
                            .tick(last_tick, clock.now_ms(), &mut worker.events);
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

    /// 本机接口背后的一方，交给 [`crate::status::StatusServer`]。`reloads` 通往读取期望状态的一方
    /// （[`crate::source::FileSource`]），`reload` 请求经它触发重新读取。
    pub fn status_source(&self, reloads: tokio::sync::mpsc::Sender<ReloadReply>) -> RuntimeStatus {
        RuntimeStatus {
            tx: self.tx.clone(),
            reloads,
        }
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

struct Sockets {
    tunnel_v4: UdpSocket,
    tunnel_v6: UdpSocket,
    relay: UdpSocket,
    direct: Box<dyn DirectSend>,
}

/// 经后台线程的队列查询本机状态，经读取期望状态的一方触发重新读取。
pub struct RuntimeStatus {
    tx: SyncSender<Msg>,
    reloads: tokio::sync::mpsc::Sender<ReloadReply>,
}

impl StatusSource for RuntimeStatus {
    fn snapshot(&self) -> Option<StatusDoc> {
        let (reply, answer) = sync_channel(1);
        // 队列满时不等：查询让位给探测与期望状态
        self.tx.try_send(Msg::Status(reply)).ok()?;
        answer.recv_timeout(QUERY_TIMEOUT).ok()
    }

    fn reload(&self) -> Option<ReloadOutcome> {
        let (reply, answer) = sync_channel(1);
        self.reloads.try_send(reply).ok()?;
        answer.recv_timeout(RELOAD_TIMEOUT).ok()
    }
}

struct Worker<D, E> {
    engine: Engine<D>,
    events: E,
    tx: SyncSender<Msg>,
    sockets: Option<Sockets>,
    stop: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
    receivers: Vec<JoinHandle<()>>,
    /// 已经处理过第一份期望状态（启动时的读取）。
    started: bool,
}

impl<D: DataPlane, E: EventSink> Worker<D, E> {
    /// 组网接口就绪后创建探测用的套接字和接收线程（只创建一次）。
    fn ensure_sockets(&mut self) {
        if self.sockets.is_some() {
            return;
        }
        let Some(interface) = self.engine.interface() else {
            return;
        };
        let addrs: Vec<IpAddr> = interface.spec.addresses.iter().map(|a| a.addr).collect();
        match self.open(&addrs, interface.listen_port) {
            Ok(sockets) => self.sockets = Some(sockets),
            Err(e) => self.events.emit(Event::DataPlaneFailed {
                reason: format!("opening probe sockets: {e}"),
            }),
        }
    }

    fn open(&mut self, addrs: &[IpAddr], listen_port: u16) -> std::io::Result<Sockets> {
        let dataplane = self.engine.dataplane_mut();
        let tunnel = |ip: Option<&IpAddr>| -> std::io::Result<UdpSocket> {
            let ip =
                ip.ok_or_else(|| std::io::Error::other("interface has no address of this family"))?;
            let addr = SocketAddr::new(*ip, TUNNEL_PROBE_PORT);
            dataplane
                .bind_tunnel(addr)
                .map_err(|e| std::io::Error::new(e.kind(), format!("binding {addr}: {e}")))
        };
        let tunnel_v4 = tunnel(addrs.iter().find(|a| a.is_ipv4()))?;
        let tunnel_v6 = tunnel(addrs.iter().find(|a| a.is_ipv6()))?;
        let relay = dataplane.bind_underlay(0)?;
        let DirectProbes {
            send: direct,
            recv: mut log,
        } = dataplane
            .direct_probes(listen_port)
            .map_err(std::io::Error::other)?;

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
        let (tx, stop, dropped) = (self.tx.clone(), self.stop.clone(), self.dropped.clone());
        self.receivers.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok(probes) = log.recv() {
                    for (from, data) in probes {
                        forward(&tx, &dropped, Incoming::Direct, from, data);
                    }
                }
            }
        }));
        Ok(Sockets {
            tunnel_v4,
            tunnel_v6,
            relay,
            direct,
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
                Outgoing::Direct { to, data } => s.direct.send(to, &data),
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
