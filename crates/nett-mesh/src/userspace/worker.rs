//! Data plane thread (design/userspace.md section 4): uses `poll` to wait on the TUN, the WireGuard port,
//! the obfuscated port and control commands at the same time; the sessions, peer table, connection table
//! and obfuscation keys belong only to this thread. Control commands arrive through a bounded queue, and
//! the sender waits for the reply with a timeout; the engine's probes arrive through another, so this
//! thread wraps those that go to an obfuscated port.

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::AsFd as _;
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
use crate::dataplane::{
    DataPlaneError, ObfsSpec, PeerSpec, PeerStat, UdpPort, WgPortRecv, WgPortSend,
};

/// Upper limit of the control command queue.
const COMMANDS: usize = 64;
/// Upper limit on waiting for the data plane thread's reply (hard rule 14).
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
/// At most this many packets are read from one source per wakeup, with the TUN and UDP handled in turn,
/// so a flood on one side does not starve the other.
const BATCH: usize = 64;
/// Receive buffer: the maximum length of a UDP datagram or IP packet.
const MAX_PACKET: usize = 65_535;
/// Upper limit of the queue of probe messages handed to the engine; when full they are dropped (affecting
/// only one measurement).
const PROBES: usize = 256;
/// Upper limit on the wait of [`WgPortRecv::recv`].
const PROBE_WAIT: Duration = Duration::from_millis(500);
/// Upper limit of the queue of the engine's probes waiting to be sent; when full they are dropped, as
/// a lost probe.
const PROBES_OUT: usize = 256;

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
    /// The kernel's netfilter has its first rule set in place (design/userspace.md section 4.2).
    Netfilter(SyncSender<()>),
    GuardTlsPorts(Vec<u16>, SyncSender<()>),
    SetLocal(Vec<IpAddr>, SyncSender<()>),
    SetNames(crate::dns::NameTable, SyncSender<()>),
    /// The obfuscation keys, and the obfuscated port's socket when it changes (`Some`): bound by the
    /// caller, so a port that cannot be bound is reported there.
    Obfs(ObfsSpec, Option<Option<UdpSocket>>, SyncSender<()>),
    Shutdown,
}

/// Handle of the data plane thread; dropping it makes the thread exit and waits for it to finish.
pub(super) struct Worker {
    commands: SyncSender<Command>,
    probes_out: SyncSender<(UdpPort, SocketAddr, Vec<u8>)>,
    wake: UnixDatagram,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    /// Starts the data plane thread. `socket` is the WireGuard port's socket (non-blocking); probe messages and
    /// cookie copies are put into the returned receiver.
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
        let (probes_out, probes_out_rx) = sync_channel(PROBES_OUT);
        let (wake, wake_rx) = UnixDatagram::pair()?;
        wake.set_nonblocking(true)?;
        wake_rx.set_nonblocking(true)?;
        socket.set_nonblocking(true)?;
        let granted = crate::sockbuf::enlarge_receive_buffer(&socket);
        tracing::debug!(bytes = ?granted, "data plane: receive buffer");
        let mut loop_ = Loop {
            plane,
            tun,
            v6: socket.local_addr()?.is_ipv6(),
            socket,
            obfs: None,
            wake: wake_rx,
            commands: rx,
            probes: probes_tx,
            probes_out: probes_out_rx,
            #[cfg(target_os = "linux")]
            batch: Batch {
                recv: super::mmsg::RecvBatch::new(),
                wireguard: Vec::with_capacity(super::mmsg::SLOTS),
                obfs: Vec::with_capacity(super::mmsg::SLOTS),
            },
        };
        let thread = std::thread::Builder::new()
            .name("nett-dataplane".into())
            .spawn(move || loop_.run())?;
        Ok((
            Self {
                commands,
                probes_out,
                wake,
                thread: Some(thread),
            },
            ProbeQueue(probes_rx),
        ))
    }

    /// The engine's end for sending probes through this thread.
    pub(super) fn probe_sender(&self) -> io::Result<ProbeSender> {
        Ok(ProbeSender {
            queue: self.probes_out.clone(),
            wake: self.wake.try_clone()?,
        })
    }

    /// Sends a command and waits for the reply.
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
        // A wakeup failure happens only when the buffer is full, and then the thread already has a pending wakeup
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

/// Probe messages and cookie copies the data plane thread hands to the engine.
pub(super) struct ProbeQueue(Receiver<(UdpPort, SocketAddr, Vec<u8>)>);

impl WgPortRecv for ProbeQueue {
    fn recv(&mut self) -> io::Result<Vec<(UdpPort, SocketAddr, Vec<u8>)>> {
        let first = match self.0.recv_timeout(PROBE_WAIT) {
            Ok(first) => first,
            Err(RecvTimeoutError::Timeout) => return Ok(Vec::new()),
            Err(RecvTimeoutError::Disconnected) => {
                // The data plane thread has already exited; still return on timeout, so the caller checks as usual
                // whether it should exit
                std::thread::sleep(PROBE_WAIT);
                return Ok(Vec::new());
            }
        };
        let mut batch = vec![first];
        batch.extend(self.0.try_iter().take(PROBES));
        Ok(batch)
    }
}

/// Sends probes through the data plane thread, which sends them from the WireGuard port or the
/// obfuscated port, wrapped where they go to an obfuscated port.
pub(super) struct ProbeSender {
    queue: SyncSender<(UdpPort, SocketAddr, Vec<u8>)>,
    wake: UnixDatagram,
}

impl ProbeSender {
    fn queue(&self, port: UdpPort, to: SocketAddr, data: &[u8]) -> io::Result<()> {
        self.queue
            .try_send((port, to, data.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "probe queue full"))?;
        // A wakeup failure happens only when the buffer is full, and then the thread already has a
        // pending wakeup
        let _ = self.wake.send(&[0]);
        Ok(())
    }
}

impl WgPortSend for ProbeSender {
    fn send(&self, to: SocketAddr, data: &[u8]) -> io::Result<()> {
        self.queue(UdpPort::WireGuard, to, data)
    }

    fn send_obfs(&self, to: SocketAddr, data: &[u8]) -> io::Result<()> {
        self.queue(UdpPort::Obfs, to, data)
    }
}

/// Uses the mapped address when a dual-stack socket sends to an IPv4 address.
fn outgoing(to: SocketAddr, v6: bool) -> SocketAddr {
    match to {
        SocketAddr::V4(a) if v6 => SocketAddr::new(IpAddr::V6(a.ip().to_ipv6_mapped()), a.port()),
        _ => to,
    }
}

/// An IPv4 source received on a dual-stack socket is a mapped address; restores it to IPv4.
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
    /// This machine's obfuscated port, when it offers one (design/userspace.md section 4.1), and
    /// whether it is a dual-stack socket.
    obfs: Option<(UdpSocket, bool)>,
    v6: bool,
    wake: UnixDatagram,
    commands: Receiver<Command>,
    probes: SyncSender<(UdpPort, SocketAddr, Vec<u8>)>,
    probes_out: Receiver<(UdpPort, SocketAddr, Vec<u8>)>,
    /// Batched receive and send on Linux (design/userspace.md section 4).
    #[cfg(target_os = "linux")]
    batch: Batch,
}

/// The receive buffer and what waits to be sent on each port, for one wakeup.
#[cfg(target_os = "linux")]
struct Batch {
    recv: super::mmsg::RecvBatch,
    wireguard: Vec<(SocketAddr, Vec<u8>)>,
    obfs: Vec<(SocketAddr, Vec<u8>)>,
}

/// Which of the data plane thread's sources are readable.
struct Ready {
    commands: bool,
    udp: bool,
    tun: bool,
    obfs: bool,
}

impl<S: Sessions, T: Tun> Loop<S, T> {
    fn run(&mut self) {
        let mut buf = vec![0u8; MAX_PACKET];
        let mut out = Vec::new();
        let mut next_tick = Instant::now() + TIMER_TICK;
        loop {
            let wait = next_tick.saturating_duration_since(Instant::now());
            let ready = self.wait(wait).unwrap_or_else(|e| {
                tracing::error!(error = %e, "data plane: poll failed");
                std::thread::sleep(TIMER_TICK);
                Ready {
                    commands: true,
                    udp: true,
                    tun: true,
                    obfs: true,
                }
            });
            if ready.commands && !self.commands_ready(&mut out) {
                return;
            }
            let now = Instant::now();
            if ready.udp {
                self.receive(UdpPort::WireGuard, &mut buf, now, &mut out);
                self.execute(&mut out);
            }
            if ready.obfs {
                self.receive(UdpPort::Obfs, &mut buf, now, &mut out);
                self.execute(&mut out);
            }
            if ready.tun {
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

    /// Takes what `port` holds, at most [`BATCH`] datagrams: in one `recvmmsg` on Linux, one at a
    /// time elsewhere.
    fn receive(&mut self, port: UdpPort, buf: &mut [u8], now: Instant, out: &mut Vec<Action>) {
        let socket = match port {
            UdpPort::WireGuard => &self.socket,
            UdpPort::Obfs => match &self.obfs {
                Some((socket, _)) => socket,
                None => return,
            },
        };
        let mut hand = |plane: &mut Plane<S>, from: SocketAddr, datagram: &[u8]| match port {
            UdpPort::WireGuard => plane.from_udp(incoming(from), datagram, now, out),
            UdpPort::Obfs => plane.from_obfs(incoming(from), datagram, now, out),
        };
        #[cfg(target_os = "linux")]
        {
            let _ = buf;
            if let Ok(n) = self.batch.recv.recv(socket) {
                for i in 0..n {
                    if let Some((datagram, from)) = self.batch.recv.get(i) {
                        hand(&mut self.plane, from, datagram);
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        for _ in 0..BATCH {
            match socket.recv_from(buf) {
                Ok((len, from)) => hand(&mut self.plane, from, &buf[..len]),
                Err(_) => break,
            }
        }
    }

    /// Waits until any source is readable, for at most `wait`.
    fn wait(&self, wait: Duration) -> io::Result<Ready> {
        let obfs = self.obfs.as_ref().map(|(s, _)| s.as_fd());
        let mut fds = [
            PollFd::new(&self.wake, PollFlags::IN),
            PollFd::new(&self.socket, PollFlags::IN),
            PollFd::new(&self.tun, PollFlags::IN),
            PollFd::from_borrowed_fd(obfs.unwrap_or(self.wake.as_fd()), PollFlags::IN),
        ];
        let watched = if obfs.is_some() { 4 } else { 3 };
        let timeout = Timespec::try_from(wait).unwrap_or(Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        });
        let none = Ready {
            commands: false,
            udp: false,
            tun: false,
            obfs: false,
        };
        match poll(&mut fds[..watched], Some(&timeout)) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => return Ok(none),
            Err(e) => return Err(e.into()),
        }
        let readable = |i: usize| i < watched && !fds[i].revents().is_empty();
        Ok(Ready {
            commands: readable(0),
            udp: readable(1),
            tun: readable(2),
            obfs: readable(3),
        })
    }

    /// Handles all pending commands and sends the engine's probes; returns `false` when an exit
    /// command is received.
    fn commands_ready(&mut self, out: &mut Vec<Action>) -> bool {
        let mut drain = [0u8; 64];
        while self.wake.recv(&mut drain).is_ok() {}
        for (port, to, data) in self.probes_out.try_iter().take(PROBES_OUT) {
            self.plane.probe_out(port, to, data, out);
        }
        self.execute(out);
        while let Ok(command) = self.commands.try_recv() {
            // A failed reply means the caller has already timed out and given up; the command is executed to
            // completion all the same
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
                Command::Netfilter(reply) => {
                    self.plane.hand_to_netfilter();
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
                Command::SetNames(names, reply) => {
                    self.plane.set_names(names);
                    let _ = reply.send(());
                }
                Command::Obfs(spec, socket, reply) => {
                    if let Some(socket) = socket {
                        self.obfs = socket.and_then(|s| {
                            s.set_nonblocking(true).ok()?;
                            crate::sockbuf::enlarge_receive_buffer(&s);
                            let v6 = s.local_addr().ok()?.is_ipv6();
                            Some((s, v6))
                        });
                    }
                    self.plane.set_obfs(&spec);
                    let _ = reply.send(());
                }
                Command::Shutdown => return false,
            }
        }
        true
    }

    fn execute(&mut self, out: &mut Vec<Action>) {
        for action in out.drain(..) {
            // A send failure (buffer full, no route) is the same as packet loss, handled by WireGuard and the path
            // layer
            match action {
                // On Linux what goes out on a port waits for one `sendmmsg` at the end, in order
                #[cfg(target_os = "linux")]
                Action::Udp {
                    port: UdpPort::WireGuard,
                    to,
                    datagram,
                } => self.batch.wireguard.push((outgoing(to, self.v6), datagram)),
                #[cfg(target_os = "linux")]
                Action::Udp {
                    port: UdpPort::Obfs,
                    to,
                    datagram,
                } => {
                    if let Some((_, v6)) = &self.obfs {
                        self.batch.obfs.push((outgoing(to, *v6), datagram));
                    }
                }
                #[cfg(not(target_os = "linux"))]
                Action::Udp {
                    port: UdpPort::WireGuard,
                    to,
                    datagram,
                } => {
                    let _ = self.socket.send_to(&datagram, outgoing(to, self.v6));
                }
                #[cfg(not(target_os = "linux"))]
                Action::Udp {
                    port: UdpPort::Obfs,
                    to,
                    datagram,
                } => {
                    if let Some((obfs, v6)) = &self.obfs {
                        let _ = obfs.send_to(&datagram, outgoing(to, *v6));
                    }
                }
                Action::Tun(packet) => {
                    let _ = self.tun.send(&packet);
                }
                // Dropped when the queue is full: affects only one measurement
                Action::Probe { port, from, data } => {
                    let _ = self.probes.try_send((port, from, data));
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            super::mmsg::send(&self.socket, &self.batch.wireguard);
            self.batch.wireguard.clear();
            if let Some((obfs, _)) = &self.obfs {
                super::mmsg::send(obfs, &self.batch.obfs);
            }
            self.batch.obfs.clear();
        }
    }
}
