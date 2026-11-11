//! Data plane thread (design/userspace.md section 4): uses `poll` to wait on the TUN, the WireGuard port
//! and control commands at the same time; the sessions, peer table and connection table belong only to
//! this thread. Control commands arrive through a bounded queue, and the sender waits for the reply with a
//! timeout.

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

/// Upper limit of the control command queue.
const COMMANDS: usize = 64;
/// Upper limit on waiting for the data plane thread's reply (hard rule 14).
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
/// At most this many packets are read from one source per wakeup, with the TUN and UDP handled in turn,
/// so a flood on one side does not starve the other.
const BATCH: usize = 64;
/// Receive buffer: the maximum length of a UDP datagram or IP packet.
const MAX_PACKET: usize = 65_535;
/// Upper limit of the queue of direct probes handed to the engine; when full they are dropped (affecting
/// only one measurement).
const PROBES: usize = 256;
/// Upper limit on the wait of [`DirectRecv::recv`].
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

/// Handle of the data plane thread; dropping it makes the thread exit and waits for it to finish.
pub(super) struct Worker {
    commands: SyncSender<Command>,
    wake: UnixDatagram,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    /// Starts the data plane thread. `socket` is the WireGuard port's socket (non-blocking); direct probes and
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

/// Direct probes and cookie copies the data plane thread hands to the engine.
pub(super) struct ProbeQueue(Receiver<(SocketAddr, Vec<u8>)>);

impl DirectRecv for ProbeQueue {
    fn recv(&mut self) -> io::Result<Vec<(SocketAddr, Vec<u8>)>> {
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

/// Sends direct probes from the WireGuard port: shares the same socket with the data plane thread.
pub(super) struct ProbeSender {
    pub(super) socket: UdpSocket,
}

impl DirectSend for ProbeSender {
    fn send(&self, to: SocketAddr, data: &[u8]) -> io::Result<()> {
        let v6 = self.socket.local_addr()?.is_ipv6();
        self.socket.send_to(data, outgoing(to, v6)).map(drop)
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

    /// Waits until any source is readable, for at most `wait`. Returns whether each of (command, UDP, TUN) is
    /// readable.
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

    /// Handles all pending commands; returns `false` when an exit command is received.
    fn commands_ready(&mut self) -> bool {
        let mut drain = [0u8; 64];
        while self.wake.recv(&mut drain).is_ok() {}
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
            // A send failure (buffer full, no route) is the same as packet loss, handled by WireGuard and the path
            // layer
            match action {
                Action::Udp { to, datagram } => {
                    let _ = self.socket.send_to(&datagram, outgoing(to, self.v6));
                }
                Action::Tun(packet) => {
                    let _ = self.tun.send(&packet);
                }
                // Dropped when the queue is full: affects only one measurement
                Action::Probe { from, data } => {
                    let _ = self.probes.try_send((from, data));
                }
            }
        }
    }
}
