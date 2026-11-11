//! Runtime of the mesh process: one background thread owns the engine, advances path selection and
//! performs switchovers; each socket has a receive thread that hands received probe messages to the
//! background thread. The queue is bounded; when full, measurement messages are dropped (affecting only
//! one measurement).
//!
//! Sockets: the probe port on the mesh address (sends and receives only packets that pass through the
//! mesh interface); probes to relays are sent from the mesh process's own port; direct probes are sent
//! and received with the WireGuard port as the source port, provided by the data plane
//! ([`DataPlane::direct_probes`]).

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use crate::clock::Clock;
use crate::config::{ConfigError, DesiredMesh};
use crate::coord::{Coordinator, Inbound};
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

/// Advance interval: after an endpoint is changed by roaming it is corrected within this time
/// (design/mesh.md section 8.3), and it is finer than the 200 ms extra-probe interval when a failure is
/// suspected (section 8.2). While a candidate is being probed at high frequency (section 7) or while
/// waiting for a re-handshake to complete (section 8.4), it is set to half of
/// [`FAST_RECOVERY_INTERVAL`]: advancing immediately on receipt of a probe message disturbs the timing,
/// so advancing more densely lets due probes and confirmations proceed in time.
const TICK: Duration = Duration::from_millis(100);
/// Interval for checking the local clock error (design/mesh.md section 8.4).
const CLOCK_CHECK: Duration = Duration::from_secs(10);
/// Upper limit of the background thread's message queue.
const QUEUE: usize = 1024;
/// Read timeout of the receive thread: used to periodically check whether it should exit.
const RECV_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_DATAGRAM: usize = 2048;

enum Msg {
    /// A desired state, plus the party waiting for the apply result (design/status.md section 4.1).
    Desired(Box<Result<DesiredMesh, ConfigError>>, Option<ReloadReply>),
    Packet {
        kind: Incoming,
        from: SocketAddr,
        data: Vec<u8>,
        at: Instant,
    },
    /// Local status query (design/status.md section 8): the background thread builds a snapshot and returns
    /// it through this channel.
    Status(SyncSender<StatusDoc>),
    /// nett-relay fetches its assignment (design/status.md section 3.1).
    Relay(
        Option<nett_core::transport::CertFingerprint>,
        SyncSender<Option<crate::helper::RelayAssignment>>,
    ),
    /// The transport adapter fetches its configuration.
    Transport(SyncSender<Option<nett_core::transport::TransportConfig>>),
    /// From nett-node over the coordination connection (design/status.md section 4.2).
    Coordination(Inbound),
    /// Who an address belongs to (design/names-and-diagnostics.md section 4).
    Whois(IpAddr, SyncSender<crate::status::Whois>),
    Shutdown,
}

/// Handle of the background thread.
pub struct Runtime {
    tx: SyncSender<Msg>,
    thread: Option<JoinHandle<()>>,
    coordinator: Arc<Coordinator>,
}

impl Applier for Runtime {
    fn apply(&mut self, delivery: Delivery) {
        // If sending fails when the background thread exits (only on a bug), shutdown reports it
        let _ = self
            .tx
            .send(Msg::Desired(Box::new(delivery.desired), delivery.reply));
    }
}

impl Runtime {
    /// Starts the background thread. `dns_port` is where the DNS responder answers on the mesh addresses
    /// (`crate::dns::PORT`; 0 turns it off).
    pub fn spawn<D: DataPlane + 'static, E: EventSink + Send + 'static, C: Clock + 'static>(
        engine: Engine<D>,
        events: E,
        clock: C,
        dns_port: u16,
    ) -> std::io::Result<Self> {
        let (tx, rx) = sync_channel(QUEUE);
        let worker_tx = tx.clone();
        let coordinator = Coordinator::new();
        let worker_coordinator = Arc::clone(&coordinator);
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
                    coordinator: worker_coordinator,
                    dns: None,
                    dns_port,
                };
                let mut last_tick = Instant::now();
                let mut last_clock_check: Option<Instant> = None;
                loop {
                    let interval = if worker.engine.needs_fine_ticks(Instant::now()) {
                        FAST_RECOVERY_INTERVAL / 2
                    } else {
                        TICK
                    };
                    // Advance immediately after receiving a probe message: during high-frequency probing, handle each reply
                    // as it arrives instead of waiting for the next timed advance
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
                            // If the whole desired state file is rejected at startup, use the last whole desired state accepted
                            // in the trust store (design/mesh.md section 4.2); if rejected while running, keep using the state
                            // already in effect
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
                            // Drop when the party waiting for the result has already timed out and left
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
                            // Drop when the querying party has already timed out and left
                            let _ = reply.try_send(doc);
                        }
                        Ok(Msg::Relay(fingerprint, reply)) => {
                            let _ = reply.try_send(
                                worker.engine.relay_assignment(fingerprint, Instant::now()),
                            );
                        }
                        Ok(Msg::Transport(reply)) => {
                            let _ = reply.try_send(worker.engine.transport_config());
                        }
                        Ok(Msg::Whois(address, reply)) => {
                            let _ = reply.try_send(worker.engine.whois(address));
                        }
                        Ok(Msg::Coordination(Inbound::Hub(up))) => worker.engine.set_hub(up),
                        Ok(Msg::Coordination(Inbound::PathSwitch { peer, message })) => {
                            let out = worker.engine.on_hub_message(
                                &peer,
                                &message,
                                Instant::now(),
                                clock.now_ms(),
                            );
                            worker.send_all(out);
                            tick_now = true;
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
            coordinator,
        })
    }

    /// The party behind the local interface, handed to [`crate::status::StatusServer`]. `reloads` leads to
    /// the party that reads the desired state ([`crate::source::FileSource`]); a `reload` request triggers
    /// a re-read through it.
    pub fn status_source(&self, reloads: tokio::sync::mpsc::Sender<ReloadReply>) -> RuntimeStatus {
        RuntimeStatus {
            tx: self.tx.clone(),
            reloads,
            coordinator: Arc::clone(&self.coordinator),
        }
    }

    /// Tells the background thread to exit and waits for it to finish. The mesh interface is left as is
    /// ([`crate::run`]).
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

/// Queries local status through the background thread's queue, and triggers a re-read through the party
/// that reads the desired state.
pub struct RuntimeStatus {
    tx: SyncSender<Msg>,
    reloads: tokio::sync::mpsc::Sender<ReloadReply>,
    coordinator: Arc<Coordinator>,
}

impl StatusSource for RuntimeStatus {
    fn snapshot(&self) -> Option<StatusDoc> {
        let (reply, answer) = sync_channel(1);
        // When the queue is full, do not wait: queries yield to probes and the desired state
        self.tx.try_send(Msg::Status(reply)).ok()?;
        answer.recv_timeout(QUERY_TIMEOUT).ok()
    }

    fn reload(&self) -> Option<ReloadOutcome> {
        let (reply, answer) = sync_channel(1);
        self.reloads.try_send(reply).ok()?;
        answer.recv_timeout(RELOAD_TIMEOUT).ok()
    }

    fn whois(&self, address: IpAddr) -> Option<crate::status::Whois> {
        let (reply, answer) = sync_channel(1);
        self.tx.try_send(Msg::Whois(address, reply)).ok()?;
        answer.recv_timeout(QUERY_TIMEOUT).ok()
    }

    fn coordinate(&self, stream: std::os::unix::net::UnixStream) -> std::io::Result<()> {
        let tx = self.tx.clone();
        // A full queue drops the line: the Hub state is sent again on change, and switch messages are
        // resent
        self.coordinator.attach(stream, move |inbound| {
            let _ = tx.try_send(Msg::Coordination(inbound));
        })
    }
}

impl crate::helper::HelperSource for RuntimeStatus {
    fn relay(
        &self,
        fingerprint: Option<nett_core::transport::CertFingerprint>,
    ) -> Option<Option<crate::helper::RelayAssignment>> {
        let (reply, answer) = sync_channel(1);
        self.tx.try_send(Msg::Relay(fingerprint, reply)).ok()?;
        answer.recv_timeout(QUERY_TIMEOUT).ok()
    }

    fn transport(&self) -> Option<Option<nett_core::transport::TransportConfig>> {
        let (reply, answer) = sync_channel(1);
        self.tx.try_send(Msg::Transport(reply)).ok()?;
        answer.recv_timeout(QUERY_TIMEOUT).ok()
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
    /// The first desired state (the read at startup) has been processed.
    started: bool,
    /// The coordination connection with nett-node: switch messages through the Hub go out here.
    coordinator: Arc<Coordinator>,
    /// The DNS responder, once the mesh addresses are up, and the port it answers on (0: none).
    dns: Option<crate::dns::DnsServer>,
    dns_port: u16,
}

impl<D: DataPlane, E: EventSink> Worker<D, E> {
    /// Creates the probe sockets and receive threads once the mesh interface is ready (only once).
    fn ensure_sockets(&mut self) {
        let Some(interface) = self.engine.interface() else {
            return;
        };
        let addrs: Vec<IpAddr> = interface.spec.addresses.iter().map(|a| a.addr).collect();
        if self.sockets.is_none() {
            match self.open(&addrs, interface.listen_port) {
                Ok(sockets) => self.sockets = Some(sockets),
                Err(e) => self.events.emit(Event::DataPlaneFailed {
                    reason: format!("opening probe sockets: {e}"),
                }),
            }
        }
        // The DNS responder on the mesh addresses (design/names-and-diagnostics.md section 2): if the
        // port cannot be bound, names do not resolve and the mesh works as before
        if self.dns.is_none() && self.dns_port != 0 {
            match crate::dns::DnsServer::spawn(&addrs, self.dns_port) {
                Ok(server) => {
                    self.dns = Some(server);
                    self.events.emit(Event::NamesReady);
                    // macOS sends the suffix to this machine's own responder (the mesh process runs as
                    // root there); elsewhere the service setup does it
                    #[cfg(target_os = "macos")]
                    if let Some(IpAddr::V4(v4)) = addrs.iter().find(|a| a.is_ipv4()) {
                        crate::macos::point_resolver(*v4);
                    }
                }
                Err(e) => self.events.emit(Event::NamesUnavailable {
                    reason: format!(
                        "binding UDP port {} on the mesh addresses: {e}",
                        self.dns_port
                    ),
                }),
            }
        }
        if let Some(dns) = &self.dns {
            dns.set_names(self.engine.name_table());
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
            // A send failure (for example no route) affects only this one measurement; the state machine treats it
            // as lost
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
                Outgoing::Hub { peer, data } => {
                    self.coordinator.send(&peer, &data);
                    Ok(())
                }
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

/// An IPv4 source received on a dual-stack socket is a mapped address; restores it to IPv4.
fn unmap(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

/// Uses the mapped address when sending to an IPv4 address from a dual-stack socket.
fn map_v6(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(a) => SocketAddr::new(IpAddr::V6(a.ip().to_ipv6_mapped()), a.port()),
        SocketAddr::V6(_) => addr,
    }
}
