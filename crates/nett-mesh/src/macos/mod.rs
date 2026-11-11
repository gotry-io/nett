//! Platform backend for macOS native members (design/userspace.md section 6): utun, addresses and routes
//! use only system calls (hard rule 1: the mesh process does not execute external commands); the
//! sockets toward the underlying network bind to the physical interface carrying the default route and
//! do not enter the proxy app's TUN, and rebind when the physical interface changes.

mod route;
mod sys;

use std::collections::BTreeSet;
use std::io::{self, IoSlice};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use nett_core::prefix::IpPrefix;

use crate::dataplane::{DataPlaneError, InterfaceAddress, InterfaceSpec};
use crate::userspace::{Platform, Tun, dual_stack_udp};

/// Address family header before each utun packet (network byte order).
const AF_INET: u32 = 2;
const AF_INET6: u32 = 30;
/// After the routing table changes, wait this long before re-selecting the physical interface: one
/// network switch produces many messages in a row.
const SETTLE: Duration = Duration::from_millis(300);
/// Read timeout of the monitor thread for routing messages: used to periodically check whether it should
/// exit.
const MONITOR_TIMEOUT: Duration = Duration::from_secs(1);
/// Maximum number of underlay sockets bound to the physical interface (the WireGuard port, probes to
/// relays).
const MAX_UNDERLAY: usize = 8;

/// Effective user ID of the peer process of a Unix socket (design/status.md section 3).
pub(crate) fn peer_uid(fd: BorrowedFd<'_>) -> io::Result<u32> {
    sys::peer_uid(fd)
}

/// System clock; the error is the maximum error reported by the kernel (`ntp_gettime`).
pub struct SystemClock;

impl crate::clock::Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        crate::clock::system_now_ms()
    }

    fn trusted(&self) -> bool {
        sys::max_clock_error().is_ok_and(|e| e <= crate::clock::MAX_TRUSTED_ERROR)
    }
}

/// Logging when running as a launchd service (design/userspace.md section 6.3): goes into the system log
/// through syslog, with its size managed by the system, and can be viewed with
/// `log show --predicate 'process == "nett"'`.
pub struct SystemLog;

impl SystemLog {
    pub fn open() -> Self {
        sys::openlog();
        Self
    }

    /// info is recorded as notice: the system log by default persists only notice and above, and state
    /// changes must be kept.
    pub fn write(&self, level: tracing::Level, line: &str) {
        let priority = match level {
            tracing::Level::ERROR => libc::LOG_ERR,
            tracing::Level::WARN => libc::LOG_WARNING,
            tracing::Level::INFO => libc::LOG_NOTICE,
            _ => libc::LOG_DEBUG,
        };
        sys::syslog(priority, line.trim_end());
    }
}

/// The control socket of a utun: each send or receive carries one IP packet with a 4-byte address family
/// header.
pub struct Utun(OwnedFd);

impl AsFd for Utun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl Tun for Utun {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = rustix::io::read(&self.0, &mut *buf)?;
        if n < 4 {
            return Err(io::Error::other(
                "utun packet without its address family header",
            ));
        }
        buf.copy_within(4..n, 0);
        Ok(n - 4)
    }

    fn send(&self, packet: &[u8]) -> io::Result<()> {
        let family = match packet.first().map(|b| b >> 4) {
            Some(4) => AF_INET,
            Some(6) => AF_INET6,
            _ => return Err(io::Error::other("not an IP packet")),
        };
        let header = family.to_be_bytes();
        rustix::io::writev(&self.0, &[IoSlice::new(&header), IoSlice::new(packet)])?;
        Ok(())
    }
}

/// Sockets toward the underlying network, and the physical interface they are currently bound to.
#[derive(Default)]
struct Underlay {
    sockets: Vec<UdpSocket>,
    index: Option<u16>,
}

impl Underlay {
    /// Re-selects the physical interface from the routing table; when it changes, rebinds all sockets.
    fn refresh(&mut self) {
        let index = physical_interface();
        if index == self.index {
            return;
        }
        for socket in &self.sockets {
            bind_physical(socket, index);
        }
        tracing::info!(
            interface = index
                .and_then(|i| sys::if_name_of(u32::from(i)))
                .unwrap_or_default(),
            "underlay interface for WireGuard and relay probes"
        );
        self.index = index;
    }
}

fn physical_interface() -> Option<u16> {
    let dump = sys::dump_gateway_routes()
        .inspect_err(|e| tracing::warn!(error = %e, "reading the routing table"))
        .ok()?;
    route::physical(&route::defaults(&dump), |i| sys::if_name_of(u32::from(i)))
}

/// Binds a dual-stack socket. `IPV6_BOUND_IF` also applies to traffic sent to IPv4-mapped addresses
/// (measured: after binding en0, packets to the IPv4 addresses taken over by the proxy app go out from
/// en0; without binding they go out from the proxy app's utun); `IP_BOUND_IF` returns EINVAL on an IPv6
/// socket. When there is no physical interface the binding is removed and packets are sent per the
/// routing table.
fn bind_physical(socket: &UdpSocket, index: Option<u16>) {
    let index = u32::from(index.unwrap_or(0));
    if let Err(e) = sys::bind_to_interface(socket.as_fd(), index, true) {
        tracing::warn!(error = %e, "binding an underlay socket to the physical interface");
    }
}

/// Monitors the routing table: when the physical interface changes (switching Wi-Fi, plugging a cable,
/// waking up) rebinds the underlay sockets (design/userspace.md section 6.4).
struct Monitor {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Monitor {
    fn spawn(underlay: Arc<Mutex<Underlay>>) -> io::Result<Self> {
        let socket = sys::route_socket()?;
        rustix::net::sockopt::set_socket_timeout(
            &socket,
            rustix::net::sockopt::Timeout::Recv,
            Some(MONITOR_TIMEOUT),
        )?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("nett-netmon".into())
            .spawn(move || {
                let mut buf = vec![0u8; 2048];
                while !flag.load(Ordering::Relaxed) {
                    if rustix::io::read(&socket, &mut buf).is_err() {
                        continue;
                    }
                    std::thread::sleep(SETTLE);
                    // Messages that arrived during the wait are handled together
                    let _ = rustix::io::ioctl_fionbio(&socket, true);
                    while rustix::io::read(&socket, &mut buf).is_ok() {}
                    let _ = rustix::io::ioctl_fionbio(&socket, false);
                    underlay
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .refresh();
                }
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub struct MacTun {
    /// A write-only routing socket: adds and deletes routes on the mesh interface.
    route: OwnedFd,
    seq: i32,
    name: String,
    index: u32,
    addresses: Vec<InterfaceAddress>,
    /// Prefixes advertised by other members that this machine has added.
    routes: BTreeSet<IpPrefix>,
    underlay: Arc<Mutex<Underlay>>,
    monitor: Option<Monitor>,
}

fn os(op: &'static str) -> impl FnOnce(io::Error) -> DataPlaneError {
    move |source| DataPlaneError::Os { op, source }
}

impl MacTun {
    pub fn open() -> Result<Self, DataPlaneError> {
        let route = sys::route_socket().map_err(os("open a routing socket"))?;
        // Write-only: do not receive routing table changes, so messages nobody reads do not pile up
        rustix::net::shutdown(&route, rustix::net::Shutdown::Read)
            .map_err(|e| os("open a routing socket")(e.into()))?;
        Ok(Self {
            route,
            seq: 0,
            name: String::new(),
            index: 0,
            addresses: Vec::new(),
            routes: BTreeSet::new(),
            underlay: Arc::new(Mutex::new(Underlay::default())),
            monitor: None,
        })
    }

    /// Adds or deletes a route via the mesh interface; it counts as success if it already exists (add) or is
    /// already gone (delete).
    fn route(&mut self, kind: u8, prefix: &IpPrefix) -> Result<(), DataPlaneError> {
        let via = self
            .addresses
            .iter()
            .find(|a| a.addr.is_ipv4() == prefix.is_ipv4())
            .map(|a| a.addr)
            .ok_or(DataPlaneError::Protocol {
                op: "route to the mesh interface",
                detail: format!("the interface has no address of the family of {prefix}"),
            })?;
        self.seq = self.seq.wrapping_add(1);
        let message = route::message(kind, prefix, via, self.seq);
        match rustix::io::write(&self.route, &message) {
            Ok(_) => Ok(()),
            Err(rustix::io::Errno::EXIST) if kind == route::RTM_ADD => Ok(()),
            Err(rustix::io::Errno::SRCH) if kind == route::RTM_DELETE => Ok(()),
            Err(e) => Err(DataPlaneError::Kernel {
                op: if kind == route::RTM_ADD {
                    "add a route to the mesh interface"
                } else {
                    "remove a route from the mesh interface"
                },
                source: e.into(),
            }),
        }
    }

    /// The mesh prefixes (IPv4 and IPv6) via the mesh interface: addresses are configured point-to-point,
    /// and the prefix routes are added separately.
    fn mesh_routes(&mut self) -> Result<(), DataPlaneError> {
        let prefixes: Vec<IpPrefix> = self
            .addresses
            .iter()
            .filter_map(|a| IpPrefix::containing(a.addr, a.prefix_len))
            .collect();
        for prefix in &prefixes {
            self.route(route::RTM_ADD, prefix)?;
        }
        Ok(())
    }
}

impl Platform for MacTun {
    type Tun = Utun;

    fn create(&mut self, spec: &InterfaceSpec) -> Result<Utun, DataPlaneError> {
        let (fd, name) = sys::utun_create().map_err(os("create a utun interface"))?;
        rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)
            .map_err(|e| os("configure the utun interface")(e.into()))?;
        rustix::io::ioctl_fionbio(&fd, true)
            .map_err(|e| os("configure the utun interface")(e.into()))?;
        sys::set_mtu_up(&name, spec.mtu).map_err(os("set the utun interface mtu and up"))?;
        for a in &spec.addresses {
            match a.addr {
                IpAddr::V4(v4) => sys::add_ipv4(&name, v4),
                IpAddr::V6(v6) => sys::add_ipv6(&name, v6),
            }
            .map_err(os("add an address to the utun interface"))?;
        }
        self.index = sys::if_index(&name);
        tracing::info!(interface = %name, "mesh interface created");
        self.name = name;
        self.addresses.clone_from(&spec.addresses);
        self.mesh_routes()?;
        Ok(Utun(fd))
    }

    fn configure(&mut self, spec: &InterfaceSpec) -> Result<(), DataPlaneError> {
        if spec.addresses != self.addresses {
            return Err(DataPlaneError::Unsupported(
                "changing mesh addresses without a restart",
            ));
        }
        sys::set_mtu_up(&self.name, spec.mtu).map_err(os("set the utun interface mtu and up"))
    }

    fn bind_underlay(&self, port: u16) -> io::Result<UdpSocket> {
        let socket = dual_stack_udp(port)?;
        let mut underlay = self.underlay.lock().unwrap_or_else(PoisonError::into_inner);
        if underlay.sockets.len() >= MAX_UNDERLAY {
            return Err(io::Error::other("too many underlay sockets"));
        }
        if underlay.sockets.is_empty() {
            underlay.index = physical_interface();
        }
        bind_physical(&socket, underlay.index);
        underlay.sockets.push(socket.try_clone()?);
        Ok(socket)
    }

    fn bind_tunnel(&self, addr: SocketAddr) -> io::Result<UdpSocket> {
        let socket = UdpSocket::bind(addr)?;
        sys::bind_to_interface(socket.as_fd(), self.index, addr.is_ipv6())?;
        Ok(socket)
    }

    fn sync_routes(&mut self, routes: &[IpPrefix]) -> Result<(), DataPlaneError> {
        // Monitoring of the physical interface starts after the mesh is ready, only once
        if self.monitor.is_none() {
            self.monitor = Some(
                Monitor::spawn(Arc::clone(&self.underlay))
                    .map_err(os("watch the routing table"))?,
            );
        }
        let wanted: BTreeSet<IpPrefix> = routes.iter().copied().collect();
        // Added again every time: routes deleted by other programs are restored here
        for prefix in &wanted {
            self.route(route::RTM_ADD, prefix)?;
        }
        let stale: Vec<IpPrefix> = self.routes.difference(&wanted).copied().collect();
        for prefix in &stale {
            self.route(route::RTM_DELETE, prefix)?;
        }
        self.routes = wanted;
        self.mesh_routes()
    }
}

/// The file that sends `nett.internal` to this machine's responder (design/names-and-diagnostics.md
/// section 3).
pub const RESOLVER_FILE: &str = "/etc/resolver/nett.internal";

/// Points the system resolver's `nett.internal` at `ipv4`, rewriting the file only when it differs. A
/// failure leaves names unresolved by the system resolver and is logged.
pub fn point_resolver(ipv4: std::net::Ipv4Addr) {
    let content = format!(
        "# Written by the nett mesh service: names under nett.internal resolve through this machine's\n\
         # mesh address.\nnameserver {ipv4}\n"
    );
    let written = (|| {
        use std::os::unix::fs::PermissionsExt as _;
        // Readable by everyone like the rest of /etc: the mesh process's umask keeps its own files
        // private, and tools other than the system resolver read these as ordinary users
        let readable = |path: &str, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        };
        std::fs::create_dir_all("/etc/resolver")?;
        readable("/etc/resolver", 0o755)?;
        if std::fs::read_to_string(RESOLVER_FILE).ok().as_deref() != Some(content.as_str()) {
            let tmp = format!("{RESOLVER_FILE}.new");
            std::fs::write(&tmp, &content)?;
            std::fs::rename(&tmp, RESOLVER_FILE)?;
        }
        readable(RESOLVER_FILE, 0o644)
    })();
    if let Err(e) = written {
        tracing::warn!(error = %e, file = RESOLVER_FILE, "pointing the system resolver at the mesh");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataplane::MESH_MTU;

    #[test]
    fn underlay_follows_the_physical_interface_for_ipv4_too() {
        let Some(index) = physical_interface() else {
            return; // No default route on this machine, so there is nothing to compare
        };
        let name = sys::if_name_of(u32::from(index)).expect("name");
        assert!(!route::is_virtual(&name), "{name}");
        let mac = MacTun::open().expect("routing socket");
        let underlay = mac.bind_underlay(0).expect("underlay");
        // Comparison: an IPv4 socket bound to only this interface
        let v4 = UdpSocket::bind("0.0.0.0:0").expect("v4");
        sys::bind_to_interface(v4.as_fd(), u32::from(index), false).expect("bind v4");
        let target: SocketAddr = "192.0.2.1:9".parse().expect("addr");
        v4.connect(target).expect("connect v4");
        underlay
            .connect(SocketAddr::new(
                IpAddr::V6(std::net::Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped()),
                9,
            ))
            .expect("connect underlay");
        let mapped = match underlay.local_addr().expect("local").ip() {
            IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4),
            v4 => Some(v4),
        };
        assert_eq!(
            mapped,
            Some(v4.local_addr().expect("local").ip()),
            "via {name}"
        );
    }

    /// Requires root: creates a utun, configures addresses and routes, sends and receives through the mesh
    /// address, and the interface disappears on exit. Run with sudo in CI
    /// (`cargo test -- --ignored macos`).
    #[test]
    #[ignore = "needs root"]
    fn macos_utun_smoke() {
        let mut mac = MacTun::open().expect("routing socket");
        let spec = InterfaceSpec {
            name: "nett0".into(),
            listen_port: None,
            mtu: MESH_MTU,
            addresses: vec![
                InterfaceAddress {
                    addr: "100.88.255.1".parse().expect("ip"),
                    prefix_len: 16,
                },
                InterfaceAddress {
                    addr: "fd00:88::ff01".parse().expect("ip"),
                    prefix_len: 48,
                },
            ],
        };
        let tun = mac.create(&spec).expect("create utun");
        let name = mac.name.clone();
        assert!(name.starts_with("utun"), "{name}");
        assert_ne!(mac.index, 0);
        mac.sync_routes(&["192.0.2.0/24".parse().expect("prefix")])
            .expect("routes");

        // A packet to another address in the mesh prefixes enters the utun: read it out of the TUN
        let probe = mac
            .bind_tunnel("100.88.255.1:0".parse().expect("addr"))
            .expect("tunnel socket");
        let mut buf = vec![0u8; 2048];
        for (to, want) in [
            ("100.88.1.2:9", [100, 88, 1, 2]),
            ("192.0.2.7:9", [192, 0, 2, 7]),
        ] {
            probe.send_to(b"nett", to).expect("send");
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            // After IPv6 is enabled on the interface the system sends multicast control packets by itself (MLD,
            // router solicitation); skip them
            let packet = loop {
                match tun.recv(&mut buf) {
                    Ok(n) if buf[0] >> 4 == 4 && buf[16..20] == want => break buf[..n].to_vec(),
                    Ok(_) => {}
                    Err(_) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("nothing arrived on {name} for {to}: {e}"),
                }
            };
            assert_eq!(packet[9], crate::userspace::packet::PROTO_UDP);
        }

        // A packet written into the TUN and addressed to this machine's mesh address is handed to this
        // machine's socket
        let listener = UdpSocket::bind("100.88.255.1:0").expect("listener");
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let port = listener.local_addr().expect("addr").port();
        let packet = crate::userspace::packet::build::udp(
            "100.88.1.2".parse().expect("ip"),
            9,
            "100.88.255.1".parse().expect("ip"),
            port,
        );
        tun.send(&packet).expect("into utun");
        let mut got = [0u8; 64];
        let (_, from) = listener.recv_from(&mut got).expect("delivered locally");
        assert_eq!(from, "100.88.1.2:9".parse::<SocketAddr>().expect("addr"));

        // A datagram to this machine's own mesh address enters the utun (the address is
        // point-to-point with itself); written back unchanged, it is delivered locally, which is what
        // the data plane does (design/userspace.md section 4)
        let own = UdpSocket::bind("100.88.255.1:0").expect("own listener");
        own.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let own_port = own.local_addr().expect("addr").port();
        let client = UdpSocket::bind("0.0.0.0:0").expect("client");
        client
            .send_to(b"self", ("100.88.255.1", own_port))
            .expect("send to the own mesh address");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let packet = loop {
            match tun.recv(&mut buf) {
                Ok(n) if buf[0] >> 4 == 4 && buf[16..20] == [100, 88, 255, 1] => {
                    let header = usize::from(buf[0] & 0x0f) * 4;
                    if u16::from_be_bytes([buf[header + 2], buf[header + 3]]) == own_port {
                        break buf[..n].to_vec();
                    }
                }
                Ok(_) => {}
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("the datagram to the own mesh address did not enter {name}: {e}"),
            }
        };
        tun.send(&packet).expect("back into utun");
        let (n, _) = own
            .recv_from(&mut got)
            .expect("delivered to the own mesh address");
        assert_eq!(&got[..n], b"self");

        // Over IPv6 the system leaves the UDP checksum of such a datagram unfilled; filled in, it is
        // delivered
        let own6 = UdpSocket::bind("[fd00:88::ff01]:0").expect("own IPv6 listener");
        own6.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let port6 = own6.local_addr().expect("addr").port();
        let client6 = UdpSocket::bind("[::]:0").expect("IPv6 client");
        client6
            .send_to(b"self6", ("fd00:88::ff01", port6))
            .expect("send to the own IPv6 mesh address");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut packet6 = loop {
            match tun.recv(&mut buf) {
                Ok(n)
                    if buf[0] >> 4 == 6
                        && buf[6] == crate::userspace::packet::PROTO_UDP
                        && u16::from_be_bytes([buf[42], buf[43]]) == port6 =>
                {
                    break buf[..n].to_vec();
                }
                Ok(_) => {}
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("the datagram to the own IPv6 address did not enter {name}: {e}"),
            }
        };
        crate::userspace::packet::fill_checksum(&mut packet6);
        tun.send(&packet6).expect("back into utun");
        let (n, _) = own6
            .recv_from(&mut got)
            .expect("delivered to the own IPv6 mesh address");
        assert_eq!(&got[..n], b"self6");

        // The underlay socket is bound to the physical interface (when there is a default route)
        let underlay = mac.bind_underlay(0).expect("underlay");
        drop(underlay);

        drop(tun);
        drop(mac);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            sys::if_index(&name),
            0,
            "{name} disappears with its descriptor"
        );
    }
}
