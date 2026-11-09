//! macOS 原生成员的平台后端（design/userspace.md 第 6 节）：utun、地址与路由只用系统调用（硬性规则 1：
//! 组网进程不执行外部命令）；发往底层网络的套接字绑定承载默认路由的物理接口，不进入代理应用的 TUN，
//! 物理接口变化时重新绑定。

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

/// utun 每个包前的地址族头（网络字节序）。
const AF_INET: u32 = 2;
const AF_INET6: u32 = 30;
/// 路由表变化之后等这么久再重新选物理接口：一次网络切换会连续产生很多条消息。
const SETTLE: Duration = Duration::from_millis(300);
/// 监视线程读路由消息的超时：据此定期检查是否该退出。
const MONITOR_TIMEOUT: Duration = Duration::from_secs(1);
/// 绑定物理接口的底层套接字最多几个（WireGuard 端口、发往中继的探测）。
const MAX_UNDERLAY: usize = 8;

/// 系统时钟；误差以内核报告的最大误差为准（`ntp_gettime`）。
pub struct SystemClock;

impl crate::clock::Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        crate::clock::system_now_ms()
    }

    fn trusted(&self) -> bool {
        sys::max_clock_error().is_ok_and(|e| e <= crate::clock::MAX_TRUSTED_ERROR)
    }
}

/// 以 launchd 服务运行时的日志（design/userspace.md 第 6.3 节）：经 syslog 进入系统日志，大小由系统管理，
/// 用 `log show --predicate 'process == "nett"'` 查看。
pub struct SystemLog;

impl SystemLog {
    pub fn open() -> Self {
        sys::openlog();
        Self
    }

    /// info 记为 notice：系统日志默认只持久保存 notice 及以上，状态变化要留下来。
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

/// utun 的控制套接字：每次收发一个带 4 字节地址族头的 IP 包。
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

/// 发往底层网络的套接字，与它们当前绑定的物理接口。
#[derive(Default)]
struct Underlay {
    sockets: Vec<UdpSocket>,
    index: Option<u16>,
}

impl Underlay {
    /// 按路由表重新选物理接口；变化时重新绑定所有套接字。
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

/// 双栈套接字：IPv6 与 IPv4（映射地址）两个方向都绑定。没有物理接口时解除绑定，按路由表发送。
fn bind_physical(socket: &UdpSocket, index: Option<u16>) {
    let index = u32::from(index.unwrap_or(0));
    for v6 in [true, false] {
        if let Err(e) = sys::bind_to_interface(socket.as_fd(), index, v6) {
            tracing::warn!(error = %e, v6, "binding an underlay socket to the physical interface");
        }
    }
}

/// 监视路由表：物理接口变化时（换 Wi-Fi、插拔网线、唤醒）重新绑定底层套接字（design/userspace.md 第 6.4 节）。
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
                    // 等待期间的其他消息一并处理
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
    /// 只写的路由套接字：增删组网接口上的路由。
    route: OwnedFd,
    seq: i32,
    name: String,
    index: u32,
    addresses: Vec<InterfaceAddress>,
    /// 本机加上的其他成员宣告的网段。
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
        // 只写：不接收路由表的变化，免得没人读的消息堆积
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

    /// 增删一条经组网接口的路由；已经存在（增）或已经不在（删）都算成功。
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

    /// 组网网段（IPv4 与 IPv6）经组网接口：地址按点对点配置，网段的路由另加。
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
        // 物理接口的监视从组网就绪之后开始，只启动一次
        if self.monitor.is_none() {
            self.monitor = Some(
                Monitor::spawn(Arc::clone(&self.underlay))
                    .map_err(os("watch the routing table"))?,
            );
        }
        let wanted: BTreeSet<IpPrefix> = routes.iter().copied().collect();
        // 每次都重新添加：被其他程序删掉的路由在这里补回
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataplane::MESH_MTU;

    /// 需要 root：创建 utun、配置地址和路由，经组网地址收发，退出后接口消失。CI 中用 sudo 运行
    /// （`cargo test -- --ignored macos`）。
    #[test]
    #[ignore = "needs root"]
    fn macos_utun_smoke() {
        let mut mac = MacTun::open().expect("routing socket");
        let spec = InterfaceSpec {
            name: "nett0".into(),
            listen_port: 0,
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

        // 发往组网网段中另一个地址的包进入 utun：从 TUN 读出来
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
            // 接口启用 IPv6 后系统自己会发组播的控制包（MLD、路由器请求），跳过它们
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

        // 写进 TUN、发往本机组网地址的包交给本机的套接字
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

        // 底层套接字绑定在物理接口上（有默认路由时）
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
