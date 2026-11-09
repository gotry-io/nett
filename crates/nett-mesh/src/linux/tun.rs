//! 用户态数据面在 Linux 上的平台后端（DSM、旧内核与实验场景，design/userspace.md）：TUN 接口经
//! `/dev/net/tun` 创建，随组网进程退出而删除；地址、MTU 与路由经 rtnetlink 配置，与内核后端相同。

use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::OpenOptionsExt as _;

use nett_core::prefix::IpPrefix;

use super::netlink::Socket;
use super::{kernel, rtnl, sync_addresses, sync_routes, sys};
use crate::dataplane::{DataPlaneError, InterfaceSpec};
use crate::userspace::{Platform, Tun, dual_stack_udp};

pub struct LinuxTun {
    route: Socket,
    name: String,
    ifindex: Option<u32>,
}

impl LinuxTun {
    pub fn open() -> Result<Self, DataPlaneError> {
        Ok(Self {
            route: Socket::open(None).map_err(kernel("open rtnetlink socket"))?,
            name: String::new(),
            ifindex: None,
        })
    }

    fn configure_link(&mut self, spec: &InterfaceSpec) -> Result<(), DataPlaneError> {
        let link = rtnl::get_link(&mut self.route, &spec.name)
            .map_err(kernel("look up interface"))?
            .ok_or_else(|| DataPlaneError::Protocol {
                op: "look up interface",
                detail: format!("{} vanished after creation", spec.name),
            })?;
        rtnl::set_mtu_up(&mut self.route, link.index, spec.mtu)
            .map_err(kernel("set interface mtu and up"))?;
        sync_addresses(&mut self.route, link.index, spec)?;
        self.ifindex = Some(link.index);
        Ok(())
    }
}

pub struct TunDevice(File);

impl AsFd for TunDevice {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl Tun for TunDevice {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.0).read(buf)
    }

    fn send(&self, packet: &[u8]) -> io::Result<()> {
        (&self.0).write(packet).map(drop)
    }
}

impl Platform for LinuxTun {
    type Tun = TunDevice;

    fn create(&mut self, spec: &InterfaceSpec) -> Result<TunDevice, DataPlaneError> {
        let os = |op| move |source| DataPlaneError::Os { op, source };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/net/tun")
            .map_err(os("open /dev/net/tun"))?;
        sys::tun_set_iff(file.as_fd(), &spec.name).map_err(os("create the TUN interface"))?;
        self.name.clone_from(&spec.name);
        self.configure_link(spec)?;
        Ok(TunDevice(file))
    }

    fn configure(&mut self, spec: &InterfaceSpec) -> Result<(), DataPlaneError> {
        self.configure_link(spec)
    }

    fn bind_wireguard(&mut self, port: u16) -> Result<UdpSocket, DataPlaneError> {
        dual_stack_udp(port).map_err(|source| DataPlaneError::Os {
            op: "bind the WireGuard port",
            source,
        })
    }

    fn bind_tunnel(&self, addr: SocketAddr) -> io::Result<UdpSocket> {
        let socket = UdpSocket::bind(addr)?;
        sys::bind_to_device(socket.as_fd(), &self.name)?;
        Ok(socket)
    }

    fn sync_routes(&mut self, routes: &[IpPrefix]) -> Result<(), DataPlaneError> {
        sync_routes(&mut self.route, self.ifindex, routes)
    }
}
