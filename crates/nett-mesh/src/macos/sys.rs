//! rustix 没有提供的 macOS 系统调用（design/userspace.md 第 6 节）：utun、接口地址与 MTU、套接字绑定接口、
//! 接口名与编号、路由表、时钟误差。只在这里使用 `unsafe`（CLAUDE.md "代码规则"）：把指向本地数据的指针交给
//! 内核，内核只在调用期间读写它们。
#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::Duration;

use libc::{c_char, c_int, c_uint, c_ulong};

/// <sys/sockio.h>、<netinet6/in6_var.h>、<netinet6/nd6.h> 中的取值，libc 没有提供；与 SDK 头文件一致。
const SIOCAIFADDR: c_ulong = 0x8040_691a;
const SIOCAIFADDR_IN6: c_ulong = 0x8080_691a;
const SIOCSIFMTU: c_ulong = 0x8020_6934;
const SIOCGIFFLAGS: c_ulong = 0xc020_6911;
const SIOCSIFFLAGS: c_ulong = 0x8020_6910;
const ND6_INFINITE_LIFETIME: u32 = u32::MAX;
/// 地址不做重复地址检测：utun 上没有其他主机，检测只会让地址推迟约一秒才能使用。
const IN6_IFF_NODAD: c_int = 0x20;
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";

#[repr(C)]
struct In6AddrLifetime {
    expire: libc::time_t,
    preferred: libc::time_t,
    vltime: u32,
    pltime: u32,
}

#[repr(C)]
struct In6Aliasreq {
    name: [c_char; libc::IFNAMSIZ],
    addr: libc::sockaddr_in6,
    dstaddr: libc::sockaddr_in6,
    prefixmask: libc::sockaddr_in6,
    flags: c_int,
    lifetime: In6AddrLifetime,
}

// 与内核的结构一致（SDK 头文件中 sizeof(struct in6_aliasreq) == 128）
const _: () = assert!(size_of::<In6Aliasreq>() == 128);

fn check(rc: c_int) -> io::Result<()> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn if_name(name: &str) -> io::Result<[c_char; libc::IFNAMSIZ]> {
    if name.len() >= libc::IFNAMSIZ || name.bytes().any(|b| b == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
    let mut out = [0 as c_char; libc::IFNAMSIZ];
    for (d, s) in out.iter_mut().zip(name.bytes()) {
        *d = s as c_char;
    }
    Ok(out)
}

fn socket(family: c_int, ty: c_int, protocol: c_int) -> io::Result<OwnedFd> {
    // SAFETY: socket 只读取整数参数；返回的描述符归我们所有
    let fd = unsafe { libc::socket(family, ty, protocol) };
    check(fd)?;
    // SAFETY: fd 是刚创建的、有效的描述符，没有其他所有者
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// 创建一个 utun 接口，编号由系统分配；返回它的控制套接字（收发 IP 包）和接口名。
pub(crate) fn utun_create() -> io::Result<(OwnedFd, String)> {
    let fd = socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL)?;
    let mut info = libc::ctl_info {
        ctl_id: 0,
        ctl_name: [0; libc::MAX_KCTL_NAME],
    };
    for (d, s) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME) {
        *d = *s as c_char;
    }
    // SAFETY: info 是完整初始化的 ctl_info，名字以 NUL 结尾
    check(unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &raw mut info) })?;
    let addr = libc::sockaddr_ctl {
        sc_len: size_of::<libc::sockaddr_ctl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        // 0：由系统选一个空闲的编号
        sc_unit: 0,
        sc_reserved: [0; 5],
    };
    // SAFETY: 指针指向本地的 sockaddr_ctl，长度为它的大小
    check(unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&raw const addr).cast(),
            size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    })?;
    let mut name = [0 as c_char; libc::IFNAMSIZ];
    let mut len = libc::IFNAMSIZ as libc::socklen_t;
    // SAFETY: 缓冲区有 len 字节，内核写入以 NUL 结尾的名字并更新 len
    check(unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &raw mut len,
        )
    })?;
    // SAFETY: 内核写入的名字以 NUL 结尾，且在缓冲区之内
    let name = unsafe { CStr::from_ptr(name.as_ptr()) }
        .to_str()
        .map_err(|_| io::Error::other("utun name is not UTF-8"))?
        .to_owned();
    Ok((fd, name))
}

/// 地址族为 AF_INET 的 sockaddr（端口为 0）。
fn sockaddr_v4(addr: Ipv4Addr) -> libc::sockaddr {
    let mut sa_data = [0 as c_char; 14];
    for (d, s) in sa_data[2..6].iter_mut().zip(addr.octets()) {
        *d = s as c_char;
    }
    libc::sockaddr {
        sa_len: size_of::<libc::sockaddr_in>() as u8,
        sa_family: libc::AF_INET as u8,
        sa_data,
    }
}

fn sockaddr_v6(addr: Ipv6Addr) -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_len: size_of::<libc::sockaddr_in6>() as u8,
        sin6_family: libc::AF_INET6 as u8,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: addr.octets(),
        },
        sin6_scope_id: 0,
    }
}

/// 给接口加一个 IPv4 地址，按点对点配置：本端和对端都是这个地址，掩码 /32。路由另加。
pub(crate) fn add_ipv4(name: &str, addr: Ipv4Addr) -> io::Result<()> {
    let sock = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    let mut req = libc::ifaliasreq::default();
    req.ifra_name = if_name(name)?;
    req.ifra_addr = sockaddr_v4(addr);
    req.ifra_broadaddr = sockaddr_v4(addr);
    req.ifra_mask = sockaddr_v4(Ipv4Addr::BROADCAST);
    // SAFETY: req 是完整初始化的 ifaliasreq
    check(unsafe { libc::ioctl(sock.as_raw_fd(), SIOCAIFADDR, &raw mut req) })
}

/// 给接口加一个 IPv6 地址（前缀长度 128，长期有效，不做重复地址检测）。路由另加。
pub(crate) fn add_ipv6(name: &str, addr: Ipv6Addr) -> io::Result<()> {
    let sock = socket(libc::AF_INET6, libc::SOCK_DGRAM, 0)?;
    let mut dst = sockaddr_v6(Ipv6Addr::UNSPECIFIED);
    dst.sin6_len = 0;
    dst.sin6_family = 0;
    let mut req = In6Aliasreq {
        name: if_name(name)?,
        addr: sockaddr_v6(addr),
        dstaddr: dst,
        prefixmask: sockaddr_v6(Ipv6Addr::from(u128::MAX)),
        flags: IN6_IFF_NODAD,
        lifetime: In6AddrLifetime {
            expire: 0,
            preferred: 0,
            vltime: ND6_INFINITE_LIFETIME,
            pltime: ND6_INFINITE_LIFETIME,
        },
    };
    // SAFETY: req 与内核的 in6_aliasreq 布局相同（见上面的断言），完整初始化
    check(unsafe { libc::ioctl(sock.as_raw_fd(), SIOCAIFADDR_IN6, &raw mut req) })
}

fn ifreq(name: &str) -> io::Result<libc::ifreq> {
    Ok(libc::ifreq {
        ifr_name: if_name(name)?,
        ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
    })
}

/// 设置接口的 MTU 并启用它。
pub(crate) fn set_mtu_up(name: &str, mtu: u32) -> io::Result<()> {
    let sock = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    let mut req = ifreq(name)?;
    req.ifr_ifru.ifru_mtu = c_int::try_from(mtu).map_err(io::Error::other)?;
    // SAFETY: req 是完整初始化的 ifreq
    check(unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSIFMTU, &raw mut req) })?;
    let mut req = ifreq(name)?;
    // SAFETY: 同上；内核写回接口当前的标志
    check(unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGIFFLAGS, &raw mut req) })?;
    // SAFETY: SIOCGIFFLAGS 写入的是 ifru_flags
    unsafe { req.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short };
    // SAFETY: 同上
    check(unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSIFFLAGS, &raw mut req) })
}

/// 接口名对应的编号；接口不存在时为 0。
pub(crate) fn if_index(name: &str) -> u32 {
    let Ok(name) = CString::new(name) else {
        return 0;
    };
    // SAFETY: name 是以 NUL 结尾的字符串
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

/// 接口编号对应的名字。
pub(crate) fn if_name_of(index: u32) -> Option<String> {
    let mut buf = [0 as c_char; libc::IFNAMSIZ];
    // SAFETY: 缓冲区有 IFNAMSIZ 字节，内核写入以 NUL 结尾的名字
    let p = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: 成功时 buf 中是以 NUL 结尾的名字
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// 让套接字只经编号为 `index` 的接口收发（0 解除绑定），IPv4 与 IPv6 两个方向都设置。
pub(crate) fn bind_to_interface(fd: BorrowedFd<'_>, index: u32, v6: bool) -> io::Result<()> {
    let value: c_uint = index;
    let set = |level, name| {
        // SAFETY: 指针指向本地的整数，长度为它的大小
        check(unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                level,
                name,
                (&raw const value).cast(),
                size_of::<c_uint>() as libc::socklen_t,
            )
        })
    };
    if v6 {
        set(libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    } else {
        set(libc::IPPROTO_IP, libc::IP_BOUND_IF)
    }
}

/// 路由表中所有带网关的 IPv4 路由（`rt_msghdr` 消息序列，[`super::route::defaults`] 解析）。
pub(crate) fn dump_gateway_routes() -> io::Result<Vec<u8>> {
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_INET,
        libc::NET_RT_FLAGS,
        libc::RTF_GATEWAY,
    ];
    // 先问长度再取；两次之间路由表变大时重试
    for _ in 0..4 {
        let mut len: libc::size_t = 0;
        // SAFETY: 只问长度：输出指针为空
        check(unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as c_uint,
                std::ptr::null_mut(),
                &raw mut len,
                std::ptr::null_mut(),
                0,
            )
        })?;
        let mut buf = vec![0u8; len + 4096];
        let mut len = buf.len();
        // SAFETY: 缓冲区有 len 字节，内核最多写入 len 字节并更新 len
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as c_uint,
                buf.as_mut_ptr().cast(),
                &raw mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        match check(rc) {
            Ok(()) => {
                buf.truncate(len);
                return Ok(buf);
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOMEM) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other(
        "routing table keeps growing while reading it",
    ))
}

/// 内核报告的时钟最大误差（`ntp_gettime`）。
pub(crate) fn max_clock_error() -> io::Result<Duration> {
    let mut t = libc::ntptimeval {
        time: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        maxerror: 0,
        esterror: 0,
        tai: 0,
        time_state: 0,
    };
    // SAFETY: 指针指向本地的 ntptimeval，内核只在调用期间写入它
    check(unsafe { libc::ntp_gettime(&raw mut t) })?;
    let micros = u64::try_from(t.maxerror).map_err(io::Error::other)?;
    Ok(Duration::from_micros(micros))
}

/// 一个路由套接字（`PF_ROUTE`）：写入路由消息、接收路由表变化。
pub(crate) fn route_socket() -> io::Result<OwnedFd> {
    let fd = socket(libc::PF_ROUTE, libc::SOCK_RAW, 0)?;
    rustix::io::fcntl_setfd(fd.as_fd(), rustix::io::FdFlags::CLOEXEC)?;
    Ok(fd)
}
