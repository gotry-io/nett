//! macOS system calls rustix does not provide (design/userspace.md section 6): utun, interface addresses
//! and MTU, binding sockets to interfaces, interface names and numbers, the routing table, clock error.
//! `unsafe` is used only here (CLAUDE.md "Code rules"): it hands the kernel pointers to local data, and
//! the kernel reads and writes them only during the call.
#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::Duration;

use libc::{c_char, c_int, c_uint, c_ulong};

/// Values from <sys/sockio.h>, <netinet6/in6_var.h> and <netinet6/nd6.h> that libc does not provide;
/// consistent with the SDK headers.
const SIOCAIFADDR: c_ulong = 0x8040_691a;
const SIOCAIFADDR_IN6: c_ulong = 0x8080_691a;
const SIOCSIFMTU: c_ulong = 0x8020_6934;
const SIOCGIFFLAGS: c_ulong = 0xc020_6911;
const SIOCSIFFLAGS: c_ulong = 0x8020_6910;
const ND6_INFINITE_LIFETIME: u32 = u32::MAX;
/// No duplicate address detection for addresses: there are no other hosts on a utun, and detection would
/// only make the address usable about a second later.
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

// Consistent with the kernel's structure (in the SDK headers sizeof(struct in6_aliasreq) == 128)
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
    // SAFETY: socket only reads integer arguments; the returned descriptor is owned by us
    let fd = unsafe { libc::socket(family, ty, protocol) };
    check(fd)?;
    // SAFETY: fd is a freshly created valid descriptor with no other owner
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Creates a utun interface with the number assigned by the system; returns its control socket (for
/// sending and receiving IP packets) and the interface name.
pub(crate) fn utun_create() -> io::Result<(OwnedFd, String)> {
    let fd = socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL)?;
    let mut info = libc::ctl_info {
        ctl_id: 0,
        ctl_name: [0; libc::MAX_KCTL_NAME],
    };
    for (d, s) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME) {
        *d = *s as c_char;
    }
    // SAFETY: info is a fully initialized ctl_info with a NUL-terminated name
    check(unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &raw mut info) })?;
    let addr = libc::sockaddr_ctl {
        sc_len: size_of::<libc::sockaddr_ctl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        // 0: the system picks a free number
        sc_unit: 0,
        sc_reserved: [0; 5],
    };
    // SAFETY: the pointer points to a local sockaddr_ctl, with the length of its size
    check(unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&raw const addr).cast(),
            size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    })?;
    let mut name = [0 as c_char; libc::IFNAMSIZ];
    let mut len = libc::IFNAMSIZ as libc::socklen_t;
    // SAFETY: the buffer has len bytes; the kernel writes a NUL-terminated name and updates len
    check(unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &raw mut len,
        )
    })?;
    // SAFETY: the name the kernel wrote is NUL-terminated and within the buffer
    let name = unsafe { CStr::from_ptr(name.as_ptr()) }
        .to_str()
        .map_err(|_| io::Error::other("utun name is not UTF-8"))?
        .to_owned();
    Ok((fd, name))
}

/// A sockaddr with address family AF_INET (port 0).
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

/// Adds an IPv4 address to the interface, configured point-to-point: both ends are this address, mask
/// /32. The route is added separately.
pub(crate) fn add_ipv4(name: &str, addr: Ipv4Addr) -> io::Result<()> {
    let sock = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    let mut req = libc::ifaliasreq::default();
    req.ifra_name = if_name(name)?;
    req.ifra_addr = sockaddr_v4(addr);
    req.ifra_broadaddr = sockaddr_v4(addr);
    req.ifra_mask = sockaddr_v4(Ipv4Addr::BROADCAST);
    // SAFETY: req is a fully initialized ifaliasreq
    check(unsafe { libc::ioctl(sock.as_raw_fd(), SIOCAIFADDR, &raw mut req) })
}

/// Adds an IPv6 address to the interface (prefix length 128, valid indefinitely, no duplicate address
/// detection). The route is added separately.
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
    // SAFETY: req has the same layout as the kernel's in6_aliasreq (see the assertion above), fully
    // initialized
    check(unsafe { libc::ioctl(sock.as_raw_fd(), SIOCAIFADDR_IN6, &raw mut req) })
}

fn ifreq(name: &str) -> io::Result<libc::ifreq> {
    Ok(libc::ifreq {
        ifr_name: if_name(name)?,
        ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
    })
}

/// Sets the interface's MTU and brings it up.
pub(crate) fn set_mtu_up(name: &str, mtu: u32) -> io::Result<()> {
    let sock = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    let mut req = ifreq(name)?;
    req.ifr_ifru.ifru_mtu = c_int::try_from(mtu).map_err(io::Error::other)?;
    // SAFETY: req is a fully initialized ifreq
    check(unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSIFMTU, &raw mut req) })?;
    let mut req = ifreq(name)?;
    // SAFETY: same as above; the kernel writes back the interface's current flags
    check(unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGIFFLAGS, &raw mut req) })?;
    // SAFETY: SIOCGIFFLAGS writes ifru_flags
    unsafe { req.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short };
    // SAFETY: same as above
    check(unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSIFFLAGS, &raw mut req) })
}

/// The number for an interface name; 0 if the interface does not exist.
pub(crate) fn if_index(name: &str) -> u32 {
    let Ok(name) = CString::new(name) else {
        return 0;
    };
    // SAFETY: name is a NUL-terminated string
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

/// The name for an interface number.
pub(crate) fn if_name_of(index: u32) -> Option<String> {
    let mut buf = [0 as c_char; libc::IFNAMSIZ];
    // SAFETY: the buffer has IFNAMSIZ bytes; the kernel writes a NUL-terminated name
    let p = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: on success buf holds a NUL-terminated name
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// Makes the socket send and receive only through the interface numbered `index` (0 removes the binding):
/// IPv6 sockets (including dual-stack) use `IPV6_BOUND_IF`, and IPv4 sockets use `IP_BOUND_IF`.
pub(crate) fn bind_to_interface(fd: BorrowedFd<'_>, index: u32, v6: bool) -> io::Result<()> {
    let value: c_uint = index;
    let set = |level, name| {
        // SAFETY: the pointer points to a local integer, with the length of its size
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

/// All IPv4 routes with a gateway in the routing table (a sequence of `rt_msghdr` messages, parsed by
/// [`super::route::defaults`]).
pub(crate) fn dump_gateway_routes() -> io::Result<Vec<u8>> {
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_INET,
        libc::NET_RT_FLAGS,
        libc::RTF_GATEWAY,
    ];
    // Ask for the length first and then fetch; retry if the routing table grows between the two
    for _ in 0..4 {
        let mut len: libc::size_t = 0;
        // SAFETY: only asking for the length: the output pointer is null
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
        // SAFETY: the buffer has len bytes; the kernel writes at most len bytes and updates len
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

/// The kernel's reported maximum clock error (`ntp_gettime`).
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
    // SAFETY: the pointer points to a local ntptimeval, and the kernel writes it only during the call
    check(unsafe { libc::ntp_gettime(&raw mut t) })?;
    let micros = u64::try_from(t.maxerror).map_err(io::Error::other)?;
    Ok(Duration::from_micros(micros))
}

/// Opens the system log: afterwards [`syslog`] is tagged with `nett-mesh` and the process ID.
pub(crate) fn openlog() {
    // SAFETY: the identifier is a static NUL-terminated string, valid for the whole life of the process
    unsafe { libc::openlog(c"nett-mesh".as_ptr(), libc::LOG_PID, libc::LOG_DAEMON) };
}

/// Writes a system log entry. NULs in the message are removed (a C string cannot contain them).
pub(crate) fn syslog(priority: c_int, message: &str) {
    let Ok(message) = CString::new(message.replace('\0', "")) else {
        return;
    };
    // SAFETY: the format string is the static "%s", and the only argument is a NUL-terminated string
    unsafe { libc::syslog(priority, c"%s".as_ptr(), message.as_ptr()) };
}

/// A routing socket (`PF_ROUTE`): writes routing messages, receives routing table changes.
pub(crate) fn route_socket() -> io::Result<OwnedFd> {
    let fd = socket(libc::PF_ROUTE, libc::SOCK_RAW, 0)?;
    rustix::io::fcntl_setfd(fd.as_fd(), rustix::io::FdFlags::CLOEXEC)?;
    Ok(fd)
}

/// Effective user ID of the peer process of a Unix socket (connection check for local status, design/status.md
/// section 3).
pub(crate) fn peer_uid(fd: BorrowedFd<'_>) -> io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: both pointers point to local integers, and the kernel writes them only during the call
    check(unsafe { libc::getpeereid(fd.as_raw_fd(), &raw mut uid, &raw mut gid) })?;
    Ok(uid)
}
