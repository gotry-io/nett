//! rustix 没有提供的系统调用：绑定到接口的套接字选项，读取内核的时钟误差，创建 TUN 接口。只在这里使用 `unsafe`
//! （CLAUDE.md "代码规则"）：把指向本地数据的指针交给内核。
#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::Duration;

/// 把打开的 `/dev/net/tun` 关联到名为 `name` 的 TUN 接口（不存在时创建）；收发的包不带额外的头。
pub(crate) fn tun_set_iff(fd: BorrowedFd<'_>, name: &str) -> io::Result<()> {
    if name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name is too long",
        ));
    }
    let mut ifr_name = [0 as libc::c_char; libc::IFNAMSIZ];
    for (dst, src) in ifr_name.iter_mut().zip(name.bytes()) {
        *dst = src as libc::c_char;
    }
    let mut request = libc::ifreq {
        ifr_name,
        ifr_ifru: libc::__c_anonymous_ifr_ifru {
            ifru_flags: (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short,
        },
    };
    // SAFETY: `request` 是完整初始化的 ifreq，名字以 NUL 结尾；内核只在这次调用中读写它
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &raw mut request) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// 把套接字绑定到一个接口：只收发经这个接口的包。
pub(crate) fn bind_to_device(fd: BorrowedFd<'_>, name: &str) -> io::Result<()> {
    // SAFETY: 指针指向 `name` 的字节，长度为它的长度；内核按长度读取，不要求结尾的 NUL
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            u32::try_from(name.len()).unwrap_or(u32::MAX),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// 内核报告的时钟最大误差（`adjtimex` 的 `maxerror`），由时间同步服务维护；没有同步时它逐秒增大，
/// 最终达到 16 秒。只读取，不修改任何时间变量。
pub(crate) fn max_clock_error() -> io::Result<Duration> {
    // SAFETY: `timex` 只含整数字段，全零是合法值；`modes` 为 0 表示只读取
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    // SAFETY: 指针指向本地的 `timex`，内核只在调用期间写入它
    let rc = unsafe { libc::adjtimex(&mut tx) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(Duration::from_micros(
        u64::try_from(tx.maxerror).unwrap_or(u64::MAX),
    ))
}
