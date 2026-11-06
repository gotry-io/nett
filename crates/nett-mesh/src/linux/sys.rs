//! rustix 没有提供的两个套接字选项：挂 BPF 过滤器、绑定到接口。只在这里使用 `unsafe`
//! （CLAUDE.md "代码规则"）：两处都是把指向本地变量的指针和它的长度交给 `setsockopt`。
#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

/// 一条经典 BPF 指令。
pub(crate) type BpfInsn = libc::sock_filter;

pub(crate) const fn insn(code: u16, jt: u8, jf: u8, k: u32) -> BpfInsn {
    libc::sock_filter { code, jt, jf, k }
}

/// 给套接字挂上 BPF 过滤器：只有过滤器放行的包才交给用户态。
pub(crate) fn attach_filter(fd: BorrowedFd<'_>, program: &[BpfInsn]) -> io::Result<()> {
    let prog = libc::sock_fprog {
        len: u16::try_from(program.len()).map_err(|_| io::Error::other("BPF program too long"))?,
        // 内核只读这段指令；指针在调用期间有效
        filter: program.as_ptr().cast_mut(),
    };
    // SAFETY: `prog` 和它指向的 `program` 在调用期间都有效，长度与结构体大小一致
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&raw const prog).cast(),
            u32::try_from(size_of::<libc::sock_fprog>()).unwrap_or(u32::MAX),
        )
    };
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
