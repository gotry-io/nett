//! rustix 没有提供的套接字选项：绑定到接口。只在这里使用 `unsafe`（CLAUDE.md "代码规则"）：
//! 把指向本地数据的指针和它的长度交给 `setsockopt`。
#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

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
