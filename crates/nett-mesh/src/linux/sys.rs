//! System calls rustix does not provide: socket options that bind to an interface, reading the kernel's
//! clock error, and creating a TUN interface. `unsafe` is used only here (CLAUDE.md "Code rules"): it
//! hands the kernel pointers to local data.
#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::Duration;

/// Associates an opened `/dev/net/tun` with the TUN interface named `name` (created if it does not
/// exist); sent and received packets carry no extra header.
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
    // SAFETY: `request` is a fully initialized ifreq with a NUL-terminated name; the kernel reads and writes
    // it only during this call
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &raw mut request) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Binds a socket to an interface: it only sends and receives packets through that interface.
pub(crate) fn bind_to_device(fd: BorrowedFd<'_>, name: &str) -> io::Result<()> {
    // SAFETY: the pointer points to the bytes of `name`, with its length; the kernel reads by length and
    // does not require a trailing NUL
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

/// The kernel's reported maximum clock error (`maxerror` of `adjtimex`), maintained by the time
/// synchronization service; without synchronization it grows by the second and eventually reaches 16
/// seconds. Read-only: no time variable is modified.
pub(crate) fn max_clock_error() -> io::Result<Duration> {
    // SAFETY: `timex` contains only integer fields and all zeros is a valid value; `modes` of 0 means read
    // only
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    // SAFETY: the pointer points to the local `timex`, and the kernel writes it only during the call
    let rc = unsafe { libc::adjtimex(&mut tx) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(Duration::from_micros(
        u64::try_from(tx.maxerror).unwrap_or(u64::MAX),
    ))
}
