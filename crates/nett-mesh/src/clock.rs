//! Local clock (design/mesh.md section 8.4): when both sides are `dial-only` and the current path is
//! broken, relays are rotated in absolute time slices, which needs the two clocks far closer than a
//! slice: that holds while the system's time service keeps the clock synchronized; otherwise
//! random-interval retries are used instead.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The kernel's limit on the maximum error it reports (Linux `NTP_PHASE_LIMIT`). The bound grows by
/// 0.5 ms each second from the last synchronization, so below it the time service set the clock
/// within about 9 hours; systemd counts the clock synchronized below it.
pub const SYNCHRONIZED_ERROR: Duration = Duration::from_secs(16);

/// Whether the clock is synchronized, from the maximum error the kernel reports and whether the
/// kernel reports it unsynchronized. The maximum error bounds the error by the worst drift since
/// the last synchronization rather than measuring it: a clock milliseconds off reports more than 2
/// seconds an hour after it, so only the kernel's own limit says the time service has stopped.
pub fn synchronized(max_error: Duration, unsynchronized: bool) -> bool {
    !unsynchronized && max_error < SYNCHRONIZED_ERROR
}

pub trait Clock: Send {
    /// Current Unix time (milliseconds).
    fn now_ms(&self) -> u64;
    /// Whether the system's time service keeps the clock synchronized ([`synchronized`]).
    fn trusted(&self) -> bool;
}

/// System clock Unix milliseconds.
pub fn system_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock its time service keeps synchronized is trusted whatever the bound has grown to since
    /// the last synchronization: measured on a Linux machine whose time service polls every 34
    /// minutes, 2.2 ms off with a bound of 0.9 s, past 2 s after one missed poll. A bound at the
    /// kernel's limit, or a clock the kernel reports unsynchronized, is not (design/mesh.md section
    /// 8.4).
    #[test]
    fn a_synchronized_clock_is_trusted_whatever_its_bound() {
        assert!(synchronized(Duration::from_millis(916), false));
        assert!(synchronized(Duration::from_millis(2050), false));
        assert!(!synchronized(SYNCHRONIZED_ERROR, false));
        assert!(!synchronized(Duration::ZERO, true));
    }
}
