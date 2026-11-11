//! Local clock (design/mesh.md section 8.4): when both sides are `dial-only` and the current path is
//! broken, relays are rotated in absolute time slices, which requires the local clock error to be small
//! enough; otherwise random-interval retries are used instead.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Upper limit of the clock error required for rotating by time slices.
pub const MAX_TRUSTED_ERROR: Duration = Duration::from_secs(2);

pub trait Clock: Send {
    /// Current Unix time (milliseconds).
    fn now_ms(&self) -> u64;
    /// Whether the local clock error is within [`MAX_TRUSTED_ERROR`], based on the system's time
    /// synchronization status.
    fn trusted(&self) -> bool;
}

/// System clock Unix milliseconds.
pub fn system_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
