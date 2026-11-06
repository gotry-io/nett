//! 本机时钟（design/mesh.md 第 8.4 节）：双方都是 `dial-only`、当前路径中断时按绝对时间片轮换中继，
//! 前提是本机时钟误差足够小，否则改用随机间隔重试。

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 按时间片轮换所要求的时钟误差上限。
pub const MAX_TRUSTED_ERROR: Duration = Duration::from_secs(2);

pub trait Clock: Send {
    /// 当前的 Unix 时间（毫秒）。
    fn now_ms(&self) -> u64;
    /// 本机时钟误差是否在 [`MAX_TRUSTED_ERROR`] 以内，以系统的时间同步状态为准。
    fn trusted(&self) -> bool;
}

/// 系统时钟的 Unix 毫秒。
pub fn system_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
