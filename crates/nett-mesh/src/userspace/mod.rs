//! 用户态数据面（design/userspace.md）：WireGuard 会话、选择对端与来源校验、进程内过滤、WireGuard 端口上
//! 的分流都在组网进程中完成，平台后端只提供 TUN 和接口配置。macOS、DSM 与旧内核的 Linux 共用。

pub mod filter;
pub mod packet;
pub mod plane;
pub mod session;
