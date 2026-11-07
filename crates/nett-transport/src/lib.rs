//! 传输适配进程 `nett transport`：UDP 不可用时把 WireGuard 数据包转成 TLS 传输，只经手密文（design/mesh.md
//! 第 5.3 节，ADR 0013）。
//!
//! 每个 TLS 中继在本机回环地址上一个 UDP 端口：WireGuard 与组网进程把发往这个中继的包发到这里，每个包
//! 作为 WebSocket 的一个二进制消息发出；反方向按消息类型分发：中继应答交还发出探测的组网进程端口，其余
//! 交给 WireGuard 端口。不持有任何密钥：连接由组网进程经它发出的第一个中继探测认证。

pub mod client;
pub mod forward;
