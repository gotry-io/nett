//! 每台机器上的控制代理 nett-node（design/hub.md 第 5 节）：连接 Hub，把期望状态交给组网进程，上报状态。
//! 也提供签名工具调用 Hub API 的客户端。

pub mod config;
pub mod http;
pub mod join;
pub mod session;
pub mod tls;
pub mod url;
