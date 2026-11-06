//! 签名载荷、信任锚、准入材料与撤销记录的验证，nett-node 与组网进程共用（design/auth.md）。
//!
//! 编码规则见 design/auth.md 第 10.5 节。这里只验证；生成签名的代码在 `signing` 特性中，
//! 只供实验工具和测试使用。

pub mod admission;
pub mod anchors;
pub mod canonical;
pub mod encoding;
pub mod keys;
pub mod payload;
pub mod revocation;
pub mod signed;
#[cfg(any(test, feature = "signing"))]
pub mod signing;
