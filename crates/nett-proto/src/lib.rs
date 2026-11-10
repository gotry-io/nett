//! nett-node 与 Hub 之间的控制协议（design/protocol.md）：Protobuf 消息、Noise 通道与分片。

pub mod frame;
pub mod noise;

/// `nett.v1` 的消息，由 `cargo run -p nett-proto-gen` 从 `proto/nett/v1/control.proto` 生成。
#[allow(clippy::all, clippy::pedantic)]
pub mod v1 {
    include!("gen/nett.v1.rs");
}

/// 协议版本：主版本不同则不兼容，次版本只做增量修改（protocol.md 第 9 节）。
pub const PROTOCOL_VERSION: &str = "1.0";
