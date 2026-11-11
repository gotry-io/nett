//! The control protocol between nett-node and the Hub (design/protocol.md): Protobuf messages, the
//! Noise channel and fragmentation.

pub mod api;
pub mod frame;
pub mod noise;
pub mod token;

/// Messages of `nett.v1`, generated from `proto/nett/v1/control.proto` by `cargo run -p
/// nett-proto-gen`.
#[allow(clippy::all, clippy::pedantic)]
pub mod v1 {
    include!("gen/nett.v1.rs");
}

/// Protocol version: a different major version is incompatible; minor versions only make
/// incremental changes (protocol.md section 9).
pub const PROTOCOL_VERSION: &str = "1.0";
