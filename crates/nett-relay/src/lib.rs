//! The relay (ADR 0011, ADR 0032): forwards encrypted packets between members in the nett daemon,
//! and nett-relay (`nett relay`), its public TCP entry, which holds no mesh private key.

pub mod cert;
pub mod entry;
pub mod relay;
pub mod server;
pub mod service;
pub mod wg;
