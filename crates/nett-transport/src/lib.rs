//! The TLS transport: when UDP is unavailable it carries WireGuard packets over TLS and handles only
//! ciphertext (design/mesh.md section 5.3). It runs in the nett daemon (ADR 0013).
//!
//! Each TLS relay has a UDP port on this machine's loopback address: WireGuard and the mesh send
//! packets destined for this relay here, and each packet is sent as one binary WebSocket message; in
//! the other direction messages are dispatched by type: relay replies go back to the mesh's port
//! that sent the probe, and the rest go to the WireGuard port. It holds no keys: the connection is
//! authenticated by the first relay probe the mesh sends over it.

pub mod client;
pub mod forward;
mod obfuscated;
pub mod queue;
