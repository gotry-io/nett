//! The transport adapter `nett transport`: when UDP is unavailable it converts WireGuard packets
//! into TLS transport and handles only ciphertext (design/mesh.md section 5.3, ADR 0013).
//!
//! Each TLS relay has a UDP port on this machine's loopback address: WireGuard and the mesh process
//! send packets destined for this relay here, and each packet is sent as one binary WebSocket
//! message; in the other direction messages are dispatched by type: relay replies go back to the
//! mesh process port that sent the probe, and the rest go to the WireGuard port. It holds no keys:
//! the connection is authenticated by the first relay probe the mesh process sends over it.

pub mod client;
pub mod forward;
