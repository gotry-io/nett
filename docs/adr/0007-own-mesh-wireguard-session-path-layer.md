# 0007. Own mesh: WireGuard session layer + nett path layer

- Status: accepted
- Date: 2026-10-12

## Context

The desired mesh works like a navigation app: it covers LAN, public, domestic and cross-border scenarios; nodes have multiple ways to connect; every node reachable from outside can act as a relay; the best path is detected automatically; when a path jitters, breaks, or a node goes offline, traffic switches automatically without interrupting connections; there is no single point of failure. At the same time, nodes run on machines of about 1 GB, so resource usage is a hard constraint.

No existing solution fully satisfies this:

| Solution | What it can do | What it cannot do |
|---|---|---|
| Tailscale | Hole punching, direct connections, UDP relay through your own nodes (Peer Relays, released October 2025), DERP fallback, clients on all platforms | Does not compare path quality (direct whenever direct is possible); no multi-hop; cannot choose a relay by carrier line; tailscaled stays resident at 25–70 MB and may exceed 200 MB under traffic |
| Plain kernel WireGuard | Encryption, best performance, near-zero memory | Each peer has a single fixed address: no probing, no switching, no relay; UDP only |
| EasyTier and similar | Multiple transport protocols, adapted to Chinese networks | No iOS client; not suitable for embedding as a library |

## Decision

nett builds its own mesh, in three layers:

- **Session layer: WireGuard**, responsible only for encryption. Linux uses the kernel implementation; platforms without a kernel module use a Rust userspace implementation. No other encryption protocol is maintained alongside.
- **Transport layer: pluggable**. UDP is the default; when UDP is restricted, TCP/TLS 443 is used; QUIC and obfuscation wrappers are added later. Encrypted packets are placed into these transports, and WireGuard itself is unchanged.
- **Path layer: the mesh process** (ADR 0013; originally designed as the mesh module in nett-node). For each pair of nodes it maintains candidate paths (direct LAN, direct public, through a relay, multi-hop relay), measures continuously, selects by score with hysteresis, and switches quickly when a path degrades. A switch only updates the peer address of the WireGuard session; the session and upper-layer connections are unaffected.

Supporting rules:

- All `public` nodes have relay capability, and the Hub chooses which relays are actually used; a relay only forwards encrypted packets;
- A `dial-only` node connects to at least two `public` nodes;
- Topology and keys are persisted locally on nodes, and nodes keep selecting paths and switching when the Hub is offline;
- A LAN joins through one host running nett-node acting as the smart gateway;
- tailscale is kept as an optional fallback, managed by the Hub and hidden from upper layers. The fallback is not scheduled; it runs only on nodes where the user explicitly enables it and is not bound by the node memory budget; Headscale's address pool must exclude nett's mesh prefixes.
- The path layer and the userspace WireGuard run in a separate mesh process (ADR 0013); on macOS in M1 it joins as a native member (ADR 0018), and container services that need the visitor's real IP use the container member (ADR 0016).

## Rationale

- WireGuard is minimal, formally verified, has a kernel implementation and standard clients on all platforms, and natively supports peer address changes, making it a fit for a session layer that stays constant as paths change;
- Its shortcomings (UDP only, a distinctive fingerprint, no relay or path selection) can all be filled in the transport layer and the path layer;
- Only a self-built path layer can implement quality-based path selection, multi-hop, and relay selection by carrier line, which is the core value of the product;
- Encryption is done by the kernel and relays forward only ciphertext, which is better in resource usage and security than processing all traffic in userspace.

## Alternatives considered

- **Use tailscale as the main backend and replace it gradually**: a quick start, but core capabilities (quality-based path selection, multi-hop) stay limited, and the cost of replacing it grows over time.
- **A self-built encryption protocol, or QUIC, OpenVPN, or IPsec in the session layer**: a self-built protocol needs additional security audits and has no standard client on phones; QUIC is better suited as a transport layer; OpenVPN has poor performance and resource usage; IPsec performs poorly in NAT environments and roaming scenarios.
- **Everything through relays (no direct connections)**: the best resistance to interference, but heavy traffic (such as remote video viewing) would be limited by relay bandwidth.

## Consequences

- The mesh is the largest piece of work in the project; M1 needs session management, the path layer, nett-relay and the TCP/TLS transport;
- A Rust userspace WireGuard implementation needs to be evaluated and selected;
- Links where both ends are behind NAT: hole-punched direct connection when at least one end has a cone NAT, or both ends have global IPv6 addresses (M1), otherwise connectivity goes through a relay; hole punching when both ends have symmetric NAT is in M2. The kernel WireGuard port belongs to the kernel; the mesh process sends probes using this port as the source port and receives copies of probes through nftables, and switches only after the hole-punched path has been verified, without interrupting the current connection (design/mesh.md sections 6.1 and 7.1, ADR 0021).
