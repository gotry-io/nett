# 0013. Mesh process and transport adapter

- Status: accepted
- Date: 2026-11-04

## Context

Two kinds of mesh work do not belong in nett-node:

- **Packet handling in user space**: the TLS transport adapter used when UDP is unavailable, and userspace WireGuard on platforms without a kernel module (Synology DSM, old kernels). ADR 0001 says the WireGuard UDP port is "listened on by the kernel", so nett-node is not considered to listen on a public port; on userspace platforms this premise does not hold;
- **The path layer**: measurement, scoring, switching, DNS answering, access rules and address translation. nett-node is a tokio single-threaded root process. A bug in it, a memory leak, a blocking operation mistakenly placed in the runtime, the node being killed by the OOM killer, or a node upgrade would stop the mesh from switching paths and DNS from answering.

architecture.md section 2 requires the mesh to keep working when both the Hub and the node are stopped. Moving only packet handling out of the node is not enough: established paths survive, but if a path fails while the node is down, nobody switches.

## Decision

The mesh is split into two independent system services, both subcommands of the `nett` executable (ADR 0012):

| Process | Responsibility | Runs as | Keys held |
|---|---|---|---|
| **Mesh process** `nett mesh` | WireGuard configuration (kernel netlink, or a userspace implementation + TUN); the path layer (measurement, scoring, switching, coordination with peers); probe responses on the mesh address and LAN addresses; the DNS responder; access rules, anti-spoofing and address translation for Edge addresses, and filter rules for smart gateway address translation; admission material verification; local identity lookups | Linux: `CAP_NET_ADMIN`, `CAP_NET_RAW` (probing on the WireGuard port, ADR 0021), plus `CAP_NET_BIND_SERVICE` when DNS needs it; not root. Userspace platforms: an identity that can create a TUN device (usually root) | Mesh private key |
| **Transport adapter** `nett transport` | TLS (WebSocket) transport adaptation, QUIC later: sends and receives WireGuard ciphertext on the loopback address and relays it to the TLS connection | Linux: a user systemd allocates while it runs (`DynamicUser`), known to the mesh process by its unit. macOS: no separate process; the mesh process runs the same forwarding | None; handles ciphertext only |

- **The mesh process runs independently**: it receives the `trust` and `mesh` partitions from nett-node over a local interface, verifies signatures itself, and persists the last configuration, the trust anchors and the revocations; when the node is stopped it keeps measuring, switching and answering DNS. It does not connect to the Hub, access Docker or execute external commands;
- **Configuration has a single owner**: the WireGuard interface and the mesh-related filter and address translation rules are modified only by the mesh process;
- **On Linux the transport adapter is not merged into the mesh process**: it parses TLS and WebSocket data from outside. In a process with `CAP_NET_ADMIN`, a compromise could change routes, filter rules and the WireGuard configuration; running separately with low privileges, a compromise can only drop or tamper with ciphertext that cannot be decrypted. With kernel WireGuard the mesh process otherwise reads nothing from outside but authenticated probes;
- **On macOS the mesh process carries the TLS transport itself**: running it separately there takes a hidden account that nett adds to the user's directory service and a third launchd service, on a computer the user works on. The macOS mesh process is a root process that already receives WireGuard packets from the network in user space, as Tailscale's does on macOS; merging adds the TLS and WebSocket parsing (rustls, memory safe). It connects only to the relays in its desired state and verifies their certificates by fingerprint, so after the handshake only those relays send it data. A compromise of this code, for example from a compromised relay, would reach root and the mesh private key on that machine; this is accepted for a smaller footprint on end-user computers. The forwarding is the transport adapter's code (`nett-transport`), which takes its configuration from the mesh process's worker directly instead of the helper socket;
- **Each is supervised by the system's service manager**: the mesh process starts before the node, with its own memory limit, automatic restart and a lower OOM priority; the transport adapter and nett-relay are likewise supervised individually, restarted by the service manager after a crash, and do not depend on the node being online. nett-node only enables or disables them according to policy;
- **The mesh process is the sole source of mesh configuration**: when the transport adapter and nett-relay start, they fetch their configuration from the mesh process (TLS target and certificate fingerprint, local port, relay assignment, the verified material needed for CONNECT), and the mesh process confirms they are ready; nett-relay does not open CONNECT until the mesh process reports that the filter rules are ready. The local socket authenticates the caller by the peer process's systemd unit (or root);
- **Upgrades**: the local interface and the state files carry version numbers and are bidirectionally compatible between two adjacent release versions. The release package metadata states whether the mesh process changed; if it did not, an upgrade does not restart the mesh process; the mesh process lags by at most one release version, and restarts with the next upgrade;
- The mesh private key is generated by nett-node at enrollment (the admission proof needs it), handed to the mesh process over a local interface with `0600` permissions, and from then on held only by the mesh process and never leaves the node;
- The resource budget is counted separately: idle RSS of each of the two processes is <= 5 MB, and forwarding buffers have upper bounds.

This is **fault isolation, not a security boundary**: nett-node is still root, and a compromised node can still modify the mesh process. The split guarantees that node failures and upgrades do not affect the mesh.

## Rationale

- Restores "management and traffic are separate": when the node is upgraded, crashes or is killed by the OOM killer, the mesh keeps switching and DNS keeps answering;
- Restores "privileged components are not exposed, exposed components are not privileged": the node does not handle packets on any public port;
- On Linux, code that parses external input (the transport adapter) holds no privileges and no keys; on macOS this is traded for a smaller footprint on the user's computer (see the decision above).

## Alternatives considered

- **Keep it in nett-node**: one process fewer, but any nett-node failure would stop the mesh from switching, and the smart gateway is the node affected most.
- **Move only packet handling out of the node**: preserves established paths, but when the node is down nobody switches paths or answers DNS.
- **Merge the transport adapter into the mesh process everywhere**: one process and one local interface fewer, but on Linux code that parses external input would gain the privilege to modify network configuration, in a process that otherwise reads nothing from outside.
- **A separate transport adapter on macOS too, under its own hidden account**: keeps the TLS parsing away from root and the mesh private key, but adds an account to the user's directory service and a third launchd service on the user's computer, which comparable products do not need there.
- **Put it in nett-relay**: the relay runs only on `public` nodes and, by design, does not hold the mesh private key.

## Consequences

- A node with the mesh module enabled has one more resident service (the mesh process); on Linux, when a TLS transport candidate exists, one more again (the transport adapter); the resource budget table grows accordingly. On macOS the mesh process's budget covers the TLS transport;
- nett-node and the mesh process need a versioned local interface (configuration delivery, status and counter reporting);
- The configuration of the transport adapter and nett-relay is provided by the mesh process, and they do not depend on the node when they restart;
- When the mesh process restarts it reloads the saved configuration: kernel WireGuard sessions are unaffected, and paths through it are briefly interrupted on userspace platforms.
