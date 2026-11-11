# Architecture

This document is the overall design of nett: what runs on each machine, how the three kinds of traffic flow, where trust comes from, and where the risks are. Details for each topic are in [design/](design/README.md), which is authoritative; the rationale for key decisions is in [adr/](adr/README.md); development rules are in [CLAUDE.md](../CLAUDE.md).

## 1. Overview

```
┌──────────────────────── The user's computer ─────────────────────┐
│ nett site: maintains the site; computes, displays and signs      │
│ locally (recovery key)                                           │
└───────────────┬──────────────────────────────────────────────────┘
                │ HTTPS: REST/JSON
┌───────────────▼─────────────────── Hub host ─────────────────────┐
│ Reverse proxy (Caddy by default): the Hub's HTTPS; hands off to  │
│   nett-relay by SNI                                              │
│ nett-hub: public API · authentication · desired state · audit    │
│           SQLite · node gateway                                  │
│ nett-relay: relay and public transport entry (low privilege)     │
│ nett-node                                                        │
└───────────────┬──────────────────────────────────────────────────┘
                │ Control: WebSocket over TLS + Protobuf (node connects out)
                │ Data: nett mesh (WireGuard session + nett path layer)
        ┌───────┼────────────┬─────────────────┐
     VPS node   VPS node     Smart gateway     Other hosts at home
     nett-node (+ nett-relay) at home          (join via the smart gateway,
                                                nothing to install)

External: phone ─standard WireGuard─► home gateway / mobile gateway
```

**Three planes**

| Plane | Carries | Components | Does not depend on |
|---|---|---|---|
| Control plane | Desired state, inventory and link status, tasks | Hub ⇄ nett-node (WebSocket + Noise, see design/protocol.md) | The mesh: the Hub endpoint list keeps at least one endpoint that does not go through the mesh (protocol.md section 8) |
| Mesh data plane | IP traffic between members | Mesh process (WireGuard, path layer, DNS, filtering) + transport adapter + nett-relay (see design/mesh.md) | The Hub being online; nett-node being online (ADR 0013) |
| Ingress plane | Traffic from public visitors through the Edge (the user's own reverse proxy) to services | Edge → mesh → service (section 8) | The Hub and nett-node being online |

The ingress plane depends on the mesh data plane. The control plane can use the mesh as a route (for example, connecting to the Hub through another ingress node), but cannot rely on the mesh alone; otherwise one faulty mesh configuration would leave nodes unable to receive a fix.

## 2. Roles and capability boundaries

| Role | Responsible for | Not responsible for | Privileges | Listens on public network |
|---|---|---|---|---|
| **Hub** | Stores desired state; aggregates node and link status; public API; distributes the mesh topology; forwards signed policies | Operating machines directly; raising any node's privileges on its own; sitting on the data path | Normal | Exposed through the local reverse proxy (section 4) |
| **nett-node** | Control agent: enrolls, connects to the Hub; hands signed material to the mesh process and starts and stops the processes; reports inventory and link status; upgrades (section 3) | Listening on public ports; executing arbitrary commands; accessing Docker; running AI logic; deciding privileges on its own | High | No |
| **Mesh process** | WireGuard configuration, path layer (measurement, path selection, switchover), DNS, access rules and address translation, admission material verification; runs independently of the node (ADR 0013) | Connecting to the Hub; accessing Docker; executing external commands | `CAP_NET_ADMIN`, `CAP_NET_RAW` (probing on the WireGuard port, ADR 0021); TUN permission on userspace platforms | Only the WireGuard port: answers only authenticated probes and, like the kernel implementation, does not respond to unauthenticated packets |
| **Transport adapter** | TLS transport adaptation; handles ciphertext only (ADR 0013) | Holding any key; any management function | Low | No (dials out) |
| **nett-relay** | Relays encrypted packets; accepts transports such as TCP/TLS; probe responses; per-connection forwarding (CONNECT) | Decrypting mesh traffic; any management function | Low | Yes |
| **Edge** | A reverse proxy the user runs on the ingress node (any implementation): terminates TLS and forwards requests to services through the mesh by domain name; nett does not generate or manage its configuration (section 8) | Any management function | Low | Yes |
| **Signing tool** (`nett site`) | Maintains the site on the user's own computer; computes, displays and signs changes that raise privileges (design/site.md) | Running as a daemon; connecting to nodes directly | Holds the recovery key | No |

**Three principles**

1. **Management and traffic are separate**: when the Hub and the nodes are both stopped, websites and the mesh keep working; changes are temporarily impossible.
2. **Privileged components are not exposed; exposed components are not privileged**: nett-node and the mesh process listen on no public address (the mesh process provides DNS and probe responses only on the mesh address; probe responses on a LAN address are enabled only when a LAN direct candidate exists, and do not respond to unauthenticated probes); all public listeners are handled by separate low-privilege processes (Edge, nett-relay). The WireGuard UDP port is listened on by the kernel or the mesh process, answers only authenticated probes, and does not respond at all to unauthenticated packets.
3. **Decision and execution are separate; raising privileges requires a signature**: a compromised Hub cannot exceed its authority: signing happens on the user's own computer, and the content to be signed is computed and displayed locally by the signing tool, not through the Hub (ADR 0024, design/auth.md section 2). Mesh members, advertised routes and access rules are likewise composed of signed artifacts (ADR 0014).

## 3. nett-node

A single process on a tokio single-threaded runtime, **running directly on the system, not in a container**: the mesh needs to configure the host's network (the mesh process configures the kernel WireGuard and nftables through netlink), and nett-node has to start and stop the local mesh process, transport adapter and nett-relay, and replace the local executable on upgrade. Putting it in a container would require privileged mode and the host network, which amounts to running natively. The container member on macOS only lets other members reach container services on the Mac, and is an exception (ADR 0016); Home Assistant OS does not allow installing programs directly, so nett runs as an add-on, which is another exception (ADR 0017).

nett-node is the control agent. It only handles enrollment, connecting to the Hub, keeping local state, upgrades, handing signed material to the mesh process, reporting inventory (platform, capabilities, addresses) and link status, executing mesh actions, and pulling the Hub's encrypted backup (section 12.3); it does not access Docker. It consists of the following parts:

- **Transport**: connects to the Hub, authenticates, reconnects after disconnection, and picks the best of multiple endpoints;
- **Supervisor**: computes whether modules and roles are in effect (see the module switches below), manages module lifecycles, and restarts after a crash with backoff;
- **mesh module**: a reconciler (desired state → actual state → diff → execute), safe to repeat. It hands the `trust` and `mesh` partitions to the mesh process, starts and stops the mesh process, transport adapter and nett-relay, and relays link status. The mesh work itself (section 6) is done in the mesh process and continues when the node is absent (ADR 0013);
- **State Store**: stores the identity key and the last effective configuration locally (the mesh topology, admission material and revocations are stored by the mesh process itself, ADR 0013). **On startup it applies the local cache first, then connects to the Hub**, so the mesh and the Hub do not depend on each other.

### Module switches

**Effective = not forbidden locally ∩ node capabilities ∩ signed policy**

| Layer | Decided by | Effect |
|---|---|---|
| Local hard prohibition | Node administrator | An optional absolute upper bound that a signed policy cannot exceed |
| Node capabilities | Automatically detected by the node | When kernel modules, root permission and the like are missing, the corresponding module is unavailable or an alternative implementation is used |
| Signed policy | Issued by the Hub | Lowering privileges can be issued directly; **raising privileges requires the user's signature**; the version number only increases |

The mesh module and the following roles can be switched. Roles are written in the signed node policy (`node.set_roles`, requires a signature):

| Switch | Effect | Typically enabled on |
|---|---|---|
| **mesh** module | Runs the mesh process; this machine joins the mesh directly (see above) | Nodes that join the mesh directly |
| `relay` | Runs nett-relay to relay for other nodes (section 6.4) | `public` nodes |
| `gateway` | Mobile gateway (section 7) | The Hub host or other `public` nodes |
| `subnet_router` | Smart gateway; brings a LAN prefix into the mesh (section 6.6) | One per LAN |
| `edge` | Declares that this machine runs an Edge and how to identify traffic sent by the Edge; an Edge address is allocated accordingly (section 8) | Ingress nodes |

### Zero configuration

A node stores only **identity and permissions** locally; everything else comes from the Hub or local detection: the Hub endpoint list (at enrollment only one public address is needed, the Hub pushes the rest, and the node probes them concurrently and picks the best), network reachability (`public` / `dial-only`), LAN addresses, mesh address, and so on. The mesh private key is generated on the machine and never leaves the node.

```bash
curl -fsSL https://hub.example.com/install.sh | sudo sh -s -- install <token>
```

## 4. Hub

- **Public API**: REST + JSON, resource-oriented; OpenAPI 3.1 generated from code; the command line, scripts, and later the web console and mobile clients all use the same API;
- **node gateway**: WebSocket + Protobuf;
- **Mesh control**: allocates addresses, distributes public keys and candidate paths, maintains the relay list and the link quality matrix;
- **Storage**: SQLite (WAL);
- **HTTPS**: the Hub sits behind a reverse proxy on the same machine, run with Caddy by default through Compose (ADR 0009, design/hub.md section 8). The Caddy configuration includes handing nett-relay's domain off to nett-relay by SNI on the same port 443; when the Hub host already has a reverse proxy, `nett-hub init` prints these two configuration snippets. This reverse proxy can also be the user's Edge, but nett only provides the two snippets for the Hub and nett-relay.

**Resource protection**: all queues, caches and channels have limits; data and audit records have retention policies; a 24-hour soak test is done before going live.

## 5. Authentication and authorization

| Identity | Authentication |
|---|---|
| User | Recovery key, used by the signing tool on the user's computer (design/site.md section 8); passkeys and sessions arrive with the web console (ADR 0024) |
| API token | `owner` (issued to the signing tool when the site is linked, design/hub.md section 4) and `script`; has a permission scope and an expiry time and is revocable; fixed prefix; the server stores only the hash |
| node | One-time enrollment token → X25519 identity key; the enrollment private key is generated by the signing tool, and the node uses it to sign its admission proof (ADR 0014); on connection, the Noise protocol inside the WebSocket provides mutual authentication and end-to-end encryption |
| Phone device | Device credentials (a WireGuard key, or CONNECT credentials) |

```
Request → identify → check permission scope → check policy → execute → write audit
```

**A token can only propose high-risk changes, not approve them.** Approval is a signature made by the user on their own computer with the signing tool, and the content to be signed is displayed locally (ADR 0024); once the web console arrives, a passkey can also be used to sign (design/auth.md section 10.2).

At enrollment, the signing tool allocates the node ID and address and generates the enrollment key pair (design/hub.md section 6); the token carries the Hub's full public key (needed by Noise IK) and the enrollment private key; the node signs its admission proof with the enrollment private key; other members verify this node by "signed policy + admission proof", not by the Hub's word alone (design/auth.md section 8).

**Chain of trust**

| Root of trust | Signs | Verified by |
|---|---|---|
| The user's recovery key (passkeys later) | Trust anchor updates; change approvals; node policy; mesh admission material (members, device credentials, advertised routes, access rule sets); permission to downgrade | Nodes verify independently, without trusting the Hub |
| The one-time enrollment private key generated by the signing tool | Admission proof (binds node ID, identity public key, mesh public key) | The Hub and all mesh members |
| The project's release signing keys (primary and backup, ADR 0020) | Release packages | Nodes (the public keys are embedded in `nett` at build time) |
| The user's backup key | Encrypted Hub backup | Only the user holding the offline private key can decrypt it |

After a Hub compromise, the attacker **can**: view the mesh state; perform low-risk operations; confirm medium-risk operations, such as changing a connection's policy; disconnect the mesh; and withhold a revocation from a member that has never received it. The attacker **cannot**: raise any node's privileges; add mesh members or widen mesh access (including by relabeling, and by letting an Edge address reach more targets); downgrade nodes; forge node identity; or restore revoked privileges by replaying old signed artifacts.

None of this requires the user to avoid anything the compromised Hub provides: the content to be signed is computed and displayed by the signing tool on the user's computer, and the enrollment command states the release package's hash, neither going through the Hub; `nett trust log` on a node lets the user check afterward which authorizations the node has accepted (design/auth.md section 2; ADR 0006, 0012, 0014, 0024).

## 6. The mesh

### 6.1 Goals

It works like a navigation app: there are multiple candidate paths and multiple transports between nodes, they are measured continuously, and the best path is selected automatically; when a path jitters or breaks, or a node goes offline, traffic switches automatically within seconds and **ongoing connections are not interrupted**; there is no single point. The experience on disconnect, fluctuation, fallback and recovery is no worse than the Tailscale baseline (ADR 0021).

### 6.2 Layers

```
┌─ Session layer: WireGuard (encryption) ──────────────────────────┐
│ One encrypted session per pair of nodes; the session is          │
│ unchanged when the path changes                                  │
│ Linux uses kernel WireGuard; platforms without the kernel        │
│ module use a Rust userspace implementation                       │
├─ Transport layer: pluggable (delivers encrypted packets) ────────┤
│ UDP (default) · TCP/TLS 443 · QUIC 443 (later) ·                 │
│ obfuscation wrapper (later)                                      │
├─ Path layer: mesh process (path selection, ADR 0013) ────────────┤
│ Candidate paths: LAN direct · public direct · via relay ·        │
│ multi-hop relay                                                  │
│ Measure continuously → score → select best (with hysteresis) →   │
│ switch fast when degraded                                        │
└──────────────────────────────────────────────────────────────────┘
Control plane: Hub (addresses, public keys, candidate paths, relay list, link quality matrix)
```

- **The session layer uses only WireGuard**: compact code, formally verified, natively supported by the Linux kernel, with standard clients on every platform. WireGuard lets a peer change its address (designed for roaming), so switching paths only requires updating the session's peer address, and upper-layer connections are unaffected. WireGuard configuration, the path layer, and the userspace implementation on platforms without the kernel module are all in the independent mesh process (ADR 0013); macOS joins as a native member (ADR 0018), and container services that need the visitor's real IP use a container member instead (ADR 0016).
- **The transport layer is pluggable**: WireGuard supports only UDP, and its fingerprint is distinctive. When UDP is restricted, encrypted packets are put into a TCP/TLS or QUIC transport, so outsiders see ordinary HTTPS or HTTP/3 traffic.
- **The path layer is the core of nett**: it decides which path and which transport each pair of nodes uses.

### 6.3 Candidate paths and path selection

| Candidate path | Condition |
|---|---|
| LAN direct | Both nodes are on the same LAN (the Hub issues both sides' LAN addresses, and the mesh process confirms by probing) |
| Public direct | At least one end is reachable from outside (`public`; IPv4 and IPv6 are judged separately) |
| Via relay | Forwarded through the nett-relay of some `public` node |
| Multi-hop relay | Through two or more relays (for example, over a high-quality line when crossing borders) |
| Hole-punched direct | At least one end is behind a cone NAT, or both ends have global IPv6 addresses; the mapped address is taken from the source address seen by a `public` node, agreed over the current tunnel, then packets are sent simultaneously from the WireGuard port, and the switch happens after the path is verified; a failure does not affect the current connection (design/mesh.md section 6.1); both ends behind symmetric NAT comes later |

Path selection:

- Latency, loss and jitter are measured continuously for each candidate path;
- The current path is chosen by score; among paths of the same type, a new path must be **clearly better and stay so for a while** before switching, to avoid flapping; a better type of path (for example, from relay back to direct) is switched back to as soon as it is verified;
- When probes on the current path get no response several times in a row, extra probes are sent immediately and all candidates are probed at the same time; a failure is declared after about 3 seconds, and traffic switches **immediately** to the best candidate just measured (design/mesh.md section 8.2);
- Nodes switch on their own according to the locally cached topology, **without depending on the Hub being online**;
- Policy overrides are supported, for example preferring direct for a class of traffic, or forcing a particular relay.

### 6.4 Relays

- **All `public` nodes are relay-capable** (`dial-only` nodes and phones cannot relay for other nodes). The Hub decides which relays to actually use based on location, measured quality, traffic quota and spare resources.
- **A relay only forwards encrypted packets and cannot see the content**, so end-to-end encryption is unaffected.
- Relaying is handled by the separate low-privilege process nett-relay, which consumes resources only while forwarding traffic.
- Each relay uses a single UDP port. On the Hub host it shares 443 with the Hub: the reverse proxy in front of the Hub hands nett-relay's domain off to nett-relay by SNI (section 4, ADR 0011).

### 6.5 Network reachability

| Type | Meaning | Connection rule |
|---|---|---|
| `public` | Reachable from outside (a public address, or a mapped port) | Can accept connections and can act as a relay |
| `dial-only` | Can only dial out | Connects to `public` nodes; **connects to at least two** to avoid a single point |

Reachability is detected jointly by the node and the Hub, with IPv4 and IPv6 judged separately, and is updated automatically after network changes. Cloud provider security groups must be opened manually by the user; the ports each role needs are in design/mesh.md section 5.5.

### 6.6 LAN access

A LAN needs only one host running nett-node as the **smart gateway** (subnet router): it brings the whole LAN prefix into the mesh, with full path selection and switchover. Other hosts on the LAN do not need any mesh software. The smart gateway applies source NAT to forwarded traffic, so that replies of LAN hosts are not intercepted by other VPNs or proxies on the gateway itself; traffic from the Edge address is translated to a separate "ingress address", which services that need the real IP trust exclusively (ADR 0015). Advertised LAN prefixes are open only to the user's devices by default. The WireGuard built into the gateway device can serve as a backup path.

### 6.7 Per-connection forwarding (CONNECT)

Besides packet-level mesh networking, nett-relay also provides an **HTTPS CONNECT proxy** (HTTP/2 over TLS):

- It suits scenarios where "the application itself initiates the TCP connection": programs that support an HTTPS proxy reach internal services from networks where UDP is restricted (the host where the Edge runs is itself a mesh member, so origin traffic goes directly over the mesh without CONNECT);
- On the Hub host's 443 only HTTP/2 CONNECT is supported (handed off by the reverse proxy; in testing, standard Caddy cannot forward HTTP/1.1 CONNECT tunnels), while nett-relay on other nodes supports both;
- No dedicated client is needed; any program that supports an HTTPS proxy can use it;
- TCP only; the relay can see the destination address, and the content of unencrypted traffic is visible too. All relays run on the user's own machines, and every hop between relays uses TLS.

The two approaches complement each other: the mesh carries any protocol; CONNECT suits clients that cannot conveniently run the mesh and application-layer proxies.

### 6.8 Fallback

tailscale (Headscale + derper + tailscaled) is an optional fallback: it is used in scenarios the in-house mesh does not yet cover, managed centrally by the Hub and hidden from the upper layers. The upper layers see only nett's own concepts (nodes, addresses, hostnames, access rules, link status). The fallback is not scheduled; it runs only on nodes where the user explicitly enables it and is not bound by the node memory budget; Headscale's address pool must exclude nett's mesh prefixes.

## 7. Phone access

The phone side is compatible with **any standard WireGuard client**: nett exports a standard configuration (a configuration file and a QR code) and does not pin a client; it also exports configurations for Surge, mihomo and sing-box (ADR 0018). The configuration contains **two paths**:

```
Phone ─┬─ direct to the smart gateway at home (standard WireGuard) → services at home;
       │   heavy traffic (such as video) does not detour
       └─ mobile gateway (standard WireGuard) → other nodes; fallback when direct is unavailable
```

- The two peers split traffic by prefix, which standard clients support;
- At any time, each credential of a device belongs to only one mobile gateway, which advertises that credential's address on its behalf; the configuration lists two DNS servers (the mobile gateway and the smart gateway);
- The mobile gateway is a WireGuard interface on the Hub host (or another `public` node); the path beyond the gateway is handled by the nett path layer;
- A device can have multiple credentials (for example, one each for two different client programs), each revocable independently, with permissions granted per device;
- When UDP is restricted, clients that support an HTTPS proxy can reach internal services through nett-relay's CONNECT proxy;
- Standard clients do not switch between paths automatically, so a backup configuration that sends "everything via the gateway" is exported as well (using a separate credential), for manual switching when direct is blocked. Proxy client configurations put the two paths in an automatic fallback policy group, so when direct fails they switch to the gateway automatically, and they do not use up the phone's only VPN slot;
- The phone app and Windows arrive in M3, when they are full members and choose paths themselves (ADR 0018).

## 8. Origin traffic

The last hop of origin traffic determines two things: whether the service can get the visitor's real IP, and whether services that trust by source are accidentally opened up.

The Edge is a reverse proxy the user runs on the ingress node, and any implementation works (Caddy, nginx, Traefik, and so on); nett does not generate or manage its configuration (ADR 0019). Origin traffic from the Edge goes through the mesh, and the path layer selects the path; the Edge configuration uses mesh addresses instead of hostnames (the Edge often runs in a container and cannot resolve the mesh suffix).

**Edge address**: the `edge` role in the node policy (`node.set_roles`, requires a signature) declares that this machine runs an Edge and how to identify traffic sent by the Edge: the address of the container the Edge runs in, or the system user when it runs natively. An Edge address is allocated accordingly, and the mesh process rewrites the source of mesh traffic sent by the Edge to this address; other processes and containers on the machine cannot use it (ADR 0015).

**Origin identity** (ADR 0015): for a service that needs the visitor's real IP, the last hop must come from an address that only the Edge can use; the service trusts only the `X-Forwarded-For` sent from this address, and the user configures the corresponding forwarder address as a trusted proxy in the service. The Edge must overwrite this header with the visitor's real address (Caddy does so by default, fact 6 in section 17), so that a header forged by the visitor is overwritten.

| Where the service is | Origin path | Forwarder the service sees |
|---|---|---|
| On a mesh member (Linux, container or native process) | Edge → mesh → member's mesh address:port. On Linux, Docker port mapping applies destination NAT to external traffic and preserves the source | The ingress node's Edge address |
| LAN host behind a smart gateway | Edge → mesh → smart gateway (translation by source class) → LAN host | The smart gateway's ingress address (used only to translate traffic from Edge addresses) |
| Container in Docker on macOS | Edge → mesh → container member → container network (a published port loses the source, fact 1 in section 17) | The container member's address in that container network (ADR 0016) |

**Services that trust by source**:

- The translated address must never be a loopback address; when forwarding to a service on the host, use the host's LAN address and never `host.docker.internal` (fact 2 in section 17);
- Advertised LAN prefixes are open only to the user's devices by default;
- An Edge address cannot reach any target by default; which hosts and ports it can reach is written by the user in the access rules. These rules belong to the signed access rule set: adding or changing an origin target amounts to exposing an internal port to the public network, so widening requires a signature (design/mesh.md section 12);
- Origin traffic from the Edge to a service on the same host does not go through the mesh and is not subject to these rules.

## 9. AI access

nett contains no AI logic. AI, like any other external program, uses nett only through the Hub API (a `script`-type API token, section 5) (ADR 0010).

## 10. Technology stack

| Part | Choice |
|---|---|
| Hub | Rust: axum, SQLite + sqlx, utoipa, rustls; webauthn-rs and rust-embed are added with the web console (ADR 0024) |
| node | Rust: tokio (single-threaded), tokio-tungstenite, prost, hyper; WireGuard is managed through netlink against the kernel implementation (only the few message types used are encoded; no netlink library) |
| Shared by all components | serde, serde_json; ring (signature verification, hashing, HMAC, HKDF, also the crypto backend of rustls); x25519-dalek (derives the keys for direct probing between members from the mesh private key; ring cannot import an existing private key); rustix (system calls for netlink and raw sockets; nftables rules are also installed through netlink, without calling the `nft` command); lexopt (command-line parsing) |
| nett-relay | Rust: tokio, rustls (via tokio-rustls), tokio-tungstenite (WebSocket for the TLS transport entry), hyper (HTTP/2 CONNECT); blake2 (computes `mac1` per the WireGuard protocol); quinn later (QUIC) |
| nett-transport | Rust: tokio (single-threaded), rustls (via tokio-rustls, verifying certificates by fingerprint), tokio-tungstenite |
| Userspace WireGuard | The `noise` layer of gotatun, for platforms without the kernel module (design/userspace.md section 3) |
| Protocols | Public: REST + JSON (OpenAPI 3.1), plus SSE when the web console arrives; internal: WebSocket + Protobuf |
| Web (console, ADR 0024) | React + Vite, TanStack Router / Query / Table, shadcn/ui + Tailwind, xyflow |
| Reverse proxy in front of the Hub | Caddy (default, ADR 0009) |

## 11. Code organization

```
nett/
├── proto/              # Protobuf definitions for node ↔ Hub
├── crates/             # node, mesh, transport, relay, cli are linked into the same nett executable
│   ├── nett-proto/
│   ├── nett-core/      # shared domain model
│   ├── nett-trust/     # verification of signed payloads, trust anchors, admission material and revocations (shared by node and mesh process)
│   ├── nett-hub/
│   ├── nett-node/
│   ├── nett-mesh/      # mesh process: platform-independent core (admission, measurement, path selection, switchover) + per-platform data plane backends (ADR 0018)
│   ├── nett-transport/ # transport adapter
│   ├── nett-relay/
│   ├── nett-site/      # site model and composition of desired state (shared by the signing tool and the Hub, design/site.md)
│   ├── nett-cli/       # the nett command
│   └── nett-lab/       # lab tooling: generates lab configuration, builds topologies, injects faults, collects measurements (development and testing only, not in release packages)
├── web/                # web console (React SPA, ADR 0024); src/api is generated from OpenAPI
├── keys/               # release signing public keys (ADR 0020)
├── packaging/          # systemd units, container images and Homebrew formula templates (section 13.2)
└── docs/
```

Generation chain: `proto → prost → Rust`; `Hub code → utoipa → openapi.json → TypeScript client`. CI checks that the generated files are up to date.

## 12. Failure and availability

### 12.1 Relationship between the Hub and the node

The Hub is the control plane and the node is the executor:

- The node connects to the Hub; the Hub never connects to a node;
- The node executes only the signed desired state issued by the Hub and does not decide privileges on its own;
- **The node and the mesh process each store the last effective configuration locally** (the mesh topology, admission material and revocations are stored by the mesh process), and on restart apply the local configuration first, then connect to the Hub;
- **The Hub is not on the data path**: neither mesh traffic between nodes nor visitor traffic to services goes through the Hub; path switching is done by the nodes on their own.

### 12.2 Failure scenarios

| Scenario | Keeps working | Paused | Response |
|---|---|---|---|
| **Hub process stops** (crash, upgrade, restart) | Mesh between nodes and automatic switching, Edge origin traffic, phone access | Configuration changes, new nodes enrolling | The service manager restarts it automatically (section 13.2) |
| **nett-node stops** (crash, upgrade, killed by the OOM killer) | Mesh and automatic switching, DNS, Edge origin traffic | Status reporting, configuration changes, upgrades | The service manager restarts it automatically; the mesh process runs independently (ADR 0013) |
| **Mesh process stops** | Kernel WireGuard keeps the current path | Path switching; all paths are interrupted on userspace platforms | The service manager restarts it automatically; it loads the trust store first, then the desired state (design/mesh.md section 4.2) |
| **Reverse proxy in front of the Hub stops** | The mesh | The Hub's API; nodes that connect to the Hub through this host | Nodes switch to other endpoints in the Hub endpoint list |
| **Hub host goes down** | Paths and services that do not go through this host | All of the above, plus the reverse proxy, relay and mobile gateway on this host | The path layer routes around it automatically; see 12.3 |
| **A node goes down** | The remaining nodes; paths that use it as a relay route around it automatically | Services on that node | — |
| **A path degrades or breaks** | — | — | The path layer switches within seconds and connections are not interrupted |

### 12.3 Eliminating single points

1. **Multi-point connectivity**: a `dial-only` node connects to at least two `public` nodes.
2. **At least two usable relays**, on different hosts. This is a redundancy floor, not a limit on the number of relays.
3. **The mesh does not depend on the control plane being online**: the topology and keys are persisted locally on each node and do not expire; when the Hub is absent, nodes keep selecting paths and switching.
4. **Multiple mobile gateways can be deployed**; the phone also keeps its direct path to home.
5. **Backup and rebuild**: the Hub's database, together with the Hub identity private key, is encrypted with the backup public key and pulled periodically by other nodes (the Hub never connects to nodes); an operations manual for rebuilding the Hub on another host is provided. The node's endpoint list includes a backup entry, so after the Hub moves, nodes connect to the new Hub automatically. A backup always lags behind the state of the nodes, and on restore the nodes send back the signed artifacts in effect (protocol.md section 6.4).

## 13. Packaging, installation and operation

### 13.1 Release artifacts

| Artifact | Contents | Installed on |
|---|---|---|
| **`nett`** | One executable that runs as different roles by subcommand: command line, `nett node`, `nett mesh`, `nett transport`, `nett relay` | All nodes |
| **`nett-hub`** | The Hub (executable and container image, design/hub.md section 8) | The Hub host only |
| **HA add-on** | The container image of `nett` and the add-on repository (ADR 0017) | Devices running Home Assistant OS |

At the code level, node, mesh, transport, relay and cli remain separate crates that are finally linked into the same executable. This way installation and upgrade happen once and versions cannot be mismatched; multiple processes map the same file, so code pages are shared by the system and total memory is lower. Security isolation relies on the user and privileges each process runs with, regardless of whether it is the same file.

`nett` on Linux (x86_64, aarch64) is statically linked against musl: the same file works on all distributions and does not depend on the system's libc version; the resident memory of each process is also smaller. With dynamic glibc linking, the code pages of ld.so, libc and libgcc_s all count toward each process's RSS, and measured idle RSS of every process exceeds 5 MB, of which the process's own memory is under 1 MB (prototype.md section 9, scenario 21). Each process disables transparent huge pages at startup (`PR_SET_THP_DISABLE`): when the system is set to `always` (for example, Linux 6.1), a thread stack is replaced wholesale by a 2 MB huge page and RSS grows by 2 MB; these processes have no use for huge pages.

### 13.2 How it runs

| Service | Runs as | Keys held | Listens on | When it runs |
|---|---|---|---|---|
| `nett-node` | root (replaces the executable on upgrade, starts and stops the other nett processes on the machine); runs directly on the system, not in a container (section 3) | Node identity key | Nothing | All nodes |
| `nett-mesh` | On Linux, a dedicated user with `CAP_NET_ADMIN` and `CAP_NET_RAW` (plus `CAP_NET_BIND_SERVICE` when DNS needs it); on userspace platforms, an identity that can create a TUN | Mesh private key | Mesh address (DNS, probe responses); on userspace platforms, the WireGuard port | Nodes with the mesh module enabled; starts before nett-node, with its own memory limit and a lower OOM priority |
| `nett-transport` | A dedicated low-privilege user | None | Nothing (dials out) | Enabled by nett-node when a TLS transport candidate exists |
| `nett-relay` | A dedicated low-privilege user | The relay's TLS certificate private key; does not hold the mesh private key | Public: one relay UDP port, TLS 443 | The Hub decides whether it is enabled based on node reachability and signed policy; nett-node enables or disables it, and the configuration comes from the mesh process; `dial-only` nodes do not run it |
| `nett-hub` | A dedicated low-privilege user; can also run in a container (the Hub does not need to access the host) | Hub identity key | Local (exposed through the reverse proxy in front of the Hub) | The Hub host |
| Reverse proxy in front of the Hub | Low privilege | Private key of the certificate for the Hub domain | Public 80, 443 | The Hub host |

The user's own Edge is not part of nett and is not listed here. The list of public ports is in design/mesh.md section 5.5.

Each service is restarted automatically by the service manager after a crash, without depending on nett-node. Service management: Linux uses systemd (with a memory limit), macOS uses launchd, Synology DSM uses a boot task (a package comes later), and Home Assistant OS uses an add-on (ADR 0017).

### 13.3 Installation

**Hub (once)**: run nett-hub and Caddy on the Hub host using the project's Compose example, or run natively (design/hub.md section 8), then:

```bash
nett-hub init --url https://hub.example.com   # on the Hub host: prints a one-time link code
nett site link nett_lnk_…                     # on the user's own computer
```

The link code is valid for 1 hour and can be used only once, which keeps others from linking first; `nett site link` hands the site's trust anchors to the Hub (design/hub.md section 3.1). The recovery key is generated at `nett site init` and is stored only on the user's computer (design/site.md section 8).

**Nodes**: on the user's computer run `nett site add <name>`, then run the command it prints on that machine (design/hub.md section 3.3):

```bash
curl -fsSLo nett.tar.gz https://hub.example.com/dl/nett-<version>-<target>.tar.gz \
  && echo "<SHA-256>  nett.tar.gz" | sha256sum -c && tar -xzf nett.tar.gz && sudo ./nett install nett_enr_…
```

- **Installation runs no code provided by the Hub**: the enrollment command is generated by the signing tool and states the release package's SHA-256, and the signing tool has already checked the release signature with the embedded release public keys (the primary and backup public keys are embedded in `nett` at build time, ADR 0020). The release package can be downloaded from the Hub's cache (nodes do not need to reach public code hosting platforms, which is more reliable in regions with restricted networks) or from the project's release page, and it runs only after the hash is verified (design/hub.md section 3.3);
- The token is valid once and expires quickly;
- You can also download manually, verify the signature with minisign, then run `sudo nett install <token>`;
- On macOS you can also install through Homebrew and then run `sudo nett install <token>`.

**Phone**: no nett installation is needed. Once device credentials and the mobile gateway are implemented, the `nett site` command generates a standard WireGuard configuration (a configuration file and a QR code, ADR 0008) that any WireGuard client can import; configurations for Surge, mihomo and sing-box can also be exported, which switch to the gateway automatically when direct access to home fails.

### 13.4 Commands

Commands are in three groups by scope, and each command does one thing. `nett` or `nett help` lists all commands in these three groups, and any command with `--help` shows its usage.

**The whole network**: run only on the computer that holds the site. The `nett site` commands maintain machines, Edges, advertised routes and access rules, and link with the Hub; each modifying command lists what is to be signed, and after confirmation signs and delivers it. Commands and usage are in design/site.md section 3.

**This machine**: run on each machine, most need root.

| Command | Effect |
|---|---|
| `nett status` | State of this machine and its peers (design/status.md) |
| `nett reload` | Asks the mesh process to re-read the desired state file and shows whether it was accepted (design/status.md section 4.1) |
| `nett install` | Sets this machine up as a member: generates keys, installs services, imports the desired state (macOS, design/release.md section 4); with an enrollment token, enrolls with the Hub (design/hub.md section 6) |
| `nett uninstall` | Stops and removes the services, keeping the keys and the desired state; running `install` again restores it |
| `nett keys` | Only generates this machine's keys and prints the line needed by `nett site add --keys`: for container members and machines whose service configuration is written by hand |
| `nett leave` | Leaves this network (root): notifies the Hub, tears down the mesh interface, deletes this machine's keys, trust anchors and desired state, and uninstalls the services; the machine can then join any network (design/auth.md section 8.3) |
| `nett doctor` | Automatic diagnosis, with plain-language explanations and suggested fixes |
| `nett whois <address>` | Looks up which node, device or Edge a mesh address belongs to, according to the admission material this machine has verified |
| `nett trust log` | Lists the signed artifacts and revocations this machine has accepted, without going through the Hub (design/auth.md section 2) |
| `nett upgrade` | Manual upgrade; by default the Hub pushes it through the `release` partition; verifies the release signature, rejects downgrades, then replaces, and rolls back automatically on failure |
| `nett deny <module>` | Sets a local hard prohibition (section 3) that a signed policy cannot exceed |

`nett-hub` on the Hub host is a separate executable; its commands are in design/hub.md section 8.

**Service processes**: run by systemd, launchd or containers, not run directly by the user: `nett mesh` (mesh process), `nett node` (control agent), `nett relay`, `nett transport` (section 13.2).

### 13.5 Node forms

| Form | Typical machine | Processes run | Mesh | Notes |
|---|---|---|---|---|
| Hub host | A public VPS that can use the Hub domain | nett-hub, reverse proxy in front of the Hub (Caddy by default), nett-node, mesh process, nett-relay | Kernel WireGuard, `public` | After the web console arrives, only this one address is used (design/auth.md section 5) |
| Public node | An ordinary VPS | nett-node, mesh process, nett-relay, optionally the user's own Edge | Kernel WireGuard, `public` | All are relay-capable |
| NAT node | A NAT-type VPS | nett-node, mesh process, transport adapter | Kernel WireGuard, `dial-only` | Connects to at least two `public` nodes |
| Smart gateway | An always-on NAS or small host at home | nett-node, mesh process, optionally nett-relay | Kernel or userspace (in the mesh process) | Advertises the LAN prefix; becomes `public` once the router maps a port |
| LAN host | Other machines at home | Does not run nett | Through the smart gateway | Add an alias when a name is needed (design/mesh.md section 11) |
| macOS host | A Mac (including laptops) | Native nett-node, mesh process; optionally a container member | Native member: userspace WireGuard + utun (ADR 0018); container member uses kernel WireGuard (ADR 0016) | With a container member enabled, the same host corresponds to multiple node identities |
| HAOS device | A device running Home Assistant OS | nett-node and mesh process in the add-on, optionally nett-relay | Kernel WireGuard (ADR 0017) | Can act as a smart gateway |
| Device | Phone | A standard WireGuard client, or Surge, mihomo, sing-box | Dual path (ADR 0008); proxy clients fall back automatically (ADR 0018) | Does not run nett; the app arrives in M3 |

## 14. Supported platforms and external integrations

### 14.1 Platforms (first release)

| Platform | How it runs | Mesh | Available modules |
|---|---|---|---|
| Linux (Debian, Ubuntu, and other distributions with kernel ≥ 5.6) | systemd, native | Kernel WireGuard | All |
| Linux (older kernels) | systemd, native | Userspace WireGuard | All |
| Synology DSM 7.x | Boot task (a package comes later), native | Userspace WireGuard | mesh, relay |
| macOS | launchd, native | Native member: userspace WireGuard + utun (ADR 0018); container services that need the visitor's real IP use a container member (OrbStack, Docker Desktop, ADR 0016) | mesh, relay |
| Home Assistant OS | Add-on (ADR 0017) | Kernel WireGuard | mesh (can act as a smart gateway), relay |
| Phone | A standard WireGuard client, or Surge, mihomo, sing-box (automatic fallback) | — | — |

- Windows members and the iOS and Android apps arrive in M3 (ADR 0018);
- Other platforms are marked "untested" and support is not promised; capability detection explains what is missing and what it degrades to;
- Home Assistant running on ordinary Linux (the Container and Core installation methods) is treated as Linux.

### 14.2 External integrations (first batch)

| Category | First batch supported | How to extend |
|---|---|---|
| Reverse proxy in front of the Hub | Caddy (in the project's Compose example, ADR 0009) | — |

### 14.3 Language

Everything nett ships and documents is in English only, like common open-source projects: the command line, API error messages, the future web console, README and guides, design documents and ADRs (CLAUDE.md, "Language"). Each text exists once, so when users report problems or search for troubleshooting material they are matching the same sentence. How to write command-line output:

- Keep the wording neutral and concise: state the result first, and when the user needs to do something next, give the complete command; do not reference design documents;
- Human-readable output is column-aligned, with units on values and a precision suited to reading, and times written as relative times (`12s ago`); where there is no value, write `-`;
- Output meant for programs uses `--json`, with stable field names and a version number;
- No colors and no emoji;
- Exit codes: 0 for success, non-zero for failure, which scripts use to decide.

### 14.4 Telemetry

No usage data is collected or reported by default.

## 15. Security essentials

| Point | Where |
|---|---|
| Release signing belongs to the project, with a primary and a backup key: the primary key is available only in a separate signing job in CI, and the backup key is stored offline only; nodes automatically accept only higher versions, and downgrades require a signature; upgrades go only through the `release` partition | design/auth.md section 11.3, ADR 0012, 0020 |
| The backup contains the Hub identity private key, is encrypted with the backup public key, and is pulled periodically by other nodes | design/auth.md section 12, design/protocol.md section 5 |
| The recovery key is used only by the signing tool on the user's computer, and the Hub has never seen the recovery private key | design/site.md section 8, design/auth.md section 4 |
| Nodes do not serve DNS on the "LAN address" of a cloud host; probe responses on LAN addresses do not respond to unauthenticated probes | design/mesh.md sections 7, 11 |
| The content to be signed is computed and displayed locally by the signing tool, not through the Hub; `nett trust log` checks afterward | design/auth.md section 2, ADR 0024 |
| Revocations: old signed artifacts cannot restore revoked privileges; admission material is not rejected by its approved expiry time | design/auth.md sections 10.2, 10.4 |
| Access rules are signed as the expanded result, so relabeling cannot widen access | design/mesh.md section 12, design/api-resources.md section 5.5 |
| Edge address anti-spoofing; CONNECT is authorized per connection by nett-relay | ADR 0015; design/mesh.md sections 5.4, 12 |
| Filter rules are attached before destination NAT, take effect before peers, and deny on failure | design/mesh.md section 12 |
| The Hub trusts only the `X-Forwarded-For` sent by the reverse proxy in front of it | design/auth.md section 12 |

## 16. Main risks

| Risk | Description | Response |
|---|---|---|
| Mesh workload | M1 is the largest piece of the whole project: path layer, admission verification, single-port relay, classified translation, hole punching | The first step of M1 is the Linux prototype gate, which measures relay takeover, switchover time, roaming correction and MTU, and compares performance with native WireGuard and Tailscale; only after it passes is the work spread out; the macOS native member and DSM share the userspace WireGuard; the core logic is platform-independent, leaving room for M3 clients |
| Userspace WireGuard performance and memory | Throughput, latency, CPU and idle RSS | The session layer is wrapped behind a trait so the implementation can be replaced (design/userspace.md section 3); performance is compared with wireguard-go on the same Mac and with Tailscale on the same NAS; TUN, IP forwarding and NAT capabilities are verified one by one on the NAS system first |
| Network environment | UDP throttled or identified, poor cross-border line quality at evening peak, domain filing restrictions | TLS transport as a fallback; the mesh process measures continuously and reports line quality; whether a given transport (for example, TLS by IP without SNI) is usable in a given network is decided by measurement, not assumed |
| Resource budget | Up to four resident processes per node (node, mesh process, transport adapter, relay), each ≤ 5 MB | Measured separately, recording both RSS and PSS (CLAUDE.md, "Resource discipline"); fragment reassembly is spilled to disk; a soak test at every milestone |
| Clients that support only HTTP/1.1 CONNECT | CONNECT cannot be used on ingress nodes | Use nett-relay on a non-ingress node |
| Cloud security groups can only be changed by hand | Cannot be automated | The port list in design/mesh.md section 5.5, and `nett doctor` gives specific hints |
| The Hub host is the largest single point | The Hub, reverse proxy, relay and mobile gateway are concentrated on one machine | Section 12.3; encrypted backups are pulled by other nodes |

## 17. Facts learned in practice

Items 1-7 come from a real deployment: Caddy on a cloud host, over a WireGuard tunnel, forwarding origin traffic to a container service in OrbStack on a macOS machine at home. Items 9 and 10 were measured in a container against standard Caddy 2.10.2.

| # | Fact | Used in |
|---|---|---|
| 1 | Docker on macOS (OrbStack): all clients that reach a container through a published port appear inside the container as the container network's gateway address, whether from the LAN, a VPN, or the machine itself | Section 8; ADR 0015, 0016 |
| 2 | When a container reaches a native service on the host through `host.docker.internal`, the host sees the source as `127.0.0.1` | Section 8 |
| 3 | Kernel WireGuard inside an OrbStack container works normally while a proxy-style VPN app (enhanced mode) is on, on the host; UDP is sent out directly and is not intercepted by the proxy | ADR 0016 |
| 4 | Some cloud providers' security groups deny all inbound UDP by default and can only be changed manually in the web console | design/mesh.md section 5.5 |
| 5 | Caddy in a container can reach a tunnel address directly through the host's WireGuard interface, and Docker's address masquerading rewrites the source to the host's tunnel address | ADR 0015 (matching Edge traffic by container address) |
| 6 | Caddy overwrites `X-Forwarded-For` with the real source by default and writes `X-Forwarded-Proto: https`, so forged headers are overwritten | Section 8 |
| 7 | Putting the tunnel endpoint into the container network where the service lives and listening only on the tunnel address lets the service recognize the proxy; this endpoint container uses about 1.6 MiB of idle memory | ADR 0016 |
| 8 | Cloud hosts in mainland China: a domain that is not filed with that cloud provider cannot be used for website service (a known platform restriction, not measured) | design/mesh.md section 5.3 |
| 9 | Standard Caddy's reverse proxy can forward HTTP/2 CONNECT tunnels (including TLS inside the tunnel), but cannot route them by Host; an expression matcher of "method is CONNECT and SNI matches" can separate them from websites on the same listening port | design/mesh.md section 5.4; ADR 0011 |
| 10 | Standard Caddy cannot forward HTTP/1.1 CONNECT tunnels: the request reaches the backend, but Caddy treats the response as an ordinary response and the tunnel cannot be established | design/mesh.md section 5.4; ADR 0011 |
