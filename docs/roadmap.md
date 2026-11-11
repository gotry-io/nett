# Roadmap

Every phase is **usable on its own**. Before each phase starts, write that phase's design document in [design/](design/README.md).

```
P0 Kickoff → M1 Mesh → M2 Mesh enhancements → M3 Clients
```

nett only does the mesh (ADR 0019). M1 is written to the point where work can start; M2 and M3 list directions only and are detailed before they start.

## P0: Kickoff

- [x] Vision, roadmap, architecture decision records
- [x] Design: API resource model (draft)
- [x] Design: authentication and authorization (draft)
- [x] Design: change sets and action catalog (draft)
- [x] Design: node ↔ Hub protocol (draft)
- [x] Design: mesh (session layer, path layer, transports, relay, path selection and switchover) (draft)
- [x] Design: overall design (architecture.md, draft)
- [x] Rust workspace skeleton (`crates/`) and CI (format, clippy, tests, cargo-deny, passing on GitHub Actions); the generated-files check is added with the first generated file; the web skeleton is set up together with the Hub in M1
- [x] Release signing keys: primary and backup generated, public keys in `keys/`; the primary private key is in CI's `release` environment, available only to `v*` version tags; version tags are protected (ADR 0020)
- [x] License files: dual-licensed MIT or Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`)
- [x] English README
- [x] Scope: nett only does the mesh (ADR 0019)

## M1: Mesh

Proceed in order: first pass the prototype gate, then replace the existing hand-made tunnels with local signing, then join the Hub, and finally roll out platforms and features (ADR 0022).

- **Prototype gate** (first step, Linux only, static configuration instead of the Hub): signed admission, UDP relay and switching to a new relay, switchover and time-slice rendezvous when both sides are `dial-only`, roaming correction, relay restart, MTU (large-packet TCP), TLS fallback, hole punching (probing on the WireGuard port, success rate), comparison with Tailscale for disconnect, flapping, fallback and recovery (ADR 0021), and the actual behavior of the chosen WireGuard implementation (index collision retry, handshake time after deleting and re-adding a peer); **performance benchmark**: compare throughput, latency and CPU use against native WireGuard and Tailscale on the same set of machines. Only after switchover time and performance meet the acceptance criteria below do the other platforms, CONNECT and the smart gateway follow. Scenarios and pass criteria are in [design/prototype.md](design/prototype.md). Passed; the full-speed comparison of direct connections over the public internet and the maximum forwarding throughput of a 1 vCPU relay are left to the acceptance below (prototype.md section 9)
- **Local signing** (second step, before joining the Hub): the signing tool `nett site` on the user's computer (the recovery key is the only trust anchor), keys generated on the node itself, release builds reading the local desired state file; access control, Edge address, container member; used to replace the existing hand-made WireGuard tunnels. See [design/local-signing.md](design/local-signing.md)
- **Foundations the mesh depends on**:
  - Hub and nett-node (native): enrollment, capability detection (WireGuard, TUN, packet filtering, whether reachable from outside); the node connects to the Hub over public HTTPS and does not depend on the mesh; the node hands the `trust` and `mesh` partitions to the mesh process; proceed as H1–H5 (design/hub.md section 9). H1 is implemented: `nett-hub`, nett-node (`nett node`), `nett site link`, `status`, `invite` (existing machines), `sudo nett install` on both platforms; H2 is implemented: new machines join through the Hub (`nett site add` with the same one-line enrollment command on all platforms, install script on the project website), the public address of `public` machines learned by the Hub, `sudo nett leave`; H3 is implemented: machines upgrade themselves from signed releases the Hub announces (design/release.md section 7). The lab scenario `hub` passes, and CI runs enrollment, an upgrade and leaving on Linux with systemd and on macOS; the Hub API has a generated OpenAPI document (`docs/api/openapi.json`); connecting the user's own machines is still to do
  - Site: maintain machines, permissions and access rules with `nett site` commands, with connections derived from access rules (design/site.md)
  - Authentication: recovery key and backup key, the site's API token, node keys and admission proofs, trust anchors; signing is done by the signing tool on the user's own computer (ADR 0024)
  - Installation: release packages and container images of `nett-hub`, run with Compose together with Caddy by default (including the section that hands traffic to nett-relay by SNI), one-time initialization and link to the site (design/hub.md sections 3.1 and 8); one-command enrollment for nodes (the enrollment command states the hash of the release package, which the Hub can cache); Homebrew (macOS); Home Assistant add-on repository; the release workflow (built in CI, with a separate signing job that signs automatically) and the release public keys as build parameters; automatic upgrade and rollback (project release signature, downgrade protection)
  - Availability: node and mesh process save their configuration locally; Hub backup (including the identity private key, encrypted and pulled by other nodes) and a rebuild runbook
- The mesh process runs independently of nett-node, and the TLS transport adapter runs separately with low privileges (ADR 0013); the core logic is platform-independent and the data plane has a backend per platform, leaving room for the M3 clients (ADR 0018)
- Session layer: kernel WireGuard on Linux; DSM and older kernels use the Rust userspace implementation running inside the mesh process; macOS joins natively (userspace WireGuard + utun; measure coexistence with proxy-style VPN apps before rollout), and container services that need the visitor's real IP use a container member instead; the Home Assistant OS add-on can act as a smart gateway; member admission verification (signed member table, prefixes, access rules)
- Path layer: LAN direct, public direct (IPv4, IPv6), via a single relay; hole punching for a direct connection when at least one side is behind a cone NAT or both sides have global IPv6 addresses (probing on the WireGuard port, switching only after the probe succeeds, without interrupting the current connection); continuous measurement, scoring, hysteresis, fast switchover (parameters aligned with Tailscale, ADR 0021); autonomous switching when a node is offline
- Transports: UDP; TCP/TLS 443 as a fallback (adapted by the transport adapter)
- nett-relay: forwards encrypted packets on a single port, accepts the TCP/TLS transport, answers probes, HTTPS CONNECT proxy (HTTP/2 only on entry nodes)
- LAN smart gateway (subnet router + source NAT by source class); Edge address (`edge` role; Edge is the user's own reverse proxy); advertised routes denied by default
- Node identity and the identity lookup interface (`whois`), node hostnames and aliases (`hostnames`), hostname resolution, access control
- Phones: mobile gateway + direct-to-home dual path; device and credential model; export of standard WireGuard configurations (configuration file and QR code), and configurations for Surge, mihomo and sing-box (two outbounds placed in an automatic-fallback policy group)
- OpenAPI (covering this phase's resources); `nett status`, `nett doctor`, `nett leave`, `nett whois` (command line in English only, architecture.md section 14.3); troubleshooting manual
- First platforms: Linux, Synology DSM, macOS (native member; container member optional), Home Assistant OS (add-on)
- Availability: at least two usable relays (on different hosts); `dial-only` nodes connect to at least two `public` nodes

**Acceptance**:

- Performance: on paths of 1 Gbps or less, direct throughput is at least 95% of native WireGuard on the same machine, with no measurable latency difference; on both direct and relayed paths, throughput is at least 95% of Tailscale; record the CPU use of each, and the maximum forwarding throughput of a 1 vCPU relay;
- All Edge origin traffic goes through the mesh (Edge's configuration is maintained by the user), and services that need the real IP can identify the visitor's address; a phone away from home can watch video directly from home and can also reach other nodes through the mobile gateway; after switching to the "all via gateway" backup configuration, services at home are still reachable; with a proxy client configuration, a failed direct connection to home automatically goes through the gateway;
- A Mac laptop recovers automatically after changing networks or waking from sleep and can initiate access to other members; the mesh works normally while the enhanced mode of a proxy-style VPN app is on (or works once configured as documented);
- Disconnect, flapping, fallback, recovery: compared with Tailscale in the same experiment under the same faults, outage time, recovery time, number of switches during flapping, throughput and latency are no worse (ADR 0021); **in-flight TCP connections are not interrupted**; the same holds when switching to a relay that has not carried the connection before and after a relay restarts; large-packet transfers are unaffected;
- Both sides behind cone NAT, or both with global IPv6 addresses and only a router firewall in between: hole punching succeeds in establishing a direct connection; with only one side behind a cone NAT, hole punching is attempted and the success rate is recorded; when hole punching fails, the current connection is unaffected;
- Stop any relay or node: paths that depend on it route around it automatically;
- Block UDP: automatically falls back to TCP/TLS 443;
- Stop the Hub: the mesh, automatic switching and phone access keep working;
- Stop nett-node: the mesh keeps measuring and switching, and DNS keeps answering;
- Replace the primary key with a release signed by the backup key: after installation, nodes reject packages signed by the old primary key; official builds refuse to install packages signed by the development key;
- The Hub sends a peer without admission material: all members refuse to configure it; after a member is removed, the Hub resends its original admission material: all members refuse; a member that enrolled long ago can be verified normally by newly joined members;
- Rebuild the Hub from backup on another host following the runbook, and all nodes reconnect automatically. The backup used is older than the nodes' state (changes were approved after the backup), and after restoration the user does not need to approve again (protocol.md section 6.4);
- Idle for 24 hours on a 1 vCPU / 1 GB machine: the memory of nett-node, mesh process, transport adapter and nett-relay each meets the resource budget; Hub ≤ 30–50 MB with memory not growing.

## M2: Mesh enhancements

- Multi-hop relaying and automatic path finding
- QUIC transport, obfuscation wrapping, UDP support for CONNECT
- Hole punching when both sides are behind symmetric NAT (port guessing)

**Acceptance** (direction): when a single-hop relay is deliberately degraded, switching automatically to multi-hop when a two-segment relay is clearly better, with the connection uninterrupted; automatically switching to QUIC on networks that allow only UDP 443; the obfuscated transport still connects in environments that drop packets by WireGuard signature; hole punching succeeds when both sides are behind symmetric NAT; resident processes still meet the resource budget.

## M3: Clients

- iOS and Android apps: full members, running userspace WireGuard and the path layer in a Network Extension (iOS) and VpnService (Android)
- Windows member: wireguard-nt kernel driver, with filtering through Windows Filtering Platform (WFP)
- Reuse the platform-independent mesh core from M1, adding only the per-platform data plane backends and the app shells (ADR 0018); iOS needs an Apple developer account (paid)

## Unscheduled

- **Web console and passkeys** (ADR 0024): a graphical interface on the same API, added after site state moves to the Hub (H5 in design/hub.md section 9). View first: nodes, members and devices, access rules, and for each pair of nodes the current path, transport, latency and loss; then passkey login and signing, and change sets (design/changes.md)

## To be discussed

- **Agent-to-agent access**: workload identity (verifying which agent or container the caller is) may become a mesh extension, reusing the Edge address mechanism to give individual programs dedicated addresses; an MCP gateway is not part of nett (ADR 0019).
