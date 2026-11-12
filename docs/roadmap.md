# Roadmap

Every phase is **usable on its own**. Before each phase starts, write that phase's design document in [design/](design/README.md).

```
P0 Kickoff → M1 Mesh → M2 Mesh enhancements → M3 Clients
```

nett only does the mesh (ADR 0019). M1 is divided into stages that run in order, each usable once done; M2 and M3 list directions only and are detailed before they start.

## Where things stand

| Phase | Stage | State |
|---|---|---|
| P0 | Kickoff | Done |
| M1 | 1. Prototype gate | Done |
| M1 | 2. Local signing | Done |
| M1 | 3. Userspace data plane and the macOS native member | Done |
| M1 | 4. Hub | Done; several signing devices are stage 9 |
| M1 | 5. Names and diagnostics | Done |
| M1 | 6. A real site on the Hub | **Current** |
| M1 | 7. Phones and restricted networks | To do |
| M1 | 8. Home gateways and more platforms | To do |
| M1 | 9. Several signing devices | To do |
| M2 | Mesh enhancements | Directions |
| M3 | Clients | Directions |

## P0: Kickoff

- [x] Vision, roadmap, architecture decision records
- [x] Designs (drafts): API resource model, authentication and authorization, change sets and action catalog, node ↔ Hub protocol, mesh, overall design (architecture.md)
- [x] Rust workspace skeleton (`crates/`) and CI (format, clippy, tests, cargo-deny, generated files)
- [x] Release signing keys: primary and backup, public keys in `keys/`; the primary private key is in CI's `release` environment, available only to protected `v*` version tags (ADR 0020)
- [x] Licenses (MIT or Apache-2.0), English README, scope: nett only does the mesh (ADR 0019)

## M1: Mesh

The stages follow ADR 0022: the prototype gate first, then replacing hand-made tunnels with local signing, then the Hub, then devices and platforms. The architecture underneath is the same in every stage: the mesh process runs independently of nett-node, the TLS transport adapter runs separately with low privileges (ADR 0013), and the core logic is platform-independent with one data plane backend per platform (ADR 0018). The acceptance at the end of M1 shows which criteria are met and which stage verifies the rest.

### 1. Prototype gate

Linux only, static configuration instead of the Hub. Scenarios, pass criteria and results are in [design/prototype.md](design/prototype.md).

- [x] Signed admission and admission counterexamples; UDP relay and switching to a new relay; switchover and time-slice rendezvous when both sides are `dial-only`; roaming correction; relay restart; MTU (large-packet TCP); TLS fallback
- [x] Hole punching: probing on the WireGuard port, success rate
- [x] Disconnect, flapping, fallback and recovery compared with Tailscale (ADR 0021)
- [x] Behavior of the chosen WireGuard implementation: index collision retry, handshake time after deleting and re-adding a peer
- [x] Performance against native WireGuard and Tailscale on paths of 1 Gbps and below (the public-internet and 1 vCPU relay measurements are in stage 6)

### 2. Local signing

[design/local-signing.md](design/local-signing.md).

- [x] The signing tool `nett site` on the user's computer, with the recovery key as the only trust anchor; keys generated on each node; release builds read the local desired state file
- [x] Access control, denied by default between members (ADR 0023); Edge address (`edge` role; Edge is the user's own reverse proxy, ADR 0015); container member (ADR 0016)
- [x] A locally signed mesh replaces hand-made WireGuard tunnels

### 3. Userspace data plane and the macOS native member

[design/userspace.md](design/userspace.md).

- [x] Userspace WireGuard (gotatun) in the mesh process with in-process filtering; a Linux TUN backend runs it in the lab and CI
- [x] macOS native member: utun, routes, binding to the physical interface, network changes, launchd service, Homebrew

### 4. Hub

[design/hub.md](design/hub.md) section 9, [design/site.md](design/site.md), [design/release.md](design/release.md).

- [x] H1 Distribution and status: `nett-hub`, nett-node (`nett node`), `nett site link`, `status`, `invite` for existing machines, `sudo nett install` on both platforms
- [x] H2 Enrollment and leaving: the same one-line enrollment command on all platforms, the install script on the project website, public addresses learned by the Hub, `sudo nett leave`
- [x] H3 Upgrade: machines upgrade themselves from signed releases the Hub announces, with downgrade protection and rollback (design/release.md section 7)
- [x] H4 Runtime coordination: relays (`nett site relay`) with UDP and TLS paths for every connection, LAN direct paths from the addresses machines report, `dial-only` pairs switching together through the Hub
- [x] H5, first half: the encrypted Hub backup every machine keeps, `nett-hub restore` and the rebuild procedure (design/hub.md section 8.2); the second half is stage 9
- [x] Site: machines, Edge, advertised routes (denied by default) and access rules maintained with `nett site` commands; connections derived from access rules
- [x] Authentication: recovery key and backup key, the site's API token, node keys and admission proofs, trust anchors; signing on the user's own computer (ADR 0024)
- [x] Installation: release workflow (built in CI, a separate signing job), release packages of `nett` and `nett-hub`, the install script, Homebrew (macOS), images for container members and the Hub built from `packaging/` with a Compose example, automatic upgrade and rollback
- [x] Availability: nett-node and the mesh process apply the locally saved configuration at start-up
- [x] OpenAPI document of the Hub API (`docs/api/openapi.json`)

### 5. Names and diagnostics

[design/names-and-diagnostics.md](design/names-and-diagnostics.md), [design/status.md](design/status.md).

- [x] Hostnames under `nett.internal` and hostname resolution on each platform
- [x] Node identity and the identity lookup interface (`nett whois`), `nett ping`, `nett doctor`, `nett status`; command line in English only (architecture.md section 14.3)

### 6. A real site on the Hub

A site that runs on local signing moves to the Hub, and the acceptance that does not depend on stages 7–9 is verified on real machines.

- [x] Run the Hub; connect the existing members (`nett site invite`) and enroll the rest
- [x] At least two usable relays on different hosts; `dial-only` nodes connect to at least two `public` nodes. On a host whose TCP 443 is held by a reverse proxy, the relay serves TLS on another TCP port until stage 7
- [ ] Measurements on real machines: full-speed direct paths across the public internet against native WireGuard and Tailscale, the maximum forwarding throughput of a 1 vCPU relay, a Mac laptop changing networks and waking from sleep, coexistence with a proxy-style VPN app's enhanced mode
- [x] Release key rotation: a release signed by the backup key (CI, `linux` job)
- [x] Troubleshooting manual, including how to run alongside proxy-style VPN apps ([troubleshooting.md](troubleshooting.md))

### 7. Phones and restricted networks

[design/mesh.md](design/mesh.md) sections 5.3, 5.4 and 13; ADR 0008, 0011.

- [ ] Device and credential model; mobile gateway and the direct-to-home dual path
- [ ] Export of standard WireGuard configurations (configuration file and QR code), and of Surge, mihomo and sing-box configurations (two outbounds in an automatic-fallback policy group)
- [ ] Hostname aliases (`hostnames`) and names for devices
- [ ] HTTPS CONNECT proxy in nett-relay (HTTP/2 only on entry nodes)
- [ ] On entry nodes the reverse proxy hands the TLS transport and CONNECT to nett-relay by domain name, and members verify that relay by CA certificates and domain name; the Hub's Compose example with Caddy includes this section
- [ ] TLS transport on macOS (the transport adapter)

### 8. Home gateways and more platforms

[design/mesh.md](design/mesh.md) section 10; ADR 0017.

- [ ] LAN smart gateway: subnet router with source NAT by source class
- [ ] Batched receive and send in the userspace data plane on Linux (`recvmmsg`, `sendmmsg`), before userspace members that are reachable from outside (design/userspace.md section 9)
- [ ] Synology DSM: the userspace data plane, packaging and boot tasks
- [ ] Home Assistant OS add-on, which can act as a smart gateway, and its add-on repository

### 9. Several signing devices

- [ ] H5, second half: the site state moves to the Hub, several signing devices each use their own key, trust anchor update (design/hub.md section 9, auth.md section 11.2)

### Acceptance

Checked items are met; the others name the stage that verifies them.

- [ ] Performance: on paths of 1 Gbps or less, direct throughput is at least 95% of native WireGuard on the same machine, with no measurable latency difference; on both direct and relayed paths, throughput is at least 95% of Tailscale; record the CPU use of each, and the maximum forwarding throughput of a 1 vCPU relay. *Met in the lab and between VPSes under rate limits (stage 1); full speed across the public internet and the 1 vCPU relay: stage 6*
- [ ] All Edge origin traffic goes through the mesh (Edge's configuration is maintained by the user), and services that need the real IP can identify the visitor's address. *Stage 6*
- [ ] A phone away from home can watch video directly from home and can also reach other nodes through the mobile gateway; after switching to the "all via gateway" backup configuration, services at home are still reachable; with a proxy client configuration, a failed direct connection to home automatically goes through the gateway. *Stage 7*
- [ ] A Mac laptop recovers automatically after changing networks or waking from sleep and can initiate access to other members; the mesh works normally while the enhanced mode of a proxy-style VPN app is on (or works once configured as documented). *Stage 6*
- [x] Disconnect, flapping, fallback, recovery: compared with Tailscale in the same experiment under the same faults, outage time, recovery time, number of switches during flapping, throughput and latency are no worse (ADR 0021); **in-flight TCP connections are not interrupted**; the same holds when switching to a relay that has not carried the connection before and after a relay restarts; large-packet transfers are unaffected. *Stage 1*
- [x] Both sides behind cone NAT, or both with global IPv6 addresses and only a router firewall in between: hole punching succeeds in establishing a direct connection; with only one side behind a cone NAT, hole punching is attempted and the success rate is recorded; when hole punching fails, the current connection is unaffected. *Stage 1*
- [ ] Stop any relay or node: paths that depend on it route around it automatically. *Met in the lab (stages 1 and 4); on real machines: stage 6*
- [ ] Block UDP: automatically falls back to TCP/TLS 443. *Met in the lab (stages 1 and 4); on real machines: stage 6; through entry nodes: stage 7*
- [ ] Stop the Hub: the mesh, automatic switching and phone access keep working. *Mesh and switching met in the lab (stage 4); phones: stage 7*
- [ ] Stop nett-node: the mesh keeps measuring and switching, and DNS keeps answering. *Stage 6*
- [x] Replace the primary key with a release signed by the backup key: after installation, nodes reject packages signed by the old primary key; official builds refuse to install packages signed by the development key. *Stage 6 (CI, with test keys)*
- [x] The Hub sends a peer without admission material: all members refuse to configure it; after a member is removed, the Hub resends its original admission material: all members refuse; a member that enrolled long ago can be verified normally by newly joined members. *Stages 1 and 4 (lab)*
- [ ] Rebuild the Hub from backup on another host following the runbook, and all nodes reconnect automatically. The backup used is older than the nodes' state (changes were approved after the backup), and after restoration the user does not need to approve again (protocol.md section 6.4). *Met in the lab (stage 4); on another host: stage 6*
- [ ] Idle for 24 hours on a 1 vCPU / 1 GB machine: the memory of nett-node, mesh process, transport adapter and nett-relay each meets the resource budget; Hub ≤ 30–50 MB with memory not growing. *Stage 6*

## M2: Mesh enhancements

- Multi-hop relaying and automatic path finding; relay choice from a line quality matrix, traffic limits per relay
- QUIC transport, obfuscation wrapping, UDP support for CONNECT
- Hole punching when both sides are behind symmetric NAT (port guessing)

**Acceptance** (direction): when a single-hop relay is deliberately degraded, switching automatically to multi-hop when a two-segment relay is clearly better, with the connection uninterrupted; automatically switching to QUIC on networks that allow only UDP 443; the obfuscated transport still connects in environments that drop packets by WireGuard signature; hole punching succeeds when both sides are behind symmetric NAT; resident processes still meet the resource budget.

## M3: Clients

- iOS and Android apps: full members, running userspace WireGuard and the path layer in a Network Extension (iOS) and VpnService (Android)
- Windows member: wireguard-nt kernel driver, with filtering through Windows Filtering Platform (WFP)
- Reuse the platform-independent mesh core from M1, adding only the per-platform data plane backends and the app shells (ADR 0018); iOS needs an Apple developer account (paid)

## Unscheduled

- **Web console and passkeys** (ADR 0024): a graphical interface on the same API, added after the site state moves to the Hub (M1 stage 9). View first: nodes, members and devices, access rules, and for each pair of nodes the current path, transport, latency and loss; then passkey login and signing, and change sets (design/changes.md)

## To be discussed

- **Agent-to-agent access**: workload identity (verifying which agent or container the caller is) may become a mesh extension, reusing the Edge address mechanism to give individual programs dedicated addresses; an MCP gateway is not part of nett (ADR 0019).
