# Vision

## In one sentence

nett is open-source, self-hosted mesh infrastructure that connects your scattered machines into one network: it picks the best path automatically, switches automatically when a path degrades or a node goes offline, and keeps in-flight connections alive.

## Who it is for

Individuals or small teams with a small number of scattered machines: a few VPSes from different vendors and regions, plus a NAS, Mac or mini PC at home. These machines sit in different network environments, some behind NAT, some across borders, and their specs are generally modest (typically 1 vCPU / 1 GB).

nett is designed as an open-source project: anyone can deploy it on their own machines; each deployment serves a single user.

## Problems to solve

| Problem | Typical situation today |
|---|---|
| **Machines are not connected to each other** | Services at home are exposed through port forwarding plus a reverse proxy on a VPS, and origin traffic is often plaintext; machines behind NAT cannot be reached from outside |
| **Links are intermittent** | Cross-border and cross-carrier links often jitter or drop, and UDP may be throttled or identified; a hand-written tunnel that breaks has to be fixed by hand |
| **Reaching home from a phone is awkward** | Connecting directly to home is fastest, but on some networks it fails; switching to another path means changing configuration manually |
| **Origin traffic cannot tell who is who** | Services cannot see the visitor's real IP, nor tell visitors from the user's own devices |
| **Small machines are short on resources** | Always-on tools already take a considerable amount of memory |

## What it consists of

- **Hub**: the center, that is, the mesh control plane. It handles node enrollment and signed admission, devices and credentials, access rules, hostnames and the external API; it is not on the data path, and the mesh keeps working while it is offline;
- **nett-node**: one per machine, running directly on the system (not in a container). As the control agent it handles enrollment, connects to the Hub, upgrades, hands the signed mesh configuration to the mesh process, and reports status;
- **nett-relay**: a low-privilege process on nodes that are reachable from outside, responsible for relay forwarding and the public transport entry point;
- **Mesh process**: runs on nodes that join the mesh and is responsible for WireGuard, path selection and switchover, DNS and access rules. It is separate from nett-node, so the mesh keeps working while the node upgrades, crashes or restarts; when UDP is unavailable, a separate low-privilege **transport adapter** converts traffic to TLS;
- **Command line `nett`**: the operating interface. On the user's computer it defines and signs the whole network and shows all machines; on each machine it handles installation and troubleshooting. What gets signed is computed and displayed by the command line locally, not through the Hub (ADR 0024). A web console is added later as a graphical interface on the same API. The mobile app arrives in M3; until then, phones join the mesh through a standard WireGuard client or common proxy clients.

The reverse proxy at the entry node (Edge) is run by the user and can be any implementation (Caddy, nginx, Traefik, and so on); nett neither generates nor manages its configuration. It only makes sure the proxy's origin traffic is encrypted through the mesh and lets services that need the real IP recognize it (ADR 0015, 0019).

## Feature scope

| Area | What is included |
|---|---|
| **Path selection and switchover** | LAN direct, public direct, via relay, multi-hop relaying, hole punching; continuous measurement, automatic path selection and switching, with in-flight connections kept alive |
| **Transports** | UDP, TLS, QUIC and obfuscated transports; automatic fallback to other transports when UDP is blocked |
| **Relay** | Nodes reachable from outside run nett-relay, which only forwards encrypted packets and does not decrypt mesh traffic |
| **LAN access** | LAN smart gateway: other hosts at home join the mesh through the smart gateway without installing nett |
| **Phone access** | Dual path: direct to home, with the mobile gateway as a fallback; export of standard WireGuard configurations and configurations for common proxy clients (automatic fallback when the direct path fails) |
| **Hostnames and access control** | Node hostnames and aliases; identity lookup (`whois`); access rules: default deny, allow by rule |
| **Authentication and authorization** | The user signs authorizations on their own computer, with passkeys later; API tokens; raising privileges and mesh admission must both be signed by the user |
| **Origin identity** | The user's reverse proxy (Edge) sends origin traffic encrypted through the mesh; traffic from Edge uses a dedicated mesh address that other processes on the machine cannot spoof; services that need the real IP trust only requests forwarded by Edge, so they see the visitor's real IP and can tell visitors from the user's own devices |

## Requirement priorities

**Must have**: the mesh (including automatic path selection and switchover, relay, multi-hop, hole punching, TLS, QUIC and obfuscated transports, LAN smart gateway, phone access, hostnames and access control); encrypted origin traffic and the visitor's real IP; authentication and signed authorization (including signed admission); a complete API and command line, with signing done on the user's own computer and the signed content displayed locally; iOS and Android apps and Windows members (M3).

**Nice to have**: signing with hardware keys; web console and passkeys (ADR 0024).

**To be discussed**: agent-to-agent access. Workload identity may become a mesh extension (reusing the Edge address mechanism to give individual programs dedicated addresses); an MCP gateway is not part of nett. Not scheduled (ADR 0019).

## What counts as "usable"

When M1 is done: hand-written tunnels, home broadband port forwarding and existing mesh tools can be retired; all reverse proxy origin traffic goes through the mesh, and services that need the real IP can identify the visitor's address; a phone away from home can connect directly to home and can also reach other nodes through the mobile gateway; nett uses fewer resources than the tools it replaces.

## API first

- All state is exposed through a resource-oriented API, and whatever the interface can do, the API can do;
- Medium- and high-risk changes all go through the same change path, so there is no difference between operating from the command line and through the API; high-risk changes must be approved by the user's signature.

## Design constraints

| Constraint | Meaning |
|---|---|
| **Very low resource use** | Each resident process on a node (node, mesh process, transport adapter, relay) uses ≤ 5 MB when idle; the Hub uses ≤ 30–50 MB when running steadily |
| **High performance** | Mesh encryption uses WireGuard, done by the kernel on Linux; bulk traffic prefers the direct path and avoids relays |
| **Adapts to complex networks** | LAN, public internet, mainland China, cross-border; home broadband without inbound 80/443, NAT-based VPSes, links where UDP is throttled or identified |
| **High availability** | Automatic switching when a path jitters, breaks or a node goes offline, with connections kept alive; no single point; the mesh is unaffected when the Hub is offline |
| **Multi-platform** | Linux, Synology DSM, macOS (native mesh membership; container services that need the visitor's real IP use a container member instead), Home Assistant OS (runs as an add-on); phones join through a standard WireGuard client or proxy client; iOS, Android apps and Windows in M3. See architecture.md section 14 for the support matrix |
| **General purpose** | Open-source project: does not depend on a specific cloud vendor, region or network environment; differences between environments are handled by capability detection and measurement, not hard-coded |
| **Bilingual** | The web interface, API error messages and user-facing documentation are provided in Chinese and English; the command line is English only |
| **Single user** | Each deployment serves a single user; no multi-tenancy |
| **Secure by default** | Control and traffic are separated and the Hub is not on the data path; high-privilege components are not exposed externally; raising privileges requires a signature, and mesh members are admitted by signature too; a compromised Hub cannot exceed its authority: signing happens on the user's own computer, and the signed content is computed and displayed locally, not through the Hub (design/auth.md section 2) |

## Non-goals

| Not done | Reason |
|---|---|
| Kubernetes | nett neither replaces nor integrates with K8s. Users who run k3s on some machines can still use nett to connect those machines |
| Multi-tenancy | Each deployment serves a single user |
| One machine joining several networks at once, one-click network switching | One network can hold all of a user's machines, and grouping is done with access rules (default deny between members, ADR 0023). Changing networks is a deliberate operation: run `nett leave` as root on the machine, then join the new network (design/auth.md section 8.3); if trust anchors could be switched freely, a compromised machine could be pulled into another network |
| Remote shell, arbitrary command execution | Once an agent is hit by prompt injection, a shell means arbitrary command execution that spreads along the mesh and is hard to audit and revoke afterwards. nett only provides the pipe: when needed, use SSH over the mesh, with access rules limiting who can reach which machine |
| Observability and management | Monitoring, alerting, container deployment, ingress routing and AI operations will be separate projects later, integrating through nett's API and identity lookup (`whois`); nett reserves no interfaces for them (ADR 0019) |
| Telemetry | No usage data is collected or reported by default |
| Running AI logic | nett contains no AI logic; the node stays small and deterministic (ADR 0010) |
| Billing and usage accounting | nett is infrastructure: it provides only mechanisms such as capacity limits, measurement and automatic path selection. How machines are billed and how upper-layer workloads use bandwidth is up to the user, and nett makes no judgment about it |
