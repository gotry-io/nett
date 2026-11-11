# 0019. nett does only the mesh

- Status: accepted
- Date: 2026-11-05

## Context

When the mesh, observability (replacing lightweight monitoring) and management (container deployment, ingress routing, AI operations) lived in one project, the three shared the Hub, nett-node and the change set and were coupled together:

- nett-node had to handle metrics collection, deployment, ingress configuration and the mesh handoff at the same time;
- The change set, protocol and API had to carry a lot of structure for deployment and AI (multi-step, rollback, auto-execution policy, deployment profiles, secrets);
- The first usable version had to wait for both observability and the mesh to be finished.

The mesh is the most central and riskiest capability. The user decided that nett does only the mesh, and observability and management are decoupled from it.

## Decision

- **nett does only the mesh**. Observability and management will be built later as independent projects, integrating through nett's API and identity lookup (`whois`); nett reserves no interfaces or data structures for them. Their early designs are kept in git history (commit cfd5ef1 and earlier).
- **Not in nett**:
  - Observability: the metrics module, asset inventory and service discovery (`services`), measurement of lines to targets outside the mesh, alerts and notification channels, heartbeat checks, external dead man's switches, metrics storage, real-time data and charts;
  - Management: the deploy module (Compose, stack, deployment profiles, deployment hooks, encrypted secret delivery and `stack_spec`, CI identity), the ingress module (routes, certificates, Edge configuration generation, DNS provider integration), read-only container logs, importing from existing tools; multi-step change sets, impact analysis, auto-execution policy, active verification and rollback; AI operations (the MCP adapter layer, the operations agent, `ai`-type API tokens) and the MCP gateway.
- **Components of nett**:
  - **nett-hub**: the control plane of the mesh and the Web console. It handles users and passkeys, recovery keys and backup keys, API tokens (only the `script` type), trust anchors, nodes and enrollment, node policy, devices and credentials, access rules, hostnames (node names and user-added aliases), links (`links`), `whois`, activity events, release package distribution, Hub backup, and change sets for mesh actions (single step, passkey signature when high risk);
  - **nett-node**: the control agent. It only handles enrollment, connecting to the Hub, keeping local state, upgrades, handing signed material to the mesh process, reporting inventory (platform, capabilities, addresses) and link status, executing mesh actions, and pulling the Hub's encrypted backups; it does not access Docker;
  - **The mesh process, the transport adapter, nett-relay, and the command-line `nett`**.
- **Origin traffic is a general mesh capability** (ADR 0015):
  - The Edge is the reverse proxy the user runs on the entry node; any implementation will do (Caddy, nginx, Traefik and so on). nett neither generates nor manages its configuration;
  - The `edge` role in the node policy (`node.set_roles`, requires a signature) declares that this machine runs an Edge and states how to identify the traffic the Edge sends: the address of the container the Edge runs in, or the system user when it runs natively. The Edge address is assigned accordingly;
  - The Edge address cannot reach any target by default; which hosts and ports it can reach is written by the user in the access rules (part of the signed access rule set, widening requires a signature);
  - The smart gateway translates by source class; container services on macOS that need the visitor's real IP use the container member (ADR 0016).
- **The Hub's own HTTPS**: the Hub install script generates the reverse proxy configuration for the Hub console's domain (Caddy by default, ADR 0009), and on the same port 443 hands the nett-relay domain over to nett-relay by SNI. This reverse proxy can also be the user's Edge, but nett generates only these two sections, for the Hub and nett-relay.
- **Agent-to-agent access is to be discussed**: workload identity may become an extension of the mesh (reusing the Edge address mechanism, assigning a dedicated address to a single program); the MCP gateway does not belong to nett. Not scheduled.
- **Phases**: P0 project start → M1 mesh → M2 mesh enhancements (multi-hop, QUIC and obfuscation, UDP support for CONNECT, hole punching when both ends are behind symmetric NAT) → M3 clients (iOS and Android apps and Windows).
- Role boundaries and resource budget: idle RSS of nett-node, the mesh process, the transport adapter and nett-relay is <= 5 MB each, and the Hub <= 30-50 MB.

## Rationale

- The mesh is the most central and riskiest capability; building it on its own yields a usable version earliest;
- With the structure reserved for deployment and AI removed, the Hub, nett-node, the protocol, the API and the change set all become much simpler;
- Observability and management will integrate later through the API and `whois`, and the mesh's signed identity can serve as their basis of identity;
- Origin traffic belongs to the mesh because "this request really comes from my reverse proxy" can only be guaranteed at the network layer, and cloud reverse proxies sending origin traffic to services at home is already a use case.

## Alternatives considered

- **Build observability, mesh and management together**: the first usable version would be delayed too long, and the mesh design would be pulled around by other features.
- **Keep them in nett as independent components**: nett would still have to maintain their interfaces and documentation, and the scope would be unclear.
- **Also put the origin traffic capability outside nett**: services cannot see the visitor's real IP and cannot tell visitors apart from the user's own devices.

## Consequences

- The Hub, nett-node, the protocol, the API and the change set contain only the structure the mesh needs: change sets have only a single step, API tokens have only the `script` type, and nett-node does not access Docker;
- ADR 0010 constrains only that "nett contains no AI logic";
- The user's existing monitoring, container management panels and reverse proxies keep being used until later projects replace them.
