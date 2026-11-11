# 0015. Origin identity and default deny for LAN prefixes

- Status: accepted
- Date: 2026-11-04

## Context

A real deployment exposed several problems with ingress origin traffic (see architecture.md section 17):

- A service that needs the real client IP trusts the `X-Forwarded-For` sent by only one forwarder. But after the smart gateway applies source NAT to mesh traffic, all mesh traffic looks like the same source on the LAN, and the service cannot tell which requests were forwarded by the Edge;
- On macOS, Docker's published ports turn every source into the gateway address of the container network; when a container reaches the host via `host.docker.internal`, the source becomes `127.0.0.1`;
- Many services skip authentication for local or LAN sources. Source NAT lets mesh traffic inherit that trust; if access rules default to allow, then once a prefix is advertised, any member (including a compromised VPS) can reach the whole LAN with LAN identity;
- Other processes on the host where the Edge and the Hub run share the same mesh address with the Edge, and the access rules cannot tell them apart.

## Decision

**Principle: for a service that needs the real IP, the last hop must come from an address that only the Edge can use, and the service trusts only that address.**

1. **Edge address**: the Edge is the reverse proxy the user runs on the entry node; any implementation will do, and nett does not manage its configuration. The `edge` role in the node policy declares that this machine runs an Edge and how to identify the traffic the Edge sends (the address of the container the Edge runs in, or the system user when it runs natively); a node with this role is assigned one extra mesh address, written into the signed node policy (ADR 0014). The machine rewrites the source of the mesh traffic sent by the Edge to this address, based on the Edge's run user or the Edge container's address. WireGuard `AllowedIPs` guarantees that other members cannot forge this address; **other processes and containers on the machine cannot use it either**: in both directions, local output and container forwarding, the mesh process drops packets whose source address is the Edge address but which do not come from the Edge (an unprivileged process can also bind a non-local address, and a container can forge a source address, so address translation alone is not enough);
2. **The smart gateway translates by source class**: the smart gateway uses two addresses on the LAN. Traffic from the Edge address is translated to the "gateway address" and other mesh traffic to the "ordinary address". Services on the LAN trust only the gateway address;
3. **Containers on macOS**: they join the mesh as a container member (ADR 0016). A container member is the smart gateway of the container network its services live in; it admits only the Edge address and rewrites the source to its own fixed address in that network;
4. **The translated address must never be a loopback address**; when forwarding to a service on the host, the host's LAN address is used;
5. **Advertised LAN prefixes are denied by default**: they are open only to the user's devices, and other members need an access rule to be allowed (access is default deny, ADR 0023). The Edge address cannot reach any target by default; which hosts and ports it can reach is written by the user in the access rules, and widening requires a signature;
6. Edge configuration uses mesh addresses, not hostnames (the Edge often runs in a container, which cannot resolve the mesh suffix);
7. The Hub sits behind the reverse proxy on the Hub host (ADR 0009) and trusts only the `X-Forwarded-For` sent by this reverse proxy, for rate limiting and `allowed_sources`.

## Rationale

- WireGuard already guarantees that mesh source addresses cannot be forged; giving "traffic sent by the Edge" a separate address is enough to pass the real IP through the "trusted proxy address" mechanism that services widely support, with no change needed in the services;
- The same address also lets access rules separate the Edge from other processes on the same host: if the Edge is compromised, the impact is limited to the targets the access rules allow;
- LANs often contain devices and services that trust by prefix, so the default for an advertised prefix should be deny.

## Alternatives considered

- **No source NAT, route return packets back to the smart gateway**: hosts on the LAN see the real mesh address; but a static route must be configured on the router, and proxy-style VPN apps on LAN hosts will intercept the return packets.
- **The Edge uses mTLS or a shared-secret header for origin traffic**: does not depend on addresses, but every service would have to support it. Kept as a supplementary measure.
- **One forwarding container per service**: workable, but each service needs separate maintenance and address planning becomes scattered.

## Consequences

- Mesh address planning gains an "Edge address" class; the smart gateway needs two addresses on the LAN;
- A service on the LAN that needs the real IP must configure the smart gateway's gateway address (or the container member's address) as the "trusted proxy". This is a one-time deployment-level configuration;
- The Edge's configuration is maintained by the user, and origin targets are written as mesh addresses; the services the Edge address needs to reach are written by the user into the access rules;
- **Boundary**: when the Edge sends origin traffic to a service on the same host (via the local address or a container network on the same machine), the traffic does not pass through the mesh; nett does not constrain it, and it is determined by the user's own Edge configuration. The Edge's configuration does not pass through the Hub, so a compromised Hub cannot change it;
- Access rules are default deny (ADR 0023), and advertised prefixes are open only to the user's devices.
