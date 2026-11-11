# 0016. Container member on macOS

- Status: accepted
- Date: 2026-11-04

## Context

On macOS a machine joins the mesh as a native member by default (userspace WireGuard + utun, ADR 0018). But measurements (architecture.md section 17) found:

- Docker's published ports on macOS drop the origin of the access: every client that reaches a container through a published port appears inside the container as the gateway address of the container network. Only by bringing a mesh endpoint into the container network can the services in the containers recognize the Edge and visitor sources (ADR 0015);
- Running kernel WireGuard in a macOS Docker (OrbStack) container works correctly when the host has the enhanced mode of a proxy-style VPN app turned on, with UDP going out directly.

## Decision

- When a **container service on a Mac needs to recognize the visitor's real IP**, a separate **container member** is run: a Linux member running in Docker's Linux virtual machine, using kernel WireGuard, provided by nett as a container;
- It is an independent node identity, with only the mesh module enabled, and only serves other members' access to these container services; the native nett-node and native member on the host keep running, and the native member is responsible for the Mac's own outbound access to the mesh;
- The container member is the **smart gateway of its container network** (mesh.md section 10): it uses one fixed address in the network and advertises the addresses of specific services (one `/32` per service, with the services using fixed addresses in the network). It forwards to the services only traffic that comes from the Edge address and is allowed by access rules, rewriting the source to its own fixed address in this network (ADR 0015). A service that needs the real IP configures this address as the trusted proxy. Inbound traffic to the machine itself and to the advertised addresses is denied by default. The services keep their own network, and restarting or upgrading the container member does not affect them;
- Native services on the host are accessed through the native member; the container member does not proxy them (so the source does not become `127.0.0.1` via `host.docker.internal`).

## Rationale

- When the native member accesses a container through a published port, the source is lost; only the container member lets services in containers recognize the visitor;
- Coexistence with proxy-style VPN apps is backed by measurements;
- The service and the mesh process do not depend on each other: when the container member restarts, the service's connections (for example to other devices on the LAN) are unaffected;
- It is the same mechanism as the LAN smart gateway (advertised prefixes, forwarding, translation by source), so no separate mechanism is built for containers;
- It reuses the Linux member implementation (kernel WireGuard, nftables).

## Alternatives considered

- **Native member only**: container services on a Mac cannot get the visitor's real IP.
- **macOS does not join the mesh and is accessed only through the smart gateway at home**: when the services are all on the Mac, all traffic takes an extra hop through another device, and the problem of published ports losing the source remains.
- **A sidecar sharing the network namespace with the service** (`network_mode: service:<container member>`, common in community tutorials): it needs no forwarding and no fixed addresses, but after the sidecar container restarts Docker gives it a new network namespace, and the services sharing it lose network connectivity until they restart too; unacceptable for services such as trading.
- **Port forwarding** (mesh address ports mapped to service names): services need no fixed addresses, but a separate kind of signed forwarding table must be built for containers, and the mesh process must resolve service names periodically.

## Consequences

- Depends on the Docker runtime on the host (OrbStack or Docker Desktop); when Docker stops, this member goes offline too;
- One Mac may correspond to several nodes (the native member and each container member), and the console must display them as the same host;
- Services must use fixed addresses in the container network (`ipv4_address` in Compose); the container member enables forwarding in its own network namespace;
- The container member sits behind an extra layer of NAT from the Docker virtual machine; whether hole punching is feasible is decided automatically by NAT type detection (mesh.md section 6.1).
