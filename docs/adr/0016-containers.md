# 0016. Containers: one image, one container

- Status: accepted
- Date: 2026-11-04

## Context

nett runs as three processes on a machine (the mesh process, nett-node and, on Linux, the transport adapter), each with only the privileges it needs (hard rule 1). Some machines can only run containers, and some services run in containers on hosts that also run nett. Measurements (architecture.md section 17) found:

- Docker's published ports on macOS drop the origin of the access: every client that reaches a container through a published port appears inside the container as the gateway address of the container network. On Linux, published ports keep the client's address;
- Kernel WireGuard runs correctly in a container in Docker's Linux virtual machine on macOS (OrbStack) while the host has the enhanced mode of a proxy-style VPN app turned on.

Mesh products ship one image that runs as one container; Tailscale's runs `tailscaled` with a small start-up program, takes its key from the environment, and is used as a sidecar whose network the service shares.

## Decision

- **One image, one container**: the official image `ghcr.io/gotry-io/nett` (linux/amd64 and linux/arm64) holds the statically linked `nett` and the CA certificates; its entry point `nett container` starts the mesh process, nett-node and the transport adapter itself, each with only its own privileges (design/container.md). Users configure it with environment variables (`NETT_TOKEN` joins the site through the Hub on the first start) and keep its state in one volume;
- **Upgrades like every machine**: the container upgrades itself through the Hub; the verified program goes into its state volume, and the program in the image checks it and runs it (ADR 0026). The container does not restart for an upgrade, so its network namespace stays;
- **A service joins the mesh as a sidecar**: it shares the nett container's network (`network_mode: service:nett`), is reached at the member's mesh address under the access rules, and sees the mesh source address of each connection, the Edge address included, on macOS as on Linux;
- **On a host that runs nett**, services in containers are reached through published ports of the host's own member, with no container member: on Linux they see the client's address; on macOS they see the gateway address, a limitation of Docker there.

## Rationale

- One container hides nett's process split from the user while keeping it: each process still runs with only its own privileges;
- The sidecar needs no fixed addresses, no advertised routes and no forwarding, and keeps the source of every connection, which is what services behind Edge need (ADR 0015);
- Upgrading by running the new program in the same container keeps the network namespace a sidecar shares, so an upgrade does not cut the service off;
- The image is pulled like any other, as users of other mesh products expect.

## Alternatives considered

- **Three containers, one per process, joined by a shared volume and `network_mode`**: the process split becomes the user's to wire up, and the image has to be built and upgraded by hand.
- **A container member as the gateway into a container network** (fixed addresses in the service's network, the service's address advertised, Edge traffic forwarded with its source rewritten): it works around one platform's published ports by changing the service's Compose file, and makes one host several nodes. The general smart gateway (mesh.md section 10) remains for LAN prefixes.
- **A userspace proxy mode without a network device** (Tailscale's `TS_USERSPACE`): services would reach the mesh through a SOCKS or HTTP proxy; nett has no such mode, and the sidecar needs none.

## Consequences

- The container needs `NET_ADMIN` and `NET_RAW`, and the TUN device when the host kernel has no WireGuard;
- A sidecar's service loses its network when the nett container itself is recreated (not when it upgrades), until the service is restarted too, as with other mesh products' sidecars;
- The release workflow publishes the image, multi-architecture, with each release.
