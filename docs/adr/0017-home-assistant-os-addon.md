# 0017. Running as an add-on on Home Assistant OS

- Status: accepted
- Date: 2026-11-04

## Context

nett is designed as an open-source project and needs to cover the devices common among home users. Home Assistant OS (HAOS) runs on Raspberry Pi, mini PCs, official hardware or virtual machines, is usually powered on all the time, and sits on the home LAN, which makes it well suited as a mesh member and smart gateway.

But HAOS is a closed system: it has no package manager, users cannot install programs directly on the system, and all extensions run as **add-ons** (containers managed by HA's Supervisor). architecture.md section 3 requires nett-node to run directly on the system, which is impossible on HAOS.

Home Assistant running on ordinary Linux (the Container or Core installation methods) is not affected; its host is treated as an ordinary Linux node.

## Decision

- On HAOS, nett is provided as an **add-on**: the project maintains an HA add-on repository, with images covering the architectures HA supports (amd64, aarch64);
- The add-on requests the minimum privileges needed to run: host network, `NET_ADMIN`, `/dev/net/tun`. The add-on runs nett-node and the mesh process (the mesh uses the WireGuard built into the HAOS kernel), and also the transport adapter and nett-relay when needed, each supervised by the process manager inside the add-on (ADR 0013);
- Module scope:

| Module | On HAOS | Notes |
|---|---|---|
| mesh | ✅ | Can be a mesh member, a smart gateway or a mobile gateway |
| relay | ✅ | Needs port forwarding on the router |

- Upgrades: the add-on version follows nett releases; **HA is responsible for upgrades** (the user updates the add-on in HA), they do not go through the `release` partition, and the node does not replace its own files. When a new version is available, the console prompts "update in HA". HAOS does not verify image signatures before running, so the image signature is only for users to check manually;
- Downgrade protection is checked at startup: nett records the highest version it has run in the add-on's persistent directory, and if at startup it finds itself lower than that, it enters **restricted mode**: it still connects to the Hub and reports, but applies no new configuration until it is upgraded back or receives `release_override`. When the add-on is restored from an HA backup, this record rolls back together with the persistent directory and cannot be detected;
- The node's `status.install_method` is recorded as `haos_addon`, and the console shows only the available modules accordingly.

## Rationale

- Add-ons are the only supported extension mechanism on HAOS, and the existing mesh add-ons on HA run the same way;
- The kernel WireGuard, TUN, IP forwarding and NAT that the smart gateway needs are all usable with host network plus `NET_ADMIN`.

## Alternatives considered

- **Require users to enable debug mode on HAOS and install directly**: not supported by HA, and lost after a HAOS upgrade.
- **Request the highest privileges (disable protection mode, access Docker)**: would weaken HAOS's own security boundary, conflicts with "secure by default", and the mesh does not need it.
- **Support only HA's Container / Core installation methods**: would not cover HAOS, the most widely used.

## Consequences

- The release artifacts gain an HA add-on image and an add-on repository (ADR 0012);
- The statement in architecture.md that "nett-node must run directly on the system" gains HAOS as an exception.
