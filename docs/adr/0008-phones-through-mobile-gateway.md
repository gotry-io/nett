# 0008. Phones join over standard WireGuard through a mobile gateway

- Status: accepted (pairing runs in the signing tool, see 0024)
- Date: 2026-10-12

## Context

Phone operating systems only allow network access through the system VPN interface, and only one VPN can run at a time. Phones need to reach services at home and the other nodes. A standard WireGuard client has one fixed endpoint per peer: it neither measures paths nor switches between them.

## Decision

- The phone side is compatible with **any standard WireGuard client**; nett exports a standard configuration and does not restrict the client; it also exports Surge, mihomo, and sing-box configurations (ADR 0018);
- **One entry, the mobile gateway** (a WireGuard interface on the Hub host or another `public` node): a device's only peer is a mobile gateway, which carries its traffic to the nodes and to the LAN prefixes advertised in the mesh; the path beyond the gateway is handled by the nett path layer;
- At any one time, each credential of a device belongs to exactly one mobile gateway, which advertises that credential's address to other nodes on its behalf;
- The exported configuration lists the mobile gateway as its DNS server, so mesh names resolve;
- **Devices and credentials are separate**: a device can have multiple credentials (for example one each for two different client programs), each revoked independently, with permissions granted per device;
- Pairing: the signing tool adds the device (signed with the recovery key) -> allocates the address and keys -> exports a standard WireGuard configuration (config file and QR code) (ADR 0024);
- When UDP is restricted, clients that support an HTTPS proxy can reach internal services through nett-relay's CONNECT proxy (see ADR 0011; on the entry node's 443, only HTTP/2 CONNECT is supported);
- **Direct paths come with the phone app** (M3, ADR 0018): there the phone is a full member and selects its paths itself, directly to home and to other nodes as the network allows.

## Rationale

- A standard protocol means any WireGuard-capable client can join, so no client has to be developed for each platform, and the user's choice is not restricted;
- A standard client cannot choose between entries by itself. A second entry, direct to home, would need a smart gateway reachable from outside, a backup configuration with a credential of its own, and a switch by hand whenever the direct path is blocked; one entry keeps the configuration the same for every client and asks nothing of the home network;
- The mobile gateway decouples the phone from the mesh details between nodes: beyond it the path layer measures and switches as between any two nodes.

## Alternatives considered

- **Two entries, direct to the smart gateway at home and the mobile gateway**: heavy traffic from home (such as video) does not detour through the gateway, and home stays reachable while the gateway is down. A standard client cannot pick between the two, so it adds the backup configuration and the manual switch, and the home router maps a port. The phone app brings the same benefits with paths chosen automatically.
- **Phone joins a tailscale network directly**: needs a dedicated client, inconsistent with the self-built mesh.
- **Only a private protocol**: all clients must be self-built; when the network is healthy, WireGuard is faster and uses less battery.

## Consequences

- All of a phone's traffic to the mesh goes through its mobile gateway: heavy traffic from home is limited by the gateway's bandwidth, and while the gateway is unreachable the phone reaches nothing in the mesh;
- Phones need nothing on the home network to be reachable from outside.
