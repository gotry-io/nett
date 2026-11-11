# 0008. Phones join over standard WireGuard with dual paths

- Status: accepted (pairing runs in the signing tool, see 0024)
- Date: 2026-10-12

## Context

Phone operating systems only allow network access through the system VPN interface, and only one VPN can run at a time. Phones need to reach services at home (including heavy-traffic scenarios such as remote video viewing) and other nodes.

## Decision

- The phone side is compatible with **any standard WireGuard client**; nett exports a standard configuration and does not restrict the client; it also exports Surge, mihomo, and sing-box configurations, whose policy groups fall back automatically (ADR 0018);
- **Two paths** are configured, split by prefix:
  - **Direct to the smart gateway at home**: reaches services at home, and heavy traffic does not go through a relay;
  - **Mobile gateway** (a WireGuard interface on the Hub host or another `public` node): reaches other nodes and serves as the fallback when the direct path is unavailable; the path beyond the gateway is handled by the nett path layer;
- A device establishes peers only with the smart gateway and the mobile gateway. At any one time, each credential of a device belongs to exactly one mobile gateway, which advertises that credential's address to other nodes on its behalf;
- The exported configuration lists two DNS servers: the mobile gateway and the smart gateway; if either is reachable, mesh names resolve;
- **Devices and credentials are separate**: a device can have multiple credentials (for example one each for two different client programs), each revoked independently, with permissions granted per device;
- Pairing: the signing tool adds the device (signed with the recovery key) -> allocates the address and keys -> exports a standard WireGuard configuration (config file and QR code) (ADR 0024);
- When UDP is restricted, clients that support an HTTPS proxy can reach internal services through nett-relay's CONNECT proxy (see ADR 0011; on the entry node's 443, only HTTP/2 CONNECT is supported);
- The phone app is in M3 (ADR 0018); an "everything through the gateway" fallback configuration is exported at the same time, for manual switching when the direct path is blocked. The fallback configuration uses a **separate credential** (another key pair and address): the address of one credential is a direct peer on the smart gateway, and packets arriving through the gateway are dropped (mesh.md section 13).

## Rationale

- A standard protocol means any WireGuard-capable client can join, so no client has to be developed for each platform, and the user's choice is not restricted;
- Going direct to home keeps heavy traffic from being limited by relay bandwidth;
- The mobile gateway decouples the phone from the mesh details between nodes.

## Alternatives considered

- **Only through the mobile gateway**: all traffic detours through the gateway, so remote video viewing is limited by gateway bandwidth.
- **Phone joins a tailscale network directly**: needs a dedicated client, inconsistent with the self-built mesh.
- **Only a private protocol**: all clients must be self-built; when the network is healthy, WireGuard is faster and uses less battery.

## Consequences

- A standard client has a single fixed address per peer, so the phone does not select paths automatically, and when the direct path is blocked the user must manually switch to the fallback configuration; with a proxy client configuration, the policy group switches to the gateway automatically;
- The smart gateway at home must be reachable from outside: map the WireGuard port; if it also acts as a relay, map one more relay port (ADR 0011).
