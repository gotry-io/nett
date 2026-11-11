# 0018. End devices: macOS native member, proxy client configuration and client planning

- Status: accepted
- Date: 2026-11-05

## Context

Laptops and phones are the end devices personal users use most, and the places where gaps compared with Tailscale / Headscale appear most easily:

- An end device must be a **full member** to choose paths on its own, roam with the user, and be reached directly by other members. A full member runs the mesh process on the device, verifies admission material itself, and measures, selects paths and switches;
- When a Mac joins only as a container member (ADR 0016), it is guaranteed only that other members can reach the container services on the Mac; there is no guarantee for the Mac's own outbound access to the mesh, and laptops that do not run Docker cannot join;
- When a phone uses a standard WireGuard client (ADR 0008), a failed direct connection home requires manually switching to the backup configuration;
- Windows is also a common end device.

The user decided: the macOS native member and the proxy client configuration are completed in M1; the phone app and Windows must be built, scheduled for M3.

## Decision

- **macOS native member (M1, the default)**: the mesh process runs on the host as root under launchd, using the Rust userspace WireGuard (one implementation shared with DSM and old-kernel Linux) and a utun interface; filtering is done by the mesh process before forwarding (as on other userspace platforms), and resolution of mesh hostnames is written to `/etc/resolver/<suffix>`; the path layer and admission verification are shared with Linux. The Mac can access the mesh actively, and the laptop can roam with the user (usually `dial-only`);
- **The container member is kept**: container services on a Mac that need to recognize the visitor's real IP keep using the container member (ADR 0016). The two can coexist, as two node identities;
- **Coexistence with proxy-style VPN apps**: whether the macOS native member can coexist with the enhanced mode of a proxy app (which takes over routes and DNS) is measured before M1 rolls out to macOS. If they cannot coexist directly, the configuration for keeping the mesh prefixes out of the proxy is documented for the proxy app;
- **Proxy client configuration (M1)**: when a device credential is created, in addition to the standard WireGuard configuration, configurations for Surge, mihomo (Clash Meta core) and sing-box are exported: two WireGuard outbounds, direct home and via the gateway (using the primary credential and the backup credential respectively, mesh.md section 13), with traffic to the home prefixes placed in a policy group with automatic fallback, switching to the gateway when the direct path fails. It is used together with the proxy app and does not take up the phone's only VPN slot. The device is still not a full member: it cannot be reached actively by other members;
- **M3: clients**: iOS and Android apps and a Windows member, all full members. iOS runs the userspace WireGuard and path layer in a Network Extension, Android in a VpnService; Windows uses the wireguard-nt kernel driver, with filtering through the Windows firewall (WFP). iOS requires an Apple developer account (paid) and App Store review. A design document is written before M3 starts, including how mobile devices connect to the Hub and battery consumption;
- **Reserved for clients from M1**: the core mesh logic (admission verification, measurement, scoring, switching, hole punching coordination) is written as a platform-independent library that does not call netlink, nftables or any specific WireGuard implementation directly; the data plane (WireGuard configuration, interfaces, routes, filtering, DNS) is implemented by per-platform backends. M1 has a Linux kernel backend and a userspace backend (DSM, old kernels, macOS); M3 adds Windows, iOS and Android backends and the app shells, without rewriting the core.

## Rationale

- Laptops and phones are the end devices personal users use most;
- The macOS native member shares userspace WireGuard with DSM, and what is added is mainly utun, routes and DNS, so the work is manageable;
- The proxy client configuration only exports a few more formats, at very low cost, yet it solves automatic fallback on phones and does not compete with the proxy app for the VPN slot;
- The apps and Windows are a lot of work, and putting them in M1 would delay the first usable version too long; with a platform-independent core library from the start, nothing needs to be rewritten later.

## Alternatives considered

- **Keep only the container member**: laptops and Macs that do not run Docker cannot join, and there is no guarantee for the Mac's own outbound access to the mesh.
- **Build the phone app and Windows in M1 as well**: the first usable version would be delayed too long.
- **Phones use only the standard WireGuard configuration**: when the direct path is blocked, a manual switch is required.

## Consequences

- The choice of userspace WireGuard covers DSM, old-kernel Linux and macOS at the same time (design/userspace.md section 3);
- macOS gains a backend for utun, routes and DNS; laptop sleep, wake and frequent network changes are included in testing; the resource budget applies equally to the mesh process on macOS;
- The proxy client configuration formats must follow version changes of these clients, and the console states the versions that were tested;
- The mesh process of a smart gateway provides a health check port on the mesh address for policy group speed tests: open only to device addresses, it returns a fixed HTTP 204 response and closes upon receiving a connection, without parsing the request content;
- Until the phone app is done, the Web console still handles all viewing, management, approval and signing.
