# 0018. End devices: macOS native member and client planning

- Status: accepted
- Date: 2026-11-05

## Context

Laptops and phones are the end devices personal users use most, and the places where gaps compared with Tailscale / Headscale appear most easily:

- An end device must be a **full member** to choose paths on its own, roam with the user, and be reached directly by other members. A full member runs the mesh on the device, verifies admission material itself, and measures, selects paths and switches;
- A container on a Mac that runs nett's image (ADR 0016) is a member of its own for the services that share its network; it gives the Mac itself no access to the mesh, and laptops that do not run Docker could not join that way;
- When a phone uses a standard WireGuard client (ADR 0008), it reaches the mesh through the mobile gateway only, and WireGuard takes the phone's only VPN slot, so a proxy app cannot run beside it;
- Windows is also a common end device.

The user decided: the macOS native member is completed in M1; the phone app and Windows must be built, scheduled for M3.

## Decision

- **macOS native member (M1, the default)**: the nett daemon runs on the host as root under launchd (ADR 0013), and its mesh uses the Rust userspace WireGuard (one implementation shared with DSM and old-kernel Linux) and a utun interface; filtering is done by the mesh before forwarding (as on other userspace platforms), and resolution of mesh hostnames is written to `/etc/resolver/<suffix>`; the path layer and admission verification are shared with Linux. The Mac can access the mesh actively, and the laptop can roam with the user (usually `dial-only`);
- **Containers beside it**: container services on a Mac that need to recognize the visitor's real IP share the network of nett's container (ADR 0016). The two coexist, as two node identities;
- **Coexistence with proxy-style VPN apps**: whether the macOS native member can coexist with the enhanced mode of a proxy app (which takes over routes and DNS) is measured before M1 rolls out to macOS. If they cannot coexist directly, the configuration for keeping the mesh prefixes out of the proxy is documented for the proxy app;
- **Devices get the standard WireGuard configuration only** (ADR 0008): a client that takes WireGuard settings in a format of its own, such as a proxy app's WireGuard outbound, is set up from the same fields, which lets a phone use the mesh beside its proxy app;
- **M3: clients**: iOS and Android apps and a Windows member, all full members, which select their paths themselves, directly to home and to other nodes. iOS runs the userspace WireGuard and path layer in a Network Extension, Android in a VpnService; Windows uses the wireguard-nt kernel driver, with filtering through the Windows firewall (WFP). iOS requires an Apple developer account (paid) and App Store review. A design document is written before M3 starts, including how mobile devices connect to the Hub and battery consumption;
- **Reserved for clients from M1**: the core mesh logic (admission verification, measurement, scoring, switching, hole punching coordination) is written as a platform-independent library that does not call netlink, nftables or any specific WireGuard implementation directly; the data plane (WireGuard configuration, interfaces, routes, filtering, DNS) is implemented by per-platform backends. M1 has a Linux kernel backend and a userspace backend (DSM, old kernels, macOS); M3 adds Windows, iOS and Android backends and the app shells, without rewriting the core.

## Rationale

- Laptops and phones are the end devices personal users use most;
- The macOS native member shares userspace WireGuard with DSM, and what is added is mainly utun, routes and DNS, so the work is manageable;
- The standard WireGuard configuration carries everything any client needs (keys, addresses, the gateway's endpoint and `AllowedIPs`), and is the one format every WireGuard implementation reads; an open-source project names no particular client;
- The apps and Windows are a lot of work, and putting them in M1 would delay the first usable version too long; with a platform-independent core library from the start, nothing needs to be rewritten later.

## Alternatives considered

- **Only containers on a Mac**: laptops and Macs that do not run Docker cannot join, and the Mac itself has no access to the mesh.
- **Build the phone app and Windows in M1 as well**: the first usable version would be delayed too long.
- **Export the formats of popular proxy clients** (Surge, mihomo, sing-box): ties the project to particular apps and to the syntax of their current versions, for settings the standard configuration already holds.

## Consequences

- The choice of userspace WireGuard covers DSM, old-kernel Linux and macOS at the same time (design/userspace.md section 3);
- macOS gains a backend for utun, routes and DNS; laptop sleep, wake and frequent network changes are included in testing; the resource budget applies equally to the nett daemon on macOS;
- Until the phone app is done, the Web console still handles all viewing, management, approval and signing.
