# 0013. One nett daemon per machine

- Status: accepted
- Date: 2026-11-23

## Context

On every machine nett does three kinds of work: the mesh (WireGuard configuration, the path layer, DNS answering, access rules and address translation, the local status interface), the connection to the Hub (the desired state, status reports, upgrades), and, where UDP is blocked, the TLS transport. A machine reachable from outside may also run a relay.

The mesh must keep working while the Hub is away (architecture.md section 2): established paths stay, failed ones are switched, and DNS answers. It must not depend on the connection to the Hub succeeding, nor stop when that connection misbehaves.

How comparable products split this work:

- **Tailscale** (v1.104.7) runs one daemon per machine, `tailscaled`, as root: the control client, userspace WireGuard, DNS and its peer relay run in that one process (`cmd/tailscaled/tailscaled.go`, `feature/relayserver`). Its Linux unit has no `User=` (`cmd/tailscaled/tailscaled.service`); on macOS the open-source build installs the one launchd daemon `com.tailscale.tailscaled` (`cmd/tailscaled/install_darwin.go`). Its DERP server, which serves TLS on 443 to anyone, is a separate program, `derper` (`cmd/derper`).
- **NetBird** (v0.83.2) installs one service, `netbird` (`client/cmd/service_installer.go`), whose daemon connects to management and runs the engine (`client/server/server.go`); its relay is a separate server.

## Decision

1. **One daemon per machine**: `nett daemon --dir <directory>` runs the mesh, the TLS transport and, once the directory holds a Hub configuration, nett-node, which connects the machine to its Hub, in one process. The directory holds the keys, the desired state, the Hub configuration and the trust store. It is the one service nett installs on a machine: `nett.service` on Linux (a variant for Synology DSM's systemd 219, started by a boot task), the launchd service `io.gotry.nett` on macOS, and the child of `nett container` in nett's image (ADR 0016).
2. **nett-node runs on a thread of its own** with its own single-threaded runtime, and calls the mesh in the same process directly: it writes the desired state file and has the mesh read it again, reads the mesh's status for its reports, and passes path switch messages over a socket pair (design/status.md section 4.2). The local socket serves the command line and the relay only. The mesh starts first and applies the locally saved desired state before nett-node connects to the Hub (hard rule 8).
3. **Faults stay where they start**: a panic in nett-node ends its thread only; the mesh keeps working as while the Hub is away, and nett-node starts again after 5 seconds. When the process itself ends, the service manager starts it again; on Linux the kernel keeps the WireGuard interface and its sessions meanwhile, while on macOS and the userspace data plane the TUN interface goes with the process (design/userspace.md section 6.3).
4. **Root with bounded capabilities**: on Linux the service runs as root with only `CAP_NET_ADMIN`, `CAP_NET_RAW` and `CAP_NET_BIND_SERVICE`, and a read-only file system except its directory, the program it upgrades and nett's units. It runs no shell; its only external programs are systemctl or launchctl (hard rule 9).
5. **nett-relay stays a service of its own**: it is the only nett process that listens on public addresses (the relay's UDP port and TLS on 443), it runs as a user systemd allocates while it runs, holds no mesh private key, and fetches its assignment from the daemon over the helper socket, which answers only the relay's unit (design/status.md section 3.1).
6. **Upgrades restart the one service**: nett-node installs the new program, records the upgrade marker, and the service exits; the service manager starts the new program, which counts its starts before the mesh comes up and goes back to the previous program when it exits three times before it settles or its mesh does not answer within 60 seconds (design/release.md section 7).
7. The idle budget is per process: the daemon holds at most 8 MB of private memory and nett-relay at most 5 MB, all of nett's processes on one machine together at most 10 MB (hard rule 14).

## Rationale

- **The split did not separate privileges where it mattered**: nett-node was root and read what the Hub sent; on macOS, Synology DSM and in the container the mesh process was root or held the same capabilities. Only on Linux did it keep the mesh, which reads authenticated probes from anyone, off root. Keeping it costs a system user and its group, a group-readable identity directory, `CAP_DAC_OVERRIDE` for nett-node to reach the mesh's socket, a coordination protocol over that socket, upgrades that restart and wait for other services, and three or four services per machine, two of them background items on a Mac. Running as root with three capabilities and a read-only system keeps most of what the dedicated user gave the mesh.
- **What the user sees is one thing**: one service to start, stop and read logs from, as with Tailscale and NetBird.
- **The relay is different**: it terminates TLS from anyone on 443 and holds what it needs to forward and nothing more; keeping it out of the root process costs one service, only on machines that run a relay, as Tailscale keeps `derper` out of `tailscaled`.
- **Fault isolation where it is cheap**: a thread of its own and a restart on panic keep a bug in nett-node from stopping the mesh, which was the reason for the split; memory exhaustion and aborts end both, and the service manager restarts the process.

## Alternatives considered

- **Separate services for the mesh, nett-node and the transport adapter** (nett before 0.9): isolates memory exhaustion and aborts in nett-node and keeps the mesh off root on Linux, at the costs above, which grew with every platform that could not run them apart (macOS, DSM, the container).
- **nett-relay in the daemon too**, as Tailscale's peer relay runs in `tailscaled`: one service fewer on relays, but the process that listens on public ports would hold the mesh private key and root.
- **nett-node in a separate process with fewer privileges and a small root helper for upgrades**: narrower than Tailscale, but two processes and an interface between them again, for a component that already accepts only what the Hub, authenticated by its pinned key, sends.

## Consequences

- A machine runs one nett service, plus nett-relay where it relays. nett places no system user, no account declaration and no transport unit on a machine (design/release.md section 8);
- The local socket no longer takes a coordination connection; it answers the command line, and `reload` only for root;
- Upgrades restart the daemon, and the mesh with it: on Linux connections continue through the kernel's WireGuard, on macOS they pause until the process is back;
- The upgrade from 0.8 to 0.9 is a reinstall: `sudo nett uninstall` with 0.8, then `sudo nett install` with 0.9, which keeps the identity.
