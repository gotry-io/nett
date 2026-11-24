# 0032. The relay runs in the nett daemon; public TCP stays in nett-relay

- Status: accepted
- Date: 2026-11-24

## Context

ADR 0011 made nett-relay a process of its own, running with low privileges, because the nett daemon was to listen on no public address. Every public port a relay needs, UDP and TCP, went to that process, and with it the forwarding between members, the relay's obfuscated port (ADR 0030) and the TLS entry. A machine that relays runs two processes and two services, and a machine reached through a port other than its WireGuard port has to run nett-relay to have one.

What comparable products do:

- **Tailscale** (v1.104.7): its UDP relay, Peer Relays, runs inside tailscaled as an extension (`feature/relayserver/relayserver.go`), on a UDP port of its own set with `RelayServerPort`, and binds each pair's endpoint with a challenge both clients answer (`net/udprelay/server.go`). Its HTTPS relay, DERP, is a separate server (derper), not part of tailscaled;
- **NetBird** (v0.83.2): its relay is a separate server; the agent holds the WireGuard port and, with kernel WireGuard, a local proxy beside it (`client/iface/wgproxy`);
- Both run the WireGuard port, and Tailscale its UDP relay, in the privileged daemon.

## Decision

- **The relay runs in the nett daemon**: forwarding between members on the links its assignment lists, the relay port and the relay's obfuscated port, by the rules of mesh.md section 5, with the assignment taken from the mesh in the same process. It forwards only between admitted members (hard rule 4) and takes no management action;
- **Public TCP stays outside**: nett-relay keeps its name and becomes the relay's public TCP entry. It terminates TLS (mesh.md section 5.3), and the CONNECT proxy when that comes (section 5.4), and hands each connection's messages to the relay in the nett daemon over the loopback address. It runs with low privileges, holds no mesh private key and has no management privileges; it runs only on a machine whose relay serves TLS;
- **Hard rules 1 and 2** read: the relay in the nett daemon forwards only between admitted members on the links its assignment lists; the nett daemon listens publicly only on UDP (its WireGuard port and, where the machine offers them, its obfuscated port and its relay's ports), answering only authenticated packets; all public TCP listening is done by separate low-privilege processes (nett-relay, Edge).

## Rationale

- What a relay's UDP port receives before anything checks it is what the WireGuard port receives: handshakes routed by `mac1`, data by session index, probes by token, and nothing unauthenticated gets an answer; in the daemon it costs no more exposure than the WireGuard port, as in tailscaled;
- One process forwards for UDP, obfuscated UDP and loopback legs with one table, and a relay that stops with the daemon restarts with it;
- Public TCP is where a parser meets anyone on the internet before any check: a TLS handshake, and with CONNECT an HTTP/2 request that opens connections into the mesh for a device (mesh.md section 5.4). Kept out of the process that holds the mesh key and configures the interface and the firewall, a fault or a compromise there reaches a low-privilege process; Tailscale keeps DERP out of tailscaled the same way.

## Alternatives considered

- **Everything in the daemon, TLS too**: one process on every machine; the daemon would terminate public TLS, and later CONNECT, with root and the mesh key;
- **nett-relay as it is** (ADR 0011): the relay's UDP and obfuscated ports outside the daemon, which ties a machine's reachability over another port to running a second process.

## Consequences

- A machine that relays over UDP only runs one process and one service; a machine whose relay serves TLS runs nett-relay beside the daemon;
- The daemon's memory includes the relay's tables, within its budget (hard rule 14); the relay's bindings are kept across a restart of the daemon as they were across one of nett-relay;
- On upgrade, a machine whose relay serves no TLS loses its `nett-relay.service` (release.md section 8);
- ADR 0011's forwarding model, assignment and binding rules stay; its process split gives way to this one.
