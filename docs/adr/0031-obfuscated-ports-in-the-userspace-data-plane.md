# 0031. Obfuscated ports in the userspace data plane

- Status: accepted
- Date: 2026-11-24

## Context

ADR 0030 put obfuscated UDP on relays: a member reaches a relay's obfuscated port, and a machine is reached obfuscated only through a relay, its own or another. A public machine that should be reached obfuscated has to become a relay for every pair, and with it a candidate for their traffic; a machine with a small uplink cannot take that. A relay also forwards to a public member's WireGuard port, so the relay's leg to it carries plain WireGuard. Connections across a border to a machine that runs no relay stay plain, and so does the far leg of every relayed path to a public member.

For the nett daemon to open obfuscated datagrams on its own port, it has to hold the socket WireGuard reads, which kernel WireGuard keeps for itself: only the userspace data plane can do it. On Linux the userspace data plane has no Edge source address translation and no forwarding (userspace.md section 5), which the machines that would offer such a port use.

What comparable products do:

- **Mullvad** (mullvadvpn-app at `b94efb5f52`, 2026-11-23): obfuscation requires its userspace WireGuard, GotaTun, also on Linux where kernel WireGuard is otherwise the default ("GotaTun applies every obfuscation method itself, so obfuscation requires it", `talpid-wireguard/src/lib.rs`); LWO rewrites each datagram in place on GotaTun's own socket, with no local proxy (`tunnel-obfuscation/src/gotatun_transport/mod.rs`), on a port of its own (CHANGELOG 2026.1-beta1, 2026.3-beta1);
- **Tailscale** (v1.104.7): on Linux, userspace wireguard-go on a TUN (`wgengine/userspace.go`), with subnet routes' source address translation and stateful filtering in the kernel's netfilter (`wgengine/router/osrouter/router_linux.go`);
- **AmneziaWG** (amneziawg-go, a fork of wireguard-go) changes WireGuard's framing inside the implementation, so both ends must run it.

## Decision

- **A machine's obfuscated port**: a `public` machine can offer an obfuscated port (`nett site set <machine> --obfs`). Its nett daemon runs the userspace data plane and listens on that UDP port beside the WireGuard port; each datagram there is opened with the machine's obfuscation key (format version 1, ADR 0030) before WireGuard or the mesh sees it, and what goes back is wrapped and sent from the same port (design/obfuscation.md);
- **Linux keeps the kernel's netfilter**: on Linux the userspace data plane applies the filter, Edge source address translation, anti-spoofing and forwarding with the same nftables rules as the kernel data plane, on its TUN interface, as Tailscale does; in-process filtering stays for platforms without nftables (macOS, Synology DSM) (design/userspace.md);
- **The data plane follows the desired state**: a Linux machine with kernel WireGuard runs it unless its desired state offers an obfuscated port; the daemon restarts to change data plane, as an upgrade does;
- **Senders**: a machine on the userspace data plane wraps on its own WireGuard socket what it sends to a peer's obfuscated port; a machine on kernel WireGuard reaches it through a loopback port of the obfuscated transport (ADR 0030);
- **Paths**: the obfuscated path to a machine's own port ranks after LAN paths and before the plain direct path, in the place of the path through the relay on the peer's machine;
- **Relays**: keep their obfuscated port for relayed paths, and forward to a member that offers an obfuscated port through that port, so both legs of a relayed path are obfuscated; the relay and its ports run in the nett daemon (ADR 0032);
- **Hard rule 2** lets the nett daemon listen on the machine's obfuscated port beside its WireGuard port, on UDP as all its public ports (ADR 0032): every datagram there is opened with the site's key before anything else reads it, and only authenticated probes and handshakes get an answer.

## Rationale

- One mechanism reaches every public machine that needs it, whatever its uplink, without making it a relay for others, and closes the plain far leg of relayed paths;
- No process per machine is added, and the receiving machine hands datagrams to WireGuard without a loopback hop;
- What a datagram on the obfuscated port can reach before it is checked is as small as on the WireGuard port: the sealed form is authenticated, a data message is unmasked and then authenticated by WireGuard, anything else is dropped without an answer, and handshakes are limited per source as on the WireGuard port (userspace.md section 4.1);
- Reusing the kernel data plane's nftables rules keeps one implementation of the filter, the Edge and forwarding on Linux, already tested on the kernel data plane.

## Alternatives considered

- **Opening the machine's port beside kernel WireGuard**, in the daemon or in a separate process, and handing what it opens to kernel WireGuard over the loopback address: kernel WireGuard stays, but every obfuscated packet takes a hop through a forwarder on the receiving machine, as on a relay, instead of being opened where WireGuard reads it;
- **Masking in the kernel with tc-eBPF**: the sealed form needs ChaCha20-Poly1305, which does not fit an eBPF program; a format the kernel can mask would be weaker;
- **Changing WireGuard** (AmneziaWG): changes the session layer, which stays WireGuard (ADR 0007);
- **In-process source address translation and forwarding on Linux too**: a second implementation of what nftables does; it is needed only where there is no nftables (DSM, roadmap stage 8).

## Consequences

- A machine that offers an obfuscated port loses what kernel WireGuard gives across restarts: its connections pause for the seconds a restart or an upgrade takes (userspace.md section 6.3), and each packet costs more CPU, measured before the release;
- One public UDP port more per machine that offers one, opened in its firewall once;
- Synology DSM offers an obfuscated port once its userspace data plane forwards (roadmap stage 8);
- ADR 0030's format, keys, relay port and record of blocked endpoints stay; its path through the relay on the peer's machine gives way to the machine's own port.
