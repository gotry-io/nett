# Obfuscated UDP transport

- Status: draft
- Phase: M2, first item (roadmap); decisions in ADR 0030 (format, keys, relays) and ADR 0031 (a machine's obfuscated port)

## 1. Goals

A censor that identifies WireGuard drops UDP sent from the identified address and port into its network, in one direction, while the other ports of the same address pass (ADR 0011). The obfuscated UDP transport carries WireGuard across such a network:

- **Nothing fixed on the wire**: the bytes look random, as the evidence favors for UDP (ADR 0030); no byte at a fixed position keeps the same value, handshakes have no fixed length, and nothing unauthenticated gets an answer, so a rule that reads the first bytes and the length of packets, as the classifiers that block WireGuard do, has nothing to match;
- **WireGuard unchanged**: the transport wraps WireGuard's packets on the way and unwraps them before WireGuard sees them; the session, keys and roaming stay WireGuard's, and standard WireGuard exports for devices are not affected;
- **UDP throughout**: no TCP under the tunnel's TCP;
- **The format is public, the keys are not**: each site derives its own keys and draws its own padding range, so knowing the format does not give a rule that matches a site's traffic (Kerckhoffs). The format carries a version, so a later one can replace it.

## 2. Where it sits

```
direct:   A's WireGuard ─► A's sender ─► obfuscated UDP ─► B's obfuscated port (B's nett daemon) ─► B's WireGuard
relayed:  A's WireGuard ─► A's sender ─► obfuscated UDP ─► R's relay (R's nett daemon) ─► obfuscated UDP ─► B's obfuscated port
```

- **A machine's obfuscated port** (ADR 0031): a `public` machine that offers one runs the userspace data plane (userspace.md section 4.2), and its nett daemon listens on that UDP port beside the WireGuard port. Each datagram there is opened with the machine's key before WireGuard or the mesh sees it; what does not open is dropped without an answer. What goes back to a peer that came through the port is wrapped and sent from it (userspace.md section 4.1). The port is separate from the WireGuard port, which carries plain WireGuard and can be identified;
- **Senders**: a machine on the userspace data plane wraps what it sends to a peer's obfuscated port on its own WireGuard socket, and opens what comes back from there with that peer's key (userspace.md section 4.1). A machine on kernel WireGuard reaches the port through the obfuscated transport, which has the shape of the TLS transport (mesh.md section 5.3) with UDP in place of TLS: for each obfuscated port it reaches, a UDP port on the loopback address serves as the WireGuard endpoint of that candidate, and one UDP socket is connected to the obfuscated port. Each packet from the loopback port is wrapped and sent on the connected socket; each packet received is unwrapped and dispatched as on the TLS transport: relay responses go back to the mesh's port that sent the probe, the rest to the WireGuard port. A packet that does not unwrap is dropped. The socket is connected, so the system delivers to it only packets from the address it reaches;
- **Relays**: the relay, in the nett daemon (ADR 0032), listens on an obfuscated port of its own, separate from the relay port, since the relay port carries plain WireGuard and can be identified the same way as the WireGuard port. It unwraps what arrives, routes it as it routes the relay port's packets (by `mac1` and session index, mesh.md section 5.1), and wraps what it sends to a member bound on the obfuscated port. Each leg is plain or obfuscated on its own: a `public` member that offers an obfuscated port is reached through that port from the relay's obfuscated port, with the member's key, and what comes from that port is opened with it; one that offers none, or reached by a relay that offers no obfuscated port, gets plain packets on its WireGuard port, since sending from the relay port would show the port a censor can identify; the WireGuard on the relay's own machine gets plain packets on loopback;
- **Paths**: a connection to a machine that offers an obfuscated port goes there directly; relays carry obfuscated UDP for the pairs that need a relay. A hole-punched path between two `dial-only` members stays plain: obfuscating it would need both ends to open datagrams on the socket that punched it, and is not part of this design.

## 3. Wire format, version 1

Every datagram starts with a 12-byte random salt, which appears once and never repeats a value on purpose. Two kinds of payload follow:

| Inner message | On the wire | Cost |
|---|---|---|
| WireGuard data (type 4) longer than a keepalive | `salt ‖ (first 16 bytes XOR mask) ‖ the rest unchanged`; the mask is the first 16 bytes of BLAKE2s-256 keyed with the data key over the salt | 12 bytes, one BLAKE2s per packet; WireGuard's payload is already ciphertext and is not touched |
| Everything else: WireGuard handshake initiation, response and cookie reply (types 1-3), keepalives (data messages of 32 bytes, sent every 25 seconds by `dial-only` members), relay probes and responses, through probes and replies (`0x90`-`0x93`) | `salt ‖ ChaCha20-Poly1305(control key, nonce = salt)` over `version (1) ‖ time in milliseconds (8) ‖ length (2) ‖ message ‖ padding` | 12 + 11 + 16 bytes plus the padding |

- **Telling them apart**: the receiver unmasks the first 16 bytes; a WireGuard data message has type 4 and three zero bytes there, which random data gives once in 2^32. Otherwise it opens the sealed form; a packet that fits neither is dropped without an answer;
- **Padding**: the sealed form adds a random number of bytes in the site's padding range (section 4), so handshakes, keepalives and probes have no fixed length, and a keepalive does not show as a packet of one length every 25 seconds. Other data messages are not padded: their lengths already follow the traffic, and padding them would cost bandwidth;
- **Replay**: a sealed message older or newer than 30 seconds by the receiver's clock is dropped, and so is a salt the receiver saw in the last 60 seconds (a bounded set). A replayed handshake therefore never reaches WireGuard, which removes the answer a prober can draw from WireGuard under load (its cookie reply);
- **Version**: the version byte is inside the sealed form, and the keys are derived with the version in their label (section 4). A later version uses new labels; during a change a receiver tries the formats it knows, at most two;
- **Size**: the largest outer packet grows from about 1360 to 1372 bytes for data, and handshakes stay far below; `nett0`'s MTU of 1280 (mesh.md section 4) is unchanged.

Compared with the published formats (ADR 0030): Shadowsocks-2022's UDP format (SIP022) encrypts every packet's whole body again with an AEAD and carries a proxy address, about 50 bytes and a second encryption per data packet; Mullvad's LWO masks the header with the server's public key, which a censor can read from the public relay list; AmneziaWG changes WireGuard itself. Version 1 keeps the per-packet salt of Shadowsocks-2022 and Hysteria's Salamander, seals only the messages that have a fixed shape, and keeps the keys secret.

## 4. Keys and per-site parameters

- **Keys**: each obfuscated port has a key, HMAC-SHA256 under the site's relay key (site.md section 8) of a label, a zero byte and the node ID of the machine it is on: `"nett obfuscation v1"` for a relay's port and `"nett machine obfuscation v1"` for a machine's own port, so the two ports of a relay's machine have different keys. The data key and the control key are derived from it with HKDF-SHA256 under the labels `"data"` and `"control"`. The site and the Hub derive it as they derive probe tokens (mesh.md section 5.2); it is delivered to the machine or the relay that owns the port, to each member in its candidates through that port, and to the relays that forward to a member through its port. Everyone who reaches a port shares its key: whoever holds it can recognize that port's obfuscated traffic, and that is all it gives, since WireGuard's keys protect the content. It is held like a key (hard rule 10): zeroized in memory, never logged, and the desired state that carries it stays `0600`;
- **Padding range**: drawn when the site's first port gets the obfuscated transport, a minimum from 0 to 64 bytes and a maximum 64 to 256 bytes above it, stored in the site state and delivered with the keys. Different sites thus send handshakes of different length distributions;
- **Obfuscated port**: drawn at random from 20000-59999 when the machine or the relay gets the obfuscated transport (section 7), until it is none of the machine's WireGuard port, its relay's ports and the ports nett itself uses on the host (site.md section 4); `--obfs-port` sets it.

## 5. Candidates and path selection

- **Candidates**: a `direct_obfs` candidate carries the address of the peer's obfuscated port, at its public IPv4 address or IPv6 without one, its key and the padding range; a `relay_obfs` candidate carries the relay's node ID, the address of the relay's obfuscated port, its key, the padding range and the probe token. For a peer that offers an obfuscated port, the end that decides the path (mesh.md section 8.3) gets a `direct_obfs` candidate first of the connection's candidates after the LAN ones, so the first handshake is already obfuscated. Relay candidates are generated like the relay's other transports (site.md section 6): the relay on the other end over obfuscated UDP, UDP and then TLS for the deciding end, then every other relay over obfuscated UDP, UDP and TLS, until the connection has 6 candidates, and at least one TLS candidate stays among them when any relay serves TLS;
- **Obfuscated UDP first where it adds no hop**: the obfuscated path to the peer's own port ranks after the LAN paths and before the plain direct one, since the user gave that machine the port for networks that block WireGuard (section 9); through a relay, obfuscated UDP comes before plain UDP, which comes before TLS: its transport penalty is 5 milliseconds below plain UDP's (mesh.md section 8.1), which follows the measurement in section 9. A pair on the obfuscated path to the peer's port moves to a much faster relay (mesh.md section 8.2) only over obfuscated UDP: being faster never gives up obfuscation, as Mullvad connects with the obfuscation method the user set rather than without it (section 9). A direct path to a machine that offers no obfuscated port stays plain: obfuscating it would send the pair's traffic through a relay, one more hop and the relay's traffic, and the pair moves to obfuscated UDP through a relay when plain UDP stops working;
- **A block stays avoided**: when a machine switches from a plain UDP path that stopped working (it no longer answers, or its handshakes no longer complete) to an obfuscated one, the endpoint it lost, the address and port of the blocked side, becomes suspected. It is recorded as blocked once the failure is shown to last: it answers no probe for 5 minutes while obfuscated UDP carries the connection to the same peer, so everything sent there is dropped, as a border firewall does to a port it identified; or it answers again, is taken back, and fails again within an hour, so probes pass and WireGuard does not. A single failure is what a path that recovers also shows, a handshake lost at start-up or a short outage: the suspicion lapses after an hour, and the path is taken back as any path that recovers. This measures that the block persists rather than inferring it from one failure. Plain UDP candidates to a recorded endpoint are neither probed nor taken, on every connection of the machine; other endpoints keep being used, since the blocks found so far list one address and port each. A block lasts days and probing it from WireGuard again only renews it, so plain UDP to it is not taken back. The record ends once no candidate leads to that endpoint (its address or port changed); `nett status` shows such a candidate as `blocked`. The record holds at most 64 endpoints and is kept in the mesh's state directory, so a restart does not try a blocked endpoint again (release.md section 8);
- **Versions**: a release that does not know a candidate kind rejects the whole desired state that carries one, revocations included, so a machine or a relay offers obfuscated UDP only once the Hub and every machine run a release that knows its candidates: `nett site set --obfs` and `nett site relay --obfs` name the Hub and the machines the Hub reports on an older release, a machine that has not reported one included, and stop. Without a Hub, every machine is upgraded first.

## 6. Measurement

The probes of an obfuscated candidate travel wrapped on the socket the tunnel uses, so they measure the obfuscated path itself: on the userspace data plane from the WireGuard socket as the tunnel's packets, on kernel WireGuard from the mesh's own port to the candidate's loopback port (mesh.md section 7.1). The peer's daemon or the relay answers them wrapped. Nothing else changes in measurement and switching.

## 7. Commands, ports and footprint

- `nett site set <machine> --obfs [--obfs-port <port>]` gives a `public` machine its obfuscated port, and `--no-obfs` removes it (site.md section 4); `nett site relay <machine> --obfs [--obfs-port <port>]` gives a relay its own, and `--no-obfs` removes it (site.md section 4.1). The change listing says when a machine's data plane changes with it;
- Each obfuscated port is opened in the machine's firewall or cloud security group once, like the relay port (mesh.md section 5.5);
- The loopback ports of a machine on kernel WireGuard are allocated like the TLS transport's (mesh.md section 5.3), from `41850`;
- Placed on a machine: the record of blocked endpoints in the mesh's state directory, listed in release.md section 8. No new process, service, account or setting; a Linux machine that offers a port runs the userspace data plane, whose TUN takes the place of the kernel's `nett0`.

## 8. Security and the hard rules

- Hard rule 1: the relay, in the nett daemon, forwards only between admitted members on the links its assignment lists, with the keys of its own obfuscated port and of the members' ports it forwards to; nett-relay, the relay's TCP entry, holds none of them and no mesh private key;
- Hard rule 2: the nett daemon listens publicly on a machine's obfuscated port beside its WireGuard port, and on its relay's ports (ADR 0031, ADR 0032): every datagram on the machine's obfuscated port is opened with the machine's key before WireGuard or the mesh sees it, handshakes are limited per source as on the WireGuard port, and what does not open gets no answer; the relay's obfuscated port opens each datagram with the relay's key, or with a member's when it comes from that member's obfuscated port, and answers nothing unauthenticated, as its relay port does. Elsewhere the daemon only sends from its WireGuard socket or from sockets connected to an obfuscated port;
- Hard rule 10: the obfuscation keys are handled as keys (section 4);
- Hard rule 13: every received datagram is checked (unmask, length, open, time, salt) before any field is used;
- Hard rule 14: the salt sets, the loopback ports and each connection's queue have named bounds; idle memory stays within the budget, measured as part of section 9.

The obfuscation protects nothing that WireGuard does not already protect: a censor that learns a site's obfuscation key can recognize its traffic, not read it.

## 9. The measurement that decides the default

Before obfuscated UDP through relays can come first, it is measured against plain UDP on the same path, on Linux with kernel WireGuard (one extra copy per packet through the loopback port), on a userspace platform, and through a 1-vCPU relay, first in the lab and then across a real border:

| Measure | Small enough when |
|---|---|
| Throughput of a bulk transfer through the tunnel | at least 95% of plain |
| Round trip | median at most 0.2 ms more |
| CPU at the same rate | at most 10% more |
| Idle memory | within the budget (nett daemon ≤ 8 MB, nett-relay ≤ 5 MB) |

All four met: obfuscated UDP through a relay comes first wherever it adds no hop (section 5). Otherwise plain UDP stays first, obfuscated UDP is taken where plain UDP stops working, and section 5's record keeps it there. If kernel WireGuard is what misses, a tc-eBPF program that masks in the kernel is the next thing to measure.

A machine's own obfuscated port (ADR 0031) is the user's choice for that machine, `nett site set --obfs`, made for networks that block WireGuard: it comes first after the LAN paths whatever this measurement finds, so the first handshake to it is already obfuscated and its WireGuard port is not shown to a censor first. Mullvad does the same with a method the user sets, which it uses from the first connection, while its automatic mode makes a WireGuard-only attempt first (mullvadvpn-app `b94efb5f52`, `mullvad-relay-selector/src/relay_selector/mod.rs`). The measurement records the cost, with the receiving end on the userspace data plane against kernel WireGuard and on one CPU, since such a machine changes data plane with the port.

**In the lab** (lab A: Linux 7.2, arm64 virtual machine, release build; the throughput scenario on `relay-only.toml` against `relay-obfs-only.toml`, two rounds each, and scenario 21 on `obfs.toml`), with obfuscated UDP against plain UDP through the same relay:

| Measure | Kernel WireGuard | Userspace WireGuard |
|---|---|---|
| Throughput on a 1 Gbit/s link | 895-899 against 903-907 Mbit/s (99%) | 844-894 against 863-903 Mbit/s (98-99%) |
| Throughput without a rate limit, where the CPU decides | 1.8-2.0 against 2.2-2.4 Gbit/s; with the whole lab on one CPU (both ends, the relay and the kernel) 1.26-1.40 against 1.6-1.97 Gbit/s | 2.0-2.2 against 2.4-2.6 Gbit/s |
| Round trip, median | 0.50-0.59 against 0.43-0.51 ms | 0.27-0.32 against 0.21-0.26 ms |
| Whole-machine CPU at 200 Mbit/s | 1.38-1.48 against 1.43-1.61 cores | 0.94-1.04 against 0.89-0.95 cores |
| Idle memory after load | the nett daemon 1.0-1.4 MB of anonymous pages, nett-relay 0.7 MB, as without the obfuscated transport | |

The virtual machine runs other workloads, so CPU differences of about 10% are within the noise. All four measures are met on paths of 1 Gbit/s and below; the measurement across a real border follows the release. The first round, before the transports' sockets had the receive buffer of tunnel sockets (userspace.md section 4), reached 1.4 Gbit/s with several times the retransmissions of plain UDP: packets were dropped at the loopback port.

**A machine's own port in the lab** (the same lab, release build, the whole lab on one CPU; the throughput scenario on `direct.toml`, as it is and with `--userspace b`, against `direct-obfs-only.toml`, as it is, a reaching b's port through the obfuscated transport's loopback port, and with `--userspace a`, a wrapping on its WireGuard socket; two rounds each, b on the userspace data plane for its port):

| Measure | Plain, kernel WireGuard | Plain, b on the userspace data plane | Obfuscated, a on kernel WireGuard | Obfuscated, a on the userspace data plane |
|---|---|---|---|---|
| Throughput on a 1 Gbit/s link | 894-906 Mbit/s | 675-879 Mbit/s | 436-691 Mbit/s | 603-666 Mbit/s |
| Throughput without a rate limit | 1.8-4.0 Gbit/s | 0.88-1.47 Gbit/s | 0.64-0.96 Gbit/s | 0.89-1.08 Gbit/s |
| Round trip, median | 0.24-0.27 ms | 0.22-0.25 ms | 0.28-0.29 ms | 0.14-0.18 ms |
| Whole-machine CPU at 200 Mbit/s | 0.65-0.99 cores | 0.70-1.06 cores | 0.71-0.98 cores | 0.53-1.18 cores |

Idle memory (scenario 21 on `machine-obfs.toml`, 600 s after load): b's nett daemon, on the userspace data plane with its obfuscated port, holds 1.6 MB of anonymous pages, the kernel WireGuard and userspace clients 1.6-1.7 MB. The round trip, the CPU at the same rate and idle memory are within the bounds; the throughput is not. With both ends and the kernel on one CPU, the userspace data plane on the receiving end alone takes up to a quarter of a 1 Gbit/s path, and obfuscated UDP to its port reaches 48-76% of plain kernel WireGuard; a path that carries less than about 600 Mbit/s is not held back. Batched receive and send in the userspace data plane on Linux (userspace.md section 9) is what raises that limit.

**Across a real border** (after the release; a 1-vCPU machine abroad offering its own port, reached at about 150 ms by two machines across the border on kernel WireGuard, through the obfuscated transport's loopback port; about 37 MB in all): the machine's plain WireGuard port answered none of their probes, while its obfuscated port, on the same address, lost none and answered 2-14 ms faster than the path through the relay on the same machine; transfers from the machine abroad ran at 31-34 Mbit/s, and to it at the rate of each sender's uplink, 2.8 and 8.7 Mbit/s; its nett daemon held 1.4 MB of anonymous pages. A relay that offers no obfuscated port could not reach that machine at all: its leg went to the blocked plain port (section 2).

## 10. Verification

| Level | Content |
|---|---|
| Unit | Round trip of both forms; a tampered, replayed, stale or unknown-version packet is dropped; padding stays in the site's range; over many packets no byte position keeps a value and handshake lengths vary |
| Relay | Unwrap, route and wrap across plain, obfuscated, TLS and loopback legs, a member that offers an obfuscated port reached through it with its key; no answer to unauthenticated packets; bounded salt set |
| Userspace data plane | The obfuscated port opens its datagrams with the machine's key and answers through it; a peer's obfuscated port is reached wrapped with its key from the WireGuard socket; a forged source does not move a peer's replies between the ports; what does not open gets no answer; on Linux the filter, Edge and forwarding apply on the TUN through nftables, and a new desired state that changes the data plane restarts the daemon onto it |
| Mesh | A plain endpoint lost to obfuscated UDP is recorded once it stays silent for 5 minutes or fails again within an hour, and not after one failure it recovers from; a recorded endpoint stays avoided, also after reopening the state directory, and its record ends when the endpoint changes; only a switch away from plain UDP that stopped working counts toward a block |
| Mesh order | The obfuscated path to the peer's own port is taken over the plain direct one, and through a relay obfuscated UDP over plain UDP; a recovering path of a better type is the best type that answers |
| nett-site and CLI | Candidate order and limit, the obfuscated path to a machine that offers a port first after the LAN paths, the TLS candidate kept, the relay's section with the members' ports and keys, a machine's own port and key; the Hub and the machines on an older release are named |
| Lab | A censor that blocks each port WireGuard is sent to: the pair moves to obfuscated UDP, stays there, and the record survives a restart; the same with the peer's own obfuscated port, on Linux with Edge and forwarding through nftables on the userspace data plane; the section 9 benchmark, also with the receiving end on the userspace data plane on one CPU |
| Real link | An obfuscated port on a machine abroad carries traffic for two weeks beside a plain WireGuard port as the control |

## 11. Open questions

- Whether fully random first bytes fare differently from bytes that parse as a common protocol such as STUN or DTLS: the one measurement found random UDP not blocked (USENIX Security 2023, data from 2021-2023), and nothing newer was found. Version 1 sends random bytes; a profile that imitates a protocol is added only if measurement shows random UDP blocked;
- Whether continued use of other ports of an address after one is listed escalates to blocking the address;
- Per-carrier throttling of long-lived single-port UDP, by hour of day.
