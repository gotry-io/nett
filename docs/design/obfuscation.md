# Obfuscated UDP transport

- Status: draft
- Phase: M2, first item (roadmap); decision in ADR 0030

## 1. Goals

A censor that identifies WireGuard drops UDP sent from the identified address and port into its network, in one direction, while the other ports of the same address pass (ADR 0011). The obfuscated UDP transport carries WireGuard across such a network:

- **Nothing fixed on the wire**: the bytes look random, as the evidence favors for UDP (ADR 0030); no byte at a fixed position keeps the same value, handshakes have no fixed length, and nothing unauthenticated gets an answer, so a rule that reads the first bytes and the length of packets, as the classifiers that block WireGuard do, has nothing to match;
- **WireGuard unchanged**: the transport wraps WireGuard's packets on the way and unwraps them before WireGuard sees them; the session, keys and roaming stay WireGuard's, and standard WireGuard exports for devices are not affected;
- **UDP throughout**: no TCP under the tunnel's TCP;
- **The format is public, the keys are not**: each site derives its own keys and draws its own padding range, so knowing the format does not give a rule that matches a site's traffic (Kerckhoffs). The format carries a version, so a later one can replace it.

## 2. Where it sits

```
A's WireGuard ─► 127.0.0.1:x (obfuscated transport) ─► obfuscated UDP ─► R's nett-relay ─► B
```

It has the shape of the TLS transport (mesh.md section 5.3) with UDP in place of TLS:

- **Member side**: the transport in the nett daemon opens, for each relay it reaches this way, a UDP port on the loopback address that serves as the WireGuard endpoint of that candidate, and one UDP socket connected to the relay's obfuscated port. Each packet from the loopback port is wrapped and sent on the connected socket; each packet received is unwrapped and dispatched as on the TLS transport: relay responses go back to the mesh's port that sent the probe, the rest to the WireGuard port. A packet that does not unwrap is dropped. The socket is connected, so the system delivers to it only packets from the relay's address; the nett daemon still listens on no public address (hard rule 2);
- **Relay side**: nett-relay listens on an obfuscated port of its own, separate from the relay port, since the relay port carries plain WireGuard and can be identified the same way as the WireGuard port. It unwraps what arrives, routes it as it routes the relay port's packets (by `mac1` and session index, mesh.md section 5.1), and wraps what it sends to a member bound on the obfuscated port. Each leg is plain or obfuscated on its own: a member bound on the relay port gets plain packets, the WireGuard on the relay's own machine gets plain packets on loopback, and only the leg that needs it is wrapped;
- **Paths**: a path through obfuscated UDP always goes through a nett-relay, on the peer's own machine (mesh.md section 5.1, reached with nearly the round trip of a direct path) or on a third machine. A direct obfuscated path between two members without a relay would need the nett daemon to listen publicly, and is not part of this design.

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

- **Keys**: each relay has an obfuscation key, HMAC-SHA256 under the site's relay key (site.md section 8) of `"nett obfuscation v1"`, a zero byte and the relay's node ID. The data key and the control key are derived from it with HKDF-SHA256 under the labels `"data"` and `"control"`. The site and the Hub derive it as they derive probe tokens (mesh.md section 5.2); it is delivered to the relay in its `relay` section and to each member in its candidates through that relay. All of a relay's members share it: whoever holds it can recognize the relay's obfuscated traffic, and that is all it gives, since WireGuard's keys protect the content. It is held like a key (hard rule 10): zeroized in memory, never logged, and the desired state that carries it stays `0600`;
- **Padding range**: drawn when the site is created, a minimum from 0 to 64 bytes and a maximum 64 to 256 bytes above it, stored in the site state and delivered with the keys. Different sites thus send handshakes of different length distributions;
- **Obfuscated port**: chosen at random from 20000-59999 when the relay gets the obfuscated transport (section 7), avoiding the ports the machine already uses; `--obfs-port` sets it.

## 5. Candidates and path selection

- **Candidates**: a `relay_obfs` candidate carries the relay's node ID, the address of its obfuscated port, the relay's obfuscation key, the padding range and the probe token. They are generated like the relay's other transports (site.md section 6): for the deciding end, the relay on the other end over UDP, obfuscated UDP and then TLS; then every other relay over UDP, obfuscated UDP and TLS, until the connection has 6 candidates, and at least one TLS candidate stays among them when any relay serves TLS;
- **Order and score**: obfuscated UDP is a transport between UDP and TLS: a transport penalty of 10 milliseconds against TLS's 20 (mesh.md section 8.1), and "a path of a better type recovers" counts plain UDP over obfuscated UDP over TLS (section 8.2);
- **Site policy**: `fallback` (the starting value) uses that order. `prefer` uses obfuscated candidates first on every path that leaves a LAN: a candidate over plain UDP that crosses the public network (public direct, hole-punched direct, a UDP relay) is used only while no obfuscated candidate of the connection works; LAN paths stay plain. Which one becomes the default follows the measurement in section 9;
- **A block stays avoided**: when a connection leaves plain UDP because every plain UDP candidate stopped answering while an obfuscated one works, the decider records that the endpoint it lost, the address and port of the blocked side, is blocked, and from then on treats the connection as under `prefer`. A block lasts days and probing it from WireGuard again only renews it, so plain UDP is not taken back. The record ends when that endpoint changes (its address or port), or with `nett site obfuscation reset <machine> <machine>`; `nett status` shows it. It is kept in the mesh's state directory so a restart does not try the blocked endpoint again (release.md section 8);
- **Versions**: a machine gets `relay_obfs` candidates only once the version it reports knows them, and a relay gets its obfuscated port only then; a machine of the previous version keeps its other candidates (adjacent versions interoperate).

## 6. Measurement

Relay probes and through probes of an obfuscated candidate are sent from the mesh's own port to the candidate's loopback port and travel wrapped, on the socket the tunnel uses (mesh.md section 7.1), so they measure the obfuscated path itself; the relay answers them wrapped. Nothing else changes in measurement and switching.

## 7. Commands, ports and footprint

- `nett site relay <machine> --obfs [--obfs-port <port>]` gives a relay the obfuscated transport, `--no-obfs` removes it; `nett site obfuscation fallback|prefer` sets the site policy; `nett site obfuscation reset <a> <b>` ends a recorded block;
- The relay's obfuscated port is opened in the cloud security group once, like the relay port (mesh.md section 5.5);
- The member's loopback ports are allocated like the TLS transport's, from `41850`-`41865`, a range the machine's WireGuard port may not use (site.md section 4);
- Placed on a machine: the record of blocked endpoints in the mesh's state directory, listed in release.md section 8. No new process, service, account or setting.

## 8. Security and the hard rules

- Hard rule 1: nett-relay holds the relays' obfuscation keys and probe tokens, never a mesh private key;
- Hard rule 2: public listening is nett-relay's obfuscated port; the nett daemon only sends from sockets connected to a relay, and drops what does not unwrap. Unauthenticated packets on the obfuscated port get no answer, as on the relay port;
- Hard rule 10: the obfuscation keys are handled as keys (section 4);
- Hard rule 13: every received datagram is checked (unmask, length, open, time, salt) before any field is used;
- Hard rule 14: the salt sets, the loopback ports and each connection's queue have named bounds; idle memory stays within the budget, measured as part of section 9.

The obfuscation protects nothing that WireGuard does not already protect: a censor that learns a site's obfuscation key can recognize its traffic, not read it.

## 9. The measurement that decides the default

Before `prefer` can become the default, obfuscated UDP is measured against plain UDP on the same path, on Linux with kernel WireGuard (one extra copy per packet through the loopback port), on a userspace platform, and through a 1-vCPU relay, first in the lab and then across a real border:

| Measure | Small enough when |
|---|---|
| Throughput of a bulk transfer through the tunnel | at least 95% of plain |
| Round trip | median at most 0.2 ms more |
| CPU at the same rate | at most 10% more |
| Idle memory | within the budget (nett daemon ≤ 8 MB, nett-relay ≤ 5 MB) |

All four met: the site default becomes `prefer`. Otherwise it stays `fallback`, where obfuscated UDP is taken where measurement shows plain UDP blocked, and section 5's record keeps it there. If kernel WireGuard is what misses, a tc-eBPF program that masks in the kernel is the next thing to measure.

## 10. Verification

| Level | Content |
|---|---|
| Unit | Round trip of both forms; a tampered, replayed, stale or unknown-version packet is dropped; padding stays in the site's range; over many packets no byte position keeps a value and handshake lengths vary |
| nett-relay | Unwrap, route and wrap across plain, obfuscated, TLS and loopback legs; no answer to unauthenticated packets; bounded salt set |
| nett-site | Candidate order and limit, the TLS candidate kept, `prefer` and `fallback`, no obfuscated candidates for a machine of the previous version |
| Lab | A router drops packets that match WireGuard's signature (first bytes and lengths) in one direction: the pair moves to obfuscated UDP, stays there, and the record survives a restart; the section 9 benchmark |
| Real link | An obfuscated port on a machine abroad carries traffic for two weeks beside a plain WireGuard port as the control |

## 11. Open questions

- Whether fully random first bytes fare differently from bytes that parse as a common protocol such as STUN or DTLS: the one measurement found random UDP not blocked (USENIX Security 2023, data from 2021-2023), and nothing newer was found. Version 1 sends random bytes; a profile that imitates a protocol is added only if measurement shows random UDP blocked;
- Whether continued use of other ports of an address after one is listed escalates to blocking the address;
- Per-carrier throttling of long-lived single-port UDP, by hour of day.
