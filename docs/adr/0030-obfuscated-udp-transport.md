# 0030. Obfuscated UDP transport: WireGuard wrapped in a public format with site keys

- Status: accepted
- Date: 2026-11-23

## Context

WireGuard has cleartext framing: message types 1-4 followed by three zero bytes, and handshakes of 148 and 92 bytes (wireguard.com/protocol). Classifiers match exactly that: libprotoident's rule (`lib/udp/lpi_wireguard.cc`) takes `01 00 00 00` at 148 bytes, `02 00 00 00` at 92 and `04 00 00 00` at 92-512, and the firewall analyzed from the Geedge Networks source leak runs libprotoident, which reads only the first four payload bytes in each direction (Ablove et al., USENIX Security 2026). Once WireGuard is identified, the Chinese censor drops UDP sent from the server's address and port into China, in one direction, for days (net4people/bbs#117, 2022), and a measurement matched it: random payloads from other ports of the same address arrived, none from its WireGuard port. nett falls back to its TLS transport, WireGuard over TCP, or since 0.9.5 to the relay's own UDP port (ADR 0011), which carries plain WireGuard and can be identified the same way.

What comparable products do:

- **WireGuard** itself leaves it to a layer above: "Obfuscation, rather, should happen at a layer above WireGuard" (wireguard.com/known-limitations);
- **Mullvad** keeps WireGuard and wraps it: QUIC with MASQUE (RFC 9298; blog 2025-09-09), Shadowsocks, udp-over-tcp, and LWO, which masks the header with the server's public key;
- **Tailscale**, **NetBird** and **Nebula** have no obfuscation; **AmneziaWG** changes WireGuard's framing, so both ends must run it;
- **Shadowsocks-2022** (SIP022) and **Hysteria 2**'s Salamander put a random salt in front of every packet; **obfs4** answers nothing that fails its MAC.

The session layer stays WireGuard (ADR 0007): none of the session protocols compared (AmneziaWG, Nebula, ZeroTier, OpenVPN, IPsec, Lightway, MASQUE CONNECT-IP) combines a kernel data path, standard clients, relays without keys, roaming at both ends and a Rust library under an allowed license, and all but QUIC have cleartext fields of their own.

## Decision

nett adds an obfuscated UDP transport (design/obfuscation.md):

- **Shape of the TLS transport**: on the member, a loopback port per relay as the WireGuard endpoint and a socket connected to the relay's obfuscated port; on nett-relay, an obfuscated port of its own that unwraps, routes by `mac1` and session index as today, and wraps each leg that needs it. WireGuard is unchanged;
- **Format version 1**: a 12-byte random salt on every datagram; data messages have their first 16 bytes masked with a keyed BLAKE2s of the salt; handshakes and probes are sealed with ChaCha20-Poly1305 with a time and random padding, and replays and unauthenticated packets get no answer;
- **Public format, site keys**: the format is open source; each relay's obfuscation key is derived from the site's relay key, and each site draws its own padding range;
- **Order**: a measurement showed obfuscated UDP costs less than 5% of throughput, 0.2 ms of round trip and 10% of CPU on paths of 1 Gbit/s and below, within the memory budget (design/obfuscation.md section 9), so it comes first wherever it adds no hop: through a relay before plain UDP, and through the relay on the peer's own machine before the plain direct path. A direct path between machines that run no relay stays plain until plain UDP stops working, since obfuscating it would route it through a relay. An endpoint lost to a block stays avoided until it changes.

## Rationale

- Random-looking UDP is the form the evidence favors: the censor's detection of fully encrypted traffic "is limited to TCP", and "sending a UDP datagram with a random payload cannot trigger the blocking" (Wu et al., USENIX Security 2023, observed 2021-2023); that detection blocks a client, server and port for 180 seconds, not an address. Whole addresses have been blocked after known circumvention protocols ran on them (net4people/bbs#129, 2026-10), a risk plain WireGuard on the same address already carries;
- The classifiers read the first bytes and the lengths; a per-packet salt, masked headers and padded handshakes leave them nothing, at 12 bytes and one hash per data packet, and UDP throughout avoids TCP over TCP;
- The relays keep forwarding by WireGuard's fields: each hop unwraps, so the relay reads what the censor cannot;
- The keys, not the format, decide who can recognize the traffic: a program that is published can be reverse-engineered, and a censor's rules are statistical, so a hidden format buys little while costing the project its reviewability;
- The shape of the TLS transport keeps public listening in nett-relay (hard rule 2) and gives kernel and userspace platforms one implementation;
- A block lasts days, so taking plain UDP back only renews it.

## Alternatives considered

- **Shadowsocks-2022's UDP format**: a published specification with Rust implementations, but every data packet is encrypted again with an AEAD and carries a proxy address, about 50 bytes and a second encryption per packet on top of WireGuard's;
- **Mullvad's LWO**: cheap, but masked with the server's public key, which a censor can read from a public list; its implementation is GPL-3.0;
- **AmneziaWG**: both ends must replace WireGuard, the Linux module is GPL-2.0, and exports stop being standard WireGuard;
- **A closed format**: the program is published and can be reverse-engineered; the keys already decide recognition;
- **QUIC first**: China blocks QUIC by its SNI and holds a residual block; QUIC adds a congestion controller under WireGuard's flows and costs binary size and memory; it stays in M2 for networks that pass only UDP 443;
- **Fake TCP (Phantun, udp2raw)**: needs raw sockets and `NET_ADMIN` in nett-relay and fails on phones;
- **Moving or hopping the WireGuard port**: leaves one entry of the block list, not the detection, and has been reported to end with the whole address blocked (net4people/bbs#425).

## Consequences

- One more UDP port per relay that offers it, to open in the security group;
- The member's daemon copies each packet once more through the loopback port; the measurement decides whether this is small enough to make obfuscation the default, and a tc-eBPF variant is the next step if kernel WireGuard is what misses;
- A relay offers obfuscated UDP only once the Hub and every machine run a release that knows it;
- The format will change as censors adapt; the version byte and the key labels let a new one replace it.
