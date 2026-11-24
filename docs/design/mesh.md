# Mesh

- Status: draft
- Phase: P0 design; M1 implements the first version, M2 extends it (see section 18)
- Related: ADR [0007](../adr/0007-own-mesh-wireguard-session-path-layer.md), [0008](../adr/0008-phones-through-mobile-gateway.md), [0011](../adr/0011-nett-relay.md), [0013](../adr/0013-one-daemon-per-machine.md), [0014](../adr/0014-signed-mesh-membership.md), [0015](../adr/0015-origin-identity-and-lan-default-deny.md), [0016](../adr/0016-containers.md), [0018](../adr/0018-client-platforms.md); [protocol.md](protocol.md), [auth.md](auth.md), [architecture.md](../architecture.md)

## 1. Goals

Nodes have multiple candidate paths and multiple transports between them. The mesh measures continuously and selects the best path automatically. When a path jitters, breaks, or a node goes offline, it switches automatically and **connections in progress are not interrupted**; the experience on disconnect, fluctuation, fallback and recovery is no worse than Tailscale (ADR 0021). There is no single point of failure. The Hub being offline does not affect the mesh. **nett-node being stopped does not affect the mesh either**: path selection, switching and DNS carry on as usual (ADR 0013).

Out of scope for this phase: per-connection path selection (all traffic between the same pair of nodes shares one path); automatic handling of overlapping prefixes between different sites; Windows and the mobile app (M3, ADR 0018).

## 2. Terms

| Term | Meaning |
|---|---|
| Member | A node or device that has joined the mesh |
| Link | A WireGuard session between a pair of members |
| Candidate path | A path a link may use: LAN direct, public direct, via relay, multi-hop relay |
| Transport | The way WireGuard packets are carried: UDP, TLS (WebSocket), later QUIC |
| `public` / `dial-only` | Whether a node can be reached from outside (see architecture.md section 6.5) |
| Relay | A `public` node whose nett daemon forwards ciphertext for other members (ADR 0032); nett-relay is its public TCP entry |
| Smart gateway | A node that brings an entire LAN prefix into the mesh |
| Mobile gateway | A node that accepts device connections and carries device traffic into the mesh |
| nett daemon | `nett daemon`: the one nett process on each machine (ADR 0013). Its mesh does all the mesh work described in this document and does not depend on nett-node, which runs on a thread of its own in the same process; it also carries the TLS transport (section 5.3) |
| Revocation | The record left when a member is removed, credentials are revoked, a prefix is revoked or a rule is narrowed; it prevents old signed artifacts from restoring privileges (auth.md section 10.4) |
| Admission material | Signed artifacts that prove a peer may join the mesh (section 4.1) |
| Edge | A reverse proxy the user runs on the entry node; any implementation works (Caddy, nginx, Traefik, etc.); nett neither generates nor manages its configuration (ADR 0019) |
| Edge address | On a node with the `edge` role, the mesh address reserved for traffic sent by Edge (ADR 0015) |
| Full member | A member that runs the nett daemon, verifies admission material itself and selects paths; other members can connect to it directly. A device using a WireGuard client is not a full member |
| Container | A member that runs nett's image; services sharing its network are reached at its mesh address (ADR 0016, design/container.md) |

## 3. Address plan

| Address | Rule |
|---|---|
| IPv4 mesh prefix | Default `100.88.0.0/16`, can be changed when the Hub is initialized; avoids the internal services some cloud vendors provide on `100.100.0.0/16` |
| IPv6 mesh prefix | A random ULA `/48` generated when the Hub is initialized |
| Member address | One IPv4 and one IPv6 address per node, assigned when the enrollment token is created; one pair of addresses per WireGuard credential of a device (multiple credentials of the same device act as different peers of the gateway at the same time, and WireGuard does not allow peers' `AllowedIPs` to overlap), assigned when the credential is created. Addresses are written into signed artifacts and never change. **They are not reclaimed in the first release**: addresses of removed members and credentials are not assigned again (a `/16` is enough for a small number of machines for a long time), so a new member never inherits authorization left over on an old address |
| Edge address | One extra pair of addresses per node with the `edge` role, written into the signed node policy |
| CONNECT egress address | One extra pair of addresses per relay node that provides a CONNECT proxy, written into the signed node policy and appearing in the `AllowedIPs` of that node's peers; the far side may only reach the targets allowed by CONNECT rules (section 5.4) |
| LAN prefix | Advertised by the smart gateway (section 10) |

When allocating addresses and advertising prefixes, the Hub detects conflicts and rejects the following with a message: the mesh prefix overlaps any member's LAN prefix or reported external address (CGNAT addresses of home broadband carriers also lie in `100.64.0.0/10`); two sites advertise overlapping prefixes; the tailscale fallback is enabled and its address pool does not exclude the mesh prefix (ADR 0007).

## 4. Session layer

- Each node has one WireGuard interface `nett0`, listening on one UDP port (default `41820`, configurable);
- Peers: all other nodes; devices are peers only of the mobile gateway (section 13);
- `AllowedIPs` of each peer: its mesh address; its Edge address and CONNECT egress address (if any); the LAN prefixes it advertises (if any); the device credential addresses for which it is the current gateway (if any, only for nodes with the `gateway` role). **When this machine has a device credential directly as a peer (a mobile gateway), that credential's address is configured only on the device peer and does not appear on another gateway's peer**;
- **The WireGuard private key is generated on the machine and never leaves the node**; the public key is distributed through the Hub together with the admission material (the `mesh` partition of the desired state);
- Linux uses kernel WireGuard, configured by the mesh through netlink; platforms without the kernel module (Synology DSM, old kernels) use a Rust userspace implementation with a TUN device, running in the nett daemon;
- `dial-only` members set a persistent keepalive of 25 seconds on every peer to maintain the NAT mapping;
- **MTU**: the MTU of `nett0` is fixed at 1280 (the IPv6 minimum). With the WireGuard and outer IP and UDP headers, the largest outer packet is about 1360 bytes: when the outer path MTU is at least 1360 (true for common networks) there is no fragmentation and no dependence on path MTU discovery. When it is smaller, fragmentation takes over: outer IPv4 packets do not set DF, and the router at the bottleneck fragments them; for IPv6 the router at the bottleneck returns ICMPv6 "packet too big" and the sender fragments from then on. With an outer path MTU of 1300, both were measured to transfer completely (prototype.md section 9, scenario 19). Known limitation: the IPv6 route depends on ICMPv6 getting back to the sender; if ICMPv6 is dropped on the path and the outer path MTU is below 1360, large packets are silently lost while small probes pass as usual, and the path layer does not notice. The remedy is left until a real case appears (for example, periodically send an in-tunnel probe that fills the MTU and treat a loss as a failure). The TLS transport is segmented by TCP itself and is not affected. The mobile gateway and smart gateway clamp the MSS of forwarded TCP; TCP originated on the machine determines its MSS from the interface MTU automatically.

**Switching path = changing the peer's endpoint**. The WireGuard session, keys and upper-layer TCP connections are not affected. The mesh does the measuring, path selection and endpoint setting, and does not depend on nett-node running. Switching to a relay that has not yet handled this link also requires a new handshake (section 8.4).

### 4.1 Admission verification

A member configures WireGuard only for peers whose chain of signatures it can verify (ADR 0014):

| Peer attribute | Verified against |
|---|---|
| Node's mesh public key and address | Trust anchor -> signed node policy with the mesh module (containing node ID, address, enrollment public key) -> admission proof (signature by the enrollment private key over node ID, identity public key and mesh public key) |
| Edge address | The `edge` role and address assignment in the signed node policy |
| Device's mesh public key and address | The signed artifact of `device.add` / `device_credential.create` |
| LAN prefix | The signed artifact of `node.advertise_routes` |
| Device address appearing on a node's peer | That node's signed policy has the `gateway` role |
| Access rules | The signed artifact of the whole rule set (members, addresses and ports after selector expansion), version number only increases |

Peers that fail verification are not configured, and an event is reported. Removing a member, revoking a prefix and narrowing rules can take effect directly without a signature, leaving a revocation; when verifying other members' admission material, the approval expiry time is not checked, only the signature, version and revocations (auth.md sections 10.2 and 10.4). The baseline for verification is the local trust store, not the desired state file (section 4.2).

### 4.2 The local trust store

The mesh keeps the authorizations it has accepted on the local machine as the baseline for verification; the desired state file is only an input, and rewriting it cannot change the verification baseline (auth.md sections 10.4 and 11.2, protocol.md section 6.2).

| Saved content | Purpose |
|---|---|
| The machine's node ID and trust anchor list | Fixed when the desired state is first accepted. A desired state with different trust anchors is afterwards rejected as a whole; trust anchors can only be changed by an update signed by the current trust anchors (auth.md section 11.2), and are cleared only by `nett leave` run as root on the machine (auth.md section 8.3) |
| Revocations | Kept permanently, take effect at startup before any authorization |
| The version and hash in effect for each signed artifact: each member's admission material, the access rule set, each member's advertised prefixes | Versions only increase, also across restarts: artifacts of an old version, and artifacts of the same version with different content, are rejected |
| The most recent desired state accepted as a whole | When the desired state file is rejected as a whole (unreadable, malformed, not for this machine, different trust anchors), it is used instead at startup, and the state already in effect continues to be used at run time |

- **Location**: `state/` in the directory of `nett daemon --dir <directory>`, next to the keys and the desired state: on Linux `/etc/nett/state`, on macOS `/Library/Application Support/nett/state` (both in a root-only directory); in the container `/var/lib/nett/state`, in its volume, so it is kept after the container is rebuilt. Directory `0700`, files `0600`, written to a temporary file and then renamed;
- **Startup**: read the trust store first, then the desired state file. The machine's node ID is taken from the trust store, or from the desired state file when there is no trust store;
- **Establishment**: when there is no trust store, it is established from the first desired state accepted as a whole, and this time the expiry time of the local node policy is not checked. This is the case at the first start after an already-running member is upgraded, so the first desired state must arrive through a trusted channel (local-signing.md section 5; when joining a Hub, it is checked against the trust anchor fingerprint in the enrollment token, auth.md section 8.1);
- **Expiry of the local node policy**: after the trust store is established, when a new version of the local node policy appears its expiry is checked (auth.md section 10.2, item 6); an expired one is not accepted and the version already in effect continues to be used;
- **Read/write failure**: when the trust store cannot be written, the mesh keeps running as usual (hard rule 8), verifies against the state in memory, and lists it as a problem needing attention (status.md section 6): a restart in this period may accept artifacts of an old version. A corrupted trust store is kept as `trust.json.bad` and re-established as under "Establishment", also listed as a problem;
- Size and count have limits (section 17).

## 5. Relay

### 5.1 Forwarding model

The relay does not take part in the WireGuard session and only forwards ciphertext. **Each relay uses only one UDP port** and decides the destination from the WireGuard message itself (ADR 0011):

| Message | How the relay decides the destination |
|---|---|
| Handshake initiation (type 1) | `mac1` is computed with the receiver's public key as the key (BLAKE2s, per the WireGuard protocol); the relay tries the public keys of the links assigned to it one by one to determine the receiver; it records the initiator's session index and source (a pending entry) |
| Handshake response (type 2) | The receiver is determined the same way by `mac1`; it records the session indexes of both sides, and the pending entry becomes a regular entry |
| Cookie reply (type 3) | Looked up by receiver index; it may arrive before the handshake response, so pending entries are also searched |
| Data (type 4) | Looked up by receiver index; dropped if not found |
| Through probe (`0x92`, section 7.2) | The receiver is named in the probe; forwarded to its bound address when the sender's relay checksum holds and the two are a link assigned to the relay; the probe's source is remembered for 2 seconds |
| Through reply (`0x93`) | Forwarded once to the source of the probe it answers, only from the receiver's bound address |

```
A's WireGuard ──► R:p ──(by mac1 / session index)──► B's WireGuard
A's WireGuard ◄── R:p ◄─(by mac1 / session index)─── B's WireGuard
```

- On a link through R, A sets B's endpoint to `R:p` and B also sets A's endpoint to `R:p`; the same relay can be the endpoint of several peers at once;
- R records each member's actual address and passes packets to the other end;
- **A link with one end on R's own machine**: the other end reaches R's relay port over UDP, or over TLS (section 5.3), and R hands the packets to WireGuard on its own machine: the relay, in the same nett daemon (ADR 0032), takes this machine's address as the loopback address of its WireGuard port, which no binding learned or saved before replaces (section 5.2), and WireGuard there follows to R's port by roaming. This keeps the two connected when the way to the WireGuard port is blocked but the relay's port passes: a censor can drop UDP sent from the WireGuard port of a machine abroad while the other ports of that address pass (ADR 0011), and UDP can be blocked while TCP passes. Only the end that decides the path (section 8.3) uses such a path, so it is generated for the other end when that end decides (site.md section 6);
- **Multi-hop**: R1 does not pass the packet directly to B but to R2, and R2 likewise decides the destination from the message;
- On a session index collision, the relay drops the colliding handshake and WireGuard automatically retries with a new index; entries age out according to the session's idle time;
- The relay's UDP sockets ask for the receive buffer of every socket that carries tunnel traffic (userspace.md section 4); running without privileges, the relay gets at most what the system limit allows (on Linux `net.core.rmem_max`; with the usual settings that is twice the default buffer).

### 5.2 Assignment and authorization

- Which links go through which relay is computed when the desired state is composed (site.md section 6; with a Hub, by the Hub) and delivered in the `relay` section of the desired state of the machine where the relay runs: the UDP port, the TLS port when it serves TLS, the links (pairs of node IDs), and for each member on them its node ID, the WireGuard address of a `public` member, with its own obfuscated port, key and padding range when it offers one and this relay offers obfuscated UDP (design/obfuscation.md section 2), and the probe token between that member and this relay (section 7.2; the same token is in that member's relay candidates). The token is HMAC-SHA256 of the relay's and the member's node IDs under the site's relay key (site.md section 4.1); only the member, the relay, the site and the Hub know it;
- The mesh validates the section and resolves each member to its mesh public key from the verified admission material: a member that is not admitted is left out of the assignment together with its links (why it was not admitted is already listed in status), so the relay forwards only between admitted members (hard rule 4). The relay runs in the nett daemon (ADR 0032) and takes the assignment from the mesh in the same process each time a desired state is applied, and applies a changed assignment in place: bindings and session indexes of the links that remain are kept, and those of removed links are dropped. The relay forwards only for links assigned to it;
- **Address binding**: a member's actual address is updated only after **the peer has returned a response to a handshake initiation from the new address**, and a handshake response is accepted only from the peer's currently bound address. For the first binding, the address of a `public` member is delivered with the assignment; the address of a `dial-only` member is the address from which it sent a handshake initiation, likewise bound after the peer responds. When a changed assignment gives a `public` member another address (its port changed, section 5.5), the member is bound there: it answers the handshakes forwarded to it and starts none through the relay, so no handshake would bring its new address. When both ends are `dial-only` and neither has an address yet, a handshake initiation can identify only the receiver, and the relay keeps it in the pending table; when the other end's handshake initiation arrives, the relay forwards it to the addresses that may be the receiver (sources of pending handshake initiations whose receiver is one of the assigned peers, at most 4); the receiver returns a response from one of them, and the addresses of both ends are bound together. The relay holds no keys and cannot verify whether handshake messages are genuine: an attacker who can forge source addresses may still forge a response and change the binding. The consequence is that the ciphertext of this link is sent to a wrong address, which is a disconnection; no content is leaked. Two further measures therefore apply: binding changes are rate-limited; if no data arrives from the new address within 10 seconds after a new binding, the old binding is restored. The path layer switches as usual after detecting the interruption;
- nett-relay, the relay's public TCP entry (section 5.3, ADR 0032), obtains what it needs from the mesh in the nett daemon over the helper socket (status.md section 3.1), and later the verified material needed for CONNECT (device credentials, access rules, revocations), without depending on nett-node. It is a process of its own, the only nett process that listens on public TCP: on Linux it runs as a user systemd allocates while it runs (`DynamicUser`), with only the capability to bind ports below 1024; nett-node enables its service while the relay serves TLS and disables it otherwise;
- **Restart without disconnection**: once per second and before the daemon exits, the relay saves the index table and address bindings to the daemon's runtime directory (`/run/nett/`, which systemd keeps while the service restarts and which goes with a reboot; only session indexes and addresses, no keys; writing to disk is not done in the forwarding loop, so a disk stall only delays the save and does not stall forwarding), and restores them at startup, a member's binding only while the assignment still gives that member the address it gave when the binding was saved; connections through it are not interrupted (also during upgrades). On a crash, sessions created in the last second are not in the saved table and handshake again per section 8.4;
- A traffic and bandwidth limit per relay, beyond which no new links are assigned to it, comes in M2 with the line quality matrix (section 18);
- The number of `mac1` trials and the size of the index table both have limits; at most 4096 forwarded through probes are remembered, each for 2 seconds (ADR 0029).

### 5.3 TLS transport

When UDP is unavailable:

```
A's WireGuard ─► 127.0.0.1:x (TLS transport) ─► WebSocket/TLS 443 ─► R's nett-relay ─► R's relay (nett daemon) ─► B
```

- The TLS transport runs in the nett daemon on every platform (ADR 0013). For each TLS relay it opens a UDP port on the local loopback address, which serves as the endpoint of this candidate in WireGuard; each received packet is sent as one binary WebSocket message, and likewise in the other direction. Both ends of the connection, the TLS transport and nett-relay, send each message at once (`TCP_NODELAY`), as a UDP path would: probes and keepalives share the connection, and with Nagle's algorithm a packet would wait until the one before is acknowledged. It handles only ciphertext. The loopback port is allocated by the mesh, from `41830` in the order of the relays' node IDs and going around the machine's own UDP ports (its WireGuard port, its relay port and its relay's obfuscated port, which bind every local address), and handed to the TLS transport together with the TLS target and certificate fingerprint: the TLS transport asks the mesh in the same process for this configuration every second. A loopback port it cannot open, for example while another process still holds it, is tried again after 1 second, then at doubling intervals up to a minute;
- Probes sent to a TLS relay (`0x90`, section 7.2) are sent and received through the same loopback port and WebSocket connection, and TLS candidates are measured like UDP relays; the TLS transport dispatches messages in the other direction by message type: relay responses go back to the mesh's port that sent the probe, and the rest go to the WireGuard port;
- **Hand-off to the relay**: nett-relay terminates TLS and WebSocket and nothing else. For each connection it uses one UDP socket on the loopback address, connected to the relay's TLS hand-off port in the nett daemon, a loopback port the daemon picks and gives it over the helper socket; each WebSocket message becomes one datagram there, and each datagram back one message. To the relay, each such socket is one member's TLS address;
- **Connection authentication**: the first message on a WebSocket connection must be an authenticated relay probe, from which the relay identifies the member (the token is only in the mesh, and the TLS transport merely passes it along); nett-relay closes a connection whose first relay response has not come back within 30 seconds, and until the relay has authenticated it, the relay forwards no message from it and makes no response. After that the connection is one address of this member, with the same binding rules as UDP (section 5.2); the number of TLS connections and the number of connections waiting for authentication have limits. Each end's send queue on a connection holds the newest 32 packets and drops the oldest when another arrives: a packet that waited behind a slow connection is worth less to the WireGuard and TCP it carries than a fresh one, which they would otherwise send again. Tailscale's DERP queues 32 packets per client and drops the head the same way (v1.104.7 `derp/derpserver/derpserver.go`);
- **Certificate**: nett-relay terminates TLS itself with a self-signed certificate. nett-node creates it when it first enables the relay (`sudo nett install` on a machine without a Hub): an Ed25519 key in `/etc/nett/relay/`, `0600` and root only, never leaving the machine. systemd hands it to nett-relay when it starts (`LoadCredential=`), so nett-relay, which runs as a user systemd allocates, has no directory of its own; it reports the certificate's SHA-256 fingerprint to the nett daemon when it asks for its ports (status.md section 3.1), the mesh shows it in status (status.md section 6), and the Hub learns it from there (hub.md section 5). Clients verify the certificate against the fingerprint in their candidates, connect by IP, and send no SNI, so no domain name is needed (for example where the region requires domain names to be filed with the cloud vendor). Like the other candidates, whether this transport is usable is decided by measurement (section 7); when it is blocked the path layer simply does not select it, and no advance test is needed;
- nett-relay listens on TCP 443 by default (site.md section 4.1). On an entry node the reverse proxy holds 443: it passes the WebSocket to nett-relay by domain name and terminates TLS itself, and the members then check the proxy's certificate against the system's CA certificates and the relay's domain name instead of a fingerprint (ADR 0011). This hand-off is not implemented yet; until it is, a relay on an entry node uses another TCP port;
- In the TLS transport, the performance of TCP carried by WireGuard degrades under packet loss (TCP over TCP), so it is used only when UDP is unavailable;
- **Blocking the old path after leaving the TLS path**: far more packets queue on the TLS path than on UDP, and after switching away they keep arriving; the peer is changed back to the relay by these packets, its packets come back over TLS and change this end back to TLS (WireGuard roaming, section 8.3), and the two ends pull each other back and forth, which can last several seconds. So when no peer is using a given TLS relay, the mesh drops, on the local machine, packets entering the WireGuard port from that relay's loopback port: it opens them before switching to TLS and blocks them again after switching away. This involves only the loopback port this machine selected; if the rule cannot be installed, switching back is merely slower;
- **Standby connection**: for `dial-only` members with TLS candidates, the mesh probes these candidates as usual (section 7); the TLS transport connects to a TLS relay when it receives the first probe addressed to it, and keeps the connection afterwards (keepalive every 25 seconds), so no TLS connection has to be established on the spot during fallback (ADR 0021). The follower of a pair of `dial-only` members does not probe candidates, but it may have to move to a TLS relay together with the decider (section 8.4), so it sends its own probe to each TLS relay every 5 seconds and its standby connection stays authenticated.

### 5.4 CONNECT proxy

- HTTP/2 over TLS, forwarded per connection, can chain multiple relays;
- On an entry node it shares 443 with the website: the reverse proxy hands over requests "whose method is CONNECT and whose TLS SNI is the nett-relay domain name", and cannot hand over by Host (the `:authority` of a CONNECT request is the target address). Measured: standard Caddy 2.10.2 can forward HTTP/2 CONNECT tunnels but not HTTP/1.1 CONNECT tunnels, so through Caddy only HTTP/2 CONNECT is provided; for other reverse proxies, rely on measurement. This configuration on the Hub host is generated by the Hub install script; nett-relay on other `public` nodes supports both;
- The client credential is a kind of device credential (`kind = connect`, see api-resources.md section 5.4), and adding one requires a signature;
- The CONNECT egress uses the CONNECT egress address on the relay node (section 3), shared by all devices. The target node cannot tell devices apart by source, so **nett-relay authorizes each connection per credential**: for each CONNECT connection, it checks the signed access rules for the device corresponding to the credential (relay is a verifier of `device_credential` and `access_rule_set`); the check is on the address finally connected to, not the name in the request;
- CONNECT targets can only be mesh addresses (including prefixes advertised through smart gateways); the host the relay runs on and its LAN are not connected to directly; nett-relay does not open CONNECT until the mesh reports that filter rules are ready;
- **Boundary**: a compromised nett-relay can reach, using the CONNECT egress address, all targets allowed by CONNECT rules (the union of the privileges of all CONNECT devices), which exceeds what an ordinary low-privilege process can do; create such credentials only for devices that really need CONNECT;
- The host where Edge runs is itself a mesh member, and origin traffic goes directly over the mesh without CONNECT.

### 5.5 Public ports and security groups

nett cannot modify a cloud vendor's security group, and some cloud vendors deny all inbound UDP by default. The ports needed by each role are listed below, to be opened once by the user in the cloud console; when `nett doctor` and the console detect that a port is unreachable, they state which port should be opened.

| Role | Protocol and port | Purpose |
|---|---|---|
| All `public` nodes | UDP 41820 (configurable) | WireGuard |
| Nodes that relay | UDP relay port (one, configurable) | Relay forwarding, probe responses (the relay in the nett daemon) |
| | TCP 443 | TLS transport entry, CONNECT (nett-relay); shared with Edge on an entry node |
| | UDP obfuscated port (random, configurable), when the relay offers it | Obfuscated relay forwarding (design/obfuscation.md) |
| `public` nodes that offer an obfuscated port | UDP obfuscated port (random, configurable) | Obfuscated WireGuard to the node itself (design/obfuscation.md, ADR 0031) |
| Entry node | TCP 80, 443 | Website, certificate validation |
| Smart gateway (home broadband) | Router maps the WireGuard port and relay port | Other members connect to it directly; can act as a relay |
| M2 | UDP 443 | QUIC transport |

The WireGuard port of a `dial-only` member is assigned by the system and the desired state carries no port: nobody connects to it at a pre-agreed address. Public direct candidates point to `public` nodes, hole punching uses the mapped address observed at run time (section 6.1), and the LAN direct and IPv6 direct candidates generated by the Hub that point to it (section 6) use the actual port it reports. Multiple members on the same host therefore do not contend for ports, for example the native member and nett's container on a Mac (the container's UDP may keep its original port when forwarded out). If a port that the mesh itself uses locally is assigned, it is reallocated: the probe port of section 7.2 and the loopback ports of the TLS transport (section 5.3) and of the obfuscated transport (design/obfuscation.md section 7) are within the Linux ephemeral port range. The port does not change while the interface exists: on Linux the interface persists across restarts of the nett daemon and so does the port; on userspace platforms the interface is rebuilt with the process and the port changes with it, the connection is initiated by the `dial-only` end, and the peer learns the new address from the handshake arriving from the new port (WireGuard roaming). When the desired state changes from carrying a port to carrying none, the current port is kept. The port of a `public` member can change while it runs, for example to step around a network that blocks it: on Linux the interface takes the new port at once and the probes on the WireGuard port (section 7.1) move with it; on userspace platforms the new port takes effect when the nett daemon restarts. Relays forward to the new port as soon as their assignment carries it (section 5.2).

Reachability detection: the WireGuard port does not respond to unauthenticated packets and cannot be probed directly from outside, so reachability is judged by whether an actual handshake succeeds; the relay port and 443 are probed with authenticated probes initiated by other `public` nodes.

## 6. Candidate paths

For every pair of members that need to connect (derived from access rules, site.md section 6), the Hub computes a list of candidate paths and delivers it through the `mesh` partition; members measure and select locally.

| Candidate path | Generation condition |
|---|---|
| LAN direct | One for each LAN address the peer lists in its status (status.md section 6), at the peer's WireGuard port, whatever network the two are on; probes decide which ones work. Tailscale finds local paths the same way (magicsock in tailscale main at c4d689c: each node hands every peer the addresses of its interfaces, and peers try them all), so machines on one LAN, on routed LANs of one site (two VLANs, for example) or on a network the Hub is also on reach each other directly, and nothing is inferred from where the Hub sees them. Generated by the Hub, IPv4 first, leaving out an address this machine has itself, which leads back to this machine. An authenticated direct probe from a LAN address that is none of this machine's candidates to that peer adds the address as a LAN direct candidate of the pair for as long as the peer's probes keep coming from it, and drops it 45 seconds after the last one, as Tailscale adds the source of a ping (`addCandidateEndpoint`; a public source is learned by hole punching, section 6.1); this matters where both ends measure, between two `dial-only` members (section 8.4): when another NAT sits inside the LAN, such as a container on a Mac reaching a NAS through the Mac's address, that address is where the peer can be reached. Only a probe sent later than every probe already received from that peer adds its source, so a probe replayed from another address adds nothing |
| Public direct | At least one side is `public`. Reachability is judged separately for IPv4 and IPv6: a member behind NAT on IPv4 but reachable from outside on IPv6 counts as `public` on IPv6 |
| Via relay | The relay on the other end over TLS, when that end runs one and this end decides the path (section 5.1); then every relay other than the two ends, in the order of the relays' node IDs, UDP before TLS, within the candidate limit (site.md section 6); measurement then picks among them. Preferring relays located between the two ends, from a line quality matrix, comes in M2 (section 18) |
| Multi-hop relay (M2) | Single-hop relay quality is poor and a two-segment relay is clearly better |
| Hole-punched direct | Both sides are `dial-only` and both have a global IPv6 address, or at least one is behind a cone NAT (section 6.1); hole punching when both ends are behind symmetric NAT is in M2 |

Each path can also be combined with a transport (UDP, TLS). The number of candidates has a limit (default 6 per pair of members); the LAN direct candidates come in addition, at most 8, as many as the LAN addresses a member lists. The candidates of a `dial-only` member include at least paths through two different `public` nodes (architecture.md section 12.3).

**Active links** (with traffic in the last 10 minutes) are measured fully; **idle links** are measured only at a low frequency, and the first time there is traffic, the link is established immediately on the best candidate.

### 6.1 Hole-punched direct

When both ends are behind NAT or a firewall, both sides send packets to each other at the same time, open mappings on their respective NATs, and then connect directly. Hole-punching probes are **sent from the WireGuard port** and use WireGuard's own NAT mapping (section 7.1). During hole punching, traffic continues on the current path, switching happens after the punched path is verified, and failure does not affect the connection (ADR 0021):

- **Mapped address**: the actual source address of a member's WireGuard port as seen by a `public` node is the mapped address the NAT allocated for it, attached to the response to a probe of that member (told only to that member). Direct probes are sent from the WireGuard port (section 7.1), and the source address in the peer's response is that address; probes of a UDP relay are sent from the WireGuard port too, and what nett-relay attaches to the response is the WireGuard address of this member bound per section 5.2 (when not yet bound, the source of the probe). From this the mesh obtains the machine's mapped address, shows it in status (which nett-node reports to the Hub through `LinkReport`), and tells the peer directly in the hole-punching proposal; the hole-punching candidate itself carries no addresses (site.md section 6);
- **NAT type**: a `dial-only` member connects to at least two `public` nodes (section 6). If the mapped addresses (IP and port) seen by two `public` nodes are the same, it is judged a cone NAT (mapping independent of destination address), and if different, a symmetric NAT. Hole punching is attempted when at least one end is a cone NAT: the port a symmetric end allocates for a new destination cannot be predicted by the other side, whether it succeeds depends on the filtering behavior of the cone end, and the attempt itself does not affect the connection; it is not attempted when both ends are symmetric. It is re-judged after a network change;
- **IPv6**: when both sides have a global IPv6 address no mapped address is needed; the stateful firewall of the router lets packets coming back from the other side through, and both sides simply send at the same time. The address used is the source address seen by the `public` node (when temporary addresses are enabled on the machine, the address used for outbound traffic changes); when there is no `public` node reachable over IPv6, the source address chosen by the machine's route to the peer's address is used;
- **Procedure**: the decider sends a hole-punching proposal carrying a round number through the current tunnel (the same mechanism as the switch proposal of section 8.4, messages in section 7.2), attaching this machine's NAT type, IPv4 mapped address and IPv6 address; the peer confirms, attaching its own three items. When both ends are symmetric it gives up here. Otherwise both sides immediately send direct probes (`0x82`) from the WireGuard port to each of the other side's addresses, once every 200 milliseconds, for at most 10 seconds. Receiving a response to its own probe shows that both directions work; the punched address is the source from which a probe or response was actually received: the port a symmetric NAT allocates for a new destination cannot be predicted by the other side, and the cone end learns it from the source of the peer's probe. The punched path serves as a direct candidate and is compared with the current path per section 8.2; to switch over, because both sides are `dial-only`, both ends switch together per section 8.4 (proposal through the tunnel, the target being the punched direct path). Changing the endpoint needs no new handshake, and the existing session sends directly over the new path;
- **Failure**: if it is not punched through within 10 seconds it is given up, and the connection stays on the current path, unaffected;
- **When to attempt**: it may be attempted when a link has just been established or when there is traffic; after a failure for the same pair of members it is retried with exponential backoff (at most 1 hour); it is re-evaluated immediately after a change of mapped address or NAT type. After a path is punched through, it is compared with the current path per section 8.2 and not switched to if it is no better than the current path;
- **Keeping**: both sides set a persistent keepalive of 25 seconds to maintain the mapping (section 4). When the peer changes network its mapped address changes and the punched path becomes invalid; this is handled as a failure switch (section 8.2), and it is re-evaluated on the new network afterwards;
- **M2**: hole punching when both ends are behind symmetric NAT (port guessing).

## 7. Measurement

| Measurement | Method | Frequency |
|---|---|---|
| Current path | Send probes inside the tunnel (to the peer's mesh address) and measure round-trip time and packet loss; when the current path is direct, additionally send direct probes from the WireGuard port to the peer, and the response carries back the machine's mapped address (section 6.1) | In the tunnel: every 1 second for active links, extra probes when a failure is suspected (section 8.2); direct probes as for candidates (every 15 seconds for active links) |
| Candidate paths | Probe packets outside the tunnel: member -> `public` member, member -> relay, and through the relay to the peer and back (through probes, ADR 0029); direct candidates and UDP relays are probed from the WireGuard port (section 7.1); a path via a relay is measured by its through probes once one has come back, and estimated by combining segments otherwise | Every 15 seconds for active links; for a candidate that has never responded, every 1 second within 1 minute after the first probe (the peer may not have started yet at startup); when the current path is clearly worse (round-trip time doubled relative to the best value since switching to it and at least 10 milliseconds more, or 2 or more of the last 10 in-tunnel probes lost), candidates of the same kind every 3 seconds; when the current path is not of the best kind, candidates of better kinds every 1 second, except one that has never responded, which after its first minute is probed on Tailscale's schedule for an address it has had no reply from: every 5 seconds while the current path goes through a relay, every minute while it is direct, and not at all while that direct path's round-trip time is at most 5 milliseconds (ADR 0021); right after switching away from a better-kind path because of its first failure, that path is probed every 50 milliseconds for 15 seconds (after the first response, probe once more immediately to confirm, and handle a response as soon as it arrives without waiting for the next timer tick), except a path left while it was losing packets (section 8.2); when a failure is suspected, all candidates once immediately; idle links every 5 minutes |
| Line quality matrix | Aggregates the segment measurements and reports to the Hub | Every minute |

- Metrics: round-trip time (exponential moving average; when one measurement differs from the average by more than a factor of two the new value is adopted directly, so there is no need to wait for the average to catch up after a path change), packet loss rate (sliding window), jitter;
- Timeout of in-tunnel probes: twice the round-trip time plus 100 milliseconds, bounded between 300 milliseconds and 1 second, used only to enter suspected failure (section 8.2). A timed-out probe waits another 10 seconds: a late response is still counted in the round-trip time; it is recorded as lost only when overtaken by the response to a later probe, or when there is still no response after 10 seconds. When the machine's own traffic fills a slow link and the queue is deep (rate-limited VPS, home broadband with a very deep upload buffer), responses are delayed by several seconds; this is queuing, not packet loss;
- A link with traffic: the number of bytes WireGuard sent or received for this peer changed within the last 30 seconds;
- Probe packets carry authentication: between members a checksum is computed with a key derived from the two sides' WireGuard keys; probes sent to a relay use the token delivered at assignment;
- Responders: probes sent to a relay are answered by nett-relay on the relay port; in-tunnel probes are answered by the mesh on the mesh address; probes of direct candidates (public direct, LAN direct, hole-punched) are sent to the peer's WireGuard port and answered by the peer's mesh (section 7.1) whatever address they come from, as Tailscale answers every authenticated ping: the probe needs a key only members hold, and WireGuard on the same port answers authenticated handshakes from any address too. The "LAN address" on a cloud host's network card often corresponds to a public address through 1:1 NAT, so all responders **make no response at all to unauthenticated probes**;
- Probe traffic has a budget: no more than about 1 KiB/s per pair of active links; the only exception is the 15 seconds right after switching away because of a failure, where the quick-recovery probe round trips are about 2.5 KB/s.

### 7.1 Probing on the WireGuard port

Probes of direct candidates, of hole punching (section 6.1) and of UDP relays are sent from the WireGuard port, so they measure the addresses WireGuard itself uses: its own NAT mapping (ADR 0021), and any network on the way that treats the WireGuard port differently from the machine's other ports, such as a firewall rule or a block keyed on the port. A leg to a relay measured from another port can look healthy while the tunnel through that relay cannot cross it, and the decider would keep moving onto that relay and back:

- **Linux kernel WireGuard**: the mesh uses a raw socket to build UDP packets with the WireGuard port as source port and sends them (so `CAP_NET_RAW` is needed). Receiving uses nftables: the mesh adds a rule on the input chain through netlink, handing to itself only copies (`log`, nfnetlink_log) of packets addressed to the WireGuard port whose first byte is a probe type that arrives there (a direct probe, a direct response, a relay response), and of WireGuard's cookie replies (type 3, 64 bytes, section 8.4); other packets only incur a few extra rule matches and are not copied. Cookie replies are handed to WireGuard as usual, and the mesh only reads and does not respond. These probe packets are not WireGuard messages, and kernel WireGuard drops them on receipt. A raw socket is not used for receiving: the kernel first copies every incoming UDP packet to the raw socket and then filters, which was measured to reduce WireGuard throughput by about 7% (prototype.md section 9);
- **Userspace platforms**: the mesh already holds the WireGuard UDP port and distinguishes probes from WireGuard messages by the first byte; a received cookie reply is handled per section 8.4 and then handed to WireGuard as usual;
- The first byte of a probe message differs from all four WireGuard message types; probes carry authentication (see above), unauthenticated packets get no response, and the externally visible behavior of the WireGuard port is unchanged;
- Probes of a UDP relay are answered by nett-relay on the relay port, back to the WireGuard port. Probes of a TLS relay are sent from the mesh's own port to the transport's loopback port and travel inside the TLS connection the tunnel uses (section 5.3);
- Through probes (section 7.2) go out the same way as the relay probes beside them, and the relay forwards each to the peer's WireGuard address as it forwards WireGuard's data; the peer's answer and its forwarded reply arrive on the WireGuard port, over TLS through the TLS transport, which hands everything but relay responses to the WireGuard port. Both types are among those the Linux rule copies and the userspace data plane hands to the mesh.

### 7.2 Probe messages

The first byte of a probe message is the type, different from all four WireGuard messages (1-4). All fields have fixed length, and packets that are malformed or fail authentication get no response.

| Type | Sender and destination | Content |
|---|---|---|
| `0x80` in-tunnel probe | Member -> probe port `41821` on the peer's mesh address (listening only on `nett0`) | Sequence number |
| `0x81` in-tunnel response | Returns along the same path | Sequence number; the responder's latest measurements to each relay (round-trip time, packet loss rate), used to estimate the other segment of a path via a relay |
| `0x84` switch proposal | Decider -> probe port on the peer's mesh address (through the current tunnel, section 8.4) | Round number, kind of target (relay, the punched direct path, or a LAN direct path, for which the follower takes its own LAN direct candidate with the best measurement), number of the target relay (first 8 bytes of the SHA-256 of the relay node ID) |
| `0x85` switch confirmation | Returns along the same path | Same as above |
| `0x86` hole-punching proposal | Decider -> probe port on the peer's mesh address (through the current tunnel, section 6.1) | Round number, NAT type (unknown, cone, symmetric), IPv4 mapped address, IPv6 address (empty if none) |
| `0x87` hole-punching confirmation | Returns along the same path | Round number, the responder's NAT type, IPv4 mapped address, IPv6 address |
| `0x82` direct probe | Member's WireGuard port -> direct candidate address on the peer's WireGuard port (section 7.1) | Number of the sender's mesh public key (first 8 bytes of the SHA-256 of the public key), sequence number, send time, checksum |
| `0x83` direct response | Returns along the same path | Sequence number, the source address seen by the responder (mapped address), checksum |
| `0x90` relay probe | Member's WireGuard port -> relay port (section 7.1); TLS relays are reached from the mesh's own port through the TLS transport (section 5.3) | Token number, sequence number, send time, checksum |
| `0x91` relay response | Relay -> member | Sequence number, the WireGuard address of this member bound by the relay per section 5.2 (mapped address, section 6.1; the source of the probe when not yet bound or over TLS), checksum |
| `0x92` through probe | Member -> relay, as its relay probe (section 7.1) -> the receiver's bound address (section 5.1) | Number of the sender's mesh public key, sequence number, send time, number of the receiver's mesh public key, a checksum with the pair's direct probe key over those, a checksum with the sender's relay token over everything before it |
| `0x93` through reply | Receiver -> the source of the probe (the relay) -> the source of the probe at the relay | Number of the replier's mesh public key, sequence number and send time echoed, number of the original sender's mesh public key, a checksum with the pair's direct probe key |

- In-tunnel probes carry no separate checksum: WireGuard has already authenticated the source by `AllowedIPs`, and the mesh answers only probes whose source is the mesh address of an admitted member;
- All checksums are HMAC-SHA256, truncated to 16 bytes, covering the rest of the message; those whose send time differs from the receiver's clock by more than 30 seconds are dropped, limiting replay; a response is never longer than the probe, so it cannot be used to amplify traffic;
- The key of direct probes is derived from the two sides' mesh keys: the result of X25519 (this machine's mesh private key, the peer's mesh public key) goes through HKDF-SHA256 (with "nett direct probe v1" distinguishing the purpose, and the two public keys ordered by bytes as additional information) to give 32 bytes; only admitted members can compute it. The key of relay probes is the token delivered at assignment;
- **Through probes** (ADR 0029): with each probe of a candidate through relay R, A also sends a through probe; R checks the token checksum and the link and forwards it to B, which checks the direct checksum, that it is the named receiver and the send time, and answers to where the probe came from; R forwards the answer once to where the probe came from. Once a through reply has come back through R, a path through R is measured by its through probes alone, as the whole path: R answering A's own probe no longer counts as the path working. After 30 seconds with no through reply through R while R answers A, the path through R is estimated from the segments again, as below, and held off as broken beyond R until B reports its leg to R without loss (section 8.2): a leg that broke stays avoided, and a peer or relay gone back to an older release, which never answers through probes, reports its leg working and R is taken again. The relay on B's own machine is probed the same way: its through probe also shows that B's mesh and WireGuard answer;
- Without through replies, the round-trip time and packet loss rate of the path A -> R -> B are estimated by combining A <-> R measured by A with B <-> R brought by B in the in-tunnel responses (a relay B has probed without any response is reported as fully lost, so A knows the path through it is down); when the tunnel is interrupted the most recent values are used. Until B has reported its leg, A's probes show only that the relay answers, not that the path through it works, so the path has no round-trip time of its own: it is not a better path to move to (section 8.2), and a failover takes it only after the candidates whose whole round trip is known, which are direct paths, the relay on B's own machine (its leg to B is B's loopback) and relays B has reported. Tailscale likewise uses a relay path only once a ping through it has come back from the peer (relaymanager.go in tailscale main at 1a4f4eb).

## 8. Path selection and switching

### 8.1 Scoring

```
score = round-trip time + loss penalty + jitter penalty + path type preference + transport penalty + relay load
```

- Path type preference: LAN < public direct (including hole-punched direct) < via relay < multi-hop; obfuscated UDP to the peer's own obfuscated port comes first among the direct paths (design/obfuscation.md section 5);
- Transport penalty on a relay path, on top of the via-relay preference: obfuscated UDP 5 milliseconds below UDP, TLS 20 above it (design/obfuscation.md section 5);
- Relay load: rises when the relay approaches the traffic limit the user set for it. The limit is only a capacity mechanism; nett does not care how machines are billed or how upper-layer services use bandwidth;
- Policy overrides are supported (`spec.policy` of `links`): prefer direct, pin to a given relay, pin the transport.

### 8.2 Switching rules

| Situation | Rule |
|---|---|
| Current path suspected failed | 2 consecutive in-tunnel probes without response: immediately send 3 extra probes on the current path (200 milliseconds apart) and probe all candidate paths at the same time |
| Current path failed | All extra probes lost (about 3 seconds from the disconnection), or packet loss above 30% for 3 seconds: switch **immediately** to the best candidate just measured, those whose whole round trip is known first (section 7.2); when all UDP candidates are unreachable, switch directly to TLS without trying UDP relays one by one. When the failed path goes through a relay that still answered this end's probes since the suspected failure, the break lies beyond the relay, on its leg to the peer, which every transport through that relay shares: the switch goes to a candidate through another relay or direct, and to that relay's other transport only when none of them responded. This end's probes of that relay say nothing about the broken leg, so the relay counts as recovered only when the peer reports its leg to the relay without loss in a report that covers the time since the break (the peer probes its relays every 5 seconds), or after 10 minutes. When the peer's packets are still arriving, all extra probes being lost is not a failure: since the suspected failure, the bytes WireGuard received from this peer are still growing (the engine reads every 100 milliseconds), and an in-tunnel response (including late ones) was received within 10 seconds, which shows the path works and is only queuing; all paths pass the same bottleneck, switching and re-handshaking are of no help, and normal probing resumes. When the peer's packets are arriving but no response at all within 10 seconds (only one direction works), it is judged a failure as usual. Likewise, when a late response was received within 10 seconds (queuing), a too-high packet loss rate is not a failure either: the loss is from a full queue dropping packets, and changing to a path that passes the same bottleneck is of no help; a path that does not share the bottleneck has a much shorter round-trip time, and is switched to as a better path of the same type |
| Path of a better type recovers | Currently via relay while some direct candidate responds, or currently via TLS while some UDP candidate responds, in 2 consecutive probes, with its whole round trip known (section 7.2): switch over (a relay chosen for being much faster, in the row below, returns to direct by its own rule). After the first failure of this path, it is probed every 50 milliseconds for 15 seconds after switching away, and after recovery the switch back takes about 0.1 seconds; from the second failure of this path within 10 minutes, the waiting time doubles with the failure count (starting at 10 seconds, at most 5 minutes); when a path fails without ever having connected (for example the first handshake has not completed), the first time does not count as a failure. A path left while it was losing packets, for high packet loss or for a better score while in-tunnel probes were being lost, still answers most probes, so replies in a row say nothing about its loss rate: it is probed every second, without the 50-millisecond recovery, and switched back to only when at least 60 of its probes since then have results and at most 2 of the last 60 were lost (about a minute), on top of the waiting above |
| Better path of the same type | Switch only to a candidate whose whole round trip is known (section 7.2), when its score is better than the current by at least 15% and at least 10 milliseconds, and this lasts 30 seconds (hysteresis); when 2 or more of the current path's last 10 in-tunnel probes were lost and this candidate responded to 2 consecutive probes, switch after 5 seconds. The hold is on the improvement: candidates of the same quality take turns at being the best by a fraction of a millisecond, and the switch goes to the best one when the hold ends |
| Relay much faster than direct | When the current path is public, hole-punched or obfuscated direct, is not queuing (no late in-tunnel reply within 10 seconds: a full uplink slows every path alike), and the pair carries less than 2 Mbit/s: a UDP or obfuscated UDP relay candidate, from the obfuscated path to the peer's own port an obfuscated one only (being faster never gives up obfuscation, design/obfuscation.md section 5), whose round-trip time includes both legs (the peer's leg arrives with its in-tunnel replies, section 7) scores at most 70% of the current path and at least 20 milliseconds lower, for 30 seconds (some such relay all along, not necessarily the same one), then switch to the one that scores lowest. Back to direct when the direct candidate's score comes within 85% of the relay's, when the pair carries more than 2 Mbit/s (measured over 10 seconds), or when the relay fails as usual. Long direct paths, for example across a congested border, are often much slower than a path through a well-placed relay; a relay's uplink is often far narrower than a direct path, so bulk transfers stay direct, and per-relay traffic limits come in M2 (section 18). Pairs that are both `dial-only` switch together by proposal (section 8.4) and keep the order of path types |

Path types from best to worst: LAN direct, obfuscated UDP to the peer's own obfuscated port, public direct (including hole-punched direct), via relay, multi-hop; on the same relay obfuscated UDP is better than UDP, which is better than TLS (design/obfuscation.md section 5). When several better types answer, the switch goes to the best of them. A relay much faster than direct, as in the table, comes before direct. The parameters are based on alignment with Tailscale (ADR 0021) and are adjusted according to measurements at the prototype gate.

### 8.3 Who decides

WireGuard automatically updates a peer's endpoint from the source of the most recent authenticated packet (the roaming mechanism). If both sides choose paths on their own, they overwrite each other. So **for each pair of members one side decides the path**:

- When one side is `dial-only` and the other is `public`, the `dial-only` side decides;
- Otherwise the side with the smaller member ID decides;
- The other side follows automatically through the roaming mechanism and does not change the endpoint itself (except when both are `dial-only`, see section 8.4).

The roaming mechanism of kernel WireGuard cannot be turned off: after a switch, packets still in flight or late on the old path change the decider's endpoint back to the old path when they arrive (leaving a TLS path is handled separately, see section 5.3). So the decider **keeps maintaining the desired endpoint**: it checks at every probe, changes it back if it finds it changed, with no time window. The decider's desired endpoint is always a public address or relay address and does not change when the peer changes network, so continuous correction does not harm normal roaming. For a hole-punched direct path the desired endpoint is the peer's mapped address; after the peer changes network this path becomes invalid and is handled per section 6.1.

### 8.4 Switching to a relay path

A relay can only forward sessions whose handshake it has seen (section 5.1). This applies when the path switches to a relay that has not yet handled this link, and when the current relay has lost the link's index (for example a session established just before a crash; it shows as the current relay still answering probes while in-tunnel probes fail and the peer's packets no longer arrive, and on a suspected failure the handshake is first redone once on the same relay):

- **Re-handshake**: the decider removes this peer from WireGuard and adds it back with the new endpoint; the next data packet immediately triggers a new handshake, from which the relay builds the index. The cost is one handshake round trip, and upper-layer TCP connections are not affected;
- **Confirming the handshake completed**: when the old path is still usable (for example switching to a faster relay), packets sent over it before the switch keep arriving at the peer after the switch; if one of them arrives exactly between the peer processing the handshake initiation and sending the response, the roaming of the peer's WireGuard changes the endpoint back to the old path, and the response is then sent to the old relay, which has not seen this handshake, and dropped. The roaming of kernel WireGuard cannot be turned off, so after the re-handshake it must be confirmed to have completed: wait the larger of the old path's round-trip time and twice the new path's round-trip time, plus 20 milliseconds (at most 1 second; in this time all packets on the old path have arrived), advancing the runtime every 25 milliseconds meanwhile; at expiry, if the latest handshake time reported by WireGuard is still empty, no in-tunnel response has been received, and this peer has traffic, re-handshake once more on the same relay. If that still fails, it is left to the suspected-failure detection (section 8.2);
- **When the peer is under load, wait for WireGuard to retry with the cookie**: when the peer's WireGuard is pressed into the under-load state by a large number of handshake initiations, it replies only with cookie replies and accepts only handshake initiations carrying the cookie (`mac2`); after receiving the cookie, the initiator's WireGuard retries with it only after about 5 seconds (`REKEY_TIMEOUT`, plus up to 1/3 second of jitter). A re-handshake removes and re-adds the peer, which loses the cookie, so when the mesh receives a cookie reply from this peer's current endpoint while the tunnel is not yet established, it neither re-handshakes nor switches away as a suspected failure, but waits 5.4 seconds plus twice the new path's round-trip time plus 20 milliseconds; if a cookie is received again in the meantime it waits another round, at most two rounds per path (about 11 seconds), and the count restarts after the handshake completes. The cookie reply itself cannot be verified: an attacker who can forge the source address of a relay or peer can at most delay one failover by about 11 seconds. For measurements see prototype.md section 9 (scenario 20);
- **When both sides are `dial-only`, both ends switch together**: the follower's NAT has no mapping to the new relay, packets from the new relay cannot reach it, and it cannot follow by roaming. Starting from the first relay in relay-number order, both ends measure the tunnel, detect interruptions and maintain the desired endpoint; only the decider chooses the optimum. A new desired state that changes a pair's candidates (for example a LAN address the peer reports) keeps the pair on the path it uses, with the measurements of the candidates that remain and the punched and learned direct paths; only when that path is no longer a candidate does the pair start over from the first relay. Starting over while the other end stays where both were would break the tunnel until they meet again; Depending on the conditions at the time there are three ways:
  - The current path is usable (switching to a better path, or the loss rate is too high but the tunnel can still carry messages): the decider sends a switch proposal carrying a round number through the current tunnel (the same port as in-tunnel probes); the follower replies with a confirmation and switches after about 100 milliseconds (letting the confirmation go out first over the old session), and the decider switches after receiving the confirmation. If no confirmation is received it is resent every 300 milliseconds, and if still none after about 2 seconds it switches as usual, and if an interruption follows, recovery is by the two ways below. While the pair has traffic, a better path is proposed only once the tunnel has answered since the pair moved onto the current path: before that the proposal could not arrive and the decider would switch alone. Messages of expired rounds are dropped directly; the round number has Unix seconds as its lower bound and only increases across restarts too;
  - The current path is interrupted: the proposal and confirmation are relayed through the Hub (`PathSwitch`, protocol.md section 5). The mesh does not connect to the Hub: it hands the message to nett-node in the same process over the coordination connection, a socket pair between the two (status.md section 4.2); nett-node sends it to the Hub, and the Hub passes it to the peer's nett-node, which hands it to its mesh the same way. The message is the same proposal or confirmation with the send time and an HMAC-SHA256 checksum (truncated to 16 bytes) under a key derived from the two mesh keys like the direct probe key (section 7.2, with "nett path switch v1"): the Hub can delay or drop it but cannot forge it, and messages more than 30 seconds off the receiver's clock are dropped. While nett-node reports the Hub connected, the decider proposes through the Hub the relay path a failover would take (section 8.2): of those that answered since the interruption was first suspected, so that a relay stopped together with the current one is not chosen on replies from before, and, as after a failover, the earlier replies of those that did not answer no longer count toward a better path; when none answered, the first other one in relay-number order. It resends every second, and switches when the confirmation arrives; without a confirmation after 3 sends it rotates by time slot as below. The follower waits up to 4 seconds for a proposal through the Hub before it rotates, and a proposal that arrives during rotation ends the rotation. Each end carries out a switch both ends agreed on before it measures the tunnel in the same step, so an outage it measured on the path it leaves does not start a wait of its own after the pair has moved;
  - Neither the current path nor the Hub is available: **rotate by absolute time slot**. Both sides use the system clock to compute `slot = floor(unix time / 15 seconds)` and pick the `slot mod n`-th among the candidate relays sorted by relay number: on detecting an interruption they immediately choose by the current time slot and re-handshake, and change again at the start of each later time slot; the choice depends only on time, regardless of when each side detects the failure. Each side takes "the machine's in-tunnel probe received a response" as bidirectional confirmation, stops on this relay after confirmation, and re-enters rotation on the next interruption. The prerequisite is that the clock error between the two sides is far smaller than 15 seconds: time slots are used only when the machine's clock error is within 2 seconds (according to the most recent comparison with the Hub and the system's time synchronization status; on Linux the maximum error reported by the kernel, i.e. `maxerror` of `adjtimex`), otherwise it falls back to random-interval retries: every 5-15 seconds it picks a random relay and re-handshakes; on a clock jump it recomputes from the new time. The first address binding on the new relay follows section 5.2: a handshake initiation that arrives first waits in the relay's pending table for 5 seconds for the other end's handshake initiation, and after expiry WireGuard's own retry of about 5 seconds fills in, so the time slot is no shorter than 15 seconds. When the two sides' candidate list versions differ they may be unable to meet, and can only wait for the Hub to recover. This way is best-effort recovery and promises no recovery time;
- The time from the start of a switch to bidirectional recovery, and the recovery time after a relay restart, are measured at the M1 prototype gate (section 18).

### 8.5 Hub or nett-node offline

Candidate paths, relay assignments, admission material and keys are all kept locally; measurement, scoring and switching are done entirely locally on the member. While the Hub is offline, new candidate paths or relay assignments cannot be added, and existing ones remain usable. While nett-node is stopped (after a panic it starts again 5 seconds later, ADR 0013), the mesh measures, switches and answers DNS as usual.

## 9. Transport

| Transport | Phase | Purpose |
|---|---|---|
| UDP | M1 | Default |
| TLS (WebSocket, 443) | M1 | When UDP is unavailable; carried by the TLS transport in the nett daemon (section 5.3) |
| QUIC (UDP 443) | M2 | When UDP is available but ports are restricted or the traffic pattern is identified |
| Obfuscation wrapper | M2 | As needed |

## 10. LAN smart gateway

- The smart gateway advertises one or more LAN prefixes; **advertising a prefix widens the range reachable from the mesh and is a high-risk change** (action `node.advertise_routes`, requires a signature, and the signed artifact is verified by the other members);
- The smart gateway enables IP forwarding and performs **source NAT** on traffic entering the LAN from the mesh, so replies are not intercepted by other VPNs or proxies on LAN hosts. The smart gateway uses two addresses on the LAN, **translating by source class** (ADR 0015):

| Mesh source | Translated to | How LAN services treat it |
|---|---|---|
| The Edge address of an entry node | Entry address | Services that need the real IP configure it as a trusted proxy and trust the `X-Forwarded-For` it sends |
| Other members and devices | Ordinary address | Trust no forwarding headers |

- The translated address **must never be a loopback address**; when forwarding to a service on a host, use that host's LAN address (in Docker on macOS, traffic reaching the host through `host.docker.internal` has source `127.0.0.1`);
- Advertised prefixes deny access by default (section 12). When advertising, the console shows the notice: "Services in the LAN that trust by source prefix will trust all permitted mesh traffic";
- Other members on the same LAN can discover each other and prefer LAN direct;
- The gateway device's own WireGuard can serve as a backup path: it is attached as an ordinary peer with a fixed endpoint and does not take part in automatic path selection;
- On NAS-type systems, the TUN, IP forwarding and NAT capabilities that the smart gateway needs are confirmed one by one by capability detection;

## 11. Hostnames

- The suffix defaults to `nett.internal` (`.internal` is a top-level domain reserved for private networks) and can be changed when the Hub is initialized;
- Each node automatically gets `<node name>.nett.internal`; users can add aliases (the `hostnames` resource), for example naming a service and pointing it to the member where it runs;
- Hosts on the LAN do not need nett installed; when a name is needed, the user adds an alias pointing to its LAN address within an advertised prefix;
- The mesh runs a minimal DNS responder only on the mesh address, answering names under that suffix (names-and-diagnostics.md section 2);
- **Upstream forwarding**: only the mobile gateway forwards other queries for devices, accept queries only from device addresses, and rate-limit them, so they do not become open forwarders;
- Local resolver configuration: on Linux, split-domain resolution for that suffix is set on `nett0` through systemd-resolved; on macOS, `/etc/resolver/<suffix>` is written;
- Devices: the exported WireGuard configuration lists the mobile gateway's mesh address as its DNS server;
- Edge configuration uses mesh addresses and not hostnames: Edge often runs in a container, which by default uses the host's upstream DNS and cannot resolve the mesh suffix;
- **Hostnames are only for locating and are not a basis for identity**: hostnames are delivered by the Hub and are not signed. When you need to confirm who the other side is, use the local identity query (`nett whois <address>`, and the interface of the same name on the local socket), which the mesh answers from verified admission material; the Hub's `whois` interface is for console display, and its result is a claim by the Hub.

## 12. Access control

- **Default deny** (ADR 0023): a new connection not allowed by any rule is always denied; the same applies between nodes and for advertised prefixes;
- **The user's devices**: by default they can reach all members and advertised LAN prefixes; a device added as limited reaches only what rules allow, like a member. The signing tool writes this default into the signed rule set as one allow rule (devices.md section 5);
- **Edge address**: by default it cannot reach any target; which hosts and ports it can reach is written by the user in the access rules (part of the signed access rule set, and widening requires a signature). On a node with the `edge` role, the mesh, according to the identification method declared in the node policy (the address of the container where Edge runs, or the system user when running natively), rewrites the source of mesh traffic sent by Edge to the Edge address; and in both directions, local output and container forwarding, drops packets whose source address is the Edge address but which do not come from Edge (ADR 0015). When Edge fetches from an origin service on the same host it does not pass through the mesh and is not bound by these rules;
- The rule set is delivered as a whole as one signed artifact, with a version number that only increases; adding a deny rule or deleting an allow rule is narrowing and can take effect directly without a signature;
- **Matching**: rules apply only to new connections; established connections and packets related to them (replies, ICMP errors) pass directly. Rules are matched in rule set order, and the first matching rule decides allow or deny; when no rule matches, the connection is denied. The mesh's own in-tunnel probes are not affected by access rules. The same holds when there is no rule set;
- **What is signed is the expanded result**: rules are written with selectors such as nodes, devices and tags; a source can also select a node's Edge address (written as that node's `edge`), to allow Edge to reach specified services. The signed artifact contains the expanded member IDs, addresses and ports. If a change of tags (for example adding a tag to a node) makes the expansion larger, it is widening access and requires a signature; nodes execute only the expanded result in the signed artifact and do not expand by tag themselves;
- Rules are compiled into filter rules local to each member: Linux uses nftables, attached at `prerouting` with priority before Docker's destination NAT, matching traffic entering from `nett0`, so traffic to the local machine, to Docker published ports and traffic that needs forwarding (mobile gateway, smart gateway) all passes through; matching is by source mesh address, destination address and port, with IPv4 and IPv6 treated the same. On userspace platforms the mesh filters before forwarding;
- **Deny first, then open**: at startup the filter rules are installed first, and peers are added afterwards; when a rule update fails, deny is kept and an event is reported;
- WireGuard's `AllowedIPs` guarantees that source addresses cannot be forged.

### 12.1 Served ports

A service that listens only on `127.0.0.1` is reached from the mesh through a port its machine serves (ADR 0028), set with `nett site serve` (site.md section 5.3) and signed in the node policy (`serve`, auth.md section 10.5):

- **Listening**: once the mesh interface has its addresses, the mesh listens on each served TCP port on this machine's mesh addresses, IPv4 and IPv6, bound to the mesh interface (`SO_BINDTODEVICE` on Linux, `IP_BOUND_IF` on macOS). Ports are added and removed with the node policy; removing one closes its connections;
- **Accepting**: a connection whose peer address is outside the mesh prefixes is closed at once. A host on the LAN can address a packet to the mesh address through another interface, which Linux accepts by default and macOS accepts while IP forwarding is on; a forged mesh source does not complete the handshake, because the reply is routed into the mesh interface;
- **Forwarding**: each connection is copied unchanged to `127.0.0.1` on the same port, over plain TCP; the service sees `127.0.0.1` as its peer. A service that refuses the connection or does not answer within 10 seconds gets the mesh connection closed;
- **Who connects** is decided by the access rules, as for any port on the machine: the filter runs before the listener, between members by rule, and the user's devices by default;
- **Bounds**: 16 served ports per machine; 256 forwarded connections, beyond which a new one is closed at once; 8 KiB of buffer per direction; TCP keepalive on both sides (60 seconds idle, then 10-second probes, 3 lost) closes a connection whose peer has gone, while an idle connection whose peers remain stays open;
- **Failure**: a port that cannot be bound, for example because another program holds it on all addresses, is listed as a problem in `nett status` and retried like the DNS responder (section 15); the other ports and the mesh are unaffected.

## 13. Phones and the mobile gateway

- The mobile gateway is a `public` node with the `gateway` role (the role is granted by the signed node policy): it accepts devices as peers on `nett0` and carries device traffic into the mesh through the path layer;
- The configuration exported to a device has one peer, its mobile gateway, with the mesh prefixes and the LAN prefixes advertised in the mesh as `AllowedIPs`; beyond the gateway the path layer chooses the path (ADR 0008);
- **Device ownership is per credential**: in WireGuard an address can appear in the `AllowedIPs` of only one peer, so at any one time a device credential belongs to only one mobile gateway, which advertises this credential's address on its behalf. When multiple mobile gateways are deployed, the configuration of each credential corresponds to one gateway; the gateway reports the credential's latest handshake, and the Hub accordingly moves the credential address into the `AllowedIPs` of the current gateway peer (it can move only between nodes with the `gateway` role, section 4.1). A gateway that has the credential as a direct peer configures its address only on that peer (section 4);
- The gateway can send traffic with the addresses of devices connected through it; this is trust inherent to the `gateway` role (auth.md section 2), so it is granted only to nodes the user trusts;
- **One configuration format** (ADR 0018): the standard WireGuard configuration; a client that takes WireGuard settings in a format of its own, such as a proxy app's WireGuard outbound, is set up from the same fields, and does not occupy the phone's single VPN slot;
- Traffic between devices is forwarded through the mobile gateway;
- Direct paths to home and to other nodes, chosen automatically, come with the phone app, a full member (M3, ADR 0018).

## 14. Platforms

| Platform | Session layer | Filtering | Notes |
|---|---|---|---|
| Linux (kernel >= 5.6) | Kernel WireGuard (netlink) | nftables | Primary target; relays run here |
| Linux (old kernel), Synology DSM | Rust userspace implementation in the nett daemon + TUN, chosen when the kernel has no WireGuard | In the nett daemon | On DSM nett adds no iptables rules (dsm.md) |
| macOS | Native member: Rust userspace implementation in the nett daemon + utun (ADR 0018) | In the nett daemon | Default way; laptops are usually `dial-only` |
| Container (Linux, or the Docker Linux virtual machine on macOS) | Kernel WireGuard in the container's network namespace, or userspace over TUN (ADR 0016) | nftables (in the container's network namespace) | Serves the services that share its network |
| Home Assistant OS | Runs inside an add-on, using the WireGuard that comes with the HAOS kernel (ADR 0017) | Packet filtering on the host network (subject to capability detection) | Can act as smart gateway, mobile gateway, relay |
| Phone | Any WireGuard client, from the standard configuration | Enforced by the mobile gateway | See section 13; app in M3 |
| Windows, iOS, Android (M3) | Windows: wireguard-nt; iOS, Android: userspace implementation inside the app | Windows firewall (WFP); inside the app | Full members (ADR 0018) |

The concrete userspace WireGuard implementation is evaluated and selected after the prototype gate and before rolling out to DSM and macOS; M1 must cover DSM, Linux with old kernels and macOS.

**Core and backends are separate** (ADR 0018): admission verification, measurement, scoring, switching and hole-punching coordination are platform-independent libraries; WireGuard configuration, interfaces, routes, filtering and DNS are implemented by the backend of each platform (M1: Linux kernel, userspace; M3: Windows, iOS, Android).

## 15. Failures and degradation

| Situation | Behavior |
|---|---|
| Current path interrupted | Failure is determined within about 3 seconds and the mesh switches to the best candidate just measured |
| Relay down | Links through that relay switch to other paths; reassigned after the Hub recovers |
| All UDP unavailable | Switch directly to the TLS transport without trying UDP relays one by one |
| Hub offline | Local autonomous path selection and switching; new candidates and assignments cannot be added |
| nett-node stopped (a panic or an error at its start; it starts again after 5 seconds) | The mesh in the same process keeps measuring, switching and answering DNS; once nett-node is back it syncs the Hub's new configuration |
| nett daemon stopped (an upgrade, a crash) | Kernel WireGuard keeps the current path but no longer switches, and paths over the TLS transport are interrupted; on userspace platforms all paths are interrupted. The service manager restarts it automatically, and after the restart it loads the trust store first, then the desired state (section 4.2) |
| The TLS transport ends on an error | Paths over the TLS transport stay down until the nett daemon restarts; the error is logged, and the path layer measures those candidates as unavailable |
| Relay restart | Obtains the assignment from the nett daemon again; the index table is lost, and links through it recover after re-handshaking (section 8.4) |
| Member removed | The Hub delivers a revocation, other members delete its public key and permanently reject that node ID, and relay assignments through it are voided |
| Admission material verification fails | The peer is not configured, and an event is reported |
| Clock skew | Does not affect WireGuard; affects measurement timestamps, and an event is reported when the skew is too large |
| A data plane update fails (the interface cannot be created before the system provides its TUN device, the kernel refuses a change) | What the failure left closed stays closed (hard rule 6). The desired state in effect is applied again after 1 second, then after twice as long each time up to 30 seconds, until it succeeds; no new desired state is needed. Probe sockets and the DNS responder that cannot be opened are retried the same way. The failure is listed as a problem while it lasts (status.md section 6) |

## 16. Observability

- The `links` resource: the current path, transport, quality, candidate scores and the most recent switch with its reason for each link;
- Measurements and counters: `link.rtt`, `link.loss`, `link.jitter`, `link.bytes`, `relay.bytes`, reported through `LinkReport` and shown in the console;
- Events: path switch, transport switch, relay over limit, all candidates unavailable, admission material verification failure;
- `nett status` shows the current path and quality of each link on this machine (design/status.md); `nett doctor` checks port reachability (giving the ports to open per the list in section 5.5), WireGuard state, DNS and filter rules.

## 17. Resource budget

| Item | Limit |
|---|---|
| Candidate paths per pair of members | 6 |
| Probe traffic | About 1 KiB/s per pair of active links; about 2.5 KB/s for 15 seconds after switching away because of a failure (section 7) |
| nett daemon | Idle private memory <= 8 MB (hard rule 14); mesh state (including admission material and revocations) no more than 1 MiB at 50 members; forwarding buffers, the TLS transport's included, have limits; served ports: 16, with 256 connections of 16 KiB of buffers each (section 12.1) |
| Desired state file and trust store | 4 MiB each; 256 members; 4096 revocations; candidate paths per member as above |
| nett-relay | Idle private memory <= 5 MB (hard rule 14); about 1 KiB per link through the relay; the total number of connections, the index table size and the number of `mac1` trials per second all have limits |

## 18. Phased implementation

| Capability | M1 | M2 |
|---|---|---|
| **Prototype gate** (first step of M1, Linux, static configuration instead of the Hub): signed admission, UDP relay and switching to a new relay, switching and time-slot convergence when both sides are `dial-only`, roaming correction (including late and out-of-order packets), relay restart, MTU (large-packet TCP, small-MTU outer path), TLS fallback, success rate of hole punching (cone NAT, IPv6); comparison with Tailscale on disconnect, fluctuation, fallback and recovery (ADR 0021); actual behavior of the chosen WireGuard implementation (retry after index collision, handshake time after removing and re-adding a peer, cookie, aging of old indexes); measured switching time; **performance benchmark**: throughput, latency and CPU usage compared with native WireGuard and Tailscale on the same set of machines. Scenarios and pass criteria are in prototype.md | ✅ | |
| Address plan, session layer (kernel and userspace) | ✅ | |
| Admission verification (signed member table, prefixes, rules) | ✅ | |
| The nett daemon: the mesh, the TLS transport and nett-node in one process (ADR 0013) | ✅ | |
| Candidate paths: LAN direct, public direct (IPv4, IPv6), via a single relay; hole-punched direct (at least one end behind cone NAT, IPv6); probing on the WireGuard port | ✅ | |
| Candidate paths: multi-hop relay; hole punching when both ends are behind symmetric NAT | | ✅ |
| Measurement, scoring, hysteresis, fast switching, decider rules | ✅ | |
| Transport: UDP, TLS | ✅ | |
| Transport: QUIC, obfuscation | | ✅ |
| Relay: single-port forwarding, binding rules | ✅ | |
| Relay choice from a line quality matrix, traffic limits per relay | | ✅ |
| CONNECT proxy (HTTP/2 only on entry nodes) | ✅ | |
| Smart gateway, source NAT by source class | ✅ | |
| Edge address | ✅ | |
| Hostnames and DNS | ✅ | |
| Access control (advertised prefixes denied by default) | ✅ | |
| Mobile gateway and device configuration | ✅ | |
| macOS native member; the container (services that share its network) | ✅ | |

M3: iOS and Android apps and Windows members (ADR 0018).

## 19. Open questions

| Question | Notes |
|---|---|
| TUN, IP forwarding and NAT capabilities on NAS systems | Verified one by one after the prototype gate and before rolling out to NAS |
| Sending and receiving probes on the WireGuard port | Behavior on each distribution's kernel (including IPv6, existing connection tracking and NAT rules on the host, whether nfnetlink_log is available) is verified at the prototype gate |
| Hole punching when both ends are behind symmetric NAT | Designed in M2 |
| Time to first connectivity of a new member | For a `dial-only` member behind NAT, if the first handshake is earlier than the peer having configured it, the peer drops it and WireGuard retries only after 5 seconds: measured 5.2-5.7 seconds to connect, while direct takes only 11 milliseconds (prototype.md section 9). Optimize later, for example by notifying the new member over an existing path to re-handshake immediately once the peer has configured it; first compare with Tailscale's time to first connectivity |
