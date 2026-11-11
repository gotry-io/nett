# Mesh

- Status: draft
- Phase: P0 design; M1 implements the first version, M2 extends it (see section 18)
- Related: ADR [0007](../adr/0007-own-mesh-wireguard-session-path-layer.md), [0008](../adr/0008-mobile-dual-path.md), [0011](../adr/0011-nett-relay.md), [0013](../adr/0013-mesh-and-transport-processes.md), [0014](../adr/0014-signed-mesh-membership.md), [0015](../adr/0015-origin-identity-and-lan-default-deny.md), [0016](../adr/0016-macos-container-member.md), [0018](../adr/0018-client-platforms.md); [protocol.md](protocol.md), [auth.md](auth.md), [architecture.md](../architecture.md)

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
| Relay | A `public` node that runs nett-relay and forwards ciphertext for other members |
| Smart gateway | A node that brings an entire LAN prefix into the mesh |
| Mobile gateway | A node that accepts device connections and carries device traffic into the mesh |
| Mesh process | `nett mesh`: does all the mesh work described in this document, runs independently of nett-node (ADR 0013) |
| Transport adapter | `nett transport`: the TLS transport adapter, runs as a dedicated low-privilege user and handles only ciphertext (ADR 0013) |
| Revocation | The record left when a member is removed, credentials are revoked, a prefix is revoked or a rule is narrowed; it prevents old signed artifacts from restoring privileges (auth.md section 10.4) |
| Admission material | Signed artifacts that prove a peer may join the mesh (section 4.1) |
| Edge | A reverse proxy the user runs on the entry node; any implementation works (Caddy, nginx, Traefik, etc.); nett neither generates nor manages its configuration (ADR 0019) |
| Edge address | On a node with the `edge` role, the mesh address reserved for traffic sent by Edge (ADR 0015) |
| Full member | A member that runs the mesh process, verifies admission material itself and selects paths; other members can connect to it directly. A device using a standard WireGuard or proxy client is not a full member |
| Container member | A member that runs in the host's Docker Linux virtual machine, used on a Mac for container services that need the visitor's real IP (ADR 0016) |

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
- Peers: all other nodes; devices are peers only of the smart gateway and the mobile gateway (section 13);
- `AllowedIPs` of each peer: its mesh address; its Edge address and CONNECT egress address (if any); the LAN prefixes it advertises (if any); the device credential addresses for which it is the current gateway (if any, only for nodes with the `gateway` role). **When this machine has a device credential directly as a peer (for example a smart gateway), that credential's address is configured only on the device peer and does not appear on the gateway peer**;
- **The WireGuard private key is generated on the machine and never leaves the node**; the public key is distributed through the Hub together with the admission material (the `mesh` partition of the desired state);
- Linux uses kernel WireGuard, configured by the mesh process through netlink; platforms without the kernel module (Synology DSM, old kernels) use a Rust userspace implementation with a TUN device, running in the mesh process;
- `dial-only` members set a persistent keepalive of 25 seconds on every peer to maintain the NAT mapping;
- **MTU**: the MTU of `nett0` is fixed at 1280 (the IPv6 minimum). With the WireGuard and outer IP and UDP headers, the largest outer packet is about 1360 bytes: when the outer path MTU is at least 1360 (true for common networks) there is no fragmentation and no dependence on path MTU discovery. When it is smaller, fragmentation takes over: outer IPv4 packets do not set DF, and the router at the bottleneck fragments them; for IPv6 the router at the bottleneck returns ICMPv6 "packet too big" and the sender fragments from then on. With an outer path MTU of 1300, both were measured to transfer completely (prototype.md section 9, scenario 19). Known limitation: the IPv6 route depends on ICMPv6 getting back to the sender; if ICMPv6 is dropped on the path and the outer path MTU is below 1360, large packets are silently lost while small probes pass as usual, and the path layer does not notice. The remedy is left until a real case appears (for example, periodically send an in-tunnel probe that fills the MTU and treat a loss as a failure). The TLS transport is segmented by TCP itself and is not affected. The mobile gateway and smart gateway clamp the MSS of forwarded TCP; TCP originated on the machine determines its MSS from the interface MTU automatically.

**Switching path = changing the peer's endpoint**. The WireGuard session, keys and upper-layer TCP connections are not affected. The mesh process does the measuring, path selection and endpoint setting, and does not depend on nett-node being online. Switching to a relay that has not yet handled this link also requires a new handshake (section 8.4).

### 4.1 Admission verification

A member configures WireGuard only for peers whose chain of signatures it can verify (ADR 0014):

| Peer attribute | Verified against |
|---|---|
| Node's mesh public key and address | Trust anchor -> signed node policy with the mesh module (containing node ID, address, enrollment public key) -> admission proof (signature by the enrollment private key over node ID, identity public key and mesh public key) |
| Edge address | The `edge` role and address assignment in the signed node policy |
| Device's mesh public key and address | The signed artifact of `device.add` / `device_credential.create` |
| LAN prefix | The signed artifact of `node.advertise_routes` |
| Device address appearing on a node's peer | That node's signed policy has the `gateway` or smart gateway role |
| Access rules | The signed artifact of the whole rule set (members, addresses and ports after selector expansion), version number only increases |

Peers that fail verification are not configured, and an event is reported. Removing a member, revoking a prefix and narrowing rules can take effect directly without a signature, leaving a revocation; when verifying other members' admission material, the approval expiry time is not checked, only the signature, version and revocations (auth.md sections 10.2 and 10.4). The baseline for verification is the local trust store, not the desired state file (section 4.2).

### 4.2 The local trust store

The mesh process keeps the authorizations it has accepted on the local machine as the baseline for verification; the desired state file is only an input, and rewriting it cannot change the verification baseline (auth.md sections 10.4 and 11.2, protocol.md section 6.2).

| Saved content | Purpose |
|---|---|
| The machine's node ID and trust anchor list | Fixed when the desired state is first accepted. A desired state with different trust anchors is afterwards rejected as a whole; trust anchors can only be changed by an update signed by the current trust anchors (auth.md section 11.2), and are cleared only by `nett leave` run as root on the machine (auth.md section 8.3) |
| Revocations | Kept permanently, take effect at startup before any authorization |
| The version and hash in effect for each signed artifact: each member's admission material, the access rule set, each member's advertised prefixes | Versions only increase, also across restarts: artifacts of an old version, and artifacts of the same version with different content, are rejected |
| The most recent desired state accepted as a whole | When the desired state file is rejected as a whole (unreadable, malformed, not for this machine, different trust anchors), it is used instead at startup, and the state already in effect continues to be used at run time |

- **Location**: `nett mesh --state <directory>`. On Linux `/var/lib/nett` (the `StateDirectory` of the systemd unit), on macOS `/Library/Application Support/nett/state` (in a root-only directory); in the container image `/etc/nett/state`, in the same mounted directory as the desired state, so it is kept after the container is rebuilt. Directory `0700`, files `0600`, written to a temporary file and then renamed;
- **Startup**: read the trust store first, then the desired state file. The machine's node ID is taken from the trust store, or from the desired state file when there is no trust store;
- **Establishment**: when there is no trust store, it is established from the first desired state accepted as a whole, and this time the expiry time of the local node policy is not checked. This is the case at the first start after an already-running member is upgraded, so the first desired state must arrive through a trusted channel (local-signing.md section 5; when joining a Hub, it is checked against the trust anchor fingerprint in the enrollment token, auth.md section 8.1);
- **Expiry of the local node policy**: after the trust store is established, when a new version of the local node policy appears its expiry is checked (auth.md section 10.2, item 6); an expired one is not accepted and the version already in effect continues to be used;
- **Read/write failure**: when the trust store cannot be written, the mesh process keeps running as usual (hard rule 8), verifies against the state in memory, and lists it as a problem needing attention (status.md section 6): a restart in this period may accept artifacts of an old version. A corrupted trust store is kept as `trust.json.bad` and re-established as under "Establishment", also listed as a problem;
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

```
A's WireGuard ──► R:p ──(by mac1 / session index)──► B's WireGuard
A's WireGuard ◄── R:p ◄─(by mac1 / session index)─── B's WireGuard
```

- On a link through R, A sets B's endpoint to `R:p` and B also sets A's endpoint to `R:p`; the same relay can be the endpoint of several peers at once;
- R records each member's actual address and passes packets to the other end;
- **Multi-hop**: R1 does not pass the packet directly to B but to R2, and R2 likewise decides the destination from the message;
- On a session index collision, the relay drops the colliding handshake and WireGuard automatically retries with a new index; entries age out according to the session's idle time.

### 5.2 Assignment and authorization

- Which links go through which relay is computed when the desired state is composed (site.md section 6; with a Hub, by the Hub) and delivered in the `relay` section of the desired state of the machine where the relay runs: the UDP port, the TLS port when it serves TLS, the links (pairs of node IDs), and for each member on them its node ID, the WireGuard address of a `public` member, and the probe token between that member and this relay (section 7.2; the same token is in that member's relay candidates). The token is HMAC-SHA256 of the relay's and the member's node IDs under the site's relay key (site.md section 4.1); only the member, the relay, the site and the Hub know it;
- The mesh process validates the section and resolves each member to its mesh public key from the verified admission material: a member that is not admitted is left out of the assignment together with its links (why it was not admitted is already listed in status), so the relay forwards only between admitted members (hard rule 4). nett-relay fetches the assignment from the mesh process over the helper socket (status.md section 3.1) when it starts and every 5 seconds, and applies a changed assignment in place: bindings and session indexes of the links that remain are kept, and those of removed links are dropped. The relay forwards only for links assigned to it;
- **Address binding**: a member's actual address is updated only after **the peer has returned a response to a handshake initiation from the new address**, and a handshake response is accepted only from the peer's currently bound address. For the first binding, the address of a `public` member is delivered with the assignment; the address of a `dial-only` member is the address from which it sent a handshake initiation, likewise bound after the peer responds. When both ends are `dial-only` and neither has an address yet, a handshake initiation can identify only the receiver, and the relay keeps it in the pending table; when the other end's handshake initiation arrives, the relay forwards it to the addresses that may be the receiver (sources of pending handshake initiations whose receiver is one of the assigned peers, at most 4); the receiver returns a response from one of them, and the addresses of both ends are bound together. The relay holds no keys and cannot verify whether handshake messages are genuine: an attacker who can forge source addresses may still forge a response and change the binding. The consequence is that the ciphertext of this link is sent to a wrong address, which is a disconnection; no content is leaked. Two further measures therefore apply: binding changes are rate-limited; if no data arrives from the new address within 10 seconds after a new binding, the old binding is restored. The path layer switches as usual after detecting the interruption;
- At startup nett-relay obtains the relay assignment, and later the verified material needed for CONNECT (device credentials, access rules, revocations), from the mesh process (resident), without depending on nett-node. On Linux it runs as the system user `nett-relay` with only the capability to bind ports below 1024; nett-node enables its service while the desired state has a `relay` section and disables it otherwise;
- **Restart without disconnection**: once per second and before exiting, nett-relay saves the index table and address bindings to the local state directory (only session indexes and addresses, no keys; writing to disk is not done in the forwarding loop, so a disk stall only delays the save and does not stall forwarding), and restores them at startup; connections through it are not interrupted (also during upgrades). On a crash, sessions created in the last second are not in the saved table and handshake again per section 8.4;
- A traffic and bandwidth limit per relay, beyond which no new links are assigned to it, comes in M2 with the line quality matrix (section 18);
- The number of `mac1` trials and the size of the index table both have limits.

### 5.3 TLS transport

When UDP is unavailable:

```
A's WireGuard ─► 127.0.0.1:x (transport adapter) ─► WebSocket/TLS 443 ─► R's nett-relay ─► B
```

- For each TLS relay, the transport adapter opens a UDP port on the local loopback address, which serves as the endpoint of this candidate in WireGuard; each received packet is sent as one binary WebSocket message, and likewise in the other direction. It handles only ciphertext and runs as a dedicated low-privilege user (`nett-transport` on Linux). The loopback port is allocated by the mesh process and handed to the transport adapter together with the TLS target and certificate fingerprint: the transport adapter fetches this configuration over the helper socket (status.md section 3.1) when it starts and every 5 seconds (ADR 0013). nett-node enables its service while the desired state has a TLS candidate and disables it otherwise. On macOS the transport adapter comes later; until then the mesh process there leaves TLS candidates out;
- Probes sent to a TLS relay (`0x90`, section 7.2) are sent and received through the same loopback port and WebSocket connection, and TLS candidates are measured like UDP relays; the transport adapter dispatches messages in the other direction by message type: relay responses go back to the mesh process port that sent the probe, and the rest go to the WireGuard port;
- **Connection authentication**: the first message on a WebSocket connection must be an authenticated relay probe, from which the relay identifies the member (the token is only in the mesh process, and the transport adapter merely passes it along); if it is not received within 30 seconds the connection is closed, and until then no message is forwarded and no response is made. After that the connection is one address of this member, with the same binding rules as UDP (section 5.2); the number of TLS connections, the number of connections waiting for authentication and the send queue of each connection all have limits;
- **Certificate**: nett-relay terminates TLS itself with a self-signed certificate it creates the first time it starts (an Ed25519 key in its state directory, `0600`, never leaving the machine); it reports the certificate's SHA-256 fingerprint to the mesh process when it fetches its assignment, the mesh process shows it in status (status.md section 6), and the Hub learns it from there (hub.md section 5). Clients verify the certificate against the fingerprint in their candidates, connect by IP, and send no SNI, so no domain name is needed (for example where the region requires domain names to be filed with the cloud vendor). Like the other candidates, whether this transport is usable is decided by measurement (section 7); when it is blocked the path layer simply does not select it, and no advance test is needed;
- nett-relay listens on TCP 443 by default (site.md section 4.1). On an entry node the reverse proxy holds 443: it passes the WebSocket to nett-relay by domain name and terminates TLS itself, and the members then check the proxy's certificate against the system's CA certificates and the relay's domain name instead of a fingerprint (ADR 0011). This hand-off is not implemented yet; until it is, a relay on an entry node uses another TCP port;
- In the TLS transport, the performance of TCP carried by WireGuard degrades under packet loss (TCP over TCP), so it is used only when UDP is unavailable;
- **Blocking the old path after leaving the TLS path**: far more packets queue on the TLS path than on UDP, and after switching away they keep arriving; the peer is changed back to the relay by these packets, its packets come back over TLS and change this end back to TLS (WireGuard roaming, section 8.3), and the two ends pull each other back and forth, which can last several seconds. So when no peer is using a given TLS relay, the mesh process drops, on the local machine, packets entering the WireGuard port from that relay's loopback port: it opens them before switching to TLS and blocks them again after switching away. This involves only the loopback port this machine selected; if the rule cannot be installed, switching back is merely slower;
- **Standby connection**: for `dial-only` members with TLS candidates, the mesh process probes these candidates as usual (section 7); the transport adapter connects to a TLS relay when it receives the first probe addressed to it, and keeps the connection afterwards (keepalive every 25 seconds), so no TLS connection has to be established on the spot during fallback (ADR 0021). The follower of a pair of `dial-only` members does not probe candidates, but it may have to move to a TLS relay together with the decider (section 8.4), so it sends its own probe to each TLS relay every 5 seconds and its standby connection stays authenticated.

### 5.4 CONNECT proxy

- HTTP/2 over TLS, forwarded per connection, can chain multiple relays;
- On an entry node it shares 443 with the website: the reverse proxy hands over requests "whose method is CONNECT and whose TLS SNI is the nett-relay domain name", and cannot hand over by Host (the `:authority` of a CONNECT request is the target address). Measured: standard Caddy 2.10.2 can forward HTTP/2 CONNECT tunnels but not HTTP/1.1 CONNECT tunnels, so through Caddy only HTTP/2 CONNECT is provided; for other reverse proxies, rely on measurement. This configuration on the Hub host is generated by the Hub install script; nett-relay on other `public` nodes supports both;
- The client credential is a kind of device credential (`kind = connect`, see api-resources.md section 5.4), and adding one requires a signature;
- The CONNECT egress uses the CONNECT egress address on the relay node (section 3), shared by all devices. The target node cannot tell devices apart by source, so **nett-relay authorizes each connection per credential**: for each CONNECT connection, it checks the signed access rules for the device corresponding to the credential (relay is a verifier of `device_credential` and `access_rule_set`); the check is on the address finally connected to, not the name in the request;
- CONNECT targets can only be mesh addresses (including prefixes advertised through smart gateways); the host the relay runs on and its LAN are not connected to directly; nett-relay does not open CONNECT until the mesh process reports that filter rules are ready;
- **Boundary**: a compromised nett-relay can reach, using the CONNECT egress address, all targets allowed by CONNECT rules (the union of the privileges of all CONNECT devices), which exceeds what an ordinary low-privilege process can do; create such credentials only for devices that really need CONNECT;
- The host where Edge runs is itself a mesh member, and origin traffic goes directly over the mesh without CONNECT.

### 5.5 Public ports and security groups

nett cannot modify a cloud vendor's security group, and some cloud vendors deny all inbound UDP by default. The ports needed by each role are listed below, to be opened once by the user in the cloud console; when `nett doctor` and the console detect that a port is unreachable, they state which port should be opened.

| Role | Protocol and port | Purpose |
|---|---|---|
| All `public` nodes | UDP 41820 (configurable) | WireGuard |
| Nodes running nett-relay | UDP relay port (one, configurable) | Relay forwarding, probe responses |
| | TCP 443 | TLS transport entry, CONNECT; shared with Edge on an entry node |
| Entry node | TCP 80, 443 | Website, certificate validation |
| Smart gateway (home broadband) | Router maps the WireGuard port and relay port | Devices connect directly to home; can act as a relay |
| M2 | UDP 443 | QUIC transport |

The WireGuard port of a `dial-only` member is assigned by the system and the desired state carries no port: nobody connects to it at a pre-agreed address. Public direct candidates point to `public` nodes, hole punching uses the mapped address observed at run time (section 6.1), and the LAN direct and IPv6 direct candidates generated by the Hub that point to it (section 6) use the actual port it reports. Multiple members on the same host therefore do not contend for ports, for example the native member and the container member on a Mac (the container's UDP may keep its original port when forwarded out). If a port that the mesh process itself uses locally is assigned, it is reallocated: the probe port of section 7.2 and the TLS loopback port of section 5.3 are within the Linux ephemeral port range. The port does not change while the interface exists: on Linux the interface persists across mesh process restarts and so does the port; on userspace platforms the interface is rebuilt with the process and the port changes with it, the connection is initiated by the `dial-only` end, and the peer learns the new address from the handshake arriving from the new port (WireGuard roaming). When the desired state changes from carrying a port to carrying none, the current port is kept.

Reachability detection: the WireGuard port does not respond to unauthenticated packets and cannot be probed directly from outside, so reachability is judged by whether an actual handshake succeeds; the relay port and 443 are probed with authenticated probes initiated by other `public` nodes.

## 6. Candidate paths

For every pair of members that need to connect (derived from access rules, site.md section 6), the Hub computes a list of candidate paths and delivers it through the `mesh` partition; members measure and select locally.

| Candidate path | Generation condition |
|---|---|
| LAN direct | Both sides list LAN addresses in the same prefix in their status (status.md section 6) and reach the Hub from the same public IPv4 address (they are behind the same NAT); a probe confirms reachability. Generated by the Hub, at most one per pair, IPv4 first. A probe that arrives from a LAN address is answered only when this machine has a LAN direct candidate to that address: a probe reaching this machine's LAN address comes from the LAN, so this is how probe replies on LAN addresses stay off without such a candidate |
| Public direct | At least one side is `public`. Reachability is judged separately for IPv4 and IPv6: a member behind NAT on IPv4 but reachable from outside on IPv6 counts as `public` on IPv6 |
| Via relay | Every relay other than the two ends, in the order of the relays' node IDs, UDP before TLS, within the candidate limit (site.md section 6); measurement then picks among them. Preferring relays located between the two ends, from a line quality matrix, comes in M2 (section 18) |
| Multi-hop relay (M2) | Single-hop relay quality is poor and a two-segment relay is clearly better |
| Hole-punched direct | Both sides are `dial-only` and both have a global IPv6 address, or at least one is behind a cone NAT (section 6.1); hole punching when both ends are behind symmetric NAT is in M2 |

Each path can also be combined with a transport (UDP, TLS). The number of candidates has a limit (default 6 per pair of members). The candidates of a `dial-only` member include at least paths through two different `public` nodes (architecture.md section 12.3).

**Active links** (with traffic in the last 10 minutes) are measured fully; **idle links** are measured only at a low frequency, and the first time there is traffic, the link is established immediately on the best candidate.

### 6.1 Hole-punched direct

When both ends are behind NAT or a firewall, both sides send packets to each other at the same time, open mappings on their respective NATs, and then connect directly. Hole-punching probes are **sent from the WireGuard port** and use WireGuard's own NAT mapping (section 7.1). During hole punching, traffic continues on the current path, switching happens after the punched path is verified, and failure does not affect the connection (ADR 0021):

- **Mapped address**: the actual source address of a member's WireGuard port as seen by a `public` node is the mapped address the NAT allocated for it, attached to the response to a probe of that member (told only to that member). Direct probes are sent from the WireGuard port anyway (section 7.1), and the source address in the peer's response is that address; probes sent to a relay are sent from the mesh process's own port, and what nett-relay attaches to the response is the WireGuard address of this member bound per section 5.2 (when not yet bound, the source of the probe). From this the mesh process obtains the machine's mapped address, shows it in status (which nett-node reports to the Hub through `LinkReport`), and tells the peer directly in the hole-punching proposal; the hole-punching candidate itself carries no addresses (site.md section 6);
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
| Candidate paths | Probe packets outside the tunnel, measured per path segment: member -> relay, relay -> member, member -> `public` member; direct candidates are probed from the WireGuard port (section 7.1); paths via a relay are estimated by combining segments | Every 15 seconds for active links; for a candidate that has never responded, every 1 second within 1 minute after the first probe (the peer may not have started yet at startup); when the current path is clearly worse (round-trip time doubled relative to the best value since switching to it and at least 10 milliseconds more, or 2 or more of the last 10 in-tunnel probes lost), candidates of the same kind every 3 seconds; when the current path is not of the best kind, candidates of better kinds every 1 second; right after switching away from a better-kind path because of its first failure, that path is probed every 50 milliseconds for 15 seconds (after the first response, probe once more immediately to confirm, and handle a response as soon as it arrives without waiting for the next timer tick); when a failure is suspected, all candidates once immediately; idle links every 5 minutes |
| Line quality matrix | Aggregates the segment measurements and reports to the Hub | Every minute |

- Metrics: round-trip time (exponential moving average; when one measurement differs from the average by more than a factor of two the new value is adopted directly, so there is no need to wait for the average to catch up after a path change), packet loss rate (sliding window), jitter;
- Timeout of in-tunnel probes: twice the round-trip time plus 100 milliseconds, bounded between 300 milliseconds and 1 second, used only to enter suspected failure (section 8.2). A timed-out probe waits another 10 seconds: a late response is still counted in the round-trip time; it is recorded as lost only when overtaken by the response to a later probe, or when there is still no response after 10 seconds. When the machine's own traffic fills a slow link and the queue is deep (rate-limited VPS, home broadband with a very deep upload buffer), responses are delayed by several seconds; this is queuing, not packet loss;
- A link with traffic: the number of bytes WireGuard sent or received for this peer changed within the last 30 seconds;
- Probe packets carry authentication: between members a checksum is computed with a key derived from the two sides' WireGuard keys; probes sent to a relay use the token delivered at assignment;
- Responders: probes sent to a relay are answered by nett-relay on the relay port; in-tunnel probes are answered by the mesh process on the mesh address; probes of direct candidates (public direct, LAN direct, hole-punched) are sent to the peer's WireGuard port and answered by the peer's mesh process (section 7.1), where the response on a LAN address is **enabled only when the Hub determines that a LAN direct candidate exists**. The "LAN address" on a cloud host's network card often corresponds to a public address through 1:1 NAT, so all responders **make no response at all to unauthenticated probes**;
- Probe traffic has a budget: no more than about 1 KiB/s per pair of active links; the only exception is the 15 seconds right after switching away because of a failure, where the quick-recovery probe round trips are about 2.5 KB/s.

### 7.1 Probing on the WireGuard port

Probes of direct candidates and hole punching (section 6.1) must use WireGuard's own NAT mapping, so they are sent from the WireGuard port (ADR 0021):

- **Linux kernel WireGuard**: the mesh process uses a raw socket to build UDP packets with the WireGuard port as source port and sends them (so `CAP_NET_RAW` is needed). Receiving uses nftables: the mesh process adds a rule on the input chain through netlink, handing to itself only copies (`log`, nfnetlink_log) of packets addressed to the WireGuard port whose first byte is a probe type, and of WireGuard's cookie replies (type 3, 64 bytes, section 8.4); other packets only incur one extra rule match and are not copied. Cookie replies are handed to WireGuard as usual, and the mesh process only reads and does not respond. These probe packets are not WireGuard messages, and kernel WireGuard drops them on receipt. A raw socket is not used for receiving: the kernel first copies every incoming UDP packet to the raw socket and then filters, which was measured to reduce WireGuard throughput by about 7% (prototype.md section 9);
- **Userspace platforms**: the mesh process already holds the WireGuard UDP port and distinguishes probes from WireGuard messages by the first byte; a received cookie reply is handled per section 8.4 and then handed to WireGuard as usual;
- The first byte of a probe message differs from all four WireGuard message types; probes carry authentication (see above), unauthenticated packets get no response, and the externally visible behavior of the WireGuard port is unchanged;
- Probes sent to a relay are sent from the mesh process's own port and answered by nett-relay on the relay port.

### 7.2 Probe messages

The first byte of a probe message is the type, different from all four WireGuard messages (1-4). All fields have fixed length, and packets that are malformed or fail authentication get no response.

| Type | Sender and destination | Content |
|---|---|---|
| `0x80` in-tunnel probe | Member -> probe port `41821` on the peer's mesh address (listening only on `nett0`) | Sequence number |
| `0x81` in-tunnel response | Returns along the same path | Sequence number; the responder's latest measurements to each relay (round-trip time, packet loss rate), used to estimate the other segment of a path via a relay |
| `0x84` switch proposal | Decider -> probe port on the peer's mesh address (through the current tunnel, section 8.4) | Round number, kind of target (relay, the punched direct path, or the LAN direct path of this pair), number of the target relay (first 8 bytes of the SHA-256 of the relay node ID) |
| `0x85` switch confirmation | Returns along the same path | Same as above |
| `0x86` hole-punching proposal | Decider -> probe port on the peer's mesh address (through the current tunnel, section 6.1) | Round number, NAT type (unknown, cone, symmetric), IPv4 mapped address, IPv6 address (empty if none) |
| `0x87` hole-punching confirmation | Returns along the same path | Round number, the responder's NAT type, IPv4 mapped address, IPv6 address |
| `0x82` direct probe | Member's WireGuard port -> direct candidate address on the peer's WireGuard port (section 7.1) | Number of the sender's mesh public key (first 8 bytes of the SHA-256 of the public key), sequence number, send time, checksum |
| `0x83` direct response | Returns along the same path | Sequence number, the source address seen by the responder (mapped address), checksum |
| `0x90` relay probe | Member (mesh process's own port) -> relay port; TLS relays are reached through the transport adapter (section 5.3) | Token number, sequence number, send time, checksum |
| `0x91` relay response | Relay -> member | Sequence number, the WireGuard address of this member bound by the relay per section 5.2 (mapped address, section 6.1; the source of the probe when not yet bound or over TLS), checksum |

- In-tunnel probes carry no separate checksum: WireGuard has already authenticated the source by `AllowedIPs`, and the mesh process answers only probes whose source is the mesh address of an admitted member;
- All checksums are HMAC-SHA256, truncated to 16 bytes, covering the rest of the message; those whose send time differs from the receiver's clock by more than 30 seconds are dropped, limiting replay; a response is never longer than the probe, so it cannot be used to amplify traffic;
- The key of direct probes is derived from the two sides' mesh keys: the result of X25519 (this machine's mesh private key, the peer's mesh public key) goes through HKDF-SHA256 (with "nett direct probe v1" distinguishing the purpose, and the two public keys ordered by bytes as additional information) to give 32 bytes; only admitted members can compute it. The key of relay probes is the token delivered at assignment;
- The round-trip time and packet loss rate of the path A -> R -> B are estimated by combining A <-> R measured by A with B <-> R brought by B in the in-tunnel responses; when the tunnel is interrupted the most recent values are used.

## 8. Path selection and switching

### 8.1 Scoring

```
score = round-trip time + loss penalty + jitter penalty + path type preference + transport penalty + relay load
```

- Path type preference: LAN < public direct (including hole-punched direct) < via relay < multi-hop;
- Transport penalty: TLS is higher than UDP (20 milliseconds added on top of the via-relay preference);
- Relay load: rises when the relay approaches the traffic limit the user set for it. The limit is only a capacity mechanism; nett does not care how machines are billed or how upper-layer services use bandwidth;
- Policy overrides are supported (`spec.policy` of `links`): prefer direct, pin to a given relay, pin the transport.

### 8.2 Switching rules

| Situation | Rule |
|---|---|
| Current path suspected failed | 2 consecutive in-tunnel probes without response: immediately send 3 extra probes on the current path (200 milliseconds apart) and probe all candidate paths at the same time |
| Current path failed | All extra probes lost (about 3 seconds from the disconnection), or packet loss above 30% for 3 seconds: switch **immediately** to the best candidate just measured; when all UDP candidates are unreachable, switch directly to TLS without trying UDP relays one by one. When the peer's packets are still arriving, all extra probes being lost is not a failure: since the suspected failure, the bytes WireGuard received from this peer are still growing (the engine reads every 100 milliseconds), and an in-tunnel response (including late ones) was received within 10 seconds, which shows the path works and is only queuing; all paths pass the same bottleneck, switching and re-handshaking are of no help, and normal probing resumes. When the peer's packets are arriving but no response at all within 10 seconds (only one direction works), it is judged a failure as usual. Likewise, when a late response was received within 10 seconds (queuing), a too-high packet loss rate is not a failure either: the loss is from a full queue dropping packets, and changing to a path that passes the same bottleneck is of no help; a path that does not share the bottleneck has a much shorter round-trip time, and is switched to as a better path of the same type |
| Path of a better type recovers | Currently via relay while some direct candidate responds, or currently via TLS while some UDP candidate responds, in 2 consecutive probes: switch over. After the first failure of this path, it is probed every 50 milliseconds for 15 seconds after switching away, and after recovery the switch back takes about 0.1 seconds; from the second failure of this path within 10 minutes, the waiting time doubles with the failure count (starting at 10 seconds, at most 5 minutes); when a path fails without ever having connected (for example the first handshake has not completed), the first time does not count as a failure |
| Better path of the same type | Switch only when the score is better than the current by at least 15% and at least 10 milliseconds, and this lasts 30 seconds (hysteresis); when 2 or more of the current path's last 10 in-tunnel probes were lost and this candidate responded to 2 consecutive probes, switch after 5 seconds |

Path types from best to worst: LAN direct, public direct (including hole-punched direct), via relay, multi-hop; on the same path UDP is better than TLS. The parameters are based on alignment with Tailscale (ADR 0021) and are adjusted according to measurements at the prototype gate.

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
- **When the peer is under load, wait for WireGuard to retry with the cookie**: when the peer's WireGuard is pressed into the under-load state by a large number of handshake initiations, it replies only with cookie replies and accepts only handshake initiations carrying the cookie (`mac2`); after receiving the cookie, the initiator's WireGuard retries with it only after about 5 seconds (`REKEY_TIMEOUT`, plus up to 1/3 second of jitter). A re-handshake removes and re-adds the peer, which loses the cookie, so when the mesh process receives a cookie reply from this peer's current endpoint while the tunnel is not yet established, it neither re-handshakes nor switches away as a suspected failure, but waits 5.4 seconds plus twice the new path's round-trip time plus 20 milliseconds; if a cookie is received again in the meantime it waits another round, at most two rounds per path (about 11 seconds), and the count restarts after the handshake completes. The cookie reply itself cannot be verified: an attacker who can forge the source address of a relay or peer can at most delay one failover by about 11 seconds. For measurements see prototype.md section 9 (scenario 20);
- **When both sides are `dial-only`, both ends switch together**: the follower's NAT has no mapping to the new relay, packets from the new relay cannot reach it, and it cannot follow by roaming. Starting from the first relay in relay-number order, both ends measure the tunnel, detect interruptions and maintain the desired endpoint; only the decider chooses the optimum. Depending on the conditions at the time there are three ways:
  - The current path is usable (switching to a better path, or the loss rate is too high but the tunnel can still carry messages): the decider sends a switch proposal carrying a round number through the current tunnel (the same port as in-tunnel probes); the follower replies with a confirmation and switches after about 100 milliseconds (letting the confirmation go out first over the old session), and the decider switches after receiving the confirmation. If no confirmation is received it is resent every 300 milliseconds, and if still none after about 2 seconds it switches as usual, and if an interruption follows, recovery is by the two ways below. Messages of expired rounds are dropped directly; the round number has Unix seconds as its lower bound and only increases across restarts too;
  - The current path is interrupted: the proposal and confirmation are relayed through the Hub (`PathSwitch`, protocol.md section 5). The mesh process does not connect to the Hub: it hands the message to nett-node over the coordination connection of its local socket (status.md section 4.2), nett-node sends it to the Hub, and the Hub passes it to the peer's nett-node, which hands it to its mesh process. The message is the same proposal or confirmation with the send time and an HMAC-SHA256 checksum (truncated to 16 bytes) under a key derived from the two mesh keys like the direct probe key (section 7.2, with "nett path switch v1"): the Hub can delay or drop it but cannot forge it, and messages more than 30 seconds off the receiver's clock are dropped. While nett-node reports the Hub connected, the decider proposes the best relay by its own measurements through the Hub, resends every second, and switches when the confirmation arrives; without a confirmation after 3 sends it rotates by time slot as below. The follower waits up to 4 seconds for a proposal through the Hub before it rotates, and a proposal that arrives during rotation ends the rotation;
  - Neither the current path nor the Hub is available: **rotate by absolute time slot**. Both sides use the system clock to compute `slot = floor(unix time / 15 seconds)` and pick the `slot mod n`-th among the candidate relays sorted by relay number: on detecting an interruption they immediately choose by the current time slot and re-handshake, and change again at the start of each later time slot; the choice depends only on time, regardless of when each side detects the failure. Each side takes "the machine's in-tunnel probe received a response" as bidirectional confirmation, stops on this relay after confirmation, and re-enters rotation on the next interruption. The prerequisite is that the clock error between the two sides is far smaller than 15 seconds: time slots are used only when the machine's clock error is within 2 seconds (according to the most recent comparison with the Hub and the system's time synchronization status; on Linux the maximum error reported by the kernel, i.e. `maxerror` of `adjtimex`), otherwise it falls back to random-interval retries: every 5-15 seconds it picks a random relay and re-handshakes; on a clock jump it recomputes from the new time. The first address binding on the new relay follows section 5.2: a handshake initiation that arrives first waits in the relay's pending table for 5 seconds for the other end's handshake initiation, and after expiry WireGuard's own retry of about 5 seconds fills in, so the time slot is no shorter than 15 seconds. When the two sides' candidate list versions differ they may be unable to meet, and can only wait for the Hub to recover. This way is best-effort recovery and promises no recovery time;
- The time from the start of a switch to bidirectional recovery, and the recovery time after a relay restart, are measured at the M1 prototype gate (section 18).

### 8.5 Hub or nett-node offline

Candidate paths, relay assignments, admission material and keys are all kept locally; measurement, scoring and switching are done entirely locally on the member. While the Hub is offline, new candidate paths or relay assignments cannot be added, and existing ones remain usable. While nett-node is stopped, the mesh process measures, switches and answers DNS as usual (ADR 0013).

## 9. Transport

| Transport | Phase | Purpose |
|---|---|---|
| UDP | M1 | Default |
| TLS (WebSocket, 443) | M1 | When UDP is unavailable; adapted by the transport adapter |
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
- The container member on macOS is the smart gateway of the container network it is in (ADR 0016): it advertises the addresses of specific services, forwards only traffic from the Edge address, and rewrites the source to its own fixed address in this network.

## 11. Hostnames

- The suffix defaults to `nett.internal` (`.internal` is a top-level domain reserved for private networks) and can be changed when the Hub is initialized;
- Each node automatically gets `<node name>.nett.internal`; users can add aliases (the `hostnames` resource), for example naming a service and pointing it to the member where it runs;
- Hosts on the LAN do not need nett installed; when a name is needed, the user adds an alias pointing to its LAN address within an advertised prefix;
- The mesh process runs a minimal DNS responder only on the mesh address, answering names under that suffix;
- **Upstream forwarding**: only the mobile gateway and smart gateway forward other queries for devices, accept queries only from device addresses, and rate-limit them, so they do not become open forwarders;
- Local resolver configuration: on Linux, split-domain resolution for that suffix is set on `nett0` through systemd-resolved; on macOS, `/etc/resolver/<suffix>` is written;
- Devices: the exported WireGuard configuration lists two DNS servers, the mesh addresses of the mobile gateway and the smart gateway;
- Edge configuration uses mesh addresses and not hostnames: Edge often runs in a container, which by default uses the host's upstream DNS and cannot resolve the mesh suffix;
- **Hostnames are only for locating and are not a basis for identity**: hostnames are delivered by the Hub and are not signed. When you need to confirm who the other side is, use the local identity query (`nett whois <address>`, and the interface of the same name on the local socket), which the mesh process answers from verified admission material; the Hub's `whois` interface is for console display, and its result is a claim by the Hub.

## 12. Access control

- **Default deny** (ADR 0023): a new connection not allowed by any rule is always denied; the same applies between nodes, for advertised prefixes and for container members;
- **The user's devices**: by default they can reach all members and advertised LAN prefixes;
- **Edge address**: by default it cannot reach any target; which hosts and ports it can reach is written by the user in the access rules (part of the signed access rule set, and widening requires a signature). On a node with the `edge` role, the mesh process, according to the identification method declared in the node policy (the address of the container where Edge runs, or the system user when running natively), rewrites the source of mesh traffic sent by Edge to the Edge address; and in both directions, local output and container forwarding, drops packets whose source address is the Edge address but which do not come from Edge (ADR 0015). When Edge fetches from an origin service on the same host it does not pass through the mesh and is not bound by these rules;
- The rule set is delivered as a whole as one signed artifact, with a version number that only increases; adding a deny rule or deleting an allow rule is narrowing and can take effect directly without a signature;
- **Matching**: rules apply only to new connections; established connections and packets related to them (replies, ICMP errors) pass directly. Rules are matched in rule set order, and the first matching rule decides allow or deny; when no rule matches, the connection is denied, except that it is allowed when the source is a user's device. The mesh's own in-tunnel probes are not affected by access rules. The same holds when there is no rule set;
- **What is signed is the expanded result**: rules are written with selectors such as nodes, devices and tags; a source can also select a node's Edge address (written as that node's `edge`), to allow Edge to reach specified services. The signed artifact contains the expanded member IDs, addresses and ports. If a change of tags (for example adding a tag to a node) makes the expansion larger, it is widening access and requires a signature; nodes execute only the expanded result in the signed artifact and do not expand by tag themselves;
- Rules are compiled into filter rules local to each member: Linux uses nftables, attached at `prerouting` with priority before Docker's destination NAT, matching traffic entering from `nett0`, so traffic to the local machine, to Docker published ports and traffic that needs forwarding (mobile gateway, smart gateway) all passes through; matching is by source mesh address, destination address and port, with IPv4 and IPv6 treated the same. On userspace platforms the mesh process filters before forwarding;
- **Deny first, then open**: at startup the filter rules are installed first, and peers are added afterwards; when a rule update fails, deny is kept and an event is reported;
- WireGuard's `AllowedIPs` guarantees that source addresses cannot be forged.

## 13. Phones and the mobile gateway

- The mobile gateway is a `public` node with the `gateway` role (the role is granted by the signed node policy): it accepts devices as peers on `nett0` and carries device traffic into the mesh through the path layer;
- The configuration exported to a device contains two peers, splitting traffic by prefix:

| Peer | `AllowedIPs` |
|---|---|
| The smart gateway at home (direct) | The LAN prefixes advertised at home, and the smart gateway's mesh address |
| Mobile gateway | The rest of the mesh prefix |

- **Device ownership is per credential**: in WireGuard an address can appear in the `AllowedIPs` of only one peer, so at any one time a device credential belongs to only one mobile gateway, which advertises this credential's address on its behalf. When multiple mobile gateways are deployed, the configuration of each credential corresponds to one gateway; the gateway reports the credential's latest handshake, and the Hub accordingly moves the credential address into the `AllowedIPs` of the current gateway peer (it can move only between nodes with the `gateway` role, section 4.1). On the directly connected smart gateway, this credential's address is configured only on the device peer (section 4);
- The gateway can send traffic with the addresses of devices connected through it; this is trust inherent to the `gateway` role (auth.md section 2), so it is granted only to nodes the user trusts;
- Standard clients cannot switch between peers automatically: when direct is unavailable, traffic to home does not automatically go through the gateway. So a **"all through the gateway"** backup configuration is exported as well, for the user to switch to manually when direct is blocked (the phone app is in M3). The backup configuration uses **another credential** (another pair of keys and addresses): on the smart gateway the main configuration's credential address is configured only on the direct peer, and packets arriving through the gateway with this address as source are dropped. The private key exists only in the browser, and the two credentials and configurations are generated together at creation (auth.md section 9);
- **Proxy client configuration** (ADR 0018): when creating a credential, an export format can be chosen: standard WireGuard, or Surge, mihomo, sing-box. Every format uses one main and one backup credential, with the same rules as the previous item. The proxy client configuration contains two WireGuard outbounds: "direct to home" uses the main credential with the smart gateway as peer; "via gateway" uses the backup credential with the mobile gateway as peer. Traffic to the home prefixes goes into an automatic-fallback policy group (direct to home first, via the gateway when that fails), and the other mesh prefixes go through the gateway; domain names under the mesh suffix are resolved by the DNS of the smart gateway and the mobile gateway. The speed-test target of the policy group is the health check port on the smart gateway's mesh address: open only to device addresses, it returns a fixed HTTP 204 response when a connection arrives and closes, without parsing the request content. These configurations do not occupy the phone's single VPN slot and can be used together with proxy apps;
- Traffic between devices is forwarded through the mobile gateway.

## 14. Platforms

| Platform | Session layer | Filtering | Notes |
|---|---|---|---|
| Linux (kernel >= 5.6) | Kernel WireGuard (netlink) | nftables | Primary target; the TLS transport is adapted by the transport adapter; relays run here |
| Linux (old kernel), Synology DSM | Mesh process: Rust userspace implementation + TUN | Mesh process | DSM needs root to use TUN |
| macOS | Native member: Rust userspace implementation in the mesh process + utun (ADR 0018) | Mesh process | Default way; laptops are usually `dial-only`; the transport adapter comes later (section 5.3) |
| Container member on macOS | Kernel WireGuard in the Docker Linux virtual machine (ADR 0016) | nftables (inside the virtual machine) | Only serves other members' access to container services on the Mac that need the visitor's real IP |
| Home Assistant OS | Runs inside an add-on, using the WireGuard that comes with the HAOS kernel (ADR 0017) | Packet filtering on the host network (subject to capability detection) | Can act as smart gateway, mobile gateway, relay |
| Phone | Standard WireGuard client, or Surge, mihomo, sing-box | Enforced by the mobile gateway and smart gateway | See section 13; app in M3 |
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
| nett-node stopped (upgrade, crash) | The mesh keeps measuring, switching and answering DNS; after node recovers it syncs the Hub's new configuration |
| Mesh process stopped | Kernel WireGuard keeps the current path but no longer switches; on userspace platforms all paths are interrupted. The service manager restarts it automatically, and after the restart it loads the trust store first, then the desired state (section 4.2) |
| Transport adapter stopped | Paths over the TLS transport are interrupted, restarted by the service manager |
| Relay restart | Obtains the assignment from the mesh process again; the index table is lost, and links through it recover after re-handshaking (section 8.4) |
| Member removed | The Hub delivers a revocation, other members delete its public key and permanently reject that node ID, and relay assignments through it are voided |
| Admission material verification fails | The peer is not configured, and an event is reported |
| Clock skew | Does not affect WireGuard; affects measurement timestamps, and an event is reported when the skew is too large |

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
| Mesh process | Idle RSS <= 5 MB; mesh state (including admission material and revocations) no more than 1 MiB at 50 members; forwarding buffers have limits |
| Desired state file and trust store | 4 MiB each; 256 members; 4096 revocations; candidate paths per member as above |
| Transport adapter | Idle RSS <= 5 MB; forwarding buffers have limits |
| nett-relay per link through the relay | About 1 KiB; the total number of connections, the index table size and the number of `mac1` trials per second all have limits |

## 18. Phased implementation

| Capability | M1 | M2 |
|---|---|---|
| **Prototype gate** (first step of M1, Linux, static configuration instead of the Hub): signed admission, UDP relay and switching to a new relay, switching and time-slot convergence when both sides are `dial-only`, roaming correction (including late and out-of-order packets), relay restart, MTU (large-packet TCP, small-MTU outer path), TLS fallback, success rate of hole punching (cone NAT, IPv6); comparison with Tailscale on disconnect, fluctuation, fallback and recovery (ADR 0021); actual behavior of the chosen WireGuard implementation (retry after index collision, handshake time after removing and re-adding a peer, cookie, aging of old indexes); measured switching time; **performance benchmark**: throughput, latency and CPU usage compared with native WireGuard and Tailscale on the same set of machines. Scenarios and pass criteria are in prototype.md | ✅ | |
| Address plan, session layer (kernel and userspace) | ✅ | |
| Admission verification (signed member table, prefixes, rules) | ✅ | |
| Mesh process, transport adapter | ✅ | |
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
| Mobile gateway and device dual-path configuration | ✅ | |
| macOS native member; container member (container services that need the visitor's real IP) | ✅ | |
| Proxy client configuration (Surge, mihomo, sing-box) | ✅ | |

M3: iOS and Android apps and Windows members (ADR 0018).

## 19. Open questions

| Question | Notes |
|---|---|
| TUN, IP forwarding and NAT capabilities on NAS systems | Verified one by one after the prototype gate and before rolling out to NAS |
| Sending and receiving probes on the WireGuard port | Behavior on each distribution's kernel (including IPv6, existing connection tracking and NAT rules on the host, whether nfnetlink_log is available) is verified at the prototype gate |
| Hole punching when both ends are behind symmetric NAT | Designed in M2 |
| Time to first connectivity of a new member | For a `dial-only` member behind NAT, if the first handshake is earlier than the peer having configured it, the peer drops it and WireGuard retries only after 5 seconds: measured 5.2-5.7 seconds to connect, while direct takes only 11 milliseconds (prototype.md section 9). Optimize later, for example by notifying the new member over an existing path to re-handshake immediately once the peer has configured it; first compare with Tailscale's time to first connectivity |
