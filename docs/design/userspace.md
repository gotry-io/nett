# Userspace Data Plane and the macOS Native Member

- Status: draft
- Phase: M1, after local signing (roadmap M1, ADR 0018)

## 1. Goal

A Mac joins the mesh as a native member: it has its own mesh address, other members reach native services on the Mac according to the access rules, and the Mac can also reach the mesh. When Edge forwards origin traffic to a service on the Mac that listens on a wildcard address, the service sees the Edge address as the source, not a loopback address (hard rule 7).

The userspace data plane is platform-independent: DSM and older-kernel Linux use the same implementation and only swap the TUN and interface-configuration backend (ADR 0018).

## 2. Scope

| Included | Not included |
|---|---|
| Userspace data plane: WireGuard sessions, peer selection by `AllowedIPs` with source validation, in-process stateful filtering, demultiplexing on the WireGuard port | DNS and `/etc/resolver` (done together with hostnames and DNS) |
| macOS backend: utun, addresses, routes, binding outbound sockets to the physical interface, network changes | The Edge role and advertised routes on macOS |
| Linux TUN backend: lab scenarios and CI use it to verify the userspace data plane; it is also the basis for DSM and older kernels | DSM packaging and boot tasks; performance optimizations such as batched I/O and offloads (GSO, GRO) |
| launchd operation (installation is in design/release.md section 4); macOS nodes in local signing | Dedicated optimization for laptop sleep and frequent network switching (basic network-change handling is in section 6.4) |
| Measured coexistence with proxy-type VPN apps (Surge enhanced mode) | |

Candidate paths are the same as in local signing (local-signing.md).

## 3. WireGuard implementation

| Candidate | License | Status | Fit with this project | Verdict |
|---|---|---|---|---|
| gotatun (Mullvad) | MPL-2.0 | 21 releases in 2026; third-party audit completed in February 2026; Mullvad uses it on Android, macOS, iOS and desktop platforms | `noise::Tunn` can be used on its own, without its socket and TUN layers; `tokio`, `futures` and `eyre` are always compiled in; the timer advances every 250 ms; up to 256 packets are buffered per peer before the handshake completes | Adopted |
| sanstun (Firezone) | Apache-2.0 (0.1.0 on crates.io is marked BSD-3-Clause) | 0.1.0 released 2026-10-30, interface still has incompatible changes, not audited, maintained mainly by one person | Does no I/O (including time and randomness); timers advance by deadline; no internal packet buffering; fewest dependencies | Re-evaluate before M3 (section 9) |
| boringtun (Cloudflare) | BSD-3-Clause | Maintenance only; fixes on other branches are not merged | | Not used |
| neptun (Nord) | BSD-3-Clause | Published only as git tags | | Not used |

Usage:

- Imported with `default-features = false, features = ["ring"]`: only the `noise` layer is used, not its `device`, `socket` or `tun`; AEAD uses the project's existing ring, and aws-lc is not introduced;
- The session layer is wrapped behind a `Session` trait (encryption, decryption, timers, handshake state); the rest of the data plane does not use gotatun types directly, so replacing the implementation changes one module;
- When it is introduced, report binary size (`cargo bloat`) and idle RSS on macOS and Linux.

## 4. Data plane structure

The core of the mesh process (engine, path layer, probing) is unchanged and operates the data plane through the `DataPlane` interface. The userspace implementation gets its TUN and interface configuration from the platform backend.

- **Data plane thread**: uses `poll` to wait on the TUN, the WireGuard port socket and the control queue at the same time. Sessions, the peer table and the connection table belong to this thread alone and take no locks;
- **Control**: the engine thread sends commands to the data plane thread through a bounded queue (sync peers, change endpoint, re-handshake, replace filter rules, read statistics) and waits for the reply with a timeout; the `DataPlane` methods keep synchronous semantics;
- **Timing**: the data plane thread advances the session timers every 250 ms;
- **Inbound**: UDP → demultiplex (section 4.1) → decrypt → validate the inner packet (IP version, length) → the source address must be within that peer's `AllowedIPs` → filter (section 5) → write to the TUN. A packet that fails any step is dropped without a response;
- **Outbound**: TUN → longest-prefix match of the destination address against peers, drop if there is no peer → record the connection (section 5) → encrypt → send from the WireGuard port to the peer's current endpoint;
- **This machine's own mesh address**: macOS routes the address of a point-to-point interface into it, so a packet a local program sends to this machine's own mesh address (the system resolver asking the DNS responder, a local client of a service on the mesh address) arrives on the TUN. The data plane writes it back into the TUN unchanged, and the system delivers it locally. No filter applies: both ends are this machine, and only the local system writes into the TUN (a peer's packet with this machine's address as its source fails source validation);
- **endpoint**: same as kernel WireGuard. An authenticated packet from a new address updates the endpoint (roaming), and the path layer corrects it (mesh.md section 8.3); `set_endpoint` changes only the endpoint and leaves the session unaffected; `rehandshake` discards the session and the next packet triggers a new handshake (mesh.md section 8.4);
- **Limits**: the control queue and the connection table have limits set by named constants; packets buffered before the handshake completes are limited by the session layer (256 per peer);
- **Receive buffer**: the WireGuard port socket asks for a 1 MiB receive buffer (Linux doubles the value for its bookkeeping). The system default, about 200 KiB on Linux, holds less than 2 ms of traffic at gigabit rates, so a short scheduling delay of the data plane thread drops packets, and TCP inside the tunnel reads the loss as congestion. On Linux the mesh process has `CAP_NET_ADMIN` and sets it with `SO_RCVBUFFORCE`, past the system limit `net.core.rmem_max`; a process without that capability gets at most the limit. The send buffer keeps the default: when the uplink is slower, a full send buffer drops packets at the sender instead of queuing them;
- **Process exit**: on macOS a utun belongs to the process that created it, so the interface is deleted when the process exits and connections through the mesh are interrupted. After the service manager restarts the process, it recovers from the locally saved configuration (architecture.md section 12).

### 4.1 Demultiplexing on the WireGuard port

The mesh process itself holds the WireGuard port socket and demultiplexes both receiving and sending in-process:

- A first byte of 1-4 is a WireGuard message and goes to the session layer; a cookie reply also notifies the engine (mesh.md section 8.4);
- Probe messages have a type byte different from WireGuard's (mesh.md section 7.2) and go to the engine for authentication;
- All other packets are dropped without a response (hard rule 2);
- **Handshake limits**: anyone who knows this machine's public key can construct a handshake message that passes the `mac1` check, and processing each one (cryptography, cookie reply, system calls) costs far more than receiving it. Before entering the session layer, handshake messages (types 1 and 2) are limited per source IP: 128 per second per source, 2048 per second across all sources, and at most 4096 entries in the source table; anything over the limit is dropped without a response. A flood therefore costs one receive and one table lookup, and cannot crowd out other peers' handshakes or the data of established sessions. The session layer's own load protection still applies: when one source initiates more than 100 handshakes per second, it replies with a cookie and requires a retry carrying `mac2`;
- Direct probes are sent from the same socket, with the same source port as WireGuard's own packets and through the same NAT mapping. The raw socket and nftables copy required by the Linux kernel backend are not needed on userspace platforms;
- Packets from the idle TLS loopback port (mesh.md section 5.3) are dropped during demultiplexing;
- In-tunnel probes are the same as on Linux: the mesh process listens on the probe port of the local mesh address, with the socket bound to the mesh interface.

## 5. In-process filtering

It uses the same `FilterSpec` as Linux (mesh.md section 12): rules apply only to new connections arriving from the tunnel, anything not allowed by a rule is rejected (ADR 0023), and packets of established connections and related packets are allowed directly. IPv4 and IPv6 are handled the same way. This section covers traffic addressed to this machine; forwarding on userspace platforms (DSM as a smart gateway) is designed together with DSM.

| Protocol | New connection | Allowed directly |
|---|---|---|
| TCP | A packet with SYN and without ACK, matched against the rules | Other TCP packets: those not belonging to any connection are dropped or reset by the local stack and cannot be used to establish a connection |
| UDP | A packet not belonging to any entry in the connection table, matched against the rules | Reply packets of flows this machine has sent (same addresses and ports at both ends) |
| ICMP | Echo request, matched against the rules | Replies to echo requests this machine has sent; ICMP errors (unreachable, time exceeded, packet too big) whose embedded header has this machine's mesh address as the source |
| Other | Matched against the rules | |
| Fragments | The first fragment is matched by its protocol | Subsequent fragments: without the first fragment the receiver cannot reassemble them |

- **Connection table**: records only UDP flows and ICMP echoes that this machine sent through the tunnel, and expires entries after 2 minutes of idleness; the number of entries has a limit (named constant), and when full the least recently used entry is evicted. For an evicted flow, reply packets are matched against the rules again and may be rejected, but are never widened;
- **Reject on failure**: when the data plane starts, the filter rules deny everything, so all new connections are dropped until the engine installs the first rule set; replacing rules completes in one step on the data plane thread with no intermediate state (hard rule 6).

## 6. macOS backend

### 6.1 utun, addresses and routes

- **Creation**: a `PF_SYSTEM` control socket connects to `com.apple.net.utun_control`, and the system assigns the number (`utunN`). The interface name is not the fixed `nett0`; the mesh process reads the actual name after creation and writes it to logs and events. Each packet is preceded by a 4-byte address family header;
- **Address**: the IPv4 mesh address is configured point-to-point (both the local and the remote end are its own mesh address); the IPv6 mesh address has prefix length 128; MTU 1280 (mesh.md section 4);
- **Routes**: the mesh prefixes (IPv4 and IPv6) and the routes advertised by other members are added to the utun through a routing socket (`PF_ROUTE`) and disappear when the interface is deleted;
- **System calls only**: `ifconfig` and `route` are not called (hard rule 1: the mesh process does not execute external commands). System calls are concentrated in one module, and `unsafe` is allowed only in that module, with the reason commented at each use;
- The in-tunnel probe socket is bound to the utun with `IP_BOUND_IF`, corresponding to `SO_BINDTODEVICE` on Linux.

### 6.2 Coexistence with proxy-type VPN apps

The enhanced mode of a proxy app (for example Surge) creates its own utun and takes over the default route and DNS.

- Sockets sent to the underlying network (the WireGuard port, probes sent to relays) are bound with `IP_BOUND_IF` and `IPV6_BOUND_IF` to the physical interface that carries the default route (tunnel interfaces such as utun do not count). This keeps WireGuard and probe packets out of the proxy app's TUN: the path layer measures the real network and is not affected by policies such as the proxy app's "reject when UDP cannot be proxied". Tailscale does the same on macOS;
- The routes for the mesh prefixes are more specific than the proxy app's default route, so traffic to the mesh enters nett's utun. If the proxy app also lists the mesh prefixes in its own routes, the mesh prefixes must be excluded in its configuration. The measured results are written into the user manual (section 8).

### 6.3 Operation

- launchd runs the mesh process as root (creating a utun requires root), starts it at boot and restarts it after it exits. `sudo nett install` installs the service (design/release.md section 4): the service runs the copy in the root-only directory, not the program in the Homebrew directory;
- Files are placed in `/Library/Application Support/nett/` (owner root, mode `0700`): the copy of the program, the mesh private key and identity private key (`0600`), and the desired state file, all generated and copied by `sudo nett install`;
- Reload: `sudo nett reload`, or `sudo nett install` when the desired state has changed (status.md section 4.1);
- Logs: when running as a service, logs go to the system log through syslog (info is recorded as notice, which the system keeps persistently by default), and the size is managed by the system; the launchd standard error file records only startup failures. When run interactively, logs go to standard error.

### 6.4 Network changes

- The mesh process subscribes to routing socket messages. When the physical interface carrying the default route changes (switching Wi-Fi, plugging or unplugging a cable, waking from sleep), the sockets sent to the underlying network are rebound to the new interface, and the port number stays the same. The physical interface is chosen from the routing table: a default route that is not a tunnel interface and has a gateway, preferring the one that is not interface-scoped;
- The path layer then handles it as usual: measurement, switching and re-handshake (mesh.md section 8);
- The mesh process maintains the routes on the mesh interface while the interface exists; if another program deletes them, they are restored at the next sync.

## 7. macOS nodes in local signing

- In a site, a macOS node is the same as other nodes and is usually `dial-only`; the formats of signed artifacts and the desired state file are unchanged;
- When the node policy carries an `edge` or `subnet_router` role, the mesh process on macOS does not apply that part and reports an event;
- The same Mac can have both a native member and a container member (architecture.md section 13). The native member handles services on the Mac itself and the Mac's outbound access to the mesh, and the container member handles container services that need the visitor's real IP (ADR 0016). They are different node identities with different mesh addresses.

## 8. Verification

| Level | Content | Where |
|---|---|---|
| Unit tests | Demultiplexing, source validation, filtering (TCP new connections, UDP replies, ICMP errors, connection table limit and expiry), command timeouts; TUN and UDP use test doubles | All platforms, CI |
| Lab scenarios | The Linux TUN backend runs the existing scenarios (admission, switching, access control, etc.), mixing userspace members and kernel WireGuard members in the scenarios, with unchanged pass criteria. The exception is the handshake flood (scenario 20c): the userspace flooded side limits by source (section 4.1) and does not require other sources to carry a cookie, so this item becomes that a handshake after switching relays gets an answer directly; the criterion that the tunnel recovers during the flood without switching back and forth is the same | Linux, CI |
| macOS smoke test | Create a utun, configure addresses and routes, the in-tunnel probe socket, cleanup after exit | macOS, CI |
| macOS end to end | A native member on a Mac and a Linux member in OrbStack (kernel WireGuard) on the same Mac: handshake, two-way access, access rules, recovery after mesh process restart, network change | Developer's Mac, scripted |
| Coexistence with proxy app | Surge enhanced mode on and off: the mesh is connected; WireGuard packets use the physical interface; Surge started first and started later; sleep and wake | Developer's Mac |
| Resources | Idle RSS ≤ 5 MB (hard rule 14); macOS has no PSS, so record RSS and `footprint` | macOS, Linux |
| Performance | Between the Mac and the OrbStack member on the same Mac, compare throughput, latency and CPU with wireguard-go. Record first; judge against the roadmap's criteria in M1 acceptance | Developer's Mac |

## 9. Open questions

| Question | Notes |
|---|---|
| sanstun re-evaluation | Done before M3 (mobile) starts: the deadline-driven timers and the no-packet-buffering design save more power. At that point check whether the interface is stable and whether it has been audited |
| Receive capacity under a handshake flood | In scenario 20 (c), at about 450,000 flood packets per second, the handshake limit lets a handshake after switching relays get an answer immediately (longest interruption 0.4-0.6 s, while kernel WireGuard has to wait for the cookie retry, about 10.5 s), but during the flood single-threaded one-by-one receiving cannot keep up, the socket buffer overflows, mesh traffic loses 22-50%, and switching relays by latency flaps back and forth. On Linux, switch to batched receiving with `recvmmsg`; macOS has no public batch interface, and native members are usually `dial-only` behind NAT, so the outside cannot reach their WireGuard port. Do this before userspace members that are reachable from outside (DSM) |
| Interruption during restart | A macOS utun is deleted when the process exits, so connections through the mesh are interrupted while the mesh process restarts. After measuring the restart time, decide whether the interface needs to be kept across restarts |
