# Names and Diagnostics

- Status: draft
- Phase: M1 (roadmap: hostnames and hostname resolution, `whois`, `nett doctor`)

## 1. Goals

Everyday use on top of a working mesh:

- Reach a machine by name: `ssh nas.nett.internal` instead of a mesh address;
- Know who an address belongs to, from what this machine has verified (`nett whois`);
- See whether a peer answers right now, over which path and how fast (`nett ping`);
- Find out what is wrong in plain words, with what to do about it (`nett doctor`).

Hostnames, the responder's scope and the identity rule are decided in mesh.md section 11; this document is how they are built. Aliases (the `hostnames` resource) and forwarding for devices come with the mobile gateway (mesh.md section 13).

## 2. The DNS responder

- **Where**: the mesh process answers on UDP port 53 of this machine's own mesh addresses (IPv4 and IPv6), and nowhere else (hard rule 2). With the userspace data plane, a query this machine sends to itself reaches the data plane, which answers it from the same names (userspace.md section 4). The socket is bound once the mesh interface has its addresses. On Linux the mesh service gets `CAP_NET_BIND_SERVICE` for it; on macOS and in containers the mesh process runs as root. If the port cannot be bound, status lists a problem and the mesh keeps working;
- **What**: `A` and `AAAA` for `<node name>.nett.internal`, for every admitted member: the name comes from the desired state (unsigned, mesh.md section 11), the addresses from the member's verified admission material, so a wrong name can only point at a real member, never at an address outside the mesh. Names are compared without regard to case;
- **Answers**: an authoritative answer with a TTL of 60 seconds; a name under the suffix that is not a member, or a type other than `A`/`AAAA` for a member, gets an empty authoritative answer (`NXDOMAIN` for unknown names, `NOERROR` without records for other types); every other name gets `REFUSED`: the responder never forwards and never recurses. Malformed queries, responses, and anything but a standard query with one question get no reply;
- **Bounds**: queries at most 512 bytes, replies at most 512 bytes (always enough for one name's two records), at most 1000 queries a second in total; above that, queries are dropped. Other members cannot reach it unless an access rule allows UDP 53, which no default does: each machine asks its own responder;
- **One thread** with a blocking socket and a read timeout, owning a copy of the name table that the engine replaces after every applied desired state.

## 3. Using the names on each platform

The system resolver sends only names under `nett.internal` to this machine's mesh address:

| Platform | How | Done by |
|---|---|---|
| macOS | `/etc/resolver/nett.internal` with `nameserver <mesh IPv4>` | the mesh process (it runs as root) when the interface is up; removed by `sudo nett leave` |
| Linux with systemd-resolved | per-link settings on `nett0`: its DNS server is the mesh IPv4, the routing domain `~nett.internal`, not a default route | `nett resolver`, run by the mesh unit after it starts (`ExecStartPost=+`, with root, through `resolvectl`); it waits up to 15 seconds for `nett0`, and never fails the unit |
| Linux without systemd-resolved | no split resolution in `/etc/resolv.conf`: names work with `dig @<mesh IPv4>` and in programs that take a DNS server; `nett doctor` says so | — |
| Container member | the container's own resolver; services in the container use mesh addresses | — |

The mesh process itself runs no external command (hard rule 1); `nett resolver` is part of the root-owned service setup, calls only `resolvectl` by absolute path with its arguments as an array (hard rule 9), and does nothing when systemd-resolved is not running.

## 4. `nett whois <address>`

- A query on the local socket, `{"v":1,"query":"whois","address":"100.88.0.6"}`, answered only for root and the mesh process's own user (status.md section 3);
- The mesh process answers from verified admission material only: the member whose mesh or Edge address it is (node ID, name, mesh addresses, roles), or, for an address inside a prefix a member advertises, that gateway; otherwise "not a member". The name is shown as a label; the node ID and the verified material are the identity (mesh.md section 11);
- `--json` prints the answer as is.

## 5. `nett ping <name or address>`

- Sends in-tunnel probes (mesh.md section 7.2, `0x80`) to the peer's probe port on its mesh address, once a second, 4 by default (`-c <count>`), each waiting up to 2 seconds, and prints the round-trip time of each reply and a summary (sent, received, loss, min/avg/max);
- The probe port is open between all members whatever the access rules say (design/mesh.md section 12), so a reply shows the tunnel works, not that a service port is open; the output says so when no rule allows anything to that peer;
- A name is looked up in this machine's status (or through the responder); with access to the status socket (root) each line also shows the path the probe took: direct, LAN, or the relay and transport;
- Needs no privileges for the probes themselves: an ordinary UDP socket whose source is this machine's mesh address; the peer answers only probes from the mesh address of an admitted member.

## 6. `nett doctor`

Runs a fixed list of checks on this machine, prints one line per check (`ok`, `warning`, `problem`) with what was found and, for anything not ok, what to do; exits 1 when there is a problem. It reads the local status, the configuration directory and the service manager; it changes nothing.

| Check | Problem or warning when | Advice |
|---|---|---|
| Mesh service | the status socket does not answer | how to see the service's log |
| Admission and desired state | not admitted; the desired state rejected; problems in status | each problem's reason, and the command that shows more |
| Peers | a linked peer is unreachable or never connected | its candidates and their state: all relays failing points at the relay port, every direct candidate failing at the WireGuard port in the cloud's security group (the port list of mesh.md section 5.5) |
| Clock | not synchronized | enable time synchronization; switching by time slot needs it (mesh.md section 8.4) |
| Hub | `hub.json` present but the nett-node service is not running, or the last upgrade failed | the service's log; the reason recorded in `upgrade.json` |
| Relay | this machine runs a relay but nett-relay has not fetched its assignment in the last minute | the relay service's log |
| TLS transport | there is a TLS candidate but the transport adapter is not running | the transport service's log |
| Names | the responder does not answer this machine's own name, or the system resolver does not send `nett.internal` to it | per section 3 |
| Units (Linux) | a unit in `/etc/systemd/system` overrides nett's | move it away (release.md section 5) |
| Host firewall (Linux) | ufw is on, denies incoming connections and has no rule for `nett0`: it drops what nett's own filter lets in, in-tunnel probes included, so other members see this machine as unreachable | `sudo ufw allow in on nett0`: nett filters the interface itself (mesh.md section 12), so this opens nothing the access rules do not allow; `sudo nett install` says the same when it finds this |

Network probes from outside (is my WireGuard port reachable from the internet) need another member's help and are left to the Hub view in `nett site status`.

## 7. Verification

| Level | Content |
|---|---|
| Unit tests | DNS: parsing and answers (member, other type, unknown name under the suffix, other domain refused, malformed and oversized ignored, case); the name table follows the admitted members; whois for mesh, Edge and routed addresses; ping's summary; each doctor check from a status document |
| Lab | `hub-relay`: a member resolves another's name through its own responder and pings it, the path shown matches status; `nett doctor` is clean on a healthy member and names the cause when the relay is stopped |
| Real machines | the Mac resolves `<name>.nett.internal` through `/etc/resolver` |
