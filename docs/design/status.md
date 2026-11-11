# Local Status and `nett status`

- Status: draft
- Phase: M1, after local signing and before joining the Hub (roadmap M1)

## 1. Goal

See on a node, with one command, how the mesh is doing right now: the machine's addresses and how it runs, whether each peer is reachable, which path it uses and with what quality, why it last switched, and whether the desired state and access rules have been rejected. It does not depend on the Hub, so existing nodes can use it right away.

Status comes from the mesh process's local interface. This is the local interface between nett-node and the mesh process described in ADR 0013: reading status, and asking the mesh process to re-read its desired state file (section 4.1). After joining the Hub, nett-node reads link status through the same interface and reports it to the Hub (`LinkReport`, protocol.md section 5), and after writing the desired state file it uses the same request to have the mesh process apply it (hub.md section 5). Identity lookup (`whois`), names, `nett ping` and `nett doctor` are in names-and-diagnostics.md.

## 2. Scope

| Included | Not included |
|---|---|
| The mesh process's local socket: status query; re-reading the desired state file (`nett reload`) | Identity lookup, names, `nett ping`, `nett doctor` (names-and-diagnostics.md) |
| Node name in the desired state (unsigned, for display only, section 5) | Continuously refreshing views |
| `nett status`, `nett status <peer>`, `--json` | |
| Linux (kernel and userspace WireGuard), macOS, container member | |

## 3. Local socket

- **Location**: a Unix socket, `/run/nett/mesh.sock` on Linux and for container members, `/var/run/nett/mesh.sock` on macOS. `nett mesh --socket <path>` can move it elsewhere (a lab scenario runs several members on one host), and `nett status --socket <path>` matches it;
- **Permissions**: the directory is `0700` (`0711` on Linux, for the helper socket of section 3.1) and the socket `0600`, owned by the mesh process's run identity; the mesh process additionally checks peer credentials (`SO_PEERCRED` on Linux, `getpeereid` on macOS) and accepts only root and its own run identity. `nett status` therefore has to run with `sudo`, and for a container member use `docker exec <container> /nett status` (runs as root inside the container). Status contains no keys, but it does contain the public addresses of the members, the advertised routes and the access rule version, which is the structure of the whole network: ordinary users and programs on the machine cannot see it;
- **Creation**: the socket is for inspection only; if it cannot be created, the mesh process logs a warning and the mesh keeps working (hard rule 8). When a socket already exists at the path, it first tries to connect: if a process answers, it does not take over; if nothing answers (left behind by an abnormal exit), it removes the socket and creates a new one; if the path holds some other kind of file, it leaves it alone. The socket is first created under a temporary name and set to `0600`, then renamed to the agreed path, so it is already `0600` when it appears. The mesh process removes it on exit. If the directory does not exist it is created with `0700`: the Linux systemd unit creates it in advance with `RuntimeDirectory=nett`, and on macOS and in containers the mesh process creates it itself;
- The socket is local to the machine and is not a network listener (hard rule 2).

### 3.1 Helper socket

nett-relay and the transport adapter run as their own low-privilege users and fetch their configuration from the mesh process (ADR 0013) over a second socket, `helpers.sock` next to `mesh.sock`. On Linux the directory is `0711` (others can reach a known name but not list it), `mesh.sock` stays `0600`, and `helpers.sock` is `0666`: the mesh process checks the caller's identity on every connection and accepts only the system users `nett-relay` and `nett-transport`, each for its own query. One query per connection, as in section 4, at most 1 KiB:

```json
{"v": 1, "query": "relay", "fingerprint": "sha256:…"}
{"v": 1, "query": "transport"}
```

- `relay` (only from `nett-relay`): the reply is the relay assignment of mesh.md section 5.2 with each member's mesh public key resolved, or `null` when this machine is not a relay. The request carries the fingerprint of the relay's TLS certificate, which the mesh process shows in status (section 6);
- `transport` (only from `nett-transport`): the reply is the transport adapter's configuration (mesh.md section 5.3): the WireGuard port, and for each TLS relay its loopback port, address and certificate fingerprint;
- Both helpers ask again every 5 seconds and when they start, and apply the reply only when it changed. The replies hold probe tokens, which is why each query is limited to its own user.

## 4. Messages and versions

- One query per connection: the client sends one line of JSON, the mesh process replies with one JSON document and closes the connection.

  ```json
  {"v": 1, "query": "status"}
  ```

- `v` is the major version of the interface, and the reply carries the same `v`. Within a major version only fields are added: the client ignores fields it does not recognize and shows missing fields as `-`. This way, after an upgrade and before the mesh process restarts, the new `nett` can still read the old process's status (adjacent versions interoperate, ADR 0013);
- When the major version differs, the query is unknown, or the request is not valid JSON, the reply is an error and the connection is closed:

  ```json
  {"v": 1, "error": {"code": "unknown_query", "message": "unknown query `stats`"}}
  ```

- The request is validated as untrusted input (hard rule 13): at most 1 KiB, and the connection is closed if it is not fully read within 1 second.

### 4.1 Re-reading the desired state

```json
{"v": 1, "query": "reload"}
```

- The mesh process re-reads the file given by `--config` at startup, the same as on receiving `SIGHUP`; the request carries nothing itself and is only a trigger. The reply is sent after the background thread has finished applying:

  ```json
  {"v": 1, "reload": {"result": "applied", "problems": []}}
  {"v": 1, "reload": {"result": "rejected", "reason": "listen port 41821 is one nett itself uses on this host: …"}}
  ```

  `applied`: this desired state is in effect, and `problems` lists situations that still need attention after applying (section 6, for example a member's admission material being rejected); `rejected`: the whole document is rejected and the previous one stays in use;
- If applying has not finished within 10 seconds (for example a data plane operation is stuck), the reply is `busy`, and this desired state continues to be applied as usual;
- `nett reload` sends this request and shows the result: the exit code is 0 for `applied`, listing `problems`; 1 for `rejected` or when the mesh process cannot be reached. For a container member use `docker exec <container> /nett reload`. **Do not use `docker kill -s HUP`**: whenever any signal is sent with `docker kill`, Docker records the container as manually stopped, and a `unless-stopped` container then does not start automatically after Docker restarts (host reboot);
- On macOS, `sudo nett install` sends the same request when the desired state has changed (release.md section 4); `SIGHUP` still works (systemd's `systemctl reload`), only without a result to inspect.

### 4.2 Coordination with nett-node

```json
{"v": 1, "query": "coordinate"}
```

- nett-node (root only) keeps this connection open while it runs; both sides then write one JSON object per line, each at most 1 KiB. It carries the switch proposals and confirmations that go through the Hub when both ends of a pair are `dial-only` (mesh.md section 8.4), so the mesh process never connects to the Hub:

  ```json
  {"hub": true}
  {"path_switch": {"peer": "node_01J…", "message": "<base64>"}}
  ```

- nett-node sends `hub` when the connection opens and whenever its Hub session comes up or goes down; the mesh process uses the Hub path only while it is `true`. `path_switch` from the mesh process names the peer it is for, and from nett-node the peer it came from; the message is authenticated end to end and opaque to nett-node and the Hub;
- One coordinator at a time: a new `coordinate` connection replaces the old one. Lines in each direction queue up to 16 and further ones are dropped (the sender retries); a line that is not valid is dropped and the connection kept.

## 5. Node names

The desired state gains an unsigned `names` entry: a map from node ID to node name. The signing tool writes it from the names of the machines in the site (site.md section 4); after joining the Hub, the Hub delivers it, from the same source as hostnames (mesh.md section 11).

```json
"names": { "node_01JC…": "edge-vps", "node_01JD…": "mac-app" }
```

- Node names are used only for display and lookup, not as a basis for identity: a wrong name never causes any peer to be configured or allowed. To confirm who the other side is, use the node ID, and later the identity lookup (mesh.md section 11);
- The format is the same as the names of machines in the site: lowercase letters, digits and `-`, at most 63 characters; with a wrong format the whole desired state is rejected and the previous one stays in use (local-signing.md section 5). A node without a name is shown by its node ID;
- The desired state has one more field: upgrade `nett` on the nodes first, then switch to the newly generated desired state. Older versions reject fields they do not recognize, and keep using the previous desired state in the meantime.

## 6. Status contents

Times are UTC in RFC 3339 format; durations and relative times are computed by `nett status` from the local clock.

| Part | Contents |
|---|---|
| `node` | Node ID and name, `nett` version, mesh address, Edge address (with the `edge` role), reachability, data plane (`kernel` / `userspace`), WireGuard port, NAT type and mapped address (mesh.md section 6.1), LAN addresses with their prefix length (private IPv4 and IPv6 unique local addresses on interfaces other than the mesh interface and loopback, at most 8, used by the Hub for LAN direct candidates, mesh.md section 6), whether the clock is trusted (mesh.md section 8.4), the time the mesh process started |
| `relay` | On a relay: UDP and TLS ports, the number of members and links assigned, the TLS certificate fingerprint nett-relay reported and when it last fetched its assignment (mesh.md section 5.2); absent elsewhere |
| `config` | The time the desired state in effect was accepted; the version of the access rule set. A rejected desired state is listed in `problems` (when a reload fails, the previous one stays in use) |
| `peers` | One entry for each admitted member, see the table below |
| `problems` | Situations that need attention, each with a time and a reason: this machine is not among the admitted members, desired state rejected, a member's admission material rejected, access rule set or advertised routes rejected, data plane operation failed, trust store read or write failed (mesh.md section 4.2). The first five belong to one desired state: they are discarded when the next desired state is accepted, and those that still exist are reported again on application (material that fails verification is reported on every application). Data plane operations are retried automatically after a failure and are listed if one happened in the last 5 minutes, and stay listed while the failure continues. A trust store read or write failure stays listed until the next successful write |
| `events` | The mesh process's 32 most recent events (path switches, hole punching, admission and rejection, and so on, the same as the events in the log), for investigating recent switches |

For each peer:

| Field | Contents |
|---|---|
| `id`, `name` | Node ID and name |
| `mesh`, `edge`, `routes` | Mesh address; Edge address (with the `edge` role); the routes it advertises |
| `state` | `connected`: a packet from the peer was received in the last 30 seconds; `connecting`: sending to it, nothing received yet; `unreachable`: sending to it, something was received before, but nothing in the last 30 seconds; `idle`: no packets in either direction in the last 30 seconds (no probing without traffic, so there is nothing to judge by; the `dial-only` side sends keepalive every 25 seconds, mesh.md section 4, so this appears only between two `public` nodes); `no_path`: the desired state has no path to it (no access rule involves this pair, site.md section 6) and no packet from it was received |
| `path` | The current path: `kind` (`lan` / `direct` / `relay` / `relay_tls`), the relay it goes through, the endpoint in WireGuard, whether it was obtained by hole punching (`punched`), the time and reason of switching to it. The follower does not choose paths, and the path is judged from WireGuard's current endpoint: if it is the address of one of the relays among the local candidates, the path is via that relay, otherwise it is direct; there is no switching time or reason |
| `rtt_ms`, `loss`, `jitter_ms` | Round-trip time of in-tunnel probes on the current path, loss rate and jitter over the last 10 probes (mesh.md section 7). Empty when this machine follows by roaming and does not probe; when both sides are `dial-only`, both ends measure |
| `last_handshake`, `last_received`, `rx_bytes`, `tx_bytes` | Time of the last completed WireGuard handshake; time the last packet from the peer was received; bytes received and sent |
| `role` | This machine's role in the pair: `decider` (decides the path, sends probes) / `follower` (follows by roaming, mesh.md section 8.3); between `public` and `dial-only`, the `dial-only` side decides |
| `candidates` | Each candidate path on the decider: type, relay, address, round-trip time, loss rate, and `current` / `ok` / `failing` / `untested` |

Status contains no private keys, probe tokens, or any credential content other than signatures and certificate fingerprints (hard rule 10).

## 7. `nett status`

Output is in English, following architecture.md section 14.3.

### 7.1 Overview

```
$ sudo nett status
node     mac (node_01JD7M3XQ4W8N2K5R9T6V3B7C1)
version  nett 0.2.0
mesh     100.88.0.4, fd00:88::4
network  dial-only, userspace WireGuard, port 53557
nat      cone, 198.51.100.7:53557
config   applied 3h ago, access rules v3

PEER      ADDRESS     STATE        PATH                RTT     LOSS  HANDSHAKE
edge-vps  100.88.0.1  connected    direct              9.4 ms  0%    41s ago
laptop    100.88.0.5  unreachable  relay vps-02 (tls)  -       -     2h ago
mac-app   100.88.0.3  no path      -                   -       -     -
vps-02    100.88.0.6  connected    direct              31 ms   <1%   12s ago
```

- The header is this machine, one item per line; items that do not apply are not shown (for example there is no `edge` line without the `edge` role, and a `public` node has no `nat` line);
- Peers are sorted by name; `PATH` shows the type and the relay it goes through, and a direct path obtained by hole punching is shown as `direct (punched)`;
- For peers where this machine is the follower (for example the `dial-only` peers of a `public` node), `RTT` and `LOSS` are `-`: only the decider measures, so look at the peer;
- When there are `problems`, they are listed at the end, one per line, with a relative time:

  ```
  PROBLEMS
  2m ago  desired state rejected, still using the previous one: listen port 41821 is one nett itself uses on this host: …
  ```

- When the clock error exceeds 2 seconds (mesh.md section 8.4), the header gets an extra line `clock  not synchronized`; when this machine is not among the admitted members, the `mesh` line reads `not admitted`;

- Round-trip times under 10 milliseconds keep one decimal place and the rest are rounded to integers; loss rates are rounded to integers, and shown as `<1%` when below 1% but not 0; byte counts use decimal units (`13.2 MB`); relative times are written as `41s ago`, `5m ago`, `2h ago`, `3d ago`;
- When output is not a terminal it is the same, not truncated and without color.

### 7.2 One peer

```
$ sudo nett status edge-vps
peer       edge-vps (node_01JC4QK2ZB8X5R3N9T7V6W2Y1H)
mesh       100.88.0.1, fd00:88::1
edge       100.88.0.2, fd00:88::2
state      connected
path       direct 203.0.113.10:41820, since 2h ago (better path type)
quality    rtt 9.4 ms, loss 0%, jitter 0.3 ms
handshake  41s ago
received   1s ago
traffic    13.2 MB in, 10.1 MB out
role       decider

CANDIDATE     ADDRESS              RTT     LOSS  STATE
direct        203.0.113.10:41820   9.4 ms  0%    current
relay vps-02  198.51.100.20:41822  12 ms   0%    ok

EVENTS
2h ago  path switched to direct 203.0.113.10:41820 (better path type)
2h ago  path switched to relay 198.51.100.20:41822 (unreachable)
```

The argument is the peer's name or node ID; if not found, it reports an error and lists the existing peers. Events are listed newest first, only those related to this peer; paths in events are the same as in the log and are written as addresses. When this machine is the follower there is no `quality`, no candidate paths and no switch reason, and the `role` line reads `follower (edge-vps measures and chooses the path)`.

### 7.3 `--json` and exit codes

- `--json` outputs the whole status the mesh process replied with (section 6), with field names and versions kept stable per section 4; used together with a peer name, it outputs only that peer;
- Exit codes: 0 when status was obtained, even if some peers are unreachable; 1 when the mesh process cannot be reached, permissions are insufficient, or the peer is not found. Errors are written to standard error:

  ```
  nett: the mesh service is not running (no socket at /run/nett/mesh.sock)
  nett: the mesh service is not running (/run/nett/mesh.sock does not accept connections)
  nett: permission denied for /run/nett/mesh.sock; run with sudo
  ```

## 8. Implementation and resources

- The mesh process has one more thread that accepts connections and handles them one at a time: it reads the request, sends a query to the runtime's background thread (through an existing bounded queue), the background thread builds a snapshot from the engine, the path selection state and the data plane's peer statistics and hands it back, and then it is written back to the client. When the queue is full, or no snapshot can be delivered within 2 seconds (for example the desired state is being applied), the reply is `busy`; reads and writes each have a 1-second timeout. After replying it first closes the write direction, then discards input from the other side that was not read (at most 64 KiB): when closing with unread data, Linux sends a reset to the other side, which may then be unable to read the reply;
- The thread that accepts connections checks every 500 milliseconds whether it should exit, without depending on the socket file still being there (exit does not hang when the file has been deleted);
- The event ring buffer holds 32 entries; `problems` holds one entry each for the desired state and the access rule set, and at most 32 each for members and advertised routes (hard rule 14); a reply is at most 4 MiB, and `nett status` reads no more than that;
- The thread that accepts connections uses a 256 KiB stack (only the pages actually used are resident); the extra memory when idle targets within 100 KB, measured on Linux (RSS, PSS) and macOS (RSS, `footprint`);
- `nett status` is read-only and does not change any state of the mesh process;
- `reload` is handed over a bounded channel to the party that reads the desired state, going the same way as `SIGHUP`: read the file, validate, hand to the background thread; after applying, the background thread hands the result back. At most 4 `reload` requests are in progress at once, and the rest get `busy`.

## 9. Verification

| Level | Contents |
|---|---|
| Unit tests | Snapshot generation (the various peer states and paths, follower without probe data, peer without a path); no private keys or probe tokens in the serialized result; request validation (too long, not JSON, wrong version, unknown query, timeout); the results of `reload` (accepted with problems listed, whole document rejected, `busy`) and how the party that reads the desired state handles them; `nett status` layout (units, precision, relative times, missing fields, `problems`), comparing the output against fixed status documents |
| Lab scenarios | In the admission scenario (`admission`, which CI runs on all three topologies), each member's `nett status --json` lists the other members and their names, a pair that has just connected has state `connected` and a path, and the negative case is listed as `member_rejected` on the first member; the same is readable on userspace members. When reloading a desired state that carries only lower-version material, `nett reload` reports `applied` and lists this rejection, and peers already in effect stay unchanged. The state attached to a failed scenario includes each member's status (there is no `wg show` on userspace members) |
| Real machines | Run `nett status` on edge-vps (kernel WireGuard), the Mac native member (userspace) and mac-app (container member), and compare with `wg show` and the logs; running as non-root yields a permission error |
| Resources | The memory target in section 8 |

## 10. Open questions

| Question | Notes |
|---|---|
| Non-root users viewing status | Currently root only. If needed, a group (for example `admin` on macOS) can be added, opening only queries and not the later desired state delivery |
