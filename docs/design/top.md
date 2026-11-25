# Live Views: `nett top` and `nett site top`

- Status: draft
- Phase: M1 (roadmap stage 6)

## 1. Goals

Watch the mesh while it works, in the terminal:

- `nett top`: this machine and its peers, refreshed every second: each peer's state and path, traffic in and out, round-trip time, loss and jitter, and on request the candidate paths and recent events of one peer;
- `nett site top`: every machine and every link between them, on the computer that holds the site, through the Hub: the same numbers for each pair of machines, refreshed every 2 seconds, with the machines' state and the events of the whole mesh;
- Both cost nothing while nobody watches: the machines report their full status to the Hub only when it changes (hub.md section 5), and send the numbers that move all the time only while a `nett site top` is open.

`nett status` and `nett site status` stay the one-shot views for reading and for scripts (`--json`); the live views read the same data and add rates and short histories.

## 2. What comparable products show

Read at Tailscale v1.106.1, NetBird v0.83.2, ZeroTier 1.16.2 and Nebula v1.12.0:

- **One machine**: none has a live full-screen view. `tailscale status` has no watch mode (`cmd/tailscale/cli/status.go`); its debug command `watch-ipn --engine-updates` streams the engine's state, with each peer's byte totals and last handshake, every 2 seconds on one long-lived response from the local API (`ipn/ipnlocal/local.go`). `netbird status -d` has no watch mode either (`client/cmd/status.go`), and its daemon's `SubscribeStatus` pushes on state changes only, not on counters (`client/proto/daemon.proto`). `zerotier-cli peers` prints once (`one.cpp`); Nebula has no status command;
- **Numbers**: every one exposes per-peer byte totals, and rates are computed by whoever reads them: Tailscale's client metrics are totals labeled by path type, with no peer (`wgengine/magicsock/magicsock.go`); ZeroTier's Prometheus metrics have per-peer latency and packet counts, off by default since 1.16.1 (`node/Metrics.cpp`); Nebula's are totals only (`stats.go`). Per-peer latency comes only from NetBird (the ICE pair's, on direct paths, `client/internal/peer/worker_ice.go`) and ZeroTier; none reports per-peer loss;
- **The whole network**: none has a live view. Tailscale's client sends its network information to the control server only when it changes (`control/controlclient/direct.go`) and no per-peer traffic; its network flow logs, per connection in 5-second windows (`wgengine/netlog/netlog.go`), go to a separate log service on paid plans and are documented as not meant for monitoring. NetBird's management API has each peer's connection state and last seen, without traffic, latency or path (`shared/management/http/api/types.gen.go`);
- Third-party terminal views exist for Tailscale (lazytailscale, tuiscale) and NetBird (netbird-tui); their READMEs describe polling the local daemon every 2 to 5 seconds.

nett differs in three ways. The Hub already gathers every machine's status, so a live view of all links needs no new collection, only a faster pace while someone watches. Each pair's round-trip time, loss and jitter come from the in-tunnel probes of the machine that chooses the path (mesh.md section 7), so the view shows loss, which none of the others measure per peer. And the pace follows the viewer: when no view is open, machines report on change, as Tailscale's client does, instead of streaming counters nobody reads.

## 3. Where the numbers come from

| View | Source | Pace |
|---|---|---|
| `nett top` | The daemon's local socket, the `status` query (status.md section 4), read by any local user | Every second |
| `nett site top` | The Hub: each machine's latest status (`GET /api/v1/site/status`) at start, then the stream of section 6, which carries each machine's status when it changes and its samples | Samples every 2 seconds while the view is open (hub.md section 5) |

- **Rates** are the change in WireGuard's byte counts between two readings divided by the time between them: the client's monotonic clock for `nett top`, the daemon's monotonic clock carried in each sample for `nett site top`, so the delay through the Hub does not bend them. The counts include WireGuard's own overhead and keepalives, so they are the traffic on the wire. When a count goes down (the peer was set up again, the daemon restarted), that interval has no rate;
- **A pair** is measured by the machine that decides its path, as in `nett site status` (hub.md section 3.4): its path, state and candidates, its measurements, and its counts for the two directions. When the decider sends no samples (a release without them), the other end's counts are used for the rates;
- **Histories** for the small charts are kept by the view while it runs, at most 300 points per series (5 minutes at 1 second, 10 minutes at 2 seconds); nothing keeps them after it ends, on the machines or the Hub.

## 4. `nett top`

```
nett top  mac (node_01JD…)  100.88.0.4  dial-only, userspace WireGuard, port 53557      live

PEER    ADDRESS     STATE      PATH           RTT     LOSS  IN          OUT         RTT
edge-vps  100.88.0.1  connected  direct (obfs)  9.2 ms  0%    1.2 Mbit/s  48 kbit/s   ▁▁▁▂▁▁▁▁▁▁▁▁▁▁
vps-02  100.88.0.6  connected  direct (obfs)  164 ms  0%    12 kbit/s   3.0 kbit/s  ▃▃▃▄▃▃▇▃▃▃▃▃▃▃
nas     100.88.0.8  no path    -              -       -     -           -
vps-03  100.88.0.5  connected  direct (obfs)  5.5 ms  0%    9.6 Mbit/s  320 kbit/s  ▁▁▁▁▁▁▂▁▁▁▁▁▁▁

EVENTS
12s ago  vps-02: path switched to direct 203.0.113.20:41820 (peer restarted)
2m ago   member laptop admitted, policy v2

↑↓ select   enter details   t traffic or rtt   q quit
```

- The header is this machine's line from `nett status` (status.md section 7.1), shortened to one line; the peers are those of `nett status`, in the same order and with the same words for state and path;
- `IN` and `OUT` are this machine's view: received from the peer and sent to it. A peer this machine follows shows `-` for round-trip time and loss, as `nett status` does: only the decider measures; a peer the site gives no path shows `-` for traffic too;
- The header's right side says `live`, or why the last reading failed;
- An event about one peer names it first, unless its text already does;
- When the daemon cannot be reached at start, the command ends with the error of `nett status` (status.md section 7.3) and exit code 1; when it stops answering later, the header says so and the view keeps asking every second.

## 5. `nett site top`

```
nett site top  hub.example.com  5 machines  access rules v5                             live

MACHINE  HUB     VERSION  NETWORK               RELAY                PROBLEMS
edge-vps   online  0.12.0   public, userspace     -                    -
vps-02   online  0.12.0   public, userspace     4 members, 5 links  -
mac      online  0.12.0   dial-only, userspace  -                    -

LINK           STATE      PATH           RTT     LOSS  JITTER  A→B         B→A         RTT
edge-vps - vps-02  connected  direct (obfs)  164 ms  0%    0.5 ms  12 kbit/s   3.0 kbit/s  ▃▃▃▄▃▃▇▃▃▃▃
mac - vps-03   connected  direct (obfs)  4.8 ms  0%    0.2 ms  9.6 Mbit/s  320 kbit/s  ▁▁▁▁▁▁▂▁▁▁▁

EVENTS
12s ago  laptop  vps-02: path switched to direct 203.0.113.20:41820 (peer restarted)
7m ago   mac     vps-02: path switched to relay 198.51.100.20:41822 (high loss)

↑↓ select   enter details   t traffic or rtt   q quit
```

- Machines and links are those of `nett site status` (hub.md section 3.4), from the site directory and the Hub; `A` is the first machine of the pair as written;
- The events are the most recent ones in every machine's status (status.md section 6), with the machine they come from and the peer they are about, newest first; a switch both ends record shows once for each end;
- The header's right side says how current the view is: `live` while samples arrive, `connecting` while the stream is being opened, and when the Hub cannot be reached the reason and the next attempt; the stream is opened again after 1 second, then twice as long each time up to 30 seconds. A machine whose last sample is more than 10 seconds old shows the values of its latest status and `-` for rates; one on a release without samples always does. A Hub of a release without the stream answers it with `404`: the view still shows each machine's latest status, read again at each attempt, and the header says `this Hub sends no samples: nett site upgrade`;
- Run where `nett site status` runs: on the computer that holds the site, with the Hub linked; without a Hub the command says so and ends with exit code 1.

## 6. The stream: `GET /api/v1/streams/links`

Server-sent events (api-resources.md section 7), with the owner token; risk low, read only. While at least one stream is open, the Hub asks every connected machine for samples (hub.md section 5); the open stream is the request, so a view that ends, or loses its connection, stops the samples within 10 seconds without a message of its own.

```
event: status
data: {"name": "vps-02", "node_id": "node_01JD…", "status_at": 1795570000, "status": {…}}

event: sample
data: {"name": "vps-02", "node_id": "node_01JD…", "at_ms": 86412345,
       "peers": [{"id": "node_01JC…", "rx_bytes": 120400, "tx_bytes": 98100,
                  "rtt_ms": 9.4, "loss": 0.0, "jitter_ms": 0.3}]}

event: resync
data: {}
```

- `status` carries a machine's status document each time it reports one, the same as in `GET /api/v1/site/status`; `sample` carries a machine's sample as it arrives, with `at_ms` on that machine's monotonic clock; `resync` tells a view that fell behind that messages were dropped, and the view reads `GET /api/v1/site/status` again;
- The Hub keeps no samples: it passes each one to the open streams and forgets it. It sends a comment line every 15 seconds so that proxies and the view see the connection alive, and the view opens the stream again when nothing arrives for 30 seconds;
- At most 4 streams at a time; a fifth gets `503` with a problem saying so. Each stream queues at most 64 messages; when one is full, its oldest messages are dropped and it gets `resync`.

## 7. Screen and keys

The two views share one screen, built with ratatui (section 8):

- `↑` `↓` (or `k` `j`) select a row of the peers or links; `enter` opens its details, `esc` closes them; `t` switches the small charts between round-trip time and traffic (both directions together); `q` or `ctrl-c` ends the view with exit code 0;
- A chart spans the whole history in the width it has, each character the highest of its share of the points; round-trip time is scaled from its lowest point to its highest, traffic from zero; a gap is a reading without a value;
- The details of a peer or link: its path with the time and reason of the switch, its quality and traffic in all, the charts of round-trip time and of each direction's rate over the history, its candidate paths as in `nett status <peer>` (status.md section 7.2), and its events;
- The command line's rules apply (architecture.md section 14.3): no colors and no emoji, units on every value, relative times, `-` where there is no value. The selected row is shown in reverse video; the charts are Unicode block characters;
- Below 80 columns the chart column is left out, below 60 the screen asks for a wider terminal; the screen follows resizes;
- Both views need a terminal on standard input and output; otherwise they end with exit code 1 and name the command for programs (`nett status --json`, `nett site status --json`). The screen is restored on exit, on `ctrl-c` and after a panic.

## 8. The terminal library

ratatui 0.30 with its crossterm 0.29 backend (both MIT), `default-features = false` with only that backend:

- It does the parts a full-screen view needs and that are easy to get wrong by hand: raw input and its restoration, resizing, layout by constraints, tables, wide characters, and drawing only what changed. Written by hand on escape codes, the views would need all of these with no dependency;
- Cost, measured with nett's release profile on aarch64-apple-darwin: the stripped program grows from 6,600,872 to 6,965,192 bytes (+364 KB, 5.5%) with the views, the stream and the reporting on change together. Of the code `cargo bloat` counts (+307 KiB), about 150 KiB is ratatui, crossterm and their helpers (ratatui-core 44, crossterm 30, ratatui-widgets 20, kasuari 17, unicode-segmentation 9) and 64 KiB nett's own. The build on macOS gains 37 crates, about half of them derive macros used only while compiling; `unicode-width` 0.2 sits beside the 0.1 nett already has;
- Only `nett top` and `nett site top` run it. The daemon never executes it, so its private memory does not change; the program, which every machine carries, grows by its size.

## 9. Resources

- `nett top` reads one status per second, which the daemon builds as for `nett status` (status.md section 8);
- `nett site top` holds one stream; while it is open each machine reads its status every 2 seconds and sends a sample of about 60 bytes per peer, about 2 KB every 2 seconds for six machines with five peers each, and the Hub passes them on;
- The views keep at most 300 points per series and the latest status of each machine; the Hub keeps at most 4 streams of 64 messages each, and a machine one request, which lasts at most 60 seconds (hard rule 14).

## 10. Verification

| Level | Contents |
|---|---|
| Unit tests | nett-node: a status whose counts, measurements and candidates' answers move makes no report for 10 minutes, a path, state, event or block makes one at once (on tokio's paused clock); a request held to its bounds, renewed and ended; a sample's peers. The Hub: streams counted and capped, samples checked, a stream that falls behind told to resync, streams ended when the Hub stops. The views: rates from counts (two readings, a count that goes down, a clock that did not move); a link's numbers from the end that measures it and from the other end once the measuring end's samples are stale; a newer status replacing an older one; charts fitting their width and histories bounded; the screen on ratatui's test backend at 120, 70 and 50 columns and with details open; the keys; the event stream's parser |
| Hub integration | Real routes over HTTP with a real nett-node session: the stream needs the owner token; a machine that connects while it is open is asked for samples and they arrive on it; a fifth stream gets `503`; closed streams stop counting |
| Real machines | Before release: the reports the rule makes, judged on each machine's status read through the Hub every 15 seconds for 50 minutes; `nett top` on a Mac against a daemon of the release before, and `nett site top` against a Hub of the release before. After release: `nett site top` against the Hub of this release, and the report bytes the Hub receives in a day without a view, against the 257 MB a day six machines send when each reports its whole status every 15 seconds |
| Resources | The daemon's idle private memory unchanged; the program's size from `cargo bloat`, recorded in section 8 |
