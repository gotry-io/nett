# Changelog

User-visible changes by version. Versions follow [Semantic Versioning](https://semver.org); see design/release.md section 2.

## [Unreleased]

## [0.8.2] - 2026-11-22

- Right after two dial-only machines moved together to another relay through the Hub, the follower
  could still act on the outage it had measured on the relay they left: it waited for another
  proposal, then rotated through relays on its own and split the pair for several seconds. A
  switch both ends agreed on is now carried out before the follower measures.
- When the relay two dial-only machines were using stopped, the pair could be moved onto the same
  relay over TLS, which had stopped with it but still counted as working from an answer before the
  outage; the pair then stayed disconnected for several more seconds, and one end started rotating
  through relays on its own. The relay proposed through the Hub is now one that answered since the
  outage began, a path that stopped with it is not taken back on its earlier answers, and a better
  path is proposed through the tunnel only once that tunnel answers.
- Two dial-only machines could lose their connection for several seconds after a change on the
  Hub, such as a LAN address one of them reported: a new list of paths started one end over from the
  first relay while the other stayed on the relay both were using, and that end then rotated on its
  own. A pair now stays on the path it uses when its paths change, with what was measured of them.
- A path through a relay is measured end to end: with each probe of the relay, a member sends a
  through probe the relay forwards to the peer, and the peer's answer comes back through the relay
  (ADR 0029). Before, a member judged the path from the relay's answer and the peer's report of its
  own leg, which is over its last 10 probes, one every 5 seconds: when the peer's leg broke, for
  example when the peer's UDP was blocked, the member could move onto the broken path within
  seconds and lose every packet for about 4 seconds before moving back. A relay or peer on an older
  release does not answer through probes, and paths through it are judged as before.

## [0.8.1] - 2026-11-22

- `nett site status` kept listing a problem a machine reported when it applied a change after the
  problem had healed, such as a served port another program held until it was stopped. A machine's
  problems now come from the status it reports every 15 seconds.
- After a machine restarted while its peer reached it through the relay on that machine, the pair
  could stay disconnected for ten minutes, switching between the transports of another relay that
  only answered for its own leg. A path through a relay now has a round trip only once the peer has
  reported its leg: it is no better path to move to before that, and a failover tries the paths
  whose whole round trip is known first.
- The README, the Compose examples and the design say that upgrades start once you approve them
  with `nett site upgrade`.

## [0.8.0] - 2026-11-22

- A machine can serve a service that listens only on `127.0.0.1` to the mesh, as `tailscale serve`
  does for TCP: `nett site serve <machine> 8080/tcp` signs the port into the machine's node policy,
  and its mesh service forwards connections that arrive on its mesh address to the same port on
  `127.0.0.1`. Access rules decide who reaches the port, as for any other; the service sees every
  such connection come from `127.0.0.1`, so serve only services that trust loopback no more than
  the mesh. `nett status` shows the served ports. Every machine and the Hub need this release
  before a port is served; with a Hub, `nett site serve` checks.

## [0.7.1] - 2026-11-21

- `nett` and `nett-hub` end quietly when the reader of their output goes away, such as
  `nett status --json | jq` where jq is not installed, or `| head -1`, instead of panicking.

## [0.7.0] - 2026-11-19

- Machines on one LAN connect over it wherever the Hub runs: every LAN address a machine reports is
  tried by its peers and probes decide, as in Tailscale. Two dial-only containers on one Docker
  network, machines on a LAN the Hub is also on, and machines on routed LANs of one site (two VLANs)
  now connect directly. A probe is answered from any address once authenticated, and two dial-only
  machines learn the address the other's probes come from when another NAT sits inside the LAN.
- A better path that has never answered is probed every second only in its first minute, then every
  5 seconds while the pair is on a relay and every minute while it is direct (not at all when that
  direct path is within 5 ms), as in Tailscale.
- `nett status`, `nett whois` and `nett ping` need no sudo, as with Tailscale: every local user
  may read the status and probe, and only root may change what the mesh service does (`nett
  reload`). The status shows no keys or tokens; to an ordinary user it newly shows the members'
  public and LAN addresses, which Tailscale's status shows too.
- `nett ping` probes every path to the peer before each ping, so a path that just started working,
  such as after a firewall in the way was opened, is taken during the ping.
- The change listing of `nett site` says that two dial-only machines without a relay connect only
  over a LAN (`punch only; connects over a LAN, or once a relay is added: nett site relay
  <machine>`), and no longer lists LAN paths, which every pair tries.

## [0.6.0] - 2026-11-19

- Upgrades start when you approve them: the Hub holds each release, and `nett site status` shows
  it as available. `nett site upgrade` approves it for the Hub and every machine; `nett site
  upgrade <machine>` approves one machine first, and `--hub` the Hub alone. Nothing upgrades on
  its own. A site moving to this release still upgrades its Hub once by itself, as before; the
  machines then wait for the approval (ADR 0027). The computer that holds the site approves with
  `nett` 0.6.0: while it still runs an older one, approve once with the 0.6.0 program from the
  release (`./nett site upgrade`), which upgrades that computer's own `nett` with the rest.
- `nett site device add` writes the standard WireGuard configuration only: a client that takes
  WireGuard settings in a format of its own, such as a proxy app's WireGuard outbound, is set up
  from the same fields. The Surge configuration is no longer written.

## [0.5.0] - 2026-11-18

- The container: one image, `ghcr.io/gotry-io/nett`, for linux/amd64 and linux/arm64. Set
  `NETT_TOKEN` to the token from `nett site add`, keep `/var/lib/nett` in a volume, and run the
  service with `network_mode: service:nett`: it is reached at the member's mesh address and sees
  each caller's mesh address, on macOS too (design/container.md). The three-container Compose
  example is gone; a container member set up with it is removed with `nett site remove` and added
  again with the new image.
- The Hub and the container upgrade themselves with each release, the Hub before it relays the
  release: the program installed by root, or the one in the image, runs a newer version from the
  data directory or the volume once its release signature holds, and goes back to the version
  before when a new one does not settle (ADR 0026). `nett site status` shows the Hub's upgrade
  problem on its own line. The Hub's release files are named `nett-<version>-hub-<target>`, and its
  image is `ghcr.io/gotry-io/nett-hub`. A Hub before this release is upgraded by hand once.

## [0.4.0] - 2026-11-18

- Devices: a phone or computer that runs no nett joins with a standard WireGuard client or Surge.
  `nett site device add <name> --gateway <machine>` adds it through a public Linux machine, which
  is a mobile gateway while devices come through it, and writes the device's WireGuard and Surge
  configurations (and prints the QR code on a terminal); its private key is in those files only.
  Later devices come through the same gateway without `--gateway`. A device reaches every machine,
  or with `--limited` only what rules allow, such as `nett site allow <device> <machine> 8081/tcp`;
  `nett site device remove` revokes it. On a gateway
  whose system `filter FORWARD` chain drops forwarded traffic, as Docker sets it, nett adds one
  accept for `nett0` to `nett0` there. Devices need nett 0.4.0 on the Hub and every machine first,
  which `nett site` checks (design/devices.md).

## [0.3.21] - 2026-11-18

- macOS: every Mac installs with the install script, the one that holds the site too, and on a
  machine connected to a Hub nett-node upgrades the `nett` command together with the services, so
  the command always matches them. Homebrew is no longer a way to install nett: run
  `brew uninstall nett`, then the install script.
- Every nett program logs plain text, in a terminal too: the Hub's log in the journal carried
  terminal color codes.

## [0.3.20] - 2026-11-18

- Upgrades fetch the new program through the Hub (ADR 0025): the Hub keeps a verified copy of the
  current release's programs and relays a new release only once it holds them, and machines fetch
  the program over their connection to the Hub, falling back to the website when the Hub does not
  have it. Machines write the program to disk as it arrives instead of holding it in memory, and
  verify it as before. A program that could not be fetched is fetched again after 1 minute, then
  after twice as long each time up to an hour. A download that did not finish within 5 minutes
  marked the release as failed for good: a machine whose path to the website was slow never
  upgraded to it.
- `nett-hub` keeps the programs of the current release in `releases/` in its data directory.

## [0.3.19] - 2026-11-17

- Synology DSM 7 joins as a member: the install script and `sudo nett install <token>` as on
  other Linux machines. DSM's systemd is too old for nett's usual units, so nett writes units for
  it that run as root with bounded capabilities, and a Task Scheduler boot task starts them; the
  mesh process uses userspace WireGuard and carries the TLS transport itself (design/dsm.md).
  DSM loads the kernel's TUN driver only for packages that need it, so `nett install` loads it
  before it starts the services.
- Linux: when the kernel has no WireGuard, the mesh process uses the userspace data plane instead
  of failing to start.
- When a data plane update fails, the mesh process applies the desired state again after 1 second,
  then after twice as long each time up to 30 seconds, until it succeeds, and the failure stays in
  `nett status` and `nett site status` while it lasts. An interface that could not be created when
  the service started, for example because the system provided its TUN device later, stayed down
  until the next desired state or a restart, and after 5 minutes nothing showed the failure.

## [0.3.18] - 2026-11-16

- When a `public` member's WireGuard port or address changes, relays forward to the new one as
  soon as their assignment carries it. A relay kept the address it had bound before, also across
  its restarts, and learned the new one only from a handshake the member starts through it, which
  a member that only answers never does: every path to that member through a relay failed.

## [0.3.17] - 2026-11-16

- A pair that left a path because it was losing packets returns to it only once the path loses
  almost nothing for about a minute. A lossy path still answers most probes, and a pair went back
  to it after two replies, often within a second, and left again at the next burst of loss: tens
  of switches an hour, with most of the time spent on the lossy path.
- Linux: when a `public` member's WireGuard port changes while it runs, the probes on the
  WireGuard port move to the new port. They stayed on the old one until the mesh service
  restarted, so its direct path no longer answered probes and its relay legs were measured from
  a port the tunnel no longer used.

## [0.3.16] - 2026-11-16

- A pair moves to a better path, or to a relay much faster than its direct path, after the usual
  30 seconds even when two candidates of the same quality take turns at being the best; each turn
  started the 30 seconds again, so the pair could stay on the worse path.
- `nett status <peer>` shows the current path's round-trip time and loss as the tunnel measures them
  now; for a relay path the candidate table showed the values from before the switch.

## [0.3.15] - 2026-11-16

- A member measures its leg to a UDP relay from its WireGuard port, as the tunnel through that relay
  uses it. On a network that drops WireGuard's port toward a relay while other ports pass, the leg
  now shows as down, and the peer no longer moves onto that relay and back every minute or two.

## [0.3.14] - 2026-11-15

- Linux: one directory and one account. The trust store moves to `/etc/nett/state` and the relay's
  certificate to `/etc/nett/relay`, next to the keys, so `/var/lib/nett` and `/var/lib/nett-relay` go;
  the relay and the transport adapter run as users systemd allocates while they run, so the system
  users `nett-relay` and `nett-transport` go. The mesh process knows each helper by its systemd unit.
  The relay keeps its bindings in `/run/nett-relay` across restarts of the service. nett-node moves a
  machine to this layout after its upgrade: it copies first and keeps the old files until the upgrade
  has settled, then restarts once to remove them.

## [0.3.13] - 2026-11-15

- `sudo nett uninstall` removes everything nett placed on the machine except its identity, and says
  where that is: the services, the program, nett's own copy of the command, the upgrade records, the
  files of the running mesh, `/etc/resolver/nett.internal` on macOS, and on Linux also the `nett0`
  interface with nett's nftables tables and the system users with `/etc/sysusers.d/nett.conf`. The
  identity on Linux is given to root first. `sudo nett leave` also deletes the copy of the Hub's backup
  and the relay's certificate key. After both, nothing of nett remains. design/release.md section 8
  lists what nett places on each platform.
- Linux: the relay's and the transport adapter's units exist only while the desired state needs them;
  nett-node writes one when it starts the service and deletes it when it stops it.
- macOS: the services log only to the system log, an error that ends one and a panic included, so
  `/Library/Logs/nett` and `/etc/newsyslog.d/nett.conf` go. nett-node brings the launchd configuration
  up to the new program after an upgrade and reloads the mesh service with it; its own takes effect
  the next time launchd loads it, and the old log files go then.

## [0.3.12] - 2026-11-15

- macOS: the mesh service carries paths over TLS itself, as Tailscale does on macOS, so nett adds no
  account and no third service to a Mac. nett-node and `sudo nett install` remove the transport service
  of 0.3.11 together with its account and group `_nett-transport`, and the socket directory
  `/var/run/nett` is `0700` again. The TLS code now runs as root in the mesh process (ADR 0013).
- A relay's loopback port for TLS that cannot be opened, for example while another process still holds
  it, is tried again after 1 second and then at doubling intervals up to a minute. It stayed closed
  until the configuration changed, which would break the path over TLS on a Mac upgrading from 0.3.11.

## [0.3.11] - 2026-11-15

- macOS: paths over TLS work. The transport adapter runs as the launchd service
  `io.gotry.nett.transport` under its own hidden account, `_nett-transport`, which nett creates, and only
  while the machine has a path over TLS. Its connections leave through the physical interface like the
  mesh's own packets, so a proxy app's tunnel does not carry them. A Mac whose UDP to a relay is blocked
  now reaches it over TLS.
- `sudo nett install` with a new program also restarts a running relay and transport adapter, which
  otherwise kept the old program until the machine restarted.

## [0.3.10] - 2026-11-15

- A pair whose relay still answers but no longer reaches the other machine moves to another relay. It
  went back and forth between that relay's UDP and TLS paths, which share the broken leg, and stayed
  disconnected. A machine also reports a relay it has never reached as lost, so the other end does not
  move back to it.

## [0.3.9] - 2026-11-15

- The relay on a machine reaches that machine's WireGuard on loopback after an upgrade from 0.3.7. It kept
  the machine's public address it had learned, which works only where the cloud's network sends a
  machine's packets for its own public address back to it.

## [0.3.8] - 2026-11-15

- A machine that decides the path to a relay's machine also reaches it through that relay over TLS, which
  hands the packets to WireGuard there. The two stay connected when only TCP passes between them, for
  example when UDP across a border is blocked; before, every path between them crossed that UDP.

## [0.3.7] - 2026-11-15

- A stopping Hub says goodbye to every machine, which tries to connect again after about a second, and
  records when each was last seen and its disconnection. `nett site status` showed a machine that was
  online until the Hub restarted as last seen when it had connected, possibly hours before.
- A machine whose connection to the Hub breaks after more than a minute tries to connect again after
  about a second. It waited up to 90 seconds once earlier failures had lengthened its wait.

## [0.3.6] - 2026-11-15

- macOS: `nett` is signed with a Developer ID and notarized by Apple. macOS knows it as the same program
  across versions, so its firewall keeps letting other members reach the mesh process after an upgrade,
  and Gatekeeper accepts it.

## [0.3.5] - 2026-11-12

- On Linux, nett-relay and the transport adapter move to a new version once its upgrade has settled. They
  kept running the program they started with until the machine rebooted, through any number of upgrades.

## [0.3.4] - 2026-11-12

- A pair with little traffic moves to a relay that is much faster than its direct path, for example across
  a congested border: when the relay scores at most 70% of direct for 30 seconds. It returns to direct when
  direct comes close again or the pair carries more than 2 Mbit/s, so bulk transfers keep the direct path.
- On Linux, `nett doctor` says when `/etc/resolv.conf` names the upstream DNS servers instead of
  systemd-resolved's stub: programs then skip the routing of `nett.internal` to `nett0`, and only
  `resolvectl query` sees the names. It gives the command that points the file at the stub.

## [0.3.3] - 2026-11-11

- macOS: names under `nett.internal` resolve. The system resolver's queries to this machine's own mesh
  address are answered by the data plane, and other packets a Mac sends to its own mesh address get the
  checksum macOS leaves out for them, so local programs reach it over IPv6 as well as IPv4.
- `nett doctor` asks the DNS responder for this machine's own name, and reports a responder that does not
  answer as a problem rather than as a resolver setting.

## [0.3.2] - 2026-11-11

- macOS: a Mac reaches its own mesh address, and names under `nett.internal` resolve. The utun's address is
  point-to-point with itself, so macOS sent packets for it into the utun, and the system resolver's queries
  to the DNS responder timed out; the data plane now hands them back. `/etc/resolver` and its
  `nett.internal` file are readable by everyone.
- On Linux, `nett doctor` and `sudo nett install` say when ufw denies incoming connections without a rule
  for `nett0`: it drops what the mesh lets in, and other machines see this one as unreachable. The fix is
  `sudo ufw allow in on nett0`; nett filters the interface itself.
- Container members fall back to TLS when UDP is blocked: the Compose example runs the transport adapter
  as a third container in the mesh member's network namespace.

## [0.3.1] - 2026-11-11

- Container members: nett-node in its own container reads the mesh process's status and asks it to reload.
  The mesh process read a peer in another PID namespace as an error and closed the connection, so new
  desired states waited for the next restart and the site showed the machine as pending.
- A machine whose program nett-node does not install, such as a container member, counts the release it
  already runs as applied, and reports a newer one as available for its image to be upgraded.

## [0.3.0] - 2026-11-11

- Names: every machine answers as `<name>.nett.internal` (design/names-and-diagnostics.md). The mesh
  process answers `A` and `AAAA` for the site's machines on UDP 53 of its own mesh address and refuses
  every other name, so it never forwards. On macOS it writes `/etc/resolver/nett.internal`; on Linux the
  mesh service routes the suffix to `nett0` through systemd-resolved (`nett resolver`, run when the service
  starts) and does nothing without it. `sudo nett leave` removes the resolver file on macOS.
- `nett ping <peer>` sends probes through the tunnel and shows each round trip and, with sudo, the path it
  took; it works whatever the access rules allow. `sudo nett whois <address>` says which member, Edge or
  advertised prefix an address belongs to, from what this machine verified. `sudo nett doctor` checks the
  mesh service, the desired state, unreachable peers with their likely cause (closed WireGuard or relay
  ports), the clock, the relay, the TLS transport, the Hub connection, names, overriding units and failed
  upgrades, and exits with 1 when it finds a problem.
- The userspace data plane (macOS, and Linux members that use it) and relays ask for a 1 MiB receive buffer
  on their UDP sockets, which keeps short scheduling delays from dropping packets: in the lab the userspace
  data plane carries about 2.6 Gbit/s instead of 1.9, with no receive drops.

## [0.2.0] - 2026-11-11

- The Hub keeps an encrypted backup on every machine (design/hub.md section 8.2). `nett site link` creates
  `backup.key` in the site directory (keep a copy offline with `recovery.pk8`); the Hub seals a copy of its
  database and its identity key to it, and every machine fetches the latest copy into `hub-backup.enc` next
  to its configuration. When the Hub host is lost, `nett-hub restore --data <empty directory> hub-backup.enc`
  rebuilds it from any machine's copy with the `nett-backup-…` line, the machines connect to it on their own,
  and the next `nett site` command pushes what changed since. `nett site status` shows when the backup was
  made and how many machines keep it.
- Relays (design/site.md section 4.1, design/mesh.md section 5): `nett site relay <machine>` runs a relay on
  a public Linux machine, on UDP 41822 and TLS 443 unless `--port`, `--tls <port>` or `--no-tls` say
  otherwise, and `--off` stops it. Every connection then also goes through the relays other than its ends,
  over UDP and over TLS, and the path layer picks among them; a machine that cannot send UDP falls back to
  TLS. The relay creates its own certificate and the Hub learns its fingerprint; without a Hub, pass
  `--fingerprint` from `sudo nett status` on the relay. `nett relay` and `nett transport` are part of the
  Linux build and run as the system users `nett-relay` and `nett-transport`; nett-node starts them only
  while they are needed.
- When both ends of a connection are dial-only and their path breaks, they move to another relay together
  through the Hub within seconds, instead of waiting for the next time slot; the Hub only passes on messages
  the two members authenticate.
- Machines behind the same NAT connect over their LAN (design/mesh.md section 6): with a Hub, each machine's
  status lists its LAN addresses, and two connected machines on the same network get a LAN direct path.
- On Linux, nett's systemd units now live in `/usr/local/lib/systemd/system` and nett-node rewrites them
  when an upgrade changes them. A unit copied by hand to `/etc/systemd/system` would override them:
  `sudo nett install` stops and names it; move it away and run it again. The
  mesh service runs as the system user `nett` (created with systemd-sysusers), and `/etc/nett` belongs to its
  group, so the desired state is no longer readable by every user.
- `nett join <token> [--dir <directory>]` joins a machine that runs nett without nett's services, such as a
  container member: it does what `sudo nett install <token>` does and writes `hub.json` and `desired.json`
  in the directory; `nett leave --dir <directory>` undoes it. The container Compose example runs nett-node
  as a second container next to the member.
- The Hub limits what nodes can do to it (design/protocol.md section 11): 256 node connections, 16 handshakes
  at a time, 50 messages per second per session with bursts of 200. It keeps each machine's recent events
  (connections, applied and rejected changes, upgrades; 100 per machine for 30 days), and
  `nett site status <name>` shows the last ten. The Hub API is described by a generated OpenAPI document,
  `docs/api/openapi.json` (`nett-hub openapi`), with each operation's permission scope and risk level.
- `nett site status --json` prints only JSON; what was fetched from the Hub goes to standard error.
- Machines connected to a Hub upgrade themselves (design/release.md section 7). The Hub fetches
  `https://nett.gotry.io/release.json` every 6 hours (`nett-hub serve --releases <URL or file>`,
  `--releases off` to turn it off) and passes it on; nett-node downloads the program for its target,
  installs it only when the release signature verifies against the keys built into `nett` and the
  version is higher, restarts the mesh service, and rolls back to the previous program when the mesh
  service or the new nett-node does not come up. A version that failed is not tried again;
  `nett site status` shows each machine's version and the last upgrade problem. Releases also
  publish the bare program for each target. On Linux the program now lives in
  `/usr/local/lib/nett/nett` with the link `/usr/local/bin/nett`; `sudo nett install` and the install
  script set this up. The Hub's Compose example mounts the host's CA certificates.
- New machines join through the Hub (design/hub.md section 9, H2): with a Hub, `nett site add <name>` needs no
  `--keys`; it signs the node policy and prints one line to run on the new machine,
  `curl -fsSL https://nett.gotry.io/install.sh | sh && sudo nett install nett_enr_…`, the same on every
  platform. The install script only installs `nett` and checks it against the hash written in the script; the
  token carries an enrollment key, is valid for 30 minutes and works once, and `nett site invite <name>` prints a
  new one. A `--public` machine may leave out its public address: the Hub learns it (the global address the
  machine uses to reach the Hub, or the source address the Hub sees), and `nett site status <name>` shows the
  address and where it came from. `sudo nett leave` takes a machine out: it tells the Hub (every member then
  drops it) and removes the services, the mesh interface, and the machine's keys and configuration. Every
  `nett site` command first fetches what happened on the Hub (joins, departures, addresses) and records it in
  the site directory.
- Hub (design/hub.md section 9, H1): the new `nett-hub` (`serve`, `init`, `reset`; static Linux builds, a
  Compose example with Caddy in [packaging/hub/](packaging/hub/), a systemd unit for running it natively).
  `nett site link` links the site to a Hub; from then on every change is signed and pushed, and the Hub checks
  each signed artifact against the trust anchors pinned when linking (forged artifacts, older versions, the same
  version with other content, and bringing back a removed machine are refused whole) and composes each machine's
  desired state (identical to the file written without a Hub). The command waits up to 10 seconds and reports
  which machines applied the change and which rejected it or still have problems. `nett site invite <name>`
  prints `sudo nett install nett_enr_…` for an existing machine; it checks the node ID and trust anchors on the
  machine, writes the Hub configuration and starts the new `nett node` service (the control agent nett-node:
  connects to the Hub with Noise IK over WebSocket, writes the desired state file, asks the mesh process to
  reload it, reports its status; the mesh keeps working while the Hub is down). With a Hub, `nett site status`
  lists each machine's connection, version, acknowledgement and problems, and the state, path and round-trip
  time between each pair; `nett site status <name>` shows that machine's own status.
- On Linux, `sudo nett install` installs too: it puts `nett` in `/usr/local/bin`, creates or keeps the keys in
  `/etc/nett`, writes the systemd units built into it and starts them; `--config` imports the desired state,
  and a changed desired state is only reloaded. `sudo nett uninstall` stops and removes the services and keeps
  the keys and the desired state.
- Fixed: advertising routes again after removing all of them restarted the version at 1, which the mesh process
  rejected; the version now keeps counting.
- The site is kept with commands (design/site.md): `nett site add`, `set`, `remove`, `invite`, `edge`, `routes`,
  `allow`, `rules`, `status`. Every change first lists what will be signed (addresses and ports after selectors
  expand, connections added or removed), then signs once you confirm and rewrites the desired state of the
  machines it affects; pass `--yes` when not on a terminal. Which machines connect follows from the access rules:
  every pair a rule names, plus each dial-only machine with every public one; a pair of two dial-only machines
  is flagged as possibly unable to connect. Removing a machine also cleans up the rules that name it.
  `site.toml` and `nett site apply` are gone, and a 0.1.x site needs converting once; `nett keys` and
  `sudo nett install` print the line for `nett site add --keys`.
- The mesh process keeps a trust store on the machine (design/mesh.md section 4.2): the first accepted desired
  state pins this machine's trust anchors, and a desired state with different trust anchors is rejected as a
  whole; revocations and the applied versions of signed artifacts are written to disk, so after a restart
  older artifacts and revoked members are still refused; when the desired state file is rejected at start,
  the last state accepted as a whole is used. Machines that are already running build it from their current
  desired state on the first start after the upgrade, without losing connections. Location: `/var/lib/nett`
  on Linux — install the new `packaging/systemd/nett-mesh.service` (it adds `StateDirectory=nett`), otherwise
  `nett status` lists a "trust store" problem; `/Library/Application Support/nett/state` on macOS;
  `/etc/nett/state` in the mounted directory for the container image.
- `nett reload` reports a desired state for another node (a different node ID) as rejected and exits with 1.
  A new version of this machine's own node policy is refused once it has expired. The desired state file
  and its member and revocation counts are bounded.
- macOS: when the service configuration changes, `sudo nett install` unloads and reloads the service so the
  new configuration takes effect; it does not follow symbolic links when reading the desired state file.

## [0.1.5] - 2026-11-10

- Commands are regrouped by scope (`nett help` lists them by group; `--help` after any command shows its
  usage): commands for this machine are top-level, and `nett mesh` is only the mesh process run by the
  service manager. Renamed: `nett mesh install` / `uninstall` -> `nett install` / `uninstall`,
  `nett mesh keys` -> `nett keys`, `nett site build` -> `nett site apply`. Installed macOS services, systemd
  units and container images start `nett mesh` and keep working; update scripts and notes that use the old
  commands.
- New command `nett reload`: asks the mesh process to re-read its desired state file and shows whether it was
  accepted and what problems remain; it exits with 1 when the file is rejected. Container members use
  `docker exec <container> /nett reload`, Linux nodes `sudo nett reload`; on macOS, `sudo nett install` does
  this when the desired state changed. The 0.1.4 hint from `nett site build` said `docker kill -s HUP` for
  containers, which makes Docker treat the container as manually stopped, so an `unless-stopped` container
  no longer starts after the host restarts; if you followed it, run `docker restart <container>` once to
  clear that.
- macOS: `sudo nett install` prints the key line for the site description only while this machine has no
  desired state yet; later runs just report what happened.

## [0.1.4] - 2026-11-10

- New command `nett status`: this node's addresses and setup; for each peer whether it is connected, which
  path it uses, round-trip time and loss, and the last handshake; plus any rejected desired state, members
  or access rules. `nett status <peer>` shows the candidate paths and recent switches; `--json` prints the
  full status. It is read from the mesh process's local socket (`/run/nett/mesh.sock` on Linux and in
  containers, `/var/run/nett/mesh.sock` on macOS, `nett mesh --socket` to change it), which only root can
  read, so run `sudo nett status`. If you installed the systemd unit yourself, replace `nett-mesh.service`
  (it adds `RuntimeDirectory=nett`) and run `systemctl daemon-reload`; without it the mesh keeps working,
  the log has a warning and `nett status` cannot connect.
- `nett site build` puts node names into the desired state (unsigned, for display only). Earlier versions
  reject the field: upgrade nett on the nodes before giving them the new desired state; in the other order a
  node keeps using its previous desired state. Node names are at most 63 characters.
- Command-line messages and errors are in English only, and shorter.

## [0.1.3] - 2026-11-10

- A `dial-only` node's WireGuard port is picked by the system: the site description no longer sets
  `listen_port`, `ipv4` or `ipv6` for it, so a native member and a container member on the same host no
  longer compete for a port; `mesh interface ready` in the log shows the port in use. Earlier versions
  reject a desired state without a port: upgrade nett on `dial-only` nodes before giving them the new one.
- The WireGuard port cannot be one the mesh process uses itself (the probe port `41821` on mesh addresses,
  the TLS relay loopback ports `41830`–`41845`); `nett site build` reports it. Before, such a node stayed
  connected but sent and answered no probes, so it could not measure paths or notice failures.

## [0.1.2] - 2026-11-10

- A node in the site description can set `listen_port` for its own WireGuard port, so a native member and a
  container member on the same host each get one.
- The `nett site` directory defaults to `~/.config/nett` (following `$XDG_CONFIG_HOME`), so `--dir` is
  optional; `nett site init` makes the directory `0700`.
- `nett site build` writes each node's desired state to `nodes/<node>/desired.json` in the site directory.
- macOS: `sudo nett mesh install` finds this machine's desired state in the site directory of the user who
  ran sudo, so `--config` is only needed when the site is on another machine.
- macOS: `sudo nett mesh uninstall` reports the service as stopped only after its process has exited.

## [0.1.1] - 2026-11-09

- macOS: `sudo nett mesh install` does the whole setup: it creates this machine's keys and prints the line
  for the site description; with `--config <desired.json>` it checks that the desired state belongs to this
  machine, imports it and starts the service, and reloads without a restart when only the desired state changed.
- `nett mesh keys --dir` keeps existing keys and prints the same line again.
- The Homebrew caveats are in English only.

## [0.1.0] - 2026-11-09

First release: deploy a mesh with local signing before the Hub is ready.

- The mesh process: signed membership, automatic path selection and failover across direct, hole-punched
  and relayed paths; kernel WireGuard on Linux, a native member on macOS (userspace WireGuard and utun),
  and container members for container services on a Mac.
- Access is denied by default and opened by signed rules; the Edge address lets origin services see real
  client addresses.
- The signing tool `nett site`: keeps the recovery key on your own computer, signs nodes and rules, and
  writes each node's desired state.
- macOS: `brew install gotry-io/tap/nett`, then `sudo nett mesh install` installs the mesh service.
