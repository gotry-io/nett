# Changelog

User-visible changes by version. Versions follow [Semantic Versioning](https://semver.org); see design/release.md section 2.

## [Unreleased]

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
