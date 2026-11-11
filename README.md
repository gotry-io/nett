# nett

> Open-source, self-hosted mesh networking that connects your scattered machines into one network. It picks the best path automatically and switches when a path degrades or a node goes offline, without dropping active connections.

nett is for individuals and small teams with a few scattered machines, for example several VPSes in different regions plus a NAS or a server at home. WireGuard handles encryption, and nett's path layer picks the best path among LAN direct, public direct, hole-punched and relayed paths; when UDP is blocked it falls back to TLS. Other hosts at home join through a LAN smart gateway (subnet router), and your phone can reach them while you are out. Members join only with your signature. The footprint is very small, and the mesh keeps working while the Hub is offline.

- Homepage: [nett.gotry.io](https://nett.gotry.io) · a GoTry project
- Command line: `nett`
- Services:
  - `nett-hub`: the mesh control plane, operated with the `nett` command line; a web console comes later (ADR 0024)
  - `nett-node`: the control agent on every machine; handles enrollment, the connection to the Hub and upgrades
  - `nett-mesh`: the mesh process; handles WireGuard, path selection and switching, DNS and access rules
  - `nett-transport`: a low-privilege transport adapter that runs on demand and carries traffic over TLS when UDP is unavailable
  - `nett-relay`: relay and public transport entry point on nodes that accept inbound connections
- Status: **M1 in development** ([roadmap](docs/roadmap.md)). A mesh can be deployed with local signing ([design/local-signing.md](docs/design/local-signing.md)) or with a Hub ([design/hub.md](docs/design/hub.md)): Linux uses kernel WireGuard, macOS joins as a native member, and container services on a Mac that need real client IPs use a container member.
- License: [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option

## Install

`nett` runs on Linux and macOS:

```bash
curl -fsSL https://nett.gotry.io/install.sh | sh
```

The script installs only the `nett` program to `/usr/local/bin`, after checking the download against the hash written in the script. Release archives and their signatures are also on the [releases page](https://github.com/gotry-io/nett/releases) ([keys/](keys/README.md) explains how to verify them). On the computer that holds your site, you can install with Homebrew instead: `brew install gotry-io/tap/nett`.

### With a Hub

1. Run the Hub on a host other machines can reach ([packaging/hub/](packaging/hub/) has a Compose example with Caddy). `nett-hub init --url https://hub.example.com` prints a one-time link code.
2. On the computer that holds the site: `nett site init` once, then `nett site link <link code>`.
3. Add a machine: `nett site add <name>` (with `--public` for a machine others connect to; the Hub learns its public address). It prints one line to run on the new machine, the same on every platform, valid for 30 minutes and usable once:
   ```bash
   curl -fsSL https://nett.gotry.io/install.sh | sh && sudo nett install nett_enr_…
   ```
4. Change the site with commands such as `nett site allow`, `routes` and `edge` ([design/site.md](docs/design/site.md)). Every change lists what will be signed, is signed once you confirm, and is pushed to the Hub; nett-node on each machine hands it to the mesh process, and the command reports which machines applied it.

`nett site status` lists whether each machine is online and has applied the latest change, and the path and round-trip time between each pair. Machines upgrade themselves when a new release is out: each one verifies the release signature before installing it ([design/release.md](docs/design/release.md) section 7). Machines that were already members before the Hub connect with `nett site invite <name>`. `sudo nett leave` takes a machine out of the site, and every member drops it. While the Hub is down the mesh keeps working, and changes catch up when it is back.

### Without a Hub (local signing)

1. On the computer that holds the site: `nett site init`.
2. On each machine, `sudo nett install` creates its keys and prints the line for `nett site add`.
3. On the computer: `nett site add <name> --keys "<that line>"` (with `--public --ipv4 <address>` for a machine others connect to).
4. Give the machine its desired state: on a Mac that holds the site, run `sudo nett install` again, which finds it in the site directory; elsewhere, copy the generated `nodes/<name>/desired.json` over and run `sudo nett install --config desired.json`. Run the same command again after the desired state changes; it reloads without a restart.

The mesh service runs as root from a copy in a root-only directory, so run `sudo nett install` again after upgrading nett ([design/release.md](docs/design/release.md) section 4).

## Use

- `nett help` lists every command; add `--help` to any command for its usage.
- `sudo nett status` lists this node and every peer: whether it is connected, the path, round-trip time and loss, and any rejected configuration; `sudo nett status <peer>` shows one peer's candidate paths and recent switches ([design/status.md](docs/design/status.md)).

## Documentation

- [Vision](docs/vision.md): problems, goals and constraints
- [Architecture](docs/architecture.md): role boundaries, chain of trust, mesh, origin identity, technology stack
- [Roadmap](docs/roadmap.md): milestones and acceptance criteria
- [Architecture decision records](docs/adr/README.md)
- [Design documents](docs/design/README.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md) and [security policy](SECURITY.md)
- [CLAUDE.md](CLAUDE.md): security boundaries, coding conventions and commit format, also used by AI coding assistants
