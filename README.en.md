# nett

[中文](README.md) · English

> Open-source, self-hosted mesh networking infrastructure that connects your scattered machines into one network: it picks the best path automatically and switches when a path degrades or a node goes offline, without dropping active connections.

nett is for individuals and small teams with a few scattered machines, for example several VPSes in different regions plus a NAS or a server at home. WireGuard handles encryption, and nett's path layer picks the best path among LAN direct, public direct, hole-punched and relayed paths; when UDP is blocked it falls back to TLS. Other hosts at home join through a smart LAN gateway (subnet router), and your phone can reach them while you are out. Members join only with your signature. The footprint is very small, and the mesh keeps working while the Hub is offline.

- A GoTry project · Homepage `nett.gotry.io` (under construction)
- CLI: `nett`
- Services:
  - `nett-hub`: the mesh control plane and web console
  - `nett-node`: the control agent on every machine; handles enrollment, the connection to the Hub, and upgrades
  - `nett-mesh`: the mesh process; handles WireGuard, path selection and switching, DNS, and access rules
  - `nett-transport`: a low-privilege transport adapter that runs on demand and carries traffic over TLS when UDP is unavailable
  - `nett-relay`: relay and public transport entry point on nodes that accept inbound connections
- Status: **M1 in development**. Before the Hub is ready, you can deploy a mesh with local signing ([design/local-signing.md](docs/design/local-signing.md), in Chinese): Linux uses kernel WireGuard, macOS joins as a native member, and container services on a Mac that need real client IPs use a container member. The Hub and the console are not done yet
- License: [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option

## Install

- **macOS** (native member and the signing tool `nett site`):
  ```bash
  brew install gotry-io/tap/nett
  sudo nett install    # creates this machine's keys and prints the line for the site description
  # add this node to the site description (~/.config/nett/site.toml by default)
  nett site apply
  sudo nett install    # finds this machine's desired state, checks and imports it, starts the mesh service
  ```
  Run the same command whenever the desired state changes (it reloads without a restart); if the site is on another machine, add `--config <this node's desired.json>`. The mesh service runs as root (creating the utun interface needs root) from a copy in a root-only directory, so run `sudo nett install` again after every `brew upgrade nett` ([design/release.md](docs/design/release.md) section 4, in Chinese).
- **Linux**: download the static build for your architecture from [Releases](https://github.com/gotry-io/nett/releases), verify its signature ([keys/](keys/README.md)), install it to `/usr/local/bin`, create this machine's keys with `sudo nett keys --dir /etc/nett`, and use [packaging/systemd/nett-mesh.service](packaging/systemd/nett-mesh.service).
- **Commands**: `nett help` lists every command; add `--help` to any command for its usage.
- **Check the status**: `sudo nett status` lists this node and every peer: whether it is connected, the path, round-trip time and loss, and any rejected configuration; `sudo nett status <peer>` shows one peer's candidate paths and recent switches ([design/status.md](docs/design/status.md), in Chinese).

## Documentation

Design documents are written in Chinese, which is the source of truth. User-facing guides (installation, usage, troubleshooting) will be available in both Chinese and English.

- [Vision](docs/vision.md): problems, goals and constraints
- [Architecture](docs/architecture.md): overall design: role boundaries, chain of trust, mesh, origin identity, tech stack
- [Roadmap](docs/roadmap.md): milestones and acceptance criteria
- [Architecture decision records](docs/adr/README.md)
- [Design documents](docs/design/README.md)
- [Security policy](SECURITY.md)
- [Development rules](CLAUDE.md): security boundaries, coding conventions and commit format (also used by AI coding assistants)
