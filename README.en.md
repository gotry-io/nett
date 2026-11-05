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
- Status: **design phase**, no usable code yet
- License: MIT or Apache-2.0 (dual-licensed)

## Documentation

Design documents are written in Chinese, which is the source of truth. User-facing guides (installation, usage, troubleshooting) will be available in both Chinese and English.

- [Vision](docs/vision.md): problems, goals and constraints
- [Architecture](docs/architecture.md): overall design: role boundaries, chain of trust, mesh, origin identity, tech stack
- [Roadmap](docs/roadmap.md): milestones and acceptance criteria
- [Architecture decision records](docs/adr/README.md)
- [Design documents](docs/design/README.md)
- [Development rules](CLAUDE.md): security boundaries, coding conventions and commit format (also used by AI coding assistants)
