# nett

[中文](README.md) · English

> Open-source, self-hosted infrastructure that connects your machines and AI agents into one network: AI can understand it and operate it safely, and your agents can reach each other with trust.

nett is for individuals and small teams with a few scattered machines, for example several VPSes in different regions plus a NAS or a server at home. One Hub, plus `nett-node` on every machine, covers mesh networking, monitoring and alerting, deployment, and ingress routing. It is designed for a very small footprint and gives AI operations and agent-to-agent access a secure foundation. The mesh picks the best path among LAN, public internet and cross-border routes, and switches automatically when a path degrades or a node goes offline.

- A GoTry project · Homepage `nett.gotry.io` (under construction)
- CLI: `nett`
- Services: `nett-hub`, `nett-node`, `nett-mesh`, `nett-transport`, `nett-relay`
- Status: **design phase**, no usable code yet
- License: MIT or Apache-2.0 (dual-licensed)

## Documentation

Design documents are written in Chinese, which is the source of truth. User-facing guides (installation, usage, troubleshooting) will be available in both Chinese and English.

- [Vision](docs/vision.md): problems, goals and constraints
- [Architecture](docs/architecture.md): role boundaries, modules, authentication, mesh, tech stack
- [Roadmap](docs/roadmap.md): milestones and acceptance criteria
- [Architecture decision records](docs/adr/README.md)
- [Design documents](docs/design/README.md)
- [Development guide](docs/development.md)
