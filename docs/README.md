# Documentation

| Document | Contents |
|---|---|
| [vision.md](vision.md) | The problem to solve, feature scope, requirement priorities, design constraints, non-goals |
| [architecture.md](architecture.md) | Overall design: the three planes, role boundaries, chain of trust, mesh, phone access, origin traffic, tech stack, failures and availability, packaging and running, platforms, security essentials, main risks, facts learned in practice |
| [roadmap.md](roadmap.md) | Content and acceptance criteria of each phase |
| [design/](design/README.md) | Detailed design per topic; the details are authoritative here |
| [adr/](adr/README.md) | Architecture decision records: the context, rationale and rejected alternatives of each key decision |

Development rules (security boundaries, coding conventions, documentation style, commit conventions) are in [CLAUDE.md](../CLAUDE.md) at the repository root.

**Maintenance conventions**

- When an architectural decision changes, add or revise an ADR, then update `architecture.md` and `roadmap.md`;
- Before each phase starts, write its design document in `design/`; when the implementation and the document disagree, change the document first;
- Each piece of knowledge is written in one place; elsewhere, write a summary and link to it; documents describe the current state, and history stays in git;
- The repository holds no research material and no information about specific deployment environments.
