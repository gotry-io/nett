# Design documents

[architecture.md](../architecture.md) is the overall design; each document here covers one topic in enough detail to start implementing. Before each phase starts, write that phase's design document here; when the implementation and the document disagree, change the document first.

| Document | Contents | Status |
|---|---|---|
| [prototype.md](prototype.md) | Prototype gate (first step of M1): questions to validate, scope, static configuration, lab environment, scenarios and pass criteria, order of work | Draft |
| [local-signing.md](local-signing.md) | Local signing (second step of M1, before joining the Hub): signing tool and keys, site, distribution and updates, access control and Edge, replacing existing tunnels | Draft |
| [userspace.md](userspace.md) | Userspace data plane and the macOS native member (M1, after local signing): choice of WireGuard implementation, data plane structure and traffic splitting, in-process filtering, utun and routes, coexistence with proxy apps, how it runs, verification | Draft |
| [site.md](site.md) | Site (M1, together with H1 of joining the Hub): maintaining machines, Edge, advertised routes and access rules with commands, connections derived from access rules, changes, signing and delivery, site directory | Draft |
| [hub.md](hub.md) | Joining the Hub (M1, after local signing): the command line as the operating interface, the headless Hub, site and Hub, node and Hub, enrollment, steps (H1–H5) | Draft |
| [status.md](status.md) | Local status (M1, before joining the Hub): the mesh process's local socket and read-only queries, node name in the desired state, status contents, output of `nett status` | Draft |
| [names-and-diagnostics.md](names-and-diagnostics.md) | Names and diagnostics (M1): the DNS responder for `<name>.nett.internal` and the system resolver on each platform, `nett whois`, `nett ping`, `nett doctor` | Draft |
| [release.md](release.md) | Release and installation (M1): versions and artifacts, release workflow and signing, Homebrew and the mesh service on macOS, Linux | Draft |
| [mesh.md](mesh.md) | Mesh: address plan, session layer and admission verification, relay, candidate paths and hole punching, measurement, path selection and switchover, transports, LAN smart gateway, hostnames, access control, phones and mobile gateway, platforms, failures and degradation | Draft |
| [auth.md](auth.md) | Authentication and authorization: trust model, identities and credentials, initialization and recovery, API tokens, permission scopes, node enrollment, device credentials, signature format, revocation, trust anchors, release signatures | Draft |
| [protocol.md](protocol.md) | Node ↔ Hub protocol: encrypted channel and authentication, message format, desired state, tasks, keepalive and reconnection, version compatibility | Draft |
| [api-resources.md](api-resources.md) | API resource model: general conventions, write paths and risk levels, resource details, real-time streams | Draft |
| [changes.md](changes.md) | Change sets and the action catalog: state machine, risk and approval, signing, execution, action catalog | Draft |

Naming: `<topic>.md`. Each document opens with its status (draft / accepted / implemented) and the phase it belongs to.
