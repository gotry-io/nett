# Architecture Decision Records (ADR)

One record per decision with a long-term architectural impact: context, decision, rationale, alternatives considered, consequences.

**Amendment rule**: before the project's first public release, an ADR can be revised directly. After the release, an accepted ADR is no longer modified; when a decision changes, a new ADR is added and the old one is marked "superseded".

| No. | Decision | Status |
|---|---|---|
| [0001](0001-hub-node-edge-roles.md) | Hub / node / public-facing processes are separate; management and traffic are separate | Accepted |
| [0002](0002-rust-for-hub-and-node.md) | Hub and node use Rust | Accepted |
| [0003](0003-api-and-protocols.md) | REST + OpenAPI externally, WebSocket + Protobuf internally | Accepted |
| [0004](0004-sqlite-storage.md) | Hub uses SQLite storage | Accepted |
| [0005](0005-react-spa-embedded.md) | Web console is a React SPA embedded in the Hub binary | Accepted; deferred, see 0024 |
| [0006](0006-auth-and-passkey-signing.md) | Identity model and passkey signing authorization | Accepted; passkey deferred, see 0024 |
| [0007](0007-own-mesh-wireguard-session-path-layer.md) | Own mesh: WireGuard session layer + nett path layer | Accepted |
| [0008](0008-mobile-dual-path.md) | Phones join over standard WireGuard with dual paths | Accepted; pairing see 0024 |
| [0009](0009-caddy-as-first-edge.md) | The reverse proxy in front of the Hub defaults to Caddy | Accepted |
| [0010](0010-ai-via-api-only.md) | AI connects only through the Hub API; node has no AI logic | Accepted |
| [0011](0011-nett-relay.md) | nett-relay: independent low-privilege relay and transport entry point | Accepted |
| [0012](0012-single-binary-packaging.md) | Single node-side executable, run as multiple processes by subcommand | Accepted; install script see 0024 |
| [0013](0013-mesh-and-transport-processes.md) | Mesh process and transport adapter | Accepted |
| [0014](0014-signed-mesh-membership.md) | The mesh member table consists of signed artifacts | Accepted |
| [0015](0015-origin-identity-and-lan-default-deny.md) | Origin identity and default deny for LAN prefixes | Accepted |
| [0016](0016-macos-container-member.md) | Container member on macOS | Accepted |
| [0017](0017-home-assistant-os-addon.md) | Run as an add-on on Home Assistant OS | Accepted |
| [0018](0018-client-platforms.md) | End-user devices: macOS native member, proxy client configs, and client planning | Accepted |
| [0019](0019-mesh-only.md) | nett only does mesh networking | Accepted |
| [0020](0020-release-signing.md) | Release signing: two keys (primary and backup), the public key is a build parameter | Accepted |
| [0021](0021-tailscale-parity.md) | Mesh experience is baselined on Tailscale | Accepted |
| [0022](0022-local-signing-before-hub.md) | Before joining the Hub, replace existing tunnels with local signing | Accepted |
| [0023](0023-access-default-deny.md) | Access is denied by default | Accepted |
| [0024](0024-cli-first-headless-hub.md) | The command line is the operating interface; the Hub ships without a console at first | Accepted |

Template:

```markdown
# Number. Title

- Status: draft / accepted / superseded by XXXX
- Date: YYYY-MM-DD

## Context
## Decision
## Rationale
## Alternatives considered
## Consequences
```
