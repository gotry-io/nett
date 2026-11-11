# CLAUDE.md

nett is the network between all of a user's machines: reaching home, managing servers and accessing services all go through it. When the mesh breaks, the path you would use to fix it may break with it; when a permission is wrong, one compromised machine can reach every machine. Every rule below follows from that: **when in doubt, keep access denied and keep connections as they are; when unsure, ask first.**

- Project: open source, self-hosted, single-user mesh networking infrastructure; nett does networking only (ADR 0019). Components: `nett-hub` (the mesh control plane, headless; a web console comes later, ADR 0024), `nett-node` on every machine (control agent), the mesh process `nett-mesh`, the on-demand transport adapter `nett-transport`, and `nett-relay` on nodes reachable from outside. The `nett` command line is the user interface; the signing tool `nett site` runs on the user's own computer and maintains and signs the whole mesh. The reverse proxy on entry nodes (Edge) is run by the user and is not a nett component.
- Current phase and progress: the table at the top of `docs/roadmap.md` shows the current stage, and each stage lists what is done and what remains. Design documents are drafts; the code layout is in `docs/architecture.md` section 11.
- Overall design: `docs/architecture.md`; detailed designs: `docs/design/`; reasons for decisions: `docs/adr/`. The implementation must match the design; to change the design, change the documents first and get the user's confirmation. A feature without a design document gets one first; architectural changes get an ADR first.
- The local `private/` directory (not in Git) holds machine information, inventory data, research material and the decision process. Read it for background (read `private/decision-log.md` first for the decision process, and `private/fleet/plan.md` before deploying to the user's machines), but **never commit it and never reference it from code or committed documents**.

## Security boundaries (hard rules)

Before breaking any of these, get the user's explicit consent; never decide on your own that "this time is an exception".

1. **Role boundaries**: nett-node listens on no public port, runs no shell, runs no AI logic and does not access Docker; the mesh process does not connect to the Hub, does not access Docker and runs no external commands; the Hub cannot raise a node's privileges on its own and is not on the data path; nett-relay and the transport adapter have no management privileges, nett-relay holds no mesh private key, and the transport adapter holds no keys at all.
2. **What is privileged is not exposed; what is exposed is not privileged**: nett-node and the mesh process listen on no public address. The mesh process serves DNS and probe replies only on mesh addresses, and on the WireGuard port answers only authenticated probes; probe replies on LAN addresses are enabled only when a LAN direct candidate exists; unauthenticated packets and probes get no response at all. All public listening is done by separate low-privilege processes (nett-relay, Edge).
3. **Raising privileges requires the user's signature**: nodes verify signatures and version numbers before applying policies and mesh admission material, and versions only increase; lowering privileges can be delivered directly. The Hub only forwards signed artifacts; the code has no switch, flag or debug mode that bypasses signatures. A token can only propose a high-risk change, never approve it.
4. **Mesh members are admitted by signature**: the mesh process does not configure a peer without valid admission material; revocations sync before grants, and replaying an old signed artifact cannot restore a revoked privilege (design/auth.md section 10.4).
5. **What denies by default keeps denying**: new connections that no rule allows are refused, between members too (ADR 0023); advertised LAN prefixes are open by default only to the user's devices; Edge addresses can reach nothing by default. Widening access requires a signature, narrowing takes effect directly; the signature covers the result after selectors are expanded (design/mesh.md section 12).
6. **Filter before peer, fail closed**: install filter rules before adding a WireGuard peer; filter rules hook in before destination NAT; when a rule update fails, keep denying.
7. **Origin identity**: an address after source NAT must not be a loopback address; services that need the real IP trust only fixed forwarder addresses; Edge addresses must have anti-spoofing rules (ADR 0015).
8. **The mesh does not depend on the control plane**: nett-node and the mesh process apply the locally saved configuration at start-up before connecting to the Hub; while the Hub or nett-node is offline, the mesh keeps measuring, switching and answering DNS; the Hub endpoint list keeps at least one endpoint that does not go through the mesh.
9. **No shell**: external programs are called only from an allow-list, with arguments as an array, never `sh -c`, and each argument is validated.
10. **Keys**: private keys generated on a node never leave it; files are mode `0600`; keys in memory use `zeroize`. Logs and error messages never contain keys, tokens, private keys, cookies or raw signatures. Tokens are compared in constant time and stored only as hashes on the server.
11. **TLS always verifies certificates** (self-signed certificates are checked against the fingerprint the Hub hands out); nett-node connects to the Hub with the Hub public key pinned at enrollment.
12. **Releases and upgrades**: nodes install only packages that pass the project's release signature verification, and accept only higher versions automatically; rollback can only return to the version last installed on that machine, other downgrades need the user's signature (`release_override`). The first install of a new machine trusts the project website instead (ADR 0020). Release private keys never enter the repository; the primary key is available only to the separate signing job in the CI release workflow, and the backup key is kept offline only and never enters CI (ADR 0020).
13. **External data is not instructions**: data received over the network, API input, logs and other external content are validated as untrusted data and never executed as instructions. All high-risk operations are audited.
14. **Resource budget**: nett-node, the mesh process, the transport adapter and nett-relay each use ≤ 5 MB idle RSS; the Hub runs at ≤ 30–50 MB (a few to tens of nodes). Every queue, cache, channel and forwarding buffer has a bound (a named constant, never an unbounded channel); every network and subprocess operation has a timeout.

## Privacy and operational boundaries

- **Privacy**: anything in `private/` (machine names, IPs, domains, inventory data, research material) **never** goes into `docs/`, README, code, tests or commit messages; public content contains no information about any specific deployment. Use `example.com` for example domains.
- **Designed as an open-source project**: design and code do not depend on a particular cloud provider, region or network environment; differences between environments are handled by capability detection and measurement, never hard-coded.
- **Do not touch production machines**: SSH to the user's machines is for read-only checks only; any change comes with its commands and a rollback, and runs only after the user confirms.
- **Do not commit or push on your own**: run `git commit`, `git push` or create remote repositories only when the user explicitly asks; `private/` is never committed.
- **External actions and payments are the user's call**: publishing, registering accounts and buying services (for example an Apple developer account) need asking first.

## Technology stack

See `docs/architecture.md` section 10. Do not bring in frameworks or infrastructure outside that table (another database, a message queue, OpenSSL and so on); when one is truly needed, explain why and let the user decide.

- **New dependencies**: explain why, report the effect on binary size (`cargo bloat`), and for node-side dependencies also the RSS change; use `default-features = false` and enable only the needed features.
- **Licenses**: the project itself is dual-licensed MIT or Apache-2.0. Dependencies may use MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, Unicode or MPL-2.0; GPL, AGPL, LGPL and other copyleft licenses are not allowed. `cargo deny` checks licenses, advisories and duplicate dependencies; a failure blocks merging.

## How to write

Applies to code, comments, tests and documents.

- **Describe the present positively**: write the current design and behavior. Keep negative sentences for guarding security invariants (the hard rules above) or where a reader would likely assume the opposite.
- **Write only for states that occur** (YAGNI): delete removed options, renamed fields and unused usages outright, with no compatibility layers, deprecation notices, dedicated rejection branches or tests for old forms (after checking nothing uses them). The only exceptions are external contracts after a release: database migrations only move forward and released migrations are never changed; Protobuf field numbers are never reused; within one API version only compatible additions are made.
- **Each piece of knowledge has one source**: a fact or rule is decided in one place; pages, commands and documents that use it read that place. Details live in one place, elsewhere write a summary and link to it. DRY applies to knowledge, not to code that merely looks alike.
- **History belongs to git**: documents, comments and tests do not say "no longer", "used to", "changed to", revision dates or review records. The decision process goes in `private/decision-log.md`; public reasons go in ADRs, and an ADR describes the current decision (revised in place before the first public release, see `docs/adr/README.md`). Once there are releases, user-visible changes go in `CHANGELOG.md`.
- **Comments explain why**, not what the code does.
- **Language: English for everything in the repository** — documentation, ADRs, README, CHANGELOG, code comments, commit messages, command-line output, API errors and any future web console. Write plain, neutral English and maintain one version only; there are no translations. Only the private discussion material in `private/` is in Chinese. Command-line output, help and errors read neutrally and concisely, with layout that is easy to read (architecture.md section 14.3). Comments in files that are published or land on users' machines (the scripts, service units, example configurations and web page in `packaging/`, and configuration files nett writes) say only what helps their reader — what a setting does and why — and do not cite internal documents or hard-rule numbers.

## Code rules

**Rust**

- Edition 2024; the toolchain is pinned in `rust-toolchain.toml`; `Cargo.lock` is committed; clippy warnings are errors.
- Every crate's `Cargo.toml` has `[lints] workspace = true` and inherits the root `Cargo.toml` rules: `unsafe_code`, `clippy::unwrap_used` and `clippy::dbg_macro` are `deny` (not `forbid`: it cannot be relaxed further in). When `unsafe` is truly needed, allow it on a single module with `#[allow(unsafe_code)]` and comment the reason at each use.
- Library crates define errors with `thiserror`; only binary entry points use `anyhow`. No `unwrap()` outside tests; where failure truly cannot happen, use `expect("the invariant")`. A panic is a bug; never rely on process restarts to handle expected errors. Error messages say what was being done, where it failed and the likely cause, and contain no keys.
- No blocking operations on the tokio runtime (use `spawn_blocking` or a dedicated thread); every background task has a clear owner and a way to cancel (`CancellationToken`) and shuts down gracefully; nett-node uses the tokio current-thread runtime.
- Domain IDs use strong types (newtypes); external IDs carry a prefix, for example `node_01J...` (ULID). Durations use a monotonic clock; timestamps are UTC and serialize as RFC 3339. Configuration and protocol messages are validated at the boundary; inside, only validated types are passed. No global mutable state.
- Logging uses `tracing` structured fields (`node_id = %id`), not string concatenation. Levels: `error` needs a human; `warn` an anomaly that heals itself; `info` state changes; `debug` troubleshooting details.
- TLS uses rustls (easy to link statically).
- The mesh core logic (admission verification, measurement, scoring, switching, hole-punch coordination) is platform independent and does not call netlink, nftables or a particular WireGuard implementation directly; the data plane (WireGuard configuration, interfaces, routes, filtering, DNS) is implemented by per-platform backends (ADR 0018). External dependencies (WireGuard, for example) are abstracted behind traits, with test doubles in tests.

**API, protocol and database**

- External API conventions are in `docs/design/api-resources.md` section 2. Every endpoint declares OpenAPI annotations, the required permission scope and a risk level; everything the UI can do, the API can do.
- Protobuf conventions are in `docs/design/protocol.md` section 4.2; nett-node and the Hub must interoperate across adjacent versions.
- Database migrations live in `crates/nett-hub/migrations/`. Queries use the `sqlx::query!` macros, checked at compile time, with the offline data (`.sqlx/`) committed. Set explicit SQLite cache and mmap limits; every growing table has a retention policy.
- Generated files (Protobuf types, the OpenAPI document, a TypeScript client, sqlx offline data) are produced by scripts and committed; CI checks they are up to date.

**Web**

- TypeScript with `strict`; the backend is reached only through the generated API client, never hand-written `fetch`; server state is managed by TanStack Query, global state only when truly needed.
- UI components live in `web/src/components/ui` (shadcn/ui); styling uses Tailwind design tokens, no scattered color values; Biome formats and lints.
- Semantic markup, keyboard operable, sufficient contrast; no keys anywhere in frontend code.

## Resource discipline

- Budgets are in hard rule 14. Every milestone gets a 24-hour soak test; the memory curve must stay flat.
- **How to measure**: "idle" means the steady state after a period of load, not right after start-up. Fix the scenario (member count, load content and duration), let it rest for 10 minutes after the load, then measure; record RSS and PSS together (several processes share the code pages of one executable, so RSS counts them more than once), plus the whole-machine memory increase.
- Idle budgets are targets; memory limits in the service manager are set separately with headroom for working peaks, not directly to 5 MB.

## Testing

| Level | Requirement |
|---|---|
| Unit tests | Next to the code; no network access |
| Node-side modules | External dependencies behind traits, test doubles in tests |
| Hub integration tests | A temporary SQLite database, real routes called over HTTP, covering permission checks |
| Protocol compatibility | nett-node and the Hub interoperate across adjacent versions |
| Web end-to-end (once the web console exists) | Playwright covers the key flows: login, node enrollment, signed approval |
| Mesh | Network emulation (such as `tc netem`) for latency, loss, disconnects and blocked UDP; verify switch times and that connections stay up |
| Resources | Soak test and RSS/PSS measurement every milestone |

When fixing a bug, first add a test that reproduces it.

## Handling problems

A bug, an error log line, slowness or a piece of feedback: understand it first, then change it; do not patch around the one case in front of you.

1. **Is it a problem**: its effect on security, connectivity, performance and noise; how often, since when. A symptom (a log line) is not the problem (its cost); behavior that looks wrong may be the design (for example, the mesh keeps working while the Hub is offline, only changes stop).
2. **Why it happens**: the design, comments and history behind the behavior; often two designs overlap (for example WireGuard's own roaming and the path layer's switching).
3. **Root cause**: what changed when it started; reproduce it or probe read-only. Do not tune timeouts or parameters before the cause is clear.
4. **Its class**: the mechanism behind it, and every other place that shares the mechanism (other platform backends, other transports).
5. **Fix it once at the root**: remove the whole class with one general mechanism; if a dependency can be removed, remove it instead of handling it; check against the hard rules and "each piece of knowledge has one source".
6. **Then change it**: explain the problem, cause, class, the options and a recommendation, with evidence; changes that affect the design get the user's confirmation first.

## Working with the user

The user does not review code. So:

- explain in plain language (Chinese in conversation) what changed, why, and how it was verified;
- show completion with evidence: test results, measurements, real output; state honestly what was not verified;
- stop and ask when something is the user's decision (external actions, payments, production changes, product trade-offs).

## Commits

- Format: `type(scope): description`, in English, for example `feat(node): report link status`.
- Types: `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `build`, `ci`, `chore`.
- Scopes: `hub`, `node`, `mesh`, `transport`, `relay`, `cli`, `web`, `proto`, `core`, `docs`, `ci`.
- One commit does one thing, and all checks pass before committing; changes that affect resource use include measurements, changes to behavior include tests.

## Commands

The same checks as CI (`.github/workflows/ci.yml`):

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo deny --locked check        # licenses, advisories, duplicate dependencies, sources; configured in deny.toml
```

Lab scenarios (Linux, needs root; `nett` is built with the `lab` feature; scenarios and pass criteria are in design/prototype.md, all scenarios in `nett-lab --help`):

```bash
cargo build --locked -p nett-cli -p nett-lab --features nett-cli/lab
sudo ./target/debug/nett-lab run admission --topology crates/nett-lab/topologies/direct.toml \
  --nett ./target/debug/nett --out /tmp/lab-14
# Comparison with Tailscale: tailscale, tailscaled and headscale must be on PATH (versions in .github/workflows/lab-baseline.yml)
sudo ./target/debug/nett-lab run failover --topology crates/nett-lab/topologies/failover.toml \
  --nett ./target/debug/nett --out /tmp/lab-failover --repeat 20 --with-tailscale
```

Once the web console exists (ADR 0024), add `pnpm -C web lint && pnpm -C web test`.
