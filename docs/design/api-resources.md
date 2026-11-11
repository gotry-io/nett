# API Resource Model

- Status: draft
- Phase: P0 (resources are implemented in M1, see section 8)
- Related: [architecture.md](../architecture.md), ADR [0003](../adr/0003-api-and-protocols.md), [0006](../adr/0006-auth-and-passkey-signing.md), [0015](../adr/0015-origin-identity-and-lan-default-deny.md), [0019](../adr/0019-mesh-only.md)

## 1. Scope

This document defines the resources of the external API: which resources exist, their fields, relationships, lifecycles, who may read and write them, and the general conventions.

Out of scope:

| Content | Document |
|---|---|
| Authentication methods, the full definition of permission scopes, the signing flow | `auth.md` |
| The execution flow of change sets, the full list of the action catalog | `changes.md` |
| The communication protocol between node and Hub | `protocol.md` |
| Mesh path selection and switchover algorithms | `mesh.md` |

## 2. General conventions

### 2.1 Paths and naming

- Base path `/api/v1`; resource names are plural and hyphen-joined: `/api/v1/nodes`, `/api/v1/api-tokens`;
- JSON fields use `snake_case`; enum values are lowercase `snake_case` strings;
- Timestamps are UTC in RFC 3339 format; durations are integers in seconds, with field names ending in `_secs`;
- Singleton resources carry no ID: `/api/v1/owner`, `/api/v1/hub`.

### 2.2 Identifiers

- **ID**: `<prefix>_<ULID>`, for example `node_01J9Z3K8Q2T7V4X6Y8A0B2C4D6`. IDs are immutable and ordered by time.
- **Name**: most resources also have a human-readable `name` (such as the node `edge-us-1`), unique within the resource type and changeable.
- `{id}` in a path also accepts the name: `/api/v1/nodes/edge-us-1` is equivalent to access by ID. References between resources always store the ID.

| Resource | Prefix | Resource | Prefix |
|---|---|---|---|
| nodes | `node` | changes | `chg` |
| passkeys | `pk` | events | `evt` |
| sessions | `ses` | devices | `dev` |
| api-tokens | `tok` | device-credentials | `dcr` |
| enrollment-tokens | `enr` | access-rules | `acr` |
| node-policies | `pol` | hostnames | `hst` |
| links | `lnk` | backups | `bak` |

### 2.3 General structure of a resource

```json
{
  "id": "node_01J9Z3K8Q2T7V4X6Y8A0B2C4D6",
  "name": "edge-us-1",
  "labels": { "region": "us", "role": "edge" },
  "created_at": "2026-10-12T08:00:00Z",
  "updated_at": "2026-10-12T09:30:00Z",
  "revision": 7,
  "spec": { },
  "status": { }
}
```

| Field | Meaning | Written by |
|---|---|---|
| `spec` | **Desired state**: what it should look like | User, API token, Hub (by permission) |
| `status` | **Actual state**: what it looks like now | Reported by the node, or computed by the Hub; API callers cannot write it |
| `revision` | Incremented on every change to `spec`, and also serves as the ETag | Hub |
| `labels` | Key-value pairs, used for filtering and selectors | User |

Common fields in `status`:

| Field | Meaning |
|---|---|
| `phase` | The current phase (an enum defined by each resource) |
| `observed_revision` | The `spec` revision most recently processed by the node or reconciler; a mismatch with `revision` means "taking effect" |
| `conditions` | List of status conditions: `{ type, ok, reason, message, since }`, explaining "why it is in this state" |

Read-only resources (such as `events`) have no `spec`.

### 2.4 Lists, filtering and pagination

- Cursor pagination: `?limit=50&cursor=<opaque string>`; `limit` defaults to 50 with a maximum of 200; the response carries `next_cursor`;
- Filtering: by label `?label=role:edge`, by reference `?node=edge-us-1`, by state `?phase=online`;
- Sorting: by `created_at` descending by default; supported sort fields are described per resource.

### 2.5 Concurrency and idempotency

- Changing `spec` requires `If-Match: <revision>`; a revision mismatch returns `412`, which avoids overwriting someone else's (including a script's) changes;
- Create requests support `Idempotency-Key`; a repeated request within 24 hours returns the result of the first one.

### 2.6 Errors

Uses RFC 9457 (`application/problem+json`) with a stable `code`:

```json
{
  "type": "https://nett.example.com/errors/revision-conflict",
  "title": "Resource was modified",
  "status": 412,
  "code": "revision_conflict",
  "detail": "Current revision is 8, the request is based on 7",
  "instance": "/api/v1/nodes/edge-us-1"
}
```

`code` is stable and meant for programs; `title` and `detail` are returned in Chinese or English according to the request's `Accept-Language` (or the user's `locale`).

### 2.7 Sensitive fields

- Keys, tokens and private keys are returned only once at creation; afterwards only a prefix or fingerprint is returned.

## 3. Write paths and risk levels

| Risk | Examples | Method |
|---|---|---|
| **Low** | Changing names and labels | Modify the resource directly |
| **Medium** | Changing a link's policy override (`link.set_policy`) | Through a change set: plan → apply |
| **High** | Enabling a module, setting a node role (such as `edge`), adding a device or device credential, widening access rules, advertising routes, revoking a node | Through a change set, requiring passkey signature approval |

- Medium- and high-risk writes do not modify the resource directly but create a `change`. When the write endpoint of the corresponding resource is called directly, the Hub returns `202` and the newly created `change`;
- **Lowering privileges** (disabling a module, revoking a token, disabling a device, narrowing access rules) is always treated as low risk and can be executed directly;
- Changing labels is itself low risk, but if it makes the expansion of an access rule larger (for example giving a node a label selected by an allow rule), that change is widening access and is handled as high risk (section 5.5);
- The risk level of each kind of write is defined by the action catalog (`action-types`), and `changes.md` gives the full list;
- Change sets are added with the web console and are used only for mesh actions, each with a single step (ADR 0019). Until then, medium- and high-risk changes are signed on the user's computer by the signing tool and pushed as signed artifacts through the `site` resource (hub.md section 4); the Hub only verifies the signature and version, without change sets (ADR 0024).

### 3.1 Actions on resources

Operations beyond create, update and delete are provided as actions:

```
POST /api/v1/<resource>/{id}/actions/<action>
```

For example `POST /api/v1/nodes/node_…/actions/remove`. Actions are also subject to the risk levels: low-risk ones execute directly and return the result; medium- and high-risk ones return `202` and the corresponding `change`.

## 4. Resource overview

| Area | Resource | Phase | spec written by | status written by |
|---|---|---|---|---|
| Identity and access | `owner` | M1 | User | Hub |
| | `trust` (trust anchor list) | M1 | User (signed) | Hub |
| | `passkeys` | M1 | User | Hub |
| | `sessions` | M1 | — | Hub |
| | `api-tokens` | M1 | User | Hub |
| Nodes | `nodes` | M1 | User | Node, Hub |
| | `enrollment-tokens` | M1 | User | Hub |
| | `node-policies` | M1 | User (signed) | Node |
| Activity | `events` | M1 | — | Hub |
| System | `hub`, `releases`, `backups` | M1 | User | Hub |
| Mesh | `links` | M1 | User (policy override) | Node, Hub |
| | `devices` | M1 | User (signed) | Hub, node (gateway) |
| | `device-credentials` | M1 | User (signed) | Hub |
| | `access-rules` | M1 | User (signed) | Hub |
| | `hostnames` | M1 | User, Hub | Hub |
| Changes | `changes` | With the web console | User, API token | Hub |
| | `action-types` | With the web console | — | Hub (built in) |

## 5. Resource details

### 5.1 Identity and access

**`owner`** (singleton): the only user.

| Field | Description |
|---|---|
| `spec.display_name` | Display name |
| `spec.locale`, `spec.timezone` | Console display preferences |
| `status.initialized_at` | Time initialization completed (first passkey registered) |
| `status.recovery_key` | Fingerprint and creation time of the recovery key |
| `status.backup_key` | Fingerprint and creation time of the backup public key |

**`trust`** (singleton): the trust anchor list currently in effect (format in `auth.md` section 11) and its version. Read-only; when a passkey is added or removed or the recovery key is replaced, the Hub generates a new version, which takes effect once signed.

**`passkeys`**: registered passkeys. See `auth.md` for registration and signing flows.

| Field | Description |
|---|---|
| `spec.name` | A recognizable name (such as "MacBook Touch ID") |
| `status.credential_id_hash`, `status.created_at`, `status.last_used_at` | — |

At least one passkey is kept; deleting the last one is rejected.

**`sessions`**: browser sessions, read-only. Action: `revoke`.

**`api-tokens`**

| Field | Description |
|---|---|
| `spec.name` | Description of the purpose |
| `spec.kind` | `script` (see `auth.md` section 6.2) |
| `spec.scopes` | List of permission scopes (defined in `auth.md`) |
| `spec.expires_at` | Expiry time, required, at most 1 year |
| `spec.allowed_sources` | Optional, allowed source address ranges |
| `status.prefix` | Plaintext prefix for identification (such as `nett_tok_8Kq3…`) |
| `status.last_used_at`, `status.last_used_from` | Most recent use |
| `status.phase` | `active` / `expired` / `revoked` |

The plaintext token is returned only once, in the creation response. Action: `revoke`.

### 5.2 Nodes

**`nodes`**

| Field | Description |
|---|---|
| `spec.name`, `labels` | Name and labels |
| `spec.description` | Note |
| `spec.relay_limits` | Traffic and bandwidth limits when acting as a relay |
| `status.phase` | `pending` (enrollment token created, not yet connected) / `online` / `offline` / `removed` |
| `status.version` | nett version |
| `status.platform` | `os`, `distro`, `kernel`, `arch` |
| `status.install_method` | `native` / `container_member` (the container member on macOS) / `haos_addon` (Home Assistant OS add-on); the console uses it to show only the modules that are available |
| `status.capabilities` | Detection results such as `wireguard_kernel`, `tun`, `docker`, `root` |
| `status.hard_deny` | Modules forbidden locally on the node (read-only, reported by the node) |
| `status.modules` | The state of each module: `{ name, enabled, state, message }` |
| `status.reachability` | `public` / `dial-only`, plus the detected external address and ports that need to be opened but are not reachable |
| `status.addresses` | LAN address, mesh address, Edge address (when the node has the `edge` role) |
| `status.relay` | Whether it provides relay and the traffic currently carried |
| `status.last_seen_at` | Time of the most recent communication with the Hub |

When Edge sends origin traffic, the source a service sees is the Edge address; when forwarded through a smart gateway or a container member, it is the smart gateway's entry address or the container member's address (ADR 0015, 0016). Services that need the visitor's real IP configure this address as a trusted proxy.

A node's module permissions are not changed in `spec` but through `node-policies`: enabling a module goes through a change set and requires a signature, while disabling a module can be delivered directly. Action: `remove` (high risk, revokes the node's credentials). Upgrades go through the `release` partition (`auth.md` section 11.3) and are not an action on the node. When a node leaves by itself (`nett leave`), the Hub marks it `removed` directly.

**`enrollment-tokens`**

| Field | Description |
|---|---|
| `spec.node_name` | The node's name after enrollment |
| `spec.modules` | Modules enabled initially |
| `spec.labels` | Initial labels |
| `spec.expires_at` | Expiry time (30 minutes by default, at most 24 hours) |
| `spec.enrollment_public_key` | The enrollment public key generated by the signing tool (the private key lives only in the token, see `auth.md` section 8.1) |
| `status.phase` | `active` / `used` / `expired` / `revoked` |
| `status.node_id` | The node ID assigned at creation; the node enters `pending` at the same time |
| `status.install_command` | The install command with the token (assembled by the signing tool, not stored by the Hub) |

**`node-policies`**: signed policies for node permissions. Policies that raise privileges are generated after a change set is approved and cannot be created directly.

| Field | Description |
|---|---|
| `spec.node_id` | Target node |
| `spec.modules` | Modules allowed to be enabled |
| `spec.roles` | Roles: `relay`, `gateway` (mobile gateway), `subnet_router` (smart gateway), `edge` (runs Edge on this machine and declares how to recognize traffic sent by Edge: the address of the container Edge runs in, or the system user when running natively); signed by `node.set_roles` |
| `spec.addresses` | Mesh address; with the `edge` role, also the Edge address |
| `spec.advertised_routes` | Advertised LAN prefixes (signed by `node.advertise_routes`) |
| `spec.enrollment_public_key` | Enrollment public key, used to verify admission proofs |
| `spec.policy_version` | Only increases |
| `spec.signature` | Passkey signature (may be omitted when lowering privileges) |
| `status.phase` | `pending` / `applied` / `rejected` |
| `status.reason` | Why it was rejected (such as invalid signature, version too old, hit a local hard deny) |

### 5.3 Activity: `events`

Read-only and append-only; serves as both the audit log and the activity timeline.

| Field | Description |
|---|---|
| `at` | Time of occurrence |
| `actor` | `{ kind, id }`; `kind` is `owner` / `api_token` / `node` / `system` |
| `action` | In the form `<resource>.<action>`, for example `device.add`, `node.remove`, `session.login` |
| `targets` | List of references to the resources involved |
| `outcome` | `success` / `failure` |
| `change_id` | The associated change set (if any) |
| `summary` | A one-sentence description for the timeline |
| `details` | Structured details; sensitive values are redacted |

- Recorded: all write operations and security events (login, token creation and revocation, signing, enrollment, and so on); queries are not recorded;
- Retained for 90 days by default; the API provides no deletion;
- Can be filtered by time, actor, action and target resource; real-time streaming is in section 7.

### 5.4 System

| Resource | Contents |
|---|---|
| `hub` (singleton) | Version, public address, data retention policy |
| `releases` | Available releases and their signature information; nodes fetch them from the Hub when upgrading |
| `backups` | Backup records: time, size, location, result. Actions: `create`, `verify` |

### 5.5 Mesh

**`links`**: the connection between a pair of nodes. Generated by the Hub from the mesh topology; no need to create manually.

| Field | Description |
|---|---|
| `status.endpoints` | The nodes or devices at both ends |
| `status.path` | The current path: `kind` (`lan` / `direct` / `relay` / `multi_hop`), `via` (the relays it goes through) |
| `status.transport` | `udp` / `tls` / `quic` |
| `status.rtt_ms`, `status.loss`, `status.jitter_ms` | Current quality |
| `status.candidates` | Candidate paths and their scores |
| `status.switched_at`, `status.switch_reason` | Time and reason of the most recent switch |
| `spec.policy` | Optional policy override: prefer direct, force via a given relay, fix the transport |

**`devices`**

| Field | Description |
|---|---|
| `spec.name`, `spec.kind` | Name; `phone` / `laptop` / `other` |
| `spec.paths` | Enabled paths: direct to home, mobile gateway |
| `spec.disabled` | When disabled, all of the device's credentials become invalid immediately (lowering privileges, executed directly) |
| `status.last_handshake_at` | The most recent handshake among all credentials |

Adding a device is a high-risk operation (`device.add`, which also creates the first credential).

**`device-credentials`**: one access credential of a device.

| Field | Description |
|---|---|
| `spec.device_id`, `spec.label` | The device it belongs to; description of its purpose (such as "third-party client") |
| `spec.kind` | `wireguard` / `connect` (CONNECT proxy credential, see `auth.md` section 9) |
| `status.public_key` | WireGuard public key (`wireguard`); for the `connect` type only the token prefix is returned |
| `status.address` | The assigned mesh address (`wireguard`). One address per credential: multiple credentials of the same device act as different peers of the gateway at the same time, and WireGuard does not allow the `AllowedIPs` of two peers to overlap |
| `status.gateway_node_id` | The mobile gateway this credential currently belongs to (determined by the handshake reported by the gateway, see `mesh.md` section 13) |
| `status.last_handshake_at` | The most recent handshake |

- **Private keys are generated only on the user's computer by the signing tool**; the Hub stores only the public key and never handles the private key; **configuration files, QR codes and proxy client configurations are generated by the signing tool once, at creation**, and cannot be exported again afterwards; if lost, create a new credential (`auth.md` section 9);
- Adding a WireGuard device creates two credentials at once: one for the primary configuration (direct to home + mobile gateway) and one for the "all via gateway" backup configuration (`mesh.md` section 13);
- Adding a credential to an existing device is a high-risk operation (`device_credential.create`) and requires a signature just like adding a device; creation is recorded in `events`;
- Action: `revoke`.

**`access-rules`**

| Field | Description |
|---|---|
| `spec.from`, `spec.to` | Selectors: nodes, devices, labels; `spec.from` can also select a node's Edge address (that node's `edge`) |
| `spec.ports` | Ports and protocols |
| `spec.action` | `allow` / `deny` |
| `spec.priority` | Priority |

The default is **deny** (`mesh.md` section 12, ADR 0023): connections between mesh members, to advertised LAN prefixes, and initiated from an Edge address can be established only if a rule allows them; the user's devices can by default reach all members and advertised LAN prefixes. Rules are matched by `priority`.

The whole rule set is delivered as one versioned signed artifact (`auth.md` section 10.1). **The signed artifact holds the result after selector expansion** (member IDs, addresses, ports), and nodes enforce only the expansion result; when a label change makes the expansion larger, the Hub generates a new rule set, which waits for a signature as a change that widens access, and until it is signed the old expansion result stays in force. Changes that widen access are high-risk operations; adding a deny rule or deleting an allow rule is narrowing and is executed directly.

**`whois`** (query interface): `GET /api/v1/mesh/whois?address=…` looks up which node, device or Edge a mesh address belongs to, for the console to display (the "identity lookup" in roadmap M1). This is a statement by the Hub; when a service or agent needs to confirm who the other side is, it uses the local `nett whois` (the mesh process answers from verified admission material, `mesh.md` section 11).

**`hostnames`**: hostnames within the mesh. Nodes automatically get a hostname (the node name); users can add aliases.

| Field | Description |
|---|---|
| `spec.name` | Hostname |
| `spec.target` | The node it points to |
| `status.origin` | `auto` / `user` |

### 5.6 Changes

**`changes`**: see [changes.md](changes.md) for the full design. Key points:

| Field | Description |
|---|---|
| `spec.steps` | Steps `{ action_type, target, payload, expected_revision }`; each change set has a single step |
| `spec.reason` | Reason |
| `spec.apply_mode` | `manual` / `on_approval` |
| `spec.not_before`, `spec.expires_at` | Earliest execution time; deadline for approval |
| `status.phase` | `planned` / `awaiting_approval` / `approved` / `applying` / `succeeded` / `failed` / `rejected` / `cancelled` / `expired` |
| `status.risk`, `status.proposed_by` | Risk level; proposer |
| `status.plan` | Plan result; its `hash` is the `plan_hash` that approval and signature bind to |
| `status.approval` | Approval information; for high risk, a passkey signature bound to `plan_hash` |
| `status.progress`, `status.result` | Execution progress; execution result |

Actions: `approve`, `reject`, `apply`, `cancel`.

**`action-types`**: the read-only action catalog. Fields: name, target resource type, risk level, whether it can be undone, required permission scope, description. See [changes.md](changes.md) section 8 for the full list.

## 6. Relationships

```
owner ── passkeys
      ── api-tokens ──┐
                      ├─► events (actor)
enrollment-tokens ─► nodes ◄── node-policies
                      │
                      ├── links (two ends)
                      └── hostnames
devices ── device-credentials
changes ─► any resource (target); events.change_id ─► changes
```

## 7. Real-time streams

Uses SSE:

| Endpoint | Contents |
|---|---|
| `GET /api/v1/streams/events` | Newly added activity events |
| `GET /api/v1/streams/resources?kind=nodes` | Resource changes (`status` updates), for the console to refresh |

The number of connections is capped; idle connections periodically send comment lines to stay alive.

## 8. Phases

| Phase | Resources |
|---|---|
| M1 | `owner`, `trust`, `nodes`, `enrollment-tokens`, `node-policies`, `events`, `hub`, `releases`, `backups`; site: `site` (the pushed site model, hub.md section 4); mesh: `links`, `devices`, `device-credentials`, `access-rules`, `hostnames` (node names and aliases), `whois` |
| Added with the web console (ADR 0024) | `passkeys`, `sessions`, `api-tokens` (`script`), `changes`, `action-types` |

## 9. Open questions

| Question | Where it is decided |
|---|---|
| The full list and naming of permission scopes | `auth.md` |
