# node ↔ Hub Protocol

- Status: draft
- Phase: P0 design; M1 implementation (see section 12)
- Related: ADR [0003](../adr/0003-api-and-protocols.md), [0019](../adr/0019-mesh-only.md), [auth.md](auth.md), [changes.md](changes.md), [api-resources.md](api-resources.md)

## 1. Scope and goals

This document defines the control protocol between nett-node and the Hub: connection establishment, encryption and authentication, message format, desired state delivery, status reporting, task execution, reconnection, and version compatibility. The mesh data plane (traffic between nodes) is out of scope; see `mesh.md`.

Goals:

| Goal | Meaning |
|---|---|
| End-to-end security | Even if TLS terminates at a reverse proxy in front of the Hub, the reverse proxy cannot read or tamper with messages |
| Works offline | The node keeps working when the Hub is offline; state is caught up automatically after recovery |
| Low resource use | A single long-lived connection; compact messages; all buffers have limits |
| Evolvable | Adjacent versions of node and Hub interoperate; new capabilities do not break old versions |

## 2. Layering

```
┌─ Messages: Protobuf Envelope (sections 4, 5)
├─ Noise channel: Noise_IK_25519_ChaChaPoly_BLAKE2s (section 3)
├─ WebSocket: binary frames; one WebSocket message carries one Noise message
└─ TLS: wss://, may terminate at a reverse proxy in front of the Hub
```

- WebSocket path: `/node/v1/connect`. It is not part of the public REST API and does not appear in the OpenAPI document;
- WebSocket over TLS (443) is chosen over a custom port to pass through networks that allow only HTTPS and to share the entry point with the Hub's console.

## 3. Encrypted channel and authentication

### 3.1 Keys

| Key | Type | Description |
|---|---|---|
| Hub identity key | X25519 static key | The public key is pinned to the node at enrollment (the full public key is contained in the enrollment token, since the IK handshake needs it) |
| Node identity key | X25519 static key | Generated locally on the node at enrollment; the private key never leaves the node; the Hub stores the mapping between the public key and the node ID |

The Noise static keys serve directly as identity keys, with no separate signing key: the channel itself provides mutual authentication, and artifacts that need independent verification (node policies, trust anchors) are signed by the user's passkey or recovery key (see `auth.md`).

### 3.2 Handshake (IK pattern, 1 round trip)

```
node                                                     Hub
 │ Message 1: e, es, s, ss + encrypted payload Hello ───────►│
 │                                                         │ Decrypt the node static public key → look up the node
 │                                                         │ (at enrollment: verify the admission proof in Hello)
 │◄─────────────────── Message 2: e, ee, se + encrypted payload Welcome │
 │ After that both sides exchange messages with the transport keys
```

- Prologue: `nett-control/1`, to prevent mixing with other protocols;
- The node's static public key is transmitted encrypted in message 1, so an outside observer cannot tell which node is connecting;
- The Hub rejects unknown or revoked node public keys; on rejection it returns a clear error code and then closes the connection (see section 4.3);
- Rekeying: a Noise rekey is performed once per 2^20 messages in each direction. Each end counts on its own, which needs no extra messages and does not depend on the clock; control connections normally reconnect and re-handshake long before this.

### 3.3 Hello and Welcome

| Hello (node → Hub) | Description |
|---|---|
| `protocol_versions` | Range of supported protocol versions |
| `node_version` | nett version |
| `node_id` | Node ID; at enrollment, the ID pre-assigned in the token |
| `admission_proof` | Carried only at enrollment: the signature by the enrollment private key over `{node ID, identity public key, mesh public key}`, that is, the JSON of the admission proof in `auth.md` section 10.5 (section 8.2); the identity public key in it must be the one used in the handshake |
| `boot_id` | Random ID of this process start, used to detect restarts |
| `applied_generation` | The desired state generation applied locally (section 6) |
| `capabilities` | Optional feature flags (section 9) |

| Welcome (Hub → node) | Description |
|---|---|
| `protocol_version` | The selected protocol version |
| `hub_version` | Hub version |
| `session_id` | ID of this session |
| `server_time` | Server time, for clock calibration |
| `keepalive_secs` | Keepalive interval |

At enrollment, Welcome is the same as usual: the node obtains the trust anchor list and its own admission material from the first desired state that follows, and checks that the fingerprint of the trust anchor list matches the one in the token (`auth.md` section 8.2).

## 4. Message format

### 4.1 Envelope

```protobuf
message Envelope {
  uint64 id = 1;                 // monotonically increasing in each direction
  uint64 reply_to = 2;           // when replying, the id of the peer's message
  google.protobuf.Timestamp sent_at = 3;
  oneof body {
    // message types listed in section 5
  }
}
```

- A single encoded Envelope does not exceed 60 KiB (a single Noise message is limited to 65535 bytes);
- Content above the limit (such as a full desired state) uses chunking: `Chunk { stream_id, seq, last, data }`, which the receiver reassembles by `stream_id`, with a total size limit per stream.

### 4.2 Package name and evolution

- Package name `nett.v1`; field numbers are never reused, and deleted fields use `reserved`; the 0 value of an enum is `*_UNSPECIFIED`;
- An unrecognized `oneof` branch or field: the receiver ignores it and logs at debug level, without disconnecting.

### 4.3 Errors

```protobuf
message Error {
  ErrorCode code = 1;   // for example NODE_REVOKED, UPGRADE_REQUIRED, INVALID_MESSAGE, RATE_LIMITED, ENROLLMENT_REFUSED
  string message = 2;
  uint64 related_id = 3;
}
```

A fatal error (such as a revoked node or a refused enrollment) is sent and then the connection is closed; a non-fatal error concerns only the related message. The reason for a refused enrollment (`ENROLLMENT_REFUSED`) is written in `message`: token expired, this machine has already enrolled, or the admission proof is wrong (hub.md section 6).

## 5. Message types

| Category | Direction | Message | Purpose |
|---|---|---|---|
| Session | Both | `Ping` / `Pong` | Keepalive, round-trip time, clock offset |
| | Both | `Goodbye` | Deliberate close, with a reason (upgrade, restart, shutdown) |
| | node → Hub | `Leave` | The node leaves on its own (`nett leave`); the Hub marks the node `removed`, which lowers privileges and needs no signature |
| | Both | `Error` | See 4.3 |
| Desired state | Hub → node | `DesiredState` | Desired state snapshot or delta (section 6) |
| | node → Hub | `StateAck` | Application result, reported per partition |
| Inventory and status | node → Hub | `Inventory` | Platform, capabilities, addresses (the address this machine uses when connecting to the Hub, from which the Hub learns the public address of a `public` machine, hub.md section 5); the full version is sent on connect, changes afterwards |
| | node → Hub | `ModuleStatus` | Status and conditions of each module |
| Events | node → Hub | `NodeEvent` | Events that occur on the node: policy rejected, upgrade result, etc. |
| Tasks | Hub → node | `Task` | A request to execute a change set step on the node (section 7) |
| | node → Hub | `TaskUpdate` | Accepted, running, succeeded, failed, interrupted (`interrupted`), and the result |
| Backup | node → Hub | `BackupFetch` | The node that stores backups periodically pulls the latest encrypted backup (the Hub never initiates connections to nodes) |
| | Hub → node | `BackupChunk` | A chunk of the encrypted backup |
| Mesh | Hub → node | The mesh partition in `DesiredState` | Addresses, peer public keys and admission material, candidate paths, relay list |
| | node → Hub | `LinkReport` | The current path, transport, and quality of a link; this machine's mapped address and NAT type (`mesh.md` section 6.1). The content is the JSON of the mesh process's local state (`status.md` section 6), sent when it changes |
| | Both | `PathSwitch` | When both sides are `dial-only` and the current tunnel is unavailable, relays "switch to a given relay" and its confirmation through the Hub (`mesh.md` section 8.4) |
| Recovery | node → Hub | `ArtifactSync` | After the Hub is restored from a backup, the node sends back the signed artifacts and revocations in effect (section 6.4) |

## 6. Desired state

### 6.1 Partitions and generation

The desired state is organized in partitions, each versioned independently:

| Partition | Content | Phase |
|---|---|---|
| `trust` | Trust anchor list (signed) | M1 |
| `policy` | Node policy (signed when it raises privileges) | M1 |
| `hub_endpoints` | The Hub's endpoint list: a JSON array of `https://` addresses | M1 |
| `release` | Target version and release package address; the node verifies the package with the project public keys (primary and backup) embedded in `nett` and automatically accepts only higher versions (`auth.md` section 11.3). This is the only path for upgrades | M1 |
| `mesh` | Mesh topology, admission material, and revocations. Members, advertised routes, and access rule sets are signed artifacts, verified independently by the mesh process (`mesh.md` section 4.1); node names are not signed and are used only for display (`status.md` section 5); nett-node only hands them over. The content is the mesh process's desired state file (JSON), identical to the file the signing tool writes when no Hub is used (`hub.md` section 4) | M1 |

- Each node has a monotonically increasing **generation**; a change in any partition increments it by one;
- `DesiredState` carries `generation`, `base_generation`, and a number of partitions: when `base_generation` is empty it is a full snapshot, otherwise a delta relative to that generation;
- On connect, if the node's `applied_generation` is too far from the current generation, or the Hub no longer keeps the corresponding deltas, the Hub sends a full snapshot.

### 6.2 Applying and acknowledging

- The node validates each partition: a signed partition has its signature verified first (see `auth.md` section 10), and on failure the partition is rejected; a signed artifact identical to the version currently in effect (for example a policy resent in a full snapshot) is treated as idempotent and acknowledged directly, without lifting any narrowing already in effect (`auth.md` section 10.4); within one batch of desired state, revocations are applied before new authorizations;
- After validation passes, it is written to the local State Store and then handed to the corresponding module to reconcile;
- `StateAck` reports each partition's result: `applied` / `rejected` (with a reason) / `pending` (the module is still reconciling);
- When a node restarts it first applies the locally saved desired state and then connects to the Hub.

### 6.3 When the Hub is offline

- The node keeps running on its local desired state;
- Module reconciliation, and mesh path selection and switching, do not depend on the Hub;
- Operations that need the Hub (new tasks, configuration changes) continue after the connection is restored.

### 6.4 After the Hub is restored from a backup

A backup always lags behind the nodes: a node may already have applied a higher generation, higher-versioned signed artifacts, or received newer revocations. A restored Hub must not require nodes to go backwards:

- The Hub first enters the **recovery state**: it only collects and does not deliver desired state;
- When a node connects, it reports `applied_generation` in `Hello` and sends back the signed artifacts in effect, the trust anchor update chain, revocations, and local narrowing through `ArtifactSync`. Signed artifacts carry the user's signature, so the Hub verifies them and fills in the database without the user approving again; revocations and narrowing never needed a signature, so the Hub merges them directly (they can only make privileges smaller);
- It completes in batches and does not wait indefinitely for all nodes: the console shows which nodes have not yet sent back their data, and the user can end the recovery state; nodes that connect afterwards first send back and reconcile, and then receive changes;
- After reconciliation, the Hub advances each node's generation above the value it reported and then delivers a full snapshot; members remove a peer only because of a revocation, and a member missing from the snapshot is not removed;
- For a node that enrolled after the backup was taken, the restored Hub does not know its identity key and the node must enroll again; before re-enrolling, remove the old identity in the console (delivering a revocation), otherwise the other members keep its admission;
- Content without signatures (hostnames, etc.) follows the restored Hub;
- When the Hub identity key is replaced, a backup is generated immediately (`auth.md` section 8.3): earlier backups contain the old key, and a Hub restored from them cannot handshake with nodes;
- M1 acceptance uses a backup that lags behind the node state (roadmap.md).

## 7. Tasks

The steps of a change set that need a node to execute them are delivered as tasks:

```protobuf
message Task {
  string task_id = 1;        // globally unique
  string change_id = 2;
  uint32 step = 3;
  string action_type = 4;
  bytes payload = 5;         // a Protobuf message defined per action type
  google.protobuf.Timestamp deadline = 6;
}
```

- **Only action types defined in the action catalog are executed**; an unknown type returns failure immediately;
- **At most once**: the node writes the `task_id` to a local record **before starting execution** and writes the result on completion (kept for 7 days, at most 1000 entries; a task's `deadline` must be shorter than the retention period). **Records whose `deadline` has not passed are not evicted**, and when the records are full new tasks are rejected with `RATE_LIMITED`. When the same task is received again, the existing result is returned and it is not executed again. If the node crashes in the middle of execution, after restart it reports the task as `interrupted` (result unknown) and does not redo it automatically; the Hub checks the actual state according to the action type, or leaves the decision to the user;
- The number of tasks in progress at the same time has a limit; beyond it `RATE_LIMITED` is returned;
- A task that has not started by its `deadline` is not executed and a timeout is returned;
- Execution results are reported via `TaskUpdate`; while the connection is down results are kept locally and reported after recovery.

## 8. Keepalive and reconnection

| Item | Rule |
|---|---|
| Keepalive | A `Ping` every 25 seconds (also to keep intermediate proxies from dropping the connection as idle); 3 consecutive unanswered pings count as disconnected |
| Reconnection | Exponential backoff, starting at 1 second with a cap of 60 seconds, with random jitter |
| Endpoint selection | Try the endpoints in the Hub-delivered list concurrently and pick the first to complete the handshake; after connecting to a fallback endpoint, periodically retry the preferred endpoint. The list keeps at least one endpoint that does not go through the mesh: the control connection can route through the mesh but must not rely on it alone, otherwise one wrong mesh configuration would leave the node never receiving a correction again. A fallback endpoint through another entry node is forwarded to the Hub by that reverse proxy, and the user maintains that configuration |
| Session | No session resumption; every reconnect performs a fresh handshake and catches up state through `applied_generation` and unacknowledged task results |
| Clock | Estimate the offset from the server time in `Pong`; report an event when the offset exceeds 30 seconds |

## 9. Version compatibility

- Protocol versions use "major.minor": different major versions are incompatible; minor versions make only incremental changes;
- The Hub supports nodes of at least the current and the previous minor version; a node can likewise connect to a Hub of the previous minor version;
- **Optional features** are negotiated through `capabilities` flags, for example `chunked_state`; both sides use only features both support;
- When a node's version is too old to be compatible, the Hub returns `UPGRADE_REQUIRED` but still lets it into **upgrade-only mode**: it receives only the `release` partition and upgrade tasks, so that it can complete an automatic upgrade.

## 10. Security

| Threat | Measure |
|---|---|
| Eavesdropping or tampering by a reverse proxy or intermediate network | Noise end-to-end encryption and authentication |
| Impersonating the Hub | The node pins the Hub public key; a failed handshake disconnects |
| Impersonating a node | The Hub accepts only registered node public keys; the enrollment token is valid once; the admission proof is signed by an enrollment private key that the signing tool generates and puts only in the token, so the Hub cannot replace the node's public key |
| Adding mesh members after the Hub is compromised | A member configures WireGuard only for peers whose admission material it can verify (ADR 0014) |
| Raising node privileges after the Hub is compromised | Partitions that raise privileges must carry the user's signature, and the node verifies it independently |
| Replay | The Noise transport layer has its own counters; desired state generations and policy versions only increase; revocations stop old signed artifacts from restoring privileges; tasks are deduplicated by `task_id` |
| Resource exhaustion | Message size, total chunk volume, and tasks in progress all have limits; the Hub rate-limits per node |
| Malicious payloads | All messages are validated at the boundary; the node executes only known action types |

## 11. Resource budget

| Item | node-side limit |
|---|---|
| Single message | 60 KiB |
| Chunk reassembly | 8 MiB per stream, reassembled in memory: the mesh process has to parse the whole desired state anyway, and the desired state file itself does not exceed 4 MiB (`mesh.md` section 17); 2 streams at the same time, released as soon as they are used |
| Completed task records | 7 days, at most 1000 entries; entries whose `deadline` has not passed are not evicted, and when full new tasks are rejected |

M1 uses no compression; if snapshot size becomes a problem, per-message compression will be added as an optional feature flag.

## 12. Phased implementation

Everything in this document is implemented in M1:

| Capability | Phase |
|---|---|
| Session: handshake, keepalive, reconnection, errors, version negotiation | M1 |
| Enrollment (admission proof), `Leave` | M1 |
| Backup pull (`BackupFetch`); reconciliation after restoring from a backup (`ArtifactSync`) | M1 |
| Desired state: `trust`, `policy`, `hub_endpoints`, `release`, `mesh` | M1 |
| Inventory (platform, capabilities, addresses), module status, events | M1 |
| Tasks (`node.*` actions, mesh actions); upgrades via the `release` partition | M1 |
| `LinkReport`, `PathSwitch` | M1 |

## 13. Open questions

| Question | Description |
|---|---|
| How long the Hub keeps incremental state | Affects the ratio of deltas to full snapshots sent after reconnection |
