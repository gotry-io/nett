# Change Sets and the Action Catalog

- Status: draft
- Phase: P0 design; added with the web console (ADR 0024). Once joined to the Hub, changes are signed on the user's computer by commands of the signing tool (site.md section 7)
- Related: [api-resources.md](api-resources.md), ADR [0006](../adr/0006-auth-and-passkey-signing.md), [0014](../adr/0014-signed-mesh-membership.md), [0015](../adr/0015-origin-identity-and-lan-default-deny.md), [0019](../adr/0019-mesh-only.md); see `auth.md` for the signature format

## 1. Goals and principles

A change set is the complete record and process of one mesh modification: what is changed, who approves it, and what the result is.

1. **All actors take the same path**: medium- and high-risk changes initiated by the user and by API tokens all go through the same plan, approval and execution.
2. **Designed only for mesh actions**: each change set has a single step, and action types cover only the mesh (section 8); no state or fields are reserved for features outside the mesh. When a data structure really needs migrating, use versioned migration steps and cover them with migration tests.
3. **What is signed is what takes effect**: the signature of a high-risk change covers the content actually delivered, and the receiver can verify it independently.

Low-risk changes (renaming, labels; disabling a module; revoking a token, and so on) do not use change sets; they are applied directly and recorded as activity events.

## 2. Concepts

| Concept | Meaning |
|---|---|
| **Change set** (change) | One modification as a whole, containing a single step |
| **Step** | One action applied to one target: `{ action_type, target, payload }` |
| **Action type** | A built-in operation definition: risk level, whether it can be undone, required permission, execution logic |
| **Plan** | The diff and risk computed before execution; produces an immutable `plan_hash` |
| **Approval** | Consent to one specific plan result; for high risk, a passkey signature |
| **Apply** | Executing the step; when a node is involved, the result reported by the node is authoritative |

## 3. Data structure

```json
{
  "id": "chg_01J…",
  "created_at": "…",
  "spec": {
    "title": "Enable the mesh module",
    "reason": "…",
    "steps": [
      { "action_type": "node.enable_module", "target": "node_…", "payload": { … }, "expected_revision": 4 }
    ],
    "not_before": null,
    "expires_at": "…",
    "apply_mode": "manual"
  },
  "status": {
    "phase": "awaiting_approval",
    "proposed_by": { "kind": "owner", "id": "…" },
    "risk": "high",
    "plan": { "hash": "sha256:…", "planned_at": "…", "steps": [ … ] },
    "approval": { "kind": "passkey", "passkey_id": "pk_…", "signed_at": "…", "plan_hash": "sha256:…" },
    "progress": [ { "step": 0, "state": "succeeded", "started_at": "…", "finished_at": "…" } ],
    "result": { "message": "…" },
    "conditions": [ ]
  }
}
```

| Field | Description |
|---|---|
| `spec.steps` | Contains a single step; the change set's risk level is that step's risk level |
| `spec.steps[].expected_revision` | The target resource's `revision` at proposal time, used to detect whether someone else modified the target after the proposal |
| `spec.not_before` | Earliest execution time (scheduled execution) |
| `spec.expires_at` | Deadline for approval, 24 hours by default |
| `spec.apply_mode` | `manual` (the user triggers execution after approval) / `on_approval` (executes immediately after approval) |
| `status.plan.hash` | Hash of the plan result; approval and signature are both bound to this value |
| `status.plan.steps[]` | The step's diff and warnings |
| `status.progress` | The step's execution state |
| `status.conditions` | Conditions explaining the current state, for example `plan_stale` |

`spec` cannot be modified after creation; to adjust, cancel the original change set and create a new one.

## 4. State machine

```
                 ┌──────────── expired (past expires_at)
                 │  ┌───────── rejected
                 │  │  ┌────── cancelled
 planned ──► awaiting_approval ──► approved ──► applying ──► succeeded
                                                    │
                                                    ▼
                                                  failed
```

| Transition | Triggered by | Condition |
|---|---|---|
| create → `planned` | Proposer | Permission check passes; plan completed |
| `planned` → `awaiting_approval` | Hub | Always (every change set needs approval, section 5) |
| `awaiting_approval` → `approved` | User | Approval (high risk needs a passkey signature bound to `plan_hash`) |
| `awaiting_approval` → `rejected` / `cancelled` / `expired` | User / proposer / Hub | — |
| `approved` → `applying` | User or Hub | In `manual` mode the user triggers it; automatic in `on_approval` mode; `not_before` has been reached |
| `applying` → `succeeded` | Hub | The step executed successfully (when a node is involved, the node's report is authoritative) |
| `applying` → `failed` | Hub | The step failed |

Terminal states: `succeeded`, `failed`, `rejected`, `cancelled`, `expired`.

**Plan staleness**: before execution, the Hub checks whether the target's current `revision` still equals `expected_revision`. If not, it marks `plan_stale` and stops execution; the change set has to be created again, and the existing approval and signature are void.

## 5. Risk and approval

| Risk | Approval method |
|---|---|
| Medium | User confirmation |
| High | **Passkey signature**, bound to `plan_hash` |

**Lowering privileges does not go through change sets and is executed directly**: disabling a module, revoking a token, disabling a device, narrowing access rules (adding a deny, deleting an allow), revoking advertised routes, a node leaving by itself. Exception: revoking a node (`node.remove`) cannot be undone and is still treated as high risk.

## 6. Signing

- What is signed: the signed payload defined in `auth.md` section 10.1, including the change set ID, `plan_hash` (the hash of the plan result, which already covers the step, that is `status.plan.hash`), the expiry time, and the artifacts to be delivered to nodes (node policy, device credentials, advertised routes, access rule set, and so on);
- For artifacts delivered to nodes, the artifact itself is delivered together with the signature, and **the node verifies it independently with the user's passkey public key**, without trusting the Hub;
- After the plan result changes (`plan_hash` changes), the original signature is void;
- When a signed change is cancelled or expires without being executed, the Hub delivers a revocation that voids this approval (auth.md section 10.4);
- See `auth.md` for the signature format, canonicalization and distribution of trust anchors.

## 7. Execution

Each action type implements the same set of interfaces:

```rust
trait Action {
    fn plan(&self, ctx, step) -> Result<StepPlan>;   // diff, warnings
    fn apply(&self, ctx, step) -> Result<()>;        // execute
}
```

- Steps have timeouts; progress is written to `status.progress` and pushed;
- Steps that need a node are delivered through the node ↔ Hub protocol, and the node reports the result;
- A target resource can belong to only one unfinished change set at a time; a conflicting proposal is rejected at creation, and the ID of the change set holding it is returned;
- The whole access rule set is one signed artifact, so **changes that modify it are processed serially** (access rules, and label changes that alter how rules expand): only one can be unfinished at a time; the plan is bound to the version of the rule set at that time, and if the version changes, it is re-planned and re-signed as `plan_stale`.

## 8. Action catalog

| Action type | Target | Risk | Undoable | Required permission scope | Phase |
|---|---|---|---|---|---|
| `node.enable_module` (mesh, relay) | Node | High | Yes | `nodes:propose` | M1 |
| `node.remove` | Node | High | No | `nodes:propose` | M1 |
| `node.allow_release` | Node | High | Yes | `nodes:propose` | M1 |
| `device.add` | Device | High | Yes | `devices:propose` | M1 |
| `device_credential.create` | Device credential | High | Yes | `devices:propose` | M1 |
| `access_rule.create` / `update` / `delete` (when widening access, including label changes that make a rule's expansion larger) | Access rule | High | Yes | `access-rules:propose` | M1 |
| `link.set_policy` | Link | Medium | Yes | `links:propose` | M1 |
| `node.advertise_routes` | Node | High | Yes | `nodes:propose` | M1 |
| `node.set_roles` (relay, gateway, smart gateway, edge) | Node | High | Yes | `nodes:propose` | M1 |

- Node upgrade is not an action type: upgrades go through the `release` partition of the desired state, nodes accept only higher versions (`auth.md` section 11.3), and it is low risk; downgrading requires the signed artifact generated by `node.allow_release`;
- Narrowing access rules and revoking advertised routes are lowering privileges, executed directly and not in this table, and leave a revocation when executed (auth.md section 10.4);
- Actions that cannot be undone (such as revoking a node) give a warning at plan time;
- The `edge` role assigns the node an Edge address; which targets this address can reach is written by the user in access rules (`access_rule.*`, ADR 0019).

## 9. Scenario walk-through

| Scenario | Change set form | What is checked |
|---|---|---|
| **Enable a node module** | One step `node.enable_module`; high risk; the signature is bound to the generated node policy | The node verifies the signature independently; the node reports the module enabled |
| **Concurrent conflict** | The user and a script (API token) propose changes to the same node at the same time | The later proposer is rejected at creation; or `plan_stale` is found before execution and execution stops |

**Explicitly unsupported**: multi-step change sets; dependencies between change sets; executing arbitrary scripts.

## 10. Phased implementation

All capabilities of change sets are implemented in M1.

| Capability | M1 |
|---|---|
| Data structure and states | ✅ |
| Number of steps | Single step |
| Action types | All action types in section 8 |
| Plan | Diff |
| Approval | Manual confirmation, passkey signature |
| `apply_mode` | `manual`, `on_approval` |
| Execution result | The node's report is authoritative |
| Scheduled execution `not_before` | ✅ |
| Plan staleness detection | ✅ |
| Target conflict detection | ✅ |

Write contract tests for the state machine and the API so that later changes do not break existing behavior.

## 11. API

| Request | Description |
|---|---|
| `POST /api/v1/changes` | Create and plan, returns the change set |
| `GET /api/v1/changes`, `GET /api/v1/changes/{id}` | Query; can filter by state, proposer, target |
| `POST /api/v1/changes/{id}/actions/approve` | Approve; for high risk carries a WebAuthn signature (flow in `auth.md`) |
| `POST /api/v1/changes/{id}/actions/reject` | Reject |
| `POST /api/v1/changes/{id}/actions/apply` | Trigger execution in `manual` mode |
| `POST /api/v1/changes/{id}/actions/cancel` | Cancel (only before execution) |
| `GET /api/v1/action-types` | Action catalog |

When the write endpoint of a resource is called directly for a medium- or high-risk change, the Hub creates a change set automatically and returns `202`.
