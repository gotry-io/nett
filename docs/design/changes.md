# 变更集与动作目录

- 状态：草案
- 阶段：P0 设计；M1 实现（见第 10 节）
- 相关：[api-resources.md](api-resources.md)、ADR [0006](../adr/0006-auth-and-passkey-signing.md)、[0014](../adr/0014-signed-mesh-membership.md)、[0015](../adr/0015-origin-identity-and-lan-default-deny.md)、[0019](../adr/0019-mesh-only.md)；签名格式见 `auth.md`

## 1. 目标与原则

变更集是一次组网修改的完整记录与流程：修改什么、由谁批准、执行结果如何。

1. **所有操作方走同一条路径**：用户和 API token 发起的中高风险修改，都经过同样的预演、批准与执行。
2. **只为组网动作设计**：每个变更集只有一个步骤，动作类型只覆盖组网（第 8 节），不为组网之外的功能预留状态和字段。数据结构确实需要迁移时，使用带版本号的迁移步骤，并用迁移测试覆盖。
3. **签名对象即生效对象**：高风险变更的签名覆盖实际下发的内容，接收方可以独立验证。

低风险修改（改名称、标签；关闭模块；吊销 token 等）不使用变更集，直接修改并记录活动事件。

## 2. 概念

| 概念 | 含义 |
|---|---|
| **变更集**（change） | 一次修改的整体，只包含一个步骤 |
| **步骤**（step） | 一个动作作用于一个目标：`{ action_type, target, payload }` |
| **动作类型**（action type） | 内置的操作定义：风险等级、能否撤销、所需权限、执行逻辑 |
| **预演**（plan） | 执行前计算的差异和风险；产生不可变的 `plan_hash` |
| **批准**（approval） | 对某一份预演结果的同意；高风险时为 passkey 签名 |
| **执行**（apply） | 执行步骤；需要节点参与时，以节点回报的结果为准 |

## 3. 数据结构

```json
{
  "id": "chg_01J…",
  "created_at": "…",
  "spec": {
    "title": "开启 mesh 模块",
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

| 字段 | 说明 |
|---|---|
| `spec.steps` | 只包含一个步骤；变更集的风险等级就是这个步骤的风险等级 |
| `spec.steps[].expected_revision` | 目标资源在提议时的 `revision`，用于检测提议后目标是否被他人修改 |
| `spec.not_before` | 最早执行时间（定时执行） |
| `spec.expires_at` | 等待批准的截止时间，默认 24 小时 |
| `spec.apply_mode` | `manual`（批准后由用户触发执行）/ `on_approval`（批准后立即执行） |
| `status.plan.hash` | 预演结果的哈希；批准和签名都绑定这个值 |
| `status.plan.steps[]` | 步骤的差异、警告 |
| `status.progress` | 步骤的执行状态 |
| `status.conditions` | 解释当前状态的条件，例如 `plan_stale` |

`spec` 创建后不可修改；需要调整时取消原变更集，创建新的。

## 4. 状态机

```
                 ┌──────────── expired（超过 expires_at）
                 │  ┌───────── rejected（被拒绝）
                 │  │  ┌────── cancelled（被取消）
 planned ──► awaiting_approval ──► approved ──► applying ──► succeeded
                                                    │
                                                    ▼
                                                  failed
```

| 转换 | 触发方 | 条件 |
|---|---|---|
| 创建 → `planned` | 提议方 | 权限检查通过；预演完成 |
| `planned` → `awaiting_approval` | Hub | 总是（每个变更集都需要批准，第 5 节） |
| `awaiting_approval` → `approved` | 用户 | 批准（高风险需 passkey 签名，签名绑定 `plan_hash`） |
| `awaiting_approval` → `rejected` / `cancelled` / `expired` | 用户 / 提议方 / Hub | — |
| `approved` → `applying` | 用户或 Hub | `manual` 模式由用户触发；`on_approval` 模式自动；已到 `not_before` |
| `applying` → `succeeded` | Hub | 步骤执行成功（需要节点参与时以节点回报为准） |
| `applying` → `failed` | Hub | 步骤执行失败 |

终止状态：`succeeded`、`failed`、`rejected`、`cancelled`、`expired`。

**预演过期**：执行前，Hub 检查步骤目标的当前 `revision` 是否仍等于 `expected_revision`。不一致时标记 `plan_stale` 并停止执行；需要重新创建变更集，已有的批准和签名作废。

## 5. 风险与批准

| 风险 | 批准方式 |
|---|---|
| 中 | 用户确认 |
| 高 | **passkey 签名**，绑定 `plan_hash` |

**降低权限不经过变更集，直接执行**：关闭模块、吊销 token、禁用设备、收窄访问规则（新增 deny、删除 allow）、撤销宣告网段、节点自行退出。例外：吊销节点（`node.remove`）不可撤销，仍按高风险处理。

## 6. 签名

- 签名对象：`auth.md` 第 10.1 节定义的签名载荷，包括变更集 ID、`plan_hash`（预演结果的哈希，已覆盖步骤，即 `status.plan.hash`）、过期时间，以及需要下发给节点的产物（节点策略、设备凭据、宣告网段、访问规则集等）；
- 对于下发给节点的产物，产物本身连同签名一起下发，**节点用用户的 passkey 公钥独立验证**，不信任 Hub；
- 预演结果改变（`plan_hash` 改变）后，原签名作废；
- 已签名的变更被取消或过期未执行时，Hub 下发撤销记录作废这份批准（auth.md 第 10.4 节）；
- 签名格式、规范化方式和信任锚的分发见 `auth.md`。

## 7. 执行

每个动作类型实现同一组接口：

```rust
trait Action {
    fn plan(&self, ctx, step) -> Result<StepPlan>;   // 差异、警告
    fn apply(&self, ctx, step) -> Result<()>;        // 执行
}
```

- 步骤有超时；进度写入 `status.progress` 并推送；
- 需要节点参与的步骤，经 node ↔ Hub 协议下发，节点回报结果；
- 同一个目标资源同一时间只能属于一个未结束的变更集；冲突的提议在创建时被拒绝，并返回占用它的变更集 ID；
- 整份访问规则集是一份签名产物，所以**会改变它的变更串行处理**（访问规则，以及会改变规则展开结果的标签修改）：同一时间只能有一个未结束；预演绑定规则集当时的版本，版本变了就按 `plan_stale` 重新预演和签名。

## 8. 动作目录

| 动作类型 | 目标 | 风险 | 可撤销 | 所需权限范围 | 阶段 |
|---|---|---|---|---|---|
| `node.enable_module`（mesh、relay） | 节点 | 高 | 是 | `nodes:propose` | M1 |
| `node.remove` | 节点 | 高 | 否 | `nodes:propose` | M1 |
| `node.allow_release` | 节点 | 高 | 是 | `nodes:propose` | M1 |
| `device.add` | 设备 | 高 | 是 | `devices:propose` | M1 |
| `device_credential.create` | 设备凭据 | 高 | 是 | `devices:propose` | M1 |
| `access_rule.create` / `update` / `delete`（放宽访问时，包括标签的变化让规则的展开结果变大） | 访问规则 | 高 | 是 | `access-rules:propose` | M1 |
| `link.set_policy` | 连接 | 中 | 是 | `links:propose` | M1 |
| `node.advertise_routes` | 节点 | 高 | 是 | `nodes:propose` | M1 |
| `node.set_roles`（relay、gateway、智能入口、edge） | 节点 | 高 | 是 | `nodes:propose` | M1 |

- 节点升级不是动作类型：升级经期望状态的 `release` 分区进行，节点只接受更高的版本（`auth.md` 第 11.3 节），属于低风险；降级需要 `node.allow_release` 生成的签名产物；
- 收窄访问规则、撤销宣告网段属于降低权限，直接执行，不在本表中，执行时留下撤销记录（auth.md 第 10.4 节）；
- 不可撤销的动作（如吊销节点）在预演时给出警告；
- `edge` 角色为节点分配 Edge 专用地址；这个地址能访问哪些目标，由用户在访问规则中写（`access_rule.*`，ADR 0019）。

## 9. 场景推演

| 场景 | 变更集形态 | 验证点 |
|---|---|---|
| **开启节点模块** | 1 个步骤 `node.enable_module`；高风险；签名绑定生成的节点策略 | 节点独立验签；节点回报模块已启用 |
| **并发冲突** | 用户和脚本（API token）同时提议修改同一个节点 | 后提议的一方在创建时被拒绝；或执行前发现 `plan_stale` 而停止 |

**明确不支持**：多步骤的变更集；变更集之间的依赖关系；执行任意脚本。

## 10. 分阶段实现

变更集的全部能力都在 M1 实现。

| 能力 | M1 |
|---|---|
| 数据结构与状态 | ✅ |
| 步骤数量 | 单步骤 |
| 动作类型 | 第 8 节的全部动作类型 |
| 预演 | 差异 |
| 批准 | 手动确认、passkey 签名 |
| `apply_mode` | `manual`、`on_approval` |
| 执行结果 | 以节点回报为准 |
| 定时执行 `not_before` | ✅ |
| 预演过期检测 | ✅ |
| 目标冲突检测 | ✅ |

为状态机和 API 编写契约测试，保证以后的修改不破坏已有行为。

## 11. API

| 请求 | 说明 |
|---|---|
| `POST /api/v1/changes` | 创建并预演，返回变更集 |
| `GET /api/v1/changes`、`GET /api/v1/changes/{id}` | 查询；可按状态、提议方、目标筛选 |
| `POST /api/v1/changes/{id}/actions/approve` | 批准；高风险时携带 WebAuthn 签名（流程见 `auth.md`） |
| `POST /api/v1/changes/{id}/actions/reject` | 拒绝 |
| `POST /api/v1/changes/{id}/actions/apply` | `manual` 模式下触发执行 |
| `POST /api/v1/changes/{id}/actions/cancel` | 取消（仅限执行前） |
| `GET /api/v1/action-types` | 动作目录 |

直接调用资源的中高风险写接口时，Hub 自动创建变更集并返回 `202`。
