# 变更集与动作目录

- 状态：草案
- 阶段：P0 设计；M1 实现最小版本，后续阶段逐步补全（见第 11 节）
- 相关：[api-resources.md](api-resources.md)、ADR [0006](../adr/0006-auth-and-passkey-signing.md)、[0010](../adr/0010-ai-via-api-only.md)、[0014](../adr/0014-signed-mesh-membership.md)、[0015](../adr/0015-origin-identity-and-lan-default-deny.md)；签名格式见 `auth.md`

## 1. 目标与原则

变更集是一次修改的完整记录与流程：修改什么、预计产生什么影响、由谁批准、执行与验证结果如何、失败后如何恢复。

1. **所有操作方走同一条路径**：用户、API token、CI、AI 发起的中高风险修改，都经过同样的预演、批准、执行与验证。
2. **完整设计，最小实现**：数据结构、状态和扩展接口一次定全；各阶段只增加动作类型和流程能力。最小版本是完整版本的严格子集，不做数据迁移。
3. **签名对象即生效对象**：高风险变更的签名覆盖实际下发的内容，接收方可以独立验证。
4. **失败可恢复**：执行前保存原状态；验证失败时按步骤逆序回滚。

低风险修改（改名称、标签、阈值；关闭模块；吊销 token 等）不使用变更集，直接修改并记录活动事件。例外：`ai` 类型 token 的一切写入都经过变更集，由用户批准。

## 2. 概念

| 概念 | 含义 |
|---|---|
| **变更集**（change） | 一次修改的整体，包含一个或多个有序的步骤 |
| **步骤**（step） | 一个动作作用于一个目标：`{ action_type, target, payload }` |
| **动作类型**（action type） | 内置的操作定义：风险等级、能否撤销、所需权限、执行逻辑 |
| **预演**（plan） | 执行前计算的差异、影响和风险；产生不可变的 `plan_hash` |
| **批准**（approval） | 对某一份预演结果的同意；高风险时为 passkey 签名 |
| **执行**（apply） | 按顺序执行各步骤 |
| **验证**（verify） | 确认执行结果符合预期 |
| **回滚**（rollback） | 验证失败时，按逆序恢复已执行步骤的原状态 |

## 3. 数据结构

```json
{
  "id": "chg_01J…",
  "created_at": "…",
  "spec": {
    "title": "将 app.example.com 迁移到 edge-eu-1",
    "reason": "…",
    "steps": [
      { "action_type": "stack.deploy", "target": "stk_…", "payload": { … }, "expected_revision": 12 },
      { "action_type": "route.update", "target": "rte_…", "payload": { … }, "expected_revision": 3 },
      { "action_type": "service.stop", "target": "svc_…", "payload": { } }
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
    "result": { "verified": true, "message": "…" },
    "conditions": [ ]
  }
}
```

| 字段 | 说明 |
|---|---|
| `spec.steps` | 有序步骤；风险等级取各步骤的最大值 |
| `spec.steps[].expected_revision` | 目标资源在提议时的 `revision`，用于检测提议后目标是否被他人修改 |
| `spec.not_before` | 最早执行时间（定时执行） |
| `spec.expires_at` | 等待批准的截止时间，默认 24 小时 |
| `spec.apply_mode` | `manual`（批准后由用户触发执行）/ `on_approval`（批准后立即执行）/ `auto`（预演通过后自动执行，仅限策略允许的中风险变更） |
| `status.plan.hash` | 预演结果的哈希；批准和签名都绑定这个值 |
| `status.plan.steps[]` | 每个步骤的差异、影响分析、警告 |
| `status.progress` | 每个步骤的执行状态 |
| `status.conditions` | 解释当前状态的条件，例如 `plan_stale`、`rollback_failed` |

`spec` 创建后不可修改；需要调整时取消原变更集，创建新的。

## 4. 状态机

```
                 ┌──────────── expired（超过 expires_at）
                 │  ┌───────── rejected（被拒绝）
                 │  │  ┌────── cancelled（被取消）
 planned ──► awaiting_approval ──► approved ──► applying ──► verifying ──► succeeded
    │                                  ▲            │            │
    │（无需批准，或 auto 模式）           │            ▼            ▼
    └──────────────────────────────────┘          failed ◄── rolling_back ──► rolled_back
```

| 转换 | 触发方 | 条件 |
|---|---|---|
| 创建 → `planned` | 提议方 | 权限检查通过；预演完成 |
| `planned` → `awaiting_approval` | Hub | 需要批准 |
| `planned` → `approved` | Hub | `apply_mode = auto` 且预演无警告，且策略允许 |
| `awaiting_approval` → `approved` | 用户 | 批准（高风险需 passkey 签名，签名绑定 `plan_hash`） |
| `awaiting_approval` → `rejected` / `cancelled` / `expired` | 用户 / 提议方 / Hub | — |
| `approved` → `applying` | 用户或 Hub | `manual` 模式由用户触发；其他模式自动；已到 `not_before` |
| `applying` → `verifying` | Hub | 所有步骤执行成功，且有需要主动验证的步骤 |
| `applying` → `succeeded` | Hub | 所有步骤执行成功，且没有需要主动验证的步骤（M1 的动作以节点回报为准） |
| `applying` → `failed` | Hub | 某个步骤失败，且没有可回滚的已执行步骤（M1 不触发回滚） |
| `applying` → `rolling_back` | Hub | 某个步骤失败，且有可回滚的已执行步骤 |
| `verifying` → `succeeded` | Hub | 所有步骤验证通过 |
| `verifying` → `rolling_back` | Hub | 验证失败或超时 |
| `rolling_back` → `rolled_back` / `failed` | Hub | 回滚成功 / 回滚失败（附 `rollback_failed` 条件并发出严重告警） |

终止状态：`succeeded`、`rolled_back`、`failed`、`rejected`、`cancelled`、`expired`。

**预演过期**：执行前，Hub 检查每个步骤目标的当前 `revision` 是否仍等于 `expected_revision`。不一致时标记 `plan_stale` 并停止执行；需要重新创建变更集，已有的批准和签名作废。

## 5. 风险与批准

| 风险 | 批准方式 | 可用的 `apply_mode` |
|---|---|---|
| 中 | 用户确认；或由自动执行策略放行 | `manual`、`on_approval`、`auto` |
| 高 | **passkey 签名**，绑定 `plan_hash` | `manual`、`on_approval` |

**自动执行策略**：由用户配置，指定哪些提议方、哪些动作类型、哪些目标可以在预演无警告时自动执行，例如"CI 对 stack `web` 的部署"。策略本身的修改是高风险操作。

**AI 提议**：`ai` 类型 token 的一切写入（包括低风险修改）都以变更集提出，一律需要用户批准，不适用自动执行策略；变更集必须填写 `reason`。

**降低权限不经过变更集，直接执行**：关闭模块、吊销 token、禁用设备、收窄访问规则（新增 deny、删除 allow）、撤销宣告网段、节点自行退出。例外：吊销节点（`node.remove`）不可撤销，仍按高风险处理。

## 6. 签名

- 签名对象：`auth.md` 第 11.1 节定义的签名载荷，包括变更集 ID、`plan_hash`（预演结果的哈希，已覆盖全部步骤，即 `status.plan.hash`）、过期时间，以及需要下发给节点的产物（节点策略、设备凭据、宣告网段、访问规则集、部署档位等）；
- 对于下发给节点的产物，产物本身连同签名一起下发，**节点用用户的 passkey 公钥独立验证**，不信任 Hub；
- 预演结果改变（`plan_hash` 改变）后，原签名作废；
- 签名格式、规范化方式和信任锚的分发见 `auth.md`。

## 7. 执行与验证

每个动作类型实现同一组接口：

```rust
trait Action {
    fn plan(&self, ctx, step) -> Result<StepPlan>;          // 差异、影响、警告
    fn apply(&self, ctx, step) -> Result<Snapshot>;         // 执行，返回原状态快照
    fn verify(&self, ctx, step) -> Result<Verification>;    // 主动检查结果
    fn rollback(&self, ctx, step, snapshot) -> Result<()>;  // 用快照恢复
}
```

- 步骤按顺序执行；每个步骤有超时；进度写入 `status.progress` 并推送；
- 需要节点参与的步骤，经 node ↔ Hub 协议下发，节点回报结果；
- 同一个目标资源同一时间只能属于一个未结束的变更集；冲突的提议在创建时被拒绝，并返回占用它的变更集 ID。

### 7.1 部署档位

容器可以声明特权、挂载宿主目录、使用宿主网络，所以"能部署任意 stack"就等于拿到节点的 root。为了让中风险的部署不能提升权限，每个节点有一份签名的**部署档位**（`node-policies` 的 `spec.deploy_profile`），列出允许使用的特权：

| 特权项 | 默认 |
|---|---|
| `privileged`、宿主 PID / IPC 命名空间 | 不允许 |
| 宿主网络 | 不允许 |
| `cap_add`、设备（`devices`） | 不允许 |
| 挂载宿主路径 | 只允许该 stack 的数据目录 |
| Docker socket 挂载 | 不允许 |
| 部署钩子 | 只允许在容器中运行 |

- 预演时，Hub 对照档位给出警告；执行时，nett-node 在部署前再次检查，超出档位就拒绝，不依赖 Hub 的判断；
- 提高档位（`node.set_deploy_profile`）是高风险操作，需要签名；降低档位直接执行。

## 8. 回滚

- 每个步骤执行前保存原状态快照；
- 验证失败或某步骤失败时，按逆序对已执行的步骤调用 `rollback`；
- 不可撤销的动作（如吊销节点）在预演时给出警告，并要求放在最后一个步骤；
- 回滚本身失败时，变更集进入 `failed`，附带 `rollback_failed` 条件，并发出严重告警。

## 9. 动作目录

| 动作类型 | 目标 | 风险 | 可撤销 | 所需权限范围 | 阶段 |
|---|---|---|---|---|---|
| `node.enable_module` | 节点 | 高（metrics 为低） | 是 | `nodes:propose` | M1 |
| `node.remove` | 节点 | 高 | 否 | `nodes:propose` | M1 |
| `node.allow_release` | 节点 | 高 | 是 | `nodes:propose` | M1 |
| `device.add` | 设备 | 高 | 是 | `devices:propose` | M2 |
| `device_credential.create` | 设备凭据 | 高 | 是 | `devices:propose` | M2 |
| `access_rule.create` / `update` / `delete`（放宽访问时） | 访问规则 | 高 | 是 | `access-rules:propose` | M2 |
| `link.set_policy` | 连接 | 中 | 是 | `links:propose` | M2 |
| `node.advertise_routes` | 节点 | 高 | 是 | `nodes:propose` | M2 |
| `node.set_roles`（relay、gateway、智能入口） | 节点 | 高 | 是 | `nodes:propose` | M2 |
| `stack.create` / `update` / `delete` | stack | 中（受部署档位限制） | 是 | `stacks:deploy` | M3 |
| `stack.deploy` | stack | 中（受部署档位限制） | 是 | `stacks:deploy` | M3 |
| `deployment.rollback` | 部署 | 中 | 是 | `stacks:deploy` | M3 |
| `node.set_deploy_profile` | 节点 | 高 | 是 | `nodes:propose` | M3 |
| `service.restart` | 服务 | 中 | 不适用 | `services:operate` | M3 |
| `service.stop` / `start` | 服务 | 中 | 是 | `services:operate` | M3 |
| `route.create`；改变回源目标的 `route.update` | 路由 | 高（会把一个内网端口暴露到公网，并生成 Edge 的访问规则） | 是 | `routes:propose` | M3 |
| 其他 `route.update`；`route.delete` | 路由 | 中 | 是 | `routes:propose` | M3 |
| `auto_apply_policy.update` | 自动执行策略 | 高 | 是 | 仅用户会话 | M3 |

- 节点升级不是动作类型：升级经期望状态的 `release` 分区进行，节点只接受更高的版本（`auth.md` 第 12.3 节），属于低风险；降级需要 `node.allow_release` 生成的签名产物；
- 收窄访问规则、撤销宣告网段、降低部署档位属于降低权限，直接执行，不在本表中。

AI 运维（M4）使用同一套动作类型；需要新增的操作（如调整容器内存上限）作为 `stack.update` 的一种 `payload` 实现，或新增动作类型，不改变流程。

## 10. 场景推演

| 场景 | 变更集形态 | 验证点 |
|---|---|---|
| **开启节点模块**（M1） | 1 个步骤 `node.enable_module`；高风险；签名绑定生成的节点策略 | 节点独立验签；节点回报模块已启用 |
| **CI 部署**（M3） | CI 构建出新镜像后，经 OIDC 提出 1 个步骤 `stack.deploy`；默认 `apply_mode = manual`：控制台显示可升级，用户一键执行。stack 开启了自动部署时为 `auto`，由自动执行策略放行 | 健康检查失败则回滚到上一部署 |
| **服务迁移到另一节点**（M3） | 3 个步骤：在新节点部署 → 更新路由（改变回源目标，高风险，需要签名）→ 停止旧节点上的服务 | 任一步失败，逆序回滚；路由切换后验证域名可访问 |
| **AI 调整内存上限**（M4） | 1 个步骤 `stack.update`；提议方为 AI，附原因 | 必须由用户批准；执行后观察一段时间无 OOM |
| **定时部署**（M3） | `not_before` 设为凌晨 | 批准后等待到时间再执行 |
| **并发冲突** | 用户和 CI 同时修改同一个 stack | 后提议的一方在创建时被拒绝；或执行前发现 `plan_stale` 而停止 |

**明确不支持**：变更集之间的依赖关系（需要依赖时，放进同一个变更集的有序步骤）；执行任意脚本；部分批准（只批准其中某些步骤）。

## 11. 分阶段实现

| 能力 | M1 | M3 | M4 |
|---|---|---|---|
| 数据结构与全部状态 | ✅（部分状态暂不触发） | — | — |
| 步骤数量 | 单步骤 | 多步骤 | — |
| 动作类型 | `node.enable_module`、`node.remove`、`node.allow_release` | 部署、服务、路由、部署档位、自动执行策略；M2 增加设备、设备凭据、访问规则、宣告网段、节点角色、连接策略 | 按需新增 |
| 预演 | 差异 | 差异 + 影响分析 | — |
| 批准 | 手动确认、passkey 签名 | 加上自动执行策略 | `ai` token 的全部写入经变更集审批 |
| `apply_mode` | `manual`、`on_approval` | 加上 `auto` | — |
| 验证 | 以节点回报为准 | 主动验证（健康检查、可访问性） | — |
| 回滚 | 不触发（M1 的动作由节点回报失败即可，经 `applying → failed` 结束） | 快照与逆序回滚 | — |
| 定时执行 `not_before` | 字段保留 | ✅ | — |
| 预演过期检测 | ✅ | ✅ | — |
| 目标冲突检测 | ✅ | ✅ | — |

M1 中未触发的状态（`verifying`、`rolling_back`、`rolled_back`）和字段从一开始就存在于数据结构和 API 中。为状态机和 API 编写契约测试，保证后续扩展不破坏已有行为。

## 12. API

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
