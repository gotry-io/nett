# API 资源模型

- 状态：草案
- 阶段：P0（资源在 M1 实现，见第 8 节）
- 相关：[architecture.md](../architecture.md)、ADR [0003](../adr/0003-api-and-protocols.md)、[0006](../adr/0006-auth-and-passkey-signing.md)、[0015](../adr/0015-origin-identity-and-lan-default-deny.md)、[0019](../adr/0019-mesh-only.md)

## 1. 范围

本文定义对外 API 的资源：有哪些资源、字段、关系、生命周期、读写归属，以及通用约定。

不在本文范围：

| 内容 | 文档 |
|---|---|
| 认证方式、权限范围的完整定义、签名流程 | `auth.md` |
| 变更集的执行流程、动作目录的完整列表 | `changes.md` |
| node 与 Hub 之间的通信协议 | `protocol.md` |
| 组网的路径选择与切换算法 | `mesh.md` |

## 2. 通用约定

### 2.1 路径与命名

- 基础路径 `/api/v1`；资源名使用复数、短横线连接：`/api/v1/nodes`、`/api/v1/api-tokens`；
- JSON 字段使用 `snake_case`；枚举值使用小写 `snake_case` 字符串；
- 时间戳为 UTC，RFC 3339 格式；持续时间以秒为单位的整数表示，字段名以 `_secs` 结尾；
- 单例资源不带 ID：`/api/v1/owner`、`/api/v1/hub`。

### 2.2 标识

- **ID**：`<前缀>_<ULID>`，例如 `node_01J9Z3K8Q2T7V4X6Y8A0B2C4D6`。ID 不可变，按时间有序。
- **名称**：多数资源还有一个用户可读的 `name`（如节点 `edge-us-1`），在同类资源中唯一，可以修改。
- 路径中的 `{id}` 也接受名称：`/api/v1/nodes/edge-us-1` 等价于按 ID 访问。资源之间的引用一律存储 ID。

| 资源 | 前缀 | 资源 | 前缀 |
|---|---|---|---|
| nodes | `node` | changes | `chg` |
| passkeys | `pk` | events | `evt` |
| sessions | `ses` | devices | `dev` |
| api-tokens | `tok` | device-credentials | `dcr` |
| enrollment-tokens | `enr` | access-rules | `acr` |
| node-policies | `pol` | hostnames | `hst` |
| links | `lnk` | backups | `bak` |

### 2.3 资源的通用结构

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

| 字段 | 含义 | 写入方 |
|---|---|---|
| `spec` | **期望状态**：希望它是什么样子 | 用户、API token、Hub（按权限） |
| `status` | **实际状态**：它现在是什么样子 | node 上报，或 Hub 计算；API 调用方不能写入 |
| `revision` | `spec` 每次修改加一，同时作为 ETag | Hub |
| `labels` | 键值对，用于筛选和选择器 | 用户 |

`status` 中常见的通用字段：

| 字段 | 含义 |
|---|---|
| `phase` | 当前所处阶段（各资源自行定义的枚举） |
| `observed_revision` | node 或调和器最近一次处理的 `spec` 版本；与 `revision` 不一致表示"正在生效" |
| `conditions` | 状态条件列表：`{ type, ok, reason, message, since }`，用于解释"为什么是这个状态" |

只读的资源（如 `events`）没有 `spec`。

### 2.4 列表、筛选与分页

- 游标分页：`?limit=50&cursor=<不透明字符串>`；`limit` 默认 50，最大 200；响应中带 `next_cursor`；
- 筛选：按标签 `?label=role:edge`，按引用 `?node=edge-us-1`，按状态 `?phase=online`；
- 排序：默认按 `created_at` 倒序；支持的排序字段在各资源中说明。

### 2.5 并发与幂等

- 修改 `spec` 时必须带 `If-Match: <revision>`；版本不一致返回 `412`，避免覆盖他人（包括脚本）的修改；
- 创建类请求支持 `Idempotency-Key`，24 小时内重复的请求返回第一次的结果。

### 2.6 错误

使用 RFC 9457（`application/problem+json`），带稳定的 `code`：

```json
{
  "type": "https://nett.example.com/errors/revision-conflict",
  "title": "资源已被修改",
  "status": 412,
  "code": "revision_conflict",
  "detail": "当前 revision 为 8，请求基于 7",
  "instance": "/api/v1/nodes/edge-us-1"
}
```

`code` 稳定不变，供程序判断；`title` 和 `detail` 按请求的 `Accept-Language`（或用户的 `locale`）返回中文或英文。

### 2.7 敏感字段

- 密钥、token、私钥只在创建时返回一次，之后只返回前缀或指纹。

## 3. 写入方式与风险分级

| 风险 | 例子 | 方式 |
|---|---|---|
| **低** | 修改名称、标签 | 直接修改资源 |
| **中** | 修改连接的策略覆盖（`link.set_policy`） | 通过变更集：预演 → 执行 |
| **高** | 开启模块、设置节点角色（如 `edge`）、新增设备或设备凭据、放宽访问规则、宣告网段、吊销节点 | 通过变更集，并需要 passkey 签名批准 |

- 中、高风险的写入不直接修改资源，而是创建一个 `change`。直接调用对应资源的写接口时，Hub 返回 `202` 和新建的 `change`；
- **降低权限**（关闭模块、吊销 token、禁用设备、收窄访问规则）始终视为低风险，可以直接执行；
- 修改标签本身是低风险，但如果它让某条访问规则的展开结果变大（例如给节点加上被 allow 规则选中的标签），这次修改就是放宽访问，按高风险处理（第 5.5 节）；
- 每类写入的风险等级由动作目录（`action-types`）定义，`changes.md` 给出完整列表；
- 变更集从 M1 起提供，只用于组网动作，每个变更集只有一个步骤（ADR 0019）。

### 3.1 资源上的动作

增删改之外的操作，以动作的形式提供：

```
POST /api/v1/<资源>/{id}/actions/<动作>
```

例如 `POST /api/v1/nodes/node_…/actions/remove`。动作同样受风险分级约束：低风险直接执行并返回结果；中、高风险返回 `202` 和对应的 `change`。

## 4. 资源总览

| 领域 | 资源 | 阶段 | spec 写入方 | status 写入方 |
|---|---|---|---|---|
| 身份与访问 | `owner` | M1 | 用户 | Hub |
| | `trust`（信任锚清单） | M1 | 用户（签名） | Hub |
| | `passkeys` | M1 | 用户 | Hub |
| | `sessions` | M1 | — | Hub |
| | `api-tokens` | M1 | 用户 | Hub |
| 节点 | `nodes` | M1 | 用户 | node、Hub |
| | `enrollment-tokens` | M1 | 用户 | Hub |
| | `node-policies` | M1 | 用户（签名） | node |
| 活动 | `events` | M1 | — | Hub |
| 系统 | `hub`、`releases`、`backups` | M1 | 用户 | Hub |
| 组网 | `links` | M1 | 用户（策略覆盖） | node、Hub |
| | `devices` | M1 | 用户（签名） | Hub、node（网关） |
| | `device-credentials` | M1 | 用户（签名） | Hub |
| | `access-rules` | M1 | 用户（签名） | Hub |
| | `hostnames` | M1 | 用户、Hub | Hub |
| 变更 | `changes` | M1 | 用户、API token | Hub |
| | `action-types` | M1 | — | Hub（内置） |

## 5. 资源详解

### 5.1 身份与访问

**`owner`**（单例）：唯一用户。

| 字段 | 说明 |
|---|---|
| `spec.display_name` | 显示名称 |
| `spec.locale`、`spec.timezone` | 控制台显示偏好 |
| `status.initialized_at` | 完成初始化（注册首个 passkey）的时间 |
| `status.recovery_key` | 恢复密钥的指纹与创建时间 |
| `status.backup_key` | 备份公钥的指纹与创建时间 |

**`trust`**（单例）：当前生效的信任锚清单（格式见 `auth.md` 第 11 节）及其版本。只读；新增、删除 passkey 或更换恢复密钥时由 Hub 生成新版本，经签名后生效。

**`passkeys`**：已注册的 passkey。注册与签名流程见 `auth.md`。

| 字段 | 说明 |
|---|---|
| `spec.name` | 便于识别的名称（如"MacBook Touch ID"） |
| `status.credential_id_hash`、`status.created_at`、`status.last_used_at` | — |

至少保留一个 passkey；删除最后一个时拒绝。

**`sessions`**：浏览器会话，只读。动作：`revoke`。

**`api-tokens`**

| 字段 | 说明 |
|---|---|
| `spec.name` | 用途说明 |
| `spec.kind` | `script`（见 `auth.md` 第 6.2 节） |
| `spec.scopes` | 权限范围列表（定义见 `auth.md`） |
| `spec.expires_at` | 过期时间，必填，最长 1 年 |
| `spec.allowed_sources` | 可选，允许的来源地址范围 |
| `status.prefix` | 明文前缀，用于识别（如 `nett_tok_8Kq3…`） |
| `status.last_used_at`、`status.last_used_from` | 最近一次使用 |
| `status.phase` | `active` / `expired` / `revoked` |

明文 token 只在创建响应中返回一次。动作：`revoke`。

### 5.2 节点

**`nodes`**

| 字段 | 说明 |
|---|---|
| `spec.name`、`labels` | 名称和标签 |
| `spec.description` | 备注 |
| `spec.relay_limits` | 作为中继时的流量和带宽上限 |
| `status.phase` | `pending`（已创建入网 token，尚未连接）/ `online` / `offline` / `removed` |
| `status.version` | nett 版本 |
| `status.platform` | `os`、`distro`、`kernel`、`arch` |
| `status.install_method` | `native` / `container_member`（macOS 的容器内成员）/ `haos_addon`（Home Assistant OS 加载项）；控制台据此只显示可用的模块 |
| `status.capabilities` | `wireguard_kernel`、`tun`、`docker`、`root` 等探测结果 |
| `status.hard_deny` | 节点本地硬性禁止的模块（只读，由 node 上报） |
| `status.modules` | 每个模块的状态：`{ name, enabled, state, message }` |
| `status.reachability` | `public` / `dial-only`，以及探测到的外部地址、需要放行但不通的端口 |
| `status.addresses` | 局域网地址、组网地址、Edge 专用地址（节点有 `edge` 角色时） |
| `status.relay` | 是否提供中继、当前承载的流量 |
| `status.last_seen_at` | 最近一次与 Hub 通信的时间 |

Edge 回源时，服务看到的来源是 Edge 专用地址（经容器内成员到达的容器服务也是如此）；经智能入口转发时，是智能入口的入口地址（ADR 0015、0016）。需要访客真实 IP 的服务把这个地址配置为可信代理。

节点的模块权限不在 `spec` 中修改，而是通过 `node-policies`：开启模块经由变更集并需要签名，关闭模块可以直接下发。动作：`remove`（高风险，吊销节点凭据）。升级通过 `release` 分区进行（`auth.md` 第 11.3 节），不是节点上的动作。节点自行退出（`nett leave`）时，Hub 直接把它标记为 `removed`。

**`enrollment-tokens`**

| 字段 | 说明 |
|---|---|
| `spec.node_name` | 入网后节点的名称 |
| `spec.modules` | 初始启用的模块 |
| `spec.labels` | 初始标签 |
| `spec.expires_at` | 过期时间（默认 30 分钟，最长 24 小时） |
| `spec.enrollment_public_key` | 浏览器生成的入网公钥（私钥只在 token 中，见 `auth.md` 第 8.1 节） |
| `status.phase` | `active` / `used` / `expired` / `revoked` |
| `status.node_id` | 创建时分配的节点 ID；节点同时进入 `pending` |
| `status.install_command` | 带 token 的安装命令（由浏览器拼装，Hub 不保存） |

**`node-policies`**：节点权限的签名策略。提升权限的策略由变更集批准后生成，不能直接创建。

| 字段 | 说明 |
|---|---|
| `spec.node_id` | 目标节点 |
| `spec.modules` | 允许启用的模块 |
| `spec.roles` | 角色：`relay`、`gateway`（移动网关）、`subnet_router`（智能入口）、`edge`（本机运行 Edge，并声明怎样识别 Edge 发出的流量：Edge 所在容器的地址，或原生运行时的系统用户）；由 `node.set_roles` 签名 |
| `spec.addresses` | 组网地址；有 `edge` 角色时还有 Edge 专用地址 |
| `spec.advertised_routes` | 宣告的局域网网段（由 `node.advertise_routes` 签名） |
| `spec.enrollment_public_key` | 入网公钥，用于验证准入证明 |
| `spec.policy_version` | 只增不减 |
| `spec.signature` | passkey 签名（降低权限时可省略） |
| `status.phase` | `pending` / `applied` / `rejected` |
| `status.reason` | 被拒绝的原因（如签名无效、版本过旧、命中本地硬性禁止） |

### 5.3 活动：`events`

只读、只追加，同时承担审计和活动时间线。

| 字段 | 说明 |
|---|---|
| `at` | 发生时间 |
| `actor` | `{ kind, id }`；`kind` 为 `owner` / `api_token` / `node` / `system` |
| `action` | 形如 `<资源>.<动作>`，例如 `device.add`、`node.remove`、`session.login` |
| `targets` | 涉及的资源引用列表 |
| `outcome` | `success` / `failure` |
| `change_id` | 关联的变更集（如有） |
| `summary` | 一句话描述，供时间线显示 |
| `details` | 结构化细节；敏感值已脱敏 |

- 记录范围：所有写操作和安全事件（登录、token 创建与吊销、签名、入网等）；查询不记录；
- 默认保留 90 天；API 不提供删除；
- 支持按时间、操作方、动作、目标资源筛选；实时推送见第 7 节。

### 5.4 系统

| 资源 | 内容 |
|---|---|
| `hub`（单例） | 版本、对外地址、数据保留策略 |
| `releases` | 可用的发布版本及签名信息；节点升级时从 Hub 获取 |
| `backups` | 备份记录：时间、大小、存放位置、结果。动作：`create`、`verify` |

### 5.5 组网

**`links`**：一对节点之间的连接。由 Hub 根据组网拓扑生成，不需要手动创建。

| 字段 | 说明 |
|---|---|
| `status.endpoints` | 两端的节点或设备 |
| `status.path` | 当前路径：`kind`（`lan` / `direct` / `relay` / `multi_hop`）、`via`（经过的中继） |
| `status.transport` | `udp` / `tls` / `quic` |
| `status.rtt_ms`、`status.loss`、`status.jitter_ms` | 当前质量 |
| `status.candidates` | 候选路径及各自的得分 |
| `status.switched_at`、`status.switch_reason` | 最近一次切换的时间和原因 |
| `spec.policy` | 可选的策略覆盖：优先直连、强制经某个中继、固定传输方式 |

**`devices`**

| 字段 | 说明 |
|---|---|
| `spec.name`、`spec.kind` | 名称；`phone` / `laptop` / `other` |
| `spec.paths` | 启用的路径：直连家里、移动网关 |
| `spec.disabled` | 禁用后，该设备的所有凭据立即失效（降低权限，直接执行） |
| `status.last_handshake_at` | 各凭据中最近的一次握手 |

新增设备为高风险操作（`device.add`，同时创建第一份凭据）。

**`device-credentials`**：一台设备的一份接入凭据。

| 字段 | 说明 |
|---|---|
| `spec.device_id`、`spec.label` | 所属设备；用途说明（如"第三方客户端"） |
| `spec.kind` | `wireguard` / `connect`（CONNECT 代理凭据，见 `auth.md` 第 9 节） |
| `status.public_key` | WireGuard 公钥（`wireguard`）；`connect` 类型只返回 token 前缀 |
| `status.address` | 分配的组网地址（`wireguard`）。每份凭据一个地址：同一台设备的多份凭据会同时作为网关的不同对端，而 WireGuard 不允许两个对端的 `AllowedIPs` 重叠 |
| `status.gateway_node_id` | 这份凭据当前所属的移动网关（由网关上报的握手决定，见 `mesh.md` 第 13 节） |
| `status.last_handshake_at` | 最近一次握手 |

- **私钥只在浏览器中生成**，Hub 只保存公钥，从不经手私钥；**配置文件、二维码和代理客户端配置只在创建时由浏览器生成一次**，之后不能再导出，丢失时新建凭据（`auth.md` 第 9 节）；
- 新增 WireGuard 设备时一次创建两份凭据：主配置（直连家里 + 移动网关）和"全部经网关"的备用配置各用一份（`mesh.md` 第 13 节）；
- 给已有设备新增凭据是高风险操作（`device_credential.create`），与新增设备一样需要签名；创建记入 `events`；
- 动作：`revoke`。

**`access-rules`**

| 字段 | 说明 |
|---|---|
| `spec.from`、`spec.to` | 选择器：节点、设备、标签；`spec.from` 还可以选某个节点的 Edge 专用地址（该节点的 `edge`） |
| `spec.ports` | 端口和协议 |
| `spec.action` | `allow` / `deny` |
| `spec.priority` | 优先级 |

默认值因目标而异（`mesh.md` 第 12 节）：组网成员之间**默认允许**；宣告的局域网段**默认拒绝**，只对用户的设备开放；Edge 专用地址默认不能访问任何目标，能访问哪些主机和端口由用户在访问规则中写。规则按 `priority` 匹配。

整份规则集作为一份带版本号的签名产物下发（`auth.md` 第 10.1 节）。**签名产物中写的是选择器展开后的结果**（成员 ID、地址、端口），节点只执行展开结果；标签变化导致展开结果变大时，Hub 生成新的规则集，作为放宽访问的变更等待签名，在签名之前继续执行旧的展开结果。放宽访问的修改是高风险操作；新增 deny 规则、删除 allow 规则属于收窄，直接执行。

**`whois`**（查询接口）：`GET /api/v1/mesh/whois?address=…`，按组网地址查询它属于哪个节点、设备或 Edge，供控制台显示（roadmap M1 的"身份查询"）。这是 Hub 的声明；服务和 agent 需要确认对方身份时，使用本机的 `nett whois`（组网进程按已验证的准入材料回答，`mesh.md` 第 11 节）。

**`hostnames`**：组网内的主机名。节点自动获得主机名（节点名）；用户可以添加别名。

| 字段 | 说明 |
|---|---|
| `spec.name` | 主机名 |
| `spec.target` | 指向的节点 |
| `status.origin` | `auto` / `user` |

### 5.6 变更

**`changes`**：完整设计见 [changes.md](changes.md)。要点：

| 字段 | 说明 |
|---|---|
| `spec.steps` | 步骤 `{ action_type, target, payload, expected_revision }`；每个变更集只有一个步骤 |
| `spec.reason` | 原因说明 |
| `spec.apply_mode` | `manual` / `on_approval` |
| `spec.not_before`、`spec.expires_at` | 最早执行时间；等待批准的截止时间 |
| `status.phase` | `planned` / `awaiting_approval` / `approved` / `applying` / `succeeded` / `failed` / `rejected` / `cancelled` / `expired` |
| `status.risk`、`status.proposed_by` | 风险等级；提议方 |
| `status.plan` | 预演结果；其中的 `hash` 即批准和签名绑定的 `plan_hash` |
| `status.approval` | 批准信息；高风险时为绑定 `plan_hash` 的 passkey 签名 |
| `status.progress`、`status.result` | 执行进度；执行结果 |

动作：`approve`、`reject`、`apply`、`cancel`。

**`action-types`**：只读的动作目录。字段：名称、目标资源类型、风险等级、能否撤销、所需权限范围、说明。完整列表见 [changes.md](changes.md) 第 9 节。

## 6. 关系

```
owner ── passkeys
      ── api-tokens ──┐
                      ├─► events（actor）
enrollment-tokens ─► nodes ◄── node-policies
                      │
                      ├── links（两端）
                      └── hostnames
devices ── device-credentials
changes ─► 任意资源（target）；events.change_id ─► changes
```

## 7. 实时推送

使用 SSE：

| 端点 | 内容 |
|---|---|
| `GET /api/v1/streams/events` | 新增的活动事件 |
| `GET /api/v1/streams/resources?kind=nodes` | 资源变化（`status` 更新），供控制台刷新 |

连接数有上限；空闲连接定期发送注释行保持连接。

## 8. 阶段划分

| 阶段 | 资源 |
|---|---|
| M1 | `owner`、`trust`、`passkeys`、`sessions`、`api-tokens`、`nodes`、`enrollment-tokens`、`node-policies`、`events`、`hub`、`releases`、`backups`、`changes`、`action-types`；组网：`links`、`devices`、`device-credentials`、`access-rules`、`hostnames`（节点名与别名）、`whois` |

## 9. 待定问题

| 问题 | 在哪里决定 |
|---|---|
| 权限范围的完整列表与命名 | `auth.md` |
