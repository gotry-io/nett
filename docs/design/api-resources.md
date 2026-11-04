# API 资源模型

- 状态：草案
- 阶段：P0（资源分阶段实现，见第 8 节）
- 相关：[architecture.md](../architecture.md)、ADR [0003](../adr/0003-api-and-protocols.md)、[0006](../adr/0006-auth-and-passkey-signing.md)、[0010](../adr/0010-ai-via-api-only.md)

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
| nodes | `node` | stacks | `stk` |
| passkeys | `pk` | deployments | `dep` |
| sessions | `ses` | services | `svc` |
| api-tokens | `tok` | routes | `rte` |
| enrollment-tokens | `enr` | certificates | `crt` |
| node-policies | `pol` | changes | `chg` |
| alert-rules | `arl` | events | `evt` |
| alerts | `alt` | devices | `dev` |
| heartbeat-checks | `hbc` | device-credentials | `dcr` |
| notification-channels | `nch` | access-rules | `acr` |
| links | `lnk` | hostnames | `hst` |
| backups | `bak` | auto-apply-policies | `aap` |
| ci-trust-rules | `cit` | | |

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

只读的资源（如 `events`、`certificates`）没有 `spec`。

### 2.4 列表、筛选与分页

- 游标分页：`?limit=50&cursor=<不透明字符串>`；`limit` 默认 50，最大 200；响应中带 `next_cursor`；
- 筛选：按标签 `?label=role:edge`，按引用 `?node=edge-us-1`，按状态 `?phase=online`；
- 排序：默认按 `created_at` 倒序；支持的排序字段在各资源中说明。

### 2.5 并发与幂等

- 修改 `spec` 时必须带 `If-Match: <revision>`；版本不一致返回 `412`，避免覆盖他人（包括 CI、AI）的修改；
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

- 密钥、token、私钥只在创建时返回一次，之后只返回前缀或指纹；
- 通知渠道的凭据等字段为**只写**：可以设置，读取时只返回是否已设置。

## 3. 写入方式与风险分级

| 风险 | 例子 | 方式 |
|---|---|---|
| **低** | 修改名称、标签、告警阈值、通知渠道 | 直接修改资源 |
| **中** | 部署新版本（在部署档位之内）、修改路由（不改变回源目标）、重启服务 | 通过变更集：预演 → 执行 |
| **高** | 开启模块（metrics 除外）、新增设备或设备凭据、放宽访问规则、宣告网段、新增或改变路由的回源目标、提高部署档位、吊销节点 | 通过变更集，并需要 passkey 签名批准 |

- 中、高风险的写入不直接修改资源，而是创建一个 `change`。直接调用对应资源的写接口时，Hub 返回 `202` 和新建的 `change`；
- **降低权限**（关闭模块、吊销 token、禁用设备、收窄访问规则）始终视为低风险，可以直接执行；
- `ai` 类型 token 的一切写入（包括低风险的直接修改）都通过变更集，由用户批准（auth.md 第 6.2 节）；
- 每类写入的风险等级由动作目录（`action-types`）定义，`changes.md` 给出完整列表；
- 变更集从 M1 起提供（最小版本），覆盖范围随阶段扩展，见第 8 节。

### 3.1 资源上的动作

增删改之外的操作，以动作的形式提供：

```
POST /api/v1/<资源>/{id}/actions/<动作>
```

例如 `POST /api/v1/services/svc_…/actions/restart`。动作同样受风险分级约束：低风险直接执行并返回结果；中、高风险返回 `202` 和对应的 `change`。

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
| 观测 | `metrics`（查询接口） | M1 | — | node |
| | `alert-rules` | M1 | 用户 | Hub |
| | `alerts` | M1 | — | Hub |
| | `heartbeat-checks` | M1 | 用户 | Hub |
| | `notification-channels` | M1 | 用户 | Hub |
| 活动 | `events` | M1 | — | Hub |
| 系统 | `hub`、`releases`、`backups` | M1 | 用户 | Hub |
| 服务 | `services` | M1 只读，M3 可操作 | 用户（M3） | node |
| 组网 | `links` | M2 | 用户（策略覆盖） | node、Hub |
| | `devices` | M2 | 用户（签名） | Hub、node（网关） |
| | `device-credentials` | M2 | 用户（签名） | Hub |
| | `access-rules` | M2 | 用户（签名） | Hub |
| | `hostnames` | M2 | 用户、Hub | Hub |
| 部署 | `stacks` | M3 | 用户、CI | node、Hub |
| | `deployments` | M3 | — | node、Hub |
| 入口 | `routes` | M3 | 用户 | node（ingress） |
| | `certificates` | M3 | — | node（ingress） |
| 变更 | `changes` | M1 最小版本，M3 补全 | 用户、API token、CI、AI | Hub |
| | `action-types` | M1 起，随阶段增加 | — | Hub（内置） |
| | `auto-apply-policies` | M3 | 用户（签名） | Hub |
| | `ci-trust-rules` | M3 | 用户 | Hub |

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

**`trust`**（单例）：当前生效的信任锚清单（格式见 `auth.md` 第 12 节）及其版本。只读；新增、删除 passkey 或更换恢复密钥时由 Hub 生成新版本，经签名后生效。

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
| `spec.kind` | `script` / `ai`（见 `auth.md` 第 6.2 节） |
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
| `spec.ingress_domains` | 该节点作为入口节点时能承载的域名后缀（例如某些地区要求域名在该云厂商备案）；路由的 `spec.edges` 据此校验 |
| `spec.relay_limits` | 作为中继时的流量和带宽上限 |
| `status.phase` | `pending`（已创建入网 token，尚未连接）/ `online` / `offline` / `removed` |
| `status.version` | nett 版本 |
| `status.platform` | `os`、`distro`、`kernel`、`arch` |
| `status.install_method` | `native` / `container_member`（macOS 的容器内成员）/ `haos_addon`（Home Assistant OS 加载项）；控制台据此只显示可用的模块 |
| `status.capabilities` | `wireguard_kernel`、`tun`、`docker`、`root` 等探测结果 |
| `status.hard_deny` | 节点本地硬性禁止的模块（只读，由 node 上报） |
| `status.modules` | 每个模块的状态：`{ name, enabled, state, message }` |
| `status.reachability` | `public` / `dial-only`，以及探测到的外部地址、需要放行但不通的端口 |
| `status.addresses` | 局域网地址、组网地址、Edge 专用地址（开启 ingress 时） |
| `status.relay` | 是否提供中继、当前承载的流量（M2） |
| `status.resources` | 最近一次的 CPU、内存、磁盘概况 |
| `status.last_seen_at` | 最近一次与 Hub 通信的时间 |

节点的模块权限不在 `spec` 中修改，而是通过 `node-policies`：开启模块经由变更集并需要签名，关闭模块可以直接下发。动作：`remove`（高风险，吊销节点凭据）。升级通过 `release` 分区进行（`auth.md` 第 12.3 节），不是节点上的动作。节点自行退出（`nett leave`）时，Hub 直接把它标记为 `removed`。

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
| `spec.roles` | 角色：`relay`、`gateway`（移动网关）、`subnet_router`（智能入口） |
| `spec.addresses` | 组网地址；开启 ingress 时的 Edge 专用地址 |
| `spec.advertised_routes` | 宣告的局域网网段（由 `node.advertise_routes` 签名） |
| `spec.deploy_profile` | 部署档位（M3，由 `node.set_deploy_profile` 签名，见 `changes.md` 第 7.1 节） |
| `spec.enrollment_public_key` | 入网公钥，用于验证准入证明 |
| `spec.policy_version` | 只增不减 |
| `spec.signature` | passkey 签名（降低权限时可省略） |
| `status.phase` | `pending` / `applied` / `rejected` |
| `status.reason` | 被拒绝的原因（如签名无效、版本过旧、命中本地硬性禁止） |

### 5.3 观测

**`metrics`**：查询接口，不是普通资源。

```
GET /api/v1/metrics/series                       # 可用的指标列表
GET /api/v1/metrics?series=host.mem.used&node=edge-us-1&from=…&to=…
```

- 服务端按时间范围选择降采样粒度，每条曲线最多约 1000 个点；
- 线路质量也是指标：`link.rtt`、`link.loss`、`link.jitter`，以 `src`、`dst` 作为维度。

**`alert-rules`**

| 字段 | 说明 |
|---|---|
| `spec.target` | 选择器：节点、服务、标签 |
| `spec.condition` | 条件：指标、比较方式、阈值、持续时间；或事件类条件（节点离线、容器 OOM） |
| `spec.severity` | `info` / `warning` / `critical` |
| `spec.channels` | 通知渠道 |
| `spec.enabled` | 是否启用 |
| `status.builtin` | 是否为内置规则（内置规则可以修改阈值、禁用，不能删除） |

**`alerts`**：只读，由规则触发。

| 字段 | 说明 |
|---|---|
| `status.rule_id`、`status.target` | 规则和对象 |
| `status.phase` | `firing` / `acknowledged` / `resolved` |
| `status.value` | 触发时的值 |
| `status.started_at`、`status.resolved_at` | — |

动作：`acknowledge`、`silence`（带截止时间）。

**`heartbeat-checks`**：必须按时发生的事情，例如备份、定时任务。

| 字段 | 说明 |
|---|---|
| `spec.source` | `ping`（脚本按时请求 `ping_url`）/ `systemd_timer`（由节点观察本机某个定时器的运行结果，无需改脚本） |
| `spec.period_secs`、`spec.grace_secs` | 预期周期和宽限时间 |
| `spec.related` | 关联的节点或服务（可选） |
| `status.phase` | `new` / `up` / `late` / `down` |
| `status.last_ping_at` | 最近一次收到心跳的时间 |
| `status.ping_url` | 发送心跳的地址（带独立的密钥，仅创建时返回完整值） |

心跳通过 `POST <ping_url>` 发送，只需 URL 中的密钥，不需要 API token，以便在脚本中使用。

**`notification-channels`**

| 字段 | 说明 |
|---|---|
| `spec.kind` | `telegram` / `email` / `webhook` |
| `spec.config` | 渠道配置；凭据类字段只写 |
| `status.last_delivery_at`、`status.last_error` | — |

动作：`test`（发送一条测试通知）。

### 5.4 活动：`events`

只读、只追加，同时承担审计和活动时间线。

| 字段 | 说明 |
|---|---|
| `at` | 发生时间 |
| `actor` | `{ kind, id }`；`kind` 为 `owner` / `api_token` / `ci` / `ai` / `node` / `system` |
| `action` | 形如 `<资源>.<动作>`，例如 `route.update`、`deployment.rollback`、`session.login` |
| `targets` | 涉及的资源引用列表 |
| `outcome` | `success` / `failure` |
| `change_id` | 关联的变更集（如有） |
| `summary` | 一句话描述，供时间线显示 |
| `details` | 结构化细节；敏感值已脱敏 |

- 记录范围：所有写操作和安全事件（登录、token 创建与吊销、签名、入网、部署、回滚、告警触发与恢复等）；查询不记录，导出敏感内容（如设备配置）除外；
- 默认保留 90 天；API 不提供删除；
- 支持按时间、操作方、动作、目标资源筛选；实时推送见第 7 节。

### 5.5 系统

| 资源 | 内容 |
|---|---|
| `hub`（单例） | 版本、对外地址、数据保留策略、外部死信开关的配置 |
| `releases` | 可用的发布版本及签名信息；节点升级时从 Hub 获取 |
| `backups` | 备份记录：时间、大小、存放位置、结果。动作：`create`、`verify` |

### 5.6 服务：`services`

由 node 上报的运行中服务（M1 起由 metrics 模块只读发现，M3 起可操作）。

| 字段 | 说明 |
|---|---|
| `status.node_id` | 所在节点 |
| `status.runtime` | `container` / `process` / `systemd`（原生服务只观测，不部署） |
| `status.systemd` | 原生服务所属的 systemd 单元与状态，以及相关的定时器和最近一次运行结果 |
| `status.container` | 容器名、镜像、镜像摘要 |
| `status.ports` | 监听的端口和协议 |
| `status.health` | 健康状态 |
| `status.stack_id` | 所属 stack（M3） |
| `status.resources` | 最近一次的 CPU、内存 |

动作（M3）：`restart`、`stop`、`start`（均为中风险）。

### 5.7 组网（M2）

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
| `status.gateway_node_id` | 当前所属的移动网关（由网关上报的握手决定，见 `mesh.md` 第 13 节） |
| `status.last_handshake_at` | 最近一次握手 |

新增设备为高风险操作（`device.add`，同时创建第一份凭据）。

**`device-credentials`**：一台设备的一份接入凭据。

| 字段 | 说明 |
|---|---|
| `spec.device_id`、`spec.label` | 所属设备；用途说明（如"第三方客户端"） |
| `spec.kind` | `wireguard` / `connect`（CONNECT 代理凭据，见 `auth.md` 第 10 节） |
| `status.public_key` | WireGuard 公钥（`wireguard`）；`connect` 类型只返回 token 前缀 |
| `status.address` | 分配的组网地址（`wireguard`）。每份凭据一个地址：同一台设备的多份凭据会同时作为网关的不同对端，而 WireGuard 不允许两个对端的 `AllowedIPs` 重叠 |

- **私钥优先在浏览器中生成**，Hub 只保存公钥；浏览器不支持时由 Hub 生成，只显示一次；
- 给已有设备新增凭据是高风险操作（`device_credential.create`），与新增设备一样需要签名；
- 动作：`export`（导出配置文件和二维码，记入 `events`）、`revoke`。

**`access-rules`**

| 字段 | 说明 |
|---|---|
| `spec.from`、`spec.to` | 选择器：节点、设备、标签、服务 |
| `spec.ports` | 端口和协议 |
| `spec.action` | `allow` / `deny` |
| `spec.priority` | 优先级 |

默认值因目标而异（`mesh.md` 第 12 节）：组网成员之间**默认允许**；宣告的局域网段**默认拒绝**，只对用户的设备开放；Edge 专用地址只能访问路由的目标，这部分规则由路由生成（`status.origin = route`），不能单独修改。规则按 `priority` 匹配。

整份规则集作为一份带版本号的签名产物下发（`auth.md` 第 11.1 节）：放宽访问的修改是高风险操作；新增 deny 规则、删除 allow 规则属于收窄，直接执行。

**`whois`**（查询接口）：`GET /api/v1/mesh/whois?address=…`，按组网地址查询它属于哪个节点、设备或 Edge，供服务和 agent 识别对方身份（roadmap M2 的"身份查询"）。服务注册表即 `services` 与 `hostnames`。

**`hostnames`**：组网内的主机名。节点和服务自动获得主机名；用户可以添加别名。

| 字段 | 说明 |
|---|---|
| `spec.name` | 主机名 |
| `spec.target` | 指向的节点或服务 |
| `status.origin` | `auto` / `user` |

### 5.8 部署（M3）

**`stacks`**

| 字段 | 说明 |
|---|---|
| `spec.node_id` | 部署目标节点 |
| `spec.source` | Git 仓库、路径、引用 |
| `spec.env` | 环境变量。敏感值由浏览器用目标节点的公钥加密后提交，Hub 只保存密文（`auth.md` 第 13 节）；读取时只返回是否已设置 |
| `spec.hooks` | 部署前后的钩子（白名单内的命令或容器任务） |
| `spec.auto_deploy` | CI 通知有新版本后是否自动部署；**默认关闭**，即在控制台手动一键部署 |
| `status.current_deployment_id` | 当前生效的部署 |
| `status.health` | 整体健康状态 |

**`deployments`**：只读，一次部署对应一条记录。

| 字段 | 说明 |
|---|---|
| `status.stack_id`、`status.revision` | stack 和版本 |
| `status.trigger` | `ci` / `owner` / `api_token` / `ai` / `rollback` |
| `status.phase` | `pending` / `running` / `succeeded` / `failed` / `rolled_back` |
| `status.steps` | 各步骤的结果摘要 |
| `status.change_id` | 对应的变更集 |

动作：`rollback`（中风险，回滚到这一次部署的版本）。

### 5.9 入口（M3）

**`routes`**

| 字段 | 说明 |
|---|---|
| `spec.host`、`spec.path_prefix` | 域名和路径前缀 |
| `spec.target` | 服务和端口 |
| `spec.edges` | 由哪些入口节点提供；必须匹配这些节点的 `spec.ingress_domains` |
| `spec.tls` | 证书策略：自动申请（含通配符）或指定。DNS 验证所需的凭据由浏览器用入口节点的公钥加密 |
| `spec.origin.real_ip` | 服务是否需要访客的真实 IP |
| `status.edges` | 每个入口节点上的生效状态 |
| `status.forwarder_address` | 服务实际看到的转发者地址：Edge 专用地址、智能入口的入口地址或容器内成员的地址（ADR 0015）。需要真实 IP 的服务把它配置为可信代理 |
| `status.upstream_health` | 回源健康状态 |

路由的变更会同时生成"Edge 专用地址 → 目标主机:端口"的访问规则，随路由变更一起预演和批准。

**`certificates`**：只读，由 ingress 模块上报。字段：域名、签发者、到期时间、所在入口节点、续期状态。

### 5.10 变更（M1 最小版本，M3 补全）

**`changes`**：完整设计见 [changes.md](changes.md)。要点：

| 字段 | 说明 |
|---|---|
| `spec.steps` | 有序步骤，每步为 `{ action_type, target, payload, expected_revision }` |
| `spec.reason` | 原因说明（AI 提案时必填） |
| `spec.apply_mode` | `manual` / `on_approval` / `auto` |
| `spec.not_before`、`spec.expires_at` | 最早执行时间；等待批准的截止时间 |
| `status.phase` | `planned` / `awaiting_approval` / `approved` / `applying` / `verifying` / `succeeded` / `rolling_back` / `rolled_back` / `failed` / `rejected` / `cancelled` / `expired` |
| `status.risk`、`status.proposed_by` | 风险等级；提议方 |
| `status.plan` | 预演结果；其中的 `hash` 即批准和签名绑定的 `plan_hash` |
| `status.approval` | 批准信息；高风险时为绑定 `plan_hash` 的 passkey 签名 |
| `status.progress`、`status.result` | 各步骤进度；执行与验证结果 |

动作：`approve`、`reject`、`apply`、`cancel`。

**`action-types`**：只读的动作目录。字段：名称、目标资源类型、风险等级、能否撤销、所需权限范围、说明。完整列表见 [changes.md](changes.md) 第 9 节。

**`auto-apply-policies`**（M3）：自动执行策略，指定哪些提议方、动作类型和目标可以在预演无警告时自动执行（`changes.md` 第 5 节）。字段：`spec.proposers`、`spec.action_types`、`spec.targets`、`spec.enabled`。修改为高风险操作，只能在用户会话中进行。

**`ci-trust-rules`**（M3）：CI 的 OIDC 信任规则（`auth.md` 第 9 节）。字段：`spec.issuer`、`spec.audience`、`spec.repository`、`spec.ref`（分支或环境）、`spec.scopes`。只能在用户会话中修改。

## 6. 关系

```
owner ── passkeys
      ── api-tokens ──┐
                      ├─► events（actor）
enrollment-tokens ─► nodes ◄── node-policies
                      │
                      ├── services ◄── stacks ── deployments
                      │      ▲
                      │      └── routes ── certificates
                      ├── links（两端）
                      └── hostnames
devices ── device-credentials
alert-rules ─► alerts ─► notification-channels
heartbeat-checks ─► alerts
changes ─► 任意资源（targets）；events.change_id ─► changes
```

## 7. 实时推送

使用 SSE：

| 端点 | 内容 |
|---|---|
| `GET /api/v1/streams/events` | 新增的活动事件 |
| `GET /api/v1/streams/metrics?node=…&series=…` | 实时指标；有订阅时，Hub 通知对应 node 切换到秒级采集 |
| `GET /api/v1/streams/resources?kind=nodes` | 资源变化（`status` 更新），供控制台刷新 |

连接数有上限；空闲连接定期发送注释行保持连接。

## 8. 阶段划分

| 阶段 | 资源 |
|---|---|
| M1 | `owner`、`trust`、`passkeys`、`sessions`、`api-tokens`、`nodes`、`enrollment-tokens`、`node-policies`、`metrics`、`alert-rules`、`alerts`、`heartbeat-checks`、`notification-channels`、`events`、`hub`、`releases`、`backups`、`services`（只读）、`changes` 与 `action-types`（最小版本） |
| M2 | `links`、`devices`、`device-credentials`、`access-rules`、`hostnames`、`whois` |
| M3 | `stacks`、`deployments`、`routes`、`certificates`、`auto-apply-policies`、`ci-trust-rules`；`services` 的动作；变更集补全（影响分析、自动执行策略、主动验证与自动回滚） |

变更集按"完整设计、最小实现"推进：数据结构和状态在 M1 一次定全，各阶段只增加动作类型和流程能力，不做数据迁移。

## 9. 待定问题

| 问题 | 在哪里决定 |
|---|---|
| 权限范围的完整列表与命名 | `auth.md` |
| 部署钩子允许的形式 | M3 设计 |
