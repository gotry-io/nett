# 认证与授权

- 状态：草案
- 阶段：P0 设计；M1 实现主体，后续阶段补充（见第 14 节）
- 相关：ADR [0006](../adr/0006-auth-and-passkey-signing.md)、[api-resources.md](api-resources.md)、[changes.md](changes.md)

## 1. 范围

本文定义：信任模型、各类身份及其凭据、初始化与恢复、登录与会话、API token、权限范围、node 入网与连接认证、CI 认证、设备凭据、签名格式、信任锚的分发与更新、防护措施。

## 2. 信任模型

```
用户的 passkey（及恢复密钥）  ← 最高信任锚，私钥只在用户设备上
   │ 签名
   ▼
信任锚清单（passkey 公钥 + 恢复密钥公钥）──► 写入每个节点
   │                                         │
   │ 签名                                     │ 节点用它独立验证
   ▼                                         ▼
变更批准、节点策略  ─────── Hub 转发 ───────►  节点
```

| 主体 | 持有的密钥 | 被谁信任 | 被攻破的后果 |
|---|---|---|---|
| 用户 | passkey 私钥（设备内）、恢复密钥（离线保存） | Hub、所有节点 | 全部控制权 |
| Hub | Hub 身份密钥（X25519，用于 Noise） | 节点（入网时固定其指纹） | 能观测和执行低风险操作；**不能**提升任何节点的权限 |
| 节点 | 节点身份密钥（X25519，用于 Noise）、组网私钥 | Hub、其他节点（经 Hub 分发公钥） | 影响该节点本身 |
| nett-relay | 不持有组网私钥和身份密钥 | — | 只能转发或丢弃密文 |

原则：**Hub 是中间人，而不是信任根**。所有提升权限的操作，最终都要由节点用用户的公钥验证。

## 3. 身份与凭据

| 身份 | 凭据 | 用途 | 记录到 `events` 的 `actor.kind` |
|---|---|---|---|
| 用户 | passkey；恢复密钥 | 控制台登录、批准与签名 | `owner` |
| 会话 | 会话 Cookie | 浏览器访问 API | `owner` |
| API token | Bearer token | 脚本、AI、静态集成 | `api_token` / `ai`（按 token 类型） |
| node | X25519 身份密钥 | node ↔ Hub 通信 | `node` |
| CI | OIDC 短期令牌 | 触发部署 | `ci` |
| 设备 | WireGuard 密钥 | 组网接入 | — |
| 心跳 | URL 中的独立密钥 | 上报心跳 | `system` |
| Hub 自身 | — | 自动执行、回滚、告警 | `system` |

## 4. 初始化与恢复

### 4.1 初始化

1. 安装 Hub 后，终端打印一次性**初始化链接**：包含 256 位随机密钥，1 小时内有效，只能使用一次；
2. 打开链接，注册第一个 passkey；
3. Hub 生成**恢复密钥**（一对 P-256 签名密钥），将私钥以文本形式显示一次，并提供下载，提示离线保存；Hub 只保存其公钥；
4. 建议立即注册第二个 passkey（例如另一台设备或硬件密钥）；
5. 初始化完成后，初始化链接失效，再次初始化需要在 Hub 主机上执行命令重置。

### 4.2 恢复

| 情形 | 处理 |
|---|---|
| 丢失一个 passkey，仍有其他 passkey | 用其他 passkey 登录，删除丢失的 passkey（信任锚更新，需签名） |
| 丢失全部 passkey | 用恢复密钥登录控制台，注册新的 passkey；信任锚更新由恢复密钥签名 |
| 恢复密钥也丢失 | 无法在线恢复；需要在 Hub 主机上重置信任锚，并在每个节点上执行 `nett trust reset`（需要节点 root 权限） |

恢复密钥既能登录，也能签名信任锚更新，权限等同于 passkey，必须离线保存。

**呈现形式**：私钥以 `nett-recovery-` 开头，后接 Bech32m 编码的数据部分，按 4 个字符一组、以连字符分隔显示，例如 `nett-recovery-qpzr-y9x8-gf2t-…`。校验和按 Bech32m 规则、以 `nett-recovery` 作为前缀计算；显示时省略 Bech32 规定的分隔符 `1`，解析时自动补回。输入时忽略连字符、空格和大小写，校验和可以发现绝大多数抄写错误。

## 5. 登录与会话

- **控制台只使用一个地址**：passkey 绑定注册时的域名（RP ID），在其他域名下无法使用；Hub 的备用入口只用于 node 连接（node 依靠 Hub 公钥认证，不涉及 passkey），不提供控制台；
- 登录：WebAuthn 认证，要求用户验证（UV）；
- 会话 Cookie：`__Host-nett_session`，`HttpOnly`、`Secure`、`SameSite=Strict`；空闲 12 小时过期，最长 7 天；
- **二次验证**：查看或导出敏感内容（如设备配置）、创建带写权限的 API token、修改通知渠道凭据等，要求 5 分钟内完成过一次 passkey 验证；
- CSRF：`SameSite=Strict` 之外，所有写请求校验 `Origin` 头；
- 会话可以在控制台查看和吊销。

## 6. API token

### 6.1 格式

```
nett_tok_<26 位 ID>_<43 位随机密钥>
```

- 固定前缀便于代码托管平台的密钥扫描识别；
- 随机密钥为 256 位；服务端只保存其 SHA-256 哈希，比较使用常量时间算法；
- 明文只在创建时显示一次。

### 6.2 属性

| 属性 | 说明 |
|---|---|
| `kind` | `script` / `ai`：决定活动记录中的操作方类型；`ai` 类型的 token 发起的变更一律需要用户批准 |
| `scopes` | 权限范围（第 7 节） |
| `expires_at` | 必填，最长 1 年 |
| `allowed_sources` | 可选，允许的来源地址范围 |

创建带写权限的 token 需要二次验证。

## 7. 权限范围

格式：`<资源>:<操作>[:<目标名称>]`。

| 权限范围 | 允许 |
|---|---|
| `read` | 读取所有资源（不含敏感字段） |
| `<资源>:read` | 读取某类资源，例如 `nodes:read`、`events:read`、`metrics:read` |
| `<资源>:write` | 低风险的直接修改，例如 `alerts:write`（确认、静默告警）、`nodes:write`（改名称、标签） |
| `changes:propose` | 创建变更集；同时需要对应动作要求的权限范围 |
| `stacks:deploy[:<stack>]` | 提议部署（可限定某个 stack） |
| `services:operate[:<service>]` | 提议重启、停止、启动服务 |
| `routes:write` | 提议修改路由 |
| `heartbeats:ping` | 仅用于心跳（通常直接使用 ping URL） |

规则：

- **token 不能批准变更集**；批准只能由用户在会话中完成，高风险时必须携带 passkey 签名；
- 中风险变更可以由自动执行策略放行（见 `changes.md` 第 5 节），而不是由 token 自己批准；
- 用户会话拥有全部权限范围，但高风险操作仍需签名；
- 涉及身份与信任的操作（passkey、恢复密钥、API token 管理、自动执行策略）只能通过用户会话完成。

## 8. node 入网与连接

### 8.1 入网 token

```
nett_enr_<编码内容>
```

编码内容包含：

| 字段 | 作用 |
|---|---|
| Hub 地址 | 入网时连接的地址 |
| Hub 身份公钥指纹（128 位） | 防止连接到冒充的 Hub |
| 信任锚清单指纹（128 位） | 防止 Hub 在入网时下发伪造的信任锚 |
| 一次性入网密钥（256 位） | 证明持有者获得了用户授权 |

- token 由用户在控制台创建，30 分钟内有效，只能使用一次；
- 创建时勾选的初始模块形成一份**初始节点策略**；其中包含高风险模块时，创建 token 需要 passkey 签名，签名绑定该 token。

### 8.2 入网流程

```
node                                              Hub
 │ 生成节点身份密钥（X25519），私钥只存本机
 │ ── 连接 Hub 地址，完成握手，校验 Hub 公钥指纹 ──►│
 │ ── 入网密钥 + 节点公钥 + 能力信息 ─────────────►│ 校验：未使用、未过期
 │ ◄── 节点 ID + 信任锚清单 + 初始节点策略（含签名）──│
 │ 校验信任锚清单的指纹与 token 中一致
 │ 用信任锚验证初始节点策略的签名
 │ 保存身份、Hub 公钥、信任锚、策略 → 应用 → 上报
```

### 8.3 日常连接

- node 主动建立 WebSocket 连接；
- **在 WebSocket 内层使用 Noise 协议（IK 模式）完成双向认证并建立端到端加密通道**：node 和 Hub 各自用身份密钥证明身份（细节见 [protocol.md](protocol.md)）。这样即使 TLS 由 Edge 终止，Edge 也无法读取或篡改 node 与 Hub 之间的消息；
- Hub 公钥在入网时固定；Hub 身份密钥更换时，新公钥通过以旧密钥建立的已认证通道下发，节点确认后切换；
- 吊销节点：Hub 拒绝该节点的连接，并从组网拓扑中移除其公钥。

## 9. CI 认证

- 使用 OIDC：Hub 验证 CI 平台签发的短期 JWT（如 GitHub Actions），通过 JWKS 获取公钥并缓存；
- 用户配置信任规则：签发者、受众、仓库、分支或环境 → 映射到权限范围（例如某仓库 `main` 分支 → `stacks:deploy:web` + `changes:propose`）；
- 不保存任何长期密钥；活动记录包含仓库和运行编号。

## 10. 设备凭据

- 每份凭据是一个 WireGuard 密钥对；**私钥优先在浏览器中生成**（WebCrypto X25519），Hub 只保存公钥；浏览器不支持时由 Hub 生成，只显示一次，不保存；
- 新增设备是高风险操作，需要签名；
- 导出配置记录到活动事件；吊销后立即从移动网关和直连入口移除。

## 11. 签名格式

### 11.1 签名载荷

签名的对象是一份规范化的 JSON（RFC 8785），称为**签名载荷**：

```json
{
  "v": 1,
  "kind": "change_approval",
  "change_id": "chg_…",
  "plan_hash": "sha256:…",
  "artifacts": [
    {
      "kind": "node_policy",
      "node_id": "node_…",
      "policy_version": 5,
      "modules": ["metrics", "mesh", "deploy"]
    }
  ],
  "expires_at": "…"
}
```

`kind` 的取值：`change_approval`（变更批准）、`enrollment_policy`（入网 token 的初始策略）、`trust_update`（信任锚更新）。

### 11.2 与 WebAuthn 的结合

- 浏览器以 `challenge = SHA-256(签名载荷)` 发起 WebAuthn 认证；
- 得到的认证结果（`authenticatorData`、`clientDataJSON`、`signature`）与签名载荷一起保存和下发；
- 验证方（Hub 和节点）检查：
  1. `clientDataJSON.type` 为 `webauthn.get`；
  2. `clientDataJSON.challenge` 等于签名载荷的哈希；
  3. `origin` 与信任锚清单中记录的控制台地址一致；
  4. `authenticatorData` 中的 RP ID 哈希一致，且用户在场（UP）、用户验证（UV）标志均已设置；
  5. 签名能用信任锚中的某个公钥验证；
  6. 载荷未过期；对节点策略，`policy_version` 大于当前版本。
- 允许的算法：ES256、EdDSA；
- 同步型 passkey 的签名计数器不可靠，不作为校验条件。

### 11.3 恢复密钥签名

恢复密钥直接对签名载荷的哈希做 ECDSA P-256 签名，不经过 WebAuthn。节点按相同的载荷格式验证。

## 12. 信任锚

### 12.1 信任锚清单

```json
{
  "v": 1,
  "version": 3,
  "rp_id": "hub.example.com",
  "origin": "https://hub.example.com",
  "passkeys": [ { "id": "pk_…", "alg": "ES256", "public_key": "…" } ],
  "recovery_key": { "alg": "ES256", "public_key": "…" }
}
```

### 12.2 更新

- 新增或删除 passkey、更换恢复密钥，都是信任锚更新：生成新版本的清单，以 `trust_update` 签名载荷，由**当前清单中**的某个 passkey 或恢复密钥签名；
- 节点只接受版本更高、且由当前信任锚签名的更新；
- 不允许删除最后一个 passkey；
- 控制台地址（`origin`）变化也是信任锚更新；由于 passkey 绑定域名，迁移到新域名后需要重新注册 passkey，因此该更新由恢复密钥签名，新 passkey 在新地址注册后再加入信任锚。

## 13. 防护措施

| 项 | 措施 |
|---|---|
| 暴力尝试 | 登录、入网、心跳、token 认证接口按来源限流；连续失败后临时锁定 |
| 密钥存储 | Hub 身份密钥、恢复密钥公钥、通知渠道凭据等存放在 Hub 数据目录，文件权限 `0600`；通知渠道凭据用 Hub 主密钥加密后存入数据库 |
| 内存中的密钥 | 使用 `zeroize`；不写入日志和错误信息 |
| token 泄露 | 固定前缀便于扫描；`last_used_at` 和来源可在控制台查看；一键吊销 |
| 时间 | 过期判断依赖时钟；节点与 Hub 时间偏差超过阈值时告警 |

## 14. 分阶段实现

| 能力 | M1 | 后续 |
|---|---|---|
| 初始化、passkey 登录、会话、二次验证 | ✅ | — |
| 恢复密钥 | ✅ | — |
| API token（`script`）与权限范围 | ✅ | `ai` 类型：M4 |
| node 入网、Noise 双向认证 | ✅ | Hub 身份密钥更换：M3 |
| 签名载荷：`change_approval`、`enrollment_policy`、`trust_update` | ✅ | — |
| 信任锚清单的分发与更新 | ✅ | — |
| CI（OIDC） | — | M3 |
| 设备凭据 | — | M2 |

## 15. 待定问题

| 问题 | 说明 |
|---|---|
| Hub 主密钥的保护 | 文件权限之外，是否支持从环境或外部密钥服务读取 |
