# 架构

本文描述整体架构和长期稳定的设计原则。各阶段的详细设计见 [design/](design/README.md)，关键决策的理由见 [adr/](adr/README.md)。

## 1. 总览

```
┌──────────────────────────── 浏览器 ─────────────────────────────┐
│ Web 控制台：React SPA，WebAuthn（passkey 登录与签名）             │
└───────────────┬────────────────────────────────────────────────┘
                │ HTTPS：REST/JSON + SSE
┌───────────────▼──────────── Hub 主机（同时是入口节点）────────────┐
│ Edge：反向代理（TLS 终止）                                        │
│   ▲ 本机 node 的 ingress 模块推送配置                              │
│ nett-hub：对外 API · 认证 · 期望状态 · 变更集 · 告警 · 审计          │
│           SQLite · node 网关 · 内嵌 Web 前端                          │
│ 组网控制面、中继、移动网关（由 Hub 管理）                            │
│ nett-node                                                       │
└───────────────┬────────────────────────────────────────────────┘
                │ WebSocket over TLS + Protobuf（node 主动连接）
        ┌───────┼────────────┬────────────┐
     VPS 节点   VPS 节点     家里的主机     NAS
     nett-node：metrics · deploy · mesh · ingress（按节点启用）

外部：CI ─OIDC─► Hub　　手机 ─标准 WireGuard─► 移动网关
```

## 2. 角色与能力边界

| 角色 | 负责 | 不负责 | 权限 | 监听公网 |
|---|---|---|---|---|
| **Hub** | 保存期望状态；汇总状态和指标；告警；对外 API；转发签过名的策略 | 直接操作机器；自行提升任何节点的权限 | 普通 | 经 Edge 暴露 |
| **nett-node** | 在本机执行：组网、采集、部署、生成 Edge 配置；上报状态 | 监听端口；处理业务流量；执行任意命令；运行 AI 逻辑；自行决策 | 高 | 否 |
| **Edge** | TLS 终止；按域名把请求转发到组网内的服务 | 任何管理功能 | 低 | 是 |
| **用户的 passkey** | 签名批准提升权限的变更 | — | 持有签名私钥 | — |

**三条原则**

1. **管理和流量分离**：Hub 和 node 都停止时，网站和组网照常工作，只是暂时无法变更和观测。
2. **有权限的不对外，对外的没权限**：node 永远不监听公网端口；所有公网监听都交给独立的低权限进程（Edge，以后的私有传输、MCP 网关）。
3. **决定和执行分离，提升权限必须签名**：Hub 被攻破也无法越权。

## 3. nett-node

单进程，tokio 单线程运行时，由以下部分组成：

- **Transport**：主动连接 Hub，认证，断线重连，多端点选优；
- **Supervisor**：计算模块是否生效，管理模块生命周期，崩溃后带退避地重启；
- **四个模块**：每个都是调和器（期望状态 → 实际状态 → 差异 → 执行），可重复执行，相互隔离；
- **State Store**：本地保存身份密钥、上一次生效的配置和部署版本。**启动时先应用本地缓存，再连接 Hub**，避免组网和 Hub 相互依赖。

| 模块 | 负责 | 典型启用位置 |
|---|---|---|
| **metrics** | 主机和容器指标；平台特有指标（如 NAS 的 RAID、SMART、卷使用率） | 所有节点 |
| **deploy** | 按 stack 定义拉镜像、启动、回滚，执行部署钩子；上报服务与端口 | 运行容器的节点 |
| **mesh** | 建立和维护组网；上报链路状态 | 需要直接加入组网的节点 |
| **ingress** | 把 Hub 的路由翻译成 Edge 配置并推送；检查回源健康和证书 | 入口节点 |

### 模块开关

**生效 = 本地未禁止 ∩ 节点能力 ∩ 签名策略**

| 层 | 由谁决定 | 作用 |
|---|---|---|
| 本地硬性禁止 | 节点管理员 | 可选的绝对上限，签名策略也无法突破 |
| 节点能力 | node 自动探测 | 缺少内核模块、Docker、root 权限等时，对应模块不可用 |
| 签名策略 | Hub 下发 | 降低权限可直接下发；**提升权限必须带用户签名**；版本号只增不减 |

### 零配置

节点本地只保存**身份和权限**，其余来自 Hub 下发或本地探测：Hub 端点列表（入网时只需一个公网地址，其余由 Hub 推送，node 并发探测并选择最优）、网络类型（`public` / `dial-only`）、组网地址、Docker socket 位置、平台特有采集项等。组网私钥在本机生成，永不离开节点。

```bash
curl -fsSL https://hub.example.com/install.sh | sh -s -- enroll <token>
```

## 4. Hub

- **对外 API**：REST + JSON，资源化；从代码生成 OpenAPI 3.1；Web、脚本、以后的 MCP 和移动端都使用同一套 API；
- **实时数据**：SSE；
- **node 网关**：WebSocket + Protobuf；
- **存储**：SQLite（WAL）；指标分层降采样，最多保留 30 天；
- **告警**：阈值、OOM 与重启、节点离线、心跳缺失、趋势预测。

**资源保护**：所有队列、缓存和通道设置上限；查询图表时服务端降采样（每条曲线约 1000 个点）；限制 SSE 连接数；数据和审计有保留策略；上线前做 24 小时浸泡测试。前端运行在浏览器中，对 Hub 只增加约 1 MB 二进制体积。

## 5. 认证与授权

| 身份 | 认证方式 |
|---|---|
| 用户 | passkey（WebAuthn）+ 恢复码；短期会话 Cookie |
| API token | 带权限范围、有过期时间、可吊销；固定前缀；服务端只存哈希 |
| node | 一次性入网 token → Ed25519 双向挑战认证 |
| CI | OIDC（如 GitHub Actions），不保存长期密钥 |
| 手机设备 | 设备凭据（WireGuard 密钥） |

```
请求 → 识别身份 → 检查权限范围 → 检查策略 → 执行 → 写入审计
```

**token 只能提议高风险变更，不能批准。**批准由用户用 passkey 签名：把变更内容的哈希作为 WebAuthn 挑战，浏览器里即可完成。

## 6. 组网

组网后端是可替换的，上层只看到 nett 自己的概念（节点、地址、主机名、访问规则、链路状态）：

```rust
trait MeshBackend {
    fn status(&self) -> MeshStatus;
    fn apply(&self, desired: &MeshConfig);
}
```

| 后端 | 定位 |
|---|---|
| **tailscale**（Headscale + derper + tailscaled，由 Hub 管理） | 首个后端：自带 NAT 穿透和 TCP 兜底，在网络情况未知时最稳妥；同时用来测量每条链路是直连还是中继 |
| **内核 WireGuard** | 目标后端：内存约为零、性能最好；按测量数据逐个节点切换 |

拓扑规则：一条链路只要有一端是 `public`，就由 `dial-only` 一端主动连接；两个 `dial-only` 节点之间经 `public` 节点中转。家里的网段可以由一台主机（subnet router）或网关代为接入，其他主机无需安装任何组网软件。

**私有传输**（后期）：基于 QUIC（UDP 443）和 TLS（TCP 443），按连接转发，用于 UDP 受限的链路。它是抗干扰手段，不是默认选择：网络正常时 WireGuard 更快、更省电，也更安全。

## 7. 手机接入

```
手机 ──标准 WireGuard──► 移动网关（内核 WG）──► 组网（后端对手机不可见）
```

- 手机只和移动网关建立普通 WireGuard 连接，组网后端切换时手机无需改动；
- 一台设备可以有多份凭据（第三方客户端一份、自建 App 一份），各自独立吊销；
- 支持任何具备 WireGuard 能力的客户端，包括带 WireGuard 出站的代理工具（不额外占用系统 VPN 名额）；
- 以后的自建 App：WireGuard 为默认，UDP 受限时自动切换到私有传输。

## 8. 入口路由

```
Hub 路由（域名 → 服务 → 节点:端口）→ ingress 模块 → Edge 配置
```

Hub 只保存与实现无关的路由模型；Edge 可以从 Caddy 换成其他反向代理，只需新增一个翻译后端。

## 9. AI 接入

| 阶段 | 内容 |
|---|---|
| 现在 | 把基础打好：资源模型、API 优先、变更集（plan → approve → apply → verify）、动作目录（带风险等级）、身份模型、审计事件 |
| 以后 | MCP 适配层；运维 Agent（告警 → 诊断 → 提案 → 审批 → 执行 → 验证，作为 Hub 侧的独立服务）；agent 通信（工作负载身份、MCP 网关） |

AI 不能执行 shell；它的输出只是提案，必须经过策略引擎和签名。

## 10. 技术栈

| 部分 | 选择 |
|---|---|
| Hub | Rust：axum、SQLite + sqlx、utoipa、webauthn-rs、rustls、rust-embed |
| node | Rust：tokio（单线程）、tokio-tungstenite、prost、sysinfo、hyper |
| 协议 | 对外 REST + JSON + SSE（OpenAPI 3.1）；内部 WebSocket + Protobuf |
| Web | React + Vite、TanStack Router / Query / Table、shadcn/ui + Tailwind、uPlot、xyflow |
| Edge | Caddy（首期） |

## 11. 代码组织

```
nett/
├── proto/              # node ↔ Hub 的 Protobuf 定义
├── crates/
│   ├── nett-proto/
│   ├── nett-core/      # 共享领域模型
│   ├── nett-hub/
│   ├── nett-node/
│   └── nett-cli/       # nett 命令
├── web/                # React SPA；src/api 由 OpenAPI 生成
└── docs/
```

生成链路：`proto → prost → Rust`；`Hub 代码 → utoipa → openapi.json → TypeScript 客户端`。CI 检查生成文件是否最新。
