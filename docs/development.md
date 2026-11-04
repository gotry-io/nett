# 开发指南

适用于所有贡献者（包括 AI）。约束的优先级：**安全 > 资源占用 > 正确性 > 可维护性 > 开发速度**。

## 1. 工作流程

1. **先设计，后编码**：每个阶段开工前，在 `docs/design/` 写好设计文档；实现与文档不一致时，先改文档。
2. **架构变化写 ADR**：影响角色边界、协议、存储、安全模型、核心依赖的决定，新增一份 `docs/adr/`，再同步 `architecture.md` 和 `roadmap.md`。
3. **小步提交**：一次提交只做一件事，提交前所有检查通过。
4. **用证据说明完成**：涉及资源占用的改动附上测量数据；涉及行为的改动附上测试。
5. **按开源项目设计**：设计和代码不得依赖特定的云厂商、地区或网络环境；环境差异通过能力探测和测量处理，不写死。

## 2. 命令

> P0 骨架完成后补全。约定如下：

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check                 # 许可证、安全公告、重复依赖
pnpm -C web lint && pnpm -C web test
```

生成文件（Protobuf 类型、OpenAPI 文档、TypeScript 客户端、sqlx 离线数据）由脚本生成并提交，CI 检查是否最新。

## 3. Rust

### 基础

- Edition 2024；工具链版本固定在 `rust-toolchain.toml`；`Cargo.lock` 提交。
- 所有 crate 声明 `#![deny(unsafe_code)]`（不用 `forbid`：`forbid` 不能在内层放开）。确有必要时，只在单独的模块上用 `#[allow(unsafe_code)]` 放开，逐处注释理由，并在评审中说明。
- clippy 警告视为错误。

### 错误处理

- 库 crate 用 `thiserror` 定义错误类型；只有二进制入口可以用 `anyhow`。
- 测试之外不使用 `unwrap()`、`expect()`；确属不可能失败的情况，用 `expect("原因")` 并说明不变量。
- panic 等于 bug。node 的模块崩溃由 Supervisor 隔离和重启，但不能依赖这一点来处理预期内的错误。
- 错误信息面向排障：说明"在做什么、哪里失败、可能的原因"，不包含密钥。

### 异步

- 不在 tokio 运行时中执行阻塞操作；阻塞调用放进 `spawn_blocking` 或独立线程。
- **所有网络和子进程操作都有超时。**
- **所有通道、队列、缓存都有上限**，上限用具名常量定义，不使用无界通道。
- 每个后台任务都有明确的所有者和取消方式（`CancellationToken`），支持优雅退出。
- node 使用 tokio 单线程运行时，不随意引入多线程运行时。

### 类型与数据

- 领域 ID 使用强类型（newtype），对外 ID 带前缀，例如 `node_01J...`（ULID）。
- 时间：持续时间用单调时钟；时间戳用 UTC，序列化为 RFC 3339。
- 配置和协议消息在边界处校验，内部只传递已校验的类型。
- 不使用全局可变状态。

### 日志

- 使用 `tracing`，结构化字段（`node_id = %id`），不拼接字符串。
- **任何情况下都不记录密钥、token、私钥、Cookie、签名原文。**
- 日志级别：`error` 需要人工处理；`warn` 可自愈的异常；`info` 状态变化；`debug` 排障细节。

## 4. 资源纪律

| 组件 | 预算 |
|---|---|
| nett-node | 空闲 RSS ≤ 5 MB |
| nett-hub | 稳定运行 ≤ 30–50 MB（数个到数十个节点） |
| nett-relay | 空闲 RSS ≤ 5 MB；转发流量时的内存有上限 |
| 数据面进程 | 空闲 RSS ≤ 5 MB；转发缓冲有上限 |

- 依赖使用 `default-features = false`，只开启需要的特性。
- **新增依赖时说明理由**，并报告对二进制体积的影响（`cargo bloat`）；node 的新依赖还要报告 RSS 变化。
- 优先使用 rustls，不使用 OpenSSL（便于静态链接）。
- 每个里程碑做 24 小时浸泡测试，内存曲线必须持平。
- Hub 查询指标时服务端降采样，单条曲线不超过约 1000 个点。

## 5. 安全规范

这些规则是硬性的，违反即视为 bug：

1. **nett-node 不监听任何公网地址**：只在组网地址上提供 DNS 和探测应答；局域网地址上的探测应答只在存在局域网直连候选时开启，且不响应未认证的探测。所有公网监听由独立的低权限进程（nett-relay、Edge）承担；用户态 WireGuard 在数据面进程中运行；nett-relay 不持有组网私钥。
2. **不执行 shell。**调用外部程序（如 `docker compose`、`tailscale`）只能使用白名单内的命令，以参数数组形式传参，永远不用 `sh -c`，参数逐一校验。
3. **提升权限必须验证用户签名**；node 在应用策略、组网准入材料和部署档位前验证签名和版本号。
4. **密钥**：本机生成的私钥不离开节点；文件权限 `0600`；内存中使用 `zeroize`；不出现在日志和错误信息中。
5. **token** 比较使用常量时间算法；服务端只保存哈希。
6. **TLS 始终校验证书**（自签证书按 Hub 下发的指纹校验）；node 连接 Hub 时使用入网时固定的 Hub 公钥。
7. **所有高风险操作写入审计。**
8. 来自日志、指标等外部数据的内容，一律视为不可信数据，不作为指令处理（AI 场景下尤其重要）。
9. **源地址转换后的地址不得是回环地址**；需要真实 IP 的服务只信任固定的转发者地址（ADR 0015）。

## 6. 依赖与许可证

- **项目本身**：开源，采用 MIT 或 Apache-2.0 双许可（Rust 生态的惯例）。
- 依赖允许：MIT、Apache-2.0、BSD-2/3-Clause、ISC、Zlib、Unicode、MPL-2.0。
- 禁止：GPL、AGPL、LGPL 及其他传染性许可证；由 `cargo deny` 强制检查。
- 安全公告由 `cargo deny check advisories` 检查，CI 中失败即阻止合并。

## 7. 对外 API

- 前缀 `/api/v1`；资源名用复数、短横线连接（`/api/v1/nodes`、`/api/v1/api-tokens`）；JSON 字段用 `snake_case`。
- 错误使用 RFC 9457（`application/problem+json`），带稳定的 `code` 字段。
- 列表使用游标分页。
- 创建类请求支持 `Idempotency-Key`；更新类请求使用 `ETag` / `If-Match` 做乐观锁。
- **每个接口都要声明**：OpenAPI 注解、所需权限范围、风险等级。
- 同一版本内只做兼容的增量修改；不兼容的修改进入新版本。
- 界面能做的事，API 都必须能做。

## 8. Protobuf（node ↔ Hub）

- 包名 `nett.v1`。
- 字段编号永不复用，删除的字段用 `reserved` 保留。
- 枚举的 0 值为 `XXX_UNSPECIFIED`。
- 同一版本内只做增量修改；node 与 Hub 必须能在相邻版本之间互通。

## 9. 数据库

- 迁移放在 `crates/nett-hub/migrations/`，只向前，**已发布的迁移不修改**。
- 查询使用 `sqlx::query!` 系列宏，在编译期检查；离线数据（`.sqlx/`）提交。
- 显式设置 SQLite 的缓存和 mmap 上限；所有持续增长的表都有保留策略。

## 10. Web

- TypeScript 开启 `strict`。
- **只通过生成的 API 客户端访问后端**，不手写 `fetch`。
- 服务端状态由 TanStack Query 管理；只有确实需要时才引入全局状态。
- UI 组件放在 `web/src/components/ui`（shadcn/ui）；样式使用 Tailwind 设计令牌，不写散落的颜色值。
- 关注无障碍：语义化标签、键盘可操作、对比度。
- Biome 负责格式化和代码检查。
- 前端代码中不出现任何密钥。

## 11. 测试

| 层级 | 要求 |
|---|---|
| 单元测试 | 与代码放在一起；不访问网络 |
| node 模块 | 通过 trait 抽象外部依赖（Docker、WireGuard、Edge），测试中使用替身 |
| Hub 集成测试 | 使用临时 SQLite，经由 HTTP 调用真实路由，覆盖权限检查 |
| 协议兼容 | node 与 Hub 相邻版本互通 |
| Web 端到端 | Playwright 覆盖关键流程：登录、节点入网、告警、签名授权 |
| 组网 | 用网络模拟（如 `tc netem`）制造延迟、丢包、断开、屏蔽 UDP，验证切换时间和连接不中断 |
| 资源 | 每个里程碑的浸泡测试与 RSS 测量 |

修复 bug 时先补一个能复现它的测试。

## 12. 文档与注释

- 文档、代码注释、提交信息使用**中文**；代码标识符使用英文。
- 注释说明"为什么"，不复述代码"做了什么"。
- 公开文档（`docs/`、`README.md`）中**不出现任何具体部署环境的信息**：机器名、IP、域名、个人项目名。这些内容放在不进版本库的 `private/`。
- 示例域名使用 `example.com`。

## 13. 提交

- 格式：`类型(范围): 中文描述`，例如 `feat(node): 采集容器内存指标`。
- 类型：`feat`、`fix`、`refactor`、`perf`、`test`、`docs`、`build`、`ci`、`chore`。
- 范围：`hub`、`node`、`relay`、`cli`、`web`、`proto`、`core`、`docs`、`ci`。
- `private/` 永远不提交。
