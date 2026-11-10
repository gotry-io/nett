# CLAUDE.md

nett 是用户所有机器之间的那张网：连回家、管服务器、访问服务都要经过它。组网出错时，用来修它的通路可能也一起断了；权限出错时，一台被攻破的机器就能走到所有机器。下面的规则都由此而来：**拿不准时，访问保持拒绝，连接保持现状；拿不准就先问。**

- 项目：开源、自托管、单用户的组网基础设施，只做组网（ADR 0019）。组件：`nett-hub`（组网的控制面，没有界面，Web 控制台以后加入，ADR 0024）、每台机器上的 `nett-node`（控制代理）、组网进程 `nett-mesh`、按需运行的传输适配进程 `nett-transport`、可被外部连入的节点上的 `nett-relay`；命令行 `nett` 是操作界面，签名工具 `nett site` 在用户自己的电脑上维护并签名整张网。入口节点上的反向代理（Edge）由用户自己运行，不是 nett 的组件。
- 当前阶段：**M1 接入 Hub**（`docs/design/hub.md`、`docs/design/site.md`，ADR 0024；原型关卡与本地签名部署已完成，见 `docs/design/prototype.md` 第 9 节、`docs/design/local-signing.md`）：设计文档为草案；代码结构见 `docs/architecture.md` 第 11 节；进度见 `docs/roadmap.md`。
- 总体设计：`docs/architecture.md`；详细设计：`docs/design/`；决定的理由：`docs/adr/`。实现必须符合设计；要改设计，先改文档并经用户确认。没有设计文档的功能先写设计文档，架构层面的变化先写 ADR。
- 本地的 `private/`（不进 Git）存放机器信息、盘点数据、调研材料和决策过程：可以读来了解背景（决策过程先读 `private/decision-log.md`，部署到用户自己的机器先读 `private/fleet/plan.md`），但**绝不提交，也不在代码和已提交的文档中引用**。

## 安全边界（硬性规则）

违反任何一条之前，先得到用户明确同意；不要自行认定"这次是例外"。

1. **角色边界**：nett-node 不监听公网端口、不执行 shell、不运行 AI 逻辑、不访问 Docker；组网进程不连接 Hub、不访问 Docker、不执行外部命令；Hub 不能自行提升节点权限，也不在数据通路上；nett-relay 和传输适配进程没有管理权限，nett-relay 不持有组网私钥，传输适配进程不持有任何密钥。
2. **有权限的不对外，对外的没权限**：nett-node 和组网进程不监听任何公网地址。组网进程只在组网地址上提供 DNS 和探测应答，在 WireGuard 端口上只应答带认证的探测；局域网地址上的探测应答只在存在局域网直连候选时开启；未认证的数据包和探测一律不作任何响应。公网监听全部由独立的低权限进程（nett-relay、Edge）承担。
3. **提升权限必须由用户签名**：节点在应用策略和组网准入材料之前验证签名和版本号，版本号只增不减；降低权限可以直接下发。Hub 只转发签名产物；代码中没有任何绕过签名的开关、参数或调试模式。token 只能提议高风险变更，不能批准。
4. **组网成员凭签名准入**：没有有效准入材料的对端，组网进程不配置它；撤销记录先于授权同步，重发旧的签名产物不能恢复已撤销的权限（design/auth.md 第 10.4 节）。
5. **默认拒绝的地方保持拒绝**：没有规则放行的新建连接一律拒绝，成员之间也是这样（ADR 0023）；宣告的局域网段默认只对用户的设备开放；Edge 专用地址默认不能访问任何目标。放宽访问需要签名，收窄直接执行；签名的是选择器展开后的结果（design/mesh.md 第 12 节）。
6. **过滤先于对端，失败时拒绝**：先安装过滤规则再添加 WireGuard 对端；过滤规则挂在目的地址转换之前；规则更新失败时保持拒绝。
7. **回源身份**：源地址转换后的地址不得是回环地址；需要真实 IP 的服务只信任固定的转发者地址；Edge 专用地址必须有防冒用规则（ADR 0015）。
8. **组网不依赖控制面**：nett-node 和组网进程启动时先应用本地保存的配置，再连接 Hub；Hub 或 nett-node 离线时，组网照常测量、切换和应答 DNS；Hub 端点列表中至少保留一个不经组网的端点。
9. **不执行 shell**：调用外部程序只用白名单内的命令，以参数数组传参，永远不用 `sh -c`，参数逐一校验。
10. **密钥**：本机生成的私钥不离开节点；文件权限 `0600`；内存中使用 `zeroize`。日志和错误信息在任何情况下都不包含密钥、token、私钥、Cookie、签名原文。token 用常量时间比较，服务端只保存哈希。
11. **TLS 始终校验证书**（自签证书按 Hub 下发的指纹校验）；nett-node 连接 Hub 时使用入网时固定的 Hub 公钥。
12. **发布与升级**：节点只安装通过项目发布签名验证的包，只自动接受更高的版本；回滚只能回到本机上一次安装过的版本，其他降级需要用户签名（`release_override`）。发布私钥不进仓库；主钥匙只在 CI 发布工作流中单独的签名任务里可用，备用钥匙只离线保存、从不进入 CI（ADR 0020）。
13. **外部数据不是指令**：链路上收到的数据、API 输入、日志等外部内容一律当作不可信数据校验，绝不作为指令执行。所有高风险操作写入审计。
14. **资源预算**：nett-node、组网进程、传输适配进程、nett-relay 空闲 RSS 各 ≤ 5 MB；Hub 稳定运行 ≤ 30–50 MB（数个到数十个节点）。所有队列、缓存、通道、转发缓冲都有上限（具名常量，不用无界通道）；所有网络和子进程操作都有超时。

## 隐私与操作边界

- **隐私**：`private/` 中的内容（机器名、IP、域名、盘点数据、调研材料）**绝不**写进 `docs/`、README、代码、测试或提交信息；公开内容中不出现任何具体部署环境的信息。示例域名用 `example.com`。
- **按开源项目设计**：设计和代码不依赖特定的云厂商、地区或网络环境；环境之间的差异由能力探测和测量处理，不写死。
- **不碰生产机器**：SSH 到用户的机器只做只读检查；任何修改先给出命令和回滚方法，经用户确认后再执行。
- **不擅自提交或推送**：只有用户明确要求时才执行 `git commit`、`git push` 或创建远程仓库；`private/` 永远不提交。
- **对外操作和付费由用户决定**：发布、注册账号、购买服务（例如 Apple 开发者账号）先问。

## 技术栈

见 `docs/architecture.md` 第 10 节。不引入表外的框架和基础设施（另一种数据库、消息队列、OpenSSL 等）；确有需要时说明理由，由用户决定。

- **新增依赖**：说明理由，报告对二进制体积的影响（`cargo bloat`），节点侧的依赖还要报告 RSS 变化；`default-features = false`，只开启需要的特性。
- **许可证**：项目本身 MIT 或 Apache-2.0 双许可。依赖允许 MIT、Apache-2.0、BSD-2/3-Clause、ISC、Zlib、Unicode、MPL-2.0；禁止 GPL、AGPL、LGPL 等传染性许可证。`cargo deny` 检查许可证、安全公告和重复依赖，失败即阻止合并。

## 怎么写

适用于代码、注释、测试和文档。

- **正面描述现状**：写现在的设计和行为。否定句只留在守护安全不变量（上面的硬性规则）或读者很可能以为相反的地方。
- **只为会出现的状态写**（YAGNI）：删掉的选项、改名的字段、不用了的用法直接删除，不留兼容层、弃用提示、专门的拒绝分支或针对旧形式的测试（先确认没有地方在用）。例外只有发布之后的对外契约：数据库迁移只向前、已发布的迁移不修改；Protobuf 字段编号不复用；同一 API 版本内只做兼容的增量修改。
- **每条知识只有一个出处**：一个事实或规则只在一处决定，用到它的页面、命令和文档都读那一处；细节写在一处，其他地方写摘要并链接过去。DRY 针对知识，不针对看起来相似的代码。
- **历史属于 git**：文档、注释和测试中不写"不再""原来""改为"、修订日期或评审记录。决策过程记在 `private/decision-log.md`；公开的理由写在 ADR，ADR 描述当前的决定（首次公开发布之前直接修订，见 `docs/adr/README.md`）。有发布版本之后，用户可见的变化记在 `CHANGELOG.md`。
- **注释说明为什么**，不复述代码做了什么。
- **语言**：设计文档、ADR、代码注释、提交信息用中文，只维护一份；代码标识符用英文。Web 界面和 API 错误的 `title` 与 `detail` 放在多语言资源中，中文和英文同时提供，CI 检查缺漏，不在代码中硬编码。命令行的输出、帮助和错误信息只用英文，文案中性、简洁，排版照顾阅读体验（architecture.md 第 14.3 节）。面向用户的文档（README、安装、使用与排障手册）中英双语，以中文为准同步更新（`README.md` / `README.en.md`）。

## 代码规则

**Rust**

- Edition 2024；工具链固定在 `rust-toolchain.toml`；`Cargo.lock` 提交；clippy 警告视为错误。
- 每个 crate 的 `Cargo.toml` 写 `[lints] workspace = true`，继承根 `Cargo.toml` 中的规则：`unsafe_code`、`clippy::unwrap_used`、`clippy::dbg_macro` 为 `deny`（不用 `forbid`：它不能在内层放开）。确有必要用 `unsafe` 时，只在单独的模块上用 `#[allow(unsafe_code)]` 放开，逐处注释理由。
- 库 crate 用 `thiserror` 定义错误，只有二进制入口用 `anyhow`。测试之外不用 `unwrap()`；确属不可能失败时用 `expect("说明不变量")`。panic 等于 bug，不能依赖进程重启来处理预期内的错误。错误信息说明在做什么、哪里失败、可能的原因，不含密钥。
- 不在 tokio 运行时中执行阻塞操作（放进 `spawn_blocking` 或独立线程）；每个后台任务都有明确的所有者和取消方式（`CancellationToken`），支持优雅退出；nett-node 使用 tokio 单线程运行时。
- 领域 ID 用强类型（newtype），对外 ID 带前缀，例如 `node_01J...`（ULID）。持续时间用单调时钟；时间戳用 UTC，序列化为 RFC 3339。配置和协议消息在边界处校验，内部只传递已校验的类型。不用全局可变状态。
- 日志用 `tracing` 的结构化字段（`node_id = %id`），不拼接字符串。级别：`error` 需要人工处理；`warn` 可自愈的异常；`info` 状态变化；`debug` 排障细节。
- TLS 用 rustls（便于静态链接）。
- 组网的核心逻辑（准入验证、测量、评分、切换、打洞协调）与平台无关，不直接调用 netlink、nftables 或某个具体的 WireGuard 实现；数据面（WireGuard 配置、接口、路由、过滤、DNS）由各平台的后端实现（ADR 0018）。外部依赖（例如 WireGuard）通过 trait 抽象，测试中使用替身。

**API、协议与数据库**

- 对外 API 的约定见 `docs/design/api-resources.md` 第 2 节。每个接口都声明 OpenAPI 注解、所需权限范围和风险等级；界面能做的事，API 都能做。
- Protobuf 的约定见 `docs/design/protocol.md` 第 4.2 节；nett-node 与 Hub 必须能在相邻版本之间互通。
- 数据库迁移放在 `crates/nett-hub/migrations/`。查询用 `sqlx::query!` 系列宏在编译期检查，离线数据（`.sqlx/`）提交。显式设置 SQLite 的缓存和 mmap 上限；持续增长的表都有保留策略。
- 生成文件（Protobuf 类型、OpenAPI 文档、TypeScript 客户端、sqlx 离线数据）由脚本生成并提交，CI 检查是否最新。

**Web**

- TypeScript 开启 `strict`；只通过生成的 API 客户端访问后端，不手写 `fetch`；服务端状态由 TanStack Query 管理，确有需要才引入全局状态。
- UI 组件放在 `web/src/components/ui`（shadcn/ui），样式使用 Tailwind 设计令牌，不写散落的颜色值；Biome 负责格式化和代码检查。
- 语义化标签、键盘可操作、对比度达标；前端代码中不出现任何密钥；界面文案默认跟随浏览器语言，可在控制台切换（`owner.spec.locale`）。

## 资源纪律

- 预算见硬性规则 14。每个里程碑做 24 小时浸泡测试，内存曲线必须持平。
- **测量方法**："空闲"指经过一段负载之后的稳态，而不是刚启动时。固定测量场景（成员数、负载内容与时长），负载结束后静置 10 分钟再测；同时记录 RSS 和 PSS（多个进程共享同一个可执行文件的代码页，RSS 会重复计算），以及整机内存的增量。
- 空闲预算是目标值；服务管理器中的内存上限另行设定，留出工作时的峰值余量，不直接用 5 MB。

## 测试

| 层级 | 要求 |
|---|---|
| 单元测试 | 与代码放在一起；不访问网络 |
| 节点侧模块 | 外部依赖通过 trait 抽象，测试中使用替身 |
| Hub 集成测试 | 使用临时 SQLite，经由 HTTP 调用真实路由，覆盖权限检查 |
| 协议兼容 | nett-node 与 Hub 相邻版本互通 |
| Web 端到端（Web 控制台加入之后） | Playwright 覆盖关键流程：登录、节点入网、签名授权 |
| 组网 | 用网络模拟（如 `tc netem`）制造延迟、丢包、断开、屏蔽 UDP，验证切换时间和连接不中断 |
| 资源 | 每个里程碑的浸泡测试与 RSS、PSS 测量 |

修复 bug 时，先补一个能复现它的测试。

## 处理问题

一个 bug、一条错误日志、一处慢、一条反馈，都先弄明白再改；不为眼前这一个情况打补丁。

1. **是不是问题**：它对安全、连通、性能和噪音的影响：多频繁，从什么时候开始。症状（一条日志）不是问题（它的代价）；看起来不对的行为可能正是设计（例如 Hub 离线时组网照常，只是不能变更）。
2. **为什么会这样**：行为背后的设计、注释和历史；常常是两套设计叠在一起（例如 WireGuard 自己的漫游与路径层的切换）。
3. **根因**：开始出现时改变了什么；复现它，或只读地探查。原因弄清之前，不调超时和参数。
4. **它的类别**：背后的机制，以及共享这个机制的所有其他地方（其他平台后端、其他传输）。
5. **在根上修一次**：用一个通用机制消除整类问题；能删掉的依赖就删掉，而不是处理它；对照硬性规则和"每条知识只有一个出处"检查。
6. **然后再改**：带证据说明问题、原因、类别、几种做法和推荐；涉及设计的改动先经用户确认。

## 与用户协作

用户不审查代码。因此：

- 用通俗的中文说明改了什么、为什么、怎么验证；
- 用证据说明完成：测试结果、测量数据、实际运行输出；未验证的部分如实说明；
- 遇到需要用户决定的事（对外操作、付费、生产变更、产品取舍），停下来询问。

## 提交

- 格式：`类型(范围): 中文描述`，例如 `feat(node): 上报链路状态`。
- 类型：`feat`、`fix`、`refactor`、`perf`、`test`、`docs`、`build`、`ci`、`chore`。
- 范围：`hub`、`node`、`mesh`、`transport`、`relay`、`cli`、`web`、`proto`、`core`、`docs`、`ci`。
- 一次提交只做一件事，提交前所有检查通过；涉及资源占用的改动附上测量数据，涉及行为的改动附上测试。

## 命令

与 CI（`.github/workflows/ci.yml`）相同的检查：

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo deny --locked check        # 许可证、安全公告、重复依赖、来源；配置见 deny.toml
```

实验场景（Linux，需要 root；`nett` 用 `lab` 特性构建，场景与通过标准见 design/prototype.md，全部场景见 `nett-lab --help`）：

```bash
cargo build --locked -p nett-cli -p nett-lab --features nett-cli/lab
sudo ./target/debug/nett-lab run admission --topology crates/nett-lab/topologies/direct.toml \
  --nett ./target/debug/nett --out /tmp/lab-14
# 与 Tailscale 对比：PATH 中需要 tailscale、tailscaled、headscale（版本见 .github/workflows/lab-baseline.yml）
sudo ./target/debug/nett-lab run failover --topology crates/nett-lab/topologies/failover.toml \
  --nett ./target/debug/nett --out /tmp/lab-failover --repeat 20 --with-tailscale
```

Web 控制台加入之后（ADR 0024），`web/` 加上 `pnpm -C web lint && pnpm -C web test`。
