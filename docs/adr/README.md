# 架构决策记录（ADR）

每个对架构有长期影响的决定记录一份：背景、决定、理由、放弃的方案、影响。

**修改规则**：项目首次公开发布之前，ADR 可以直接修订；发布之后，已采纳的 ADR 不再修改，决定改变时新增一份 ADR，并把旧的标记为"已被取代"。

| 编号 | 决定 | 状态 |
|---|---|---|
| [0001](0001-hub-node-edge-roles.md) | Hub / node / 公网进程分离，管理与流量分离 | 已采纳 |
| [0002](0002-rust-for-hub-and-node.md) | Hub 和 node 使用 Rust | 已采纳 |
| [0003](0003-api-and-protocols.md) | 对外 REST + OpenAPI，内部 WebSocket + Protobuf | 已采纳 |
| [0004](0004-sqlite-storage.md) | Hub 使用 SQLite 存储 | 已采纳 |
| [0005](0005-react-spa-embedded.md) | Web 控制台为 React SPA，内嵌进 Hub 二进制 | 已采纳；推迟，见 0024 |
| [0006](0006-auth-and-passkey-signing.md) | 身份模型与 passkey 签名授权 | 已采纳；passkey 推迟，见 0024 |
| [0007](0007-own-mesh-wireguard-session-path-layer.md) | 自研组网：WireGuard 会话层 + nett 路径层 | 已采纳 |
| [0008](0008-mobile-dual-path.md) | 手机以标准 WireGuard 双路径接入 | 已采纳；配对见 0024 |
| [0009](0009-caddy-as-first-edge.md) | Hub 前的反向代理默认使用 Caddy | 已采纳 |
| [0010](0010-ai-via-api-only.md) | AI 只经由 Hub API 接入，node 不含 AI 逻辑 | 已采纳 |
| [0011](0011-nett-relay.md) | nett-relay：独立的低权限中继与传输入口 | 已采纳 |
| [0012](0012-single-binary-packaging.md) | 节点侧单一可执行文件，按子命令运行为多个进程 | 已采纳；安装脚本见 0024 |
| [0013](0013-mesh-and-transport-processes.md) | 组网进程与传输适配进程 | 已采纳 |
| [0014](0014-signed-mesh-membership.md) | 组网成员表由签名产物构成 | 已采纳 |
| [0015](0015-origin-identity-and-lan-default-deny.md) | 回源身份与局域网段默认拒绝 | 已采纳 |
| [0016](0016-macos-container-member.md) | macOS 上的容器内成员 | 已采纳 |
| [0017](0017-home-assistant-os-addon.md) | Home Assistant OS 上以加载项运行 | 已采纳 |
| [0018](0018-client-platforms.md) | 终端设备：macOS 原生成员、代理客户端配置与客户端规划 | 已采纳 |
| [0019](0019-mesh-only.md) | nett 只做组网 | 已采纳 |
| [0020](0020-release-signing.md) | 发布签名：主备两把钥匙，公钥是构建参数 | 已采纳 |
| [0021](0021-tailscale-parity.md) | 组网体验以 Tailscale 为基线 | 已采纳 |
| [0022](0022-local-signing-before-hub.md) | 接入 Hub 之前，用本地签名部署替换已有的隧道 | 已采纳 |
| [0023](0023-access-default-deny.md) | 访问默认拒绝 | 已采纳 |
| [0024](0024-cli-first-headless-hub.md) | 命令行是操作界面，Hub 先不带控制台 | 已采纳 |

模板：

```markdown
# 编号. 标题

- 状态：草案 / 已采纳 / 已被 XXXX 取代
- 日期：YYYY-MM-DD

## 背景
## 决定
## 理由
## 放弃的方案
## 影响
```
