# 架构决策记录（ADR）

每个对架构有长期影响的决定记录一份：背景、决定、理由、放弃的方案、影响。已采纳的 ADR 不再修改；决定改变时，新增一份 ADR 并把旧的标记为"已被取代"。

| 编号 | 决定 | 状态 |
|---|---|---|
| [0001](0001-hub-node-edge-roles.md) | Hub / node / Edge 三个角色，管理与流量分离 | 已采纳 |
| [0002](0002-rust-for-hub-and-node.md) | Hub 和 node 使用 Rust | 已采纳 |
| [0003](0003-api-and-protocols.md) | 对外 REST + OpenAPI，内部 WebSocket + Protobuf | 已采纳 |
| [0004](0004-sqlite-storage.md) | Hub 使用 SQLite 存储，包括指标 | 已采纳 |
| [0005](0005-react-spa-embedded.md) | Web 控制台为 React SPA，内嵌进 Hub 二进制 | 已采纳 |
| [0006](0006-auth-and-passkey-signing.md) | 身份模型与 passkey 签名授权 | 已采纳 |
| [0007](0007-pluggable-mesh-backend.md) | 可替换的组网后端：先 tailscale，后内核 WireGuard | 已采纳 |
| [0008](0008-mobile-gateway.md) | 手机经移动网关以标准 WireGuard 接入 | 已采纳 |
| [0009](0009-caddy-as-first-edge.md) | 首期 Edge 使用 Caddy，路由模型与实现解耦 | 已采纳 |
| [0010](0010-ai-via-api-only.md) | AI 只经由 Hub API 接入，node 不含 AI 逻辑 | 已采纳 |

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
