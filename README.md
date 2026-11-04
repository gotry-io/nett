# nett

中文 · [English](README.en.md)

> 一个开源、自托管的基础设施，把你的机器和 AI agent 连成一张网：AI 能看懂它、安全地运维它，你的 agent 们也能通过它可信地相互访问。

面向拥有少量分散机器的个人或小团队：几台不同地域的 VPS，加上家里的 NAS 或主机。一个 Hub 加上每台机器上的 `nett-node`，覆盖组网、监控告警、部署和入口路由，资源占用极低，并为 AI 运维和 agent 之间的互相访问提供安全的基础。组网会在局域网、公网、跨境等多种路径之间自动选择最优路径，路径变差或节点离线时自动切换。

- GoTry 旗下项目 · 主页 `nett.gotry.io`（建设中）
- 命令行：`nett`
- 服务：`nett-hub`、`nett-node`、`nett-mesh`、`nett-transport`、`nett-relay`
- 状态：**设计阶段**，尚无可用代码
- 许可证：MIT 或 Apache-2.0（双许可）

## 文档

- [愿景](docs/vision.md)：要解决的问题、目标与约束
- [架构](docs/architecture.md)：角色边界、模块、认证、组网、技术栈
- [路线图](docs/roadmap.md)：各阶段内容与验收标准
- [架构决策记录](docs/adr/README.md)
- [设计文档](docs/design/README.md)
- [开发指南](docs/development.md)
