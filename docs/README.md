# 文档

| 文档 | 内容 |
|---|---|
| [vision.md](vision.md) | 要解决的问题、目标、设计约束、需求优先级、不做什么 |
| [architecture.md](architecture.md) | 整体架构、角色边界、node 模块、认证、组网、手机接入、入口路由、AI 接入、技术栈、代码组织 |
| [roadmap.md](roadmap.md) | 各阶段内容与验收标准 |
| [adr/](adr/README.md) | 架构决策记录：每个关键决定的背景、理由和放弃的方案 |
| [design/](design/README.md) | 各阶段的详细设计文档；[overview.md](design/overview.md) 把全部文档串成整体技术方案 |
| [development.md](development.md) | 开发指南：工作流程、Rust / Web 规范、安全规范、资源纪律、API 与协议约定、测试、提交 |

**维护约定**

- 架构层面的决定变化时，新增一份 ADR，再同步 `architecture.md` 和 `roadmap.md`；
- 每个阶段开工前，先在 `design/` 写好设计文档；实现与文档不一致时，先改文档；
- 仓库中不放调研过程材料和具体部署环境的信息。
