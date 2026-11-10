# 0005. Web 控制台为 React SPA，内嵌进 Hub 二进制

- 状态：已采纳；Web 控制台推迟，见 0024
- 日期：2026-10-12

## 背景

Web 是首要的交互入口。控制台是单用户的组网控制台，数据密集（表格、拓扑图、表单、审批流程），只调用对外 API。

## 决定

- React + Vite 构建纯静态 SPA，不使用服务端渲染；
- TanStack Router / Query / Table、shadcn/ui + Tailwind、xyflow（拓扑图）；
- API 客户端由 OpenAPI 生成（openapi-typescript + openapi-fetch）；
- 构建产物在构建时预压缩，用 rust-embed 嵌入 Hub 二进制。

## 理由

- React 生态最大，数据密集型控制台所需的组件都有成熟实现，生成和维护代码最可靠；
- 纯 SPA 只调用对外 API，本身就在持续检验 API 是否完备；
- 前端运行在浏览器中，对 Hub 的影响只是二进制增加约 1 MB；静态资源带内容哈希、永久缓存，运行时几乎不消耗 CPU 和内存；
- 部署仍然只有一个文件。

## 放弃的方案

- **Svelte / SvelteKit**：体积更小，但组件生态较小。
- **HTMX + 服务端模板**：页面接口与 JSON API 需要各写一套，与 API 优先冲突；WebAuthn 交互不便。
- **Rust 编译到 WASM（Leptos、Dioxus）**：全栈一种语言，但生态不成熟，WASM 体积大，迭代慢。

## 影响

- 仓库中包含一个 Node.js 构建环境（仅构建时需要）。
