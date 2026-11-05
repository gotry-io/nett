# 0003. 对外 REST + OpenAPI，内部 WebSocket + Protobuf

- 状态：已采纳
- 日期：2026-10-12

## 背景

Hub 有两类对端：面向用户和工具的客户端（Web、脚本、以后的移动端），以及大量常驻的 node。

## 决定

- **对外 API**：REST + JSON，资源化设计；事件和状态的实时推送用 SSE；从 Hub 的 Rust 代码（utoipa）生成 OpenAPI 3.1，作为唯一来源，客户端由它生成。
- **node ↔ Hub**：node 主动建立 WebSocket over TLS 长连接，消息用 Protobuf（prost）。

## 理由

- REST + OpenAPI 对所有客户端通用，并能生成 TypeScript、Swift 客户端。
- 所有客户端共用同一套 API，界面能做的事 API 都能做；以后另做的观测和管理项目也经 API 对接（ADR 0019）。
- node 主动连接，节点无需开放入站端口；Protobuf 消息紧凑，字段演进安全。
- 内外协议分开，内部协议可以自由演进而不影响公开 API。

## 放弃的方案

- **gRPC / Connect 作为对外 API**：一份定义可以生成多端客户端，但 Rust 服务端对 Connect 的支持还不成熟，浏览器端也需要额外适配。
- **内部协议也用 JSON**：实现简单，但带宽和解析开销更高，缺少显式的模式演进规则。

## 影响

- CI 需要检查生成的 OpenAPI 文档和客户端代码是否最新。
- 需要维护两套协议定义（OpenAPI 与 Protobuf）。
