# 0010. nett 不含 AI 逻辑，AI 只经 Hub API 使用 nett

- 状态：已采纳
- 日期：2026-10-12

## 背景

nett 只做组网（ADR 0019），但 AI agent 可能需要使用 nett，例如查询节点和链路状态、提议组网变更。AI 的输出不可完全信任：它可能出错，也可能受到提示词注入的影响。

## 决定

- nett 不含 AI 逻辑：Hub、nett-node 和其他组件中都不运行 AI；
- AI 和其他外部程序一样，只经 Hub API（`script` 类型的 API token）使用 nett。

## 理由

- AI 和其他外部程序使用同一个 API、同一套权限，安全机制只需要建设一次；
- nett 的各组件保持小巧、行为确定，便于验证资源占用和安全性。

## 放弃的方案

- **在 nett 中实现 MCP 适配层和运维 Agent**：属于 AI 运维，不在 nett 的范围内（ADR 0019）。
- **允许 AI 执行命令**：能力强，但无法约束和审计。

## 影响

- API 设计必须覆盖界面的全部能力，并且对每个操作标注风险等级；
- API token 只有 `script` 一种类型，AI 使用的 token 与其他脚本相同（design/auth.md 第 6.2 节）。
