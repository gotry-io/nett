# 变更记录 · Changelog

用户可见的变化，按版本记录；版本号遵循语义化版本（design/release.md 第 2 节）。
User-visible changes by version; versions follow Semantic Versioning.

## [0.1.0] - 2026-11-09

第一个发布版本：接入 Hub 之前，用本地签名部署组网（design/local-signing.md）。
First release: deploy a mesh with local signing before the Hub is ready.

- 组网进程 `nett mesh`：成员凭签名准入，直连、打洞与经中继的路径之间自动选路和切换；Linux 使用内核
  WireGuard，macOS 以原生成员加入（用户态 WireGuard 与 utun），Mac 上的容器服务可用容器内成员。
  The mesh process: signed membership, automatic path selection and failover across direct, hole-punched
  and relayed paths; kernel WireGuard on Linux, a native member on macOS (userspace WireGuard and utun),
  and container members for container services on a Mac.
- 访问控制默认拒绝，按签名的规则放行；Edge 专用地址让回源的服务认出真实访客（ADR 0015、0023）。
  Access is denied by default and opened by signed rules; the Edge address lets origin services see real
  client addresses.
- 签名工具 `nett site`：在自己的电脑上生成恢复密钥、签名节点与规则，为每个节点生成期望状态文件。
  The signing tool `nett site`: keeps the recovery key on your own computer, signs nodes and rules, and
  writes each node's desired state.
- macOS：`brew install gotry-io/tap/nett`，`sudo nett mesh install` 安装组网服务。
  macOS: `brew install gotry-io/tap/nett`, then `sudo nett mesh install` installs the mesh service.
