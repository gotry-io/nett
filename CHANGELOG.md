# 变更记录 · Changelog

用户可见的变化，按版本记录；版本号遵循语义化版本（design/release.md 第 2 节）。
User-visible changes by version; versions follow Semantic Versioning.

## [0.1.2] - 2026-11-10

- 站点描述的节点可以写 `listen_port`，用自己的 WireGuard 端口：同一台主机上的原生成员与容器内成员各用一个。
  A node in the site description can set `listen_port` for its own WireGuard port, so a native member and a
  container member on the same host each get one.
- `nett site` 的站点目录默认是 `~/.config/nett`（按 `$XDG_CONFIG_HOME`），不用再写 `--dir`；`nett site init`
  把目录权限设为 `0700`。
  The `nett site` directory defaults to `~/.config/nett` (following `$XDG_CONFIG_HOME`), so `--dir` is
  optional; `nett site init` makes the directory `0700`.
- `nett site build` 把各节点的期望状态写在站点目录的 `nodes/<节点>/desired.json`。
  `nett site build` writes each node's desired state to `nodes/<node>/desired.json` in the site directory.
- macOS：`sudo nett mesh install` 自动在运行 sudo 的用户的站点目录中找到给本机的期望状态，不用再写
  `--config`；站点不在这台机器上时仍可用 `--config` 指定。
  macOS: `sudo nett mesh install` finds this machine's desired state in the site directory of the user who
  ran sudo, so `--config` is only needed when the site is on another machine.

## [0.1.1] - 2026-11-09

- macOS：`sudo nett mesh install` 一个命令完成安装：生成本机密钥并打印写进站点描述的一行；
  `--config <desired.json>` 核对期望状态是给本机的再导入，然后启动服务；只有期望状态变化时重新加载、不重启。
  macOS: `sudo nett mesh install` does the whole setup: it creates this machine's keys and prints the line
  for the site description; with `--config <desired.json>` it checks that the desired state belongs to this
  machine, imports it and starts the service, and reloads without a restart when only the desired state changed.
- `nett mesh keys --dir` 沿用已有的密钥，打印同一行公钥。
  `nett mesh keys --dir` keeps existing keys and prints the same line again.
- Homebrew 的安装提示只用英文。The Homebrew caveats are in English only.

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
