# 变更记录 · Changelog

用户可见的变化，按版本记录；版本号遵循语义化版本（design/release.md 第 2 节）。
User-visible changes by version; versions follow Semantic Versioning.

## [Unreleased]

- 命令按作用范围重新整理（`nett help` 按组列出，任何命令加 `--help` 显示用法）：本机的命令都在顶层，
  `nett mesh` 只是由服务管理器运行的组网进程。改名：`nett mesh install` / `uninstall` → `nett install` /
  `uninstall`，`nett mesh keys` → `nett keys`，`nett site build` → `nett site apply`。已安装的 macOS 服务、
  systemd 单元和容器镜像都按 `nett mesh` 启动，不受影响；脚本和自己的笔记里的旧命令要改成新的。
  Commands are regrouped by scope (`nett help` lists them by group; `--help` after any command shows its
  usage): commands for this machine are top-level, and `nett mesh` is only the mesh process run by the
  service manager. Renamed: `nett mesh install` / `uninstall` -> `nett install` / `uninstall`,
  `nett mesh keys` -> `nett keys`, `nett site build` -> `nett site apply`. Installed macOS services, systemd
  units and container images start `nett mesh` and keep working; update scripts and notes that use the old
  commands.
- 新命令 `nett reload`：请组网进程重新读取期望状态文件，并显示它是否被接受、应用之后还有哪些问题；被拒绝时
  退出码为 1。容器内成员用 `docker exec <容器> /nett reload`，Linux 上用 `sudo nett reload`；macOS 上
  `sudo nett install` 在期望状态有变化时也这样做。0.1.4 中 `nett site build` 提示容器用 `docker kill -s HUP`，
  这会让 Docker 把容器记为手动停止过，主机重启后 `unless-stopped` 的容器不再自动启动；照着做过的，运行一次
  `docker restart <容器>` 清掉这个记录。
  New command `nett reload`: asks the mesh process to re-read its desired state file and shows whether it was
  accepted and what problems remain; it exits with 1 when the file is rejected. Container members use
  `docker exec <container> /nett reload`, Linux nodes `sudo nett reload`; on macOS, `sudo nett install` does
  this when the desired state changed. The 0.1.4 hint from `nett site build` said `docker kill -s HUP` for
  containers, which makes Docker treat the container as manually stopped, so an `unless-stopped` container
  no longer starts after the host restarts; if you followed it, run `docker restart <container>` once to
  clear that.
- macOS：`sudo nett install` 只在本机还没有期望状态时打印写进站点描述的公钥那一行；之后再运行只说明结果。
  macOS: `sudo nett install` prints the key line for the site description only while this machine has no
  desired state yet; later runs just report what happened.

## [0.1.4] - 2026-11-10

- 新命令 `nett status`：本机的地址与运行方式，每个对端是否连通、走哪条路径、往返时间与丢包、最近一次握手，以及
  被拒绝的期望状态、成员和访问规则；`nett status <对端>` 显示候选路径和最近的切换，`--json` 输出完整的状态。
  状态经组网进程的本机套接字读取（Linux 与容器内为 `/run/nett/mesh.sock`，macOS 为 `/var/run/nett/mesh.sock`，
  `nett mesh --socket` 可改），只有 root 能读，所以要 `sudo nett status`。Linux 上自己安装 systemd 单元的，
  换上新的 `nett-mesh.service`（增加了 `RuntimeDirectory=nett`）后 `systemctl daemon-reload`；不换时组网照常，
  日志中有一条警告，`nett status` 连不上。
  New command `nett status`: this node's addresses and setup; for each peer whether it is connected, which
  path it uses, round-trip time and loss, and the last handshake; plus any rejected desired state, members
  or access rules. `nett status <peer>` shows the candidate paths and recent switches; `--json` prints the
  full status. It is read from the mesh process's local socket (`/run/nett/mesh.sock` on Linux and in
  containers, `/var/run/nett/mesh.sock` on macOS, `nett mesh --socket` to change it), which only root can
  read, so run `sudo nett status`. If you installed the systemd unit yourself, replace `nett-mesh.service`
  (it adds `RuntimeDirectory=nett`) and run `systemctl daemon-reload`; without it the mesh keeps working,
  the log has a warning and `nett status` cannot connect.
- `nett site build` 把节点名写进期望状态（不签名，只用于显示）。之前的版本不接受这个字段：先升级节点上的 nett，
  再换上新生成的期望状态；顺序反了时节点继续使用上一份期望状态。节点名最长 63 个字符。
  `nett site build` puts node names into the desired state (unsigned, for display only). Earlier versions
  reject the field: upgrade nett on the nodes before giving them the new desired state; in the other order a
  node keeps using its previous desired state. Node names are at most 63 characters.
- 命令行的提示和错误只用英文，写得更短。
  Command-line messages and errors are in English only, and shorter.

## [0.1.3] - 2026-11-10

- `dial-only` 节点的 WireGuard 端口由系统分配：站点描述中不再为它写 `listen_port`、`ipv4`、`ipv6`，
  同一台主机上的原生成员与容器内成员不再争用端口；日志中的 `mesh interface ready` 写着实际的端口。
  之前的版本不接受不带端口的期望状态：先升级 `dial-only` 节点上的 nett，再换上新生成的期望状态。
  A `dial-only` node's WireGuard port is picked by the system: the site description no longer sets
  `listen_port`, `ipv4` or `ipv6` for it, so a native member and a container member on the same host no
  longer compete for a port; `mesh interface ready` in the log shows the port in use. Earlier versions
  reject a desired state without a port: upgrade nett on `dial-only` nodes before giving them the new one.
- WireGuard 端口不能用组网进程自己在本机用的端口（组网地址上的探测端口 `41821`、TLS 中继的回环端口
  `41830`–`41845`）：`nett site build` 生成时即报错。之前这样设置时组网照常连通，但不收发探测，测不到路径、
  也发现不了故障。
  The WireGuard port cannot be one the mesh process uses itself (the probe port `41821` on mesh addresses,
  the TLS relay loopback ports `41830`–`41845`); `nett site build` reports it. Before, such a node stayed
  connected but sent and answered no probes, so it could not measure paths or notice failures.

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
- macOS：`sudo nett mesh uninstall` 等服务的进程退出之后才报告已停止。
  macOS: `sudo nett mesh uninstall` reports the service as stopped only after its process has exited.

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
