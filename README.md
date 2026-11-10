# nett

中文 · [English](README.en.md)

> 一个开源、自托管的组网基础设施，把你分散在各处的机器连成一张网：自动选择最优路径，路径变差或节点离线时自动切换，进行中的连接不中断。

面向拥有少量分散机器的个人或小团队：几台不同地域的 VPS，加上家里的 NAS 或主机。WireGuard 负责加密，nett 的路径层在局域网直连、公网直连、打洞和经中继等路径之间选择最优路径；UDP 受阻时改用 TLS；家里的其他主机经局域网智能入口接入，手机在外也能访问它们；成员凭你的签名准入。资源占用极低，Hub 离线时组网照常工作。

- GoTry 旗下项目 · 主页 `nett.gotry.io`（建设中）
- 命令行：`nett`
- 服务：
  - `nett-hub`：组网的控制面，用命令行 `nett` 操作；Web 控制台以后加入（ADR 0024）
  - `nett-node`：每台机器上的控制代理，负责入网、连接 Hub 和升级
  - `nett-mesh`：组网进程，负责 WireGuard、选路与切换、DNS 和访问规则
  - `nett-transport`：按需运行的低权限传输适配进程，UDP 不可用时把流量转成 TLS
  - `nett-relay`：能被外部连入的节点上的中继与公网传输入口
- 状态：**M1 开发中**。接入 Hub 之前，可以用本地签名部署组网（[design/local-signing.md](docs/design/local-signing.md)）：Linux 使用内核 WireGuard，macOS 以原生成员加入，Mac 上需要访客真实 IP 的容器服务另用容器内成员；Hub 尚未完成（[design/hub.md](docs/design/hub.md)）
- 许可证：[MIT](LICENSE-MIT) 或 [Apache-2.0](LICENSE-APACHE)（双许可，任选其一）

## 安装

- **macOS**（原生成员与签名工具 `nett site`）：
  ```bash
  brew install gotry-io/tap/nett
  nett site init                              # 只在持有站点的这台电脑上做一次
  sudo nett install                           # 生成本机密钥，打印 nett site add 要用的一行
  nett site add mac --keys "<打印的那一行>"   # 把这台机器加进站点
  sudo nett install                           # 找到给本机的期望状态，核对、导入并启动组网服务
  ```
  站点用命令维护：`nett site add`、`allow`、`rules`、`status` 等，每条修改命令先列出要签名的内容，确认后签名（[design/site.md](docs/design/site.md)）。期望状态更新后执行 `sudo nett install`（只重新加载，不重启）；站点不在这台机器上时加 `--config <这个节点的 desired.json>`。组网服务以 root 运行（创建 utun 需要 root），运行的是复制到 root 专属目录的副本，因此每次 `brew upgrade nett` 之后再运行一次 `sudo nett install`（[design/release.md](docs/design/release.md) 第 4 节）。
- **Linux**：从 [Releases](https://github.com/gotry-io/nett/releases) 下载对应架构的静态版本，核对签名（[keys/](keys/README.md)）后解压。`sudo ./nett install` 把它装到 `/usr/local/bin`，在 `/etc/nett` 生成本机密钥，打印 `nett site add` 要用的一行；在持有站点的电脑上用 `nett site add <名字> --keys "…"` 加入它（能被连入的机器加 `--public --ipv4 <地址>`），把生成的这台机器的 `desired.json` 拷过来，`sudo nett install --config desired.json` 导入并启动组网服务（systemd 单元 [nett-mesh.service](packaging/systemd/nett-mesh.service) 由它写入）。期望状态更新后同样用 `--config` 再运行一次（只重新加载，不重启）。
- **接入 Hub**（可选，[design/hub.md](docs/design/hub.md)）：在一台能被连入的主机上运行 Hub（[packaging/hub/](packaging/hub/) 中 Hub 与 Caddy 的 Compose 示例），`nett-hub init --url https://hub.example.com` 打印一次性的关联码；在持有站点的电脑上 `nett site link <关联码>`，再对每台已有的机器运行 `nett site invite <名字>`，在那台机器上执行它打印的 `sudo nett install nett_enr_…`。之后每条修改命令签名后推送到 Hub，各台机器上的 nett-node 接收并交给组网进程，命令报告哪些机器已经应用；`nett site status` 列出每台机器是否在线、是否已应用最新的修改，以及各对机器之间的路径与往返时间。Hub 不在时组网照常，修改在它恢复后补齐。
- **命令**：`nett help` 列出全部命令，任何命令加 `--help` 显示用法。
- **查看状态**：`sudo nett status` 列出本机和每个对端的连通情况、路径、往返时间与丢包，以及被拒绝的配置；`sudo nett status <对端>` 看一个对端的候选路径和最近的切换（[design/status.md](docs/design/status.md)）。

## 文档

- [愿景](docs/vision.md)：要解决的问题、目标与约束
- [架构](docs/architecture.md)：总体设计：角色边界、信任链、组网、回源、技术栈
- [路线图](docs/roadmap.md)：各阶段内容与验收标准
- [架构决策记录](docs/adr/README.md)
- [设计文档](docs/design/README.md)
- [安全问题报告](SECURITY.md)
- [开发规则](CLAUDE.md)：安全边界、编码规范与提交约定（也供 AI 编码助手使用）
