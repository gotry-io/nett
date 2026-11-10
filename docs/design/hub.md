# 接入 Hub：常驻的分发与协调

- 状态：草案
- 阶段：M1，本地签名部署之后（roadmap M1，ADR 0022、0024）

## 1. 目标

本地签名部署中，用户在自己的电脑上用 `nett site` 维护并签名整张网，期望状态由用户拷到每台机器上（local-signing.md）。接入 Hub 之后：

- **签名照旧在用户自己的电脑上完成**，命令行是唯一的操作界面（ADR 0024，site.md）；
- 修改一次，**各台机器自动收到并应用**；离线的机器恢复后自动补齐；
- 新机器**一条命令入网**，不用复制公钥、拷文件；
- 在用户的电脑上**一处看到全部机器**的状态；
- 之后的几步：自动升级、地址变化自动跟随、中继调度、多台签名设备（第 9 节）。

手工步骤的根源是用户的电脑与各台机器之间没有通道，各台机器上也没有常驻的代理。Hub 是所有机器都连得到、一直在线的那一端，nett-node 是每台机器上的那个代理。

## 2. 角色

| 角色 | 在哪里 | 做什么 | 持有的密钥 |
|---|---|---|---|
| 签名工具 `nett site` | 用户自己的电脑，用时运行 | 用命令维护站点（site.md）：分配地址与版本号，在本机计算、显示并签名产物，推送给 Hub；查看全部机器的状态；为新机器生成入网命令 | 恢复密钥（唯一的信任锚）、Hub 的 API token |
| Hub（`nett-hub`） | 一台 `public` 主机，位于反向代理之后 | 保存签名产物与站点模型，为每台机器组成期望状态，经节点网关下发；汇总状态 | Hub 身份密钥（Noise，只用于认证通道），**没有能签名的钥匙** |
| nett-node（`nett node`） | 每台机器 | 入网；连接 Hub；把期望状态交给组网进程；上报状态 | 节点身份密钥（Noise） |
| 组网进程（`nett mesh`） | 每台成员 | 不变：验证签名、版本与撤销记录，组网（mesh.md） | 组网私钥 |

信任关系与 auth.md 第 2 节相同：Hub 是中间人，不是信任根；节点只接受能用信任锚验证的授权。区别在于签名载荷由用户电脑上的签名工具从本地的站点状态计算并显示，不经 Hub 提供的页面（ADR 0024）。

## 3. 用户怎么用

### 3.1 一次：安装 Hub，与站点关联

按第 8 节在 Hub 主机上运行 Hub（默认用 Compose，与 Caddy 一起），然后：

```
# Hub 主机上
nett-hub init --url https://hub.example.com
Hub initialized. Link your site from the computer that holds it, within 1 hour:
  nett site link nett_lnk_…

# 用户的电脑上
nett site link nett_lnk_…
Linked to https://hub.example.com. Pushed 3 nodes, access rules v3.
Connect each existing node with `nett site invite <name>`.
```

关联码包含 Hub 地址、Hub 身份公钥和一次性的随机密钥（1 小时内有效，只能用一次，与 auth.md 第 4.1 节的初始化链接相同）。`nett site link` 校验 Hub 的 TLS 证书（硬性规则 11），用一次性密钥证明自己，把信任锚清单交给 Hub，换回一个属于站点的 API token，保存在站点目录中（`0600`）。Hub 从此只接受能用这份信任锚验证的产物。站点中已有的机器按第 3.5 节接入。

### 3.2 修改

用站点的命令修改（site.md）。接了 Hub 时，确认之后推送：

```
nett site allow mac nas 22/tcp
Access rules v4 -> v5:
  + r5  mac (100.88.0.4) -> nas (100.88.0.6)  22/tcp
Connections:
  + mac - nas  punch
Sign and push? [y/N] y
Pushed. 1 of 2 nodes applied; nas has not connected yet.
```

- 推送之后，Hub 组成各台机器的期望状态并下发，各台应用后回报；命令等待最多 10 秒，报告已应用的机器，没连上的在它连上后自动补齐。某台机器拒绝了期望状态、或应用之后仍有问题（例如某个成员的准入材料被拒绝，status.md 第 4.1 节的 `problems`）时，逐台列出原因，退出码为 1，与 `nett reload` 相同；
- 不接 Hub 时，同样的命令写成期望状态文件，由用户拷到各台机器（site.md 第 7 节）。

### 3.3 新机器入网

```
nett site add nas
Adding nas (dial-only), 100.88.0.6
Sign and push? [y/N] y
On nas, run within 30 minutes (once):
  Linux  curl -fsSL https://hub.example.com/install.sh | sudo sh -s -- nett_enr_…
  macOS  brew install gotry-io/tap/nett && sudo nett install nett_enr_…
```

- 在新机器上运行其中一行：Linux 上安装脚本由 Hub 提供，下载并核对 `nett` 后运行 `sudo nett install <token>`（第 9 节的 H2）；macOS 上先用 Homebrew 安装；
- `sudo nett install <token>` 在本机生成密钥（私钥不离开本机），连接 Hub 完成入网，安装并启动 nett-node 与组网进程的服务。其他成员随即收到它的准入材料。用户不用复制公钥，也不用再签名：签名在 `add` 时已经完成（第 6 节）；
- 能被外部连入的机器加 `--public`，公网地址可以不写（第 11 节）；token 过期了用 `nett site invite nas` 重新生成。

### 3.4 查看

```
nett site status
hub     https://hub.example.com, nett-hub 0.3.0
site    4 nodes, access rules v5

NODE      ADDRESS     HUB      VERSION  CONFIG   PROBLEMS
edge-vps  100.88.0.1  online   0.3.0    current  -
mac       100.88.0.4  online   0.3.0    current  -
mac-app   100.88.0.3  online   0.3.0    current  -
nas       100.88.0.6  offline  0.3.0    behind   last seen 3h ago

PEER A    PEER B   STATE        PATH                  RTT
edge-vps  mac      connected    direct                9.0 ms
edge-vps  mac-app  connected    direct                8.6 ms
mac       nas      unreachable  relay edge-vps (tls)  -
```

- `nett site status <机器>` 显示一台机器的详情，与在那台机器上运行 `nett status`（status.md）的内容相同，另加它最近一次连接 Hub 的时间；
- 列出的机器对就是站点推导出的连接（site.md 第 6 节）；每对机器的路径与往返时间取决定方的测量（mesh.md 第 8.3 节）；
- 排版按 architecture.md 第 14.3 节；`--json` 输出完整内容。

### 3.5 已经在运行的机器接入

本地签名部署中的机器沿用已有的密钥、地址和产物版本，不重新入网：

```
nett site invite edge-vps
edge-vps is already a member. On edge-vps, run (valid for 30 minutes, once):
  sudo nett install nett_enr_…
```

已是成员的机器拿到的 token 里没有入网私钥，只有 Hub 地址、Hub 身份公钥和节点 ID：这台机器用自己的身份密钥连接 Hub，Hub 按站点推送来的身份公钥认出它。之后它的期望状态由 nett-node 从 Hub 接收（第 5 节），不用手工拷。

## 4. 站点与 Hub

- **站点状态以用户的电脑为准**：机器、权限、地址分配、产物版本保存在站点目录中（site.md 第 8 节）。Hub 保存最近一次推送的副本；
- **在 Hub 一侧发生的降低权限**：节点上运行 `nett leave` 时，Hub 收到 `Leave`，为这个节点生成身份撤销记录并下发给其他成员，不等站点（降低权限不需要签名，auth.md 第 8.3、10.4 节）。`nett site` 的每条命令先从 Hub 取回这类变化，按 `nett site remove` 处理：这台机器从站点中删除，引用它的规则随之清理，并在输出中列出（site.md 第 4 节）。同一个名字再次 `add` 时是新的机器：新的节点 ID 和地址，没有原来的规则；
- **推送的内容**：签名产物（节点策略、访问规则集、宣告网段）、撤销记录、不签名的部分（机器的名字、可达性、公网地址与端口）。连接与候选路径由 Hub 组成期望状态时推导（site.md 第 6 节）。Hub 验证每份签名产物的签名与版本，版本低于已保存的、或与已保存的版本相同而内容不同的整份拒绝；
- **组成期望状态**：Hub 按站点模型为每台机器组成 `mesh` 分区，格式与本地签名部署的期望状态文件相同（protocol.md 第 6 节）。组成的逻辑只有一份：站点模型与组成从 `nett site` 中移到一个库 crate（`nett-site`），签名工具不接 Hub 时与 Hub 共用；
- **API**：REST + JSON，经 HTTPS，带 OpenAPI（ADR 0003）。这一步用到的资源是 api-resources.md 中的 `hub`、`trust`、`nodes`、`enrollment-tokens`、`node-policies`、`access-rules`、`links`、`events` 与一个新的 `site`（推送的站点模型）；
- **API token**：关联时发给站点的 token，`kind` 为 `owner`，拥有站点的全部操作。它能推送签名产物，但推送的产物照样要通过签名验证：token 本身批准不了任何提升权限的变更（硬性规则 3）。它能做的不签名的事，与 Hub 能做的相同：撤销（降低权限）、改机器的名字、可达性与公网地址，影响的是可用性，不是权限。

## 5. 节点与 Hub

协议按 protocol.md：WebSocket 上的 Noise IK，Protobuf 消息，按分区和代数下发期望状态。这一步用到的分区是 `trust`、`mesh`、`hub_endpoints`；消息是 `Hello`/`Welcome`、`DesiredState`/`StateAck`、`Inventory`、`LinkReport`、`NodeEvent`、`Leave`、`Ping`/`Pong`。

- **交给组网进程**：nett-node 把 `mesh` 分区写成组网进程的期望状态文件（先写临时文件再改名），再经本机接口发出重新读取的请求（`nett reload` 的同一个请求，status.md 第 4.1 节），拿回结果：`applied`（附 `problems`）、`rejected`（附原因）、`busy`，分别作为 `StateAck` 的 `applied`、`rejected`、`pending` 报给 Hub（protocol.md 第 5 节）。`problems` 随状态上报；`busy` 时期望状态照常在应用，nett-node 在下一次读状态时按其中的 `config` 确认它已生效。组网进程把接受过的授权和最近一次整份接受的期望状态保存在它自己的信任存储中（mesh.md 第 4.2 节），重启时先应用它们，不等 nett-node 和 Hub（硬性规则 8）；期望状态文件只是输入，被拒绝的文件不会成为验证的基准，也不会让被撤销的权限恢复；
- **期望状态文件只有一个写入者**：接入 Hub 的机器上只由 nett-node 写，`sudo nett install` 不从站点目录导入（第 7 节）；用户运行 `nett reload` 只是让组网进程重新读同一份文件；
- **上报状态**：nett-node 每 15 秒、以及期望状态应用之后，经本机状态接口读一次状态，有变化时发 `LinkReport`（各对端的状态、路径、往返时间）和 `Inventory`（版本、平台、地址）。Hub 只保存每台机器最新的一份，事件保留最近的若干条（第 8 节）；
- **离线**：Hub 或 nett-node 不在时，组网照常（architecture.md 第 12.2 节）；nett-node 按 protocol.md 第 8 节重连，连上后按代数补齐；
- **Hub 端点**：入网 token 中的地址是公网地址，不经组网；以后增加的备用端点也至少保留一个不经组网（硬性规则 8）。

## 6. 入网

按 auth.md 第 8 节，入网 token 由签名工具代替浏览器生成：

1. `nett site add <机器>`（token 过期后用 `nett site invite <机器>` 重新生成）：签名工具分配节点 ID 和组网地址，生成一对一次性的入网签名密钥（Ed25519），用恢复密钥签名这个节点的初始策略（其中有入网公钥；重新生成时换一把入网密钥，策略版本加一），把策略推给 Hub，然后打印 token：Hub 地址、节点 ID、Hub 身份公钥、信任锚清单指纹、入网私钥。入网私钥不经过 Hub；
2. 节点上 `sudo nett install <token>`：生成身份密钥和组网密钥，用入网私钥签准入证明，以 Noise IK 连接 Hub（用 token 中的 Hub 公钥）；
3. Hub 用策略中的入网公钥验证准入证明，检查 token 未用过、未过期；把信任锚和策略交给节点，把准入材料（策略 + 准入证明）分发给其他成员；
4. 节点核对信任锚指纹、验证策略，丢弃入网私钥，安装并启动服务：Linux 上 `nett-node.service` 与 `nett-mesh.service`，macOS 上两个 launchd 服务（第 7 节）。

`nett site add --keys` 因此只用于不接 Hub 的站点；接入之前就已是成员的机器沿用站点中登记的公钥（第 3.5 节）。经 Hub 入网的节点，公钥由节点自己交给 Hub，签名工具用不到它。

## 7. 节点上的进程与权限

| 进程 | 身份 | 说明 |
|---|---|---|
| nett-node | root | 写组网进程的期望状态文件、请它重新加载；以后还要替换可执行文件（升级）。不监听任何端口，不执行 shell，不访问 Docker（硬性规则 1、2、9）；tokio 单线程；空闲 RSS ≤ 5 MB |
| 组网进程 | 不变（Linux 上的专用身份，macOS 上的 root） | 只认它自己验证过的期望状态；本机状态接口只接受 root 和它自己（status.md 第 3 节），nett-node 以 root 连接 |

- `sudo nett install <token>` 在两个平台上做同样的事：生成或沿用密钥，把正在运行的 `nett` 复制到固定的位置（已经在那里运行时不复制），写入两个服务的配置，保存 Hub 的配置（地址与 Hub 身份公钥），启动服务。服务配置的内容只有一个出处：macOS 的 launchd 配置在代码中定义（release.md 第 4 节），Linux 的单元是 `packaging/systemd/` 中的文件，编译时嵌入；
- Linux：程序在 `/usr/local/bin/nett`（单元中的路径）；`nett-node.service` 在 `nett-mesh.service` 之后启动，两者都由 systemd 重启，互不依赖；
- macOS：`io.gotry.nett.node` 与 `io.gotry.nett.mesh` 两个 launchd 服务，都运行 root 专属目录里的副本（release.md 第 4 节）；
- **本机有 Hub 的配置时**，不带 token 的 `sudo nett install` 只更新程序的副本和服务配置，程序变了时重启两个服务；它不从站点目录导入期望状态，也不接受 `--config`（第 5 节）。H3 之前，macOS 上 `brew upgrade nett` 之后运行一次 `sudo nett install` 换上新的副本；
- `sudo nett uninstall` 停止并删除两个服务，保留密钥、期望状态和 Hub 的配置，再次 `install` 即恢复；`sudo nett leave` 按 auth.md 第 8.3 节退出，连同 Hub 的配置一起删除；
- 容器内成员：见第 11 节。

## 8. Hub 的运行

- 一个可执行文件 `nett-hub`（ADR 0012）：axum、SQLite + sqlx（architecture.md 第 10 节）；这一步不带前端（不需要 rust-embed、webauthn-rs）；
- **发布与安装**：`nett-hub` 的可执行文件（Linux x86_64、aarch64，静态链接）与容器镜像，与 `nett` 一起发布、同样签名（release.md）。默认用 Compose 运行 nett-hub 与 Caddy，证书由 Caddy 申请；Hub 主机上已经有反向代理时，`nett-hub init` 打印要加进去的配置片段（把 `/api/v1/` 和 `/node/v1/connect` 的 WebSocket 转给 Hub），不改用户自己的配置；
- 原生运行时以专用的低权限用户运行，也可以在容器中运行（Hub 不需要访问宿主）；只监听本机，由反向代理暴露（architecture.md 第 4 节）；
- 保存：站点模型与签名产物、各节点的身份公钥与代数、每台机器最新的状态、最近的事件（每台 100 条，保留 30 天）、一次性 token（只存哈希）。SQLite 显式设置缓存与 mmap 上限；
- 资源：稳定运行 ≤ 30–50 MB（硬性规则 14）；每个节点的连接、消息、队列都有上限（protocol.md 第 11 节）；
- 备份与重建在第 9 节的 H5。

## 9. 分步

每一步做完都能单独使用。

| 步 | 内容 | 做完之后 |
|---|---|---|
| **H1 分发与状态** | 前提：组网进程的信任存储（mesh.md 第 4.2 节），Hub 下发的内容才不会改变验证的基准。`nett-hub` 与节点网关，发布与安装（第 8 节）；站点的命令与 `nett-site` 库（site.md）；`nett site link`、`status`、`invite`（已有的机器）；两个平台上的 `sudo nett install <token>`（第 7 节）；nett-node 接收期望状态、交给组网进程、上报状态 | 已有的机器接入 Hub；修改之后自动送达；一处看到全部机器 |
| **H2 入网与退出** | 新机器的 `add` 与入网；Hub 提供的安装脚本（architecture.md 第 13.3 节）；`public` 机器的公网地址由 Hub 得知（第 11 节）；`nett leave`（第 4 节） | 新机器在电脑上一条命令、在机器上一条命令入网，不用复制公钥；退出的机器可以重新入网 |
| **H3 升级** | `release` 分区：Hub 缓存签名的发布包，nett-node 核对发布签名、只接受更高的版本、失败回滚（auth.md 第 11.3 节、ADR 0020） | 不用逐台下载、替换 |
| **H4 运行时协调** | 节点上报的地址用于候选路径（地址变化自动跟随）；中继分配；两端都是 `dial-only` 时经 Hub 转达切换（`PathSwitch`，mesh.md 第 8.4 节） | 家宽 IP 变化、笔记本换网络不需要重新生成配置；更快地绕开失效的中继 |
| **H5 可用性与多设备** | Hub 的加密备份由节点拉取、重建手册（architecture.md 第 12.3 节，protocol.md 第 6.4 节）；站点状态移到 Hub，多台签名设备各用自己的钥匙（信任锚更新，auth.md 第 11.2 节） | Hub 主机坏了能重建；不只一台电脑能签名 |

以后：Web 控制台与 passkey（ADR 0024），在站点状态移到 Hub（H5）之后，作为同一套 API 上的另一个前端，与命令行修改同一份站点数据；手机的配置在设备凭据与移动网关实现之后（mesh.md 第 13 节），由 `nett site` 的命令生成配置文件与二维码（ADR 0008）。

## 10. 验证

| 层级 | 内容 |
|---|---|
| 单元测试 | 站点模型的组成（与不接 Hub 时写出的期望状态文件逐字节相同）；Hub 对产物的验证（签名错误、版本倒退、同版本不同内容）；token 只能用一次、过期；重新读取的结果（`applied` 带问题、`rejected`、`busy`）映射到 `StateAck`；有 Hub 配置的机器上 `install` 不改动期望状态文件 |
| Hub 集成测试 | 临时 SQLite，经 HTTP 调用真实的路由：关联、推送、权限检查（没有 token、错误的 token） |
| 实验场景 | 在实验拓扑中运行 Hub：推送之后各成员应用、`nett site status` 列出全部机器与链路；Hub 停止时组网照常、修改恢复后补齐；Hub 下发一个没有准入材料的对端或旧版本的产物，成员都拒绝（roadmap M1 验收）；入网；一个成员 `nett leave` 之后其他成员删除它，站点中删除它并清理引用它的规则，同一个名字再次加入得到新的节点 ID |
| 资源 | nett-node 空闲 RSS ≤ 5 MB；Hub 在实验拓扑中的稳定内存 |
| 实际机器 | 用户自己的一台 `public` 主机作为 Hub 主机；已有的成员接入；之后新机器入网 |

## 11. 待定问题

| 问题 | 说明 |
|---|---|
| 容器内成员怎么接 Hub | 镜像里只有一个 `nett`，以组网进程为主进程。可选：容器里也运行 nett-node（需要在容器内同时运行两个进程）；或者宿主上的 nett-node 代管它（经挂载的目录写期望状态、经挂载的本机套接字请它重新加载，不访问 Docker），这时宿主要代它连接 Hub |
| 发布包从哪里来（H2 的安装脚本、H3 的升级） | Hub 自己从项目的发布页下载并核对签名；或由用户的电脑下载核对后推给 Hub。网络受限的 Hub 主机需要后一种 |
| `public` 机器的公网地址怎样得知（H2） | 站点中没写明时：本机网卡上的全局地址（多数 VPS），或 Hub 看到的来源地址（由 Hub 前的反向代理转交，适用于公网地址不在网卡上的 1:1 NAT 云主机；Hub 主机自己经本机连接时看不到）。以哪一种为准、能否被连入怎样确认，待定 |
| Hub 主机的选择 | 需要一个 `public`、长期稳定、能用 Hub 域名的主机（architecture.md 第 13.5 节）；这也是它成为单点的地方，见 H5 |
