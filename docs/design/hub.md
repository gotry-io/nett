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
Linked to https://hub.example.com. Pushed 3 machines, access rules v3.
Connect each existing machine with `nett site invite <name>`.
```

关联码包含 Hub 地址、Hub 身份公钥和一次性的随机密钥（1 小时内有效，只能用一次，与 auth.md 第 4.1 节的初始化链接相同）。`nett site link` 校验 Hub 的 TLS 证书（硬性规则 11），用一次性密钥证明自己，把信任锚清单交给 Hub，换回一个属于站点的 API token，保存在站点目录中（`0600`）。Hub 从此只接受能用这份信任锚验证的产物。站点中已有的机器按第 3.5 节接入。

### 3.2 修改

用站点的命令修改（site.md）。接了 Hub 时，确认之后推送：

```
nett site allow mac nas 22/tcp
Access rules v4 -> v5:
  + r5  mac (100.88.0.4) -> nas (100.88.0.6)  22/tcp
Connections:
  + mac - nas  punch only; may not connect
Sign and push? [y/N] y
Pushed. 1 of 2 machines applied.
  nas has not connected yet; `nett site invite nas` connects it
```

- 推送之后，Hub 组成各台机器的期望状态并下发，各台应用后回报；命令等待最多 10 秒，报告已应用的机器，没连上的在它连上后自动补齐。某台机器拒绝了期望状态、或应用之后仍有问题（例如某个成员的准入材料被拒绝，status.md 第 4.1 节的 `problems`）时，逐台列出原因，退出码为 1，与 `nett reload` 相同；
- 推送失败（Hub 不在）时，修改照常签名并保存在站点目录中，命令报告推送失败、退出码为 1；之后的任何一条修改命令推送整个站点，把错过的修改一起送到。同一份站点再推一次时 Hub 不换代数；
- 站点目录照常写出各台机器的期望状态文件；只有还没有连过 Hub 的机器，命令才提示把文件拷过去；
- 不接 Hub 时，同样的命令写成期望状态文件，由用户拷到各台机器（site.md 第 7 节）。

### 3.3 新机器入网

```
nett site add nas
+ nas (dial-only), 100.88.0.6
Sign and push? [y/N] y
Pushed. 3 of 3 machines applied.
On nas, run within 30 minutes (once):
  curl -fsSL https://nett.gotry.io/install.sh | sh && sudo nett install nett_enr_…
```

- 所有平台都是这一行。前半句的安装脚本只安装 `nett`：判断系统与架构，从项目网站下载这个版本的压缩包，按脚本中写明的 SHA-256 核对，放到 `/usr/local/bin/nett`（release.md 第 6 节）。脚本不读 token，也不经过 Hub：被攻破的 Hub 换不了装上的程序。首次安装因此信任项目网站，与 Homebrew 信任它的配方相同；之后的升级由节点核对发布签名（ADR 0020，第 9 节 H3）。已经装好 `nett` 的机器只运行后半句；
- 后半句 `sudo nett install <token>` 在本机生成密钥（私钥不离开本机），经 Hub 完成入网，安装并启动 nett-node 与组网进程的服务（第 6、7 节）。其他成员随即收到它的准入材料。用户不用复制公钥，也不用再签名：节点策略在 `add` 时已经签好；
- token 中有入网私钥，30 分钟内有效，只能用一次。过期了或者丢了，`nett site invite nas` 换一把入网密钥，打印新的一行，原来的随之作废；
- 能被外部连入的机器加 `--public`，公网地址可以不写，由 Hub 得知（第 5 节）；
- 入网之前，`nett site status` 中这台机器的 `HUB` 为 `never`，`PROBLEMS` 写明 token 的过期时间。

### 3.4 查看

```
nett site status
hub     https://hub.example.com, nett-hub 0.3.0
site    4 nodes, access rules v5

MACHINE   ADDRESS     HUB      VERSION  CONFIG   PROBLEMS
edge-vps  100.88.0.1  online   0.3.0    current  -
mac       100.88.0.4  online   0.3.0    current  -
mac-app   100.88.0.3  online   0.3.0    current  -
nas       100.88.0.6  offline  0.3.0    behind   last seen 3h ago

PEER A    PEER B   STATE        PATH                  RTT
edge-vps  mac      connected    direct                9.0 ms
edge-vps  mac-app  connected    direct                8.6 ms
mac       nas      unreachable  relay edge-vps (tls)  -
```

- `HUB` 是这台机器与 Hub 的连接：`online`、`offline`，从没连过时为 `never`；`CONFIG` 是它对最新一次推送的确认：`current`（已应用）、`pending`（已写好，组网进程还没给出结果）、`rejected`、`behind`（还没收到或还没确认）；
- `nett site status <机器>` 显示一台机器的详情，与在那台机器上运行 `nett status`（status.md）的内容相同，另加它最近一次连接 Hub 的时间；
- Hub 不在时，`nett site status` 说明连不上，照样列出站点中的机器；
- 列出的机器对就是站点推导出的连接（site.md 第 6 节）；每对机器的路径与往返时间取决定方的测量（mesh.md 第 8.3 节）；
- 排版按 architecture.md 第 14.3 节；`--json` 输出完整内容。

### 3.5 已经在运行的机器接入

本地签名部署中的机器沿用已有的密钥、地址和产物版本，不重新入网：

```
nett site invite edge-vps
edge-vps is already a member. On edge-vps, run:
  sudo nett install nett_enr_…
```

已是成员的机器拿到的 token 里没有入网私钥，只有 Hub 地址、Hub 身份公钥、节点 ID、信任锚清单的指纹，以及 Hub 自签证书时证书的指纹：这台机器用自己的身份密钥连接 Hub，Hub 按站点推送来的身份公钥认出它。token 里没有秘密，所以不设有效期，也可以重复使用；它能做的只是让一台已是成员的机器换一个 Hub 连接，而这一步要在那台机器上以 root 执行，并核对节点 ID 与信任锚（第 7 节）。之后它的期望状态由 nett-node 从 Hub 接收（第 5 节），不用手工拷。

## 4. 站点与 Hub

- **站点状态以用户的电脑为准**：机器、权限、地址分配、产物版本保存在站点目录中（site.md 第 8 节）。Hub 保存最近一次推送的副本；
- **站点目录保存整张网的全部签名内容**：经 Hub 入网的机器，签名工具从 Hub 取回它的准入证明（其中有身份公钥和组网公钥），记进站点状态。Hub 损坏时，新的 Hub 一次 `nett site link` 就能拿到全部机器和权限（第 8.1 节）；
- **在 Hub 一侧发生的事**：有三类，Hub 记下来，当场用到自己保存的站点副本上（换代数、下发，不等站点），之后每次推送也先用到推送的站点上，所以还没取回它们的推送不会把它们抹掉：
  - **入网**：机器交来的准入证明（第 6 节）；
  - **退出**：节点上运行 `nett leave` 时 Hub 收到 `Leave`，按 `nett site remove` 处理这台机器：生成身份撤销记录，所有成员删除它（降低权限不需要签名，auth.md 第 8.3、10.4 节）；规则中引用它的部分从站点中删除，已签的访问规则集等站点重签（它的地址不再分配，留在规则集中也放行不了任何机器）；
  - **得知的公网地址**（第 5 节）；

  `nett site` 的每条命令先从 Hub 取回这些（`GET /api/v1/site/updates`），用同一份逻辑（`nett-site`）记进站点状态，准入证明由签名工具自己再验证一次，并在输出中列出。退出的机器从站点中删除，引用它的规则随之清理，访问规则集以新的版本重签（收窄，site.md 第 4 节）；同一个名字再次 `add` 时是新的机器：新的节点 ID 和地址，没有原来的规则。准入材料按机器实际用过的那份记下：取回之后、推送之前它正好入网、站点又给它换了入网密钥时，入网的结果照样保留，新的 token 随之没有用处；
- **推送的内容**：签名产物（节点策略、访问规则集、宣告网段）、撤销记录、不签名的部分（机器的名字、可达性、公网地址与端口）。连接与候选路径由 Hub 组成期望状态时推导（site.md 第 6 节）。Hub 验证每份签名产物的签名与版本，版本低于已保存的、或与已保存的版本相同而内容不同的整份拒绝；
- **组成期望状态**：Hub 按站点模型为每台机器组成 `mesh` 分区，格式与本地签名部署的期望状态文件相同（protocol.md 第 6 节）。组成的逻辑只有一份：站点模型与组成从 `nett site` 中移到一个库 crate（`nett-site`），签名工具不接 Hub 时与 Hub 共用；
- **API**：REST + JSON，经 HTTPS，带 OpenAPI（ADR 0003）。这一步用到的资源是 api-resources.md 中的 `hub`、`trust`、`nodes`、`enrollment-tokens`、`node-policies`、`access-rules`、`links`、`events` 与一个新的 `site`（推送的站点模型）；
- **H1 的接口**：`POST /api/v1/link`（关联码中的一次性密钥与信任锚清单，换回 owner token）、`PUT /api/v1/site`（推送站点状态，回复 Hub 接受之后的代数）、`GET /api/v1/site/status`（各台机器的连接、版本、确认与本机状态）；节点网关是 `GET /node/v1/connect` 上的 WebSocket（protocol.md）。H2 加上 `GET /api/v1/site/updates`（Hub 一侧的入网、退出与得知的地址）。关联码是 `nett_lnk_` 加上 base64url 编码的 JSON（Hub 地址、Hub 身份公钥、一次性密钥、自签证书的指纹），接入 token 是 `nett_enr_` 加上同样编码的 JSON（第 3.5 节）；入网 token 是同一种格式，多了入网私钥（Ed25519 的 32 字节种子）与过期时间（auth.md 第 8.1 节）。Hub 自签证书时（没有反向代理的部署、实验拓扑），`nett-hub serve --tls-cert --tls-key` 自己终止 TLS，签名工具与节点按关联码和 token 中的指纹校验证书（硬性规则 11）；
- **API token**：关联时发给站点的 token，`kind` 为 `owner`，拥有站点的全部操作。它能推送签名产物，但推送的产物照样要通过签名验证：token 本身批准不了任何提升权限的变更（硬性规则 3）。它能做的不签名的事，与 Hub 能做的相同：撤销（降低权限）、改机器的名字、可达性与公网地址，影响的是可用性，不是权限。

## 5. 节点与 Hub

协议按 protocol.md：WebSocket 上的 Noise IK，Protobuf 消息，按分区和代数下发期望状态。这一步用到的分区是 `trust`、`mesh`、`hub_endpoints`；消息是 `Hello`/`Welcome`、`DesiredState`/`StateAck`、`Inventory`、`LinkReport`、`NodeEvent`、`Leave`、`Ping`/`Pong`。

- **交给组网进程**：nett-node 把 `mesh` 分区写成组网进程的期望状态文件（先写临时文件再改名），再经本机接口发出重新读取的请求（`nett reload` 的同一个请求，status.md 第 4.1 节），拿回结果：`applied`（附 `problems`）、`rejected`（附原因）、`busy`，分别作为 `StateAck` 的 `applied`、`rejected`、`pending` 报给 Hub（protocol.md 第 5 节）。`problems` 随状态上报；`busy`、或组网进程没有应答（文件已写好，它启动时会读）时报 `pending`，nett-node 在下一次读状态时再请它重新读取一次，拿到结果后补报。组网进程把接受过的授权和最近一次整份接受的期望状态保存在它自己的信任存储中（mesh.md 第 4.2 节），重启时先应用它们，不等 nett-node 和 Hub（硬性规则 8）；期望状态文件只是输入，被拒绝的文件不会成为验证的基准，也不会让被撤销的权限恢复；
- **期望状态文件只有一个写入者**：接入 Hub 的机器上只由 nett-node 写，`sudo nett install` 不从站点目录导入（第 7 节）；用户运行 `nett reload` 只是让组网进程重新读同一份文件；
- **上报状态**：nett-node 每 15 秒、以及期望状态应用之后，经本机状态接口读一次状态，有变化时发 `LinkReport`（各对端的状态、路径、往返时间）和 `Inventory`（版本、平台、地址）。Hub 只保存每台机器最新的一份，事件保留最近的若干条（第 8 节）；
- **公网地址**：`public` 机器在站点中没有写明地址时，由 Hub 得知。nett-node 在 `Inventory` 中报告它连接 Hub 时本机用的地址；Hub 另外记下它看到的来源地址：在反向代理之后时取 `X-Forwarded-For` 的最后一项（最近的代理加上的那一项），只在 TCP 对端是回环或私有地址（即代理）时采用；自己终止 TLS 时取 TCP 对端的地址。每个地址族：本机报告的是全局单播地址时用它（多数 VPS），否则用 Hub 看到的地址（公网地址不在网卡上的 1:1 NAT 云主机）；回环地址不用。地址变化时 Hub 换代数下发。写明的地址总是优先；Hub 主机自己的成员经本机的代理连接时 Hub 看不到它的公网地址，要写明。公网地址不签名，错了只影响连通，不扩大权限；`nett site status` 列出所用的地址与来源；
- **离线**：Hub 或 nett-node 不在时，组网照常（architecture.md 第 12.2 节）；nett-node 按 protocol.md 第 8 节重连，连上后按代数补齐；
- **Hub 端点**：入网 token 中的地址是公网地址，不经组网；以后增加的备用端点也至少保留一个不经组网（硬性规则 8）。

## 6. 入网

按 auth.md 第 8 节，入网 token 由签名工具代替浏览器生成：

1. **签名工具**：`nett site add <机器>`（接了 Hub、不写 `--keys`）分配节点 ID 和组网地址，生成一把入网密钥（Ed25519），用恢复密钥签名这个节点的初始策略（其中有入网公钥），连同 token 的过期时间推给 Hub，然后打印 token：Hub 地址、Hub 身份公钥、节点 ID、信任锚清单指纹、入网私钥、过期时间，Hub 自签证书时加上证书指纹。入网私钥只在 token 中，签名工具和 Hub 都不保存。`nett site invite <机器>` 换一把新的入网密钥，策略版本加一；入网之前改了这台机器的 Edge、网段，节点策略用同一把入网公钥以新的版本重签，token 照样能用；
2. **节点**：`sudo nett install <token>` 生成身份密钥和组网密钥（已有的沿用，重试时不换），用入网私钥签准入证明，用身份密钥与 token 中的 Hub 公钥做 Noise IK 握手，`Hello` 中带上准入证明（protocol.md 第 3.3 节）；
3. **Hub**：握手中的身份公钥不认识、`Hello` 带着准入证明时按入网处理。站点中这个节点 ID 的机器要正在等待入网、token 没有过期，准入证明要能用它的节点策略中的入网公钥验证，证明中的身份公钥就是握手用的那一把。通过后 Hub 记下准入证明（第 4 节），从此按身份公钥认出这台机器：同一台机器重试时直接认出，别的机器再用这个 token 被拒绝，所以 token 只能用一次；换代数，把准入材料（策略 + 准入证明）下发给其他成员。不通过时以 `ENROLLMENT_REFUSED` 拒绝并说明原因；
4. **节点**：收到第一份期望状态后，核对其中信任锚清单的指纹与 token 中的相同、节点 ID 是自己的，写下期望状态与 Hub 的配置，丢弃入网私钥，安装并启动服务（第 7 节）。之后组网进程照常用信任锚验证全部内容。

接入之前就已是成员的机器沿用站点中登记的公钥（第 3.5 节）；经 Hub 入网的机器，公钥在准入证明中，由签名工具从 Hub 取回（第 4 节）。

## 7. 节点上的进程与权限

| 进程 | 身份 | 说明 |
|---|---|---|
| nett-node | root | 写组网进程的期望状态文件、请它重新加载；以后还要替换可执行文件（升级）。不监听任何端口，不执行 shell，不访问 Docker（硬性规则 1、2、9）；tokio 单线程；空闲 RSS ≤ 5 MB |
| 组网进程 | 不变（Linux 上的专用身份，macOS 上的 root） | 只认它自己验证过的期望状态；本机状态接口只接受 root 和它自己（status.md 第 3 节），nett-node 以 root 连接 |

- `sudo nett install <token>` 在两个平台上做同样的事：生成或沿用密钥，带入网私钥的 token 先按第 6 节入网，把正在运行的 `nett` 复制到固定的位置（已经在那里运行时不复制），写入两个服务的配置，保存 Hub 的配置（地址与 Hub 身份公钥），启动服务。本机已是某个站点的成员（有信任存储或期望状态）时不接受入网 token，要先 `nett leave`；同一台机器重试同一个 token 时照常完成。服务配置的内容只有一个出处：macOS 的 launchd 配置在代码中定义（release.md 第 4 节），Linux 的单元是 `packaging/systemd/` 中的文件，编译时嵌入；
- Linux：程序在 `/usr/local/bin/nett`（单元中的路径）；`nett-node.service` 在 `nett-mesh.service` 之后启动，两者都由 systemd 重启，互不依赖；
- macOS：`io.gotry.nett.node` 与 `io.gotry.nett.mesh` 两个 launchd 服务，都运行 root 专属目录里的副本（release.md 第 4 节）；
- **不接 Hub 时**，不带 token 的 `sudo nett install` 在两个平台上都按 release.md 第 4 节：生成密钥并打印 `nett site add --keys` 要用的一行，导入期望状态（Linux 上站点目录通常不在这台机器上，用 `--config`），写入组网进程的服务并启动。Linux 上由此取代手工复制 systemd 单元；
- **换到另一个 Hub**：已经接入某个 Hub 的机器运行 `sudo nett install <token>` 时，token 中的信任锚指纹必须与本机信任存储中固定的信任锚相同（mesh.md 第 4.2 节）：相同时换成 token 中的 Hub 地址与身份公钥，不同时拒绝，要先 `nett leave`。这一步只能在本机以 root 执行，被攻破的 Hub 做不到（第 8.1 节）；
- **本机有 Hub 的配置时**，不带 token 的 `sudo nett install` 只更新程序的副本和服务配置，程序变了时重启两个服务；它不从站点目录导入期望状态，也不接受 `--config`（第 5 节）。H3 之前的升级：再运行一次安装脚本（第 3.3 节的前半句），然后 `sudo nett install`；用 Homebrew 安装的电脑在 `brew upgrade nett` 之后运行 `sudo nett install`；
- `sudo nett uninstall` 停止并删除两个服务，保留密钥、期望状态和 Hub 的配置，再次 `install` 即恢复；
- `sudo nett leave` 按 auth.md 第 8.3 节退出：有 Hub 的配置时向 Hub 发送 `Leave`（10 秒内连不上时照常往下做，并说明要在电脑上 `nett site remove`）；停止并删除两个服务；拆掉组网接口和过滤规则（Linux 上删除 `nett0` 接口与 nett 的 nftables 表；macOS 上的 utun 接口随组网进程退出消失）；删除密钥、信任存储、期望状态和 Hub 的配置。`/usr/local/bin/nett` 保留，这台机器可以再加入任何一张网；
- 容器内成员：见第 11 节。

## 8. Hub 的运行

- 一个可执行文件 `nett-hub`（ADR 0012）：axum、SQLite + sqlx（architecture.md 第 10 节）；这一步不带前端（不需要 rust-embed、webauthn-rs）；
- **发布与安装**：`nett-hub` 的可执行文件（Linux x86_64、aarch64，静态链接）与容器镜像，与 `nett` 一起发布、同样签名（release.md）。默认用 Compose 运行 nett-hub 与 Caddy，证书由 Caddy 申请；Hub 主机上已经有反向代理时，`nett-hub init` 打印要加进去的配置片段（把 `/api/v1/` 和 `/node/v1/connect` 的 WebSocket 转给 Hub），不改用户自己的配置；
- 原生运行时以专用的低权限用户运行，也可以在容器中运行（Hub 不需要访问宿主）；只监听本机，由反向代理暴露（architecture.md 第 4 节）；
- 保存：站点模型与签名产物、各节点的身份公钥与代数、每台机器最新的状态、最近的事件（每台 100 条，保留 30 天）、一次性 token（只存哈希）。SQLite 显式设置缓存与 mmap 上限；
- 资源：稳定运行 ≤ 30–50 MB（硬性规则 14）；每个节点的连接、消息、队列都有上限（protocol.md 第 11 节）；
- 备份与重建在第 9 节的 H5。

Hub 主机上的命令（命令行的约定同 architecture.md 第 14.3 节）：

| 命令 | 作用 |
|---|---|
| `nett-hub serve` | Hub 服务本身，由 Compose 或 systemd 运行 |
| `nett-hub init --url <地址>` | 第一次初始化：生成 Hub 身份密钥，打印一次性的关联码（第 3.1 节）；Hub 主机上已有反向代理时打印要加进去的配置片段 |
| `nett-hub reset` | 作废与站点的关联：删除站点、各节点的数据和 token，保留 Hub 身份密钥，已接入的机器之后照常能连上；再运行 `nett-hub init` 打印新的关联码 |

### 8.1 更换 Hub 主机

各台机器认的是 Hub 的地址和 Hub 的身份公钥（入网时固定，auth.md 第 8.3 节）。组网不受影响，换主机期间只是修改暂时送不到。

| 情况 | 做法 |
|---|---|
| 旧 Hub 还能用 | 停掉旧 Hub，把它的数据目录（数据库与 Hub 身份私钥）搬到新主机，域名指向新主机：Hub 的身份不变，各台机器自动连上。地址要变时，先经旧 Hub 把新地址加进各台机器的 `hub_endpoints`（protocol.md 第 6 节），送达之后再搬 |
| 旧 Hub 坏了，没有备份（H5 之前） | 新主机上 `nett-hub init`，电脑上 `nett site link`：站点目录中有全部机器和权限（第 4 节）。各台机器还认旧 Hub 的身份，要逐台 `nett site invite <名字>`，在机器上运行打印的 `sudo nett install <token>` 换过去（第 7 节）；机器沿用已有的密钥，不重新入网 |
| H5 之后 | 用加密备份在新主机上重建，各台机器自动连上（protocol.md 第 6.4 节） |

## 9. 分步

每一步做完都能单独使用。

| 步 | 内容 | 做完之后 |
|---|---|---|
| **H1 分发与状态** | 前提：组网进程的信任存储（mesh.md 第 4.2 节），Hub 下发的内容才不会改变验证的基准。`nett-hub` 与节点网关，发布与安装（第 8 节）；站点的命令与 `nett-site` 库（site.md）；`nett site link`、`status`、`invite`（已有的机器）；两个平台上的 `sudo nett install`，带或不带 token（第 7 节）；nett-node 接收期望状态、交给组网进程、上报状态 | 已有的机器接入 Hub；修改之后自动送达；一处看到全部机器 |
| **H2 入网与退出** | 新机器的 `add` 与入网（第 3.3、6 节）；所有平台同一行的入网命令，安装脚本由发布工作流放到项目网站（release.md 第 6 节）；`public` 机器的公网地址由 Hub 得知（第 5 节）；Hub 一侧的入网、退出与地址取回站点（第 4 节）；`nett leave`（第 7 节） | 新机器在电脑上一条命令、在机器上一条命令入网，不用复制公钥；退出的机器可以重新入网 |
| **H3 升级** | `release` 分区：Hub 缓存签名的发布包，nett-node 核对发布签名、只接受更高的版本、失败回滚（auth.md 第 11.3 节、ADR 0020） | 不用逐台下载、替换 |
| **H4 运行时协调** | 节点上报的地址用于候选路径（地址变化自动跟随）；中继分配；两端都是 `dial-only` 时经 Hub 转达切换（`PathSwitch`，mesh.md 第 8.4 节） | 家宽 IP 变化、笔记本换网络不需要重新生成配置；更快地绕开失效的中继 |
| **H5 可用性与多设备** | Hub 的加密备份由节点拉取、重建手册（architecture.md 第 12.3 节，protocol.md 第 6.4 节）；站点状态移到 Hub，多台签名设备各用自己的钥匙（信任锚更新，auth.md 第 11.2 节） | Hub 主机坏了能重建；不只一台电脑能签名 |

以后：Web 控制台与 passkey（ADR 0024），在站点状态移到 Hub（H5）之后，作为同一套 API 上的另一个前端，与命令行修改同一份站点数据；手机的配置在设备凭据与移动网关实现之后（mesh.md 第 13 节），由 `nett site` 的命令生成配置文件与二维码（ADR 0008）。

## 10. 验证

| 层级 | 内容 |
|---|---|
| 单元测试 | 站点模型的组成（与不接 Hub 时写出的期望状态文件逐字节相同）；Hub 对产物的验证（签名错误、版本倒退、同版本不同内容）；token 只能用一次、过期；入网：准入证明签错、身份公钥与握手的不同、机器不在等待入网时都拒绝；Hub 一侧的入网、退出与地址用到推送的站点上与用到站点目录中的结果相同；公网地址的取舍（写明的、本机的全局地址、Hub 看到的、回环）；重新读取的结果（`applied` 带问题、`rejected`、`busy`）映射到 `StateAck`；有 Hub 配置的机器上 `install` 不改动期望状态文件 |
| Hub 集成测试 | 临时 SQLite，经 HTTP 调用真实的路由：关联、推送、权限检查（没有 token、错误的 token） |
| 实验场景 | 在实验拓扑中运行 Hub：推送之后各成员应用、`nett site status` 列出全部机器与链路；Hub 停止时组网照常、修改恢复后补齐；Hub 下发一个没有准入材料的对端或旧版本的产物，成员都拒绝（roadmap M1 验收）；入网；一个成员 `nett leave` 之后其他成员删除它，站点中删除它并清理引用它的规则，同一个名字再次加入得到新的节点 ID |
| 资源 | nett-node 空闲 RSS ≤ 5 MB；Hub 在实验拓扑中的稳定内存 |
| 实际机器 | 用户自己的一台 `public` 主机作为 Hub 主机；已有的成员接入；之后新机器入网 |

## 11. 待定问题

| 问题 | 说明 |
|---|---|
| 容器内成员怎么接 Hub | 镜像里只有一个 `nett`，以组网进程为主进程。可选：容器里也运行 nett-node（需要在容器内同时运行两个进程）；或者宿主上的 nett-node 代管它（经挂载的目录写期望状态、经挂载的本机套接字请它重新加载，不访问 Docker），这时宿主要代它连接 Hub |
| Linux 上期望状态文件的读权限（H1） | 组网进程以 systemd 的 `DynamicUser` 运行，直接读 `/etc/nett/desired.json`，这个文件因此要所有人可读，整张网的结构对本机的普通用户可见（status.md 第 3 节有意只让 root 看到它）。可选：组网进程改用固定的系统用户、文件只给它读；或由 nett-node 经本机接口把期望状态交给组网进程，不经文件 |
| 升级的发布包从哪里来（H3） | Hub 自己从项目网站下载、节点核对签名；或由用户的电脑下载核对后推给 Hub。网络受限的 Hub 主机需要后一种 |
| `public` 机器能否被连入怎样确认 | 得知的公网地址（第 5 节）不一定能从外部连入（防火墙、安全组）。可选：由另一个成员的测量结果判断，在 `nett site status` 中提示 |
| Hub 主机的选择 | 需要一个 `public`、长期稳定、能用 Hub 域名的主机（architecture.md 第 13.5 节）；这也是它成为单点的地方，见 H5 |
