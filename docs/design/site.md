# 站点：用命令维护整张网

- 状态：草案
- 阶段：M1，与接入 Hub 的 H1 一起（hub.md 第 9 节）；不接 Hub 的站点同样使用

## 1. 目标

用户在自己的电脑上用 `nett site` 的命令维护整张网：加入、移除机器，设置 Edge 和宣告的网段，增删访问规则。命令行是唯一的操作界面（ADR 0024），做法参考 ufw：规则一条一条地加，列出时带编号，按编号删除。

- 每条修改命令当场校验，列出要签名的内容（选择器展开后的地址和端口），确认后签名并送达：接了 Hub 时推送给 Hub（hub.md 第 3.2 节），没接时写成各节点的期望状态文件（local-signing.md 第 5 节）；
- 接不接 Hub 用同一套命令、同一份站点状态；
- 哪些机器之间建立连接由访问规则推导，用户不用逐对指定（第 6 节）。

## 2. 分工

| 内容 | 怎么维护 | 签名 |
|---|---|---|
| 机器：名字、可达性、公网地址与端口 | `add`、`set`、`remove` | 不签名；移除生成撤销记录 |
| 机器的公钥 | 不接 Hub 时 `add --keys`；接了 Hub 时由机器入网时交给 Hub（hub.md 第 6 节） | 写入准入材料 |
| 权限：Edge、宣告的网段、访问规则 | `edge`、`routes`、`allow`、`rules remove` | 放宽与收窄都以新的版本签名（第 7 节） |
| 连接与候选路径 | 由访问规则推导（第 6 节） | 不签名 |

站点的全部内容由工具保存在站点目录中（第 8 节），没有需要手工编辑的文件。规则按机器 ID 记录：移除一台机器时，引用它的规则随之清理，以后用同一个名字加入的机器不会继承它们（第 4 节）。

## 3. 命令

| 命令 | 作用 |
|---|---|
| `nett site init` | 建立站点：恢复密钥、信任锚清单、组网网段（第 8 节） |
| `nett site add <机器>` | 加入一台机器（第 4 节） |
| `nett site set <机器>` | 改一台机器的可达性、公网地址与端口 |
| `nett site remove <机器>` | 移除一台机器，连带清理引用它的规则 |
| `nett site invite <机器>` | 为已加入的机器准备入网所需的东西：接了 Hub 时打印入网命令（hub.md 第 3.3、3.5 节），没接时重签并重写它的期望状态文件 |
| `nett site edge <机器>` | 设置这台机器的 Edge 来源（第 5.2 节） |
| `nett site routes <机器>` | 设置这台机器宣告的网段（第 5.2 节） |
| `nett site allow` | 加一条访问规则（第 5.1 节） |
| `nett site rules` | 列出访问规则；`nett site rules remove <编号>` 删除一条 |
| `nett site status` | 列出全部机器；接了 Hub 时加上各台的在线状态和每对机器之间的路径（hub.md 第 3.4 节） |
| `nett site link` | 与 Hub 关联（hub.md 第 3.1 节） |

- 只在持有站点的那台电脑上运行，以普通用户身份，不需要 `sudo`；站点目录默认是 `$XDG_CONFIG_HOME/nett`（没有设置时是 `~/.config/nett`），`--dir` 可以放在别处；
- 修改命令（`add`、`set`、`remove`、`edge`、`routes`、`allow`、`rules remove`）按第 7 节列出变化、确认、签名、送达；不是终端时要加 `--yes`；
- 查看命令（`rules`、`status`）加 `--json` 输出完整内容。

## 4. 机器

```
$ nett site add edge-vps --public --ipv4 203.0.113.10 --keys "…"
+ edge-vps (public, 203.0.113.10:41820), 100.88.0.1
Sign? [y/N] y
Wrote the desired state for edge-vps in ~/.config/nett/nodes/<machine>/desired.json.
```

- **名字**：小写字母、数字和 `-`，最长 63 个字符（status.md 第 5 节），站点内唯一。名字用于显示和在命令中指代机器，不作为身份依据；
- **可达性**：`--public` 表示能被外部连入，其他成员按它的公网地址连它；不写时为 `dial-only`，只主动连出（mesh.md 第 2 节）。`public` 机器用 `--ipv4`、`--ipv6` 写明公网地址；接了 Hub 时可以不写，由 Hub 得知（hub.md 第 11 节）；
- **端口**：`public` 机器的 WireGuard 端口默认是 `41820`，`--port` 改用别的（例如同一台主机上有两个 `public` 成员）。端口不能是组网进程自己在本机用的端口：组网地址上的探测端口 `41821`（mesh.md 第 7.2 节）和 TLS 中继的回环端口（`41830`–`41845`，mesh.md 第 5.3 节）；WireGuard 的套接字绑定本机全部地址，相同时后绑定的一方失败。`dial-only` 机器的端口由系统分配（mesh.md 第 5.5 节），不写端口和公网地址；
- **公钥**：不接 Hub 时 `--keys` 必填，是机器上 `nett keys`（macOS 上 `sudo nett install`）打印的一行。接了 Hub 时不写：公钥由机器入网时交给 Hub（hub.md 第 6 节）；
- **加入**时分配节点 ID 和组网地址，签名它的节点策略；地址不回收（mesh.md 第 3 节）。`set` 改可达性、公网地址与端口，这些不签名，同样先列出、确认，再送达；
- **移除**（`remove`）是降低权限，从不因为别的原因被挡住：机器被攻破时，移除必须马上生效。工具生成身份撤销记录，所有成员删除这台机器，任何版本的签名产物都不能恢复它（auth.md 第 10.4 节）；规则中引用它的部分随之删除（第 5.1 节），并在输出中列出：

  ```
  $ nett site remove nas
  - nas (node_01JD…): every member drops it
  Access rules v5 -> v6:
    - r5  mac (100.88.0.4) -> nas (100.88.0.6)  22/tcp
  Connections:
    - mac - nas
  Sign? [y/N] y
  ```

- 同一个名字以后再 `add` 时是一台新机器：新的节点 ID 和地址，没有原来的规则、Edge 和网段。机器自己退出（`nett leave`，auth.md 第 8.3 节）时按同样的方式处理（hub.md 第 4 节）。

## 5. 权限

### 5.1 访问规则

```
$ nett site allow edge-vps.edge mac-app.routes 8686/tcp --note "web app"
Access rules v3 -> v4:
  + r4  edge-vps.edge (100.88.0.130) -> mac-app.routes (172.30.0.10/32)  8686/tcp  web app
Sign? [y/N] y

$ nett site rules
ID  FROM           TO              PORTS     NOTE
r2  edge-vps.edge  mac             3000/tcp
r4  edge-vps.edge  mac-app.routes  8686/tcp  web app

$ nett site rules remove r2
```

- **选择器**：`<机器>` 是它的组网地址，`<机器>.edge` 是它的 Edge 专用地址，`<机器>.routes` 是它宣告的网段；一边有多个时用逗号分隔，例如 `mac,nas`。选择器在签名工具中展开，签名产物写展开后的地址和端口（mesh.md 第 12 节）；
- **端口**：`<端口>[-<端口>]/<tcp|udp>`，多个用逗号分隔；不写时为全部端口，列出变化时写明 `all ports`；
- **说明**：`--note` 写这条规则做什么，只保存在站点中，不进签名产物；
- **编号**：`r1`、`r2`……按加入的顺序分配，删除之后不复用，所以一个编号始终指同一条规则；
- **只有放行，没有顺序**：任何一条规则匹配就放行，规则之间互不影响，加、删一条都不用考虑位置。签名产物的格式支持拒绝规则和按顺序匹配（mesh.md 第 12 节）；签名工具只生成放行规则，按编号排列；
- **引用的东西没了**：一条规则引用的机器被移除、Edge 或网段被去掉时，规则中引用它的选择器随之删除；一边只剩空时，整条规则删除。这些都属于收窄，列在同一次变化中；
- 删除规则是收窄，以新的版本签名（第 7 节）；同样先列出、确认：删错一条规则会断掉正在使用的服务。

### 5.2 Edge 与宣告的网段

```
$ nett site edge edge-vps 172.17.0.2/32
$ nett site routes mac-app 172.30.0.10/32
```

- **Edge**：写 Edge 所在容器的地址（ADR 0015，local-signing.md 第 6 节）。这台机器的节点策略带上 `edge` 角色，并分配一对 Edge 专用地址；
- **宣告的网段**：这台机器的节点策略带上 `subnet_router` 角色，网段另签一份带版本号的产物（auth.md 第 10.5 节）。网段不能与组网网段或其他机器宣告的网段重叠；
- 每次写这台机器的完整列表；`--none` 去掉。节点策略与宣告的网段随之以新的版本签名（第 7 节），去掉时引用它的规则按第 5.1 节清理。

## 6. 连接

组成期望状态时（接了 Hub 时由 Hub 用同一份逻辑组成，hub.md 第 4 节），按下面的规则决定哪些机器之间建立连接：

1. **访问规则涉及的每一对机器**：规则两边的每个选择器对应一台机器（`<机器>`、`<机器>.edge`、`<机器>.routes` 都对应这台机器本身），两边的每一对之间建立一条连接，机器自己与自己除外；
2. **每个 `dial-only` 成员与全部 `public` 成员**：用于判断 NAT 类型和映射地址（mesh.md 第 6.1 节），也是故障时的冗余（architecture.md 第 12.3 节）；
3. 每条连接的候选路径按 mesh.md 第 6 节生成：一端是 `public` 时，另一端直连它的公网地址（有 IPv4、IPv6 地址时分别生成）；两端都是 `dial-only` 时打洞直连；经中继的候选在中继实现之后加入。

- 连接只是通道：访问仍由规则决定，默认拒绝（ADR 0023）。没有规则涉及的两台机器之间没有连接，`nett status` 中这一对为 `no path`；
- 两端都是 `dial-only` 的连接只有打洞候选：两端都在对称型 NAT 后时打不通（mesh.md 第 6.1 节），经中继的候选加入之前可能连不上。列出变化时为这样的连接写明 `punch only; may not connect`；
- 规则变化时，连接随之增减，列在同一次变化中：

  ```
  $ nett site allow mac nas 22/tcp
  Access rules v4 -> v5:
    + r5  mac (100.88.0.4) -> nas (100.88.0.6)  22/tcp
  Connections:
    + mac - nas  punch only; may not connect
  Sign? [y/N] y
  ```

## 7. 修改、签名与送达

每条修改命令：读取站点状态 → 算出修改之后的状态并校验 → 列出变化 → 确认 → 签名 → 送达 → 保存站点状态。

- **列出的就是要签名的内容**：选择器展开后的地址和端口、产物的版本变化、增减的连接与成员；放宽的项目以 `+` 标出，收窄的以 `-` 标出，其余的变化以 `~` 标出；
- **签名**：内容变化的产物版本加一并重新签名，不变的沿用原来的签名，节点视为幂等（auth.md 第 10.2 节）；已签的节点策略离过期不到 7 天的，换一个新版本重签（local-signing.md 第 5 节）；
- **收窄**：移除机器生成身份撤销记录（auth.md 第 10.4 节）；删除规则、去掉 Edge 或网段以更高的版本重新签名。节点按版本只增不减（mesh.md 第 4.2 节），重发旧的签名产物不能恢复被收窄的权限；
- **送达**：接了 Hub 时推送给 Hub，等待各台机器应用（hub.md 第 3.2 节）；没接时为期望状态有变化的每台机器重写 `nodes/<机器>/desired.json`，列出这些机器和应用的方法（local-signing.md 第 5 节）；
- 校验失败时整条命令不做任何改动，说明哪里不对；
- 站点目录加锁，同一时间只有一个修改命令在运行。

## 8. 站点目录

```
$ nett site init
Created a site in ~/.config/nett.
recovery.pk8 signs everything in this network. Back it up offline now:
without it, every machine has to leave and join again.

Next, for each machine:
  1. On the machine, create its keys:
       macOS  sudo nett install
       Linux  sudo nett keys --dir /etc/nett
  2. Here: nett site add <name> --keys "<the printed line>"
     (with --public --ipv4 <address> when other machines connect to it)
  3. Allow what may connect: nett site allow <from> <to> <ports>
```

- `init` 建立目录时权限设为 `0700`。组网网段在建立时确定，之后不能改：IPv4 为 `100.88.0.0/16`，IPv6 为随机生成的 ULA `/48`（mesh.md 第 3 节）；
- 目录中有：恢复密钥 `recovery.pk8`（`0600`，只在签名时读取）；站点状态 `state.json`：信任锚清单、组网网段、各台机器（节点 ID、名字、可达性、地址与端口、公钥、Edge、网段、已签的产物与版本）、访问规则（编号、选择器、端口、说明，以及展开后签名的规则集与版本）、撤销记录、已分配的地址；不接 Hub 时还有生成的期望状态 `nodes/<机器>/desired.json`；
- 备份这个目录即可，恢复密钥另存一份离线备份（local-signing.md 第 3 节）。接了 Hub 时，Hub 保存最近一次推送的副本，经 Hub 入网的机器的准入证明也取回保存在这里（hub.md 第 4 节），站点状态以这个目录为准。

## 9. 验证

| 层级 | 内容 |
|---|---|
| 单元测试 | 每条修改命令对站点状态的改变与列出的变化；校验失败时不做改动；编号不复用；移除机器、去掉 Edge 或网段时引用它的规则随之清理，同名的新机器拿到新的节点 ID 和地址、没有旧规则；连接的推导（规则涉及的每一对、`dial-only` 到全部 `public`、候选路径）；放宽与收窄的划分；不变的产物沿用原来的签名；不是终端又没有 `--yes` 时不修改；生成的期望状态能被组网进程接受 |
| CI | macOS 的安装流程（release.md 第 4 节）用 `nett site add` 加入本机 |
| 实际机器 | 把已有的站点换成命令维护之后，各成员的期望状态中签名产物的版本、地址与连接不变 |
