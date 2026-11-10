# 本机状态与 `nett status`

- 状态：草案
- 阶段：M1，本地签名部署之后、接入 Hub 之前（roadmap M1）

## 1. 目标

在节点上一条命令看清组网现在怎样：本机的地址和运行方式，每个对端是否连通、走哪条路径、质量如何、最近为什么切换，以及期望状态和访问规则有没有被拒绝。不依赖 Hub，现有的节点马上能用。

状态来自组网进程的本机接口。这就是 ADR 0013 中 nett-node 与组网进程之间的本机接口：这一步实现它的只读查询；接入 Hub 之后，nett-node 经同一个接口读取链路状态、上报 Hub（`LinkReport`，protocol.md 第 5 节），并在这里加上期望状态的交付和身份查询（mesh.md 第 11 节）。

## 2. 范围

| 包含 | 不包含 |
|---|---|
| 组网进程的本机套接字：只读的状态查询 | 经接口交付期望状态、身份查询（`whois`）：接入 Hub 时加入 |
| 期望状态带上节点名（不签名，只用于显示，第 5 节） | 主机名解析与 DNS（mesh.md 第 11 节） |
| `nett status`、`nett status <对端>`、`--json` | `nett doctor`、持续刷新的视图 |
| Linux（内核与用户态 WireGuard）、macOS、容器内成员 | |

## 3. 本机套接字

- **位置**：Unix 套接字，Linux 和容器内成员为 `/run/nett/mesh.sock`，macOS 为 `/var/run/nett/mesh.sock`。`nett mesh --socket <路径>` 可以改到别处（实验场景中同一台主机上有多个成员），`nett status --socket <路径>` 与之对应；
- **权限**：目录 `0700`、套接字 `0600`，属于组网进程的运行身份；组网进程另按对端凭据（Linux 的 `SO_PEERCRED`、macOS 的 `getpeereid`）只接受 root 和它自己的运行身份。`nett status` 因此要用 `sudo` 运行，容器内成员用 `docker exec <容器> /nett status`（以容器内的 root 运行）。状态中没有密钥，但有各成员的公网地址、宣告的网段和访问规则版本，也就是整张网的结构：本机的普通用户和程序看不到它；
- **建立**：套接字只供查看，建不起来时组网进程记录一条警告，组网照常（硬性规则 8）。路径上已有套接字时先尝试连接：有进程应答就不接管；没有应答（上一次异常退出留下的）则删除后重新建立；路径上是别的文件时不动它。套接字先在临时名字上建立、设为 `0600`，再改名到约定的路径，出现时就已经是 `0600`。组网进程退出时删除它。目录不存在时以 `0700` 建立：Linux 的 systemd 单元用 `RuntimeDirectory=nett` 预先建立，macOS 和容器中由组网进程自己建立；
- 套接字只在本机，不是网络监听（硬性规则 2）。

## 4. 消息与版本

- 一个连接一次查询：客户端发送一行 JSON，组网进程回复一份 JSON 后关闭连接。

  ```json
  {"v": 1, "query": "status"}
  ```

- `v` 是接口的主版本，回复带同一个 `v`。同一主版本内只增加字段：客户端忽略不认识的字段，缺少的字段显示为 `-`。这样升级之后、组网进程重启之前，新的 `nett` 也能读旧进程的状态（相邻版本互通，ADR 0013）；
- 主版本不同、查询不认识、请求不是合法的 JSON 时，回复错误并关闭连接：

  ```json
  {"v": 1, "error": {"code": "unknown_query", "message": "unknown query `stats`"}}
  ```

- 请求按不可信的输入校验（硬性规则 13）：最长 1 KiB，1 秒内读不完整就关闭连接。

## 5. 节点名

期望状态增加一项不签名的 `names`：节点 ID 到节点名的映射。`nett site apply` 按站点描述写入；接入 Hub 之后由 Hub 下发，与主机名同一出处（mesh.md 第 11 节）。

```json
"names": { "node_01JC…": "edge-vps", "node_01JD…": "mac-app" }
```

- 节点名只用于显示和定位，不作为身份依据：名字不对，也不会让任何对端被配置或被放行。需要确认对方是谁时用节点 ID，以及以后的身份查询（mesh.md 第 11 节）；
- 格式与站点描述中的节点名相同：小写字母、数字和 `-`，最长 63 个字符；格式不对时整份期望状态被拒绝，继续使用上一份（local-signing.md 第 5 节）。没有名字的节点显示节点 ID；
- 期望状态多了一个字段：先升级节点上的 `nett`，再换上新生成的期望状态。旧版本拒绝不认识的字段，这期间继续使用上一份期望状态。

## 6. 状态内容

时间为 UTC，格式为 RFC 3339；时长、相对时间由 `nett status` 按本机时钟换算。

| 部分 | 内容 |
|---|---|
| `node` | 节点 ID 与名字、`nett` 版本、组网地址、Edge 专用地址（有 `edge` 角色时）、可达性、数据面（`kernel` / `userspace`）、WireGuard 端口、NAT 类型与映射地址（mesh.md 第 6.1 节）、时钟是否可信（mesh.md 第 8.4 节）、组网进程启动的时间 |
| `config` | 生效的期望状态被接受的时间；访问规则集的版本。被拒绝的期望状态列在 `problems` 中（重新加载失败时，继续使用的是上一份） |
| `peers` | 每个已准入的成员一项，见下表 |
| `problems` | 需要处理的情况，每项带时间和原因：本机不在已准入的成员中、期望状态被拒绝、成员的准入材料被拒绝、访问规则集或宣告网段被拒绝、数据面操作失败。前五种属于一份期望状态：下一份期望状态被接受时作废，仍然存在的在应用时重新报告（验证失败的材料每次应用都会报告）。数据面操作失败后自动重试，最近 5 分钟内发生过就列出，持续失败时一直在列 |
| `events` | 组网进程最近的 32 个事件（路径切换、打洞、准入与拒绝等，与日志中的事件相同），供排查最近的切换 |

每个对端：

| 字段 | 内容 |
|---|---|
| `id`、`name` | 节点 ID 与名字 |
| `mesh`、`edge`、`routes` | 组网地址；Edge 专用地址（有 `edge` 角色时）；它宣告的网段 |
| `state` | `connected`：最近 30 秒内收到过对端的包；`connecting`：在向它发送，还没有收到过；`unreachable`：在向它发送，曾经收到过，最近 30 秒内没有；`idle`：两个方向最近 30 秒内都没有包（没有流量时不探测，无从判断；`dial-only` 一端每 25 秒保活，mesh.md 第 4 节，所以只在两个 `public` 节点之间出现）；`no_path`：期望状态中没有到它的路径（站点描述中没有这一对的 `link`），也没有收到它的包 |
| `path` | 当前路径：`kind`（`lan` / `direct` / `relay` / `relay_tls`）、经过的中继、WireGuard 中的 endpoint、是否打洞得到（`punched`）、切到它的时间与原因。跟随方不选路，路径按 WireGuard 当前的 endpoint 判断：是本机候选中某个中继的地址时为经这个中继，否则为直连；没有切换的时间与原因 |
| `rtt_ms`、`loss`、`jitter_ms` | 当前路径上隧道内探测的往返时间、最近 10 次的丢包率与抖动（mesh.md 第 7 节）。本机经漫游跟随时不探测，为空；双方都是 `dial-only` 时两端都测量 |
| `last_handshake`、`last_received`、`rx_bytes`、`tx_bytes` | WireGuard 最近一次完成握手的时间；最近一次收到对端的包的时间；收发字节数 |
| `role` | 这一对中本机的角色：`decider`（决定路径、发探测）/ `follower`（经漫游跟随，mesh.md 第 8.3 节）；`public` 与 `dial-only` 之间由 `dial-only` 一端决定 |
| `candidates` | 决定方上每条候选路径：类型、中继、地址、往返时间、丢包率，以及 `current` / `ok` / `failing` / `untested` |

状态中不出现私钥、探测令牌、签名和证书指纹之外的任何凭据内容（硬性规则 10）。

## 7. `nett status`

按 architecture.md 第 14.3 节的写法输出英文。

### 7.1 总览

```
$ sudo nett status
node     mac (node_01JD7M3XQ4W8N2K5R9T6V3B7C1)
version  nett 0.2.0
mesh     100.88.0.4, fd00:88::4
network  dial-only, userspace WireGuard, port 53557
nat      cone, 198.51.100.7:53557
config   applied 3h ago, access rules v3

PEER      ADDRESS     STATE        PATH                RTT     LOSS  HANDSHAKE
edge-vps  100.88.0.1  connected    direct              9.4 ms  0%    41s ago
laptop    100.88.0.5  unreachable  relay vps-02 (tls)  -       -     2h ago
mac-app   100.88.0.3  no path      -                   -       -     -
vps-02    100.88.0.6  connected    direct              31 ms   <1%   12s ago
```

- 头部是本机，每行一项；没有的项不显示（例如没有 `edge` 角色时没有 `edge` 一行，`public` 节点没有 `nat` 一行）；
- 对端按名字排序；`PATH` 写类型和经过的中继，打洞得到的直连写 `direct (punched)`；
- 本机是跟随方的对端（例如 `public` 节点上它的 `dial-only` 对端），`RTT`、`LOSS` 为 `-`：只有决定方测量，在对端上查看；
- 有 `problems` 时在最后列出，每项一行，带相对时间：

  ```
  PROBLEMS
  2m ago  desired state rejected, still using the previous one: listen port 41821 is one nett itself uses on this host: …
  ```

- 时钟误差超过 2 秒时（mesh.md 第 8.4 节）头部多一行 `clock  not synchronized`；本机不在已准入的成员中时 `mesh` 一行写 `not admitted`；

- 往返时间不到 10 毫秒保留一位小数，其余取整；丢包率取整，不到 1% 但不为 0 时写 `<1%`；字节数用十进制单位（`13.2 MB`）；相对时间写成 `41s ago`、`5m ago`、`2h ago`、`3d ago`；
- 不是终端时输出相同，不截断，不加颜色。

### 7.2 一个对端

```
$ sudo nett status edge-vps
peer       edge-vps (node_01JC4QK2ZB8X5R3N9T7V6W2Y1H)
mesh       100.88.0.1, fd00:88::1
edge       100.88.0.2, fd00:88::2
state      connected
path       direct 203.0.113.10:41820, since 2h ago (better path type)
quality    rtt 9.4 ms, loss 0%, jitter 0.3 ms
handshake  41s ago
received   1s ago
traffic    13.2 MB in, 10.1 MB out
role       decider

CANDIDATE     ADDRESS              RTT     LOSS  STATE
direct        203.0.113.10:41820   9.4 ms  0%    current
relay vps-02  198.51.100.20:41822  12 ms   0%    ok

EVENTS
2h ago  path switched to direct 203.0.113.10:41820 (better path type)
2h ago  path switched to relay 198.51.100.20:41822 (unreachable)
```

参数是对端的名字或节点 ID；找不到时报错并列出已有的对端。事件按新到旧排列，只列与这个对端有关的；事件中的路径与日志相同，写的是地址。本机是跟随方时没有 `quality`、候选路径和切换原因，`role` 一行写 `follower (edge-vps measures and chooses the path)`。

### 7.3 `--json` 与退出码

- `--json` 输出组网进程回复的整份状态（第 6 节），字段名与版本按第 4 节保持稳定；与对端名一起用时只输出这个对端；
- 退出码：拿到状态为 0，即使有对端不通；连不上组网进程、权限不够、找不到对端为 1。错误写到标准错误：

  ```
  nett: the mesh service is not running (no socket at /run/nett/mesh.sock)
  nett: the mesh service is not running (/run/nett/mesh.sock does not accept connections)
  nett: permission denied for /run/nett/mesh.sock; run with sudo
  ```

## 8. 实现与资源

- 组网进程多一个线程接受连接，逐个处理：读请求，向运行时的后台线程发一个查询（经已有的有上限队列），后台线程从引擎、选路状态和数据面的对端统计生成一份快照交回，再写回客户端。队列满、或 2 秒内交不出快照（例如正在应用期望状态）时回复 `busy`；读写各 1 秒超时。回复之后先关闭写方向，再丢弃对方没被读走的输入（最多 64 KiB）：带着未读数据关闭时，Linux 向对方发送复位，对方可能读不到回复；
- 接受连接的线程每 500 毫秒检查一次是否该退出，不依赖套接字文件还在（文件被删掉时退出不会卡住）；
- 事件环形缓冲 32 项；`problems` 中期望状态、访问规则集各一项，成员与宣告网段各最多 32 项（硬性规则 14）；回复最长 4 MiB，`nett status` 也只读这么多；
- 接受连接的线程用 256 KiB 的栈（只占用实际用到的页）；空闲时多出的内存目标在 100 KB 以内，在 Linux（RSS、PSS）和 macOS（RSS、`footprint`）上实测；
- `nett status` 只读，不改变组网进程的任何状态。

## 9. 验证

| 层级 | 内容 |
|---|---|
| 单元测试 | 快照生成（对端的各种状态与路径、跟随方没有探测数据、没有路径的对端）；序列化结果中没有私钥和探测令牌；请求的校验（过长、不是 JSON、版本不对、不认识的查询、超时）；`nett status` 的排版（单位、精度、相对时间、缺少的字段、`problems`），用固定的状态文档比对输出 |
| 实验场景 | 在准入场景（`admission`，CI 中的三种拓扑都运行）中，各成员的 `nett status --json` 列出其他成员和它们的名字，刚连通的一对状态为 `connected`、有路径，反例在第一个成员上列为 `member_rejected`；用户态成员上同样可读。场景失败时附上的现场中有各成员的状态（用户态成员上没有 `wg show`） |
| 实际机器 | edge-vps（内核 WireGuard）、Mac 原生成员（用户态）、mac-app（容器内成员）上运行 `nett status`，与 `wg show` 和日志对照；非 root 运行时得到权限错误 |
| 资源 | 第 8 节的内存目标 |

## 10. 待定问题

| 问题 | 说明 |
|---|---|
| 非 root 用户查看状态 | 目前只有 root。需要时可以加一个组（例如 macOS 的 `admin`），只开放查询，不开放以后的期望状态交付 |
