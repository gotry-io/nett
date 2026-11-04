# 0017. Home Assistant OS 上以加载项运行

- 状态：已采纳
- 日期：2026-11-04

## 背景

nett 按开源项目设计，需要覆盖家庭用户常见的设备。Home Assistant OS（HAOS）运行在树莓派、迷你主机、官方硬件或虚拟机上，通常常年开机，并且就在家里的局域网中，很适合做组网成员和智能入口。

但 HAOS 是封闭的系统：没有包管理器，用户不能在系统上直接安装程序，所有扩展都以**加载项**（add-on，由 HA 的 Supervisor 管理的容器）的形式运行。architecture.md 第 3 节要求 nett-node 直接运行在系统上，这在 HAOS 上做不到。

在普通 Linux 上运行的 Home Assistant（Container 或 Core 安装方式）不受影响，所在主机按普通 Linux 节点处理。

## 决定

- 在 HAOS 上，nett 以**加载项**的形式提供：项目维护一个 HA 加载项仓库，镜像覆盖 HA 支持的架构（amd64、aarch64）；
- 加载项申请运行所需的最小权限：宿主网络、`NET_ADMIN`、`/dev/net/tun`。加载项内运行 nett-node（组网使用 HAOS 内核自带的 WireGuard），需要时也运行 nett-relay；
- 模块范围：

| 模块 | 在 HAOS 上 | 说明 |
|---|---|---|
| metrics | ✅（受限） | 主机、加载项和 HA Core 的资源数据从 Supervisor 接口读取；读不到的项（如 SMART）由能力探测标为不可用 |
| mesh | ✅ | 组网成员、智能入口、移动网关都可以 |
| relay | ✅ | 需要路由器映射端口 |
| deploy | ❌ | HAOS 上的加载项由 HA 自己管理，nett 不插手；本地硬性禁止 |
| ingress | ❌ | 不在 HAOS 上运行 Edge |

- 升级：加载项的版本跟随 nett 发布，节点上的版本规则（只自动接受更高的版本、发布签名验证）不变；加载项镜像本身也要签名；
- 节点的 `status.install_method` 记为 `haos_addon`，控制台据此只显示可用的模块。

## 理由

- 加载项是 HAOS 上唯一被支持的扩展方式，HA 上已有的组网类加载项也是这样运行的；
- 智能入口需要的内核 WireGuard、TUN、IP 转发和 NAT，在宿主网络加 `NET_ADMIN` 下都能使用；
- deploy 与 HA 自己的加载项管理冲突，关掉它比勉强支持更安全。

## 放弃的方案

- **要求用户在 HAOS 上打开调试模式、直接安装**：不被 HA 支持，升级 HAOS 后会丢失。
- **申请最高权限（关闭保护模式、访问 Docker）**：能拿到更多数据，但会削弱 HAOS 自身的安全边界，与"安全默认"冲突。
- **只支持 HA 的 Container / Core 安装方式**：覆盖不到使用最广的 HAOS。

## 影响

- 发布物增加 HA 加载项镜像与加载项仓库（ADR 0012）；
- architecture.md 中"nett-node 必须直接运行在系统上"增加 HAOS 这一例外；
- 能拿到哪些数据、Supervisor 接口的权限范围，需要在 HAOS 上实测后写进 M1 的观测设计。
