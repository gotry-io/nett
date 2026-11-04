# 0016. macOS 以容器内成员加入组网

- 状态：已采纳
- 日期：2026-11-04；同日修订（写明首版支持的访问方向）

## 背景

原设计中，macOS 用 Rust 用户态 WireGuard 加 utun 加入组网。这要求 M2 在 macOS 上实现用户态数据面，而且它与代理类 VPN 应用（增强模式会接管路由）能否共存，一直没有验证。

实测（design/overview.md 第 11 节）：

- 在 macOS 的 Docker（OrbStack）容器中运行内核 WireGuard，宿主开着代理类 VPN 应用的增强模式时工作正常，UDP 直接发出；
- macOS 上 Docker 的发布端口会丢掉访问来源，只有让组网端点进入容器网络，才能让容器中的服务认出 Edge（ADR 0015）。

## 决定

- M2 中，macOS 主机以**容器内成员**的方式加入组网：在 Docker 的 Linux 虚拟机中运行一个 Linux 成员，使用内核 WireGuard，由 nett 以容器的形式提供；
- 它是一个独立的节点身份，只开启 mesh 模块；宿主上原生运行的 nett-node（launchd）继续负责 metrics 和 deploy；
- 容器内成员可以接入宿主上的容器网络，作为 ADR 0015 中的回源端点；
- 访问宿主上的原生服务时，使用宿主的局域网地址，绝不使用 `host.docker.internal`；
- **方向**：首版只保证"其他成员访问这台 Mac 上的服务"。Mac 宿主上的程序主动访问组网，需要一条从宿主到容器内成员的路由：OrbStack 的宿主能直接访问容器地址，Docker Desktop 默认不能。M2 分别实测后再决定是否支持；在此之前，宿主需要访问组网时，可以用标准 WireGuard 客户端以设备身份接入；
- macOS 原生方案（用户态 WireGuard + utun）推迟到需要支持笔记本这类不运行 Docker 的场景时再做。

## 理由

- 内核 WireGuard 加上 Linux 的过滤与地址转换，与其他 Linux 成员共用一套实现，M2 不需要 macOS 用户态数据面；
- 与代理类 VPN 应用的共存有实测依据；
- 顺带解决了容器服务的真实 IP 问题。

## 放弃的方案

- **原生 utun**：少一个运行环境，但 M2 的工作量和不确定性都更大。保留为后续方案。
- **macOS 不加入组网，只经家里的智能入口访问**：服务都在 Mac 上时，所有流量都要多绕一个设备，而且发布端口丢失来源的问题依然存在。

## 影响

- 依赖宿主上的 Docker 运行时（OrbStack 或 Docker Desktop）；Docker 停止时，这个成员也会离线；
- 同一台 Mac 对应两个节点（原生和容器内），控制台需要把它们显示为同一台主机；
- 用户态 WireGuard 在 M2 只需要覆盖 Synology DSM 和旧内核的 Linux。
