# 0002. Hub 和 node 使用 Rust

- 状态：已采纳
- 日期：2026-10-12

## 背景

node 要常驻在 1 vCPU / 1 GB 级别的机器上，资源占用是硬性约束。

## 决定

Hub 和 node 都用 Rust 编写。node 使用 tokio 单线程运行时。

## 理由

同一负载（每秒采集一次 CPU 和内存，并发一次本地 HTTP 请求）下的空闲常驻内存，Linux arm64、容器限制 1 CPU / 1 GB、运行 60 秒：

| 实现 | VmRSS |
|---|---|
| Rust（tokio + reqwest/rustls + sysinfo） | 1.9 MB |
| C++（libcurl 静态，含 TLS） | 4.9 MB |
| Go（net/http + gopsutil） | 7.5–8.6 MB |
| Swift（SwiftNIO 或 Foundation） | 28–35 MB |

- Rust 的内存最低，并且具备内存安全；
- 强类型和编译期检查能拦截大量错误，对以审查为主的开发方式是一层保障；
- 以后的私有传输和移动端隧道核心也可以用同一套 Rust 代码（iOS 网络扩展有严格的内存上限）。

## 放弃的方案

- **Go**：生态最全（可嵌入 Tailscale、官方 Compose SDK），但内存约为 Rust 的 4 倍。在本项目的架构下（组网后端作为独立进程托管，部署调用 `docker compose` CLI），Go 的独有优势大多用不上。
- **C++**：内存与 Rust 相当，但缺乏内存安全；以 root 运行并解析网络数据的组件风险过高。
- **Swift**：Linux 上 Foundation 体积大且依赖大量系统库，缺少 Docker、系统指标等生态。

## 影响

- 开发速度比 Go 慢；交叉编译需要 musl 工具链或 cargo-zigbuild。
- Docker 通过 socket API 直接调用，Compose 通过 CLI 调用。
