# 发布与安装

- 状态：草案
- 阶段：M1（roadmap M1 "安装"一项中的发布工作流与 Homebrew）

## 1. 目标

推送版本标签后，CI 构建各平台的 `nett`，用项目的发布钥匙签名（ADR 0020），发布 GitHub Release，并更新 Homebrew 配方。macOS 用户用 Homebrew 安装和升级；Linux 服务器用发布包手动安装。经 Hub 分发的安装脚本和节点的自动升级在接入 Hub 时实现，不在本文范围内。

## 2. 版本与产物

- 版本号遵循语义化版本，等于工作区 `Cargo.toml` 中的 `version`；标签写作 `v<版本号>`，两者不一致时发布工作流失败。用户可见的变化记在 `CHANGELOG.md`；
- 每个目标平台一个压缩包 `nett-<版本号>-<目标>.tar.gz`，内含 `nett`、`LICENSE-MIT` 与 `LICENSE-APACHE`：

| 目标 | 用途 |
|---|---|
| `aarch64-apple-darwin`、`x86_64-apple-darwin` | macOS 原生成员与签名工具（Homebrew） |
| `x86_64-unknown-linux-musl`、`aarch64-unknown-linux-musl` | Linux 服务器（静态链接）与容器内成员的镜像 |

- 每个压缩包有同名的 `.minisig`；`SHA256SUMS` 列出所有压缩包的哈希，同样签名。用户可以用 `minisign -V -p keys/nett-release-primary.pub -m <文件>` 核对。

## 3. 发布工作流

`.github/workflows/release.yml`，由 `v*` 标签触发（标签受规则集保护，ADR 0020）。各任务只授予需要的最小权限，第三方 action 固定到提交哈希：

1. **构建**：各平台的原生运行器（macOS arm64、Linux x86_64 与 arm64）构建 release 版本并打包，核对标签与工作区版本一致；
2. **签名**：在 `release` 环境中运行，只接收构建任务产出的压缩包，下载固定版本、校验过哈希的 minisign，用主钥匙签名并生成 `SHA256SUMS`；不检出代码、不安装其他依赖；
3. **发布**：创建 GitHub Release，上传压缩包、签名和 `SHA256SUMS`；发布说明取 `CHANGELOG.md` 中这个版本的一节；
4. **更新配方**：按 `packaging/homebrew/nett.rb`（配方模板，唯一的出处）填入版本、地址和哈希，推送到 `gotry-io/homebrew-tap` 的 `Formula/nett.rb`，使用仓库密钥 `TAP_PUSH_TOKEN`（只对 tap 仓库有写权限）。

## 4. macOS：Homebrew 与组网服务

- `brew install gotry-io/tap/nett` 安装命令行（签名工具 `nett site` 等）。配方的安装提示只用英文，与 Homebrew 社区一致：Homebrew 运行配方时固定使用英文区域设置，无法按用户的语言选择；nett 命令自己的输出按系统语言显示；
- 原生成员的组网服务以 root 运行（design/userspace.md 第 6.3 节）。Homebrew 的目录普通用户可写，root 服务直接运行那里的程序时，用户权限下的恶意程序能替换它、在下次启动时得到 root 和组网私钥。因此服务运行一份 root 专属的副本：
  - `sudo nett mesh install`：把正在运行的 `nett` 复制到 `/Library/Application Support/nett/nett`（目录属主 root、权限 `0700`），写入 launchd 配置（`/Library/LaunchDaemons/io.gotry.nett.mesh.plist`）与日志轮转配置（`/etc/newsyslog.d/nett.conf`），然后启动服务；服务已在运行时重启它，换用新的副本。期望状态或组网私钥还不在时只安装、不启动，并说明下一步。配置文件的内容只在代码中定义；
  - 升级：`brew upgrade nett` 之后执行 `sudo nett mesh install`。接入 Hub 之后由 nett-node 的签名自动升级接管（ADR 0020）；
  - `sudo nett mesh uninstall`：停止服务，删除副本与两份配置；密钥和期望状态保留；
  - 启停服务调用 `/bin/launchctl`，以参数数组传参、带超时（硬性规则 9、14）；
- 安装与每次升级各需要一次 sudo。不用 sudo 的方式是带 Network Extension 的 App，需要 Apple 开发者账号签名（ADR 0018 中的 M3 客户端）。

## 5. Linux

服务器下载对应的压缩包，核对签名后安装到 `/usr/local/bin`，使用 `packaging/systemd/nett-mesh.service`；容器内成员的镜像用 `aarch64` 或 `x86_64` 的静态版本构建（`packaging/container/`）。
