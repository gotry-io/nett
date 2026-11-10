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

- `brew install gotry-io/tap/nett` 安装命令行（签名工具 `nett site` 等）。配方的安装提示与 nett 命令的输出一样只用英文（architecture.md 第 14.3 节）；
- 原生成员的组网服务以 root 运行（design/userspace.md 第 6.3 节）。Homebrew 的目录普通用户可写，root 服务直接运行那里的程序时，用户权限下的恶意程序能替换它、在下次启动时得到 root 和组网私钥。因此服务运行一份 root 专属的副本：
  - `sudo nett install`：一个命令完成安装，路径都是固定的，用户不需要知道：
    - 在 `/Library/Application Support/nett/`（目录属主 root、权限 `0700`）中生成组网私钥和身份私钥（`0600`，已有的沿用，私钥不离开本机）。本机还没有期望状态时，打印 `nett site add --keys` 要用的一行公钥；已经有了就只说明结果；
    - 把正在运行的 `nett` 复制为这个目录中的 `nett`，写入 launchd 配置（`/Library/LaunchDaemons/io.gotry.nett.mesh.plist`）与日志轮转配置（`/etc/newsyslog.d/nett.conf`），配置文件的内容只在代码中定义；
    - 导入期望状态：到运行 `sudo` 的用户的站点目录（site.md 第 8 节，默认 `~/.config/nett`）的 `nodes/` 中，找出给本机的那一份（其中本节点准入材料的组网公钥与本机的组网私钥相符），复制进来。签名工具不在这台机器上、或站点放在别处时，用 `--config <desired.json>` 指定，同样先核对。只读普通文件，大小有上限。站点目录中的恢复密钥本来就只受这个用户的权限保护，能改写这个目录的程序已经能签名，从这里导入不扩大风险；
    - 有期望状态时启动服务。服务已在运行时：程序变了（升级之后）重启它，换用新的副本；只有期望状态变了时经本机接口让它重新加载（`nett reload` 的同一个请求，status.md 第 4.1 节），不重启、连接不中断，并显示是否被接受；都没变时不动。还没有期望状态时只安装，并说明下一步；
  - 首次安装：`sudo nett install` → 在持有站点的电脑上 `nett site add <名字> --keys "<打印的一行>"`（site.md 第 4 节）→ 再执行一次 `sudo nett install`。期望状态更新后执行同一个命令；
  - 升级：`brew upgrade nett` 之后执行 `sudo nett install`。接入 Hub 之后由 nett-node 的签名自动升级接管（ADR 0020）；
  - `sudo nett uninstall`：停止服务，删除副本与两份配置；密钥、期望状态和信任存储（`state/`，mesh.md 第 4.2 节）保留；
  - 启停服务调用 `/bin/launchctl`，以参数数组传参、带超时（硬性规则 9、14）；
- 安装与每次升级各需要一次 sudo。不用 sudo 的方式是带 Network Extension 的 App，需要 Apple 开发者账号签名（ADR 0018 中的 M3 客户端）。

## 5. Linux

服务器下载对应的压缩包，核对签名后安装到 `/usr/local/bin`，使用 `packaging/systemd/nett-mesh.service`；容器内成员的镜像用 `aarch64` 或 `x86_64` 的静态版本构建（`packaging/container/`）。
