//! 命令行的用户可见文本（architecture.md 第 14.3 节）：每条文本同时写中文和英文，少写一种就编译不过。
//! 按 `LC_ALL`、`LC_MESSAGES`、`LANG` 的顺序取第一个非空的值，以 `zh` 开头时用中文，否则用英文。

pub struct Text {
    pub zh: &'static str,
    pub en: &'static str,
}

impl Text {
    pub fn get(&self) -> &'static str {
        if chinese() { self.zh } else { self.en }
    }
}

fn chinese() -> bool {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .is_some_and(|v| v.starts_with("zh"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub const NODE_KEYS: Text = Text {
    zh: "这个节点的私钥在 {dir}（mesh.key 与 identity.key，权限 0600，只留在这台机器上）。把下面这一行写进站点描述中这个节点的条目（design/local-signing.md 第 4 节）：",
    en: "This node's private keys are in {dir} (mesh.key and identity.key, mode 0600; they stay on this machine). Add this line to this node's entry in the site description (design/local-signing.md section 4):",
};

#[cfg(target_os = "macos")]
pub const SERVICE_NEEDS_ROOT: Text = Text {
    zh: "组网服务以 root 运行，安装和卸载需要 sudo：sudo nett mesh install",
    en: "The mesh service runs as root; installing and removing it needs sudo: sudo nett mesh install",
};

#[cfg(target_os = "macos")]
pub const SERVICE_INSTALLED_NOT_STARTED: Text = Text {
    zh: "已安装到 {dir}，服务还没有启动：还没有期望状态。把上面一行写进站点描述，运行 `nett site build` 之后执行 `sudo nett mesh install --config <这个节点的 desired.json>`。",
    en: "Installed into {dir}; the service is not started yet because there is no desired state. Add the line above to the site description, run `nett site build`, then run `sudo nett mesh install --config <this node's desired.json>`.",
};

#[cfg(target_os = "macos")]
pub const SERVICE_STARTED: Text = Text {
    zh: "组网服务已启动（launchd 标签 {label}），运行的是 {binary}。日志：log show --last 1h --predicate 'process == \"nett\"'。期望状态更新后执行 sudo nett mesh install --config <desired.json>；brew upgrade nett 之后执行 sudo nett mesh install。",
    en: "The mesh service is running (launchd label {label}) from {binary}. Logs: log show --last 1h --predicate 'process == \"nett\"'. After the desired state changes, run sudo nett mesh install --config <desired.json>; after brew upgrade nett, run sudo nett mesh install.",
};

#[cfg(target_os = "macos")]
pub const SERVICE_RESTARTED: Text = Text {
    zh: "组网服务已重启（launchd 标签 {label}），换用新的 {binary}。日志：log show --last 1h --predicate 'process == \"nett\"'。",
    en: "The mesh service restarted (launchd label {label}) with the new {binary}. Logs: log show --last 1h --predicate 'process == \"nett\"'.",
};

#[cfg(target_os = "macos")]
pub const SERVICE_RELOADED: Text = Text {
    zh: "组网服务已重新读取期望状态（没有重启，进行中的连接不中断）。",
    en: "The mesh service reloaded the desired state (no restart; active connections continue).",
};

#[cfg(target_os = "macos")]
pub const SERVICE_UNCHANGED: Text = Text {
    zh: "组网服务已在运行，程序和期望状态都没有变化。",
    en: "The mesh service is already running; neither the program nor the desired state changed.",
};

#[cfg(target_os = "macos")]
pub const SERVICE_UNINSTALLED: Text = Text {
    zh: "组网服务已停止并卸载。{dir} 中的密钥和期望状态保留，不再需要时手动删除。",
    en: "The mesh service is stopped and removed. The keys and desired state in {dir} are kept; delete them by hand when no longer needed.",
};

pub const SITE_TEMPLATE: Text = Text {
    zh: "站点描述：节点、候选路径与访问规则的写法见 design/local-signing.md 第 4 节。组网网段创建后不能修改。",
    en: "Site description: see design/local-signing.md section 4 for nodes, candidate paths and access rules. The mesh prefixes cannot change after creation.",
};

pub const SITE_CREATED: Text = Text {
    zh: "已在 {dir} 建立站点：recovery.pk8 是恢复密钥（唯一的信任锚，权限 0600），另存一份离线备份，丢失后只能重建信任锚、所有节点重新入网。在每个节点上生成密钥（macOS：`sudo nett mesh install`；Linux：`nett mesh keys --dir <目录>`），把输出的一行写进 site.toml 中这个节点的条目，再运行 `{build}`。",
    en: "Created a site in {dir}: recovery.pk8 is the recovery key (the only trust anchor, mode 0600); keep an offline copy, since losing it means rebuilding the trust anchor and re-enrolling every node. On each node create its keys (macOS: `sudo nett mesh install`; Linux: `nett mesh keys --dir <directory>`), add the printed line to that node's entry in site.toml, then run `{build}`.",
};

pub const SITE_BUILT: Text = Text {
    zh: "已为 {n} 个节点生成期望状态，在 {dir}/<节点>/desired.json。把它拷到对应的节点上，替换后向组网进程发 SIGHUP（文件不含私钥）。",
    en: "Generated the desired state for {n} nodes in {dir}/<node>/desired.json. Copy each file to its node, replace the old one and send SIGHUP to the mesh process (the files hold no private keys).",
};
