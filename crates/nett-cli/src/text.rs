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

pub const KEYS_WRITTEN: Text = Text {
    zh: "已在 {dir} 生成 mesh.key 和 identity.key（权限 0600，只留在这台机器上）。把下面这一行写进站点描述中这个节点的条目（design/local-signing.md 第 4 节）：",
    en: "Wrote mesh.key and identity.key to {dir} (mode 0600; keep them on this machine). Add this line to this node's entry in the site description (design/local-signing.md section 4):",
};
