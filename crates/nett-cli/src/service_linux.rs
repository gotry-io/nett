//! Linux 上服务的安装（design/hub.md 第 7 节）：`sudo nett install` 生成或沿用 `/etc/nett` 中的密钥，把正在运行的
//! `nett` 复制到 `/usr/local/bin/nett`，写入 systemd 单元并启动。单元是 `packaging/systemd/` 中的文件，编译时
//! 嵌入，内容只有这一个出处。不接 Hub 时期望状态由 `--config` 导入；接了 Hub 时（有 token，或已有 Hub 的
//! 配置）只由 nett-node 写。

use std::fs;
use std::path::Path;

use anyhow::{Context as _, bail};
use nett_node::config::HubConfig;

use crate::install::{
    InstallArgs, apply_token, copy_self, ensure_dir, replace_if_changed, require_root,
};

const DIR: &str = "/etc/nett";
const DESIRED: &str = "/etc/nett/desired.json";
const BINARY: &str = "/usr/local/bin/nett";
const UNIT_DIR: &str = "/etc/systemd/system";
/// systemctl 的固定位置（硬性规则 9）：多数发行版是前者，较旧的是后者。
const SYSTEMCTL: [&str; 2] = ["/usr/bin/systemctl", "/bin/systemctl"];

struct Unit {
    name: &'static str,
    content: &'static str,
    what: &'static str,
}

const MESH: Unit = Unit {
    name: "nett-mesh.service",
    content: include_str!("../../../packaging/systemd/nett-mesh.service"),
    what: "the mesh service",
};

const NODE: Unit = Unit {
    name: "nett-node.service",
    content: include_str!("../../../packaging/systemd/nett-node.service"),
    what: "nett-node",
};

fn systemctl(args: &[&str]) -> anyhow::Result<bool> {
    let Some(program) = SYSTEMCTL.iter().find(|p| Path::new(p).exists()) else {
        bail!(
            "systemctl is not on this machine; without systemd, run `nett mesh` (and `nett node`) with \
             your own service manager"
        );
    };
    crate::install::run(program, args)
}

fn unit_path(unit: &Unit) -> String {
    format!("{UNIT_DIR}/{}", unit.name)
}

/// 让服务按新的单元、程序运行：没在运行时启用并启动，单元或程序变了时重启。返回报告的一句话。
fn ensure_running(unit: &Unit, restart: bool) -> anyhow::Result<Option<String>> {
    let (ok, message) = if !systemctl(&["is-active", "--quiet", unit.name])? {
        (
            systemctl(&["enable", "--now", unit.name])?,
            format!("Started {} ({}).", unit.what, unit.name),
        )
    } else if restart {
        (
            systemctl(&["restart", unit.name])?,
            format!("Restarted {}.", unit.what),
        )
    } else {
        return Ok(None);
    };
    if !ok {
        bail!(
            "systemctl could not start {}; see `journalctl -u {}`",
            unit.name,
            unit.name
        );
    }
    Ok(Some(message))
}

pub fn install(args: &InstallArgs) -> anyhow::Result<()> {
    require_root()?;
    // 组网进程以 systemd 的专用身份运行，要能进入这个目录读期望状态；私钥文件本身是 0600
    ensure_dir(DIR, 0o755)?;
    let keys = crate::mesh::node_keys(Path::new(DIR))?;
    let hub_changed = apply_token(
        DIR,
        nett_mesh::store::DEFAULT_STATE_DIR,
        args.token.as_deref(),
    )?;
    let linked = HubConfig::load(Path::new(DIR))
        .map_err(anyhow::Error::msg)?
        .is_some();
    let desired_changed = match (&args.config, linked) {
        (Some(_), true) => {
            bail!("this machine receives its desired state from its Hub; --config is not used")
        }
        (Some(path), false) => {
            let bytes = crate::site::read_desired(path)?
                .with_context(|| format!("{} is not a regular file", path.display()))?;
            crate::site::check_desired_for(&bytes, &keys.0)?;
            replace_if_changed(Path::new(DESIRED), &bytes, 0o644)?
        }
        (None, _) => false,
    };
    let binary_changed = copy_self(BINARY)?;
    let mesh_unit_changed =
        replace_if_changed(Path::new(&unit_path(&MESH)), MESH.content.as_bytes(), 0o644)?;
    let node_unit_changed =
        linked && replace_if_changed(Path::new(&unit_path(&NODE)), NODE.content.as_bytes(), 0o644)?;
    if (mesh_unit_changed || node_unit_changed) && !systemctl(&["daemon-reload"])? {
        bail!("systemctl daemon-reload failed");
    }

    if !Path::new(DESIRED).exists() {
        crate::mesh::print_keys(Path::new(DIR), keys);
        println!(
            "Installed {BINARY} and {}. Not started: {DESIRED} does not exist yet.",
            MESH.name
        );
        println!(
            "Once the machine is in the site, copy its desired state here and run \
             `sudo nett install --config <desired.json>`."
        );
        return Ok(());
    }
    let mut messages = Vec::new();
    match ensure_running(&MESH, mesh_unit_changed || binary_changed)? {
        Some(m) => messages.push(m),
        None if desired_changed => print!(
            "{}",
            crate::status::reload_at(Path::new(nett_mesh::status::DEFAULT_SOCKET))?
        ),
        None => {}
    }
    if linked
        && let Some(m) = ensure_running(&NODE, node_unit_changed || binary_changed || hub_changed)?
    {
        messages.push(m);
    }
    if messages.is_empty() && !desired_changed {
        messages.push("The services are running. Nothing changed.".to_owned());
    }
    for m in messages {
        println!("{m}");
    }
    if mesh_unit_changed || node_unit_changed || binary_changed {
        println!("Logs: journalctl -u nett-mesh -u nett-node");
    }
    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    require_root()?;
    for unit in [&NODE, &MESH] {
        let path = unit_path(unit);
        if !Path::new(&path).exists() {
            continue;
        }
        // 停止失败时不删单元：留着它，用户还能用 systemctl 处理
        if !systemctl(&["disable", "--now", unit.name])? {
            bail!("systemctl could not stop {}", unit.name);
        }
        fs::remove_file(&path).with_context(|| format!("removing {path}"))?;
    }
    systemctl(&["daemon-reload"])?;
    println!(
        "Removed the services. {BINARY}, the keys, the desired state, the trust store and the Hub \
         configuration remain."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_run_the_installed_binary_from_the_config_directory() {
        for unit in [&MESH, &NODE] {
            assert!(
                unit.content.contains(&format!("ExecStart={BINARY} ")),
                "{}",
                unit.name
            );
        }
        assert!(MESH.content.contains(&format!("--config {DESIRED}")));
        assert!(NODE.content.contains(&format!("node --dir {DIR}")));
        assert!(NODE.content.contains(&format!("ReadWritePaths={DIR}")));
    }
}
