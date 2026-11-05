//! `nett` 可执行文件：命令行，以及 `nett node`、`nett mesh`、`nett transport`、`nett relay` 各进程的入口（ADR 0012）。

fn main() {
    println!("nett {}", env!("CARGO_PKG_VERSION"));
}
