//! `cargo run -p nett-proto-gen`：从 `proto/nett/v1/*.proto` 生成 `crates/nett-proto/src/gen/nett.v1.rs`。

use std::path::Path;

fn main() -> std::io::Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = root.join("crates/nett-proto/src/gen");
    std::fs::create_dir_all(&out)?;
    prost_build::Config::new().out_dir(&out).compile_protos(
        &[root.join("proto/nett/v1/control.proto")],
        &[root.join("proto")],
    )
}
