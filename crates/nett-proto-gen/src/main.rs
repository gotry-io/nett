//! `cargo run -p nett-proto-gen`: generates `crates/nett-proto/src/gen/nett.v1.rs` from
//! `proto/nett/v1/*.proto`.

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
