//! When the reader of the Hub command's output goes away, it ends quietly with success, as the
//! nett command does (crates/nett-cli/tests/output.rs).

use std::process::{Command, Stdio};

#[test]
fn a_closed_output_ends_the_command_quietly() {
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let out = Command::new(env!("CARGO_BIN_EXE_nett-hub"))
        .arg("openapi")
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{:?}: {stderr}", out.status);
    assert!(stderr.is_empty(), "{stderr}");
}
