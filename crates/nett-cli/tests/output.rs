//! When the reader of a command's output goes away (`nett status --json | jq` where jq is not
//! installed, `nett status | head -1`), the command ends quietly with success, as ripgrep does: it
//! has nothing left to do. A panic would be a bug.

use std::process::{Command, Stdio};

/// Runs the program with its standard output on a pipe whose reading end is already closed.
fn with_output_closed(program: &str, args: &[&str]) -> std::process::Output {
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    Command::new(program)
        .args(args)
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .expect("run")
}

#[test]
fn a_closed_output_ends_the_command_quietly() {
    let out = with_output_closed(env!("CARGO_BIN_EXE_nett"), &["help"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{:?}: {stderr}", out.status);
    assert!(stderr.is_empty(), "{stderr}");
}

/// A message that cannot be written to standard error leaves the exit status the command's own:
/// a service manager decides from it whether a service failed.
#[test]
fn a_closed_error_output_keeps_the_failure() {
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let out = Command::new(env!("CARGO_BIN_EXE_nett"))
        .args(["reload", "--socket", "/nonexistent/nett/mesh.sock"])
        .stdout(Stdio::piped())
        .stderr(writer)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(1), "{:?}", out.status);
}

/// Any other failure to write the output says why and fails.
#[cfg(target_os = "linux")]
#[test]
fn a_full_output_says_why_and_fails() {
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("/dev/full");
    let out = Command::new(env!("CARGO_BIN_EXE_nett"))
        .arg("help")
        .stdout(full)
        .stderr(Stdio::piped())
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{:?}: {stderr}", out.status);
    assert!(
        stderr.contains("writing to standard output failed"),
        "{stderr}"
    );
}
