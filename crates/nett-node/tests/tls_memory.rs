//! On macOS, connecting to a Hub with a public certificate reads no root certificates into the
//! process: reading them through the Security framework leaves several megabytes behind each time
//! (design/hub.md section 4). A process of its own, so that no other test adds to its memory.
#![cfg(target_os = "macos")]

/// The resident size of this process, in KiB.
fn resident_kib() -> u64 {
    let out = std::process::Command::new("/bin/ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .expect("ps runs");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("ps prints the resident size")
}

#[test]
fn a_connector_for_a_public_certificate_loads_no_root_store() {
    // The first one sets up what every connection shares
    nett_node::tls::connector(None).expect("connector");
    let before = resident_kib();
    for _ in 0..10 {
        nett_node::tls::connector(None).expect("connector");
    }
    let grown = resident_kib().saturating_sub(before);
    assert!(
        grown < 2048,
        "building 10 connectors grew the process by {grown} KiB"
    );
}
