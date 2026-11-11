//! `nett resolver` (design/names-and-diagnostics.md section 3): run by the mesh unit after the mesh
//! service starts (`ExecStartPost=+`, as root). It sends names under `nett.internal` to this
//! machine's DNS responder through systemd-resolved: on `nett0`, the mesh IPv4 as its DNS server, the
//! routing domain `~nett.internal`, and no default route. It never fails the unit: without
//! systemd-resolved, or when `nett0` does not come up in time, it says so and exits 0.

use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

/// The interface whose addresses the mesh responder answers on.
const INTERFACE: &str = "nett0";
/// Fixed locations of resolvectl (hard rule 9).
const RESOLVECTL: [&str; 2] = ["/usr/bin/resolvectl", "/bin/resolvectl"];
/// How long it waits for the mesh process to bring up its interface.
const WAIT: Duration = Duration::from_secs(15);

pub const USAGE: &str = "usage: nett resolver\n\n\
Run by the mesh service after it starts: points names under nett.internal at this machine's DNS\n\
responder through systemd-resolved, and does nothing without it.";

pub fn run(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    if let Some(arg) = parser.next()? {
        return Err(arg.unexpected().into());
    }
    let Some(resolvectl) = RESOLVECTL.into_iter().find(|p| Path::new(p).exists()) else {
        println!("systemd-resolved is not installed; names resolve with `dig @<mesh address>`");
        return Ok(());
    };
    if !Path::new("/run/systemd/resolve").exists() {
        println!("systemd-resolved is not running; names resolve with `dig @<mesh address>`");
        return Ok(());
    }
    let deadline = Instant::now() + WAIT;
    let ipv4 = loop {
        let found = nett_mesh::lan::interface_ips(INTERFACE)
            .into_iter()
            .find(IpAddr::is_ipv4);
        if let Some(ip) = found {
            break ip;
        }
        if Instant::now() >= deadline {
            println!("{INTERFACE} has no address yet; names under nett.internal are not routed");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let ip = ipv4.to_string();
    let steps: [&[&str]; 3] = [
        &["dns", INTERFACE, &ip],
        &["domain", INTERFACE, "~nett.internal"],
        // Older versions do not know this setting; the routing domain alone keeps other names away
        &["default-route", INTERFACE, "false"],
    ];
    for args in steps {
        match crate::install::run(resolvectl, args) {
            Ok(true) => {}
            Ok(false) => println!("resolvectl {} did not succeed", args.join(" ")),
            Err(e) => println!("resolvectl {}: {e:#}", args.join(" ")),
        }
    }
    println!("names under nett.internal go to {ip} on {INTERFACE}");
    Ok(())
}
