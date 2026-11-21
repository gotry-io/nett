//! What the programs write to standard output and standard error. `println!` and its kin panic
//! when a write fails, and a write fails whenever the reader has gone: Rust ignores SIGPIPE, so
//! `nett status --json | jq` without jq, or `nett status | head -1`, ends in an error instead of
//! the signal that quietly ends C and Go programs (the Tailscale CLI among them). The programs
//! write through these macros instead, as ripgrep does, and the workspace lints deny the standard
//! ones. Ignoring SIGPIPE stays: the sockets the programs use rely on writes returning errors.

use std::fmt;
use std::io::{ErrorKind, Write as _};

/// Writes the command's output to standard output, formatted as `print!`.
#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::output::write_out(::std::format_args!($($arg)*))
    };
}

/// Writes a line of the command's output to standard output, formatted as `println!`.
#[macro_export]
macro_rules! outln {
    () => {
        $crate::output::write_out(::std::format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::output::write_out(::std::format_args!("{}\n", ::std::format_args!($($arg)*)))
    };
}

/// Writes a message to standard error, formatted as `eprint!`.
#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => {
        $crate::output::write_err(::std::format_args!($($arg)*))
    };
}

/// Writes a message line to standard error, formatted as `eprintln!`.
#[macro_export]
macro_rules! errln {
    () => {
        $crate::output::write_err(::std::format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::output::write_err(::std::format_args!("{}\n", ::std::format_args!($($arg)*)))
    };
}

/// Behind [`out!`] and [`outln!`]. When the reader has gone, the command has done what was asked
/// of it and ends quietly with success, as ripgrep does; any other failure to write (a full disk)
/// ends it with status 1 and says why on standard error.
pub fn write_out(args: fmt::Arguments<'_>) {
    let Err(e) = std::io::stdout().lock().write_fmt(args) else {
        return;
    };
    if e.kind() == ErrorKind::BrokenPipe {
        std::process::exit(0);
    }
    write_err(format_args!("writing to standard output failed: {e}\n"));
    std::process::exit(1);
}

/// Behind [`err!`] and [`errln!`]. A failure to write is ignored: there is nowhere left to report
/// it, and the exit status stays the command's own, which a service manager reads.
pub fn write_err(args: fmt::Arguments<'_>) {
    let _ = std::io::stderr().lock().write_fmt(args);
}
