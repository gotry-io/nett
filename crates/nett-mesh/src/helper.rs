//! The helper socket (design/status.md section 3.1): on Linux nett-relay, the relay's public TCP
//! entry, runs as a user systemd allocates and asks the nett daemon here for its ports, reporting
//! its certificate's fingerprint (ADR 0032). It is answered only for a process of the relay's
//! systemd unit (and root), since what it reports reaches the Hub. The relay and the transports in
//! the daemon ask the same source directly.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use nett_core::transport::{CertFingerprint, TransportConfig};
use nett_trust::keys::X25519PublicKey;
use serde::{Deserialize, Serialize};

use crate::config::ProbeToken;
use crate::status::{
    Deadline, IO_TIMEOUT, LocalServer, MAX_DRAIN, MAX_REQUEST, QUERY_TIMEOUT, QueryError, VERSION,
    peer_uid, reply_error, send,
};

/// File name of the helper socket, next to the status socket.
pub const SOCKET_NAME: &str = "helpers.sock";
/// How often the helpers ask again.
pub const FETCH_INTERVAL: Duration = Duration::from_secs(5);
/// The systemd unit of nett-relay: a caller is known by its unit.
pub const RELAY_UNIT: &str = "nett-relay.service";

/// The helper socket next to the status socket at `status`.
pub fn socket_path(status: &Path) -> PathBuf {
    status.with_file_name(SOCKET_NAME)
}

/// The relay assignment the relay in the daemon serves (design/mesh.md section 5.2): the members'
/// mesh public keys resolved from the verified admission material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAssignment {
    pub port: u16,
    pub tls_port: Option<u16>,
    pub members: Vec<AssignedMember>,
    pub links: Vec<[X25519PublicKey; 2]>,
    pub obfs: Option<crate::config::ObfsPortDoc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedMember {
    pub public_key: X25519PublicKey,
    pub address: Option<SocketAddr>,
    pub token: ProbeToken,
}

/// What nett-relay needs to serve the relay's TLS entry (design/mesh.md section 5.3): the TCP port to
/// listen on, and the loopback port of the relay in the daemon it hands each connection to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsEntry {
    pub tls_port: u16,
    pub handoff_port: u16,
}

/// The mesh behind the helper socket, the relay and the transports.
pub trait HelperSource: Send + 'static {
    /// The current relay assignment (`None` inside when this machine is not a relay); `None` when the
    /// background thread is busy.
    fn relay(&self) -> Option<Option<RelayAssignment>>;
    /// The relay's TLS port (`None` inside when this machine's relay serves no TLS), recording the
    /// fingerprint nett-relay reported; `None` when the background thread is busy.
    fn tls_entry(&self, fingerprint: CertFingerprint) -> Option<Option<u16>>;
    /// The TLS transport's configuration (`None` inside before the interface is ready); `None` when
    /// the background thread is busy.
    fn transport(&self) -> Option<Option<TransportConfig>>;
}

#[derive(Debug, Deserialize)]
struct Request {
    v: u32,
    query: String,
    #[serde(default)]
    fingerprint: Option<CertFingerprint>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TlsEntryReply {
    v: u32,
    entry: Option<TlsEntry>,
}

/// The thread that answers the helpers. Dropping it stops the thread and deletes the socket.
pub struct HelperServer {
    _server: LocalServer,
}

impl HelperServer {
    /// Creates the socket at `path` (`0666`: every connection is checked by the caller's user) and
    /// starts accepting connections. `handoff` is the relay's hand-off port, 0 while the relay has
    /// none.
    pub fn spawn(
        path: &Path,
        source: impl HelperSource,
        handoff: Arc<AtomicU16>,
    ) -> std::io::Result<Self> {
        LocalServer::spawn(path, 0o666, "nett-helpers", move |stream| {
            handle(stream, &source, &handoff)
        })
        .map(|server| Self { _server: server })
    }
}

fn handle(
    stream: UnixStream,
    source: &impl HelperSource,
    handoff: &AtomicU16,
) -> std::io::Result<()> {
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let result = answer(&stream, source, handoff);
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let _ = std::io::copy(
        &mut Deadline::new(&stream).take(MAX_DRAIN),
        &mut std::io::sink(),
    );
    result
}

fn answer(
    stream: &UnixStream,
    source: &impl HelperSource,
    handoff: &AtomicU16,
) -> std::io::Result<()> {
    let uid = peer_uid(stream)?;
    let mut line = String::new();
    BufReader::new(Deadline::new(stream).take(MAX_REQUEST)).read_line(&mut line)?;
    let Ok(request) = serde_json::from_str::<Request>(line.trim_end()) else {
        return reply_error(stream, "bad_request", "the request is not valid JSON");
    };
    if request.v != VERSION {
        return reply_error(
            stream,
            "unsupported_version",
            &format!(
                "interface version {} is not supported; this process speaks {VERSION}",
                request.v
            ),
        );
    }
    let allowed = uid == 0 || caller_unit(stream).as_deref() == Some(RELAY_UNIT);
    let bytes = match request.query.as_str() {
        "tls_entry" if allowed => {
            let Some(fingerprint) = request.fingerprint else {
                return reply_error(stream, "bad_request", "the query needs a fingerprint");
            };
            let Some(tls_port) = source.tls_entry(fingerprint) else {
                return reply_error(stream, "busy", "the nett daemon is busy; try again");
            };
            // The entry has nothing to hand connections to until the relay has its port
            let handoff_port = handoff.load(Ordering::Acquire);
            let entry = tls_port
                .filter(|_| handoff_port != 0)
                .map(|tls_port| TlsEntry {
                    tls_port,
                    handoff_port,
                });
            serde_json::to_vec(&TlsEntryReply { v: VERSION, entry })
        }
        "tls_entry" => {
            return reply_error(
                stream,
                "permission_denied",
                "this query is answered only for the relay's service",
            );
        }
        other => {
            let query: String = other.chars().take(32).collect();
            return reply_error(stream, "unknown_query", &format!("unknown query `{query}`"));
        }
    };
    let mut bytes = bytes.map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    let mut out = stream;
    out.write_all(&bytes)
}

/// The systemd system unit the peer process runs in, when its user ID is still the peer's: a process
/// ID reused after the caller exited does not pass. Only root can place a process in a unit of the
/// system manager; where `/proc` hides other users' processes there is no answer.
#[cfg(target_os = "linux")]
fn caller_unit(stream: &UnixStream) -> Option<String> {
    use std::os::fd::AsFd as _;
    let (pid, uid) = crate::linux::peer_cred(stream.as_fd()).ok()?;
    if pid == 0 {
        return None;
    }
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    (status_uid(&status)? == uid)
        .then(|| system_unit(&cgroup).map(str::to_owned))
        .flatten()
}

/// Only Linux runs nett-relay as a service.
#[cfg(not(target_os = "linux"))]
fn caller_unit(_stream: &UnixStream) -> Option<String> {
    None
}

/// The unit in a `/proc/<pid>/cgroup` listing when the process is in a service of the system manager
/// (`/system.slice/<name>.service`), from the unified hierarchy or the systemd one; a user's own
/// services live elsewhere and never match.
#[cfg(any(target_os = "linux", test))]
fn system_unit(cgroup: &str) -> Option<&str> {
    cgroup.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let (hierarchy, controllers, path) = (fields.next()?, fields.next()?, fields.next()?);
        if !(hierarchy == "0" && controllers.is_empty() || controllers == "name=systemd") {
            return None;
        }
        let unit = path.strip_prefix("/system.slice/")?;
        (unit.ends_with(".service") && !unit.contains('/')).then_some(unit)
    })
}

/// The effective user ID in a `/proc/<pid>/status` listing.
#[cfg(any(target_os = "linux", test))]
fn status_uid(status: &str) -> Option<u32> {
    let line = status.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// nett-relay: asks for the TLS entry's ports, reporting the fingerprint of its TLS certificate.
pub fn fetch_tls_entry(
    path: &Path,
    fingerprint: CertFingerprint,
) -> Result<Option<TlsEntry>, QueryError> {
    let request =
        serde_json::json!({"v": VERSION, "query": "tls_entry", "fingerprint": fingerprint});
    let value = send(path, &request, QUERY_TIMEOUT)?;
    let reply: TlsEntryReply =
        serde_json::from_value(value).map_err(|e| QueryError::Reply(e.to_string()))?;
    Ok(reply.entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default, Clone)]
    struct Fake {
        seen: Arc<Mutex<Vec<CertFingerprint>>>,
    }

    impl HelperSource for Fake {
        fn relay(&self) -> Option<Option<RelayAssignment>> {
            Some(Some(RelayAssignment {
                port: 41822,
                tls_port: Some(443),
                members: vec![AssignedMember {
                    public_key: X25519PublicKey::from_bytes([1; 32]),
                    address: None,
                    token: ProbeToken([2; 32]),
                }],
                links: vec![],
                obfs: None,
            }))
        }

        fn tls_entry(&self, fingerprint: CertFingerprint) -> Option<Option<u16>> {
            self.seen.lock().expect("lock").push(fingerprint);
            Some(Some(443))
        }

        fn transport(&self) -> Option<Option<TransportConfig>> {
            Some(None)
        }
    }

    /// nett-relay gets the TLS port and the relay's hand-off port, and its fingerprint is recorded;
    /// before the relay has a hand-off port it gets nothing to serve.
    #[test]
    fn helpers_fetch_their_configuration() {
        let dir_tmp = tempfile::Builder::new()
            .prefix("nett-helper-")
            .tempdir()
            .expect("temp dir");
        let dir = dir_tmp.path().join("dir");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join(SOCKET_NAME);
        let fake = Fake::default();
        let handoff = Arc::new(AtomicU16::new(0));
        let server = HelperServer::spawn(&path, fake.clone(), handoff.clone()).expect("server");
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path)
            .expect("socket")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o666);

        let fingerprint: CertFingerprint =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .parse()
                .expect("fingerprint");
        // Tests run as root in the lab container and as a normal user elsewhere: only root (or the
        // helper's own user) gets an answer
        let me = rustix::process::geteuid().as_raw();
        match fetch_tls_entry(&path, fingerprint) {
            Ok(entry) => {
                assert_eq!(me, 0);
                assert_eq!(entry, None, "no hand-off port yet");
                handoff.store(50123, Ordering::Release);
                let entry = fetch_tls_entry(&path, fingerprint).expect("entry");
                assert_eq!(
                    entry,
                    Some(TlsEntry {
                        tls_port: 443,
                        handoff_port: 50123
                    })
                );
                assert_eq!(*fake.seen.lock().expect("lock"), [fingerprint, fingerprint]);
            }
            Err(QueryError::Refused { code, .. }) => {
                assert_ne!(me, 0);
                assert_eq!(code, "permission_denied");
                assert!(fake.seen.lock().expect("lock").is_empty());
            }
            Err(e) => panic!("{e}"),
        }
        drop(server);
        assert!(!path.exists(), "the socket is removed with the server");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A caller is known by its system service; a user's own service of the same name is not it
    #[test]
    fn callers_are_known_by_their_system_unit() {
        assert_eq!(
            system_unit("0::/system.slice/nett-relay.service\n"),
            Some(RELAY_UNIT)
        );
        let hybrid = "12:pids:/system.slice/nett-relay.service\n\
                      1:name=systemd:/system.slice/nett-relay.service\n\
                      0::/system.slice/nett-relay.service\n";
        assert_eq!(system_unit(hybrid), Some(RELAY_UNIT));
        for other in [
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/nett-relay.service\n",
            "0::/system.slice/nett-relay.service/extra\n",
            "0::/system.slice/nett-relay.scope\n",
            "0::/\n",
            "",
        ] {
            assert_eq!(system_unit(other), None, "{other}");
        }
        let status = "Name:\tnett\nUid:\t61184\t61185\t61184\t61184\nGid:\t0\t0\t0\t0\n";
        assert_eq!(status_uid(status), Some(61185));
        assert_eq!(status_uid("Name:\tnett\n"), None);
    }
}
