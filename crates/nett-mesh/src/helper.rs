//! The helper socket (design/status.md section 3.1): nett-relay and the transport adapter run as their
//! own low-privilege users and fetch their configuration from the mesh process here (ADR 0013). Each
//! query is answered only for the system user it belongs to (and root), because the replies hold probe
//! tokens.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
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
/// The system user nett-relay runs as.
pub const RELAY_USER: &str = "nett-relay";
/// The system user the transport adapter runs as.
pub const TRANSPORT_USER: &str = "nett-transport";

/// The helper socket next to the status socket at `status`.
pub fn socket_path(status: &Path) -> PathBuf {
    status.with_file_name(SOCKET_NAME)
}

/// The relay assignment handed to nett-relay (design/mesh.md section 5.2): the members' mesh public keys
/// resolved from the verified admission material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAssignment {
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_port: Option<u16>,
    pub members: Vec<AssignedMember>,
    pub links: Vec<[X25519PublicKey; 2]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignedMember {
    pub public_key: X25519PublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<SocketAddr>,
    pub token: ProbeToken,
}

/// The mesh process behind the helper socket.
pub trait HelperSource: Send + 'static {
    /// The current relay assignment (`None` inside when this machine is not a relay), recording the
    /// fingerprint nett-relay reported; `None` when the background thread is busy.
    fn relay(&self, fingerprint: Option<CertFingerprint>) -> Option<Option<RelayAssignment>>;
    /// The transport adapter's configuration (`None` inside before the interface is ready); `None` when
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
struct RelayReply {
    v: u32,
    relay: Option<RelayAssignment>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TransportReply {
    v: u32,
    transport: Option<TransportConfig>,
}

/// The thread that answers the helpers. Dropping it stops the thread and deletes the socket.
pub struct HelperServer {
    _server: LocalServer,
}

impl HelperServer {
    /// Creates the socket at `path` (`0666`: every connection is checked by the caller's user) and
    /// starts accepting connections.
    pub fn spawn(path: &Path, source: impl HelperSource) -> std::io::Result<Self> {
        LocalServer::spawn(path, 0o666, "nett-helpers", move |stream| {
            handle(stream, &source)
        })
        .map(|server| Self { _server: server })
    }
}

fn handle(stream: UnixStream, source: &impl HelperSource) -> std::io::Result<()> {
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let result = answer(&stream, source);
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let _ = std::io::copy(
        &mut Deadline::new(&stream).take(MAX_DRAIN),
        &mut std::io::sink(),
    );
    result
}

fn answer(stream: &UnixStream, source: &impl HelperSource) -> std::io::Result<()> {
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
    let allowed = |user: &str| uid == 0 || system_uid(user) == Some(uid);
    let busy = || reply_error(stream, "busy", "the mesh process is busy; try again");
    let bytes = match request.query.as_str() {
        "relay" if allowed(RELAY_USER) => {
            let Some(relay) = source.relay(request.fingerprint) else {
                return busy();
            };
            serde_json::to_vec(&RelayReply { v: VERSION, relay })
        }
        "transport" if allowed(TRANSPORT_USER) => {
            let Some(transport) = source.transport() else {
                return busy();
            };
            serde_json::to_vec(&TransportReply {
                v: VERSION,
                transport,
            })
        }
        "relay" | "transport" => {
            return reply_error(
                stream,
                "permission_denied",
                "this query is answered only for its own system user",
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

/// The user ID of a system user, from `/etc/passwd`; `None` when there is no such user.
fn system_uid(name: &str) -> Option<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name)
            .then(|| fields.nth(1)?.parse().ok())
            .flatten()
    })
}

/// nett-relay: fetches its assignment, reporting the fingerprint of its TLS certificate.
pub fn fetch_relay(
    path: &Path,
    fingerprint: Option<CertFingerprint>,
) -> Result<Option<RelayAssignment>, QueryError> {
    let request = serde_json::json!({"v": VERSION, "query": "relay", "fingerprint": fingerprint});
    let value = send(path, &request, QUERY_TIMEOUT)?;
    let reply: RelayReply =
        serde_json::from_value(value).map_err(|e| QueryError::Reply(e.to_string()))?;
    Ok(reply.relay)
}

/// The transport adapter: fetches its configuration.
pub fn fetch_transport(path: &Path) -> Result<Option<TransportConfig>, QueryError> {
    let request = serde_json::json!({"v": VERSION, "query": "transport"});
    let value = send(path, &request, QUERY_TIMEOUT)?;
    let reply: TransportReply =
        serde_json::from_value(value).map_err(|e| QueryError::Reply(e.to_string()))?;
    Ok(reply.transport)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default, Clone)]
    struct Fake {
        seen: Arc<Mutex<Vec<Option<CertFingerprint>>>>,
    }

    impl HelperSource for Fake {
        fn relay(&self, fingerprint: Option<CertFingerprint>) -> Option<Option<RelayAssignment>> {
            self.seen.lock().expect("lock").push(fingerprint);
            Some(Some(RelayAssignment {
                port: 41822,
                tls_port: Some(443),
                members: vec![AssignedMember {
                    public_key: X25519PublicKey::from_bytes([1; 32]),
                    address: None,
                    token: ProbeToken([2; 32]),
                }],
                links: vec![],
            }))
        }

        fn transport(&self) -> Option<Option<TransportConfig>> {
            Some(None)
        }
    }

    #[test]
    fn helpers_fetch_their_configuration() {
        let dir = std::env::temp_dir().join(format!("nett-helper-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join(SOCKET_NAME);
        let fake = Fake::default();
        let server = HelperServer::spawn(&path, fake.clone()).expect("server");
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
        match fetch_relay(&path, Some(fingerprint)) {
            Ok(relay) => {
                assert_eq!(me, 0);
                assert_eq!(relay.expect("assigned").port, 41822);
                assert_eq!(*fake.seen.lock().expect("lock"), [Some(fingerprint)]);
                assert_eq!(fetch_transport(&path).expect("transport"), None);
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

    #[test]
    fn system_users_are_read_from_passwd() {
        assert_eq!(system_uid("root"), Some(0));
        assert_eq!(system_uid("no-such-user-of-nett"), None);
    }
}
