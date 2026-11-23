//! Lab build (`lab` feature): relay allocation is read from a local file (design/prototype.md
//! section 3). In official builds the allocation is provided by the local mesh
//! (design/mesh.md section 5.2).

use std::net::SocketAddr;
use std::path::PathBuf;

use nett_trust::keys::X25519PublicKey;
use serde::{Deserialize, Serialize};

use crate::relay::{AssignedMember, AssignmentError, Relay};
use crate::server::Assignment;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    pub listen: SocketAddr,
    /// TLS (WebSocket) entry point (design/mesh.md section 5.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsDoc>,
    /// The obfuscated port, its key and padding (design/obfuscation.md section 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<nett_mesh::config::RelayObfsDoc>,
    pub members: Vec<MemberDoc>,
    pub connections: Vec<[X25519PublicKey; 2]>,
}

/// The listen address of the TLS entry point and the PEM-format certificate chain and private key
/// files.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsDoc {
    pub listen: SocketAddr,
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberDoc {
    pub public_key: X25519PublicKey,
    pub address: Option<SocketAddr>,
    #[serde(with = "nett_trust::encoding::b64_fixed")]
    pub token: [u8; 32],
}

impl RelayConfig {
    pub fn relay(&self) -> Result<Relay, AssignmentError> {
        let assignment = self.assignment();
        Relay::new(&assignment.members, &assignment.connections)
    }

    pub fn assignment(&self) -> Assignment {
        Assignment {
            members: self
                .members
                .iter()
                .map(|m| AssignedMember {
                    public_key: m.public_key,
                    address: m.address,
                    token: m.token,
                })
                .collect(),
            connections: self.connections.iter().map(|[a, b]| (*a, *b)).collect(),
        }
    }
}
