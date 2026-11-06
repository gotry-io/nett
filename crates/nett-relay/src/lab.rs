//! 实验构建（`lab` 特性）：中继分配读自本地文件（design/prototype.md 第 3 节）。官方构建中，分配由本机的
//! 组网进程提供（design/mesh.md 第 5.2 节）。

use std::net::SocketAddr;

use nett_trust::keys::X25519PublicKey;
use serde::{Deserialize, Serialize};

use crate::relay::{AssignedMember, AssignmentError, Relay};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    pub listen: SocketAddr,
    pub members: Vec<MemberDoc>,
    pub connections: Vec<[X25519PublicKey; 2]>,
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
        let members: Vec<AssignedMember> = self
            .members
            .iter()
            .map(|m| AssignedMember {
                public_key: m.public_key,
                address: m.address,
                token: m.token,
            })
            .collect();
        let connections: Vec<_> = self.connections.iter().map(|[a, b]| (*a, *b)).collect();
        Relay::new(&members, &connections)
    }
}
