//! 传输适配进程的配置（design/mesh.md 第 5.3 节，ADR 0013）：由组网进程按期望状态生成，传输适配进程只
//! 读取。不含任何密钥：WebSocket 连接由组网进程经它发出的中继探测认证。

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// 中继探测与应答的消息类型（design/mesh.md 第 7.2 节）：传输适配进程据此分发中继发回的消息。
pub const RELAY_PROBE: u8 = 0x90;
pub const RELAY_REPLY: u8 = 0x91;

/// 一份配置最多的 TLS 中继数。
pub const MAX_TARGETS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    /// 本机 WireGuard 的端口：从中继收到的 WireGuard 消息交给回环地址上的这个端口。
    pub wireguard_port: u16,
    pub targets: Vec<TlsTarget>,
}

/// 一个 TLS 中继。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsTarget {
    /// 本机回环地址上的端口：WireGuard 与组网进程把发往这个中继的包发到这里。
    pub listen: SocketAddr,
    /// 中继的 TLS 地址。按 IP 连接，不发送 SNI（design/mesh.md 第 5.3 节）。
    pub connect: SocketAddr,
    /// 中继证书的指纹，客户端按它校验（硬性规则 11）。
    pub fingerprint: CertFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportConfigError {
    #[error("transport config lists {0} targets, more than {MAX_TARGETS}")]
    TooManyTargets(usize),
    #[error("target listens on {0}, which is not a loopback address")]
    NotLoopback(SocketAddr),
    #[error("two targets listen on {0}")]
    DuplicateListen(SocketAddr),
    #[error("wireguard port must not be 0")]
    WireguardPort,
}

impl TransportConfig {
    /// 边界处的校验：本机端口只在回环地址上，彼此不重复。
    pub fn validate(&self) -> Result<(), TransportConfigError> {
        if self.wireguard_port == 0 {
            return Err(TransportConfigError::WireguardPort);
        }
        if self.targets.len() > MAX_TARGETS {
            return Err(TransportConfigError::TooManyTargets(self.targets.len()));
        }
        for (i, t) in self.targets.iter().enumerate() {
            if !t.listen.ip().is_loopback() {
                return Err(TransportConfigError::NotLoopback(t.listen));
            }
            if self.targets[..i].iter().any(|o| o.listen == t.listen) {
                return Err(TransportConfigError::DuplicateListen(t.listen));
            }
        }
        Ok(())
    }
}

/// 证书（叶证书 DER）的 SHA-256，文本形式为 `sha256:<64 位小写十六进制>`。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CertFingerprint(pub [u8; 32]);

impl fmt::Display for CertFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for CertFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("certificate fingerprint must be `sha256:` followed by 64 lower-case hex digits")]
pub struct FingerprintError;

impl FromStr for CertFingerprint {
    type Err = FingerprintError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s.strip_prefix("sha256:").ok_or(FingerprintError)?;
        let bytes = hex.as_bytes();
        if bytes.len() != 64 {
            return Err(FingerprintError);
        }
        let digit = |c: u8| match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(FingerprintError),
        };
        let mut out = [0u8; 32];
        for (i, [hi, lo]) in bytes.as_chunks::<2>().0.iter().enumerate() {
            out[i] = digit(*hi)? << 4 | digit(*lo)?;
        }
        Ok(Self(out))
    }
}

impl Serialize for CertFingerprint {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for CertFingerprint {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_round_trips_in_canonical_form_only() {
        let text = format!("sha256:{}", "0a".repeat(32));
        let fp: CertFingerprint = text.parse().expect("parse");
        assert_eq!(fp.0, [0x0a; 32]);
        assert_eq!(fp.to_string(), text);
        for bad in [
            "0a".repeat(32),
            format!("sha256:{}", "0A".repeat(32)),
            format!("sha256:{}", "0a".repeat(31)),
            format!("sha1:{}", "0a".repeat(32)),
        ] {
            assert!(bad.parse::<CertFingerprint>().is_err(), "{bad}");
        }
    }

    #[test]
    fn listen_addresses_stay_on_loopback() {
        let target = |listen: &str| TlsTarget {
            listen: listen.parse().expect("addr"),
            connect: "198.51.100.3:443".parse().expect("addr"),
            fingerprint: CertFingerprint([1; 32]),
        };
        let ok = TransportConfig {
            wireguard_port: 41820,
            targets: vec![target("127.0.0.1:41830"), target("127.0.0.1:41831")],
        };
        assert_eq!(ok.validate(), Ok(()));
        let public = TransportConfig {
            targets: vec![target("0.0.0.0:41830")],
            ..ok.clone()
        };
        assert!(matches!(
            public.validate(),
            Err(TransportConfigError::NotLoopback(_))
        ));
        let twice = TransportConfig {
            targets: vec![target("127.0.0.1:41830"), target("127.0.0.1:41830")],
            ..ok
        };
        assert!(matches!(
            twice.validate(),
            Err(TransportConfigError::DuplicateListen(_))
        ));
    }
}
