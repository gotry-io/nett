//! Release signatures and the release manifest (ADR 0020, design/release.md section 7).
//!
//! Release programs are signed with minisign (Ed25519) by the project's release keys. Nodes trust
//! only these keys for upgrades: neither the Hub nor the download location decides what gets
//! installed. The keys are a build parameter: `NETT_RELEASE_PUBLIC_KEYS` at build time replaces
//! the project's keys in `keys/`.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

/// The release public keys built into this program: the project's primary and backup keys, or
/// the keys given in `NETT_RELEASE_PUBLIC_KEYS` when it was built.
const BUILT_IN: &str = match option_env!("NETT_RELEASE_PUBLIC_KEYS") {
    Some(keys) => keys,
    None => concat!(
        include_str!("../../../keys/nett-release-primary.pub"),
        "\n",
        include_str!("../../../keys/nett-release-backup.pub"),
    ),
};

/// Largest release manifest accepted.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Largest program downloaded for an upgrade (a release program is about 5 MB).
pub const MAX_PROGRAM_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReleaseError {
    #[error("release key: {0}")]
    Key(String),
    #[error("release signature: {0}")]
    Signature(String),
    #[error("the release signature is from key {0}, which this build does not trust")]
    UnknownKey(String),
    #[error("the release signature does not match the program")]
    BadSignature,
    #[error("the signed comment is `{found}`, expected `{expected}`")]
    Comment { found: String, expected: String },
    #[error("the program's SHA-256 does not match the release manifest")]
    Digest,
    #[error("release manifest: {0}")]
    Manifest(String),
    #[error("`{0}` is not a release version such as 0.2.0")]
    Version(String),
}

/// A release version: `major.minor.patch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl FromStr for Version {
    type Err = ReleaseError;

    fn from_str(s: &str) -> Result<Self, ReleaseError> {
        let bad = || ReleaseError::Version(s.to_owned());
        let mut parts = s.split('.');
        let mut next = || -> Result<u64, ReleaseError> {
            let part = parts.next().ok_or_else(bad)?;
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) || part.len() > 9 {
                return Err(bad());
            }
            part.parse().map_err(|_| bad())
        };
        let version = Self {
            major: next()?,
            minor: next()?,
            patch: next()?,
        };
        if parts.next().is_some() {
            return Err(bad());
        }
        Ok(version)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// One minisign public key.
#[derive(Clone, PartialEq, Eq)]
struct ReleaseKey {
    id: [u8; 8],
    key: [u8; 32],
}

/// The release public keys a node trusts.
#[derive(Clone)]
pub struct ReleaseKeys(Vec<ReleaseKey>);

impl fmt::Debug for ReleaseKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ids: Vec<String> = self.0.iter().map(|k| key_id(&k.id)).collect();
        f.debug_tuple("ReleaseKeys").field(&ids).finish()
    }
}

/// A key ID as minisign prints it.
fn key_id(id: &[u8; 8]) -> String {
    id.iter().rev().map(|b| format!("{b:02X}")).collect()
}

impl ReleaseKeys {
    /// The keys built into this program.
    pub fn built_in() -> Result<Self, ReleaseError> {
        Self::parse(BUILT_IN)
    }

    /// Minisign public keys, one base64 line each; `untrusted comment:` lines and blank lines are
    /// skipped.
    pub fn parse(text: &str) -> Result<Self, ReleaseError> {
        let mut keys = Vec::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with("untrusted comment:") {
                continue;
            }
            let bytes = STANDARD
                .decode(line)
                .map_err(|e| ReleaseError::Key(e.to_string()))?;
            let (alg, rest) = bytes
                .split_first_chunk::<2>()
                .ok_or_else(|| ReleaseError::Key("too short".into()))?;
            if alg != b"Ed" || rest.len() != 40 {
                return Err(ReleaseError::Key(
                    "not a minisign Ed25519 public key".into(),
                ));
            }
            let (id, key) = rest.split_at(8);
            keys.push(ReleaseKey {
                id: id
                    .try_into()
                    .map_err(|_| ReleaseError::Key("key ID".into()))?,
                key: key
                    .try_into()
                    .map_err(|_| ReleaseError::Key("key".into()))?,
            });
        }
        if keys.is_empty() {
            return Err(ReleaseError::Key("no public keys".into()));
        }
        Ok(Self(keys))
    }

    /// Verifies a minisign signature (`.minisig` text) over `data` and returns its trusted
    /// comment. Both the plain and the prehashed (BLAKE2b-512) forms are accepted.
    pub fn verify(&self, data: &[u8], minisig: &str) -> Result<String, ReleaseError> {
        let sig = Minisig::parse(minisig)?;
        let key = self
            .0
            .iter()
            .find(|k| k.id == sig.key_id)
            .ok_or_else(|| ReleaseError::UnknownKey(key_id(&sig.key_id)))?;
        let public = UnparsedPublicKey::new(&ED25519, &key.key);
        let digest;
        let message: &[u8] = if sig.prehashed {
            use blake2::digest::Digest as _;
            digest = blake2::Blake2b512::digest(data);
            digest.as_slice()
        } else {
            data
        };
        public
            .verify(message, &sig.signature)
            .map_err(|_| ReleaseError::BadSignature)?;
        let mut global = sig.signature.to_vec();
        global.extend_from_slice(sig.trusted_comment.as_bytes());
        public
            .verify(&global, &sig.global_signature)
            .map_err(|_| ReleaseError::BadSignature)?;
        Ok(sig.trusted_comment)
    }
}

/// A parsed `.minisig` file.
struct Minisig {
    prehashed: bool,
    key_id: [u8; 8],
    signature: [u8; 64],
    trusted_comment: String,
    global_signature: [u8; 64],
}

impl Minisig {
    fn parse(text: &str) -> Result<Self, ReleaseError> {
        let bad = |what: &str| ReleaseError::Signature(what.to_owned());
        let mut lines = text.lines();
        let (Some(untrusted), Some(sig), Some(trusted), Some(global)) =
            (lines.next(), lines.next(), lines.next(), lines.next())
        else {
            return Err(bad("expected four lines"));
        };
        if !untrusted.starts_with("untrusted comment:") {
            return Err(bad("missing the untrusted comment"));
        }
        let trusted_comment = trusted
            .strip_prefix("trusted comment: ")
            .ok_or_else(|| bad("missing the trusted comment"))?
            .to_owned();
        let sig = STANDARD
            .decode(sig.trim())
            .map_err(|e| ReleaseError::Signature(e.to_string()))?;
        let global = STANDARD
            .decode(global.trim())
            .map_err(|e| ReleaseError::Signature(e.to_string()))?;
        if sig.len() != 74 || global.len() != 64 {
            return Err(bad("wrong length"));
        }
        let prehashed = match &sig[..2] {
            b"ED" => true,
            b"Ed" => false,
            _ => return Err(bad("not an Ed25519 signature")),
        };
        Ok(Self {
            prehashed,
            key_id: sig[2..10].try_into().map_err(|_| bad("key ID"))?,
            signature: sig[10..74].try_into().map_err(|_| bad("signature"))?,
            trusted_comment,
            global_signature: global
                .as_slice()
                .try_into()
                .map_err(|_| bad("global signature"))?,
        })
    }
}

/// The release manifest `release.json` (design/release.md section 7): the latest version and the
/// program for each target. It is not signed: every program is checked against the release
/// signature before it is installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: String,
    pub programs: BTreeMap<String, Program>,
}

/// The bare program for one target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    /// An `https://` URL.
    pub url: String,
    /// Lowercase hex.
    pub sha256: String,
    /// The `.minisig` text.
    pub minisig: String,
}

impl Manifest {
    /// Parses and checks a manifest received from the network (hard rule 13).
    pub fn parse(bytes: &[u8]) -> Result<Self, ReleaseError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ReleaseError::Manifest("too large".into()));
        }
        let manifest: Self =
            serde_json::from_slice(bytes).map_err(|e| ReleaseError::Manifest(e.to_string()))?;
        manifest.version()?;
        for (target, program) in &manifest.programs {
            if !program.url.starts_with("https://") || program.url.len() > 2048 {
                return Err(ReleaseError::Manifest(format!(
                    "{target}: the URL must be https"
                )));
            }
            if program.sha256.len() != 64
                || !program
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(ReleaseError::Manifest(format!(
                    "{target}: the SHA-256 is not 64 lowercase hex digits"
                )));
            }
            Minisig::parse(&program.minisig)?;
        }
        Ok(manifest)
    }

    pub fn version(&self) -> Result<Version, ReleaseError> {
        self.version.parse()
    }
}

/// The signed comment of a release program: it binds the version and the target, so an older
/// signed program cannot be offered as a newer one.
pub fn trusted_comment(version: Version, target: &str) -> String {
    format!("nett v{version} nett-{version}-{target}")
}

/// The release target this program was built for, as release archives name it.
pub fn current_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-musl"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-musl"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        _ => None,
    }
}

/// Checks a downloaded program for `target` against the manifest: SHA-256, release signature and
/// the signed comment for this version and target.
pub fn verify_program(
    keys: &ReleaseKeys,
    version: Version,
    target: &str,
    program: &Program,
    bytes: &[u8],
) -> Result<(), ReleaseError> {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    if hex != program.sha256 {
        return Err(ReleaseError::Digest);
    }
    let comment = keys.verify(bytes, &program.minisig)?;
    let expected = trusted_comment(version, target);
    if comment != expected {
        return Err(ReleaseError::Comment {
            found: comment,
            expected,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    use super::*;

    const PRIMARY: &str = include_str!("../../../keys/nett-release-primary.pub");
    const BACKUP: &str = include_str!("../../../keys/nett-release-backup.pub");

    /// A test key with its minisign public key line.
    fn key(id: u8) -> (Ed25519KeyPair, [u8; 8], String) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("key");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("key");
        let key_id = [id; 8];
        let mut public = b"Ed".to_vec();
        public.extend_from_slice(&key_id);
        public.extend_from_slice(pair.public_key().as_ref());
        let line = format!("untrusted comment: test key\n{}\n", STANDARD.encode(public));
        (pair, key_id, line)
    }

    /// What `minisign -S` writes; `prehashed` as minisign 0.11 and later do by default.
    fn sign(
        pair: &Ed25519KeyPair,
        id: [u8; 8],
        data: &[u8],
        comment: &str,
        prehashed: bool,
    ) -> String {
        use blake2::digest::Digest as _;
        let digest = blake2::Blake2b512::digest(data);
        let message: &[u8] = if prehashed { digest.as_slice() } else { data };
        let signature = pair.sign(message);
        let mut sig = if prehashed {
            b"ED".to_vec()
        } else {
            b"Ed".to_vec()
        };
        sig.extend_from_slice(&id);
        sig.extend_from_slice(signature.as_ref());
        let mut global = signature.as_ref().to_vec();
        global.extend_from_slice(comment.as_bytes());
        format!(
            "untrusted comment: signature\n{}\ntrusted comment: {comment}\n{}\n",
            STANDARD.encode(sig),
            STANDARD.encode(pair.sign(&global).as_ref())
        )
    }

    #[test]
    fn the_published_release_verifies_against_the_project_keys() {
        // SHA256SUMS of v0.1.5 and its signature, as published on the releases page
        let keys = ReleaseKeys::parse(&format!("{PRIMARY}\n{BACKUP}")).expect("keys");
        let data = include_bytes!("../tests/data/SHA256SUMS");
        let sig = include_str!("../tests/data/SHA256SUMS.minisig");
        assert_eq!(
            keys.verify(data, sig).expect("verified"),
            "nett v0.1.5 SHA256SUMS"
        );
        let mut tampered = data.to_vec();
        tampered[0] ^= 1;
        assert_eq!(keys.verify(&tampered, sig), Err(ReleaseError::BadSignature));
        // the backup key alone does not accept what the primary key signed
        assert!(matches!(
            ReleaseKeys::parse(BACKUP)
                .expect("backup")
                .verify(data, sig),
            Err(ReleaseError::UnknownKey(_))
        ));
        assert!(format!("{keys:?}").contains("16CDF76C9920EED7"));
    }

    #[test]
    fn programs_need_the_digest_the_signature_and_the_signed_comment() {
        let (pair, id, line) = key(1);
        let keys = ReleaseKeys::parse(&line).expect("keys");
        let version: Version = "0.2.0".parse().expect("version");
        let target = "x86_64-unknown-linux-musl";
        let bytes = b"the new program".to_vec();
        let hex = |b: &[u8]| -> String {
            ring::digest::digest(&ring::digest::SHA256, b)
                .as_ref()
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect()
        };
        for prehashed in [true, false] {
            let program = Program {
                url: "https://nett.example.com/dl/nett".into(),
                sha256: hex(&bytes),
                minisig: sign(
                    &pair,
                    id,
                    &bytes,
                    &trusted_comment(version, target),
                    prehashed,
                ),
            };
            verify_program(&keys, version, target, &program, &bytes).expect("verified");
            // another program under the same manifest entry
            assert_eq!(
                verify_program(&keys, version, target, &program, b"other"),
                Err(ReleaseError::Digest)
            );
            // an older signed program offered as this version, or for another target
            assert!(matches!(
                verify_program(&keys, "0.3.0".parse().expect("v"), target, &program, &bytes),
                Err(ReleaseError::Comment { .. })
            ));
            assert!(matches!(
                verify_program(&keys, version, "aarch64-apple-darwin", &program, &bytes),
                Err(ReleaseError::Comment { .. })
            ));
        }
        // signed by a key this build does not trust
        let (other, other_id, _) = key(2);
        let program = Program {
            url: "https://nett.example.com/dl/nett".into(),
            sha256: hex(&bytes),
            minisig: sign(
                &other,
                other_id,
                &bytes,
                &trusted_comment(version, target),
                true,
            ),
        };
        assert!(matches!(
            verify_program(&keys, version, target, &program, &bytes),
            Err(ReleaseError::UnknownKey(_))
        ));
        // the signed comment changed after signing
        let forged = sign(&pair, id, &bytes, "nett v0.1.0 x", true)
            .replace("nett v0.1.0 x", &trusted_comment(version, target));
        assert_eq!(
            keys.verify(&bytes, &forged),
            Err(ReleaseError::BadSignature)
        );
    }

    #[test]
    fn manifests_and_versions_from_the_network_are_checked() {
        let (pair, id, _) = key(3);
        let good = |url: &str, sha256: &str| {
            serde_json::json!({
                "version": "0.2.0",
                "programs": { "x86_64-unknown-linux-musl": {
                    "url": url, "sha256": sha256, "minisig": sign(&pair, id, b"p", "c", true)
                }}
            })
            .to_string()
        };
        let digest = "ab".repeat(32);
        let manifest = Manifest::parse(good("https://nett.example.com/p", &digest).as_bytes())
            .expect("manifest");
        assert_eq!(manifest.version().expect("v").to_string(), "0.2.0");
        assert!(Manifest::parse(good("http://nett.example.com/p", &digest).as_bytes()).is_err());
        assert!(Manifest::parse(good("file:///etc/passwd", &digest).as_bytes()).is_err());
        assert!(Manifest::parse(good("https://x/p", &"AB".repeat(32)).as_bytes()).is_err());
        assert!(Manifest::parse(&vec![b' '; MAX_MANIFEST_BYTES + 1]).is_err());
        assert!(Manifest::parse(br#"{"version":"0.2","programs":{}}"#).is_err());

        let v = |s: &str| s.parse::<Version>();
        assert!(v("0.10.0").expect("v") > v("0.9.9").expect("v"));
        assert!(v("1.0.0").expect("v") > v("0.99.99").expect("v"));
        for bad in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "1.2.x",
            "v1.2.3",
            "1.2.3-rc1",
            "+1.2.3",
            "1..2",
        ] {
            assert!(v(bad).is_err(), "{bad}");
        }
        assert!(current_target().is_some(), "built for a release target");
    }
}
