//! The Hub's copy of the programs of the current release (design/release.md section 7, ADR 0025),
//! which nodes fetch over their session. The Hub verifies each program the way nodes do and serves
//! only what holds; nodes verify again before installing, so the copy can withhold an upgrade but
//! cannot change what is installed.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use nett_node::fetch::{FetchError, ProgramFile};
use nett_trust::release::{
    Digests, MAX_PROGRAM_BYTES, Manifest, Program, ProgramDigest, ReleaseError, ReleaseKeys,
    Version, verify_program_digests,
};

/// The directory under the Hub's data directory.
pub const DIR: &str = "releases";
/// Bytes read at a time when checking a program already on disk.
const READ_CHUNK: usize = 64 * 1024;

/// A verified program the Hub serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub path: PathBuf,
    pub size: u64,
    /// The manifest's SHA-256 it was verified against.
    sha256: String,
}

/// The programs held for one version.
#[derive(Debug, Default)]
struct Current {
    version: Option<Version>,
    programs: HashMap<String, Held>,
    /// Programs that match the manifest but whose signature does not hold for the Hub's keys, by
    /// target and SHA-256: fetching them again gives the same bytes.
    refused: HashMap<String, String>,
}

/// Why a program is not held.
enum NotHeld {
    /// Not fetched, or the bytes differ from the manifest: fetched again later.
    Unavailable(String),
    /// The bytes the manifest names, with a signature that does not hold.
    Refused(String),
}

pub struct Mirror {
    dir: PathBuf,
    keys: ReleaseKeys,
    current: Mutex<Arc<Current>>,
}

impl Mirror {
    /// A mirror in `releases/` under the data directory, trusting `keys`.
    pub fn new(data: &Path, keys: ReleaseKeys) -> Self {
        Self {
            dir: data.join(DIR),
            keys,
            current: Mutex::new(Arc::new(Current::default())),
        }
    }

    fn current(&self) -> Arc<Current> {
        self.current
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The verified program of `version` for `target`, when the Hub holds it.
    pub fn get(&self, version: &str, target: &str) -> Option<Held> {
        let current = self.current();
        if current.version?.to_string() != version {
            return None;
        }
        current.programs.get(target).cloned()
    }

    /// Whether the program of `version` for `target` matches its manifest but its signature does
    /// not hold for the Hub's keys: the Hub cannot run it.
    pub fn refused(&self, version: &str, target: &str) -> bool {
        let current = self.current();
        current.version.is_some_and(|v| v.to_string() == version)
            && current.refused.contains_key(target)
    }

    /// Holds the programs of `manifest`: keeps those already held, checks one already on disk, and
    /// fetches the others from their URL. The programs of other versions are deleted. Returns why
    /// each program not held yet could not be, for fetching again later; a program whose signature
    /// does not hold is not among them, nodes fetch it from its URL and refuse it themselves.
    pub async fn update(&self, manifest: &Manifest) -> Vec<String> {
        let version = match manifest.version() {
            Ok(v) => v,
            Err(e) => return vec![e.to_string()],
        };
        if let Err(e) = create_dir(&self.dir) {
            return vec![e];
        }
        let before = self.current();
        let same = before.version == Some(version);
        let mut programs = HashMap::new();
        let mut refused = HashMap::new();
        let mut missing = Vec::new();
        for (target, program) in &manifest.programs {
            if same
                && let Some(held) = before.programs.get(target)
                && held.sha256 == program.sha256
            {
                programs.insert(target.clone(), held.clone());
                continue;
            }
            if same && before.refused.get(target) == Some(&program.sha256) {
                refused.insert(target.clone(), program.sha256.clone());
                continue;
            }
            match self.hold(version, target, program).await {
                Ok(held) => {
                    tracing::info!(%version, %target, bytes = held.size, "holding the program of the release");
                    programs.insert(target.clone(), held);
                }
                Err(NotHeld::Refused(reason)) => {
                    tracing::warn!(%version, %target, %reason, "the program of the release does not verify; the Hub does not serve it");
                    refused.insert(target.clone(), program.sha256.clone());
                }
                Err(NotHeld::Unavailable(reason)) => {
                    tracing::warn!(%version, %target, %reason, "fetching the program of the release");
                    missing.push(format!("{target}: {reason}"));
                }
            }
        }
        let keep: Vec<PathBuf> = programs.values().map(|h| h.path.clone()).collect();
        *self.current.lock().unwrap_or_else(PoisonError::into_inner) = Arc::new(Current {
            version: Some(version),
            programs,
            refused,
        });
        let dir = self.dir.clone();
        let _ = tokio::task::spawn_blocking(move || remove_others(&dir, &keep)).await;
        missing
    }

    /// The verified program of `version` for `target`, from disk or from its URL.
    async fn hold(
        &self,
        version: Version,
        target: &str,
        program: &Program,
    ) -> Result<Held, NotHeld> {
        let path = self.dir.join(format!("nett-{version}-{target}"));
        let held = |path: PathBuf, size: u64| Held {
            path,
            size,
            sha256: program.sha256.clone(),
        };
        let verify = |digests: &Digests| match verify_program_digests(
            &self.keys, version, target, program, digests,
        ) {
            Ok(()) => Ok(()),
            Err(e @ ReleaseError::Digest) => Err(NotHeld::Unavailable(e.to_string())),
            Err(e) => Err(NotHeld::Refused(e.to_string())),
        };
        if let Some(on_disk) = digest_file(&path).await.map_err(NotHeld::Unavailable)? {
            let verified = verify(&on_disk.digests);
            if verified.is_ok() {
                return Ok(held(path, on_disk.size));
            }
            tokio::fs::remove_file(&path).await.ok();
            if let Err(refused @ NotHeld::Refused(_)) = verified {
                return Err(refused);
            }
        }
        let part = self.dir.join(format!("nett-{version}-{target}.part"));
        let mut file = ProgramFile::create(&part).map_err(NotHeld::Unavailable)?;
        let fetched = nett_node::fetch::from_url(&program.url, &mut file).await;
        let size = file.len();
        let verified = fetched
            .map_err(|e| match e {
                FetchError::Unavailable(r) | FetchError::Refused(r) => NotHeld::Unavailable(r),
            })
            .and_then(|()| file.finish().map_err(NotHeld::Unavailable))
            .and_then(|digests| verify(&digests));
        if let Err(e) = verified {
            tokio::fs::remove_file(&part).await.ok();
            return Err(e);
        }
        tokio::fs::rename(&part, &path)
            .await
            .map_err(|e| NotHeld::Unavailable(format!("renaming {}: {e}", part.display())))?;
        Ok(held(path, size))
    }
}

struct FileDigests {
    size: u64,
    digests: Digests,
}

/// The digests of a regular file at `path`, or `None` when there is none.
async fn digest_file(path: &Path) -> Result<Option<FileDigests>, String> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("opening {}: {e}", path.display())),
        };
        let meta = file
            .metadata()
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        if !meta.is_file() || meta.len() > MAX_PROGRAM_BYTES as u64 {
            return Ok(None);
        }
        let mut digest = ProgramDigest::new();
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| format!("reading {}: {e}", path.display()))?;
            if n == 0 {
                break;
            }
            digest.update(&buf[..n]);
        }
        Ok(Some(FileDigests {
            size: digest.len(),
            digests: digest.finish(),
        }))
    })
    .await
    .map_err(|e| format!("checking a program on disk: {e}"))?
}

fn create_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("creating {}: {e}", dir.display()))
}

/// Deletes everything in `dir` but `keep`: programs of other versions and unfinished downloads.
fn remove_others(dir: &Path, keep: &[PathBuf]) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !keep.contains(&path)
            && let Err(e) = std::fs::remove_file(&path)
        {
            tracing::warn!(path = %path.display(), error = %e, "deleting a program the Hub no longer serves");
        }
    }
}

#[cfg(test)]
mod tests {
    use nett_trust::signing::ReleaseKeyPair;

    use super::*;

    const TARGET: &str = "x86_64-unknown-linux-musl";
    /// Nothing listens there: no program is fetched from the network in these tests
    const NOWHERE: &str = "https://127.0.0.1:9/nett";

    fn setup() -> (tempfile::TempDir, ReleaseKeyPair, Mirror) {
        let tmp = tempfile::Builder::new()
            .prefix("nett-hub-mirror-")
            .tempdir()
            .expect("temp dir");
        let pair = ReleaseKeyPair::generate().expect("key");
        let keys = ReleaseKeys::parse(&pair.public_key()).expect("keys");
        let mirror = Mirror::new(tmp.path(), keys);
        (tmp, pair, mirror)
    }

    fn manifest(pair: &ReleaseKeyPair, version: &str, program: &[u8]) -> Manifest {
        let version: Version = version.parse().expect("version");
        Manifest::parse(&pair.manifest(version, TARGET, NOWHERE, program)).expect("manifest")
    }

    /// A program on disk is served only when it verifies against the manifest; one that does not is
    /// deleted and, with its URL unreachable, reported as not held, to be fetched again later
    #[tokio::test]
    async fn only_verified_programs_are_served() {
        let (tmp, pair, mirror) = setup();
        let dir = tmp.path().join(DIR);
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join(format!("nett-0.2.0-{TARGET}"));
        std::fs::write(&path, b"tampered").expect("write");
        let missing = mirror.update(&manifest(&pair, "0.2.0", b"program")).await;
        assert_eq!(missing.len(), 1, "{missing:?}");
        assert!(!path.exists(), "a program that does not verify is deleted");
        assert_eq!(mirror.get("0.2.0", TARGET), None);

        std::fs::write(&path, b"program").expect("write");
        assert!(
            mirror
                .update(&manifest(&pair, "0.2.0", b"program"))
                .await
                .is_empty()
        );
        let held = mirror.get("0.2.0", TARGET).expect("held");
        assert_eq!((held.path.as_path(), held.size), (path.as_path(), 7));
        // Only by its exact version and target
        assert_eq!(mirror.get("0.2.1", TARGET), None);
        assert_eq!(mirror.get("0.2.0", "aarch64-apple-darwin"), None);

        // A newer release replaces it: the older program is deleted, the newer one not held yet
        let missing = mirror.update(&manifest(&pair, "0.3.0", b"newer")).await;
        assert_eq!(missing.len(), 1, "{missing:?}");
        assert!(!path.exists());
        assert_eq!(mirror.get("0.2.0", TARGET), None);
    }

    /// A program signed by a key the Hub does not trust is not served, even with the right SHA-256
    #[tokio::test]
    async fn a_program_signed_by_another_key_is_not_served() {
        let (tmp, _pair, mirror) = setup();
        let other = ReleaseKeyPair::generate().expect("key");
        let dir = tmp.path().join(DIR);
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(dir.join(format!("nett-0.2.0-{TARGET}")), b"program").expect("write");
        // Not fetched again: the same bytes would not verify either
        let manifest = manifest(&other, "0.2.0", b"program");
        for _ in 0..2 {
            assert!(mirror.update(&manifest).await.is_empty());
            assert_eq!(mirror.get("0.2.0", TARGET), None);
        }
    }
}
