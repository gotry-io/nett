//! Fetching the program of a release (design/release.md section 7, ADR 0025): from the Hub over
//! the session, then from the URL in the manifest. The program is written to disk as it arrives and
//! hashed on the way, so it is never held whole; what decides whether it is installed is the
//! release signature over those digests, not where it came from.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nett_trust::release::{Digests, MAX_PROGRAM_BYTES, ProgramDigest};
use tokio::sync::mpsc;

/// The Hub has this long to send the first part of a program; a Hub that does not know
/// `ProgramFetch` ignores it (design/protocol.md section 9).
pub const HUB_FIRST_PART: Duration = Duration::from_secs(10);
/// A source that sends nothing for this long is abandoned.
pub const NO_PROGRESS: Duration = Duration::from_secs(60);
/// Parts queued between the session and the upgrade (hard rule 14); the upgrade writes each to disk
/// as it comes.
const PART_QUEUE: usize = 8;

/// Why a source did not deliver a program.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// Unreachable, stalled, cut off, or the Hub does not hold the program yet: the program is
    /// fetched again later.
    #[error("{0}")]
    Unavailable(String),
    /// What arrived cannot be this release's program: too large, or out of order.
    #[error("{0}")]
    Refused(String),
}

/// A program being written: the file and the digests of what reached it.
pub struct ProgramFile {
    path: PathBuf,
    file: std::fs::File,
    digest: ProgramDigest,
}

impl ProgramFile {
    /// Starts an empty executable at `path` (root's, mode `0755`), replacing what was there
    /// without following links.
    pub fn create(path: &Path) -> Result<Self, String> {
        std::fs::remove_file(path).ok();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| format!("creating {}: {e}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            digest: ProgramDigest::new(),
        })
    }

    pub fn len(&self) -> u64 {
        self.digest.len()
    }

    pub fn is_empty(&self) -> bool {
        self.digest.is_empty()
    }

    pub fn write(&mut self, data: &[u8]) -> Result<(), FetchError> {
        if self.len() + data.len() as u64 > MAX_PROGRAM_BYTES as u64 {
            return Err(FetchError::Refused(format!(
                "the program is larger than {MAX_PROGRAM_BYTES} bytes"
            )));
        }
        self.file.write_all(data).map_err(|e| {
            FetchError::Unavailable(format!("writing {}: {e}", self.path.display()))
        })?;
        self.digest.update(data);
        Ok(())
    }

    /// Flushes the program to disk and returns its digests.
    pub fn finish(self) -> Result<Digests, String> {
        self.file
            .sync_all()
            .map_err(|e| format!("writing {}: {e}", self.path.display()))?;
        Ok(self.digest.finish())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// How much of `size` bytes arrived, for messages.
fn progress(received: u64, size: Option<u64>) -> String {
    let mib = |b: u64| b as f64 / (1024.0 * 1024.0);
    match size {
        Some(size) => format!("{:.1} of {:.1} MiB", mib(received), mib(size)),
        None => format!("{:.1} MiB", mib(received)),
    }
}

/// One part of a program from the Hub, as the session hands it on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    Data {
        offset: u64,
        size: u64,
        data: Vec<u8>,
    },
    /// The Hub does not hold this program.
    NotFound,
}

/// A program the upgrade asks the session to fetch from the Hub, and where its parts go.
pub struct FetchRequest {
    pub version: String,
    pub target: String,
    pub parts: mpsc::Sender<Part>,
}

/// The way between the upgrade, which outlives connections, and the session connected now: the
/// upgrade puts a request in, the session that takes it sends `ProgramFetch` and hands the parts
/// over (design/protocol.md section 5).
pub struct HubLink {
    requests: mpsc::Sender<FetchRequest>,
    /// Taken by the session for as long as it lasts.
    pub pending: tokio::sync::Mutex<mpsc::Receiver<FetchRequest>>,
}

impl Default for HubLink {
    fn default() -> Self {
        Self::new()
    }
}

impl HubLink {
    pub fn new() -> Self {
        let (requests, pending) = mpsc::channel(1);
        Self {
            requests,
            pending: tokio::sync::Mutex::new(pending),
        }
    }
}

/// Fetches the program of `version` for `target` from the Hub into `file`.
pub async fn from_hub(
    link: &HubLink,
    version: &str,
    target: &str,
    file: &mut ProgramFile,
) -> Result<(), FetchError> {
    let (parts, mut arrived) = mpsc::channel(PART_QUEUE);
    let request = FetchRequest {
        version: version.to_owned(),
        target: target.to_owned(),
        parts,
    };
    // An earlier request no session took yet still waits: this one replaces it
    if let Err(mpsc::error::TrySendError::Full(request)) = link.requests.try_send(request) {
        if let Ok(mut pending) = link.pending.try_lock() {
            let _ = pending.try_recv();
        }
        let _ = link.requests.try_send(request);
    }
    let mut size = None;
    loop {
        let wait = if file.is_empty() {
            HUB_FIRST_PART
        } else {
            NO_PROGRESS
        };
        let part = tokio::time::timeout(wait, arrived.recv())
            .await
            .map_err(|_| {
                FetchError::Unavailable(format!(
                    "from the Hub: nothing arrived for {wait:?} after {}",
                    progress(file.len(), size)
                ))
            })?
            .ok_or_else(|| {
                FetchError::Unavailable(format!(
                    "from the Hub: the connection ended after {}",
                    progress(file.len(), size)
                ))
            })?;
        let (offset, whole, data) = match part {
            Part::NotFound => {
                return Err(FetchError::Unavailable(
                    "the Hub does not hold this program yet".into(),
                ));
            }
            Part::Data { offset, size, data } => (offset, size, data),
        };
        if offset != file.len() || size.is_some_and(|s| s != whole) {
            return Err(FetchError::Refused(format!(
                "from the Hub: a part at {offset} where {} was expected",
                file.len()
            )));
        }
        size = Some(whole);
        file.write(&data)?;
        if file.len() >= whole {
            return if file.len() == whole {
                Ok(())
            } else {
                Err(FetchError::Refused(format!(
                    "from the Hub: {} bytes for a program of {whole}",
                    file.len()
                )))
            };
        }
    }
}

/// Fetches the program from its `https://` URL into `file`, from the start.
pub async fn from_url(url: &str, file: &mut ProgramFile) -> Result<(), FetchError> {
    let mut refused = None;
    let result = crate::http::get_streaming(url, MAX_PROGRAM_BYTES as u64, NO_PROGRESS, |data| {
        file.write(data).map_err(|e| {
            let reason = e.to_string();
            refused = Some(e);
            reason
        })
    })
    .await;
    match (result, refused) {
        (Ok(()), _) => Ok(()),
        (Err(_), Some(e)) => Err(e),
        (Err(crate::http::HttpError::TooLarge { .. }), None) => Err(FetchError::Refused(format!(
            "{url}: the program is larger than {MAX_PROGRAM_BYTES} bytes"
        ))),
        (Err(e), None) => Err(FetchError::Unavailable(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::Builder::new()
            .prefix("nett-fetch-")
            .tempdir()
            .expect("temp dir");
        let path = tmp.path().join("nett.new");
        (tmp, path)
    }

    /// The session hands each part on as it arrives; the program on disk is exactly what was sent,
    /// and its digests are those of the whole
    #[tokio::test]
    async fn a_program_from_the_hub_is_written_part_by_part() {
        let (_tmp, path) = temp();
        let link = HubLink::new();
        let program: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let sent = program.clone();
        let session = async {
            let request = link.pending.lock().await.recv().await.expect("request");
            assert_eq!(
                (request.version.as_str(), request.target.as_str()),
                ("0.2.0", "t")
            );
            let size = sent.len() as u64;
            for (n, chunk) in sent.chunks(48 * 1024).enumerate() {
                let offset = (n * 48 * 1024) as u64;
                request
                    .parts
                    .send(Part::Data {
                        offset,
                        size,
                        data: chunk.to_vec(),
                    })
                    .await
                    .expect("send");
            }
        };
        let mut file = ProgramFile::create(&path).expect("file");
        let (fetched, ()) = tokio::join!(from_hub(&link, "0.2.0", "t", &mut file), session);
        fetched.expect("fetched");
        let digests = file.finish().expect("digests");
        assert_eq!(std::fs::read(&path).expect("read"), program);
        let mut whole = ProgramDigest::new();
        whole.update(&program);
        assert_eq!(digests, whole.finish());
    }

    /// A Hub that does not hold the program, does not answer, or loses the connection leaves the
    /// version to be fetched again later; parts out of order are refused
    #[tokio::test(start_paused = true)]
    async fn what_the_hub_does_not_deliver_is_unavailable() {
        let (_tmp, path) = temp();
        let link = HubLink::new();
        let mut file = ProgramFile::create(&path).expect("file");
        let not_found = async {
            let request = link.pending.lock().await.recv().await.expect("request");
            request.parts.send(Part::NotFound).await.expect("send");
        };
        let (result, ()) = tokio::join!(from_hub(&link, "0.2.0", "t", &mut file), not_found);
        assert!(matches!(result, Err(FetchError::Unavailable(r)) if r.contains("does not hold")));

        // no session takes the request: an older Hub, or none connected
        let result = from_hub(&link, "0.2.0", "t", &mut file).await;
        assert!(matches!(result, Err(FetchError::Unavailable(r)) if r.contains("nothing arrived")));

        let cut = async {
            let request = link.pending.lock().await.recv().await.expect("request");
            request
                .parts
                .send(Part::Data {
                    offset: 0,
                    size: 10,
                    data: vec![1; 4],
                })
                .await
                .expect("send");
        };
        let mut file = ProgramFile::create(&path).expect("file");
        let (result, ()) = tokio::join!(from_hub(&link, "0.2.0", "t", &mut file), cut);
        assert!(
            matches!(result, Err(FetchError::Unavailable(r)) if r.contains("connection ended after"))
        );

        let disorder = async {
            let request = link.pending.lock().await.recv().await.expect("request");
            request
                .parts
                .send(Part::Data {
                    offset: 4,
                    size: 10,
                    data: vec![1; 4],
                })
                .await
                .expect("send");
        };
        let mut file = ProgramFile::create(&path).expect("file");
        let (result, ()) = tokio::join!(from_hub(&link, "0.2.0", "t", &mut file), disorder);
        assert!(matches!(result, Err(FetchError::Refused(_))));
    }

    #[test]
    fn a_program_larger_than_any_release_is_refused() {
        let (_tmp, path) = temp();
        let mut file = ProgramFile::create(&path).expect("file");
        let big = vec![0u8; MAX_PROGRAM_BYTES];
        file.write(&big).expect("up to the limit");
        assert!(matches!(file.write(&[0]), Err(FetchError::Refused(_))));
    }
}
