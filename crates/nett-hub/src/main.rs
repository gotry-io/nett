//! `nett-hub`：组网的控制面，没有界面（ADR 0024，design/hub.md）。命令见 hub.md 第 8 节：`serve` 运行服务，
//! `init` 打印一次性的关联码，`reset` 作废与站点的关联。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use lexopt::ValueExt as _;
use nett_hub::{api, db, hub, now, random, sha256, tls};
use nett_mesh::key::PrivateKey;
use nett_proto::token::{Bytes32, LinkCode};

/// 关联码的有效期（auth.md 第 4.1 节）。
const LINK_VALIDITY_SECS: i64 = 3600;
const DEFAULT_DATA: &str = "/var/lib/nett-hub";
const DEFAULT_LISTEN: &str = "127.0.0.1:8480";
const KEY_FILE: &str = "hub.key";
const DB_FILE: &str = "hub.db";

const USAGE: &str = "usage: nett-hub <command> [--data <dir>]

  serve [--listen <address:port>] [--tls-cert <cert.pem> --tls-key <key.pem>]
                       run the Hub; it listens on 127.0.0.1:8480 behind a reverse proxy by default
  init --url https://<host> [--tls-cert <cert.pem>]
                       print a one-time link code for `nett site link`, valid for an hour
  reset                forget the linked site and its machines; the Hub identity key stays

The data directory defaults to /var/lib/nett-hub.";

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
        .with_writer(std::io::stderr)
        .init();
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nett-hub: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let mut parser = lexopt::Parser::from_env();
    let mut words = Vec::new();
    let mut data = PathBuf::from(DEFAULT_DATA);
    let (mut listen, mut url, mut cert, mut key) = (None, None, None, None);
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Value(v) => words.push(v.string()?),
            lexopt::Arg::Long("data") => data = PathBuf::from(parser.value()?),
            lexopt::Arg::Long("listen") => listen = Some(parser.value()?.string()?),
            lexopt::Arg::Long("url") => url = Some(parser.value()?.string()?),
            lexopt::Arg::Long("tls-cert") => cert = Some(PathBuf::from(parser.value()?)),
            lexopt::Arg::Long("tls-key") => key = Some(PathBuf::from(parser.value()?)),
            lexopt::Arg::Long("help") | lexopt::Arg::Short('h') => {
                println!("{USAGE}");
                return Ok(());
            }
            other => return Err(other.unexpected().into()),
        }
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    match words.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["serve"] => {
            let listen: SocketAddr = listen
                .as_deref()
                .unwrap_or(DEFAULT_LISTEN)
                .parse()
                .context("--listen")?;
            let tls = match (cert, key) {
                (Some(c), Some(k)) => Some((c, k)),
                (None, None) => None,
                _ => bail!("--tls-cert and --tls-key go together"),
            };
            runtime.block_on(serve(&data, listen, tls))
        }
        ["init"] => {
            let url = url.context("--url https://<host> is needed: machines and the site connect there")?;
            runtime.block_on(init(&data, &url, cert.as_deref()))
        }
        ["reset"] => runtime.block_on(async {
            let db = db::Db::open(&data.join(DB_FILE)).await?;
            db.reset().await?;
            println!("Forgot the linked site and its machines. Run `nett-hub init --url …` for a new link code.");
            anyhow::Ok(())
        }),
        _ => bail!(USAGE),
    }
}

/// 数据目录（`0700`）与 Hub 身份密钥（`0600`，没有时生成）。
fn prepare(data: &Path) -> anyhow::Result<PrivateKey> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(data)
        .with_context(|| format!("creating {}", data.display()))?;
    let path = data.join(KEY_FILE);
    if path.exists() {
        return Ok(PrivateKey::load(&path)?);
    }
    let key = PrivateKey::generate()?;
    key.save_new(&path)?;
    Ok(key)
}

fn fingerprint(cert: &Path) -> anyhow::Result<[u8; 32]> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject as _;
    let der = CertificateDer::from_pem_file(cert)
        .with_context(|| format!("reading {}", cert.display()))?;
    let digest = ring::digest::digest(&ring::digest::SHA256, der.as_ref());
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

async fn init(data: &Path, url: &str, cert: Option<&Path>) -> anyhow::Result<()> {
    if !url.starts_with("https://") {
        bail!("--url must start with https://: machines verify the Hub's certificate");
    }
    let key = prepare(data)?;
    let db = db::Db::open(&data.join(DB_FILE)).await?;
    let secret =
        random::<32>().map_err(|_| anyhow::anyhow!("the system random number generator failed"))?;
    if !db
        .set_link(
            url.trim_end_matches('/'),
            &sha256(&secret),
            now() + LINK_VALIDITY_SECS,
        )
        .await?
    {
        bail!("this Hub is already linked to a site; `nett-hub reset` forgets it first");
    }
    let code = LinkCode {
        url: url.trim_end_matches('/').to_owned(),
        hub_key: Bytes32(*key.public_key().as_bytes()),
        secret: Bytes32(secret),
        tls_fingerprint: cert.map(fingerprint).transpose()?.map(Bytes32),
    };
    println!(
        "Hub initialized. Link your site from the computer that holds it, within 1 hour:\n  nett site link {}",
        code.encode()
    );
    if cert.is_none() {
        // 在反向代理之后（design/hub.md 第 8 节）：只转发这两段路径，不改用户自己的其他配置
        let host = url.trim_start_matches("https://").trim_end_matches('/');
        println!(
            "\nThe reverse proxy in front of the Hub forwards two paths to it, for example in Caddy:\n  \
             {host} {{\n      reverse_proxy /api/v1/* 127.0.0.1:8480\n      \
             reverse_proxy /node/v1/connect 127.0.0.1:8480\n  }}"
        );
    }
    Ok(())
}

async fn serve(
    data: &Path,
    listen: SocketAddr,
    tls: Option<(PathBuf, PathBuf)>,
) -> anyhow::Result<()> {
    let key = prepare(data)?;
    let db = db::Db::open(&data.join(DB_FILE)).await?;
    let url =
        db.hub().await?.map(|h| h.url).context(
            "the Hub is not initialized; run `nett-hub init --url https://<host>` first",
        )?;
    let hub = hub::Hub::load(db, x25519_dalek::StaticSecret::from(*key.as_bytes()), url)
        .await
        .map_err(anyhow::Error::msg)?;
    let app = api::router(hub);
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("listening on {listen}"))?;
    tracing::info!(%listen, tls = tls.is_some(), "Hub listening");
    let shutdown = async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("installing the SIGTERM handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    };
    match tls {
        None => {
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await?
        }
        Some((cert, key)) => {
            let acceptor = tls::acceptor(&cert, &key)?;
            axum::serve(tls::TlsListener::new(listener, acceptor), app)
                .with_graceful_shutdown(shutdown)
                .await?;
        }
    }
    Ok(())
}
