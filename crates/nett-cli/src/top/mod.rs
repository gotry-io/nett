//! The live views (design/top.md): `nett top` reads this machine's status every second, `nett site
//! top` every machine's through the Hub's stream. A thread reads for each and hands the screen what
//! it read over a bounded channel; the screen redraws and takes keys.

mod model;
mod screen;
mod sse;

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{SyncSender, TryRecvError, sync_channel};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use lexopt::ValueExt as _;
use nett_mesh::status::{self as mesh_status, StatusDoc};
use nett_node::http::{self, Target};
use nett_proto::api::{LINKS_STREAM_PATH, LiveSample, LiveStatus, STATUS_PATH, StatusResponse};
use nett_site::dir::SiteDir;
use nett_trust::encoding::Timestamp;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::hub::SiteHub;
use model::{Local, Site, Ui};

pub const USAGE: &str = "usage: nett top [--socket <path>]\n\n\
This machine and its peers, live. Keys: arrows or j k select, enter details, t traffic or rtt,\n\
q quit. `nett status --json` gives the same status to programs.";

/// The screen redraws at least this often, for the times it shows.
const FRAME: Duration = Duration::from_millis(250);
/// What a reader hands the screen, queued at most (hard rule 14).
const QUEUE: usize = 64;
/// How often `nett top` reads the status.
const LOCAL_EVERY: Duration = Duration::from_secs(1);
/// The stream sends a comment every 15 seconds; nothing for this long means it is gone.
const STREAM_IDLE: Duration = Duration::from_secs(30);
/// Opening the stream again: after 1 second, then twice as long each time up to 30 seconds.
const RETRY_FIRST: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);

/// `nett top` (design/top.md section 4).
pub fn local(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let mut socket = PathBuf::from(mesh_status::DEFAULT_SOCKET);
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("socket") => socket = PathBuf::from(parser.value()?.string()?),
            _ => bail!("{USAGE}"),
        }
    }
    need_terminal("nett status --json")?;
    // A daemon that cannot be reached at start ends the command, as `nett status` does
    let first = read_local(&socket).map_err(anyhow::Error::msg)?;
    let start = Instant::now();
    let mut model = Local::default();
    model.status(first, 0.0);
    let (tx, rx) = sync_channel(QUEUE);
    std::thread::spawn(move || local_reader(&socket, &tx));
    show(|ui, _| {
        loop {
            match rx.try_recv() {
                Ok((at, Ok(doc))) => model.status(doc, at.duration_since(start).as_secs_f64()),
                Ok((_, Err(e))) => model.failed(e),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    model.failed("the status reader stopped".into());
                    break;
                }
            }
        }
        (model.screen(Timestamp::now(), ui), model.rows())
    })
}

/// `nett site top` (design/top.md section 5).
pub fn site(dir: &Path) -> anyhow::Result<()> {
    let state = SiteDir::open(dir)?.load()?;
    let Some(hub) = SiteHub::load(dir)? else {
        bail!("the site is not linked to a Hub; `nett site top` shows the machines through it")
    };
    need_terminal("nett site status --json")?;
    let mut model = Site::new(state, &hub.url);
    let (tx, rx) = sync_channel(QUEUE);
    let (target, token) = (hub.target(), hub.token.clone());
    std::thread::spawn(move || site_reader(&target, &token, &tx));
    show(|ui, now| {
        loop {
            match rx.try_recv() {
                Ok(Read::Reply(reply)) => model.reply(reply),
                Ok(Read::Status(status)) => model.status(status),
                Ok(Read::Sample(sample, at)) => model.sample(sample, at),
                Ok(Read::Connection(text)) => model.connection(text),
                Err(_) => break,
            }
        }
        (model.screen(Timestamp::now(), now, ui), model.rows())
    })
}

fn need_terminal(for_programs: &str) -> anyhow::Result<()> {
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        bail!("this view needs a terminal; `{for_programs}` prints the status for programs");
    }
    Ok(())
}

/// Runs the screen until `q`: `frame` takes what arrived and returns the screen and its number of
/// rows. The terminal is restored on every way out; ratatui's panic hook restores it after a panic.
fn show(mut frame: impl FnMut(Ui, Instant) -> (model::Screen, usize)) -> anyhow::Result<()> {
    let mut terminal = ratatui::init();
    let result = (|| -> anyhow::Result<()> {
        let mut ui = Ui::default();
        loop {
            let (screen, rows) = frame(ui, Instant::now());
            ui.selected = ui.selected.min(rows.saturating_sub(1));
            terminal
                .draw(|f| screen::draw(f, &screen, ui))
                .context("drawing the screen")?;
            if !event::poll(FRAME).context("reading the keyboard")? {
                continue;
            }
            if let Event::Key(key) = event::read().context("reading the keyboard")?
                && !apply(key, &mut ui, rows)
            {
                return Ok(());
            }
        }
    })();
    ratatui::restore();
    result
}

/// Applies a key to the view; `false` to end it.
fn apply(key: KeyEvent, ui: &mut Ui, rows: usize) -> bool {
    if key.kind != KeyEventKind::Press {
        return true;
    }
    match key.code {
        KeyCode::Char('q') => return false,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return false,
        KeyCode::Up | KeyCode::Char('k') if !ui.detail => {
            ui.selected = ui.selected.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') if !ui.detail => {
            ui.selected = (ui.selected + 1).min(rows.saturating_sub(1));
        }
        KeyCode::Enter if rows > 0 => ui.detail = true,
        KeyCode::Esc => ui.detail = false,
        KeyCode::Char('t') => ui.traffic = !ui.traffic,
        _ => {}
    }
    true
}

fn read_local(socket: &Path) -> Result<StatusDoc, String> {
    let raw = mesh_status::query_raw(socket)
        .map_err(|e| format!("{:#}", crate::status::explain(e, socket)))?;
    serde_json::from_value(raw)
        .map_err(|_| "the nett service sent a status this version cannot read".to_owned())
}

/// Reads the status every second until the screen is gone.
fn local_reader(socket: &Path, tx: &SyncSender<(Instant, Result<StatusDoc, String>)>) {
    loop {
        let began = Instant::now();
        let read = read_local(socket);
        if tx.send((Instant::now(), read)).is_err() {
            return;
        }
        std::thread::sleep(LOCAL_EVERY.saturating_sub(began.elapsed()));
    }
}

/// What the site's reader hands the screen.
enum Read {
    Reply(StatusResponse),
    Status(LiveStatus),
    Sample(LiveSample, Instant),
    Connection(String),
}

/// How a stream ended.
enum Ended {
    /// The screen is gone.
    Viewer,
    /// It failed, and whether it was live first.
    Failed(String, bool),
}

/// Keeps the stream open until the screen is gone, opening it again after a failure.
fn site_reader(target: &Target, token: &str, tx: &SyncSender<Read>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.send(Read::Connection(format!("cannot start the reader: {e}")));
            return;
        }
    };
    runtime.block_on(async {
        let mut wait = RETRY_FIRST;
        loop {
            if tx.send(Read::Connection("connecting".into())).is_err() {
                return;
            }
            let (reason, was_live) = match stream(target, token, tx).await {
                Ended::Viewer => return,
                Ended::Failed(reason, live) => (reason, live),
            };
            if was_live {
                wait = RETRY_FIRST;
            }
            let until = tokio::time::Instant::now() + wait;
            while let Some(left) = until.checked_duration_since(tokio::time::Instant::now()) {
                let text = format!("{reason}; again in {}s", left.as_secs() + 1);
                if tx.send(Read::Connection(text)).is_err() {
                    return;
                }
                tokio::time::sleep(left.min(Duration::from_secs(1))).await;
            }
            wait = (wait * 2).min(RETRY_MAX);
        }
    });
}

/// Why the stream cannot be opened, in the words the header shows.
fn stream_error(e: &http::HttpError) -> String {
    match e {
        http::HttpError::Fetch { status: 404, .. } => {
            "this Hub sends no samples: `nett site upgrade`".into()
        }
        http::HttpError::Fetch { status: 503, .. } => "4 live views open at the Hub".into(),
        e => format!("Hub unreachable: {e}"),
    }
}

/// Opens the stream, then reads the status, so that no report falls between the two, and hands
/// on what arrives (design/top.md section 6).
async fn stream(target: &Target, token: &str, tx: &SyncSender<Read>) -> Ended {
    let failed =
        |e: &dyn std::fmt::Display, live| Ended::Failed(format!("Hub unreachable: {e}"), live);
    let fetch = || async {
        let bytes = http::call(target, "GET", STATUS_PATH, Some(token), None)
            .await
            .map_err(|e| e.to_string())?;
        serde_json::from_slice::<StatusResponse>(&bytes)
            .map_err(|_| "the Hub's status is not valid".to_owned())
    };
    let mut body = match http::open_stream(target, LINKS_STREAM_PATH, token).await {
        Ok(body) => body,
        Err(e) => {
            // The machines' latest reports still show, without samples
            if let Ok(reply) = fetch().await
                && tx.send(Read::Reply(reply)).is_err()
            {
                return Ended::Viewer;
            }
            return Ended::Failed(stream_error(&e), false);
        }
    };
    match fetch().await {
        Ok(reply) => {
            if tx.send(Read::Reply(reply)).is_err() {
                return Ended::Viewer;
            }
        }
        Err(e) => return failed(&e, false),
    }
    if tx.send(Read::Connection("live".into())).is_err() {
        return Ended::Viewer;
    }
    let mut parser = sse::Parser::default();
    loop {
        let chunk = match body.next(STREAM_IDLE).await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => return Ended::Failed("the Hub ended the stream".into(), true),
            Err(e) => return failed(&e, true),
        };
        let messages = match parser.push(&chunk) {
            Ok(m) => m,
            Err(e) => return failed(&e, true),
        };
        for m in messages {
            let read = match m.event.as_str() {
                "status" => serde_json::from_str(&m.data).ok().map(Read::Status),
                "sample" => serde_json::from_str(&m.data)
                    .ok()
                    .map(|s| Read::Sample(s, Instant::now())),
                "resync" => match fetch().await {
                    Ok(reply) => Some(Read::Reply(reply)),
                    Err(e) => return failed(&e, true),
                },
                _ => None,
            };
            if let Some(read) = read
                && tx.send(read).is_err()
            {
                return Ended::Viewer;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    /// Arrows and j k move within the rows, enter opens the details when there is a row, esc
    /// closes them, t switches the charts, q and ctrl-c end the view.
    #[test]
    fn keys_move_open_and_quit() {
        let mut ui = Ui::default();
        let none = KeyModifiers::NONE;
        for code in [KeyCode::Down, KeyCode::Char('j'), KeyCode::Down] {
            assert!(apply(press(code, none), &mut ui, 2));
        }
        assert_eq!(ui.selected, 1);
        assert!(apply(press(KeyCode::Char('k'), none), &mut ui, 2));
        assert_eq!(ui.selected, 0);
        assert!(apply(press(KeyCode::Enter, none), &mut ui, 0));
        assert!(!ui.detail);
        assert!(apply(press(KeyCode::Enter, none), &mut ui, 2));
        assert!(ui.detail);
        assert!(apply(press(KeyCode::Esc, none), &mut ui, 2));
        assert!(!ui.detail);
        assert!(apply(press(KeyCode::Char('t'), none), &mut ui, 2));
        assert!(ui.traffic);
        assert!(!apply(press(KeyCode::Char('q'), none), &mut ui, 2));
        assert!(!apply(
            press(KeyCode::Char('c'), KeyModifiers::CONTROL),
            &mut ui,
            2
        ));
    }
}
