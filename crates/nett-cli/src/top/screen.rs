//! Drawing a view's screen (design/top.md section 7): text in columns as the rest of the command
//! line writes it, the selected row in reverse video, charts in block characters, no colors.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::Paragraph;

use super::model::{Screen, Ui};
use crate::layout::columns;

/// Narrower than this the chart column is left out, and narrower than [`MIN_WIDTH`] nothing fits.
pub const CHART_WIDTH: u16 = 80;
pub const MIN_WIDTH: u16 = 60;
/// The chart column's widest.
const CHART_MAX: usize = 30;
/// The fewest the chart column is drawn with.
const CHART_MIN: usize = 8;
/// Event lines under the rows.
const EVENT_LINES: usize = 6;

pub fn draw(frame: &mut Frame, screen: &Screen, ui: Ui) {
    let area = frame.area();
    if area.width < MIN_WIDTH {
        frame.render_widget(
            Paragraph::new(format!(
                "The terminal is too narrow: {MIN_WIDTH} columns at least."
            )),
            area,
        );
        return;
    }
    let width = usize::from(area.width);
    let machines = lines_of(&screen.machines);
    let machine_lines = if machines.is_empty() {
        0
    } else {
        machines.len() + 1
    };
    let events = if screen.detail.is_some() || screen.events.is_empty() {
        0
    } else {
        2 + screen.events.len().min(EVENT_LINES)
    };
    let [head, _, machines_area, body, events_area, foot] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(height(machine_lines)),
        Constraint::Fill(1),
        Constraint::Length(height(events)),
        Constraint::Length(1),
    ])
    .areas(area);

    frame.render_widget(
        Paragraph::new(header(&screen.title, &screen.status, width)),
        head,
    );
    frame.render_widget(Paragraph::new(machines.join("\n")), machines_area);
    match &screen.detail {
        Some(detail) => {
            let mut text = vec![Line::raw(detail.title.clone()), Line::raw("")];
            let label = detail
                .charts
                .iter()
                .map(|c| c.0.chars().count())
                .max()
                .unwrap_or(0);
            let range = detail
                .charts
                .iter()
                .map(|c| c.2.chars().count())
                .max()
                .unwrap_or(0);
            let spark = width.saturating_sub(label + range + 4).min(120);
            for (name, chart, top) in &detail.charts {
                let pad = label - name.chars().count();
                text.push(Line::raw(format!(
                    "{}{name}  {:<spark$}  {top}",
                    " ".repeat(pad),
                    chart.history.spark(spark, chart.from_zero)
                )));
            }
            text.push(Line::raw(""));
            text.extend(detail.text.lines().map(|l| Line::raw(l.to_owned())));
            frame.render_widget(Paragraph::new(Text::from(text)), body);
        }
        None => {
            let lines = rows(screen, width, area.width >= CHART_WIDTH);
            let [head_row, rest] =
                Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(body);
            let mut lines = lines.into_iter();
            frame.render_widget(Paragraph::new(lines.next().unwrap_or_default()), head_row);
            let visible = usize::from(rest.height).max(1);
            let offset = (ui.selected + 1).saturating_sub(visible);
            let styled: Vec<Line> = lines
                .enumerate()
                .map(|(i, l)| {
                    let line = Line::raw(l);
                    if i == ui.selected {
                        line.style(Style::new().add_modifier(Modifier::REVERSED))
                    } else {
                        line
                    }
                })
                .collect();
            frame.render_widget(
                Paragraph::new(Text::from(styled))
                    .scroll((u16::try_from(offset).unwrap_or(u16::MAX), 0)),
                rest,
            );
        }
    }
    if events > 0 {
        let mut text = vec![String::new(), "EVENTS".to_owned()];
        text.extend(screen.events.iter().take(EVENT_LINES).cloned());
        frame.render_widget(Paragraph::new(text.join("\n")), events_area);
    }
    let keys = if screen.detail.is_some() {
        "esc back   t traffic or rtt   q quit"
    } else {
        "↑↓ select   enter details   t traffic or rtt   q quit"
    };
    frame.render_widget(Paragraph::new(keys), foot);
}

fn height(lines: usize) -> u16 {
    u16::try_from(lines).unwrap_or(u16::MAX)
}

fn lines_of(rows: &[Vec<String>]) -> Vec<String> {
    let rows: Vec<&[String]> = rows.iter().map(Vec::as_slice).collect();
    columns(&rows)
}

/// The title on the left and the status on the right of one line.
fn header(title: &str, status: &str, width: usize) -> String {
    let used = title.chars().count() + status.chars().count();
    if used + 2 > width {
        format!("{title}  {status}")
    } else {
        format!("{title}{}{status}", " ".repeat(width - used))
    }
}

/// The rows in columns, the header first, with the chart column where it fits.
fn rows(screen: &Screen, width: usize, charts: bool) -> Vec<String> {
    let lines = lines_of(&screen.rows);
    let widest = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0);
    let room = width.saturating_sub(widest + 2).min(CHART_MAX);
    if !charts || room < CHART_MIN {
        return lines;
    }
    lines
        .into_iter()
        .enumerate()
        .map(|(i, line)| {
            let pad = " ".repeat(widest - line.chars().count() + 2);
            let chart = match i {
                0 => screen.chart_title.to_owned(),
                i => screen
                    .charts
                    .get(i - 1)
                    .map(|c| c.history.spark(room, c.from_zero))
                    .unwrap_or_default(),
            };
            format!("{line}{pad}{chart}")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::super::model::{Local, tests::doc};
    use super::*;
    use nett_trust::encoding::Timestamp;

    fn drawn(width: u16, ui: Ui) -> Vec<String> {
        let mut local = Local::default();
        let me = ("node_01JD7M3XQ4W8N2K5R9T6V3B7C1", "mac");
        let peer = ("node_01JD7M3XQ4W8N2K5R9T6V3B7C2", "edge-vps");
        for (i, rtt) in [9.0, 9.5, 12.0].into_iter().enumerate() {
            let n = u64::try_from(i).expect("small");
            local.status(
                doc(me, peer, "decider", Some(rtt), n * 1000, n * 100),
                i as f64,
            );
        }
        let screen = local.screen(Timestamp::now(), ui);
        let mut terminal = Terminal::new(TestBackend::new(width, 24)).expect("terminal");
        terminal.draw(|f| draw(f, &screen, ui)).expect("draw");
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect()
    }

    /// The rows with the chart column where it fits, and the events; the chart column left out
    /// below 80 columns; below 60 the screen asks for a wider terminal; the details replace the
    /// rows (design/top.md section 7).
    #[test]
    fn the_screen_fits_the_terminal() {
        let wide = drawn(120, Ui::default());
        assert!(
            wide[0].starts_with("nett top  mac") && wide[0].ends_with("live"),
            "{wide:?}"
        );
        let head = wide.iter().find(|l| l.starts_with("PEER")).expect("rows");
        assert!(head.ends_with("RTT") && head.contains("OUT"), "{head}");
        let row = wide
            .iter()
            .find(|l| l.starts_with("edge-vps"))
            .expect("row");
        assert!(row.ends_with("▁▂█"), "{row}");
        assert!(wide.iter().any(|l| l == "EVENTS"));
        assert!(wide.last().is_some_and(|l| l.contains("q quit")));

        let narrow = drawn(70, Ui::default());
        let row = narrow
            .iter()
            .find(|l| l.starts_with("edge-vps"))
            .expect("row");
        assert!(!row.contains('▁'), "{row}");

        assert_eq!(
            drawn(50, Ui::default())[0],
            "The terminal is too narrow: 60 columns at least."
        );

        let detail = drawn(
            120,
            Ui {
                detail: true,
                ..Ui::default()
            },
        );
        assert!(
            detail.iter().any(|l| l.trim_start().starts_with("rtt  ")),
            "{detail:?}"
        );
        assert!(detail.last().is_some_and(|l| l.starts_with("esc back")));
    }
}
