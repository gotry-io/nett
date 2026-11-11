//! Layout of command line output (architecture.md section 14.3): shared by `nett status` and
//! `nett site`.

use std::fmt::Write as _;

/// Two columns of key and value, aligned to the longest key.
pub(crate) fn key_values(rows: &[(&str, String)]) -> String {
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    rows.iter()
        .map(|(k, v)| format!("{k:width$}  {v}\n"))
        .collect()
}

/// Aligns by column, two spaces between columns, no padding after the last column.
pub(crate) fn table<const N: usize>(rows: &[[String; N]]) -> String {
    let mut widths = [0usize; N];
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for row in rows {
        let mut line = String::new();
        for (i, cell) in row.iter().enumerate() {
            if i + 1 == N {
                line.push_str(cell);
            } else {
                let pad = widths[i] - cell.chars().count();
                write!(line, "{cell}{}  ", " ".repeat(pad)).ok();
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}
