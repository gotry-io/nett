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
    let rows: Vec<&[String]> = rows.iter().map(|r| &r[..]).collect();
    columns(&rows).into_iter().map(|line| line + "\n").collect()
}

/// The lines of [`table`], for rows of any length.
pub(crate) fn columns(rows: &[&[String]]) -> Vec<String> {
    let n = rows.iter().map(|r| r.len()).max().unwrap_or(0);
    let mut widths = vec![0usize; n];
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row.iter()) {
            *w = (*w).max(cell.chars().count());
        }
    }
    rows.iter()
        .map(|row| {
            let mut line = String::new();
            for (i, cell) in row.iter().enumerate() {
                if i + 1 == row.len() {
                    line.push_str(cell);
                } else {
                    let pad = widths[i] - cell.chars().count();
                    write!(line, "{cell}{}  ", " ".repeat(pad)).ok();
                }
            }
            line.trim_end().to_owned()
        })
        .collect()
}
