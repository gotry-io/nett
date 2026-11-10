//! 命令行输出的排版（architecture.md 第 14.3 节）：`nett status` 与 `nett site` 共用。

use std::fmt::Write as _;

/// 键值两列，键按最长的对齐。
pub(crate) fn key_values(rows: &[(&str, String)]) -> String {
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    rows.iter()
        .map(|(k, v)| format!("{k:width$}  {v}\n"))
        .collect()
}

/// 按列对齐，列之间两个空格，最后一列不补空格。
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
