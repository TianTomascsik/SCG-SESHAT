//! Minimal, dependency-free CSV writer (F-17, CSV-only output).
//!
//! Produces RFC-4180-style CSV: fields are comma-separated, rows are
//! `\r\n`-terminated, and any field containing a comma, double-quote, CR or LF
//! is wrapped in double-quotes with embedded quotes doubled. This is enough for
//! every artifact SESHAT emits and opens cleanly in spreadsheets.
#![allow(dead_code)] // builder methods are consumed across report writers.

use std::fs;
use std::io;
use std::path::Path;

/// An in-memory CSV table: a header row plus zero or more data rows.
#[derive(Debug, Default, Clone)]
pub struct Csv {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Csv {
    /// Start a table with the given column headers.
    pub fn new(headers: &[&str]) -> Self {
        Csv {
            headers: headers.iter().map(|h| (*h).to_string()).collect(),
            rows: Vec::new(),
        }
    }

    /// Start a two-column `key,value` table (used for metadata snapshots).
    pub fn key_value() -> Self {
        Csv::new(&["key", "value"])
    }

    /// Append a fully-formed row. Extra/short cells are tolerated as written.
    pub fn row(&mut self, cells: Vec<String>) -> &mut Self {
        self.rows.push(cells);
        self
    }

    /// Append a `key,value` pair (for `key_value` tables).
    pub fn kv(&mut self, key: &str, value: impl Into<String>) -> &mut Self {
        self.rows.push(vec![key.to_string(), value.into()]);
        self
    }

    /// Number of data rows (excludes the header).
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the table has no data rows.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Render the whole table to a CSV string.
    pub fn render(&self) -> String {
        let mut out = String::new();
        write_row(&mut out, &self.headers);
        for row in &self.rows {
            write_row(&mut out, row);
        }
        out
    }

    /// Render only the data rows (no header), for per-scenario artifacts that a
    /// consolidated table concatenates verbatim under a single shared header.
    /// Because the escaping is identical to [`Csv::render`], the blob can be
    /// appended byte-for-byte without re-parsing — safe even when a field
    /// contains a comma, quote, or newline.
    pub fn render_body(&self) -> String {
        let mut out = String::new();
        for row in &self.rows {
            write_row(&mut out, row);
        }
        out
    }

    /// Write the table to `path`, creating parent directories as needed.
    pub fn write(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.render())
    }
}

/// Append one CSV record (escaped) terminated by CRLF.
fn write_row(out: &mut String, cells: &[String]) {
    for (i, cell) in cells.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&escape(cell));
    }
    out.push_str("\r\n");
}

/// Quote a field if it contains a delimiter, quote, or line break.
fn escape(field: &str) -> String {
    if field
        .chars()
        .any(|c| c == ',' || c == '"' || c == '\n' || c == '\r')
    {
        let mut s = String::with_capacity(field.len() + 2);
        s.push('"');
        for c in field.chars() {
            if c == '"' {
                s.push('"');
            }
            s.push(c);
        }
        s.push('"');
        s
    } else {
        field.to_string()
    }
}

/// Format a float with fixed precision, rendering non-finite values as empty.
pub fn num(v: f64, decimals: usize) -> String {
    if v.is_finite() {
        format!("{v:.decimals$}")
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_commas_and_quotes() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape("a,b"), "\"a,b\"");
        assert_eq!(escape("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(escape("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn renders_header_and_rows_crlf() {
        let mut c = Csv::new(&["a", "b"]);
        c.row(vec!["1".into(), "2".into()]);
        c.row(vec!["x,y".into(), "z".into()]);
        let s = c.render();
        assert_eq!(s, "a,b\r\n1,2\r\n\"x,y\",z\r\n");
    }

    #[test]
    fn key_value_table() {
        let mut c = Csv::key_value();
        c.kv("tool", "seshat").kv("n", "5");
        assert_eq!(c.render(), "key,value\r\ntool,seshat\r\nn,5\r\n");
    }

    #[test]
    fn num_handles_non_finite() {
        assert_eq!(num(1.23456, 2), "1.23");
        assert_eq!(num(f64::NAN, 2), "");
        assert_eq!(num(f64::INFINITY, 3), "");
    }
}
