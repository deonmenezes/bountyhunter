//! Language-aware code item extraction — **in-progress** Rust port of
//! `core/inventory/extractors.py`.
//!
//! Status: the production extraction path (`extract_functions` / `extract_items`)
//! is tree-sitter-based (with a Python-`ast` branch and regex fallbacks), so it
//! is gated on the tree-sitter foundation being added to this workspace. Ported
//! here so far are the pure, production-faithful pieces that do NOT depend on a
//! parser:
//!   * [`CodeItem`] — the inventory item shape.
//!   * [`compute_interstitial_items`] — the coverage safety net that fills line
//!     ranges not claimed by any extracted item (runs over already-extracted
//!     items, so it's faithful regardless of how those items were produced).

/// Inventory item kinds (mirror the `KIND_*` constants in the Python module).
pub const KIND_FUNCTION: &str = "function";
pub const KIND_GLOBAL: &str = "global";
pub const KIND_MACRO: &str = "macro";
pub const KIND_CLASS: &str = "class";
pub const KIND_TOP_LEVEL: &str = "top_level";
pub const KIND_INTERSTITIAL: &str = "interstitial";

/// A code construct in the inventory (function, global, macro, class, …).
/// Mirrors the Python `CodeItem` dataclass base shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeItem {
    pub name: String,
    pub kind: String,
    pub line_start: i64,
    pub line_end: Option<i64>,
    pub checked_by: Vec<String>,
}

impl CodeItem {
    pub fn new(name: impl Into<String>, kind: impl Into<String>, line_start: i64, line_end: Option<i64>) -> Self {
        Self { name: name.into(), kind: kind.into(), line_start, line_end, checked_by: Vec::new() }
    }
}

/// Split like Python's `str.splitlines` for the common line boundaries
/// (`\n`, `\r\n`, `\r`): no trailing empty element when the text ends with a
/// newline, and `""` yields no lines.
fn splitlines(content: &str) -> Vec<&str> {
    if content.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<&str> = Vec::new();
    let bytes = content.as_bytes();
    let n = bytes.len();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < n {
        match bytes[i] {
            b'\n' => {
                out.push(&content[start..i]);
                i += 1;
                start = i;
            }
            b'\r' => {
                out.push(&content[start..i]);
                i += if i + 1 < n && bytes[i + 1] == b'\n' { 2 } else { 1 };
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < n {
        out.push(&content[start..n]);
    }
    out
}

/// Synthesise `interstitial` items for line ranges NOT inside any extracted
/// item — the coverage safety net so non-function code is never invisible.
/// One item per contiguous gap; gaps with no non-blank line are skipped. Line
/// numbers are 1-based. Faithful port of `compute_interstitial_items`.
pub fn compute_interstitial_items(items: &[CodeItem], content: &str) -> Vec<CodeItem> {
    let lines = splitlines(content);
    let total = lines.len() as i64;
    if total == 0 {
        return Vec::new();
    }
    // 1-based coverage; indices 0 and total+1 unused.
    let mut covered = vec![false; (total + 2) as usize];
    for it in items {
        let lo = std::cmp::max(1, it.line_start);
        let hi = match it.line_end {
            Some(e) => e,
            None => {
                if it.line_start != 0 {
                    it.line_start
                } else {
                    lo
                }
            }
        };
        let upper = std::cmp::min(total, hi);
        let mut ln = lo;
        while ln <= upper {
            covered[ln as usize] = true;
            ln += 1;
        }
    }

    let mut out: Vec<CodeItem> = Vec::new();
    let mut ln = 1i64;
    while ln <= total {
        if covered[ln as usize] {
            ln += 1;
            continue;
        }
        let start = ln;
        while ln <= total && !covered[ln as usize] {
            ln += 1;
        }
        let end = ln - 1;
        let has_content =
            (start..=end).any(|i| !lines[(i - 1) as usize].trim().is_empty());
        if has_content {
            out.push(CodeItem::new(
                format!("interstitial:{start}-{end}"),
                KIND_INTERSTITIAL,
                start,
                Some(end),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fn_item(line_start: i64, line_end: i64) -> CodeItem {
        CodeItem::new("f", KIND_FUNCTION, line_start, Some(line_end))
    }

    #[test]
    fn gap_between_two_functions_becomes_interstitial() {
        // Lines 1-2 fn, 5-6 fn; lines 3-4 are a non-blank gap.
        let content = "def a():\n    pass\nx = 1\ny = 2\ndef b():\n    pass\n";
        let items = vec![fn_item(1, 2), fn_item(5, 6)];
        let out = compute_interstitial_items(&items, content);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "interstitial:3-4");
        assert_eq!(out[0].kind, KIND_INTERSTITIAL);
        assert_eq!((out[0].line_start, out[0].line_end), (3, Some(4)));
    }

    #[test]
    fn blank_only_gap_is_skipped() {
        // Gap lines 3-4 are blank → no interstitial.
        let content = "def a():\n    pass\n\n\ndef b():\n    pass\n";
        let items = vec![fn_item(1, 2), fn_item(5, 6)];
        assert!(compute_interstitial_items(&items, content).is_empty());
    }

    #[test]
    fn leading_and_trailing_gaps() {
        let content = "import os\n\ndef a():\n    pass\nTAIL = 1\n";
        let items = vec![fn_item(3, 4)];
        let out = compute_interstitial_items(&items, content);
        // Lines 1-2 are one contiguous uncovered run (blank line 2 doesn't
        // split it because the run contains a non-blank line); 5 is another.
        let names: Vec<_> = out.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["interstitial:1-2", "interstitial:5-5"]);
    }

    #[test]
    fn empty_content_yields_nothing() {
        assert!(compute_interstitial_items(&[], "").is_empty());
    }

    #[test]
    fn no_items_whole_file_is_one_interstitial() {
        let content = "a\nb\nc\n";
        let out = compute_interstitial_items(&[], content);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "interstitial:1-3");
    }

    #[test]
    fn item_line_end_none_covers_single_line() {
        let content = "g = 1\nx = 2\n";
        let items = vec![CodeItem::new("g", KIND_GLOBAL, 1, None)];
        let out = compute_interstitial_items(&items, content);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "interstitial:2-2");
    }

    #[test]
    fn splitlines_matches_python_semantics() {
        assert_eq!(splitlines("a\nb\n"), vec!["a", "b"]);
        assert_eq!(splitlines("a\nb"), vec!["a", "b"]);
        assert_eq!(splitlines("a\n\nb"), vec!["a", "", "b"]);
        assert_eq!(splitlines("a\r\nb"), vec!["a", "b"]);
        assert_eq!(splitlines(""), Vec::<&str>::new());
    }
}
