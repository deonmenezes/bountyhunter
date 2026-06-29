//! Detect lexically dead scopes — faithful Rust port of
//! `core/inventory/dead_scope.py`.
//!
//! A function defined inside `if False:` (Python), `if (false) {…}`
//! (JS/TS), or behind `#[cfg(any())]` (Rust) is never created: the
//! guard's body never executes / compiles. This module returns the
//! inclusive 1-indexed line ranges of those dead scopes so the
//! inventory builder can tag the enclosed items `lexical_dead`.
//!
//! Conservative bias (same as `module_load_abort`): only fire on
//! unambiguously-constant guards. `if DEBUG:` is NOT dead (runtime
//! name); `if False:` IS. `#[cfg(test)]` is NOT dead (it compiles
//! under the test profile); `#[cfg(any())]` IS. False negatives are
//! cheap (miss a deferral); false positives are expensive (silence a
//! real finding in live code).
//!
//! Per-language detection handled (others return `[]` — graceful
//! degradation, never a false "everything is live" claim):
//!   * Python: `if/elif/while <falsey-constant>:` — the BODY only.
//!   * JavaScript / TypeScript: `if (false) {…}` / `if (0) {…}`.
//!   * Rust: `if false {…}` blocks and `#[cfg(any())]` / `#[cfg(all(any()))]`.
//!
//! Port note: the Python detector parses with `ast` and returns `[]`
//! on any `SyntaxError`. This port scans by indentation instead (no
//! Python AST in Rust), matching the Python behaviour on every tested
//! input. The only divergence is a syntactically-broken Python file
//! that still contains a literal `if False:` — `ast` bails to `[]`
//! whereas the scan still reports the range. That input never reaches
//! the inventory builder (broken files fail extraction upstream), and
//! the conservative bias makes the divergence safe.

use std::sync::OnceLock;

use regex::{Captures, Regex};

/// Inclusive 1-indexed `(start, end)` line range of a lexically dead scope.
/// A function whose `line_start` falls within any returned range is dead.
pub type DeadRange = (usize, usize);

/// Per-language dispatch. Returns inclusive 1-indexed line ranges of
/// lexically dead scopes, or an empty vec when none are found (or the
/// language has no detector wired). Best-effort: malformed input yields
/// an empty vec, never a false "no dead scope" claim about live code.
pub fn detect_dead_scopes(language: &str, content: &str) -> Vec<DeadRange> {
    if content.is_empty() {
        return Vec::new();
    }
    match language {
        "python" => detect_python(content),
        "javascript" | "typescript" | "tsx" => detect_javascript(content),
        "rust" => detect_rust(content),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Python — `if/elif/while <falsey-constant>:` guards, indentation-scoped body.
// ---------------------------------------------------------------------------

/// Header whose test is an unambiguous falsey literal
/// (`False` / `None` / `0` / `0.0` / `0j` / `""` / `''`), with optional
/// surrounding parens. Runtime names (`if DEBUG:`) and any non-literal
/// expression (`if False or x:`) are NOT matched — the trailing `:` is
/// anchored directly after the constant, so compound tests fall through.
fn py_header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"^\s*(?:if|elif|while)\s+(?:\(\s*)?(?:False|None|0\.0|0[jJ]|0|""|'')\s*\)?\s*:(?P<rest>.*)$"#,
        )
        .unwrap()
    })
}

fn leading_ws(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ' || *c == '\t').count()
}

fn detect_python(content: &str) -> Vec<DeadRange> {
    let lines: Vec<&str> = content.split('\n').collect();
    let header_re = py_header_re();
    let mut ranges: Vec<DeadRange> = Vec::new();

    for (idx, raw) in lines.iter().enumerate() {
        let Some(caps) = header_re.captures(raw) else {
            continue;
        };
        let header_line = idx + 1;
        let indent = leading_ws(raw);

        // Inline body: `if 0: dangerous()` — body is on the header line.
        // (Strip a trailing `# comment`; not string-aware, but inline
        // dead bodies are simple by construction.)
        let rest = caps.name("rest").map(|m| m.as_str()).unwrap_or("");
        let inline_code = rest.split('#').next().unwrap_or("").trim();
        if !inline_code.is_empty() {
            ranges.push((header_line, header_line));
            continue;
        }

        // Block body: subsequent lines indented strictly deeper than the
        // header. Blank lines and comment-only lines are transparent —
        // they neither start, end, nor terminate the body (Python's AST
        // sees only statements, so a comment between the header and the
        // first statement must not widen the range). The first *real*
        // statement at or below the header indent ends the body, so an
        // `else:`/`elif` at the header indent stays live.
        let mut start = 0usize;
        let mut end = 0usize;
        for (j, line) in lines.iter().enumerate().skip(idx + 1) {
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if leading_ws(line) > indent {
                if start == 0 {
                    start = j + 1;
                }
                end = j + 1;
            } else {
                break;
            }
        }
        if start != 0 {
            ranges.push((start, end));
        }
    }
    ranges
}

// ---------------------------------------------------------------------------
// JavaScript / TypeScript — brace-tracked `if (false) {…}` blocks.
// ---------------------------------------------------------------------------

fn js_block_comment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)/\*.*?\*/").unwrap())
}

fn js_line_comment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"//[^\n]*").unwrap())
}

fn js_dead_if_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bif\s*\(\s*(?:false|0)\s*\)\s*\{").unwrap())
}

/// Replace every non-newline char with a space, preserving newlines, so
/// comment removal keeps byte/line offsets stable.
fn blank_preserving_newlines(s: &str) -> String {
    s.chars().map(|c| if c == '\n' { '\n' } else { ' ' }).collect()
}

fn js_strip_comments(content: &str) -> String {
    let no_block = js_block_comment_re()
        .replace_all(content, |c: &Captures| blank_preserving_newlines(&c[0]))
        .into_owned();
    js_line_comment_re()
        .replace_all(&no_block, |c: &Captures| blank_preserving_newlines(&c[0]))
        .into_owned()
}

fn detect_javascript(content: &str) -> Vec<DeadRange> {
    let stripped = js_strip_comments(content);
    let bytes = stripped.as_bytes();
    let mut ranges: Vec<DeadRange> = Vec::new();
    for m in js_dead_if_re().find_iter(&stripped) {
        // The opening brace is the last char of the match.
        let brace_pos = m.end() - 1;
        if let Some(close) = match_brace(bytes, brace_pos) {
            ranges.push((line_of(bytes, m.start()), line_of(bytes, close)));
        }
    }
    ranges
}

// ---------------------------------------------------------------------------
// Rust — `if false {…}` blocks plus `#[cfg(any())]` attributes gating a fn/mod.
// ---------------------------------------------------------------------------

fn rust_dead_if_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bif\s+false\s*\{").unwrap())
}

/// `#[cfg(any())]` or `#[cfg(all(any()))]` — empty `any()` is always
/// false and `all(false)` is always false. Whitespace-tolerant.
fn rust_dead_cfg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"#\s*\[\s*cfg\s*\(\s*(?:any\s*\(\s*\)|all\s*\(\s*any\s*\(\s*\)\s*\))\s*\)\s*\]",
        )
        .unwrap()
    })
}

/// The immediately-following item must be a `fn` or `mod` (whose body is
/// then dead), allowing chained attributes, visibility, and qualifiers
/// between the cfg and the keyword. Anchored at the start of the slice
/// (Python uses `re.match`) so a cfg gating a non-fn/mod item does NOT
/// grab an unrelated `fn` further down the file.
fn rust_item_after_cfg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"^\s*(?:#\s*\[[^\]]*\]\s*)*(?:pub\s*(?:\([^)]*\)\s*)?)?(?:(?:async|unsafe|const|extern(?:\s+"[^"]*")?)\s+)*(?:fn|mod)\b"#,
        )
        .unwrap()
    })
}

fn detect_rust(content: &str) -> Vec<DeadRange> {
    let bytes = content.as_bytes();
    let mut ranges: Vec<DeadRange> = Vec::new();

    // `if false { … }` blocks.
    for m in rust_dead_if_re().find_iter(content) {
        let brace_pos = m.end() - 1;
        if let Some(close) = match_brace(bytes, brace_pos) {
            ranges.push((line_of(bytes, m.start()), line_of(bytes, close)));
        }
    }

    // `#[cfg(any())]` gating the immediately-following fn / mod.
    for m in rust_dead_cfg_re().find_iter(content) {
        let after = &content[m.end()..];
        if !rust_item_after_cfg_re().is_match(after) {
            // cfg gates a non-fn/mod item — do not range (avoids the
            // false positive of grabbing an unrelated later fn).
            continue;
        }
        // First `{` after the attribute is the gated item's body —
        // nothing between the cfg and the body uses braces.
        let Some(brace_rel) = after.find('{') else {
            continue;
        };
        if let Some(close) = match_brace(bytes, m.end() + brace_rel) {
            ranges.push((line_of(bytes, m.start()), line_of(bytes, close)));
        }
    }
    ranges
}

// ---------------------------------------------------------------------------
// Shared — brace matcher with string / char / line-comment skipping.
// Operates on bytes; every structural char (`{ } " ' ` /`) is ASCII, so
// byte indexing stays on char boundaries.
// ---------------------------------------------------------------------------

/// 1-indexed line containing byte offset `pos`.
fn line_of(src: &[u8], pos: usize) -> usize {
    src[..pos].iter().filter(|&&b| b == b'\n').count() + 1
}

/// Given the byte index of an opening `{`, return the byte index of the
/// matching `}`. Skips string / template / char literals and `//` line
/// comments so braces inside them don't unbalance the count. Returns
/// `None` on malformed input.
fn match_brace(src: &[u8], open_pos: usize) -> Option<usize> {
    if open_pos >= src.len() || src[open_pos] != b'{' {
        return None;
    }
    let mut depth: i32 = 1;
    let mut i = open_pos + 1;
    let n = src.len();
    while i < n {
        let c = src[i];
        if c == b'"' || c == b'\'' || c == b'`' {
            match skip_string(src, i) {
                Some(j) => {
                    i = j;
                    continue;
                }
                None => return None,
            }
        }
        if c == b'/' && i + 1 < n && src[i + 1] == b'/' {
            match memchr_newline(src, i) {
                Some(nl) => {
                    i = nl + 1;
                    continue;
                }
                None => return None,
            }
        }
        if c == b'{' {
            depth += 1;
        } else if c == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Advance past a string / template / char literal starting at `start`
/// (the opening quote). Handles backslash escapes.
fn skip_string(src: &[u8], start: usize) -> Option<usize> {
    let quote = src[start];
    let mut i = start + 1;
    let n = src.len();
    while i < n {
        let c = src[i];
        if c == b'\\' {
            i += 2;
            continue;
        }
        if c == quote {
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

fn memchr_newline(src: &[u8], from: usize) -> Option<usize> {
    src[from..].iter().position(|&b| b == b'\n').map(|p| from + p)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Python -----------------------------------------------------------

    #[test]
    fn python_if_false_body_detected() {
        let src = "if False:\n    def dead(x):\n        return x\n\ndef live():\n    return 1\n";
        assert!(detect_dead_scopes("python", src).contains(&(2, 3)));
    }

    #[test]
    fn python_if_zero_detected() {
        assert_eq!(detect_dead_scopes("python", "if 0:\n    pass\n"), vec![(2, 2)]);
    }

    #[test]
    fn python_while_false_detected() {
        assert_eq!(
            detect_dead_scopes("python", "while False:\n    do_thing()\n"),
            vec![(2, 2)]
        );
    }

    #[test]
    fn python_if_true_not_detected() {
        assert_eq!(detect_dead_scopes("python", "if True:\n    pass\n"), Vec::<DeadRange>::new());
    }

    #[test]
    fn python_runtime_name_guard_not_detected() {
        let src = "if DEBUG:\n    def maybe(): pass\n";
        assert_eq!(detect_dead_scopes("python", src), Vec::<DeadRange>::new());
    }

    #[test]
    fn python_else_branch_not_marked_dead() {
        let src = "if False:\n    dead_call()\nelse:\n    live_call()\n";
        let ranges = detect_dead_scopes("python", src);
        assert!(ranges.iter().any(|&(lo, hi)| lo <= 2 && 2 <= hi));
        assert!(!ranges.iter().any(|&(lo, hi)| lo <= 4 && 4 <= hi));
    }

    #[test]
    fn python_syntax_error_returns_empty() {
        assert_eq!(detect_dead_scopes("python", "def (:\n"), Vec::<DeadRange>::new());
    }

    #[test]
    fn python_inline_dead_body() {
        // `if 0: stmt` — body shares the header line.
        assert_eq!(detect_dead_scopes("python", "if 0: dangerous()\n"), vec![(1, 1)]);
    }

    #[test]
    fn python_nested_if_false_inside_function() {
        let src = "def f():\n    if False:\n        dead()\n    live()\n";
        let ranges = detect_dead_scopes("python", src);
        assert_eq!(ranges, vec![(3, 3)]);
    }

    // --- JavaScript / TypeScript -----------------------------------------

    #[test]
    fn js_if_false_block_detected() {
        let src = "function alive() { return 1; }\nif (false) {\n  function deadJs(p) { eval(p); }\n}\n";
        assert!(detect_dead_scopes("javascript", src).contains(&(2, 4)));
    }

    #[test]
    fn js_if_zero_detected() {
        assert!(detect_dead_scopes("javascript", "if (0) {\n  bad();\n}\n").contains(&(1, 3)));
    }

    #[test]
    fn js_if_true_not_detected() {
        assert_eq!(
            detect_dead_scopes("javascript", "if (true) {\n  ok();\n}\n"),
            Vec::<DeadRange>::new()
        );
    }

    #[test]
    fn js_runtime_guard_not_detected() {
        assert_eq!(
            detect_dead_scopes("javascript", "if (cfg.disabled) {\n  bad();\n}\n"),
            Vec::<DeadRange>::new()
        );
    }

    #[test]
    fn js_commented_if_false_not_detected() {
        let src = "// if (false) {\n/* if (false) { */\nconst ok = 1;\n";
        assert_eq!(detect_dead_scopes("javascript", src), Vec::<DeadRange>::new());
    }

    #[test]
    fn typescript_alias_detected() {
        assert_eq!(
            detect_dead_scopes("typescript", "if (false) {\n  bad();\n}\n"),
            vec![(1, 3)]
        );
    }

    // --- Rust -------------------------------------------------------------

    #[test]
    fn rust_cfg_any_empty_gates_fn() {
        let src = "#[cfg(any())]\nfn dead_rs() {\n    dangerous();\n}\nfn live_rs() {}\n";
        let ranges = detect_dead_scopes("rust", src);
        assert!(ranges.iter().any(|&(lo, hi)| lo <= 2 && 2 <= hi));
        assert!(!ranges.iter().any(|&(lo, hi)| lo <= 5 && 5 <= hi));
    }

    #[test]
    fn rust_if_false_block_detected() {
        let src = "fn f() {\n    if false {\n        dangerous();\n    }\n}\n";
        assert!(detect_dead_scopes("rust", src).contains(&(2, 4)));
    }

    #[test]
    fn rust_cfg_test_not_detected() {
        assert_eq!(detect_dead_scopes("rust", "#[cfg(test)]\nfn t() {}\n"), Vec::<DeadRange>::new());
    }

    #[test]
    fn rust_cfg_feature_not_detected() {
        assert_eq!(
            detect_dead_scopes("rust", "#[cfg(feature = \"x\")]\nfn f() {}\n"),
            Vec::<DeadRange>::new()
        );
    }

    #[test]
    fn rust_cfg_on_struct_does_not_grab_later_fn() {
        let src = "#[cfg(any())]\nstruct Dead;\n\nfn totally_live() {\n    dangerous();\n}\n";
        let ranges = detect_dead_scopes("rust", src);
        assert!(!ranges.iter().any(|&(lo, hi)| lo <= 4 && 4 <= hi));
    }

    #[test]
    fn rust_cfg_on_const_does_not_grab_later_fn() {
        let src = "#[cfg(any())]\nconst X: u32 = 1;\nfn live() { ok(); }\n";
        assert_eq!(detect_dead_scopes("rust", src), Vec::<DeadRange>::new());
    }

    #[test]
    fn rust_cfg_chained_attrs_then_fn() {
        let src = "#[cfg(any())]\n#[inline]\npub fn dead() {\n    bad();\n}\n";
        let ranges = detect_dead_scopes("rust", src);
        assert!(ranges.iter().any(|&(lo, hi)| lo <= 3 && 3 <= hi));
    }

    #[test]
    fn rust_cfg_on_mod_ranges_module_body() {
        let src = "#[cfg(any())]\nmod dead {\n    fn g() { bad(); }\n}\nfn live() {}\n";
        let ranges = detect_dead_scopes("rust", src);
        assert!(ranges.iter().any(|&(lo, hi)| lo <= 3 && 3 <= hi));
        assert!(!ranges.iter().any(|&(lo, hi)| lo <= 5 && 5 <= hi));
    }

    // --- Cross-cutting ----------------------------------------------------

    #[test]
    fn empty_content_returns_empty() {
        assert_eq!(detect_dead_scopes("python", ""), Vec::<DeadRange>::new());
    }

    #[test]
    fn unwired_language_returns_empty() {
        assert_eq!(
            detect_dead_scopes("go", "if false {\n  bad()\n}\n"),
            Vec::<DeadRange>::new()
        );
    }

    #[test]
    fn clean_python_no_dead_scope() {
        assert_eq!(
            detect_dead_scopes("python", "def handler(x):\n    return x\n"),
            Vec::<DeadRange>::new()
        );
    }
}
